//! Real same-hash SDK claim/refund builders retained for one invocation.
//! Caller supplies only declared online Wallets; root owns their opening.
//! No invoice, payment, funding, forged checkpoint or background sync is started.
//! Original SDK checkpoints remain held until independently reconciled/adopted.
use super::{evidence, phase_protocol as retained, Request};
use anyhow::{ensure, Context, Result};
use ark::{
    arkoor::package::ArkoorPackageBuilder, lightning::PaymentHash, vtxo::Full, ProtocolEncoding,
    Vtxo, VtxoPolicy,
};
use bark::{
    actions::lightning::{pay, receive},
    Wallet,
};
use bitcoin::secp256k1::Keypair;
use prost::Message;
use serde_json::{json, Value};
use server_rpc::protos::{self, ark_service_client::ArkServiceClient};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    str::FromStr,
};
use tonic::transport::Channel;
struct Leg {
    builder: retained::Prepared,
    keys: Vec<Keypair>,
    body: protos::ArkoorPackageCosignRequest,
    checkpoint: Value,
}
struct Prepared {
    claim: Leg,
    claim_body: protos::ClaimLightningReceiveRequest,
    refund: Option<Leg>,
    directory: PathBuf,
    hash: PaymentHash,
    deadline: u32,
}
fn online(actor: &str) -> Result<()> {
    ensure!(
        actor.starts_with("actor-") && !matches!(actor, "actor-03" | "actor-09" | "actor-10"),
        "phase cannot open original absent client"
    );
    Ok(())
}
async fn hydrate(
    wallet: &Wallet,
    ids: &[ark::VtxoId],
    hash: PaymentHash,
    server: &str,
    receiving: bool,
) -> Result<(Vec<Vtxo<Full>>, Vec<Keypair>, u32)> {
    ensure!(
        !ids.is_empty() && ids.len() <= 16,
        "bounded real HTLC input set required"
    );
    let mut coins = Vec::new();
    let mut keys = Vec::new();
    let mut expiry = 0;
    for id in ids {
        let coin = wallet.get_full_vtxo(*id).await?;
        ensure!(
            coin.id() == *id
                && coin.has_all_witnesses()
                && coin.server_pubkey().to_string() == server,
            "signed HTLC input differs from declared server"
        );
        let (actual, deadline) = if receiving {
            let p = coin
                .policy()
                .as_server_htlc_recv()
                .context("actual HTLC receive policy required")?;
            (p.payment_hash, p.htlc_expiry.to_u32())
        } else {
            let p = coin
                .policy()
                .as_server_htlc_send()
                .context("actual HTLC send policy required")?;
            (p.payment_hash, p.htlc_expiry.to_u32())
        };
        ensure!(
            actual == hash,
            "sender/receiver HTLC must have the exact same payment hash"
        );
        if expiry == 0 {
            expiry = deadline
        } else {
            ensure!(expiry == deadline, "HTLC package deadlines differ")
        }
        keys.push(wallet.get_vtxo_key(&coin).await?);
        coins.push(coin);
    }
    Ok((coins, keys, expiry))
}
fn leg(
    coins: Vec<Vtxo<Full>>,
    keys: Vec<Keypair>,
    policy: VtxoPolicy,
    name: &str,
    rpc: &str,
    hash: PaymentHash,
) -> Result<Leg> {
    let ids = coins.iter().map(|v| v.id().to_string()).collect::<Vec<_>>();
    let principal = coins
        .iter()
        .try_fold(0u64, |sum, v| sum.checked_add(v.amount().to_sat()))
        .context("HTLC principal overflow")?;
    let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints(coins, policy)?
        .generate_user_nonces(&keys)?;
    let body = protos::ArkoorPackageCosignRequest::from(builder.cosign_request());
    let mut checkpoint = retained::body_checkpoint(&builder, &body, name, &ids);
    checkpoint["rpc"] = json!(rpc);
    checkpoint["payment_hash"] = json!(hash.to_string());
    checkpoint["input_principal_sat"] = json!(principal);
    Ok(Leg {
        builder,
        keys,
        body,
        checkpoint,
    })
}
async fn prepare(
    receiver: &Wallet,
    sender: Option<&Wallet>,
    req: &Request,
    private_root: &Path,
    actor: &str,
) -> Result<Option<Prepared>> {
    let scenario = req.args["phase_intent"]["scenario"]
        .as_str()
        .context("phase scenario")?;
    ensure!(
        matches!(scenario, "D33" | "D34" | "D36"),
        "Lightning phase differs"
    );
    let frozen = retained::intent(req, scenario)?;
    ensure!(
        req.operation == format!("phase_execute_{}", scenario.to_lowercase()),
        "Lightning phase operation differs"
    );
    online(actor)?;
    ensure!(frozen["actor"] == actor, "selected receiver actor differs");
    let Some(directory) = retained::fence(private_root, req)? else {
        return Ok(None);
    };
    let hash = PaymentHash::from_str(
        frozen["context"]["payment_hash"]
            .as_str()
            .context("frozen payment hash")?,
    )?;
    let cp = receiver
        .lightning_receive_checkpoint(hash)
        .await?
        .context("actual SDK prepared receive checkpoint missing")?;
    ensure!(
        cp.payment_hash == hash && cp.payment_preimage.compute_payment_hash() == hash,
        "actual private preimage does not hash to the same payment"
    );
    let htlcs = match &cp.progress {
        receive::Progress::HtlcsReady(htlcs) => htlcs,
        _ => anyhow::bail!("receive must be genuinely prepared before first preimage disclosure"),
    };
    let mut ids = htlcs.vtxo_ids.clone();
    ids.sort();
    ensure!(
        ids.iter().map(|id| id.to_string()).collect::<Vec<_>>()
            == frozen["inputs"]
                .as_array()
                .context("frozen receiver inputs")?
                .iter()
                .map(|v| v["coin_id"].as_str().unwrap().to_string())
                .collect::<Vec<_>>(),
        "actual receiver HTLC inputs differ from independent frozen proof"
    );
    let (coins, keys, deadline) =
        hydrate(receiver, &ids, hash, &req.expected_server_pubkey, true).await?;
    for (coin, item) in coins.iter().zip(frozen["inputs"].as_array().unwrap()) {
        ensure!(
            retained::hash(&coin.serialize())
                == item["signed_hash"]
                    .as_str()
                    .context("signed receiver hash")?
                && Some(coin.amount().to_sat()) == item["amount_sat"].as_u64(),
            "receiver signed input/value changed"
        )
    }
    let claim_policy = if let Some(destination) = &cp.claim_destination {
        destination.policy().clone()
    } else {
        VtxoPolicy::new_pubkey(receiver.peek_keypair(cp.key_index).await?.public_key())
    };
    ensure!(
        receiver
            .pubkey_keypair(&claim_policy.user_pubkey())
            .await?
            .is_some(),
        "local owned receive destination required; external forwarding adoption is a separate gate"
    );
    retained::save(
        &directory.join("receiver-sdk-checkpoint.json"),
        &serde_json::to_vec(&cp)?,
    )?; // Includes private preimage/token: never stdout/trace.
    let mut claim = leg(
        coins,
        keys,
        claim_policy,
        "claim",
        "ClaimLightningReceive",
        hash,
    )?;
    let claim_body = protos::ClaimLightningReceiveRequest {
        payment_hash: hash.to_byte_array().to_vec(),
        payment_preimage: cp.payment_preimage.to_vec(),
        cosign_request: Some(claim.body.clone()),
    };
    let bytes = claim_body.encode_to_vec();
    retained::save(&directory.join("claim-request-private.bin"), &bytes)?;
    claim.checkpoint["wire_sha256"] = json!(retained::hash(&bytes));
    claim.checkpoint["private_checkpoint_sha256"] = json!(retained::hash(&bytes));
    claim.checkpoint["preimage_scope"]=json!("private exact request only; actual preimage hash verified; never exposed in journal or trace");
    let refund = if scenario == "D36" {
        None
    } else {
        let sender = sender.context(
            "declared same-hash sender Wallet required; caller must enforce online ownership",
        )?;
        let sender_actor = frozen["context"]["sender_actor"]
            .as_str()
            .context("declared sender actor")?;
        online(sender_actor)?;
        ensure!(
            sender_actor != actor,
            "sender and receiver must be distinct declared online actors"
        );
        let cp = sender
            .lightning_send_checkpoint(hash)
            .await?
            .context("actual sender SDK checkpoint missing")?;
        ensure!(
            cp.invoice.payment_hash() == hash && cp.fee.to_sat() <= req.maximum_fee_sat,
            "sender same-hash checkpoint or original fee ceiling differs"
        );
        let (htlcs, revocation) = match &cp.progress {
            pay::Progress::RevocableHtlcs { htlcs, revocation } => (htlcs, revocation),
            _ => anyhow::bail!(
                "actual revocable sender checkpoint required; no fabricated failure or nonce retry"
            ),
        };
        let ids = &htlcs.vtxo_ids;
        ensure!(
            ids.iter().map(|id| id.to_string()).collect::<Vec<_>>()
                == serde_json::from_value::<Vec<String>>(
                    frozen["context"]["sender_htlc_ids"].clone()
                )?,
            "sender HTLC identities changed"
        );
        let (coins, keys, _) =
            hydrate(sender, ids, hash, &req.expected_server_pubkey, false).await?;
        ensure!(
            sender.pubkey_keypair(&revocation.key).await?.is_some(),
            "SDK revocation key not owned by declared sender"
        );
        retained::save(
            &directory.join("sender-sdk-checkpoint.json"),
            &serde_json::to_vec(&cp)?,
        )?;
        let refund = leg(
            coins,
            keys,
            VtxoPolicy::new_pubkey(revocation.key),
            "refund",
            "RequestLightningPayHtlcRevocation",
            hash,
        )?;
        retained::save(
            &directory.join("refund-request.bin"),
            &refund.body.encode_to_vec(),
        )?;
        Some(refund)
    };
    let mut legs = vec![claim.checkpoint.clone()];
    if let Some(refund) = &refund {
        legs.push(refund.checkpoint.clone())
    }
    let prepared = json!({"trial_id":req.args["trial_id"],"intent_hash":req.args["intent_hash"],"legs":legs,"receiver_htlc_expiry_height":deadline});
    retained::save(
        &directory.join("preparation.json"),
        &serde_json::to_vec(&prepared)?,
    )?;
    evidence(req, "phase_lightning_preparations_frozen", prepared)?;
    Ok(Some(Prepared {
        claim,
        claim_body,
        refund,
        directory,
        hash,
        deadline,
    }))
}
async fn register(
    rpc: &mut ArkServiceClient<Channel>,
    directory: &Path,
    name: &str,
    result: &Value,
) -> Result<()> {
    if result["kind"] != "sdk_signed_successors" {
        return Ok(());
    }
    let coins = result["outputs"]
        .as_array()
        .context("signed successor rows")?
        .iter()
        .map(|v| {
            super::phase_replay::decode_hex(v["signed_vtxo"].as_str().context("signed successor")?)
        })
        .collect::<Result<Vec<_>>>()?;
    let body = protos::RegisterVtxoTransactionsRequest { vtxos: coins };
    retained::save(
        &directory.join(format!("{name}-register-request.bin")),
        &body.encode_to_vec(),
    )?;
    let outcome = match rpc.register_vtxo_transactions(body).await {
        Ok(response) => json!({"accepted":true,"metadata":format!("{:?}",response.metadata())}),
        Err(error) => {
            json!({"accepted":false,"error":format!("{error:?}"),"financial_outcome_unknown":true})
        }
    };
    retained::save(
        &directory.join(format!("{name}-register-result.json")),
        &serde_json::to_vec(&outcome)?,
    )?;
    Ok(())
}
async fn refund_authorized(
    directory: &Path,
    req: &Request,
    checkpoint: &Value,
    result: &Value,
) -> Result<()> {
    let maximum = req.args["phase_intent"]["context"]["maximum_wait_seconds"]
        .as_u64()
        .unwrap_or(900);
    ensure!(
        (30..=1800).contains(&maximum),
        "bounded immutable refund proof wait required"
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(maximum);
    let path = directory.join("independent-refund-authorization.json");
    loop {
        if path.exists() {
            let metadata = fs::symlink_metadata(&path)?;
            ensure!(
                metadata.is_file()
                    && metadata.mode() & 0o077 == 0
                    && metadata.nlink() == 1
                    && metadata.len() <= 16384
                    && metadata.uid() == fs::metadata(directory)?.uid(),
                "independent refund authorization unsafe"
            );
            let raw = fs::read(&path)?;
            let value: Value = serde_json::from_slice(&raw)?;
            ensure!(
                value["payment_hash"] == checkpoint["payment_hash"]
                    && value["refund_wire_sha256"] == checkpoint["wire_sha256"]
                    && value["actual_refund_attempt_fee_sat"] == 0,
                "independent refund proof differs from actual retained request"
            );
            let outputs = result["outputs"]
                .as_array()
                .context("actual signed refund")?
                .iter()
                .map(|v| v["id"].clone())
                .collect::<Vec<_>>();
            ensure!(
                value["refund_output_ids"] == json!(outputs),
                "independent refund proof names another signed package"
            );
            for key in ["independent_proof_sha256", "original_spend_sha256"] {
                let value = value[key]
                    .as_str()
                    .context("independent proof source hash")?;
                ensure!(
                    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()),
                    "independent refund hash missing"
                )
            }
            evidence(
                req,
                "phase_same_hash_refund_authorized",
                json!({"trial_id":req.args["trial_id"],"authorization_sha256":retained::hash(&raw),"payment_hash":checkpoint["payment_hash"],"refund_wire_sha256":checkpoint["wire_sha256"]}),
            )?;
            return Ok(());
        }
        ensure!(
            std::time::Instant::now() < deadline,
            "no independent refund proof before deadline; claim held without retry"
        );
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
/// Production caller must hold both actors before entering and retain the
/// existing principal/fee reservations until independent SDK adoption/audit.
pub async fn execute(
    receiver: &Wallet,
    sender: Option<&Wallet>,
    rpc: &mut ArkServiceClient<Channel>,
    req: &Request,
    private_root: &Path,
    actor: &str,
) -> Result<Value> {
    let Some(prepared) = prepare(receiver, sender, req, private_root, actor).await? else {
        return Ok(
            json!({"phase_unknown":true,"actual_fee_sat":Value::Null,"reason":"existing phase fence; no nonce regeneration or retry"}),
        );
    };
    let scenario = req.args["phase_intent"]["scenario"].as_str().unwrap();
    let Prepared {
        claim,
        claim_body,
        refund,
        directory,
        hash,
        deadline,
    } = prepared;
    if scenario == "D36" {
        let until = req.args["phase_intent"]["context"]["withhold_until_height"]
            .as_u64()
            .context("observed block deadline")?;
        ensure!(
            until == u64::from(deadline),
            "withhold deadline must equal exact signed HTLC expiry"
        );
        let maximum = req.args["phase_intent"]["context"]["maximum_wait_seconds"]
            .as_u64()
            .unwrap_or(900);
        ensure!(
            (30..=1800).contains(&maximum),
            "bounded withholding duration required"
        );
        let stop = std::time::Instant::now() + std::time::Duration::from_secs(maximum);
        let mut sequence = 0;
        let mut reached = false;
        loop {
            let height = receiver.chain().tip().await?;
            let request = protos::CheckLightningReceiveRequest {
                hash: hash.to_byte_array().to_vec(),
                wait: false,
            };
            retained::save(
                &directory.join(format!("withhold-{sequence}-request.bin")),
                &request.encode_to_vec(),
            )?;
            let observation = match rpc.check_lightning_receive(request).await {
                Ok(reply) => {
                    retained::save(
                        &directory.join(format!("withhold-{sequence}-reply.bin")),
                        &reply.into_inner().encode_to_vec(),
                    )?;
                    json!({"read_reply_captured":true})
                }
                Err(status) => json!({"status":format!("{status:?}"),"read_outcome_unknown":true}),
            };
            retained::save(
                &directory.join(format!("withhold-{sequence}-observation.json")),
                &serde_json::to_vec(
                    &json!({"height":height.to_u32(),"observed_at_ns":retained::now_ns(),"observation":observation,"claim_dispatch_count":0}),
                )?,
            )?;
            evidence(
                req,
                "phase_withheld_claim_observed",
                json!({"trial_id":req.args["trial_id"],"payment_hash":hash.to_string(),"height":height.to_u32(),"deadline":deadline,"claim_dispatch_count":0,"frozen_receiver_principal_sat":claim.checkpoint["input_principal_sat"],"actual_locked_principal_requires_independent_server_arbitration":true}),
            )?;
            sequence += 1;
            if height.to_u32() >= deadline {
                reached = true;
                break;
            }
            if std::time::Instant::now() >= stop {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
        }
        // Retained builder drops without signing/submission; never resumed from
        // captured public nonces. Wallet's real prepared receive stays held.
        return Ok(
            json!({"phase_unknown":true,"actual_fee_sat":Value::Null,"scenario":scenario,"deadline_reached":reached,"claim_dispatch_count":0,"customer_traffic_credit":false,"required_audit":"actual current locked HTLC/refund liability through measured block observations; retained SDK prepared receive never dispatched"}),
        );
    }
    let refund = refund.context("actual retained sender refund package")?;
    let refund_hash = refund.checkpoint["wire_sha256"]
        .as_str()
        .unwrap()
        .to_string();
    let claim_hash = claim.checkpoint["wire_sha256"]
        .as_str()
        .unwrap()
        .to_string();
    let (refund_result, claim_result) = if scenario == "D34" {
        let mut refund_rpc = rpc.clone();
        let mut claim_rpc = rpc.clone();
        let refund_future = async {
            let started = retained::now_ns();
            let reply = refund_rpc
                .request_lightning_pay_htlc_revocation(refund.body)
                .await;
            retained::signed_reply(
                &directory,
                "refund",
                refund.builder,
                &refund.keys,
                reply,
                &refund_hash,
                started,
                retained::now_ns(),
            )
        };
        let claim_future = async {
            let started = retained::now_ns();
            let reply = claim_rpc.claim_lightning_receive(claim_body).await;
            retained::signed_reply(
                &directory,
                "claim",
                claim.builder,
                &claim.keys,
                reply,
                &claim_hash,
                started,
                retained::now_ns(),
            )
        };
        let (refund, claim) = tokio::join!(refund_future, claim_future);
        (refund?, claim?)
    } else {
        let started = retained::now_ns();
        let reply = rpc.request_lightning_pay_htlc_revocation(refund.body).await;
        let result = retained::signed_reply(
            &directory,
            "refund",
            refund.builder,
            &refund.keys,
            reply,
            &refund_hash,
            started,
            retained::now_ns(),
        )?;
        evidence(
            req,
            "phase_lightning_reply_observed",
            json!({"trial_id":req.args["trial_id"],"reply":result}),
        )?;
        register(rpc, &directory, "refund", &result).await?;
        ensure!(
            result["kind"] == "sdk_signed_successors",
            "no matching complete signed sender refund; claim remains held"
        );
        refund_authorized(&directory, req, &refund.checkpoint, &result).await?;
        let started = retained::now_ns();
        let reply = rpc.claim_lightning_receive(claim_body).await;
        let claimed = retained::signed_reply(
            &directory,
            "claim",
            claim.builder,
            &claim.keys,
            reply,
            &claim_hash,
            started,
            retained::now_ns(),
        )?;
        (result, claimed)
    };
    for (leg, result) in [("refund", &refund_result), ("claim", &claim_result)] {
        retained::save(
            &directory.join(format!("{leg}-public-result.json")),
            &serde_json::to_vec(result)?,
        )?;
        evidence(
            req,
            "phase_lightning_reply_observed",
            json!({"trial_id":req.args["trial_id"],"reply":result}),
        )?;
    }
    if scenario == "D34" {
        register(rpc, &directory, "refund", &refund_result).await?
    }
    register(rpc, &directory, "claim", &claim_result).await?;
    Ok(
        json!({"phase_unknown":true,"actual_fee_sat":Value::Null,"scenario":scenario,"customer_traffic_credit":false,"required_audit":"exact same-hash claim/refund signed successors and current server arbitration; both original SDK checkpoints held; successful SDK receive movement adoption required separately"}),
    )
}

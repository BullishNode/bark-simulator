//! Explicit signet probes against the pinned client protocol; no automatic retry.
//! Request/reply bytes and signer material stay in an actor-private preparation.
use super::{InvariantFailure, Request, evidence, hex};
use anyhow::{Context, Result, bail, ensure};
use ark::arkoor::{ArkoorDestination, package::ArkoorPackageBuilder};
use ark::attestations::{
    Challenge, LightningReceiveAttestation, RoundAttemptAttestation, VtxoStatusAttestation,
};
use ark::lightning::{Bolt11Invoice, Bolt11InvoiceExt, PaymentHash};
use ark::{ProtocolEncoding, SECP, Vtxo, VtxoId, VtxoPolicy};
use bark::{
    Wallet,
    persist::{BarkPersister, sqlite::SqliteClient},
};
use bitcoin::{
    Amount, Network,
    hashes::{Hash, sha256},
    secp256k1::{Keypair, PublicKey, rand},
};
use prost::Message;
use serde_json::{Value, json};
use server_rpc::{
    RequestExt,
    protos::{self, ark_service_client::ArkServiceClient},
};
use std::{
    fs,
    future::Future,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};
use tonic::transport::Channel;

pub const SCENARIOS: &[&str] = &[
    "D13", "D14", "D15", "D16", "D21", "D22", "D23", "D25", "D29", "D30", "D31", "D32", "D35",
];
fn hashed(bytes: &[u8]) -> String {
    sha256::Hash::hash(bytes).to_string()
}
fn millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
}
fn private_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::File::open(path.parent().context("private artifact parent")?)?.sync_all()?;
    Ok(())
}
fn scope(wallet_dir: &Path, req: &Request) -> Result<PathBuf> {
    let parent = wallet_dir.join("private-probes");
    ensure!(
        !parent.is_symlink(),
        "private probe directory cannot be a symlink"
    );
    fs::create_dir_all(&parent)?;
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))?;
    fs::File::open(wallet_dir)?.sync_all()?;
    let path = parent.join(hashed(req.action_id.as_bytes()));
    ensure!(
        !path.is_symlink(),
        "private probe preparation cannot be a symlink"
    );
    Ok(path)
}
fn stage(
    path: &Path,
    req: &Request,
    rpc: &str,
    wire: &[u8],
    secret: Option<&Keypair>,
    extra: Option<&[u8]>,
) -> Result<String> {
    let intent = req
        .args
        .get("probe_intent")
        .or_else(|| req.args.get("rotation_intent"))
        .context("frozen client intent required")?;
    // A directory created before any attempted RPC is a durable once-only fence.
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    let request_hash = hashed(wire);
    private_write(&path.join("request.bin"), wire)?;
    if let Some(key) = secret {
        private_write(
            &path.join("output-key.bin"),
            &key.secret_key().secret_bytes(),
        )?;
    }
    if let Some(bytes) = extra {
        private_write(&path.join("signer-extra.bin"), bytes)?;
    }
    private_write(
        &path.join("intent.json"),
        &serde_json::to_vec(&json!({"utc_unix_ms":millis(),"action_id":req.action_id,
        "actor":intent["actor"],"operation":req.operation,"intent_hash":req.args["intent_hash"],"rpc":rpc,
        "request_hash":request_hash,"protocol_version":if matches!(rpc,"SubmitPayment"|"PrepareLightningReceiveClaim"|"RequestLightningPayHtlcCosign"|"ClaimLightningReceive"){json!(server_rpc::MAX_PROTOCOL_VERSION)}else{Value::Null},"wire_encoding":if rpc.starts_with("SDK."){ "sdk_intent_json" }else{ "protobuf" },"intent":intent,"automatic_retry":false}))?,
    )?;
    fs::File::open(path)?.sync_all()?;
    fs::File::open(path.parent().context("private preparation parent")?)?.sync_all()?;
    evidence(
        req,
        "raw_protocol_request_frozen",
        json!({"rpc":rpc,"request_hash":request_hash,
        "intent_hash":req.args["intent_hash"],"private_preparation_hash":hashed(&serde_json::to_vec(intent)?),
        "rpc_attempted":false,"wire_encoding":if rpc.starts_with("SDK."){ "sdk_intent_json" }else{ "protobuf" },"signer_material_public":false}),
    )?;
    private_write(&path.join("dispatched"), &millis().to_string().into_bytes())?;
    fs::File::open(path)?.sync_all()?;
    Ok(request_hash)
}

async fn observe<T: Message>(
    directory: &Path,
    name: &str,
    wire: &[u8],
    call: impl Future<Output = Result<tonic::Response<T>, tonic::Status>>,
) -> Result<T> {
    let prefix = directory.join(format!(
        "{}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos(),
        name
    ));
    private_write(&prefix.with_extension("request.bin"), wire)?;
    let result = call.await;
    match result {
        Ok(reply) => {
            let value = reply.into_inner();
            private_write(
                &prefix.with_extension("response.bin"),
                &value.encode_to_vec(),
            )?;
            private_write(
                &prefix.with_extension("metadata.json"),
                &serde_json::to_vec(
                    &json!({"utc_unix_ms":millis(),"rpc":name,"code":"Ok","request_hash":hashed(wire),"response_hash":hashed(&value.encode_to_vec())}),
                )?,
            )?;
            Ok(value)
        }
        Err(status) => {
            private_write(
                &prefix.with_extension("error.json"),
                &serde_json::to_vec(
                    &json!({"utc_unix_ms":millis(),"rpc":name,"code":format!("{:?}",status.code()),"message":status.message(),"details_hex":hex(status.details())}),
                )?,
            )?;
            Err(status.into())
        }
    }
}

fn blocked(reason: &str) -> Value {
    json!({"blocked":true,"reason":reason,"actual_fee_sat":0,"production_qualified":false})
}
async fn statuses(
    wallet: &Wallet,
    rpc: &mut ArkServiceClient<Channel>,
    inputs: &[Vtxo],
    observations: &Path,
) -> Result<Vec<i32>> {
    let mut result = Vec::new();
    for coin in inputs {
        let key = wallet.get_vtxo_key(coin).await?;
        let attestation = VtxoStatusAttestation::new(coin.id(), &key);
        let body = protos::GetVtxoStatusRequest {
            vtxo_id: coin.id().to_bytes().to_vec(),
            attestation: attestation.serialize(),
        };
        result.push(
            observe(
                observations,
                "GetVtxoStatus",
                &body.encode_to_vec(),
                rpc.get_vtxo_status(body.clone()),
            )
            .await?
            .spend_state,
        );
    }
    Ok(result)
}
fn package(
    inputs: Vec<Vtxo>,
    outputs: Vec<ArkoorDestination>,
    keys: &[Keypair],
) -> Result<ark::arkoor::package::ArkoorPackageBuilder<ark::arkoor::state::UserGeneratedNonces>> {
    Ok(ArkoorPackageBuilder::new_with_checkpoints(inputs, outputs)?.generate_user_nonces(keys)?)
}
fn refusal<T: Message>(
    path: &Path,
    scenario: &str,
    rpc: &str,
    result: Result<tonic::Response<T>, tonic::Status>,
    key: &str,
) -> Result<(String, String, String, String)> {
    let (code, message, response_hash) = match result {
        Ok(reply) => {
            let bytes = reply.into_inner().encode_to_vec();
            private_write(&path.join("response.bin"), &bytes)?;
            (String::from("Ok"), String::new(), hashed(&bytes))
        }
        Err(status) => {
            let bytes = serde_json::to_vec(&json!({"utc_unix_ms":millis(),
            "code":format!("{:?}",status.code()),"message":status.message(),"details_hex":hex(status.details())}))?;
            private_write(&path.join("response-error.json"), &bytes)?;
            (
                format!("{:?}", status.code()),
                status.message().to_owned(),
                hashed(&bytes),
            )
        }
    };
    let guard = super::raw_guard::classify(scenario, rpc, &code, &message, key).to_string();
    Ok((code, guard, hashed(message.as_bytes()), response_hash))
}

pub async fn execute(
    wallet: &Wallet,
    db: &Arc<SqliteClient>,
    rpc: &mut ArkServiceClient<Channel>,
    req: &Request,
    wallet_dir: &Path,
    actor: &str,
) -> Result<Value> {
    ensure!(
        wallet.network().await? == Network::Signet,
        "new raw probes require signet; unit checks never qualify production"
    );
    ensure!(
        !matches!(actor, "actor-03" | "actor-09" | "actor-10"),
        "original absent wallet must stay closed"
    );
    let scenario = req.args["probe_intent"]["scenario"]
        .as_str()
        .context("frozen scenario required")?;
    ensure!(
        SCENARIOS.contains(&scenario)
            && req.operation == format!("raw_protocol_{}", scenario.to_lowercase()),
        "probe scenario/operation differs"
    );
    ensure!(
        req.args["probe_intent"]["actor"] == actor
            && req.args["probe_intent"]["server_pubkey"] == req.expected_server_pubkey,
        "probe actor/server pin differs"
    );
    ensure!(
        req.args["probe_intent"]["maximum_fee_sat"].as_u64() == Some(req.maximum_fee_sat)
            && req.maximum_fee_sat <= 2000,
        "probe fee declaration differs"
    );
    ensure!(
        hashed(&serde_json::to_vec(&req.args["probe_intent"])?)
            == req.args["intent_hash"]
                .as_str()
                .context("intent hash required")?,
        "frozen intent digest differs"
    );
    let path = scope(wallet_dir, req)?;
    if path.exists() {
        return Ok(
            json!({"probe_unknown":true,"reason":"retained private preparation exists; read-only reconciliation required; no RPC retry","actual_fee_sat":Value::Null}),
        );
    }
    let observation_root = path.parent().context("probe parent")?.join("observations");
    ensure!(
        !observation_root.is_symlink(),
        "private observation parent cannot be a symlink"
    );
    fs::create_dir_all(&observation_root)?;
    fs::set_permissions(&observation_root, fs::Permissions::from_mode(0o700))?;
    let observations = observation_root.join(hashed(req.action_id.as_bytes()));
    ensure!(
        !observations.is_symlink(),
        "private observation directory cannot be a symlink"
    );
    fs::create_dir_all(&observations)?;
    fs::set_permissions(&observations, fs::Permissions::from_mode(0o700))?;
    let mailbox = wallet.mailbox_keypair().public_key();
    let baseline = protos::SetFallbackRequest {
        mailbox_pk: mailbox.serialize().to_vec(),
        record: None,
        key_links: vec![],
    };
    let baseline = observe(
        &observations,
        "SetFallbackRead",
        &baseline.encode_to_vec(),
        rpc.set_fallback(baseline.clone()),
    )
    .await?;
    let protected_record =
        json!({"mailbox_pk":mailbox.to_string(),"serialized":hex(&baseline.record)});
    let frozen = req.args["probe_intent"]["inputs"]
        .as_array()
        .context("frozen inputs required")?;
    ensure!(
        !frozen.is_empty() && frozen.len() <= 16,
        "probe input bound"
    );
    let mut inputs = Vec::new();
    let mut keys = Vec::new();
    for item in frozen {
        let id = VtxoId::from_str(item["coin_id"].as_str().context("input id")?)?;
        let coin = if item["owner"] == actor {
            wallet.get_full_vtxo(id).await?
        } else {
            ensure!(scenario == "D25", "foreign input cannot fund a probe");
            let body = protos::GetVtxoRequest {
                vtxo_id: id.to_bytes().to_vec(),
            };
            let bytes = observe(
                &observations,
                "GetVtxo",
                &body.encode_to_vec(),
                rpc.get_vtxo(body.clone()),
            )
            .await?
            .vtxo;
            Vtxo::deserialize(&bytes)?
        };
        ensure!(
            coin.id() == id
                && coin.amount().to_sat() == item["amount_sat"].as_u64().context("input amount")?
                && coin.user_pubkey().to_string()
                    == item["pubkey"].as_str().context("input key")?
                && hashed(&coin.serialize())
                    == item["signed_hash"].as_str().context("signed input hash")?,
            "native input differs from frozen public proof"
        );
        if item["owner"] == actor {
            keys.push(wallet.get_vtxo_key(&coin).await?);
        }
        inputs.push(coin);
    }
    // Foreign-registration mutation has no spend. Its public owner state is
    // independently checked by the inventory collector, not forged signatures.
    let before = if scenario == "D25" {
        vec![-1; inputs.len()]
    } else {
        statuses(wallet, rpc, &inputs, &observations).await?
    };
    if matches!(scenario, "D13" | "D14" | "D16" | "D23") && before.iter().any(|v| *v != 1) {
        return Ok(blocked("actual input status is not Spendable"));
    }
    let amount = inputs.iter().try_fold(0u64, |sum, v| {
        sum.checked_add(v.amount().to_sat())
            .context("input overflow")
    })?;
    ensure!(
        amount
            == req.args["probe_intent"]["input_amount_sat"]
                .as_u64()
                .context("frozen principal")?,
        "native principal differs"
    );
    let ephemeral = Keypair::new(&SECP, &mut rand::thread_rng());
    let unlinked = ephemeral.public_key();
    let mut key_string = unlinked.to_string();
    let name: String;
    let request_hash: String;
    let outcome: (String, String, String, String);
    match scenario {
        "D13" => {
            name = "SubmitPayment".into();
            let info = wallet.require_ark_info().await?;
            ensure!(
                info.nb_round_nonces > 0 && info.nb_round_nonces <= 128,
                "round nonce bound"
            );
            let mut nonces = Vec::new();
            let mut secret_nonces = Vec::new();
            for _ in 0..info.nb_round_nonces {
                let (secret, public) = ark::musig::nonce_pair(&ephemeral);
                nonces.push(public);
                secret_nonces
                    .push(ark::musig::DangerousSecretNonce::dangerous_from_secret_nonce(secret));
            }
            let output = ark::SignedVtxoRequest {
                vtxo: ark::VtxoRequest {
                    amount: Amount::from_sat(amount),
                    policy: VtxoPolicy::new_pubkey(unlinked),
                },
                cosign_pubkey: unlinked,
                nonces,
            };
            let event = observe(
                &observations,
                "LastRoundEvent",
                &[],
                rpc.last_round_event(protos::Empty {}),
            )
            .await?;
            let challenge = match event.event {
                Some(protos::round_event::Event::Attempt(a)) => Challenge::new(
                    a.round_attempt_challenge
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("round challenge length"))?,
                ),
                _ => {
                    return Ok(blocked(
                        "actual interactive round attempt/challenge unavailable",
                    ));
                }
            };
            let outputs = vec![output];
            let mut signed_inputs = Vec::new();
            for (coin, key) in inputs.iter().zip(&keys) {
                signed_inputs.push(protos::InputVtxo {
                    vtxo_id: coin.id().to_bytes().to_vec(),
                    attestation: RoundAttemptAttestation::new(challenge, coin.id(), &outputs, key)
                        .serialize(),
                });
            }
            #[allow(deprecated)]
            let body = protos::SubmitPaymentRequest {
                input_vtxos: signed_inputs,
                vtxo_requests: outputs.into_iter().map(Into::into).collect(),
                offboard_requests: vec![],
                unblinded_mailbox_id: None,
            };
            request_hash = stage(
                &path,
                req,
                &name,
                &body.encode_to_vec(),
                Some(&ephemeral),
                Some(&serde_json::to_vec(&secret_nonces)?),
            )?;
            let mut body = tonic::Request::new(body);
            body.set_pver(server_rpc::MAX_PROTOCOL_VERSION);
            outcome = refusal(
                &path,
                scenario,
                &name,
                rpc.submit_payment(body).await,
                &key_string,
            )?;
        }
        "D14" | "D16" | "D21" => {
            let outputs = if scenario == "D16" {
                let hash = PaymentHash::from_str(
                    req.args["payment_hash"]
                        .as_str()
                        .context("actual invoice payment hash required")?,
                )?;
                let htlc_amount = req.args["htlc_amount_sat"]
                    .as_u64()
                    .context("frozen HTLC principal required")?;
                let invoice = Bolt11Invoice::from_str(
                    req.args["original_invoice"]
                        .as_str()
                        .context("original immutable invoice required")?,
                )?;
                ensure!(
                    PaymentHash::from(&invoice) == hash
                        && invoice.get_payment_amount(None)?.to_sat() == htlc_amount,
                    "actual invoice hash/principal differs"
                );
                ensure!(
                    htlc_amount >= 330 && amount.checked_sub(htlc_amount).is_some_and(|c| c >= 330),
                    "actual HTLC and change must both be non-dust"
                );
                let info = wallet.require_ark_info().await?;
                let expiry = wallet
                    .chain()
                    .tip()
                    .await?
                    .checked_add(info.htlc_send_expiry_delta)
                    .context("HTLC expiry overflow")?;
                vec![
                    ArkoorDestination {
                        total_amount: Amount::from_sat(htlc_amount),
                        policy: VtxoPolicy::new_server_htlc_send(
                            inputs[0].user_pubkey(),
                            hash,
                            expiry,
                        ),
                    },
                    ArkoorDestination {
                        total_amount: Amount::from_sat(amount - htlc_amount),
                        policy: VtxoPolicy::new_pubkey(unlinked),
                    },
                ]
            } else {
                vec![ArkoorDestination {
                    total_amount: Amount::from_sat(amount),
                    policy: VtxoPolicy::new_pubkey(if scenario == "D21" {
                        inputs[0].user_pubkey()
                    } else {
                        unlinked
                    }),
                }]
            };
            if scenario == "D21" {
                key_string = inputs[0].user_pubkey().to_string();
            }
            let builder = package(inputs.clone(), outputs, &keys)?;
            let body = protos::ArkoorPackageCosignRequest::from(builder.cosign_request());
            if scenario == "D16" {
                name = "RequestLightningPayHtlcCosign".into();
                let body = protos::LightningPayHtlcCosignRequest { parts: body.parts };
                request_hash = stage(
                    &path,
                    req,
                    &name,
                    &body.encode_to_vec(),
                    Some(&ephemeral),
                    None,
                )?;
                let mut body = tonic::Request::new(body);
                body.set_pver(server_rpc::MAX_PROTOCOL_VERSION);
                outcome = refusal(
                    &path,
                    scenario,
                    &name,
                    rpc.request_lightning_pay_htlc_cosign(body).await,
                    &key_string,
                )?;
            } else {
                name = "RequestArkoorCosign".into();
                request_hash = stage(
                    &path,
                    req,
                    &name,
                    &body.encode_to_vec(),
                    Some(&ephemeral),
                    None,
                )?;
                outcome = refusal(
                    &path,
                    scenario,
                    &name,
                    rpc.request_arkoor_cosign(body).await,
                    &key_string,
                )?;
            }
            // A positive surprise remains fenced. The immutable destinations,
            // full input proofs and private output key survive for reconciliation.
        }
        "D22" | "D23" | "D25" => {
            name = "RegisterVtxoTransactions".into();
            key_string.clear();
            let mut bytes = inputs[0].serialize();
            if scenario == "D23" {
                bytes.pop().context("signed chain must be nonempty")?;
            }
            if scenario == "D25" {
                ensure!(
                    inputs.len() == 2 && frozen[0]["owner"] == actor && frozen[1]["owner"] != actor,
                    "two independent owners required"
                );
                let foreign = inputs
                    .iter()
                    .position(|v| v.user_pubkey() != inputs[0].user_pubkey())
                    .context("independent foreign policy required")?;
                let coin = &inputs[foreign];
                let changed = Vtxo::new(
                    coin.point(),
                    VtxoPolicy::new_pubkey(inputs[0].user_pubkey()),
                    coin.amount(),
                    coin.expiry_height(),
                    coin.server_pubkey(),
                    coin.exit_delta(),
                    coin.chain_anchor(),
                );
                bytes = changed.serialize();
                ensure!(bytes.pop() == Some(0), "SDK bare genesis marker differs");
                bytes.extend(coin.serialize_genesis());
            }
            let body = protos::RegisterVtxoTransactionsRequest {
                vtxos: if scenario == "D25" {
                    vec![inputs[0].serialize(), bytes]
                } else {
                    vec![bytes]
                },
            };
            request_hash = stage(&path, req, &name, &body.encode_to_vec(), None, None)?;
            outcome = refusal(
                &path,
                scenario,
                &name,
                rpc.register_vtxo_transactions(body).await,
                "",
            )?;
        }
        "D15" | "D35" => {
            name = "PrepareLightningReceiveClaim".into();
            let hash = PaymentHash::from_str(
                req.args["payment_hash"]
                    .as_str()
                    .context("existing receive hash required")?,
            )?;
            let query = protos::CheckLightningReceiveRequest {
                hash: hash.to_vec(),
                wait: false,
            };
            let node = observe(
                &observations,
                "CheckLightningReceive",
                &query.encode_to_vec(),
                rpc.check_lightning_receive(query.clone()),
            )
            .await?;
            if node.status != protos::LightningReceiveStatus::Accepted as i32 {
                return Ok(blocked("actual receive is not Accepted before grant"));
            }
            let cp = wallet
                .lightning_receive_checkpoint(hash)
                .await?
                .context("retained actual receive checkpoint required")?;
            ensure!(cp.payment_hash == hash, "receive checkpoint differs");
            let tip = wallet.chain().tip().await?;
            if inputs[0]
                .expiry_height()
                .to_u32()
                .saturating_sub(tip.to_u32())
                <= 2
            {
                return Ok(blocked(
                    "ownership anti-DoS proof lacks actual SDK expiry margin",
                ));
            }
            let anti =
                protos::prepare_lightning_receive_claim_request::LightningReceiveAntiDos::InputVtxo(
                    protos::InputVtxo {
                        vtxo_id: inputs[0].id().to_bytes().to_vec(),
                        attestation: LightningReceiveAttestation::new(
                            hash,
                            inputs[0].id(),
                            &keys[0],
                        )
                        .serialize(),
                    },
                );
            let key = if scenario == "D15" {
                unlinked
            } else {
                wallet.peek_keypair(cp.key_index).await?.public_key()
            };
            key_string = key.to_string();
            let info = wallet.require_ark_info().await?;
            let expiry = if scenario == "D35" {
                u32::MAX
            } else {
                tip.checked_add(cp.htlc_recv_cltv_delta)
                    .context("receive expiry overflow")?
                    .to_u32()
            };
            let body = protos::PrepareLightningReceiveClaimRequest {
                payment_hash: hash.to_vec(),
                user_pubkey: key.serialize().to_vec(),
                htlc_recv_expiry: expiry,
                lightning_receive_anti_dos: Some(anti),
            };
            request_hash = stage(
                &path,
                req,
                &name,
                &body.encode_to_vec(),
                Some(&ephemeral),
                None,
            )?;
            let mut body = tonic::Request::new(body);
            body.set_pver(server_rpc::MAX_PROTOCOL_VERSION);
            outcome = refusal(
                &path,
                scenario,
                &name,
                rpc.prepare_lightning_receive_claim(body).await,
                &key_string,
            )?;
            let _ = info; // Actual runtime queried; no guessed target expiry/fee setting.
        }
        "D29" | "D30" => {
            name = "RequestLightningPayHtlcRevocation".into();
            key_string.clear();
            let hash = PaymentHash::from_str(
                req.args["payment_hash"]
                    .as_str()
                    .context("retained send hash required")?,
            )?;
            let query = protos::CheckLightningPaymentRequest {
                hash: hash.to_vec(),
                wait: false,
            };
            let node = observe(
                &observations,
                "CheckLightningPayment",
                &query.encode_to_vec(),
                rpc.check_lightning_payment(query.clone()),
            )
            .await?;
            let correct = match node.payment_status {
                Some(protos::lightning_payment_status::PaymentStatus::Success(s)) => {
                    ensure!(
                        sha256::Hash::hash(&s.preimage).to_byte_array() == hash.to_byte_array(),
                        "node returned wrong preimage hash"
                    );
                    scenario == "D29"
                }
                Some(protos::lightning_payment_status::PaymentStatus::Pending(_)) => {
                    scenario == "D30"
                }
                _ => false,
            };
            if !correct {
                return Ok(blocked(
                    "actual same-hash node outcome does not match paid/pending probe",
                ));
            }
            ensure!(
                inputs.iter().all(|v| v
                    .policy()
                    .as_server_htlc_send()
                    .is_some_and(|p| p.payment_hash == hash)),
                "refund inputs are not the original same-hash HTLCs"
            );
            let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints(
                inputs.clone(),
                VtxoPolicy::new_pubkey(inputs[0].user_pubkey()),
            )?
            .generate_user_nonces(&keys)?;
            let body = protos::ArkoorPackageCosignRequest::from(builder.cosign_request());
            request_hash = stage(&path, req, &name, &body.encode_to_vec(), None, None)?;
            outcome = refusal(
                &path,
                scenario,
                &name,
                rpc.request_lightning_pay_htlc_revocation(body).await,
                "",
            )?;
        }
        "D31" | "D32" => {
            name = "ClaimLightningReceive".into();
            key_string.clear();
            let hash = PaymentHash::from_str(
                req.args["payment_hash"]
                    .as_str()
                    .context("retained receive hash required")?,
            )?;
            let query = protos::CheckLightningReceiveRequest {
                hash: hash.to_vec(),
                wait: false,
            };
            let node = observe(
                &observations,
                "CheckLightningReceive",
                &query.encode_to_vec(),
                rpc.check_lightning_receive(query.clone()),
            )
            .await?;
            let expected = if scenario == "D31" {
                protos::LightningReceiveStatus::Settled
            } else {
                protos::LightningReceiveStatus::HtlcsReady
            };
            if node.status != expected as i32 {
                return Ok(blocked(
                    "actual receive not at exact replay/wrong-preimage checkpoint",
                ));
            }
            ensure!(
                inputs.iter().all(|v| v
                    .policy()
                    .as_server_htlc_recv()
                    .is_some_and(|p| p.payment_hash == hash)),
                "claim inputs differ from original receive HTLC hash"
            );
            let mut node_ids = node
                .htlc_vtxos
                .iter()
                .map(|v| VtxoId::from_slice(v).map_err(anyhow::Error::from))
                .collect::<Result<Vec<_>>>()?;
            let mut input_ids = inputs.iter().map(|v| v.id()).collect::<Vec<_>>();
            node_ids.sort();
            input_ids.sort();
            ensure!(
                node_ids == input_ids,
                "server grant differs from frozen original HTLC input identities"
            );
            let declared = PublicKey::from_str(
                req.args["original_destination_pubkey"]
                    .as_str()
                    .context("original immutable receive destination required")?,
            )?;
            let policy = if scenario == "D32" {
                let cp = wallet
                    .lightning_receive_checkpoint(hash)
                    .await?
                    .context("original claim checkpoint missing")?;
                let original = if let Some(destination) = cp.claim_destination.as_ref() {
                    destination.policy().clone()
                } else {
                    VtxoPolicy::new_pubkey(wallet.peek_keypair(cp.key_index).await?.public_key())
                };
                ensure!(
                    original.user_pubkey() == declared,
                    "claim destination differs from actual retained SDK checkpoint"
                );
                original
            } else {
                VtxoPolicy::new_pubkey(declared)
            };
            let mut ordered = inputs.clone();
            ordered.sort_by_key(|v| v.id());
            let mut ordered_keys = Vec::new();
            for coin in &ordered {
                ordered_keys.push(wallet.get_vtxo_key(coin).await?);
            }
            let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints(ordered, policy)?
                .generate_user_nonces(&ordered_keys)?;
            if scenario == "D31" {
                let mut predicted = builder
                    .build_unsigned_vtxos()
                    .map(|v| v.id().to_string())
                    .collect::<Vec<_>>();
                predicted.sort();
                let mut original = req.args["original_output_coin_ids"]
                    .as_array()
                    .context("original signed output IDs missing")?
                    .iter()
                    .map(|v| v.as_str().map(String::from).context("output ID type"))
                    .collect::<Result<Vec<_>>>()?;
                original.sort();
                ensure!(
                    predicted == original,
                    "replay changes original unsigned transaction outputs"
                );
            }
            let preimage = if scenario == "D31" {
                db.get_settled_lightning_receive(hash)
                    .await?
                    .context("original private settled receive record required")?
                    .preimage
                    .to_vec()
            } else {
                let mut guess = vec![0u8; 32];
                if sha256::Hash::hash(&guess).to_byte_array() == hash.to_byte_array() {
                    guess[0] = 1;
                }
                guess
            };
            let body = protos::ClaimLightningReceiveRequest {
                payment_hash: hash.to_vec(),
                payment_preimage: preimage,
                cosign_request: Some(protos::ArkoorPackageCosignRequest::from(
                    builder.cosign_request(),
                )),
            };
            request_hash = stage(&path, req, &name, &body.encode_to_vec(), None, None)?;
            let mut body = tonic::Request::new(body);
            body.set_pver(server_rpc::MAX_PROTOCOL_VERSION);
            outcome = refusal(
                &path,
                scenario,
                &name,
                rpc.claim_lightning_receive(body).await,
                "",
            )?;
        }
        _ => bail!("missing native adapter"),
    }
    let after = if scenario == "D25" {
        vec![-1; inputs.len()]
    } else {
        statuses(wallet, rpc, &inputs, &observations).await?
    };
    private_write(
        &path.join("observations.json"),
        &serde_json::to_vec(
            &json!({"utc_unix_ms":millis(),"before":before,"after":after,"code":outcome.0,"guard":outcome.1}),
        )?,
    )?;
    let actual_fee = if matches!(outcome.1.as_str(), "other" | "unexpected_acceptance") {
        Value::Null
    } else {
        json!(0)
    };
    let data = json!({"probe":{"schema_version":1,"scenario":scenario,"actor":actor,"intent_hash":req.args["intent_hash"],
        "request_hash":request_hash,"rpc":name,"code":outcome.0,"guard":outcome.1,"response_message_hash":outcome.2,"response_hash":outcome.3,
        "attempted_key_pubkeys":if key_string.is_empty(){vec![]}else{vec![key_string.clone()]},"input_coin_ids":frozen.iter().map(|i|i["coin_id"].clone()).collect::<Vec<_>>(),
        "input_status_before":before,"input_status_after":after,"rpc_attempted":true,"actual_fee_sat":actual_fee,
        "client_owner_verified":false,"production_qualified":false},"actual_fee_sat":actual_fee,
        "expected_refusal":!matches!(scenario,"D22"|"D31")&&outcome.1!="other"&&outcome.1!="unexpected_acceptance",
        "protected_record":protected_record,"attempted_key_pubkeys":if key_string.is_empty(){vec![]}else{vec![key_string.clone()]},
        "scope":"native protocol observation only; independent state/binding/chain/liability checks still pending"});
    evidence(req, "raw_protocol_response", data["probe"].clone())?;
    if outcome.1 == "unexpected_acceptance" || before != after {
        return Err(InvariantFailure("negative protocol probe accepted or changed protected input; private preparation retained").into());
    }
    if outcome.1 == "other" {
        return Ok(
            json!({"probe_unknown":true,"data":data,"actual_fee_sat":Value::Null,"reason":"actual intended guard not observed; no automatic retry"}),
        );
    }
    Ok(data)
}

/// Rotate a declared script through the SDK only. Inner SDK RPC capture remains
/// a named gate; the intent and actual public readbacks are captured separately.
pub async fn rotate(
    wallet: &Wallet,
    rpc: &mut ArkServiceClient<Channel>,
    req: &Request,
    wallet_dir: &Path,
    actor: &str,
) -> Result<Value> {
    ensure!(
        wallet.network().await? == Network::Signet
            && !matches!(actor, "actor-03" | "actor-09" | "actor-10"),
        "rotation requires an online signet owner"
    );
    let intent = &req.args["rotation_intent"];
    ensure!(
        intent["actor"] == actor
            && intent["server_pubkey"] == req.expected_server_pubkey
            && req.maximum_fee_sat == 0,
        "rotation actor/server/fee declaration differs"
    );
    ensure!(
        hashed(&serde_json::to_vec(intent)?)
            == req.args["intent_hash"]
                .as_str()
                .context("rotation intent hash")?,
        "rotation intent digest differs"
    );
    let path = scope(wallet_dir, req)?;
    if path.exists() {
        return Ok(
            json!({"probe_unknown":true,"actual_fee_sat":Value::Null,"reason":"retained rotation preparation exists; read-only reconciliation required"}),
        );
    }
    let text = intent["new_script"]
        .as_str()
        .context("declared destination script")?;
    ensure!(
        text.len() % 2 == 0 && text.len() <= 84 && text.bytes().all(|b| b.is_ascii_hexdigit()),
        "destination script encoding bound"
    );
    let bytes = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let script = bitcoin::ScriptBuf::from_bytes(bytes);
    let onchain = wallet
        .onchain()
        .context("rotation requires the owned onchain wallet")?;
    ensure!(
        onchain.read().await.is_mine(&script).await?,
        "declared fallback script is not seed-owned"
    );
    let before = wallet.fallback_destination().await?;
    ensure!(
        hex(before.spk.as_bytes()) == intent["old_script"].as_str().context("original script")?
            && Some(before.seq) == intent["old_sequence"].as_u64(),
        "actual SDK fallback differs from frozen original record"
    );
    ensure!(script != before.spk, "new fallback script equals original");
    let observations = path
        .parent()
        .context("rotation parent")?
        .join("rotation-observations");
    ensure!(
        !observations.is_symlink(),
        "rotation observation directory cannot be a symlink"
    );
    fs::create_dir_all(&observations)?;
    fs::set_permissions(&observations, fs::Permissions::from_mode(0o700))?;
    let mailbox = wallet.mailbox_keypair().public_key();
    ensure!(
        mailbox.to_string() == intent["mailbox"].as_str().context("original mailbox")?,
        "rotation mailbox differs"
    );
    let query = protos::SetFallbackRequest {
        mailbox_pk: mailbox.serialize().to_vec(),
        record: None,
        key_links: vec![],
    };
    let baseline = observe(
        &observations,
        "SetFallbackRead",
        &query.encode_to_vec(),
        rpc.set_fallback(query.clone()),
    )
    .await?;
    let intent_hash = stage(
        &path,
        req,
        "SDK.set_fallback_destination",
        &serde_json::to_vec(intent)?,
        None,
        None,
    )?;
    // The pinned SDK persists the proposed owned destination before registration
    // and bounds its reconciliation loop at three requests. Never reserve a new
    // address or repeat this method after a lost reply.
    let registered = wallet.set_fallback_destination(script.clone()).await;
    private_write(
        &path.join("sdk-operation.json"),
        &serde_json::to_vec(
            &json!({"utc_unix_ms":millis(),"sdk_method":"set_fallback_destination","ok":registered.is_ok(),"error":registered.as_ref().err().map(|e|format!("{e:#}")),"raw_inner_rpc_capture":"unavailable"}),
        )?,
    )?;
    registered?;
    let after = wallet.fallback_destination().await?;
    private_write(
        &path.join("sdk-after-state.json"),
        &serde_json::to_vec(
            &json!({"utc_unix_ms":millis(),"script":hex(after.spk.as_bytes()),"sequence":after.seq}),
        )?,
    )?;
    ensure!(
        after.spk == script && after.seq > before.seq,
        InvariantFailure("rotation SDK returned another script or non-increasing sequence")
    );
    let reply = observe(
        &observations,
        "SetFallbackRead",
        &query.encode_to_vec(),
        rpc.set_fallback(query.clone()),
    )
    .await?;
    private_write(
        &path.join("sdk-result.json"),
        &serde_json::to_vec(
            &json!({"utc_unix_ms":millis(),"before_record":hex(&baseline.record),"after_record":hex(&reply.record),"old_sequence":before.seq,"new_sequence":after.seq}),
        )?,
    )?;
    let result = json!({"rotation_intent_hash":intent_hash,"mailbox_pk":mailbox.to_string(),"old_script":hex(before.spk.as_bytes()),"old_sequence":before.seq,"new_script":hex(after.spk.as_bytes()),"new_sequence":after.seq,"record_before_hash":hashed(&baseline.record),"record_after_hash":hashed(&reply.record),"actual_fee_sat":0,"production_qualified":false,"raw_sdk_registration_capture":"unavailable","scope":"SDK-owned record rotation; original payout immutability and later-coin payout still require independent evidence"});
    evidence(req, "fallback_rotation_registered", result.clone())?;
    Ok(result)
}

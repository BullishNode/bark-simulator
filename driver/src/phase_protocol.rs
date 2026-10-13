//! Genuine phase trials; opaque SDK nonces never leave their signing process.
//! Each submitted wire request is frozen before submission. Reopening a fence
//! holds the outcome unknown; it never regenerates nonces or retries a spend.
use super::{Request, evidence, hex};
use anyhow::{Context, Result, ensure};
use ark::arkoor::{
    ArkoorDestination,
    package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse},
    state,
};
use ark::{ProtocolEncoding, Vtxo, VtxoId, VtxoPolicy};
use bark::Wallet;
use bitcoin::{
    Amount, Network,
    hashes::{Hash, sha256},
    secp256k1::{Keypair, PublicKey},
};
use prost::Message;
use serde_json::{Value, json};
use server_rpc::{
    StatusExt,
    protos::{self, ark_service_client::ArkServiceClient},
};
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    str::FromStr,
};
use tonic::transport::Channel;

type Prepared = ArkoorPackageBuilder<state::UserGeneratedNonces>;
fn hash(bytes: &[u8]) -> String {
    sha256::Hash::hash(bytes).to_string()
}
fn now() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
}
fn save(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::File::open(path.parent().context("private phase parent")?)?.sync_all()?;
    Ok(())
}
fn intent(req: &Request, scenario: &str) -> Result<Value> {
    let mut frozen = req.args["phase_intent"].clone();
    let map = frozen
        .as_object_mut()
        .context("frozen phase intent missing")?;
    map.remove("intent_hash");
    ensure!(
        frozen["scenario"] == scenario
            && frozen["network"] == "signet"
            && frozen["server_pubkey"] == req.expected_server_pubkey,
        "phase scope/pin differs"
    );
    ensure!(
        hash(&serde_json::to_vec(&frozen)?)
            == req.args["intent_hash"]
                .as_str()
                .context("intent digest missing")?,
        "phase intent changed"
    );
    ensure!(
        req.args["qualification_manifest_sha256"]
            .as_str()
            .is_some_and(|s| s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit())),
        "qualified SDK manifest missing"
    );
    ensure!(
        frozen["maximum_fee_sat"].as_u64() == Some(req.maximum_fee_sat)
            && req.maximum_fee_sat <= 2000,
        "phase whole-trial fee cap differs"
    );
    Ok(frozen)
}
fn fence(root: &Path, req: &Request) -> Result<Option<PathBuf>> {
    ensure!(!root.is_symlink(), "private phase parent is symlink");
    fs::create_dir_all(root)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    let path = root.join(hash(req.action_id.as_bytes()));
    ensure!(!path.is_symlink(), "phase fence is symlink");
    match fs::create_dir(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    save(
        &path.join("intent.json"),
        &serde_json::to_vec(
            &json!({"utc_unix_ms":now(),"action_id":req.action_id,"intent":req.args["phase_intent"],"manifest_sha256":req.args["qualification_manifest_sha256"],"automatic_retry":false}),
        )?,
    )?;
    fs::File::open(root)?.sync_all()?;
    Ok(Some(path))
}
fn unknown() -> Value {
    json!({"phase_unknown":true,"reason":"existing immutable phase fence; reconcile independently; no retry","actual_fee_sat":Value::Null,"customer_traffic_credit":false})
}
fn body_checkpoint(
    builder: &Prepared,
    body: &protos::ArkoorPackageCosignRequest,
    leg: &str,
    input_ids: &[String],
) -> Value {
    json!({"leg_id":leg,"rpc":"RequestArkoorCosign","input_coin_ids":input_ids,
        "wire_sha256":hash(&body.encode_to_vec()),"private_checkpoint_sha256":hash(&body.encode_to_vec()),
        "nonce_retention":"single_process","signing_session_sha256":hash(&serde_json::to_vec(&builder.cosign_request().requests.iter().map(|r|r.user_pub_nonces.iter().map(|n|hex(&n.serialize())).collect::<Vec<_>>()).collect::<Vec<_>>()).unwrap()),
        "restart_continuation":false,"input_spends":builder.input_spend_info().map(|(id,txid)|json!({"coin_id":id.to_string(),"txid":txid.to_string()})).collect::<Vec<_>>(),
        "outputs":builder.build_unsigned_vtxos().map(|v|json!({"coin_id":v.id().to_string(),"pubkey":v.user_pubkey().to_string(),"amount_sat":v.amount().to_sat()})).collect::<Vec<_>>()})
}
fn signed_reply(
    directory: &Path,
    leg: &str,
    builder: Prepared,
    keys: &[Keypair],
    reply: Result<tonic::Response<protos::ArkoorPackageCosignResponse>, tonic::Status>,
    wire_hash: &str,
) -> Result<Value> {
    match reply {
        Ok(response) => {
            let response = response.into_inner();
            let bytes = response.encode_to_vec();
            save(&directory.join(format!("{leg}-response.bin")), &bytes)?;
            let signed = builder
                .user_cosign(keys, ArkoorPackageCosignResponse::try_from(response)?)?
                .build_signed_vtxos();
            let mut outputs = Vec::new();
            for (index, coin) in signed.into_iter().enumerate() {
                let bytes = coin.serialize();
                save(&directory.join(format!("{leg}-signed-{index}.bin")), &bytes)?;
                ensure!(
                    coin.has_all_witnesses(),
                    "completed successor is missing witnesses"
                );
                outputs.push(json!({"id":coin.id().to_string(),"pubkey":coin.user_pubkey().to_string(),"amount_sat":coin.amount().to_sat(),"signed_vtxo":hex(&bytes),"signed_hash":hash(&bytes)}));
            }
            Ok(
                json!({"leg_id":leg,"kind":"sdk_signed_successors","wire_sha256":wire_hash,"response_sha256":hash(&bytes),"outputs":outputs,"independent_proof_required":true}),
            )
        }
        Err(status) => {
            // Status code/message alone never prove money stayed untouched.
            let bytes = serde_json::to_vec(
                &json!({"utc_unix_ms":now(),"code":format!("{:?}",status.code()),"message":status.message(),"details_hex":hex(status.details())}),
            )?;
            save(
                &directory.join(format!("{leg}-response-error.json")),
                &bytes,
            )?;
            Ok(
                json!({"leg_id":leg,"kind":if status.is_rejection(){"protocol_refusal"}else{"transport_unknown"},"wire_sha256":wire_hash,"response_sha256":hash(&bytes),"code":format!("{:?}",status.code()),"rejected_coin_ids":status.rejected_vtxos().iter().map(|id|id.to_string()).collect::<Vec<_>>(),"error_message_sha256":hash(status.message().as_bytes()),"independent_proof_required":true}),
            )
        }
    }
}

pub async fn race_arkoor(
    wallet: &Wallet,
    rpc: &mut ArkServiceClient<Channel>,
    req: &Request,
    private_root: &Path,
    actor: &str,
) -> Result<Value> {
    let frozen = intent(req, "D17")?;
    ensure!(
        req.operation == "phase_execute_d17"
            && wallet.network().await? == Network::Signet
            && frozen["actor"] == actor
            && !matches!(actor, "actor-03" | "actor-09" | "actor-10"),
        "phase cannot open absent or foreign actor"
    );
    let Some(directory) = fence(private_root, req)? else {
        return Ok(unknown());
    };
    let items = frozen["inputs"].as_array().context("frozen inputs")?;
    ensure!(!items.is_empty() && items.len() <= 16, "phase input bound");
    let mut inputs = Vec::new();
    let mut keys = Vec::new();
    for item in items {
        let id = VtxoId::from_str(item["coin_id"].as_str().context("input ID")?)?;
        let coin = wallet.get_full_vtxo(id).await?;
        ensure!(
            coin.id() == id
                && hash(&coin.serialize())
                    == item["signed_hash"].as_str().context("signed hash")?
                && coin.amount().to_sat() == item["amount_sat"].as_u64().context("amount")?
                && coin.user_pubkey().to_string()
                    == item["pubkey"].as_str().context("input key")?,
            "native input differs from frozen ownership proof"
        );
        keys.push(wallet.get_vtxo_key(&coin).await?);
        inputs.push(coin);
    }
    let amount = inputs.iter().try_fold(0u64, |sum, v| {
        sum.checked_add(v.amount().to_sat())
            .context("principal overflow")
    })?;
    ensure!(
        Some(amount) == frozen["principal_sat"].as_u64(),
        "whole-trial principal differs"
    );
    let recipients = frozen["context"]["recipients"]
        .as_array()
        .context("registered recipients")?;
    ensure!(
        recipients.len() == 2 && recipients[0]["pubkey"] != recipients[1]["pubkey"],
        "distinct signed registered recipients required"
    );
    let left_key =
        PublicKey::from_str(recipients[0]["pubkey"].as_str().context("left recipient")?)?;
    let right_key = PublicKey::from_str(
        recipients[1]["pubkey"]
            .as_str()
            .context("right recipient")?,
    )?;
    // Each builder calls the SDK's cryptographic nonce generator independently.
    let left = ArkoorPackageBuilder::new_with_checkpoints(
        inputs.clone(),
        vec![ArkoorDestination {
            total_amount: Amount::from_sat(amount),
            policy: VtxoPolicy::new_pubkey(left_key),
        }],
    )?
    .generate_user_nonces(&keys)?;
    let right = ArkoorPackageBuilder::new_with_checkpoints(
        inputs,
        vec![ArkoorDestination {
            total_amount: Amount::from_sat(amount),
            policy: VtxoPolicy::new_pubkey(right_key),
        }],
    )?
    .generate_user_nonces(&keys)?;
    let left_body = protos::ArkoorPackageCosignRequest::from(left.cosign_request());
    let right_body = protos::ArkoorPackageCosignRequest::from(right.cosign_request());
    let ids = items
        .iter()
        .map(|v| v["coin_id"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    let left_checkpoint = body_checkpoint(&left, &left_body, "left", &ids);
    let right_checkpoint = body_checkpoint(&right, &right_body, "right", &ids);
    ensure!(
        left_checkpoint["signing_session_sha256"] != right_checkpoint["signing_session_sha256"],
        "conflicting packages reused nonce session"
    );
    ensure!(
        left_checkpoint["input_spends"] != right_checkpoint["input_spends"],
        "requests do not spend identical inputs differently"
    );
    let prepared = json!({"trial_id":req.args["trial_id"],"intent_hash":req.args["intent_hash"],"legs":[left_checkpoint,right_checkpoint]});
    save(
        &directory.join("left-request.bin"),
        &left_body.encode_to_vec(),
    )?;
    save(
        &directory.join("right-request.bin"),
        &right_body.encode_to_vec(),
    )?;
    save(
        &directory.join("preparation.json"),
        &serde_json::to_vec(&prepared)?,
    )?;
    evidence(req, "phase_preparations_frozen", prepared.clone())?;
    save(
        &directory.join("dispatched"),
        &now().to_string().into_bytes(),
    )?;
    let mut second_rpc = rpc.clone();
    // Process each reply in its own future: persist successful Full successors
    // immediately, even if the competing RPC is still awaiting its reply.
    let left_future = async {
        let reply = rpc.request_arkoor_cosign(left_body).await;
        signed_reply(
            &directory,
            "left",
            left,
            &keys,
            reply,
            prepared["legs"][0]["wire_sha256"].as_str().unwrap(),
        )
    };
    let right_future = async {
        let reply = second_rpc.request_arkoor_cosign(right_body).await;
        signed_reply(
            &directory,
            "right",
            right,
            &keys,
            reply,
            prepared["legs"][1]["wire_sha256"].as_str().unwrap(),
        )
    };
    let (left_result, right_result) = tokio::join!(left_future, right_future);
    // Both completed futures have persisted their replies before errors escape.
    let left_result = left_result?;
    let right_result = right_result?;
    save(
        &directory.join("result.json"),
        &serde_json::to_vec(&json!([left_result.clone(), right_result.clone()]))?,
    )?;
    evidence(
        req,
        "phase_reply_observed",
        json!({"trial_id":req.args["trial_id"],"leg_id":"left","reply":left_result}),
    )?;
    evidence(
        req,
        "phase_reply_observed",
        json!({"trial_id":req.args["trial_id"],"leg_id":"right","reply":right_result}),
    )?;
    Ok(
        json!({"phase_unknown":true,"trial_id":req.args["trial_id"],"preparation":prepared,"replies":[left_result,right_result],"actual_fee_sat":Value::Null,"reason":"independent signed-path, current entitlement, fee and once-only audit required","restart_continuation":false,"customer_traffic_credit":false}),
    )
}

/// D24 deliberately runs before any wallet is opened. The online courier only
/// supplies its protected evidence directory; archived original wallets stay closed.
pub async fn register_saved(
    rpc: &mut ArkServiceClient<Channel>,
    req: &Request,
    private_root: &Path,
    network: Network,
) -> Result<Value> {
    let frozen = intent(req, "D24")?;
    ensure!(
        network == Network::Signet
            && req.operation == "phase_register_saved"
            && req.maximum_fee_sat == 0,
        "delayed public registration scope differs"
    );
    let courier = frozen["context"]["courier_actor"]
        .as_str()
        .context("online courier missing")?;
    ensure!(
        !matches!(courier, "actor-03" | "actor-09" | "actor-10"),
        "cannot use absent courier directory"
    );
    let Some(directory) = fence(private_root, req)? else {
        return Ok(unknown());
    };
    let saved = req.args["successors"]
        .as_array()
        .context("saved signed successors")?;
    let ids = frozen["context"]["saved_successor_ids"]
        .as_array()
        .context("saved IDs")?;
    let payouts = req.args["checked_original_payouts"]
        .as_array()
        .context("confirmed original-owner payout checks")?;
    ensure!(
        !saved.is_empty()
            && saved.len() <= 16
            && ids.len() == saved.len()
            && payouts.len() == saved.len(),
        "exact bounded paid successors required"
    );
    let mut bytes = Vec::new();
    for (index, item) in saved.iter().enumerate() {
        let encoded: Vec<u8> = bitcoin::hex::FromHex::from_hex(
            item["signed_vtxo"].as_str().context("saved signed bytes")?,
        )?;
        let coin = Vtxo::deserialize(&encoded)?;
        ensure!(
            coin.has_all_witnesses()
                && coin.id().to_string() == ids[index].as_str().context("saved ID")?
                && coin.id().to_string() == item["id"].as_str().context("item ID")?
                && coin.server_pubkey().to_string() == req.expected_server_pubkey
                && coin.user_pubkey().to_string()
                    == item["pubkey"].as_str().context("saved owner key")?
                && Some(coin.amount().to_sat()) == item["amount_sat"].as_u64()
                && hash(&encoded) == item["signed_hash"].as_str().context("signed hash")?,
            "saved successor differs from exact Full proof"
        );
        let checked = &payouts[index];
        ensure!(
            checked["coin_id"] == item["id"]
                && checked["actor"] == frozen["actor"]
                && checked["amount_sat"] == item["amount_sat"],
            "payout does not establish original-owner gross settlement of saved successor"
        );
        bytes.push(encoded);
    }
    let body = protos::RegisterVtxoTransactionsRequest { vtxos: bytes };
    let wire = body.encode_to_vec();
    save(&directory.join("request.bin"), &wire)?;
    save(
        &directory.join("payout-checks.json"),
        &serde_json::to_vec(payouts)?,
    )?;
    evidence(
        req,
        "phase_delayed_registration_frozen",
        json!({"trial_id":req.args["trial_id"],"wire_sha256":hash(&wire),"saved_successor_ids":ids,"original_actor":frozen["actor"],"courier_actor":courier,"original_wallet_opened":false}),
    )?;
    save(
        &directory.join("dispatched"),
        &now().to_string().into_bytes(),
    )?;
    let result = match rpc.register_vtxo_transactions(body).await {
        Ok(response) => {
            let bytes = response.into_inner().encode_to_vec();
            save(&directory.join("response.bin"), &bytes)?;
            json!({"kind":"unexpected_registration_acceptance","wire_sha256":hash(&wire),"response_sha256":hash(&bytes)})
        }
        Err(status) => {
            let bytes = serde_json::to_vec(
                &json!({"utc_unix_ms":now(),"code":format!("{:?}",status.code()),"message":status.message(),"details_hex":hex(status.details())}),
            )?;
            save(&directory.join("error.json"), &bytes)?;
            json!({"kind":if status.is_expiry_settled(){"expiry_settled_refusal"}else if status.is_rejection(){"generic_refusal"}else{"transport_unknown"},"wire_sha256":hash(&wire),"response_sha256":hash(&bytes),"code":format!("{:?}",status.code()),"message_sha256":hash(status.message().as_bytes())})
        }
    };
    save(
        &directory.join("result.json"),
        &serde_json::to_vec(&result)?,
    )?;
    evidence(
        req,
        "phase_reply_observed",
        json!({"trial_id":req.args["trial_id"],"leg_id":"delivery","reply":result}),
    )?;
    Ok(
        json!({"phase_unknown":true,"trial_id":req.args["trial_id"],"reply":result,"actual_fee_sat":Value::Null,"original_wallet_opened":false,"reason":"fresh rightful entitlement and unique confirmed payout audit required","customer_traffic_credit":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn declaration(scenario: &str) -> Request {
        let frozen = json!({"network":"signet","scenario":scenario,"actor":"actor-11","maximum_fee_sat":2000,"server_pubkey":"pinned-key"});
        serde_json::from_value(json!({"operation":"phase_execute_d17","action_id":"unit-private-fence","actor_dir":null,"expected_server_pubkey":"pinned-key","maximum_fee_sat":2000,
            "args":{"phase_intent":frozen,"intent_hash":hash(&serde_json::to_vec(&frozen).unwrap()),"qualification_manifest_sha256":"e1".repeat(32)}})).unwrap()
    }
    #[test]
    fn frozen_scope_fee_and_manifest_are_validated_before_submission() {
        let mut req = declaration("D17");
        assert!(intent(&req, "D17").is_ok());
        req.args["phase_intent"]["maximum_fee_sat"] = json!(2001);
        assert!(intent(&req, "D17").is_err());
        let mut req = declaration("D17");
        req.args["qualification_manifest_sha256"] = Value::Null;
        assert!(intent(&req, "D17").is_err());
        assert!(intent(&declaration("D24"), "D17").is_err());
    }
    #[test]
    fn reopened_exact_request_fence_does_not_dispatch_again() {
        let root =
            std::env::temp_dir().join(format!("phase-fence-unit-{}-{}", std::process::id(), now()));
        let req = declaration("D17");
        let directory = fence(&root, &req).unwrap().unwrap();
        save(&directory.join("request.bin"), b"exact-declared-request").unwrap();
        assert!(fence(&root, &req).unwrap().is_none());
        assert!(save(&directory.join("request.bin"), b"changed-request").is_err());
        fs::remove_dir_all(root).unwrap();
    }
}

//! Legacy operation name maps to immutable-record idempotence, never rotation.
use super::{Request, evidence, hex, native_intent};
use anyhow::{Context, Result, ensure};
use ark::{ProtocolEncoding, fallback::FallbackRecord};
use bark::Wallet;
use bitcoin::Network;
use serde_json::{Value, json};
use server_rpc::protos::{self, ark_service_client::ArkServiceClient};
use std::path::Path;
use tonic::transport::Channel;
pub(super) async fn execute(
    wallet: &Wallet,
    rpc: &mut ArkServiceClient<Channel>,
    path: &Path,
    req: &Request,
    network: Network,
) -> Result<Value> {
    ensure!(
        req.maximum_fee_sat == 0,
        "immutable record probe spends no capital"
    );
    ensure!(
        req.args.get("previous_fallback_seq").is_none() && req.args.get("destination").is_none(),
        "mutable rotation is obsolete; declare exact immutable record instead"
    );
    let expected = req.args["fallback_record"]
        .as_str()
        .context("exact immutable record required")?;
    let local = wallet.fallback_destination().await?;
    ensure!(
        hex(&local.serialize()) == expected,
        "declared record differs from authenticated seed/index0 record"
    );
    let mailbox = wallet.mailbox_identifier().as_pubkey();
    let query = protos::SetFallbackRequest {
        mailbox_pk: mailbox.serialize().to_vec(),
        record: vec![],
    };
    let original = rpc.set_fallback(query.clone()).await?.into_inner().record;
    let server = FallbackRecord::deserialize(&original)?;
    server.verify(network, mailbox)?;
    ensure!(
        server.same_binding(&local),
        "server binding differs from this seed's exact index0/account"
    );
    let phase = req.args["phase"].as_str().unwrap_or("start");
    let mut intent = if let Some(intent) = native_intent::load(path, req)? {
        ensure!(
            phase == "inspect",
            "original registration attempt exists; inspect only"
        );
        intent
    } else {
        ensure!(phase == "start", "missing original record probe");
        let mut intent = native_intent::freeze(
            req,
            json!({"fallback_record":expected,"server_record":hex(&original),"mailbox_pk":mailbox.to_string()}),
        );
        native_intent::persist(path, req, &intent)?;
        let reply = rpc
            .set_fallback(protos::SetFallbackRequest {
                mailbox_pk: mailbox.serialize().to_vec(),
                record: local.serialize(),
            })
            .await?
            .into_inner()
            .record;
        ensure!(
            reply == original,
            "idempotent registration changed canonical bytes"
        );
        intent.state = "completed".into();
        intent
    };
    let after = rpc.set_fallback(query).await?.into_inner().record;
    ensure!(
        after == original,
        "immutable record changed during idempotence probe"
    );
    let result = json!({"immutable_record_verified":true,"fallback_script":hex(local.spk.as_bytes()),"account_xpub":local.account_xpub.to_string(),"fallback_record":hex(&after),"exact_server_record_match":true,"actual_fee_sat":0,"scope":"immutable registration idempotence only; no record rotation or payout asserted"});
    evidence(req, "immutable_record_readback", result.clone())?;
    intent.result = Some(result.clone());
    native_intent::persist(path, req, &intent)?;
    Ok(result)
}

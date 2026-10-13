//! Genuine unilateral-exit package versus one retained same-input SDK arkoor.
//! Depends on the ordinary exit module's explicit prepare-before-broadcast seam
//! and all of its original fee-source, budget, signing and broadcast guards.
use super::{Request, evidence, phase_protocol as retained};
use anyhow::{Context, Result, ensure};
use ark::{
    ProtocolEncoding, VtxoPolicy,
    arkoor::{ArkoorDestination, package::ArkoorPackageBuilder},
};
use bark::Wallet;
use bitcoin::{Amount, Network, Transaction, consensus::deserialize, secp256k1::PublicKey};
use prost::Message;
use serde_json::{Value, json};
use server_rpc::protos::{self, ark_service_client::ArkServiceClient};
use std::{path::Path, str::FromStr};
use tonic::transport::Channel;
fn request(req: &Request, ids: &[String], phase: &str) -> Result<Request> {
    let context = &req.args["phase_intent"]["context"];
    Ok(Request {
        operation: "exit".into(),
        action_id: req.action_id.clone(),
        actor_dir: req.actor_dir.clone(),
        expected_server_pubkey: req.expected_server_pubkey.clone(),
        maximum_fee_sat: req.maximum_fee_sat,
        args: json!({"input_vtxo_ids":ids,"phase":phase,"fee_rate_sat_per_vb":context["fee_rate_sat_per_vb"],"fee_funding_outpoint":context["fee_funding_outpoint"]}),
    })
}
pub async fn execute(
    wallet: &Wallet,
    rpc: &mut ArkServiceClient<Channel>,
    req: &Request,
    wallet_path: &Path,
    private_root: &Path,
    actor: &str,
) -> Result<Value> {
    let frozen = retained::intent(req, "D20")?;
    ensure!(
        req.operation == "phase_execute_d20"
            && frozen["actor"] == actor
            && !matches!(actor, "actor-03" | "actor-09" | "actor-10"),
        "exact online unilateral phase required"
    );
    let Some(directory) = retained::fence(private_root, req)? else {
        return Ok(
            json!({"phase_unknown":true,"actual_fee_sat":Value::Null,"reason":"existing phase fence; independent chain/arbitration reconciliation; no signing retry"}),
        );
    };
    let mut inputs = Vec::new();
    let mut keys = Vec::new();
    let mut ids = Vec::new();
    for item in frozen["inputs"].as_array().context("frozen inputs")? {
        let id = ark::VtxoId::from_str(item["coin_id"].as_str().context("input ID")?)?;
        let coin = wallet.get_full_vtxo(id).await?;
        ensure!(
            retained::hash(&coin.serialize())
                == item["signed_hash"].as_str().context("signed input hash")?
                && Some(coin.amount().to_sat()) == item["amount_sat"].as_u64()
                && coin.server_pubkey().to_string() == req.expected_server_pubkey,
            "unilateral signed input/value/server changed"
        );
        keys.push(wallet.get_vtxo_key(&coin).await?);
        ids.push(id.to_string());
        inputs.push(coin);
    }
    let recipient = &frozen["context"]["recipients"][0];
    let pubkey = PublicKey::from_str(
        recipient["pubkey"]
            .as_str()
            .context("registered cooperative recipient")?,
    )?;
    let builder = ArkoorPackageBuilder::new_with_checkpoints(
        inputs.clone(),
        vec![ArkoorDestination {
            total_amount: Amount::from_sat(frozen["principal_sat"].as_u64().context("principal")?),
            policy: VtxoPolicy::new_pubkey(pubkey),
        }],
    )?
    .generate_user_nonces(&keys)?;
    let body = protos::ArkoorPackageCosignRequest::from(builder.cosign_request());
    let checkpoint = retained::body_checkpoint(&builder, &body, "arkoor", &ids);
    retained::save(
        &directory.join("cooperative-request.bin"),
        &body.encode_to_vec(),
    )?;
    // This is a real guarded exit registration. Its prepare seam must never
    // progress/broadcast or sign CPFP/claim transactions before returning.
    let prepared_request = request(req, &ids, "prepare")?;
    let prepared =
        super::exit::execute(wallet, rpc, wallet_path, &prepared_request, Network::Signet).await?;
    retained::save(
        &directory.join("sdk-exit-prepared.json"),
        &serde_json::to_vec(&prepared)?,
    )?;
    let packages = prepared["exits"]
        .as_array()
        .context("genuine pre-broadcast SDK packages unavailable")?;
    ensure!(
        packages.len() == ids.len(),
        "incomplete exit package evidence; no setup-refusal qualification"
    );
    for (coin, identity) in inputs.iter().zip(&ids) {
        let package = packages
            .iter()
            .find(|v| v["vtxo_id"] == identity.as_str())
            .context("exit package original missing")?;
        let rows = package["transactions"]
            .as_array()
            .context("exit transaction packages missing")?;
        let mut leaf = false;
        for row in rows {
            let encoded = super::phase_replay::decode_hex(
                row["tx"]
                    .as_str()
                    .context("signed SDK parent transaction")?,
            )?;
            let tx: Transaction = deserialize(&encoded)?;
            ensure!(
                tx.compute_txid().to_string() == row["txid"].as_str().context("SDK exit txid")?,
                "exit package raw txid changed"
            );
            let expected = coin
                .transactions()
                .find(|node| node.tx.compute_txid() == tx.compute_txid())
                .context("exit package is outside exact frozen SDK signed genesis")?;
            ensure!(
                bitcoin::consensus::serialize(&expected.tx) == encoded,
                "exit package witnesses differ from exact frozen independently signed genesis"
            );
            if tx.compute_txid() == coin.point().txid {
                ensure!(
                    tx.output.get(coin.point().vout as usize) == Some(&coin.txout()),
                    "exit leaf differs from original signed value/script"
                );
                leaf = true
            }
        }
        ensure!(
            leaf,
            "SDK exit packages not initialized or missing exact leaf; hold original frozen exit intent"
        );
    }
    let preparation = json!({"trial_id":req.args["trial_id"],"intent_hash":req.args["intent_hash"],"input_vtxo_ids":ids,"signed_vtxos":inputs.iter().map(|v|super::hex(&v.serialize())).collect::<Vec<_>>(),
        "fee_cap_sat":req.maximum_fee_sat,"fee_rate_kwu":frozen["context"]["fee_rate_sat_per_vb"].as_u64().context("fee rate")?.checked_mul(250).context("fee rate overflow")?,
        "fee_funding_outpoint":frozen["context"]["fee_funding_outpoint"],"packages":packages,"cooperative_leg":checkpoint});
    retained::save(
        &directory.join("preparation.json"),
        &serde_json::to_vec(&preparation)?,
    )?;
    evidence(req, "phase_exit_preparations_frozen", preparation)?;
    // All exact public evidence is durable before either dispatch. The ordinary
    // exit helper retains its original whole-lifetime budget and fee source.
    let advance_request = request(req, &ids, "advance")?;
    let mut exit_rpc = rpc.clone();
    let mut cooperative_rpc = rpc.clone();
    let exit_future = async {
        let started = retained::now_ns();
        let result = super::exit::execute(
            wallet,
            &mut exit_rpc,
            wallet_path,
            &advance_request,
            Network::Signet,
        )
        .await;
        retained::save(
            &directory.join("exit-advance-result.json"),
            &serde_json::to_vec(
                &json!({"started_at_ns":started,"reply_at_ns":retained::now_ns(),"result":result.as_ref().map(|v|v.clone()).map_err(|e|format!("{e:#}"))}),
            )?,
        )?;
        result
    };
    let cooperative_future = async {
        let started = retained::now_ns();
        let response = cooperative_rpc.request_arkoor_cosign(body).await;
        retained::signed_reply(
            &directory,
            "arkoor",
            builder,
            &keys,
            response,
            checkpoint["wire_sha256"].as_str().context("wire hash")?,
            started,
            retained::now_ns(),
        )
    };
    let (exited, cooperative) = tokio::join!(exit_future, cooperative_future);
    let cooperative = cooperative?;
    retained::save(
        &directory.join("cooperative-public-result.json"),
        &serde_json::to_vec(&cooperative)?,
    )?;
    evidence(
        req,
        "phase_reply_observed",
        json!({"trial_id":req.args["trial_id"],"leg_id":"arkoor","reply":cooperative}),
    )?;
    let result = json!({"phase_unknown":true,"actual_fee_sat":Value::Null,"exit_progress_known":exited.is_ok(),"customer_traffic_credit":false,"required_audit":"actual confirmed unilateral package or registered cooperative successor, same-input chain arbitration, exact once-only principal and independently booked mining/customer fees"});
    retained::save(
        &directory.join("exit-race-result.json"),
        &serde_json::to_vec(&result)?,
    )?;
    Ok(result)
}

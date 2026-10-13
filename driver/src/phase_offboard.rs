//! Public SDK offboard fee, attestation and connector-forfeit primitives.
//! Prepares one genuine server session, never regenerates a finish nonce.
use super::{Request, evidence, hex, phase_protocol as retained};
use anyhow::{Context, Result, ensure};
use ark::{
    ArkInfo, ProtocolEncoding, Vtxo,
    attestations::OffboardRequestAttestation,
    fees::VtxoFeeInfo,
    musig,
    offboard::{OffboardForfeitContext, OffboardRequest},
    vtxo::Full,
};
use bark::Wallet;
use bitcoin::{
    Amount, FeeRate, Network, OutPoint, Transaction,
    consensus::{deserialize, serialize},
    hashes::Hash,
    secp256k1::Keypair,
};
use prost::Message;
use serde_json::{Value, json};
use server_rpc::StatusExt;
use server_rpc::protos::{self, ark_service_client::ArkServiceClient};
use std::path::Path;
use tonic::transport::Channel;
pub(super) struct Partner {
    pub checkpoint: Value,
    body: protos::FinishOffboardRequest,
    unsigned: Transaction,
}
pub(super) async fn prepare(
    wallet: &Wallet,
    rpc: &mut ArkServiceClient<Channel>,
    req: &Request,
    directory: &Path,
    coins: &[Vtxo<Full>],
    keys: &[Keypair],
    round_fee_sat: u64,
) -> Result<Partner> {
    let frozen = retained::intent(req, "D19")?;
    let info_reply = rpc.get_ark_info(protos::Empty {}).await?;
    retained::save(
        &directory.join("offboard-ark-info.bin"),
        &info_reply.get_ref().encode_to_vec(),
    )?;
    let info: ArkInfo = info_reply.into_inner().try_into()?;
    ensure!(
        info.network == Network::Signet
            && info.server_pubkey.to_string() == req.expected_server_pubkey,
        "offboard server identity changed"
    );
    ensure!(
        coins.len() <= info.max_offboard_inputs,
        "SDK offboard input limit exceeded"
    );
    let fallback = wallet.fallback_destination().await?;
    let script = fallback.spk;
    ensure!(
        script.to_hex_string()
            == frozen["context"]["offboard_script"]
                .as_str()
                .context("frozen owned offboard script")?,
        "offboard destination is not exact current SDK owned fallback"
    );
    let gross = Amount::from_sat(frozen["principal_sat"].as_u64().context("principal")?);
    let rate = FeeRate::from_sat_per_kwu(
        frozen["context"]["offboard_fee_rate_kwu"]
            .as_u64()
            .context("declared fee rate")?,
    );
    let tip = wallet.chain().tip().await?;
    let fee = info
        .fees
        .offboard
        .calculate(
            &script,
            gross,
            rate,
            coins.iter().map(|v| VtxoFeeInfo::from_vtxo_and_tip(v, tip)),
        )
        .context("actual SDK offboard fee unavailable")?;
    ensure!(
        fee.to_sat()
            .checked_add(round_fee_sat)
            .is_some_and(|sum| sum <= req.maximum_fee_sat),
        "actual offboard fee exceeds whole-group cap"
    );
    let net = gross
        .checked_sub(fee)
        .context("offboard fee exceeds principal")?;
    ensure!(net >= script.minimal_non_dust(), "offboard net is dust");
    let request = OffboardRequest {
        script_pubkey: script.clone(),
        net_amount: net,
        deduct_fees_from_gross_amount: true,
        fee_rate: rate,
    };
    request.validate()?;
    let ids = coins.iter().map(|v| v.id()).collect::<Vec<_>>();
    ensure!(
        ids.windows(2).all(|w| w[0] < w[1]),
        "exact frozen SDK offboard inputs must be sorted before signing"
    );
    let prepare = protos::PrepareOffboardRequest {
        offboard: Some(request.clone().into()),
        input_vtxo_ids: ids.iter().map(|id| id.to_bytes().to_vec()).collect(),
        attestation: keys
            .iter()
            .map(|key| OffboardRequestAttestation::new(&request, &ids, key).serialize())
            .collect(),
    };
    retained::save(
        &directory.join("offboard-prepare-request.bin"),
        &prepare.encode_to_vec(),
    )?;
    let response = match rpc.prepare_offboard(prepare).await {
        Ok(reply) => reply,
        Err(status) => {
            retained::save(
                &directory.join("offboard-prepare-error.json"),
                &serde_json::to_vec(
                    &json!({"code":format!("{:?}",status.code()),"message":status.message(),"details_hex":hex(status.details()),"metadata":format!("{:?}",status.metadata())}),
                )?,
            )?;
            return Err(status.into());
        }
    };
    retained::save(
        &directory.join("offboard-prepare-response.bin"),
        &response.get_ref().encode_to_vec(),
    )?;
    retained::save(
        &directory.join("offboard-prepare-metadata.json"),
        &serde_json::to_vec(&json!({"metadata":format!("{:?}",response.metadata())}))?,
    )?;
    let response = response.into_inner();
    let unsigned: Transaction = deserialize(&response.offboard_tx)?;
    let context = OffboardForfeitContext::new(coins, &unsigned)?;
    context.validate_offboard_tx(&request)?;
    let nonces = response
        .forfeit_cosign_nonces
        .iter()
        .map(|n| musig::PublicNonce::from_bytes(n))
        .collect::<Result<Vec<_>, _>>()?;
    let signed = context.user_sign_forfeits(keys, &nonces)?;
    let txid = unsigned.compute_txid();
    let body = protos::FinishOffboardRequest {
        offboard_txid: txid.as_byte_array().to_vec(),
        user_nonces: signed
            .public_nonces
            .iter()
            .map(|n| n.serialize().to_vec())
            .collect(),
        partial_signatures: signed
            .partial_signatures
            .iter()
            .map(|s| s.serialize().to_vec())
            .collect(),
    };
    let connector = OutPoint::new(txid, 1);
    let fanout = if coins.len() > 1 {
        Some(ark::connectors::construct_multi_connector_fanout_tx(
            connector,
            coins.len(),
            &unsigned.output[1].script_pubkey,
        ))
    } else {
        None
    };
    if let Some(tx) = &fanout {
        retained::save(
            &directory.join("offboard-unsigned-connector.bin"),
            &serialize(tx),
        )?
    }
    let spends=coins.iter().enumerate().map(|(index,coin)|{let point=fanout.as_ref().map(|tx|OutPoint::new(tx.compute_txid(),index as u32)).unwrap_or(connector);
        let tx=ark::forfeit::create_connector_forfeit_tx(coin,point,None,None);json!({"coin_id":coin.id().to_string(),"txid":tx.compute_txid().to_string(),"raw_unsigned_hex":hex(&serialize(&tx))})}).collect::<Vec<_>>();
    let wire = body.encode_to_vec();
    retained::save(&directory.join("offboard-finish-request.bin"), &wire)?;
    let checkpoint = json!({"leg_id":"offboard","rpc":"FinishOffboard","input_coin_ids":ids.iter().map(|id|id.to_string()).collect::<Vec<_>>(),"wire_sha256":retained::hash(&wire),"private_checkpoint_sha256":retained::hash(&wire),
        "nonce_retention":"single_process","restart_continuation":false,"signing_session_sha256":retained::hash(&serde_json::to_vec(&body.user_nonces)?),
        "input_spends":spends,"outputs":[],"unsigned_offboard_hex":hex(&serialize(&unsigned)),"offboard_txid":txid.to_string(),"net_amount_sat":net.to_sat(),"committed_fee_sat":fee.to_sat(),"destination_script":script.to_hex_string(),"fee_quote_height":tip.to_u32()});
    retained::save(
        &directory.join("offboard-preparation.json"),
        &serde_json::to_vec(&checkpoint)?,
    )?;
    Ok(Partner {
        checkpoint,
        body,
        unsigned,
    })
}
impl Partner {
    pub(super) async fn finish(
        self,
        wallet: &Wallet,
        rpc: &mut ArkServiceClient<Channel>,
        req: &Request,
        directory: &Path,
    ) -> Result<Value> {
        let started = retained::now_ns();
        retained::save(
            &directory.join("offboard-dispatched.json"),
            &serde_json::to_vec(
                &json!({"submitted_at_ns":started,"wire_sha256":self.checkpoint["wire_sha256"]}),
            )?,
        )?;
        let reply = rpc.finish_offboard(self.body).await;
        let finished = retained::now_ns();
        let result = match reply {
            Ok(reply) => {
                retained::save(
                    &directory.join("offboard-finish-reply.bin"),
                    &reply.get_ref().encode_to_vec(),
                )?;
                retained::save(
                    &directory.join("offboard-finish-metadata.json"),
                    &serde_json::to_vec(&json!({"metadata":format!("{:?}",reply.metadata())}))?,
                )?;
                let signed: Transaction = deserialize(&reply.into_inner().signed_offboard_tx)?;
                ensure!(
                    signed.compute_txid() == self.unsigned.compute_txid()
                        && signed
                            .input
                            .iter()
                            .all(|i| !i.witness.is_empty() || !i.script_sig.is_empty()),
                    "server returned changed or unsigned offboard transaction"
                );
                retained::save(&directory.join("offboard-signed.bin"), &serialize(&signed))?;
                evidence(
                    req,
                    "phase_offboard_signed",
                    json!({"trial_id":req.args["trial_id"],"txid":signed.compute_txid().to_string(),"raw_transaction":hex(&serialize(&signed)),"destination_script":self.checkpoint["destination_script"],"net_amount_sat":self.checkpoint["net_amount_sat"],"committed_fee_sat":self.checkpoint["committed_fee_sat"]}),
                )?;
                // Exact signed broadcast checkpoint precedes the real chain call.
                retained::save(
                    &directory.join("offboard-broadcast-intent.json"),
                    &serde_json::to_vec(
                        &json!({"txid":signed.compute_txid().to_string(),"signed_sha256":retained::hash(&serialize(&signed)),"intent_hash":req.args["intent_hash"]}),
                    )?,
                )?;
                let broadcast = wallet.chain().broadcast_tx(&signed).await;
                retained::save(
                    &directory.join("offboard-broadcast-result.json"),
                    &serde_json::to_vec(
                        &json!({"result":format!("{broadcast:?}"),"confirmation_scope":"broadcast reply is not chain confirmation"}),
                    )?,
                )?;
                json!({"kind":"sdk_signed_offboard","offboard_txid":signed.compute_txid().to_string(),"broadcast_reply_known":broadcast.is_ok()})
            }
            Err(status) => {
                retained::save(
                    &directory.join("offboard-finish-error.json"),
                    &serde_json::to_vec(
                        &json!({"code":format!("{:?}",status.code()),"message":status.message(),"details_hex":hex(status.details()),"metadata":format!("{:?}",status.metadata())}),
                    )?,
                )?;
                json!({"kind":if status.is_rejection(){"protocol_refusal"}else{"transport_unknown"},"code":format!("{:?}",status.code()),"rejected_coin_ids":status.rejected_vtxos().iter().map(|id|id.to_string()).collect::<Vec<_>>()})
            }
        };
        let kind = if result["kind"] == "sdk_signed_offboard"
            && result["broadcast_reply_known"] == false
        {
            "transport_unknown"
        } else {
            result["kind"]
                .as_str()
                .context("offboard actual reply classification")?
        };
        let result = json!({"kind":kind,"leg_id":"offboard","wire_sha256":self.checkpoint["wire_sha256"],"submitted_at_ns":started,"reply_at_ns":finished,"observation":result,"customer_traffic_credit":false});
        evidence(
            req,
            "phase_offboard_reply_observed",
            json!({"trial_id":req.args["trial_id"],"reply":result}),
        )?;
        Ok(result)
    }
}

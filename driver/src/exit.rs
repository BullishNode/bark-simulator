//! Explicit, persisted unilateral exits with an absolute lifetime fee budget.
//! Automatic SDK CPFP and drain helpers are deliberately not called: their
//! internal signing happens before a caller can inspect the exact fee.
use super::{Request, evidence, hex, verify_exit_budget};
use anyhow::{Context, Result, ensure};
use bark::{
    Wallet,
    onchain::{OnchainWallet, TxBuilderExt},
};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::hex::FromHex;
use bitcoin::{Amount, FeeRate, Network, OutPoint, Psbt, ScriptBuf, Transaction, TxOut, Weight};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use server_rpc::protos::{self, ark_service_client::ArkServiceClient};
use std::{
    collections::HashSet,
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    str::FromStr,
};
use tonic::transport::Channel;

#[derive(Clone, Deserialize, Serialize)]
struct Step {
    kind: String,
    txid: String,
    unsigned_tx: String,
    signed_tx: Option<String>,
    fee_sat: u64,
    parent_tx: Option<String>,
    inputs: Vec<(OutPoint, TxOut)>,
}
#[derive(Deserialize, Serialize)]
struct Intent {
    version: u32,
    action_id: String,
    server_pubkey: String,
    network: String,
    input_vtxo_ids: Vec<String>,
    signed_vtxos: Vec<String>,
    fee_cap_sat: u64,
    fee_rate_kwu: u64,
    fee_source: OutPoint,
    destination_script: ScriptBuf,
    steps: Vec<Step>,
    finished: bool,
}
fn intent_path(path: &Path, id: &str) -> std::path::PathBuf {
    path.join(format!(
        "sim-exit-{}.json",
        sha256::Hash::hash(id.as_bytes())
    ))
}
fn persist(path: &Path, intent: &Intent) -> Result<()> {
    let destination = intent_path(path, &intent.action_id);
    if let Ok(metadata) = fs::symlink_metadata(&destination) {
        ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.permissions().mode() & 0o077 == 0,
            "exit intent must be private and regular"
        );
    }
    let temp = destination.with_extension(format!("{}.tmp", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    file.write_all(&serde_json::to_vec(intent)?)?;
    file.sync_all()?;
    fs::rename(&temp, &destination)?;
    fs::File::open(path)?.sync_all()?;
    Ok(())
}
fn load(path: &Path, id: &str) -> Result<Option<Intent>> {
    let file = intent_path(path, id);
    match fs::symlink_metadata(&file) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
        Ok(m) => ensure!(
            m.is_file() && !m.file_type().is_symlink() && m.permissions().mode() & 0o077 == 0,
            "exit intent must be private and regular"
        ),
    }
    let bytes = fs::read(file)?;
    ensure!(bytes.len() <= 16 * 1024 * 1024, "exit intent exceeds bound");
    Ok(Some(serde_json::from_slice(&bytes)?))
}
pub(super) fn has_unfinished_intent(path: &Path) -> Result<bool> {
    for file in fs::read_dir(path)? {
        let file = file?;
        let name = file.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("sim-exit-") && name.ends_with(".json") {
            let m = file.file_type()?;
            ensure!(m.is_file() && !m.is_symlink(), "unsafe exit intent");
            let bytes = fs::read(file.path())?;
            ensure!(bytes.len() <= 16 * 1024 * 1024, "exit intent exceeds bound");
            let intent: Intent = serde_json::from_slice(&bytes)?;
            if !intent.finished {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
fn decode_tx(value: &str) -> Result<Transaction> {
    bitcoin::consensus::deserialize(&Vec::<u8>::from_hex(value)?)
        .context("invalid frozen exit transaction")
}
fn request_ids(req: &Request) -> Result<Vec<String>> {
    let rows = req.args["input_vtxo_ids"]
        .as_array()
        .context("declare exact exit coin IDs")?;
    ensure!(
        !rows.is_empty() && rows.len() <= 16,
        "exit requires 1–16 explicit coins"
    );
    let ids = rows
        .iter()
        .map(|id| {
            id.as_str()
                .map(str::to_owned)
                .context("invalid exit coin ID")
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        ids.iter().collect::<HashSet<_>>().len() == ids.len(),
        "duplicate exit inputs"
    );
    for id in &ids {
        let _ = ark::VtxoId::from_str(id)?;
    }
    Ok(ids)
}
fn request_terms(req: &Request) -> Result<(FeeRate, OutPoint)> {
    let rate = req.args["fee_rate_sat_per_vb"]
        .as_u64()
        .context("declare an exit fee rate")?;
    ensure!(rate > 0, "zero exit fee rate");
    let rate = FeeRate::from_sat_per_vb(rate).context("exit fee rate overflow")?;
    let source = OutPoint::from_str(
        req.args["fee_funding_outpoint"]
            .as_str()
            .context("declare an owned confirmed exit fee source")?,
    )?;
    Ok((rate, source))
}
fn verify_terms(intent: &Intent, req: &Request) -> Result<()> {
    let (rate, source) = request_terms(req)?;
    ensure!(
        rate.to_sat_per_kwu() == intent.fee_rate_kwu && source == intent.fee_source,
        "exit frozen fee rate or funding source changed"
    );
    Ok(())
}
fn verify_psbt(
    psbt: &Psbt,
    expected: &[(OutPoint, TxOut)],
    destination: &ScriptBuf,
    remaining: u64,
) -> Result<u64> {
    ensure!(
        !expected.is_empty()
            && psbt.unsigned_tx.input.len() == expected.len()
            && psbt.inputs.len() == expected.len(),
        "exit input set differs from frozen ownership"
    );
    let mut seen = HashSet::new();
    for (input, proof) in psbt.unsigned_tx.input.iter().zip(&psbt.inputs) {
        ensure!(
            seen.insert(input.previous_output),
            "duplicate exit transaction input"
        );
        ensure!(
            input.script_sig.is_empty() && input.witness.is_empty(),
            "exit fee inspection must precede signing"
        );
        let matches = expected
            .iter()
            .filter(|(point, _)| *point == input.previous_output)
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1 && proof.witness_utxo.as_ref() == Some(&matches[0].1),
            "exit input value or script differs from frozen ownership"
        );
    }
    ensure!(
        psbt.unsigned_tx.output.len() == 1
            && psbt.unsigned_tx.output[0].script_pubkey == *destination,
        "exit must return only to the declared owned script"
    );
    ensure!(
        psbt.unsigned_tx.output[0].value >= destination.minimal_non_dust(),
        "exit output is dust"
    );
    let fee = psbt.fee()?.to_sat();
    ensure!(fee <= remaining, "exit fee cap exhausted before signing");
    Ok(fee)
}
async fn statuses(wallet: &Wallet, ids: &[String]) -> Result<Vec<Value>> {
    let mut rows = Vec::new();
    for id in ids {
        let id = ark::VtxoId::from_str(id)?;
        if let Some(status) = wallet.exit_mgr().get_exit_status(id, false, true).await? {
            rows.push(json!({"vtxo_id":id.to_string(),"state":status.state,
                "transactions":status.transactions.iter().map(|package|json!({"txid":package.exit.txid.to_string(),
                  "tx":hex(&bitcoin::consensus::serialize(&package.exit.tx)),
                  "child_txid":package.child.as_ref().map(|child|child.info.txid.to_string())})).collect::<Vec<_>>() }));
        }
    }
    Ok(rows)
}
fn held(reason: &str, intent: &Intent) -> Value {
    json!({"started":true,"held":true,"reason":reason,"exit_action_id":intent.action_id,
       "input_vtxo_ids":intent.input_vtxo_ids,"fee_cap_sat":intent.fee_cap_sat,"actual_fee_sat":Value::Null,
       "note":"known persisted intent; no monetary retry or increased fee budget"})
}
async fn submit_existing(wallet: &Wallet, intent: &Intent, step: &Step) -> Result<()> {
    let signed = decode_tx(
        step.signed_tx
            .as_deref()
            .context("exit signature outcome is unknown; retain reservation")?,
    )?;
    let unsigned = decode_tx(&step.unsigned_tx)?;
    ensure!(
        signed.compute_txid().to_string() == step.txid
            && unsigned.compute_txid().to_string() == step.txid,
        "signed exit changed its frozen transaction"
    );
    ensure!(
        signed.output.len() == 1 && signed.output[0].script_pubkey == intent.destination_script,
        "signed exit changed its owned destination"
    );
    let input_value = step
        .inputs
        .iter()
        .try_fold(0u64, |sum, (_, out)| sum.checked_add(out.value.to_sat()))
        .context("exit input overflow")?;
    let output_value = signed
        .output
        .iter()
        .try_fold(0u64, |sum, out| sum.checked_add(out.value.to_sat()))
        .context("exit output overflow")?;
    ensure!(
        input_value.checked_sub(output_value) == Some(step.fee_sat),
        "signed exit fee differs from the frozen exact charge"
    );
    verify_exit_budget(
        intent.fee_cap_sat,
        intent.fee_cap_sat,
        &intent.steps.iter().map(|s| s.fee_sat).collect::<Vec<_>>(),
        0,
    )?;
    if let Some(parent) = &step.parent_tx {
        let parent = decode_tx(parent)?;
        wallet
            .exit_mgr()
            .provide_cpfp_tx(wallet, parent.compute_txid(), signed)
            .await?;
    } else {
        wallet.chain().broadcast_tx(&signed).await?;
    }
    Ok(())
}

pub(super) async fn execute(
    wallet: &Wallet,
    rpc: &mut ArkServiceClient<Channel>,
    path: &Path,
    req: &Request,
    network: Network,
) -> Result<Value> {
    let ids = request_ids(req)?;
    let phase = req.args["phase"].as_str().unwrap_or("start");
    ensure!(
        matches!(phase, "start" | "prepare" | "advance" | "inspect"),
        "unknown exit phase"
    );
    let mut intent = match load(path, &req.action_id)? {
        Some(intent) => {
            ensure!(
                intent.version == 1
                    && intent.action_id == req.action_id
                    && intent.input_vtxo_ids == ids
                    && intent.server_pubkey == req.expected_server_pubkey
                    && intent.network == network.to_string(),
                "exit frozen identity changed"
            );
            verify_terms(&intent, req)?;
            verify_exit_budget(
                intent.fee_cap_sat,
                req.maximum_fee_sat,
                &intent.steps.iter().map(|s| s.fee_sat).collect::<Vec<_>>(),
                0,
            )?;
            ensure!(
                phase != "start" && phase != "prepare",
                "exit already exists; explicit advance or inspect required"
            );
            intent
        }
        None => {
            ensure!(matches!(phase,"start"|"prepare"), "exit has no frozen intent to advance");
            ensure!(
                !has_unfinished_intent(path)? && !wallet.exit_mgr().has_pending_exits().await,
                "another exit already owns this wallet"
            );
            ensure!(
                req.maximum_fee_sat > 0,
                "exit needs a positive explicit lifetime fee budget"
            );
            let (rate, source) = request_terms(req)?;
            wallet.sync_onchain().await?;
            let onchain = wallet
                .onchain()
                .context("exit requires an onchain wallet")?;
            let guard = onchain.read().await;
            let bdk = (&*guard as &dyn std::any::Any)
                .downcast_ref::<OnchainWallet>()
                .context("exit requires BDK wallet")?;
            let own = bdk
                .list_unspent()
                .into_iter()
                .find(|u| u.outpoint == source)
                .context("exit fee source is not owned/unspent")?;
            ensure!(
                matches!(
                    own.chain_position,
                    bdk_wallet::chain::ChainPosition::Confirmed { .. }
                ) && own.txout.script_pubkey.is_p2wpkh(),
                "exit fee source must be confirmed owned BIP84 funds"
            );
            let destination = wallet.fallback_destination().await?.spk;
            ensure!(
                guard.is_mine(&destination).await?,
                "exit destination must belong to this actor"
            );
            drop(guard);
            let mut signed_vtxos = Vec::new();
            let mut inputs = Vec::new();
            for id in &ids {
                let id = ark::VtxoId::from_str(id)?;
                let coin = wallet.get_vtxo_by_id(id).await?;
                ensure!(
                    coin.state.kind() == bark::vtxo::VtxoStateKind::Spendable,
                    "locked/spent or round-held inputs cannot start an exit"
                );
                let full = wallet.get_full_vtxo(id).await?;
                full.check_standard()?;
                wallet.validate_vtxo(&full).await?;
                let tip=wallet.chain().tip().await?.to_u32();
                let margin=wallet.config().vtxo_exit_margin.to_u32();
                ensure!(margin>0 && tip.checked_add(margin).is_some_and(|h|h<full.expiry_height().to_u32()),
                    "exit start would consume the configured exitability margin");
                ensure!(
                    wallet
                        .chain()
                        .tx_confirmed(full.chain_anchor().txid)
                        .await?
                        .is_some(),
                    "exit anchor is unconfirmed"
                );
                ensure!(
                    matches!(full.policy(), ark::VtxoPolicy::Pubkey(_)),
                    "exit requires an owned public-key coin"
                );
                let (_, key) = wallet
                    .pubkey_keypair(&full.user_pubkey())
                    .await?
                    .context("exit input is not this actor's key")?;
                let status = rpc
                    .get_vtxo_status(protos::GetVtxoStatusRequest {
                        vtxo_id: id.to_bytes().to_vec(),
                        attestation: ark::ProtocolEncoding::serialize(
                            &ark::attestations::VtxoStatusAttestation::new(id, &key),
                        ),
                    })
                    .await?
                    .into_inner();
                ensure!(
                    status.spend_state == protos::VtxoSpendState::Spendable as i32,
                    "server does not positively report this exit input spendable"
                );
                signed_vtxos.push(hex(&ark::ProtocolEncoding::serialize(&full)));
                inputs.push(coin.vtxo);
            }
            // The SDK emergency estimate signs a dummy claim to measure weight.
            // Never call it before the persisted proposal. Every real CPFP and
            // claim below is priced from its unsigned PSBT before reserving or signing.
            let intent = Intent {
                version: 1,
                action_id: req.action_id.clone(),
                server_pubkey: req.expected_server_pubkey.clone(),
                network: network.to_string(),
                input_vtxo_ids: ids.clone(),
                signed_vtxos,
                fee_cap_sat: req.maximum_fee_sat,
                fee_rate_kwu: rate.to_sat_per_kwu(),
                fee_source: source,
                destination_script: destination,
                steps: Vec::new(),
                finished: false,
            };
            evidence(
                req,
                "exit_proposal",
                json!({"stage":"start","input_vtxo_ids":ids,"signed_vtxos":intent.signed_vtxos,
                "destination_script":hex(intent.destination_script.as_bytes()),"fee_cap_sat":intent.fee_cap_sat,
                "fee_rate_kwu":intent.fee_rate_kwu,"fee_funding_outpoint":source.to_string(),"no_automatic_fee_bumps":true}),
            )?;
            persist(path, &intent)?;
            wallet.exit_mgr().start_exit_for_vtxos(&inputs).await?;
            for id in &ids {
                let exit = wallet
                    .exit_mgr()
                    .get_exit_vtxo(ark::VtxoId::from_str(id)?)
                    .await
                    .context("exit registration missing")?;
                let movement = exit.movement_id().context("exit has no owner movement")?;
                wallet
                    .lock_vtxos([ark::VtxoId::from_str(id)?], Some(movement.into()))
                    .await?;
            }
            intent
        }
    };
    ensure!(
        intent.signed_vtxos.len() == ids.len(),
        "exit frozen input proof set is incomplete"
    );
    // Explicit continuation must still use exactly the same signed owned inputs.
    for (id, signed) in ids.iter().zip(&intent.signed_vtxos) {
        let full = wallet.get_full_vtxo(ark::VtxoId::from_str(id)?).await?;
        ensure!(
            hex(&ark::ProtocolEncoding::serialize(&full)) == *signed
                && wallet.pubkey_keypair(&full.user_pubkey()).await?.is_some(),
            "exit original signed ownership changed"
        );
    }
    if phase == "prepare" {
        let packages=statuses(wallet,&ids).await?;
        ensure!(packages.len()==ids.len() && packages.iter().all(|row|row["transactions"].as_array().is_some_and(|txs|!txs.is_empty())),
            "prepared exit lacks complete signed ancestor packages");
        evidence(req,"exit_prepared",json!({"input_vtxo_ids":ids,"exits":packages,"fee_cap_sat":intent.fee_cap_sat,
            "no_progress_no_cpfp_no_claim":true} ))?;
        return Ok(json!({"exit_action_id":intent.action_id,"prepared":true,"exits":packages,
            "input_vtxo_ids":ids,"fee_cap_sat":intent.fee_cap_sat,"actual_fee_sat":Value::Null,
            "no_progress_no_cpfp_no_claim":true,"note":"registered and locked original intent; signed ancestors are existing SDK inventory, not newly broadcast exits"}));
    }
    if phase == "inspect" {
        return Ok(
            json!({"exit_action_id":intent.action_id,"exits":statuses(wallet,&ids).await?,"steps":intent.steps,"read_only":true,"actual_fee_sat":0}),
        );
    }
    wallet.sync_onchain().await?;
    // Existing signatures are replayed only under explicit positive intent. No
    // unsigned/uncertain prior attempt is reconstructed or charged a second time.
    for step in &intent.steps {
        let txid = bitcoin::Txid::from_str(&step.txid)?;
        if wallet.chain().tx_confirmed(txid).await?.is_none() {
            if step.signed_tx.is_none() {
                return Ok(held(
                    "an earlier signature outcome remains unknown",
                    &intent,
                ));
            }
            submit_existing(wallet, &intent, step).await?;
            return Ok(held(
                "await existing frozen exit transaction confirmation",
                &intent,
            ));
        }
    }
    wallet.exit_mgr().progress_exits(wallet).await?;
    let rate = FeeRate::from_sat_per_kwu(intent.fee_rate_kwu);
    let spent = intent.steps.iter().map(|s| s.fee_sat).collect::<Vec<_>>();
    let used = spent
        .iter()
        .try_fold(0u64, |a, v| a.checked_add(*v))
        .context("exit fee sum overflow")?;
    let remaining = intent
        .fee_cap_sat
        .checked_sub(used)
        .context("exit budget exhausted")?;
    let claimable = wallet
        .exit_mgr()
        .list_claimable()
        .await
        .into_iter()
        .filter(|v| ids.contains(&v.id().to_string()))
        .collect::<Vec<_>>();
    let requests = wallet
        .exit_mgr()
        .exits_needing_cpfp()
        .await
        .into_iter()
        .filter(|v| ids.contains(&v.vtxo_id.to_string()) && v.rbf_requirement.is_none())
        .collect::<Vec<_>>();
    let onchain = wallet.onchain().context("exit requires onchain wallet")?;
    let mut guard = onchain.write().await;
    let bdk = (&mut *guard as &mut dyn std::any::Any)
        .downcast_mut::<OnchainWallet>()
        .context("exit requires BDK wallet")?;
    let (mut psbt, expected, parent, kind) = if claimable.len() == ids.len() {
        let mut expected = Vec::new();
        for exit in &claimable {
            let full = wallet.get_full_vtxo(exit.id()).await?;
            expected.push((full.point(), full.txout()));
        }
        let mut builder = bdk.build_tx();
        builder
            .manually_selected_only()
            .drain_to(intent.destination_script.clone())
            .fee_rate(rate);
        builder
            .add_exit_claim_inputs(wallet, &claimable.iter().collect::<Vec<_>>())
            .await?;
        (builder.finish()?, expected, None, "claim")
    } else if let Some(request) = requests.first() {
        let tx = &request.exit_tx;
        let anchors = tx
            .output
            .iter()
            .enumerate()
            .filter(|(_, out)| out.script_pubkey == ScriptBuf::new_p2a())
            .collect::<Vec<_>>();
        ensure!(anchors.len() == 1, "exit parent anchor is ambiguous");
        let anchor = (
            OutPoint {
                txid: tx.compute_txid(),
                vout: anchors[0].0 as u32,
            },
            anchors[0].1.clone(),
        );
        let source = if let Some(step) = intent.steps.iter().rev().find(|s| s.kind == "cpfp") {
            OutPoint {
                txid: bitcoin::Txid::from_str(&step.txid)?,
                vout: 0,
            }
        } else {
            intent.fee_source
        };
        let owned = bdk
            .list_unspent()
            .into_iter()
            .find(|u| u.outpoint == source)
            .context("frozen exit fee source/change is not unspent")?;
        ensure!(
            matches!(
                owned.chain_position,
                bdk_wallet::chain::ChainPosition::Confirmed { .. }
            ) && owned.txout.script_pubkey.is_p2wpkh(),
            "exit fee source/change must be confirmed owned BIP84 funds"
        );
        let expected = vec![anchor.clone(), (source, owned.txout)];
        let prepare = |bdk: &mut OnchainWallet, fee: Amount| -> Result<Psbt> {
            let mut builder = bdk.build_tx();
            builder
                .add_utxo(source)?
                .manually_selected_only()
                .exclude_unconfirmed()
                .only_witness_utxo()
                .version(3)
                .add_foreign_utxo(
                    anchor.0,
                    bitcoin::psbt::Input {
                        witness_utxo: Some(anchor.1.clone()),
                        final_script_witness: Some(bitcoin::Witness::new()),
                        ..Default::default()
                    },
                    Weight::from_wu(1),
                )?;
            builder
                .drain_to(intent.destination_script.clone())
                .fee_absolute(fee);
            Ok(builder.finish()?)
        };
        let draft = prepare(bdk, Amount::ZERO)?;
        // BIP84 witness <=109 bytes, empty anchor witness1, SegWit marker2.
        let bound = draft.unsigned_tx.weight() + Weight::from_wu(112);
        let fee = rate * (tx.weight() + bound);
        if fee.to_sat() > remaining {
            return Ok(held(
                "CPFP would exceed frozen remaining fee budget",
                &intent,
            ));
        }
        (
            prepare(bdk, fee)?,
            expected,
            Some(hex(&bitcoin::consensus::serialize(tx))),
            "cpfp",
        )
    } else {
        drop(guard);
        let states = statuses(wallet, &ids).await?;
        intent.finished =
            states.len() == ids.len() && states.iter().all(|s| s["state"]["type"] == "claimed");
        persist(path, &intent)?;
        return Ok(
            json!({"started":true,"exit_action_id":intent.action_id,"exits":states,"finished":intent.finished,
            "fee_cap_sat":intent.fee_cap_sat,"reserved_mining_fee_sat":used,"actual_fee_sat":Value::Null,"note":"CSV/confirmation/terminal outcomes require independent chain evidence"}),
        );
    };
    ensure!(
        guard.is_mine(&intent.destination_script).await?,
        "exit destination ownership changed"
    );
    let fee = verify_psbt(&psbt, &expected, &intent.destination_script, remaining)?;
    verify_exit_budget(intent.fee_cap_sat, req.maximum_fee_sat, &spent, fee)?;
    let txid = psbt.unsigned_tx.compute_txid().to_string();
    ensure!(
        !intent.steps.iter().any(|s| s.txid == txid),
        "exit transaction already reserved"
    );
    let step = Step {
        kind: kind.into(),
        txid: txid.clone(),
        unsigned_tx: hex(&bitcoin::consensus::serialize(&psbt.unsigned_tx)),
        signed_tx: None,
        fee_sat: fee,
        parent_tx: parent,
        inputs: expected,
    };
    evidence(
        req,
        "exit_proposal",
        json!({"stage":kind,"input_vtxo_ids":ids,"destination_script":hex(intent.destination_script.as_bytes()),
        "unsigned_tx":step.unsigned_tx,"parent_tx":step.parent_tx,"txid":txid,"inputs":step.inputs,"fee_sat":fee,"prior_reserved_fee_sat":used,"fee_cap_sat":intent.fee_cap_sat}),
    )?;
    // Reserve durably BEFORE signing: a lost signature reply keeps the budget.
    intent.steps.push(step);
    persist(path, &intent)?;
    if kind == "claim" {
        wallet
            .exit_mgr()
            .sign_exit_claim_inputs(&mut psbt, wallet)
            .await?;
    }
    let signed = guard.finish_psbt(psbt).await?.extract_tx()?;
    drop(guard);
    ensure!(
        signed.compute_txid().to_string() == txid,
        "signer changed exit transaction"
    );
    intent.steps.last_mut().unwrap().signed_tx = Some(hex(&bitcoin::consensus::serialize(&signed)));
    persist(path, &intent)?;
    evidence(
        req,
        "exit_signed",
        json!({"stage":kind,"txid":txid,"signed_tx":hex(&bitcoin::consensus::serialize(&signed)),
            "parent_tx":intent.steps.last().and_then(|step|step.parent_tx.as_ref()),"fee_sat":fee,"fee_cap_sat":intent.fee_cap_sat}),
    )?;
    submit_existing(wallet, &intent, intent.steps.last().unwrap()).await?;
    wallet.exit_mgr().progress_exits(wallet).await?;
    Ok(
        json!({"started":true,"exit_action_id":intent.action_id,"input_vtxo_ids":ids,"txid":txid,"phase":kind,
        "exits":statuses(wallet,&ids).await?,"actual_fee_sat":Value::Null,"note":"frozen signature submitted; await independent confirmed-chain fee and claim evidence"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn point(name: u8) -> OutPoint {
        OutPoint {
            txid: bitcoin::Txid::from_byte_array([name; 32]),
            vout: 0,
        }
    }
    fn script(name: u8) -> ScriptBuf {
        ScriptBuf::from_hex(&format!("0014{}", hex(&[name; 20]))).unwrap()
    }
    fn psbt() -> (Psbt, Vec<(OutPoint, TxOut)>, ScriptBuf) {
        let source = point(1);
        let anchor = point(2);
        let destination = script(3);
        let expected = vec![
            (
                source,
                TxOut {
                    value: Amount::from_sat(5000),
                    script_pubkey: script(4),
                },
            ),
            (
                anchor,
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::new_p2a(),
                },
            ),
        ];
        let tx = Transaction {
            version: bitcoin::transaction::Version(3),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: expected
                .iter()
                .map(|(point, _)| bitcoin::TxIn {
                    previous_output: *point,
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(4900),
                script_pubkey: destination.clone(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        for (input, (_, output)) in psbt.inputs.iter_mut().zip(&expected) {
            input.witness_utxo = Some(output.clone());
        }
        (psbt, expected, destination)
    }
    #[test]
    fn exact_exit_fee_guard_rejects_overspend_extra_inputs_or_foreign_outputs() {
        let (mut psbt, expected, destination) = psbt();
        assert_eq!(
            verify_psbt(&psbt, &expected, &destination, 100).unwrap(),
            100
        );
        assert!(verify_psbt(&psbt, &expected, &destination, 99).is_err());
        psbt.unsigned_tx.output[0].script_pubkey = script(9);
        assert!(verify_psbt(&psbt, &expected, &destination, 100).is_err());
        psbt.unsigned_tx.output[0].script_pubkey = destination.clone();
        psbt.unsigned_tx
            .input
            .push(psbt.unsigned_tx.input[0].clone());
        assert!(verify_psbt(&psbt, &expected, &destination, 100).is_err());
    }
    #[test]
    fn input_values_scripts_missing_utxos_duplicates_and_prior_signatures_are_rejected() {
        let (good, expected, destination) = psbt();
        let mut altered = good.clone();
        altered.inputs[0].witness_utxo.as_mut().unwrap().value = Amount::from_sat(5001);
        assert!(verify_psbt(&altered, &expected, &destination, 101).is_err());
        altered = good.clone();
        altered.inputs[0]
            .witness_utxo
            .as_mut()
            .unwrap()
            .script_pubkey = script(9);
        assert!(verify_psbt(&altered, &expected, &destination, 100).is_err());
        altered = good.clone();
        altered.inputs[0].witness_utxo = None;
        assert!(verify_psbt(&altered, &expected, &destination, 100).is_err());
        altered = good.clone();
        altered.unsigned_tx.input[1] = altered.unsigned_tx.input[0].clone();
        assert!(verify_psbt(&altered, &expected, &destination, 100).is_err());
        altered = good.clone();
        altered.unsigned_tx.input[0].witness.push([1]);
        assert!(verify_psbt(&altered, &expected, &destination, 100).is_err());
    }
    #[test]
    fn dust_and_split_claim_outputs_are_not_signed() {
        let (mut psbt, expected, destination) = psbt();
        psbt.unsigned_tx.output[0].value = Amount::from_sat(1);
        assert!(verify_psbt(&psbt, &expected, &destination, 5000).is_err());
        psbt.unsigned_tx.output[0].value = Amount::from_sat(4900);
        psbt.unsigned_tx
            .output
            .push(psbt.unsigned_tx.output[0].clone());
        assert!(verify_psbt(&psbt, &expected, &destination, 100).is_err());
    }
    fn request(ids: Value) -> Request {
        Request {
            operation: "exit".into(),
            action_id: "exit-action".into(),
            actor_dir: None,
            expected_server_pubkey: String::new(),
            args: json!({"input_vtxo_ids":ids}),
            maximum_fee_sat: 1000,
        }
    }
    #[test]
    fn an_exit_never_selects_undeclared_duplicated_or_unbounded_coins() {
        let id = point(1).to_string();
        assert_eq!(
            request_ids(&request(json!([id.clone()]))).unwrap(),
            vec![id.clone()]
        );
        for ids in [
            json!([]),
            json!([id.clone(), id.clone()]),
            json!(["not-a-coin"]),
            json!([1]),
            json!(vec![id; 17]),
        ] {
            assert!(request_ids(&request(ids)).is_err());
        }
    }
    #[test]
    fn capped_attempt_is_durable_even_when_signing_outcome_is_unknown() {
        let path = std::env::temp_dir().join(format!(
            "bark-exit-state-{}-{}",
            std::process::id(),
            bitcoin::secp256k1::rand::random::<u64>()
        ));
        fs::create_dir_all(&path).unwrap();
        let (psbt, inputs, destination) = psbt();
        let txid = psbt.unsigned_tx.compute_txid().to_string();
        let intent = Intent {
            version: 1,
            action_id: "../../cannot-escape".into(),
            server_pubkey: "server".into(),
            network: "regtest".into(),
            input_vtxo_ids: vec![point(1).to_string()],
            signed_vtxos: vec!["signed".into()],
            fee_cap_sat: 100,
            fee_rate_kwu: 250,
            fee_source: point(1),
            destination_script: destination,
            finished: false,
            steps: vec![Step {
                kind: "cpfp".into(),
                txid,
                unsigned_tx: hex(&bitcoin::consensus::serialize(&psbt.unsigned_tx)),
                signed_tx: None,
                fee_sat: 100,
                parent_tx: None,
                inputs,
            }],
        };
        persist(&path, &intent).unwrap();
        let loaded = load(&path, &intent.action_id).unwrap().unwrap();
        let mut continuation = request(json!([point(1).to_string()]));
        continuation.args["fee_rate_sat_per_vb"] = json!(1);
        continuation.args["fee_funding_outpoint"] = json!(point(1).to_string());
        verify_terms(&loaded, &continuation).unwrap();
        continuation.args["fee_rate_sat_per_vb"] = json!(2);
        assert!(verify_terms(&loaded, &continuation).is_err());
        continuation.args["fee_rate_sat_per_vb"] = json!(1);
        continuation.args["fee_funding_outpoint"] = json!(point(2).to_string());
        assert!(verify_terms(&loaded, &continuation).is_err());
        continuation.args["fee_funding_outpoint"] = Value::Null;
        assert!(verify_terms(&loaded, &continuation).is_err());
        let native = serde_json::to_value(&loaded.steps[0].inputs).unwrap();
        assert!(native[0][0].is_string());
        assert_eq!(native[0][1]["value"], json!(5000));
        assert_eq!(
            native[0][1]["script_pubkey"],
            json!(hex(script(4).as_bytes()))
        );
        assert_eq!(loaded.fee_cap_sat, 100);
        assert_eq!(loaded.steps[0].fee_sat, 100);
        assert!(loaded.steps[0].signed_tx.is_none());
        assert!(intent_path(&path, &intent.action_id).starts_with(&path));
        assert!(has_unfinished_intent(&path).unwrap());
        assert_eq!(
            fs::metadata(intent_path(&path, &intent.action_id))
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
        fs::remove_dir_all(path).unwrap();
    }
}

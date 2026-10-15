// Include as a round_padding submodule of simulator_vertical. Call qualify
// after the existing payments fixture has completed its actor assertions.
use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark_testing::{Captaind, TestContext};
use bitcoin::hashes::{sha256, Hash};
use bitcoin_ext::rpc::RpcApi;
use serde_json::{json, Value};
use server::database::Db;
use std::{collections::BTreeSet, io::Write, path::Path};

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

async fn inventory(db: &Db) -> (Vec<Value>, Vec<Vtxo>) {
    let metadata = db.read(async |tx| Ok(tx.query(
        "SELECT jsonb_build_object('vtxo_id',vtxo_id,'expiry',expiry,'policy_type',policy_type,'spend_state',spend_state,'onchain_spent_txid',onchain_spent_txid)::text FROM vtxo ORDER BY vtxo_id", &[]
    ).await?)).await.unwrap();
    let mut rows = metadata.iter().map(|r| serde_json::from_str::<Value>(&r.get::<_,String>(0)).unwrap()).collect::<Vec<_>>();
    let ids = rows.iter().map(|r| r["vtxo_id"].as_str().unwrap().parse::<VtxoId>().unwrap()).collect::<Vec<_>>();
    let full = db.read(async |tx| tx.get_server_vtxos_by_id(&ids).await).await.unwrap();
    let mut padding = Vec::new();
    for row in &mut rows {
        let coin = &full.iter().find(|c| c.vtxo_id.to_string()==row["vtxo_id"].as_str().unwrap()).unwrap().vtxo;
        row["signed_vtxo"] = json!(hex(&coin.serialize()));
        if coin.policy().user_pubkey().map(|p|p.to_string()).as_deref()==Some("02dfa52f6690299d2d6a08323083e290597b56fee125063e5f4e2957731639c42c")
            && coin.unlock_hash().map(|h|h.to_string()).as_deref()==Some("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef") {
            assert_eq!(coin.amount().to_sat(),330);
            padding.push(coin.clone().try_into_user_vtxo().unwrap());
        }
    }
    (rows,padding)
}

async fn check(ctx: &TestContext, srv: &Captaind, db: &Db, root: &Path, out: &Path, phase: &str) -> Vec<Vtxo> {
    let core=ctx.bitcoind().sync_client();
    let (rows,padding)=inventory(db).await;
    let scripts=srv.wallet_status().await.rounds.confirmed_utxos.iter().map(|point| {
        core.get_raw_transaction(&point.txid,None).unwrap().output[point.vout as usize].script_pubkey.to_hex_string()
    }).collect::<BTreeSet<_>>();
    let anchors=padding.iter().map(|p|p.chain_anchor().to_string()).collect::<BTreeSet<_>>();
    let candidates=rows.iter().filter(|r| anchors.contains(r["vtxo_id"].as_str().unwrap()))
        .filter_map(|r|r["onchain_spent_txid"].as_str().map(str::to_owned)).collect::<BTreeSet<_>>();
    let decoder=root.join("target/debug/server-policy-proof");
    let manifest=out.join(format!("round-padding-{phase}-manifest.json"));
    super::write_profiled(&manifest,&json!({"network":"regtest",
        "driver_config":ctx.datadir.join("sim-driver.json"),
        "core_url":ctx.bitcoind().rpc_url(),"core_cookie":ctx.bitcoind().rpc_cookie(),
        "genesis":core.get_block_hash(0).unwrap().to_string(),"server_pubkey":srv.ark_info().await.server_pubkey.to_string(),
        "decoder":decoder,"decoder_sha256":sha256::Hash::hash(&std::fs::read(&decoder).unwrap()).to_string(),
        "state_dir":out.join("round-padding-journal"),"out_dir":out,"inventory":rows,
        "fixture_operator_scripts":scripts,"sweep_candidates":candidates}));
    let process=std::process::Command::new("python3").arg(root.join("integration/round-padding-client.py")).arg(phase).arg(&manifest).output().unwrap();
    let mut log=std::fs::OpenOptions::new().append(true).create(true).open(out.join("round-padding-operations.log")).unwrap();
    log.write_all(&process.stdout).unwrap();log.write_all(&process.stderr).unwrap();
    assert!(process.status.success(),"padding {phase} assertions failed; see round-padding-operations.log");
    padding
}

pub(super) async fn qualify(ctx: &TestContext, srv: &Captaind, db: &Db, root: &Path, out: &Path) {
    let padding=check(ctx,srv,db,root,out,"before").await;
    assert!(!padding.is_empty(),"fixture must produce a real one-output padded round");
    super::super::fallback_lightning::expire_and_confirm_sweeps(ctx,db,&padding).await;
    check(ctx,srv,db,root,out,"after").await;
}

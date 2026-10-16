//! Actual Python simulator journal + native driver against isolated regtest.
use std::{path::Path, time::Duration, io::Write};
use ark_testing::{TestContext, sat};
use bitcoin::{Address, Txid, Amount};
use bitcoin::hex::FromHex;
use bitcoin_ext::{rpc::RpcApi, BlockDelta};
use server::database::Db;
use ark::{ProtocolEncoding, Vtxo, VtxoId};
use serde_json::{json, Value};

fn write(path: &Path, value: &Value) { std::fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap(); }
// Only configuration and fixture manifests use this writer. Public evidence is
// written unchanged by `write`.
fn write_profiled(path: &Path, value: &Value) {
    let mut value = value.clone();
    match std::env::var("SIMULATOR_ARCHITECTURE_PROFILE") {
        Ok(profile) => {
            assert!(matches!(profile.as_str(), "two_step_per_key" | "direct_xpub" | "direct_per_key"),
                "unsupported fixture architecture profile");
            value.as_object_mut().expect("fixture config must be an object")
                .insert("architecture_profile".to_owned(), json!(profile));
            let sdk = std::env::var("SIMULATOR_DRIVER_SDK_COMMIT")
                .expect("explicit fixture requires the qualified driver SDK pin");
            assert!(sdk.len() == 40 && sdk.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
                "full lowercase driver SDK commit required");
            value.as_object_mut().unwrap().insert("sdk_commit".to_owned(), json!(sdk));
        },
        Err(std::env::VarError::NotPresent) => {}, // Historical Track B fixture.
        Err(error) => panic!("invalid fixture architecture profile: {error}"),
    }
    write(path, &value);
}

fn client(root: &Path, mode: &str, manifest: &Path, out: &Path) -> Value {
    let result=std::process::Command::new("python3").arg(root.join("integration/regtest-client.py"))
        .arg(mode).arg(manifest).output().unwrap();
    let mut log=std::fs::OpenOptions::new().append(true).create(true).open(out.join("client-operations.log")).unwrap();
    log.write_all(&result.stdout).unwrap();log.write_all(&result.stderr).unwrap();
    assert!(result.status.success(), "Python simulator {mode} failed; see client-operations.log");
    if result.stdout.is_empty() {json!({})} else {serde_json::from_slice(&result.stdout).unwrap()}
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn simulator_board_absence_restore() {
    board_absence_restore(false,None,false).await;
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn simulator_pending_board_absence_restore() {
    board_absence_restore(true,None,false).await;
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn simulator_ark_receive_then_disappear() {
    board_absence_restore(false,Some("ark"),false).await;
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn simulator_lightning_receive_then_disappear() {
    board_absence_restore(false,Some("lightning"),false).await;
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn simulator_public_payout_seed_recovery() {
    board_absence_restore(false,None,true).await;
}

async fn board_absence_restore(pending: bool,rail: Option<&'static str>,automated: bool) {
    let root=std::path::PathBuf::from(std::env::var("SIMULATOR_WORKSPACE").unwrap());
    let out=std::path::PathBuf::from(std::env::var("SIMULATOR_OUT").unwrap());
    std::fs::create_dir_all(&out).unwrap();
    let test_name=if automated {"simulator_public_payout_seed_recovery"} else {match rail {Some("ark")=>"simulator_ark_receive_then_disappear",Some("lightning")=>"simulator_lightning_receive_then_disappear",_=>if pending {"simulator_pending_board_absence_restore"} else {"simulator_board_absence_restore"}}};
    let ctx=TestContext::new(&format!("bark_sdk/{test_name}")).await;
    let core=ctx.bitcoind().sync_client();
    let lightning=if rail==Some("lightning") {Some(ctx.new_lightning_setup("lightningd").await)} else {None};
    let mut builder=ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).funded(sat(1_000_000)).watchmand();
    if let Some(ref nodes)=lightning {builder=builder.lightningd(&nodes.internal);} else {builder=builder.no_vtxo_pool();}
    let srv=builder.cfg(move |c| {
        c.vtxo_lifetime=BlockDelta::new(if rail==Some("lightning") {432} else {144});c.min_board_amount=sat(330);
        c.required_board_confirmations=6;c.round_interval=Duration::from_secs(3600);
        if rail==Some("lightning") {c.vtxopool.vtxo_targets=vec![server::vtxopool::VtxoTarget {amount:sat(10_000),count:2}];}
    }).create().await;
    if lightning.is_some() {srv.wait_for_vtxopool(&ctx).await;}
    let db=Db::connect(&srv.config().postgres).await.unwrap();
    let operator_anchor=if automated {srv.wallet_status().await.rounds.confirmed_utxos.first().copied()} else {None};
    super::fallback_lightning::train_fee_estimator(&ctx).await;
    let endpoint=srv.ark_url().replace("://0.0.0.0:", "://127.0.0.1:");
    let cfg=ctx.bark_default_cfg(&endpoint,Some(ctx.bitcoind()));
    let wallet_config=ctx.datadir.join("sim-wallet.toml");
    std::fs::write(&wallet_config,toml::to_string(&cfg).unwrap()).unwrap();
    let driver_config=ctx.datadir.join("sim-driver.json");
    let wallet_root=ctx.datadir.join("sim-wallets");std::fs::create_dir(&wallet_root).unwrap();
    write_profiled(&driver_config,&json!({"ark_endpoint":endpoint,"wallet_config":wallet_config,
        "wallet_root":wallet_root,"network":"regtest"}));
    let info=srv.ark_info().await;
    let manifest=ctx.datadir.join("sim-fixture.json");
    write_profiled(&manifest,&json!({"network":"regtest","fee_budget_sat":if rail.is_some() {100_000} else {10_000},"core_url":ctx.bitcoind().rpc_url(),
        "core_cookie":ctx.bitcoind().rpc_cookie(),"genesis":core.get_block_hash(0).unwrap().to_string(),
        "driver_config":driver_config,"driver":root.join("target/debug/bark-sim-driver"),
        "restore":root.join("target/debug/seed-restore"),"proof":root.join("target/debug/vtxo-proof"),"wallet_root":wallet_root,
        "state_dir":ctx.datadir.join("sim-journal"),"out_dir":out,
        "server_pubkey":info.server_pubkey.to_string(),
        "server_binary":std::env::var("CAPTAIND_EXEC").unwrap(),
        "server_binary_sha256":std::env::var("SIMULATOR_SERVER_SHA256").unwrap(),
        "payout_proof":out.join("payout-proof.json"),"recovery_destination":ctx.bitcoind().get_new_address().to_string()}));
    let created=client(&root,"create",&manifest,&out);
    let destination:Address=created["data"]["funding_address"].as_str().unwrap().parse::<Address<bitcoin::address::NetworkUnchecked>>().unwrap().assume_checked();
    let funding=core.send_to_address(&destination,sat(20_000),None,None,None,None,None,None).unwrap();
    ctx.await_transaction(funding).await;ctx.generate_blocks(2).await;
    let boarded=client(&root,"board",&manifest,&out);
    let id:VtxoId=boarded["data"]["board"]["vtxos"][0].as_str().unwrap().parse().unwrap();
    let board_tx:Txid=boarded["data"]["board"]["funding_tx"].as_str().map(|raw| {
        let tx:bitcoin::Transaction=bitcoin::consensus::encode::deserialize_hex(raw).unwrap();tx.compute_txid()
    }).unwrap();
    ctx.await_transaction(board_tx).await;
    let coin=if pending {
        ctx.generate_blocks(1).await;
        let observed=client(&root,"snapshot",&manifest,&out);
        assert!(observed["data"]["balance"]["pending_board_sat"].as_u64().unwrap()>0);
        assert_eq!(observed["data"]["balance"]["spendable_sat"],0);
        let registered=db.read(async |tx| Ok(tx.query_one("SELECT count(*) FROM vtxo WHERE vtxo_id=$1",
            &[&id.to_string()]).await?.get::<_,i64>(0))).await.unwrap();
        assert_eq!(registered,0,"absence must precede registration");
        let raw=db.read(async |tx| Ok(tx.query_one("SELECT vtxo FROM pending_board WHERE vtxo_id=$1",
            &[&id.to_string()]).await?.get::<_,Vec<u8>>(0))).await.unwrap();
        Vtxo::deserialize(&raw).unwrap()
    } else {
        ctx.generate_blocks(6).await;
        client(&root,"sync",&manifest,&out);client(&root,"snapshot",&manifest,&out);
        db.read(async |tx| tx.get_user_vtxos_by_id(&[id]).await).await.unwrap().remove(0).vtxo
    };
    write(&out.join("absence-boundary.json"),&json!({"scenario":if pending {"H04"} else {"H03"},
        "source":if pending {"pending board"} else {"registered board"},"coin_id":id.to_string(),
        "anchor_confirmations":core.get_raw_transaction_info(&board_tx,None).unwrap().confirmations.unwrap_or(0),
        "required_board_confirmations":6,"client_registered_before_absence":!pending}));
    let mut coins=vec![coin.clone()];
    if automated {client(&root,"fixture_backup",&manifest,&out);}
    if let Some(rail)=rail {
        if rail=="ark" {
            let sender=command(&root,"create",&manifest,&out,"actor-02",json!({}));
            let addr=sender["data"]["funding_address"].as_str().unwrap().parse::<Address<bitcoin::address::NetworkUnchecked>>().unwrap().assume_checked();
            let funding=core.send_to_address(&addr,sat(40_000),None,None,None,None,None,None).unwrap();
            ctx.await_transaction(funding).await;ctx.generate_blocks(2).await;
            command(&root,"board",&manifest,&out,"actor-02",json!({"amount_sat":30_000}));
            ctx.generate_blocks(6).await;command(&root,"sync",&manifest,&out,"actor-02",json!({}));
            let address=command(&root,"address",&manifest,&out,"actor-01",json!({}));
            command(&root,"send_arkoor",&manifest,&out,"actor-02",json!({"destination":address["data"]["address"],"amount_sat":10_000}));
            command(&root,"sync",&manifest,&out,"actor-01",json!({}));
            // Close the still-online sender's own change through the actual
            // cooperative exit. The absence payout fee is then one wallet,
            // avoiding attributing another owner's fee to this recipient.
            let exit=command(&root,"offboard_all",&manifest,&out,"actor-02",json!({}));
            let exit_tx:Txid=exit["data"]["txid"].as_str().unwrap().parse().unwrap();
            ctx.await_transaction(exit_tx).await;ctx.generate_blocks(2).await;
        } else {
            let invoice=command(&root,"invoice",&manifest,&out,"actor-01",json!({"amount_sat":10_000}));
            let nodes=lightning.as_ref().unwrap();
            let invoice=invoice["data"]["invoice"].as_str().unwrap().to_string();
            let receiving=async {
                let deadline=std::time::Instant::now()+Duration::from_secs(60);
                loop {
                    command(&root,"sync",&manifest,&out,"actor-01",json!({}));
                    let snapshot=command(&root,"snapshot",&manifest,&out,"actor-01",json!({}));
                    if snapshot["data"]["balance"]["spendable_sat"].as_u64().unwrap()>=coin.amount().to_sat()+10_000 {break;}
                    assert!(std::time::Instant::now()<deadline,"native receive did not collect external payment");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            };
            let (paid,())=tokio::join!(nodes.external.try_pay_bolt11(invoice),receiving);
            paid.expect("external Lightning payer must pay, not receive a refund");
        }
        let snapshot=command(&root,"snapshot",&manifest,&out,"actor-01",json!({}));
        let ids=snapshot["data"]["evidence"]["coins"].as_array().unwrap().iter().filter(|c|c["state"]=="Spendable")
            .map(|c|c["id"].as_str().unwrap().parse::<VtxoId>().unwrap()).collect::<Vec<_>>();
        coins=db.read(async |t|t.get_user_vtxos_by_id(&ids).await).await.unwrap().into_iter().map(|v|v.vtxo).collect();
        assert!(coins.len()>=2,"receiver must retain board plus actual incoming value");
        let absent=command(&root,"receive_absent",&manifest,&out,"actor-01",json!({"rail":rail}));
        assert_eq!(absent["online"],false);assert_eq!(absent["payout_verdict"],"pending");
        write(&out.join("receive-absence-boundary.json"),&absent);
    } else {client(&root,"absent",&manifest,&out);}
    // From here to payout, no original client calls occur.
    super::fallback_lightning::expire_and_confirm_sweeps(&ctx,&db,&coins).await;
    super::fallback_lightning::train_fee_estimator(&ctx).await;
    srv.stop().await.unwrap();
    // Freeze the real registered source while payout is disabled and the
    // server is stopped. This is a pre-commit inventory barrier; timestamp
    // equality between separate history/payout inserts is not assumed.
    let frozen_precommit=if automated {
        db.read(async |t| {
            let r=t.query_one("SELECT jsonb_build_object('spend_state',spend_state,'policy_type',policy_type,'confirmed_height',confirmed_height,'oor_spent_txid',oor_spent_txid,'spent_in_round',spent_in_round,'onchain_spent_txid',onchain_spent_txid)::text FROM vtxo WHERE vtxo_id=$1",&[&id.to_string()]).await?;
            Ok(serde_json::from_str::<Value>(&r.get::<_,String>(0)).unwrap())
        }).await.unwrap()
    } else {json!(null)};
    {
        let mut config=srv.config_mut();
        config.expiry_payout.enabled=true;config.expiry_payout.interval=Duration::from_secs(1);
        config.expiry_payout.grace_blocks=0;config.expiry_payout.sweep_min_confs=1;
        config.expiry_payout.min_payout_sat=1000;
        config.expiry_payout.watchman_config=Some(srv.watchmand().config().data_dir
            .join(ark_testing::daemon::watchmand::WATCHMAND_CONFIG_FILE));
    }
    srv.start().await.unwrap();
    let deadline=std::time::Instant::now()+Duration::from_secs(90);
    let row=loop {
        let rows=db.read(async |t| Ok(t.query("SELECT txid,spk,fee_sat FROM expiry_settlement WHERE id=$1",&[&id.to_string()]).await?)).await.unwrap();
        if !rows.is_empty() { break rows.into_iter().next().unwrap(); }
        assert!(std::time::Instant::now()<deadline,"automatic payout not committed");
        tokio::time::sleep(Duration::from_secs(1)).await;ctx.generate_blocks(1).await;
    };
    let payout:Txid=row.get::<_,String>(0).parse().unwrap();ctx.generate_blocks(2).await;
    let tx=core.get_raw_transaction(&payout,None).unwrap();
    let spk=row.get::<_,Option<Vec<u8>>>(1).unwrap();
    let outputs=tx.output.iter().enumerate().filter(|(_,o)|o.script_pubkey.as_bytes()==spk).collect::<Vec<_>>();
    assert_eq!(outputs.len(),1);
    let vout=outputs[0].0;
    let recipient_fee=row.get::<_,i64>(2) as u64;
    let principal=coins.iter().map(|c|c.amount().to_sat()).sum::<u64>();
    assert_eq!(principal,tx.output[vout].value.to_sat()+recipient_fee);
    let inputs_sat=tx.input.iter().map(|i|core.get_raw_transaction(&i.previous_output.txid,None)
        .unwrap().output[i.previous_output.vout as usize].value).sum::<Amount>().to_sat();
    let actual_fee=inputs_sat-tx.output.iter().map(|o|o.value).sum::<Amount>().to_sat();
    assert!(actual_fee>=recipient_fee);
    assert_eq!(tx.output[vout].script_pubkey.to_hex_string(),created["data"]["fallback_script"].as_str().unwrap());
    let proof=json!({"txid":payout.to_string(),"vout":vout,"spk":tx.output[vout].script_pubkey.to_hex_string(),
        "amount_sat":tx.output[vout].value.to_sat(),"principal_sat":principal,"entitlement_ids":coins.iter().map(|c|c.id().to_string()).collect::<Vec<_>>(),
        "recipient_fee_sat":recipient_fee,"operator_fee_sat":actual_fee-recipient_fee,"tx_fee_sat":actual_fee,"entitlement_id":id.to_string(),
        "confirmations":core.get_raw_transaction_info(&payout,None).unwrap().confirmations.unwrap_or(0),
        "original_client_silent":true,"funding_txid":funding.to_string()});
    write(&out.join("payout-proof.json"),&proof);
    if automated {
        let cs=db.read(async |t| {t.read_aggregate_changeset(server::wallet::WalletKind::Rounds).await}).await.unwrap().unwrap();
        let descriptor=cs.descriptor.unwrap().to_string();
        let last_index=cs.indexer.last_revealed.values().copied().max().unwrap_or(0);
        let anchor=operator_anchor.expect("confirmed independently observed rounds-wallet anchor");
        let anchor_tx=core.get_raw_transaction(&anchor.txid,None).unwrap();
        let anchor_script=anchor_tx.output[anchor.vout as usize].script_pubkey.to_hex_string();
        let raw_coins=db.read(async |t| {
            let rows=t.query("SELECT encode(l.sig,'hex') AS sig FROM key_link l WHERE l.user_pubkey=$1",
                &[&coin.user_pubkey().serialize().to_vec()]).await?;
            Ok(rows[0].get::<_,String>(0))
        }).await.unwrap();
        let states=db.read(async |t| {
            let row=t.query_one("SELECT coalesce((SELECT jsonb_agg(jsonb_build_object('spend_state',h.spend_state)) FROM vtxo_history h WHERE h.vtxo_id=s.id AND h.history_created_at=s.created_at),'[]'::jsonb)::text FROM expiry_settlement s WHERE s.id=$1",&[&id.to_string()]).await?;
            Ok(row.get::<_,String>(0))
        }).await.unwrap();
        let identity=json!({"network":"regtest","genesis":core.get_block_hash(0).unwrap().to_string(),"server_pubkey":info.server_pubkey.to_string()});
        let advertised=&created["data"]["binding"];
        let binding=json!({"mailbox_pk":advertised["mailbox_pk"],"seq":advertised["seq"],
            "spk":advertised["spk"],"record_attestation":advertised["record_attestation"]});
        let serialized=coin.serialize().iter().map(|byte|format!("{byte:02x}")).collect::<String>();
        write(&out.join("public-proof-bundle.json"),&json!({"schema_version":1,"actor":"actor-01","identity":identity,
            "coins":[{"id":id.to_string(),"user_pubkey":coin.user_pubkey().to_string(),"amount_sat":coin.amount().to_sat(),
                "expiry_height":coin.expiry_height().to_u32(),"signed_vtxo":serialized,"key_link_attestation":raw_coins,"binding":binding}]}));
        write(&out.join("public-operator-descriptor.json"),&json!({"schema_version":1,"identity":identity,"descriptor":descriptor,"first_index":0,"last_index":last_index}));
        write(&out.join("public-payout-inventory.json"),&json!({"binding":binding,"operator_anchor":{"script":anchor_script,"outpoint":anchor.to_string(),"confirmations":core.get_raw_transaction_info(&anchor.txid,None).unwrap().confirmations.unwrap_or(0)},
            "pre_commit_source":{"scope":"actual server inventory frozen with payout disabled and captaind stopped; no original client calls after absence","history_at_settlement_timestamp":serde_json::from_str::<Value>(&states).unwrap()},
            "settlements":[{"id":id.to_string(),"txid":payout.to_string(),"fee_sat":recipient_fee,"spk":proof["spk"],"tx_settlement_count":1,"pre_commit_rows":[frozen_precommit],"htlc":null}]}));
    }
    let restored=client(&root,if automated {"verified_recovery"} else {"recover"},&manifest,&out);
    let spend:Txid=restored["spend_txid"].as_str().unwrap().parse().unwrap();
    ctx.generate_blocks(2).await;
    assert!(core.get_raw_transaction_info(&spend,None).unwrap().confirmations.unwrap_or(0)>0);
    let recovery_confirmation=if automated {client(&root,"verified_recovery_confirm",&manifest,&out)} else {json!(null)};
    let spendtx=core.get_raw_transaction(&spend,None).unwrap();
    assert!(spendtx.input.iter().any(|i|i.previous_output==bitcoin::OutPoint::new(payout,vout as u32)));
    let fee=restored["fee_sat"].as_u64().unwrap();
    let sum=restored["inputs"].as_array().unwrap().iter().map(|i|i["amount_sat"].as_u64().unwrap()).sum::<u64>();
    assert_eq!(sum,spendtx.output.iter().map(|o|o.value).sum::<Amount>().to_sat()+fee);
    write(&out.join("result.json"),&json!({"result":"PASS","owners":1,
        "source":rail.unwrap_or(if pending {"pending board"} else {"registered board"}),"scenario":if pending {"H04"} else {"H03"},
        "receive_rail":rail,"payout":proof,"seed_restore":restored,"confirmed_seed_spend":spend.to_string(),
        "automated_recovery":automated,"recovery_confirmation":recovery_confirmation,
        "coverage_limits":["one source vertical slice; other sources and full campaign unqualified","capital is not a minimum-capital model"]}));
}

fn command(root: &Path, mode: &str, manifest: &Path, out: &Path, actor: &str, args: Value) -> Value {
    let reserve=if mode.starts_with("raw_") {0} else {match mode {"create"|"snapshot"|"address"|"invoice"|"send_arkoor"=>0,"offboard_all"=>10_000,_=>2000}};
    let request=json!({"actor":actor,"args":args,"maximum_fee_sat":reserve});
    let result=std::process::Command::new("python3").arg(root.join("integration/regtest-client.py"))
        .arg(mode).arg(manifest).arg(request.to_string()).output().unwrap();
    let mut log=std::fs::OpenOptions::new().append(true).create(true).open(out.join("client-operations.log")).unwrap();
    log.write_all(&result.stdout).unwrap();log.write_all(&result.stderr).unwrap();
    assert!(result.status.success(),"actual simulator {actor} {mode} failed; see client-operations.log");
    serde_json::from_slice(&result.stdout).unwrap()
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn simulator_concurrent_clients() {
    let root=std::path::PathBuf::from(std::env::var("SIMULATOR_WORKSPACE").unwrap());
    let out=std::path::PathBuf::from(std::env::var("SIMULATOR_OUT").unwrap());
    std::fs::create_dir_all(&out).unwrap();
    let ctx=TestContext::new("bark_sdk/simulator_concurrent_clients").await;
    let core=ctx.bitcoind().sync_client();
    let srv=ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).funded(sat(1_000_000)).watchmand().no_vtxo_pool().cfg(|c| {
        c.vtxo_lifetime=BlockDelta::new(432);c.min_board_amount=sat(330);
        c.required_board_confirmations=6;c.round_interval=Duration::from_secs(3600);
    }).create().await;
    super::fallback_lightning::train_fee_estimator(&ctx).await;
    let endpoint=srv.ark_url().replace("://0.0.0.0:","://127.0.0.1:");
    let wallet_config=ctx.datadir.join("sim-wallet.toml");
    std::fs::write(&wallet_config,toml::to_string(&ctx.bark_default_cfg(&endpoint,Some(ctx.bitcoind()))).unwrap()).unwrap();
    let driver_config=ctx.datadir.join("sim-driver.json");
    let wallet_root=ctx.datadir.join("sim-wallets");std::fs::create_dir(&wallet_root).unwrap();
    write_profiled(&driver_config,&json!({"ark_endpoint":endpoint,"wallet_config":wallet_config,"wallet_root":wallet_root,"network":"regtest"}));
    let manifest=ctx.datadir.join("sim-fixture.json");
    write_profiled(&manifest,&json!({"network":"regtest","fee_budget_sat":100_000,"core_url":ctx.bitcoind().rpc_url(),"core_cookie":ctx.bitcoind().rpc_cookie(),
        "genesis":core.get_block_hash(0).unwrap().to_string(),"driver_config":driver_config,"driver":root.join("target/debug/bark-sim-driver"),
        "proof":root.join("target/debug/vtxo-proof"),"wallet_root":wallet_root,"state_dir":ctx.datadir.join("sim-journal"),"out_dir":out,
        "server_pubkey":srv.ark_info().await.server_pubkey.to_string(),"server_binary":std::env::var("CAPTAIND_EXEC").unwrap(),
        "server_binary_sha256":std::env::var("SIMULATOR_SERVER_SHA256").unwrap()}));
    let actors=["actor-01","actor-02","actor-05","actor-07","actor-08"];
    for actor in actors {
        let created=command(&root,"create",&manifest,&out,actor,json!({}));
        let address=created["data"]["funding_address"].as_str().unwrap().parse::<Address<bitcoin::address::NetworkUnchecked>>().unwrap().assume_checked();
        let tx=core.send_to_address(&address,sat(20_000),None,None,None,None,None,None).unwrap();
        ctx.await_transaction(tx).await;
    }
    ctx.generate_blocks(2).await;
    let two=command(&root,"dispatch_overlap",&manifest,&out,"actor-01",json!({"actors":&actors[..2]}));
    let three=command(&root,"dispatch_overlap",&manifest,&out,"actor-05",json!({"actors":&actors[2..]}));
    ctx.generate_blocks(6).await;
    let mut snapshots=vec![];
    for actor in actors {
        command(&root,"sync",&manifest,&out,actor,json!({}));
        let snapshot=command(&root,"snapshot",&manifest,&out,actor,json!({}));
        assert_eq!(snapshot["data"]["balance"]["spendable_sat"],10_000);
        assert!(snapshot["data"]["evidence"]["coins"].as_array().unwrap().iter().any(|coin|coin["state"]=="Spendable"));
        snapshots.push(json!({"actor":actor,"snapshot":snapshot}));
    }
    let fees=command(&root,"fee_audit",&manifest,&out,"actor-01",json!({}));
    assert_eq!(fees.as_array().unwrap().iter().filter(|row|row["operation"]=="board" && row["actual_fee_sat"].as_u64().is_some_and(|fee|fee<=2000)).count(),5);
    write(&out.join("result.json"),&json!({"result":"PASS","two":two,"three":three,"snapshots":snapshots,"fees":fees,
        "coverage_limits":["actual concurrent native boards; live seeded campaign overlap remains a separate gate"]}));
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn simulator_zero_spendable_scheduled_refresh() {
    let root=std::path::PathBuf::from(std::env::var("SIMULATOR_WORKSPACE").unwrap());
    let out=std::path::PathBuf::from(std::env::var("SIMULATOR_OUT").unwrap());
    std::fs::create_dir_all(&out).unwrap();
    let ctx=TestContext::new("bark_sdk/simulator_zero_spendable_scheduled_refresh").await;
    let core=ctx.bitcoind().sync_client();
    let srv=ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).funded(sat(1_000_000)).watchmand().no_vtxo_pool().cfg(|c| {
        c.vtxo_lifetime=BlockDelta::new(432);c.min_board_amount=sat(330);
        // Board depth is one; its first Ark receipt has three transitions.
        // This one-output round produces depth two, below this limit.
        c.max_vtxo_exit_depth=3;c.required_board_confirmations=6;c.round_interval=Duration::from_secs(3);
    }).create().await;
    super::fallback_lightning::train_fee_estimator(&ctx).await;
    let endpoint=srv.ark_url().replace("://0.0.0.0:","://127.0.0.1:");
    let wallet_config=ctx.datadir.join("sim-wallet.toml");
    std::fs::write(&wallet_config,toml::to_string(&ctx.bark_default_cfg(&endpoint,Some(ctx.bitcoind()))).unwrap()).unwrap();
    let driver_config=ctx.datadir.join("sim-driver.json");
    let wallet_root=ctx.datadir.join("sim-wallets");std::fs::create_dir(&wallet_root).unwrap();
    write_profiled(&driver_config,&json!({"ark_endpoint":endpoint,"wallet_config":wallet_config,"wallet_root":wallet_root,"network":"regtest"}));
    let manifest=ctx.datadir.join("sim-fixture.json");
    write_profiled(&manifest,&json!({"network":"regtest","fee_budget_sat":100_000,"core_url":ctx.bitcoind().rpc_url(),"core_cookie":ctx.bitcoind().rpc_cookie(),
        "genesis":core.get_block_hash(0).unwrap().to_string(),"driver_config":driver_config,"driver":root.join("target/debug/bark-sim-driver"),
        "proof":root.join("target/debug/vtxo-proof"),"wallet_root":wallet_root,"state_dir":ctx.datadir.join("sim-journal"),"out_dir":out,
        "server_pubkey":srv.ark_info().await.server_pubkey.to_string(),"server_binary":std::env::var("CAPTAIND_EXEC").unwrap(),
        "server_binary_sha256":std::env::var("SIMULATOR_SERVER_SHA256").unwrap()}));
    let sender=command(&root,"create",&manifest,&out,"actor-01",json!({}));
    command(&root,"create",&manifest,&out,"actor-07",json!({}));
    let address=sender["data"]["funding_address"].as_str().unwrap().parse::<Address<bitcoin::address::NetworkUnchecked>>().unwrap().assume_checked();
    let tx=core.send_to_address(&address,sat(40_000),None,None,None,None,None,None).unwrap();
    ctx.await_transaction(tx).await;ctx.generate_blocks(2).await;
    command(&root,"board",&manifest,&out,"actor-01",json!({"amount_sat":30_000}));
    ctx.generate_blocks(6).await;command(&root,"sync",&manifest,&out,"actor-01",json!({}));
    let recipient=command(&root,"address",&manifest,&out,"actor-07",json!({}));
    let sent=command(&root,"send_arkoor",&manifest,&out,"actor-01",json!({"destination":recipient["data"]["address"],"amount_sat":5000,"recipient_actor":"actor-07"}));
    command(&root,"sync",&manifest,&out,"actor-07",json!({}));
    let before=command(&root,"snapshot",&manifest,&out,"actor-07",json!({}));
    assert_eq!(before["data"]["balance"]["spendable_sat"],0);
    assert_eq!(before["data"]["balance"]["needs_refresh_sat"],5000);
    let old=before["data"]["evidence"]["coins"].as_array().unwrap().iter().map(|c|c["id"].as_str().unwrap().to_string()).collect::<std::collections::HashSet<_>>();
    let refreshed=command(&root,"scheduled_refresh",&manifest,&out,"actor-07",json!({}));
    let deadline=std::time::Instant::now()+Duration::from_secs(90);
    let after=loop {
        ctx.generate_blocks(ark_testing::constants::ROUND_CONFIRMATIONS).await;
        command(&root,"sync",&manifest,&out,"actor-07",json!({}));
        let snapshot=command(&root,"snapshot",&manifest,&out,"actor-07",json!({}));
        if snapshot["data"]["balance"]["spendable_sat"]==5000 && snapshot["data"]["balance"]["needs_refresh_sat"]==0 {
            let fresh=snapshot["data"]["evidence"]["coins"].as_array().unwrap().iter().filter(|c|c["state"]=="Spendable").map(|c|c["id"].as_str().unwrap().to_string()).collect::<std::collections::HashSet<_>>();
            assert!(!fresh.is_empty() && fresh.is_disjoint(&old));break snapshot;
        }
        assert!(std::time::Instant::now()<deadline,"scheduled zero-spendable refresh did not restore spendability");
        tokio::time::sleep(Duration::from_secs(1)).await;
    };
    let fees=command(&root,"fee_audit",&manifest,&out,"actor-07",json!({}));
    assert!(fees.as_array().unwrap().iter().any(|f|f["operation"]=="refresh_delegated" && f["actual_fee_sat"]==0));
    let db=Db::connect(&srv.config().postgres).await.unwrap();
    let inventory=db.read(async |t| {
        let r=t.query_one("SELECT coalesce(jsonb_agg(jsonb_build_object('vtxo_id',v.vtxo_id,'expiry',v.expiry,'spend_state',v.spend_state,'policy_type',v.policy_type,'signed_vtxo',encode(v.vtxo,'hex'),'spent_in_round',v.spent_in_round,'spent_in_round_txid',(SELECT r.funding_txid FROM round r WHERE r.id=v.spent_in_round),'offboarded_in',v.offboarded_in)),'[]'::jsonb)::text FROM vtxo v",&[]).await?;
        Ok(serde_json::from_str::<Value>(&r.get::<_,String>(0)).unwrap())
    }).await.unwrap();
    write(&out.join("public-delegated-inventory.json"),&inventory);
    let delegated=command(&root,"delegated_audit",&manifest,&out,"actor-07",json!({}));
    write(&out.join("result.json"),&json!({"result":"PASS","actor":"actor-07","max_exit_depth":3,"send":sent,"before":before,"scheduled_refresh":refreshed,"after":after,"fees":fees,"delegated_entitlement":delegated,
        "coverage_limits":["actual continuous scheduler and depth-triggered needs-refresh balance; live expiry convergence still separate"]}));
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn simulator_payments_refresh_exits() {
    let root=std::path::PathBuf::from(std::env::var("SIMULATOR_WORKSPACE").unwrap());
    let out=std::path::PathBuf::from(std::env::var("SIMULATOR_OUT").unwrap());
    std::fs::create_dir_all(&out).unwrap();
    let ctx=TestContext::new("bark_sdk/simulator_payments_refresh_exits").await;
    let lightning=ctx.new_lightning_setup("lightningd").await;
    let core=ctx.bitcoind().sync_client();
    let srv=ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).lightningd(&lightning.internal)
        .funded(sat(100_000_000)).watchmand().cfg(|c| {
            c.vtxo_lifetime=BlockDelta::new(432);c.min_board_amount=sat(330);
            c.round_interval=Duration::from_secs(3);
            c.vtxopool.vtxo_targets=vec![server::vtxopool::VtxoTarget {amount:sat(10_000),count:8}];
        }).create().await;
    srv.wait_for_vtxopool(&ctx).await;
    super::fallback_lightning::train_fee_estimator(&ctx).await;
    let endpoint=srv.ark_url().replace("://0.0.0.0:","://127.0.0.1:");
    let cfg=ctx.bark_default_cfg(&endpoint,Some(ctx.bitcoind()));
    let wallet_config=ctx.datadir.join("sim-wallet.toml");
    std::fs::write(&wallet_config,toml::to_string(&cfg).unwrap()).unwrap();
    let driver_config=ctx.datadir.join("sim-driver.json");
    let wallet_root=ctx.datadir.join("sim-wallets");std::fs::create_dir(&wallet_root).unwrap();
    write_profiled(&driver_config,&json!({"ark_endpoint":endpoint,"wallet_config":wallet_config,"wallet_root":wallet_root,"network":"regtest"}));
    let manifest=ctx.datadir.join("sim-fixture.json");
    write_profiled(&manifest,&json!({"network":"regtest","fee_budget_sat":100_000,"core_url":ctx.bitcoind().rpc_url(),"core_cookie":ctx.bitcoind().rpc_cookie(),
        "genesis":core.get_block_hash(0).unwrap().to_string(),"driver_config":driver_config,
        "driver":root.join("target/debug/bark-sim-driver"),"proof":root.join("target/debug/vtxo-proof"),"wallet_root":wallet_root,"state_dir":ctx.datadir.join("sim-journal"),
        "out_dir":out,"server_pubkey":srv.ark_info().await.server_pubkey.to_string(),
        "server_binary":std::env::var("CAPTAIND_EXEC").unwrap(),"server_binary_sha256":std::env::var("SIMULATOR_SERVER_SHA256").unwrap()}));
    command(&root,"create",&manifest,&out,"actor-06",json!({}));
    let empty_before=command(&root,"snapshot",&manifest,&out,"actor-06",json!({}));
    assert_eq!(empty_before["data"]["balance"]["spendable_sat"],0);
    assert_eq!(empty_before["data"]["onchain"]["confirmed_sat"],0);
    let empty_invoice=command(&root,"invoice",&manifest,&out,"actor-06",json!({"amount_sat":2000}));
    assert_eq!(empty_invoice["actual_fee_sat"],0);
    let receiving=async {
        let deadline=std::time::Instant::now()+Duration::from_secs(60);
        loop {
            command(&root,"sync",&manifest,&out,"actor-06",json!({}));
            let snap=command(&root,"snapshot",&manifest,&out,"actor-06",json!({}));
            if snap["data"]["balance"]["spendable_sat"]==2000 {break snap;}
            assert!(std::time::Instant::now()<deadline,"empty native wallet did not collect incoming Lightning value");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    };
    let (paid,empty_received)=tokio::join!(lightning.external.try_pay_bolt11(empty_invoice["data"]["invoice"].as_str().unwrap()),receiving);
    paid.expect("external payment to empty recipient must succeed");
    for (actor,fund,board) in [("actor-01",120_000,100_000),("actor-02",40_000,30_000)] {
        let created=command(&root,"create",&manifest,&out,actor,json!({}));
        let addr=created["data"]["funding_address"].as_str().unwrap().parse::<Address<bitcoin::address::NetworkUnchecked>>().unwrap().assume_checked();
        let tx=core.send_to_address(&addr,sat(fund),None,None,None,None,None,None).unwrap();
        ctx.await_transaction(tx).await;ctx.generate_blocks(2).await;
        command(&root,"board",&manifest,&out,actor,json!({"amount_sat":board}));
        ctx.generate_blocks(6).await;command(&root,"sync",&manifest,&out,actor,json!({}));
    }
    let address=command(&root,"address",&manifest,&out,"actor-02",json!({}));
    let arkoor=command(&root,"send_arkoor",&manifest,&out,"actor-01",json!({"destination":address["data"]["address"],"amount_sat":5000}));
    command(&root,"sync",&manifest,&out,"actor-02",json!({}));
    let received=command(&root,"snapshot",&manifest,&out,"actor-02",json!({}));
    assert_eq!(received["data"]["balance"]["spendable_sat"].as_u64().unwrap(),35_000);
    let before_a=command(&root,"snapshot",&manifest,&out,"actor-01",json!({}));
    let previous_ids=|v:&Value|v["data"]["evidence"]["coins"].as_array().unwrap().iter()
        .filter(|c|c["state"]=="Spendable").map(|c|c["id"].as_str().unwrap().to_string()).collect::<std::collections::HashSet<_>>();
    let old_a=previous_ids(&before_a);let old_b=previous_ids(&received);
    assert!(!old_a.is_empty()&&!old_b.is_empty());
    let delegated=command(&root,"refresh_delegated",&manifest,&out,"actor-02",json!({}));
    let interactive=command(&root,"refresh",&manifest,&out,"actor-01",json!({}));
    let deadline=std::time::Instant::now()+Duration::from_secs(90);
    let after_refresh=loop {
        // Each short-lived client call includes observation and proof checks.
        // Mine the configured confirmation depth per poll: slow calls must not
        // prevent an already-issued round from reaching its six confirmations.
        // Keep the original convergence deadline and ownership assertions.
        ctx.generate_blocks(ark_testing::constants::ROUND_CONFIRMATIONS).await;
        for actor in ["actor-01","actor-02"] {command(&root,"sync",&manifest,&out,actor,json!({}));}
        let a=command(&root,"snapshot",&manifest,&out,"actor-01",json!({}));
        let b=command(&root,"snapshot",&manifest,&out,"actor-02",json!({}));
        // New spendable IDs after both scheduled refresh requests must exist.
        if a["data"]["balance"]["spendable_sat"].as_u64().unwrap()>0 && b["data"]["balance"]["spendable_sat"].as_u64().unwrap()>0 {
            let fresh_a=previous_ids(&a);let fresh_b=previous_ids(&b);
            if !fresh_a.is_empty()&&!fresh_b.is_empty()&&fresh_a.is_disjoint(&old_a)&&fresh_b.is_disjoint(&old_b) {
                break json!({"interactive_actor":a,"delegated_actor":b});
            }
        }
        assert!(std::time::Instant::now()<deadline,"refresh did not converge");
        tokio::time::sleep(Duration::from_secs(1)).await;
    };
    lightning.sync().await;
    let external=lightning.external.invoice(Some(sat(2000)),"simulator-external","actual simulator payment").await;
    let paid=command(&root,"pay_invoice",&manifest,&out,"actor-01",json!({"invoice":external,"amount_sat":2000}));
    lightning.external.wait_invoice_paid("simulator-external").await;
    command(&root,"sync",&manifest,&out,"actor-01",json!({}));
    let invoice=command(&root,"invoice",&manifest,&out,"actor-02",json!({"amount_sat":2000}));
    let internal=command(&root,"pay_invoice",&manifest,&out,"actor-01",json!({"invoice":invoice["data"]["invoice"],"amount_sat":2000}));
    let deadline=std::time::Instant::now()+Duration::from_secs(60);
    loop {
        command(&root,"sync",&manifest,&out,"actor-02",json!({}));
        command(&root,"sync",&manifest,&out,"actor-01",json!({}));
        let b=command(&root,"snapshot",&manifest,&out,"actor-02",json!({}));
        let prior=after_refresh["delegated_actor"]["data"]["balance"]["spendable_sat"].as_u64().unwrap();
        if b["data"]["balance"]["spendable_sat"].as_u64().unwrap()==prior+2000 {break;}
        assert!(std::time::Instant::now()<deadline,"internal LN receive did not converge");
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let offboard=command(&root,"offboard_all",&manifest,&out,"actor-01",json!({}));
    let txid:Txid=offboard["data"]["txid"].as_str().expect("collaborative offboard did not broadcast").parse().unwrap();
    ctx.await_transaction(txid).await;ctx.generate_blocks(2).await;
    let dest=offboard["data"]["destination"].as_str().unwrap().parse::<Address<bitcoin::address::NetworkUnchecked>>().unwrap().assume_checked();
    let tx=core.get_raw_transaction(&txid,None).unwrap();
    assert_eq!(tx.output.iter().filter(|o|o.script_pubkey==dest.script_pubkey()).count(),1);
    assert!(core.get_raw_transaction_info(&txid,None).unwrap().confirmations.unwrap_or(0)>0);
    command(&root,"sync",&manifest,&out,"actor-01",json!({}));
    let end=command(&root,"snapshot",&manifest,&out,"actor-01",json!({}));
    let payments=command(&root,"payment_audit",&manifest,&out,"actor-01",json!({}));
    let payment_rows=payments.as_array().unwrap();
    assert_eq!(payment_rows.len(),2);
    for row in payment_rows {
        assert_eq!(row["payment"]["payment_status_verified"],true,"initiated payment never obtained verified status");
        assert_eq!(row["payment"]["payment_state"],"succeeded");
        assert_eq!(row["payment"]["paid"],true);
        if !row["actual_fee_sat"].is_null() {
            assert_eq!(row["actual_fee_sat"],0,"fixture successful sends have zero service charge");
        }
    }
    let received_fee=command(&root,"receive_fee_audit",&manifest,&out,"actor-02",json!({}));
    let clock=command(&root,"clock_audit",&manifest,&out,"actor-01",json!({}));
    let audited_fees=command(&root,"fee_audit",&manifest,&out,"actor-01",json!({}));
    let exits=audited_fees.as_array().unwrap().iter().filter(|row|row["operation"]=="offboard_all").collect::<Vec<_>>();
    assert_eq!(exits.len(),1);
    assert_eq!(exits[0]["actual_fee_sat"],offboard["data"]["committed_fee_sat"],"confirmed offboard fee reservation remains unresolved");
    assert_eq!(audited_fees.as_array().unwrap().len(),7,"two boards, two refreshes, two sends and one exit must be accounted");
    assert!(audited_fees.as_array().unwrap().iter().all(|row|row["actual_fee_sat"].is_u64()),"successful board/round/send/offboard cost still unresolved");
    for row in audited_fees.as_array().unwrap().iter().filter(|row|matches!(row["operation"].as_str(),Some("refresh"|"refresh_delegated"|"pay_invoice"))) {
        assert_eq!(row["actual_fee_sat"],0,"fixture round/send charges are zero; nonzero accounting is separately tested");
    }
    assert_eq!(end["data"]["balance"]["spendable_sat"].as_u64().unwrap(),0);
    let padding_db=Db::connect(&srv.config().postgres).await.unwrap();
    round_padding::qualify(&ctx,&srv,&padding_db,&root,&out).await;
    write(&out.join("result.json"),&json!({"result":"PASS","owners":3,"empty_before":empty_before,"empty_invoice":empty_invoice,"empty_received":empty_received,"arkoor":arkoor,
        "delegated":delegated,"interactive":interactive,"after_refresh":after_refresh,
        "external_ln":paid,"internal_ln":internal,"verified_payment_outcomes":payments,"receive_cost":received_fee,"qualified_traffic_audit":clock,"offboard":offboard,"confirmed_offboard_txid":txid.to_string(),
        "coverage_limits":["adapter exercise only; full ownership graph and independent capital audit pending","not a live signet campaign or all80 scenarios"]}));
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn simulator_fallback_negative_requests() {
    let root=std::path::PathBuf::from(std::env::var("SIMULATOR_WORKSPACE").unwrap());
    let out=std::path::PathBuf::from(std::env::var("SIMULATOR_OUT").unwrap());
    std::fs::create_dir_all(&out).unwrap();
    let ctx=TestContext::new("bark_sdk/simulator_fallback_negative_requests").await;
    let core=ctx.bitcoind().sync_client();
    let srv=ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).funded(sat(1_000_000)).no_vtxo_pool().create().await;
    let db=Db::connect(&srv.config().postgres).await.unwrap();
    let endpoint=srv.ark_url().replace("://0.0.0.0:","://127.0.0.1:");
    let cfg=ctx.bark_default_cfg(&endpoint,Some(ctx.bitcoind()));
    let wallet_config=ctx.datadir.join("sim-wallet.toml");
    std::fs::write(&wallet_config,toml::to_string(&cfg).unwrap()).unwrap();
    let driver_config=ctx.datadir.join("sim-driver.json");
    let wallet_root=ctx.datadir.join("sim-wallets");std::fs::create_dir(&wallet_root).unwrap();
    write_profiled(&driver_config,&json!({"ark_endpoint":endpoint,"wallet_config":wallet_config,"wallet_root":wallet_root,"network":"regtest"}));
    let manifest=ctx.datadir.join("sim-fixture.json");
    write_profiled(&manifest,&json!({"network":"regtest","core_url":ctx.bitcoind().rpc_url(),"core_cookie":ctx.bitcoind().rpc_cookie(),
        "genesis":core.get_block_hash(0).unwrap().to_string(),"driver_config":driver_config,
        "driver":root.join("target/debug/bark-sim-driver"),"proof":root.join("target/debug/vtxo-proof"),"wallet_root":wallet_root,"state_dir":ctx.datadir.join("sim-journal"),
        "out_dir":out,"server_pubkey":srv.ark_info().await.server_pubkey.to_string(),
        "server_binary":std::env::var("CAPTAIND_EXEC").unwrap(),"server_binary_sha256":std::env::var("SIMULATOR_SERVER_SHA256").unwrap()}));
    for actor in ["actor-01","actor-02"] {
        command(&root,"create",&manifest,&out,actor,json!({}));
    }
    let victim=command(&root,"address",&manifest,&out,"actor-02",json!({}));
    let before=db.read(async |t| Ok(t.query("SELECT mailbox_pk,spk,seq,sig FROM fallback_record ORDER BY mailbox_pk",&[]).await?)).await.unwrap();
    let records=|rows:Vec<tokio_postgres::Row>| rows.into_iter().map(|r| (r.get::<_,Vec<u8>>(0),r.get::<_,Vec<u8>>(1),r.get::<_,i64>(2),r.get::<_,Vec<u8>>(3))).collect::<Vec<_>>();
    let before=records(before);
    let links=db.read(async |t| Ok(t.query("SELECT user_pubkey,mailbox_pk,sig FROM key_link ORDER BY user_pubkey",&[]).await?)).await.unwrap();
    let links=links.into_iter().map(|r| (r.get::<_,Vec<u8>>(0),r.get::<_,Vec<u8>>(1),r.get::<_,Vec<u8>>(2))).collect::<Vec<_>>();
    let cases=[("D01","raw_foreign_record",json!({"victim_mailbox_pk":victim["data"]["binding"]["mailbox_pk"]})),
        ("D02","raw_record_tamper",json!({})),("D03","raw_sequence_tamper",json!({})),("D04","raw_wrong_chain",json!({})),
        ("D05","raw_stale_record",json!({})),("D06","raw_equal_sequence",json!({})),("D07","raw_mixed_link",json!({})),
        ("D08","raw_invalid_link",json!({"victim_pubkey":victim["data"]["user_pubkey"]})),
        ("D09","raw_mailbox_tamper",json!({})),("D10","raw_key_replay",json!({})),
        ("D11","raw_relink",json!({})),("D12","raw_board_unlinked",json!({})),("D39","raw_bounded_queries",json!({})),
        ("D40","raw_malformed",json!({"variant":0})),("D40","raw_malformed",json!({"variant":1})),("D40","raw_malformed",json!({"variant":2}))];
    let mut results=vec![];
    for (scenario,operation,args) in cases {
        let result=command(&root,operation,&manifest,&out,"actor-01",args);
        assert_eq!(result["actual_fee_sat"],0);
        assert_eq!(result["data"]["binding_unchanged"],true);
        let after=db.read(async |t| Ok(t.query("SELECT mailbox_pk,spk,seq,sig FROM fallback_record ORDER BY mailbox_pk",&[]).await?)).await.unwrap();
        let protected=records(after).into_iter().filter(|row|before.iter().any(|old|old.0==row.0)).collect::<Vec<_>>();
        assert_eq!(protected,before,"{scenario} changed a protected fallback record");
        for (key,mailbox,sig) in &links {
            let row=db.read(async |t| Ok(t.query_one("SELECT mailbox_pk,sig FROM key_link WHERE user_pubkey=$1",&[key]).await?)).await.unwrap();
            assert_eq!(&row.get::<_,Vec<u8>>(0),mailbox);assert_eq!(&row.get::<_,Vec<u8>>(1),sig);
        }
        if operation=="raw_relink" {
            let key=Vec::<u8>::from_hex(result["data"]["user_pubkey"].as_str().unwrap()).unwrap();
            let row=db.read(async |t| Ok(t.query_one("SELECT mailbox_pk FROM key_link WHERE user_pubkey=$1",&[&key]).await?)).await.unwrap();
            assert_eq!(row.get::<_,Vec<u8>>(0),Vec::<u8>::from_hex(result["data"]["original_mailbox_pk"].as_str().unwrap()).unwrap(),"valid alternate link replaced original mapping");
        }
        if let Some(keys)=result["data"]["attempted_key_pubkeys"].as_array() {
            for key in keys {
                let key=Vec::<u8>::from_hex(key.as_str().unwrap()).unwrap();
                let count=db.read(async |t| Ok(t.query_one("SELECT COUNT(*) FROM key_link WHERE user_pubkey=$1",&[&key]).await?.get::<_,i64>(0))).await.unwrap();
                assert_eq!(count,if links.iter().any(|old|old.0==key) {1} else {0},"invalid request partially stored a new key");
            }
        }
        results.push(json!({"scenario":scenario,"operation":operation,"response":result,"protected_records_unchanged":true,"protected_links_unchanged":true}));
    }
    write(&out.join("result.json"),&json!({"result":"PASS","cases":results,"requests":16,
        "coverage_limits":["D39 covers bounded valid reads only; invoice churn not qualified","negative registration requests only; all creation-path refusals and all80 outcomes remain pending","no funded client workload or live campaign credit"]}));
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn simulator_confirmed_receipt_recycling() {
    confirmed_receipt_recycling(false).await;
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn simulator_thin_receipt_recycling() {
    confirmed_receipt_recycling(true).await;
}

async fn confirmed_receipt_recycling(thin:bool) {
    let root=std::path::PathBuf::from(std::env::var("SIMULATOR_WORKSPACE").unwrap());
    let out=std::path::PathBuf::from(std::env::var("SIMULATOR_OUT").unwrap());
    std::fs::create_dir_all(&out).unwrap();
    let test_name=if thin {"simulator_thin_receipt_recycling"} else {"simulator_confirmed_receipt_recycling"};
    let ctx=TestContext::new(&format!("bark_sdk/{test_name}")).await;
    let core=ctx.bitcoind().sync_client();
    let srv=ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).funded(sat(1_000_000)).watchmand().no_vtxo_pool().cfg(|c| {
        c.vtxo_lifetime=BlockDelta::new(144);c.min_board_amount=sat(330);
        c.required_board_confirmations=6;c.round_interval=Duration::from_secs(3600);
    }).create().await;
    super::fallback_lightning::train_fee_estimator(&ctx).await;
    let endpoint=srv.ark_url().replace("://0.0.0.0:", "://127.0.0.1:");
    let cfg=ctx.bark_default_cfg(&endpoint,Some(ctx.bitcoind()));
    let wallet_config=ctx.datadir.join("sim-wallet.toml");
    std::fs::write(&wallet_config,toml::to_string(&cfg).unwrap()).unwrap();
    let driver_config=ctx.datadir.join("sim-driver.json");
    let wallet_root=ctx.datadir.join("sim-wallets");std::fs::create_dir(&wallet_root).unwrap();
    write_profiled(&driver_config,&json!({"ark_endpoint":endpoint,"wallet_config":wallet_config,
        "wallet_root":wallet_root,"network":"regtest"}));
    let info=srv.ark_info().await;
    let manifest=ctx.datadir.join("sim-fixture.json");
    write_profiled(&manifest,&json!({"network":"regtest","fee_budget_sat":100_000,"core_url":ctx.bitcoind().rpc_url(),
        "core_cookie":ctx.bitcoind().rpc_cookie(),"genesis":core.get_block_hash(0).unwrap().to_string(),
        "driver_config":driver_config,"driver":root.join("target/debug/bark-sim-driver"),
        "restore":root.join("target/debug/seed-restore"),"proof":root.join("target/debug/vtxo-proof"),"wallet_root":wallet_root,
        "state_dir":ctx.datadir.join("sim-journal"),"out_dir":out,
        "server_pubkey":info.server_pubkey.to_string(),
        "server_binary":std::env::var("CAPTAIND_EXEC").unwrap(),
        "server_binary_sha256":std::env::var("SIMULATOR_SERVER_SHA256").unwrap(),
        "payout_proof":out.join("payout-proof.json"),"recovery_destination":ctx.bitcoind().get_new_address().to_string()}));

    let actor="actor-04";
    let created=command(&root,"create",&manifest,&out,actor,json!({}));
    let address=created["data"]["funding_address"].as_str().unwrap().parse::<Address<bitcoin::address::NetworkUnchecked>>().unwrap().assume_checked();
    let funding=core.send_to_address(&address,sat(20_000),None,None,None,None,None,None).unwrap();
    ctx.await_transaction(funding).await;ctx.generate_blocks(2).await;
    command(&root,"board",&manifest,&out,actor,json!({"amount_sat":if thin {4973} else {10_000}}));
    ctx.generate_blocks(6).await;command(&root,"sync",&manifest,&out,actor,json!({}));
    let mut cycles=Vec::new();
    for _ in 0..if thin {1} else {2} {
        let exited=command(&root,"offboard_all",&manifest,&out,actor,json!({}));
        let exit_tx:Txid=exited["data"]["txid"].as_str().unwrap().parse().unwrap();
        ctx.await_transaction(exit_tx).await;ctx.generate_blocks(2).await;
        command(&root,"sync",&manifest,&out,actor,json!({}));
        command(&root,"snapshot",&manifest,&out,actor,json!({}));
        command(&root,"fee_audit",&manifest,&out,actor,json!({}));
        let recycled=command(&root,"recycle_once",&manifest,&out,actor,json!({"board_cap_sat":if thin {5000} else {10_000}}));
        let raw=recycled["data"]["board"]["funding_tx"].as_str().unwrap();
        let tx:bitcoin::Transaction=bitcoin::consensus::encode::deserialize_hex(raw).unwrap();
        assert_eq!(tx.input.len(),1);assert_eq!(tx.input[0].previous_output.txid,exit_tx);
        ctx.await_transaction(tx.compute_txid()).await;ctx.generate_blocks(6).await;
        command(&root,"sync",&manifest,&out,actor,json!({}));
        command(&root,"snapshot",&manifest,&out,actor,json!({}));
        command(&root,"fee_audit",&manifest,&out,actor,json!({}));
        let audit=command(&root,"recycle_audit",&manifest,&out,actor,json!({}));
        cycles.push(json!({"exit":exited,"board":recycled,"confirmed_recycle":audit}));
    }
    let audit=command(&root,"recycle_audit",&manifest,&out,actor,json!({}));
    assert_eq!(audit["recycle_confirmed"].as_array().unwrap().len(),if thin {1} else {2});
    for cycle in audit["recycle_confirmed"].as_array().unwrap() {
        assert_eq!(cycle["external_injection_sat"],0);
        let source=cycle["source"]["amount_sat"].as_u64().unwrap();
        if thin {assert_eq!(source,4119,"thin fixture must actually reproduce the recorded return amount");}
        assert_eq!(source,cycle["new_ark_principal_sat"].as_u64().unwrap()+cycle["service_fee_sat"].as_u64().unwrap()+cycle["mining_fee_sat"].as_u64().unwrap()+cycle["own_onchain_change_sat"].as_u64().unwrap());
    }
    write(&out.join("result.json"),&json!({"result":"PASS","initial_owner_funding_sat":20_000,"thin_return":thin,"cycles":cycles,"audit":audit,
        "coverage_limits":["confirmed collaborative exit recycling; signet fallback recycling and full server capital conservation separate"]}));
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn simulator_owner_funded_renewal() {
    let root=std::path::PathBuf::from(std::env::var("SIMULATOR_WORKSPACE").unwrap());
    let out=std::path::PathBuf::from(std::env::var("SIMULATOR_OUT").unwrap());
    std::fs::create_dir_all(&out).unwrap();
    let test_name="simulator_owner_funded_renewal";
    let ctx=TestContext::new(&format!("bark_sdk/{test_name}")).await;
    let core=ctx.bitcoind().sync_client();
    let srv=ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).funded(sat(1_000_000)).watchmand().no_vtxo_pool().cfg(|c| {
        c.vtxo_lifetime=BlockDelta::new(144);c.min_board_amount=sat(330);
        c.required_board_confirmations=6;c.round_interval=Duration::from_secs(3600);
    }).create().await;
    super::fallback_lightning::train_fee_estimator(&ctx).await;
    let endpoint=srv.ark_url().replace("://0.0.0.0:", "://127.0.0.1:");
    let cfg=ctx.bark_default_cfg(&endpoint,Some(ctx.bitcoind()));
    let wallet_config=ctx.datadir.join("sim-wallet.toml");
    std::fs::write(&wallet_config,toml::to_string(&cfg).unwrap()).unwrap();
    let driver_config=ctx.datadir.join("sim-driver.json");
    let wallet_root=ctx.datadir.join("sim-wallets");std::fs::create_dir(&wallet_root).unwrap();
    write_profiled(&driver_config,&json!({"ark_endpoint":endpoint,"wallet_config":wallet_config,
        "wallet_root":wallet_root,"network":"regtest"}));
    let info=srv.ark_info().await;
    let manifest=ctx.datadir.join("sim-fixture.json");
    write_profiled(&manifest,&json!({"network":"regtest","fee_budget_sat":100_000,"core_url":ctx.bitcoind().rpc_url(),
        "core_cookie":ctx.bitcoind().rpc_cookie(),"genesis":core.get_block_hash(0).unwrap().to_string(),
        "driver_config":driver_config,"driver":root.join("target/debug/bark-sim-driver"),
        "restore":root.join("target/debug/seed-restore"),"proof":root.join("target/debug/vtxo-proof"),"wallet_root":wallet_root,
        "state_dir":ctx.datadir.join("sim-journal"),"out_dir":out,
        "server_pubkey":info.server_pubkey.to_string(),
        "server_binary":std::env::var("CAPTAIND_EXEC").unwrap(),
        "server_binary_sha256":std::env::var("SIMULATOR_SERVER_SHA256").unwrap(),
        "payout_proof":out.join("payout-proof.json"),"recovery_destination":ctx.bitcoind().get_new_address().to_string()}));

    let actor="actor-04";
    let created=command(&root,"create",&manifest,&out,actor,json!({}));
    let address=created["data"]["funding_address"].as_str().unwrap().parse::<Address<bitcoin::address::NetworkUnchecked>>().unwrap().assume_checked();
    let initial=core.send_to_address(&address,sat(8000),None,None,None,None,None,None).unwrap();
    ctx.await_transaction(initial).await;ctx.generate_blocks(2).await;
    command(&root,"board",&manifest,&out,actor,json!({"amount_sat":5000}));ctx.generate_blocks(6).await;
    command(&root,"sync",&manifest,&out,actor,json!({}));
    let exit=command(&root,"offboard_all",&manifest,&out,actor,json!({}));
    let exit_tx:Txid=exit["data"]["txid"].as_str().unwrap().parse().unwrap();
    ctx.await_transaction(exit_tx).await;ctx.generate_blocks(2).await;
    command(&root,"sync",&manifest,&out,actor,json!({}));command(&root,"snapshot",&manifest,&out,actor,json!({}));
    let funder=command(&root,"renewal_funder_create",&manifest,&out,actor,json!({}));
    let funded_address=funder["address"].as_str().unwrap().parse::<Address<bitcoin::address::NetworkUnchecked>>().unwrap().assume_checked();
    let injection=core.send_to_address(&funded_address,sat(100_000),None,None,None,None,None,None).unwrap();
    ctx.await_transaction(injection).await;ctx.generate_blocks(2).await;
    let funding=command(&root,"renewal_fund",&manifest,&out,actor,json!({"owner_injection_txid":injection.to_string()}));
    assert_eq!(funding["state"],"broadcast");
    let grant_tx:Txid=funding["txid"].as_str().unwrap().parse().unwrap();ctx.await_transaction(grant_tx).await;ctx.generate_blocks(2).await;
    let confirmed=command(&root,"renewal_fund",&manifest,&out,actor,json!({"owner_injection_txid":injection.to_string()}));
    assert_eq!(confirmed["state"],"confirmed");
    command(&root,"sync",&manifest,&out,actor,json!({}));command(&root,"snapshot",&manifest,&out,actor,json!({}));
    let boarded=command(&root,"renewal_board",&manifest,&out,actor,json!({}));
    let tx:bitcoin::Transaction=bitcoin::consensus::encode::deserialize_hex(boarded["data"]["board"]["funding_tx"].as_str().unwrap()).unwrap();
    assert_eq!(tx.input.len(),1);assert_eq!(tx.input[0].previous_output.txid,grant_tx);
    ctx.await_transaction(tx.compute_txid()).await;ctx.generate_blocks(6).await;
    command(&root,"sync",&manifest,&out,actor,json!({}));
    let end=command(&root,"snapshot",&manifest,&out,actor,json!({}));command(&root,"fee_audit",&manifest,&out,actor,json!({}));
    assert_eq!(end["data"]["balance"]["spendable_sat"],5000);
    write(&out.join("result.json"),&json!({"result":"PASS","initial_client_funding_sat":8000,"new_declared_fixture_owner_deposit_sat":100000,
        "owner_injection_txid":injection.to_string(),"renewal_funding":funding,"confirmed_renewal":confirmed,"renewal_board":boarded,
        "confirmed_renewal_board_txid":tx.compute_txid().to_string(),"final_spendable_sat":5000,
        "scope":"actual isolated Core source-only funding PSBT and native actor-owned source-only board, not recycled capital or signet acceptance"}));
}

mod round_adoption {
    include!(concat!(env!("SIMULATOR_WORKSPACE"), "/integration/round_adoption.rs"));
}

mod round_padding {
    include!(concat!(env!("SIMULATOR_WORKSPACE"), "/integration/round_padding.rs"));
}

mod unilateral_exit {
    include!(concat!(env!("SIMULATOR_WORKSPACE"), "/integration/unilateral_exit.rs"));
}

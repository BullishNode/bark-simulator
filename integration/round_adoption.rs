//! Confirmed public nursery evidence drives one real scheduler cycle.
use super::{command,write};
use std::{path::Path,time::Duration};
use ark_testing::{TestContext,sat};
use bitcoin::{Address,address::NetworkUnchecked};
use bitcoin_ext::{rpc::RpcApi,BlockDelta};
use serde_json::{json,Value};
use server::database::Db;

fn controller(root:&Path,manifest:&Path,phase:&str,out:&Path)->Value {
    let result=std::process::Command::new("python3").arg(root.join("integration/round-adoption-client.py"))
        .arg(manifest).arg(phase).output().unwrap();
    std::fs::write(out.join(format!("round-{phase}.stdout")),&result.stdout).unwrap();
    std::fs::write(out.join(format!("round-{phase}.stderr")),&result.stderr).unwrap();
    assert!(result.status.success(),"round scheduler fixture {phase} failed; inspect public capture");
    serde_json::from_slice(&result.stdout).unwrap()
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn simulator_confirmed_round_scheduler_cycle() {
    let root=std::path::PathBuf::from(std::env::var("SIMULATOR_WORKSPACE").unwrap());
    let out=std::path::PathBuf::from(std::env::var("SIMULATOR_OUT").unwrap());
    std::fs::create_dir_all(&out).unwrap();
    // Declared isolated principals: server1M, two20k deposits/two12k boards.
    // Every customer operation retains <=2k maximum fee; no later funding.
    write(&out.join("principal-declaration.json"),&json!({"server_sat":1_000_000,"customer_deposits_sat":[20_000,20_000],"customer_boards_sat":[12_000,12_000],"maximum_customer_fee_sat":2000,"lifetime_blocks":432,"sdk_depth":1,"sdk_exit_margin":12}));
    let ctx=TestContext::new("bark_sdk/simulator_confirmed_round_scheduler_cycle").await;
    let lightning=ctx.new_lightning_setup("lightningd").await;
    let core=ctx.bitcoind().sync_client();
    let srv=ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).lightningd(&lightning.internal)
        .no_vtxo_pool().funded(sat(1_000_000)).watchmand().cfg(|c|{
            c.vtxo_lifetime=BlockDelta::new(432);c.min_board_amount=sat(330);
            c.round_interval=Duration::from_secs(3);
        }).create().await;
    super::super::fallback_lightning::train_fee_estimator(&ctx).await;
    let endpoint=srv.ark_url().replace("://0.0.0.0:","://127.0.0.1:");
    let mut cfg=ctx.bark_default_cfg(&endpoint,Some(ctx.bitcoind()));
    cfg.round_tx_required_confirmations=BlockDelta::new(1);cfg.vtxo_exit_margin=BlockDelta::new(12);
    let wallet_config=ctx.datadir.join("round-wallet.toml");std::fs::write(&wallet_config,toml::to_string(&cfg).unwrap()).unwrap();
    let wallet_root=ctx.datadir.join("round-wallets");std::fs::create_dir(&wallet_root).unwrap();
    let driver_config=ctx.datadir.join("round-driver.json");
    write(&driver_config,&json!({"ark_endpoint":endpoint,"wallet_config":wallet_config,"wallet_root":wallet_root,"network":"regtest"}));
    let manifest=ctx.datadir.join("round-fixture.json");
    write(&manifest,&json!({"network":"regtest","fee_budget_sat":100_000,"core_url":ctx.bitcoind().rpc_url(),"core_cookie":ctx.bitcoind().rpc_cookie(),
        "genesis":core.get_block_hash(0).unwrap().to_string(),"driver_config":driver_config,
        "driver":root.join("target/debug/bark-sim-driver"),"proof":root.join("target/debug/vtxo-proof"),"server_policy":root.join("target/debug/server-policy-proof"),
        "wallet_root":wallet_root,"state_dir":ctx.datadir.join("round-journal"),"out_dir":out,"server_pubkey":srv.ark_info().await.server_pubkey.to_string(),
        "server_binary":std::env::var("CAPTAIND_EXEC").unwrap(),"server_binary_sha256":std::env::var("SIMULATOR_SERVER_SHA256").unwrap()}));
    for actor in ["actor-02","actor-08"] {
        let created=command(&root,"create",&manifest,&out,actor,json!({}));
        let address=created["data"]["funding_address"].as_str().unwrap().parse::<Address<NetworkUnchecked>>().unwrap().assume_checked();
        let tx=core.send_to_address(&address,sat(20_000),None,None,None,None,None,None).unwrap();
        ctx.await_transaction(tx).await;ctx.generate_blocks(2).await;
        command(&root,"board",&manifest,&out,actor,json!({"amount_sat":12_000}));
        ctx.generate_blocks(6).await;command(&root,"sync",&manifest,&out,actor,json!({}));
        command(&root,"address",&manifest,&out,actor,json!({}));
    }
    command(&root,"refresh",&manifest,&out,"actor-02",json!({}));
    command(&root,"refresh_delegated",&manifest,&out,"actor-08",json!({}));
    controller(&root,&manifest,"pending",&out);
    let db=Db::connect(&srv.config().postgres).await.unwrap();
    let deadline=std::time::Instant::now()+Duration::from_secs(90);
    let inventory=loop {
        // Only the chain/server progresses here. No customer syncs after submission.
        ctx.generate_blocks(1).await;
        let inventory=db.read(async |t|{
            let coins=t.query_one("SELECT coalesce(jsonb_agg(jsonb_build_object('vtxo_id',vtxo_id,'expiry',expiry,'spend_state',spend_state,'policy_type',policy_type,'signed_vtxo',encode(vtxo,'hex'))),'[]'::jsonb)::text FROM vtxo",&[]).await?;
            let nursery=t.query_one("SELECT coalesce(jsonb_agg(jsonb_build_object('txid',txid,'kind',kind,'raw_tx',encode(tx,'hex'),'confirmed_at_height',confirmed_at_height,'abandoned_at',abandoned_at)),'[]'::jsonb)::text FROM nursery_tx WHERE kind::text='round'",&[]).await?;
            Ok(json!({"coins":serde_json::from_str::<Value>(&coins.get::<_,String>(0)).unwrap(),"nursery":serde_json::from_str::<Value>(&nursery.get::<_,String>(0)).unwrap()}))
        }).await.unwrap();
        if inventory["nursery"].as_array().unwrap().len()>=2 && inventory["nursery"].as_array().unwrap().iter().all(|n|n["confirmed_at_height"].is_number()) {break inventory;}
        assert!(std::time::Instant::now()<deadline,"server nursery did not independently record confirmation");
        tokio::time::sleep(Duration::from_secs(1)).await;
    };
    write(&out.join("round-scheduler-inventory.json"),&inventory);
    let result=controller(&root,&manifest,"cycle",&out);assert_eq!(result["result"],"PASS");
}

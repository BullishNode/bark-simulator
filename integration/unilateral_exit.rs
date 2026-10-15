// Include inside a `unilateral_exit` submodule of simulator_vertical.
use ark_testing::{TestContext, sat};
use bitcoin::Address;
use bitcoin_ext::{BlockDelta, rpc::RpcApi};
use serde_json::{Value, json};
use std::{io::Write, path::Path, time::Duration};

fn write(path: &Path, value: &Value) {
    std::fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}
fn invoke(
    root: &Path,
    script: &str,
    phase: &str,
    manifest: &Path,
    out: &Path,
    request: Value,
) -> Value {
    let result = std::process::Command::new("python3")
        .arg(root.join("integration").join(script))
        .arg(phase)
        .arg(manifest)
        .arg(request.to_string())
        .output()
        .unwrap();
    let mut log = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(out.join("exit-operations.log"))
        .unwrap();
    log.write_all(&result.stdout).unwrap();
    log.write_all(&result.stderr).unwrap();
    assert!(
        result.status.success(),
        "exit fixture phase {phase} failed; see exit-operations.log"
    );
    serde_json::from_slice(&result.stdout).unwrap()
}
fn regular(
    root: &Path,
    phase: &str,
    manifest: &Path,
    out: &Path,
    actor: &str,
    args: Value,
) -> Value {
    invoke(
        root,
        "regtest-client.py",
        phase,
        manifest,
        out,
        json!({"actor":actor,"args":args,"maximum_fee_sat":2000}),
    )
}
fn exit_phase(root: &Path, phase: &str, manifest: &Path, out: &Path, request: &Value) -> Value {
    invoke(
        root,
        "unilateral-exit-client.py",
        phase,
        manifest,
        out,
        request.clone(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simulator_explicit_board_exit() {
    exercise(false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simulator_explicit_ark_exit_with_cpfp() {
    exercise(true).await;
}

async fn exercise(ark: bool) {
    let root = std::path::PathBuf::from(std::env::var("SIMULATOR_WORKSPACE").unwrap());
    let out = std::path::PathBuf::from(std::env::var("SIMULATOR_OUT").unwrap());
    std::fs::create_dir_all(&out).unwrap();
    let name = if ark {
        "simulator_explicit_ark_exit_with_cpfp"
    } else {
        "simulator_explicit_board_exit"
    };
    let ctx = TestContext::new(&format!("bark_sdk/{name}")).await;
    let core = ctx.bitcoind().sync_client();
    let srv = ctx
        .captaind("server")
        .bitcoind(ctx.bitcoind_arc())
        .funded(sat(1_000_000))
        .watchmand()
        .no_vtxo_pool()
        .cfg(|c| {
            c.vtxo_lifetime = BlockDelta::new(144);
            c.vtxo_exit_delta = BlockDelta::new(6);
            c.required_board_confirmations = 6;
            c.min_board_amount = sat(330);
            c.round_interval = Duration::from_secs(3600);
        })
        .create()
        .await;
    super::super::fallback_lightning::train_fee_estimator(&ctx).await;
    let endpoint = srv.ark_url().replace("://0.0.0.0:", "://127.0.0.1:");
    let wallet_config = ctx.datadir.join("exit-wallet.toml");
    std::fs::write(
        &wallet_config,
        toml::to_string(&ctx.bark_default_cfg(&endpoint, Some(ctx.bitcoind()))).unwrap(),
    )
    .unwrap();
    let driver_config = ctx.datadir.join("exit-driver.json");
    let wallet_root = ctx.datadir.join("exit-wallets");
    std::fs::create_dir_all(&wallet_root).unwrap();
    super::write_profiled(
        &driver_config,
        &json!({"ark_endpoint":endpoint,"wallet_config":wallet_config,"wallet_root":wallet_root,"network":"regtest"}),
    );
    let info = srv.ark_info().await;
    let manifest = ctx.datadir.join("exit-fixture.json");
    super::write_profiled(
        &manifest,
        &json!({"exit_fixture":true,"network":"regtest","fee_budget_sat":100000,
        "core_url":ctx.bitcoind().rpc_url(),"core_cookie":ctx.bitcoind().rpc_cookie(),
        "genesis":core.get_block_hash(0).unwrap().to_string(),"driver_config":driver_config,
        "driver":root.join("target/debug/bark-sim-driver"),"proof":root.join("target/debug/vtxo-proof"),
        "wallet_root":wallet_root,"state_dir":ctx.datadir.join("exit-journal"),"out_dir":out,
        "server_pubkey":info.server_pubkey.to_string(),"server_binary":std::env::var("CAPTAIND_EXEC").unwrap(),
        "server_binary_sha256":std::env::var("SIMULATOR_SERVER_SHA256").unwrap()}),
    );
    let created = regular(&root, "create", &manifest, &out, "actor-01", json!({}));
    let destination = created["data"]["funding_address"]
        .as_str()
        .unwrap()
        .parse::<Address<bitcoin::address::NetworkUnchecked>>()
        .unwrap()
        .assume_checked();
    let funding = core
        .send_to_address(&destination, sat(40000), None, None, None, None, None, None)
        .unwrap();
    ctx.await_transaction(funding).await;
    ctx.generate_blocks(2).await;
    let boarded = regular(
        &root,
        "board",
        &manifest,
        &out,
        "actor-01",
        json!({"amount_sat":10000}),
    );
    let board_id = boarded["data"]["board"]["vtxos"][0]
        .as_str()
        .unwrap()
        .to_string();
    ctx.generate_blocks(6).await;
    regular(&root, "sync", &manifest, &out, "actor-01", json!({}));
    let exit_id = if ark {
        let sender = regular(&root, "create", &manifest, &out, "actor-02", json!({}));
        let address = sender["data"]["funding_address"]
            .as_str()
            .unwrap()
            .parse::<Address<bitcoin::address::NetworkUnchecked>>()
            .unwrap()
            .assume_checked();
        let funding = core
            .send_to_address(&address, sat(40000), None, None, None, None, None, None)
            .unwrap();
        ctx.await_transaction(funding).await;
        ctx.generate_blocks(2).await;
        regular(
            &root,
            "board",
            &manifest,
            &out,
            "actor-02",
            json!({"amount_sat":20000}),
        );
        ctx.generate_blocks(6).await;
        regular(&root, "sync", &manifest, &out, "actor-02", json!({}));
        let address = regular(&root, "address", &manifest, &out, "actor-01", json!({}));
        regular(
            &root,
            "send_arkoor",
            &manifest,
            &out,
            "actor-02",
            json!({"destination":address["data"]["address"],"recipient_actor":"actor-01","amount_sat":5000}),
        );
        regular(&root, "sync", &manifest, &out, "actor-01", json!({}));
        let snapshot = regular(&root, "snapshot", &manifest, &out, "actor-01", json!({}));
        let coins = snapshot["data"]["evidence"]["coins"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["state"] == "Spendable" && c["id"] != board_id)
            .collect::<Vec<_>>();
        assert_eq!(
            coins.len(),
            1,
            "exit requires the exact actual received coin"
        );
        coins[0]["id"].as_str().unwrap().to_string()
    } else {
        board_id
    };
    // This separate, declared operator deposit is the exact CPFP source. It
    // cannot be mistaken for funding created or discovered by the controller.
    let deposit = core
        .send_to_address(&destination, sat(20000), None, None, None, None, None, None)
        .unwrap();
    ctx.await_transaction(deposit).await;
    ctx.generate_blocks(2).await;
    let deposit_tx = core.get_raw_transaction(&deposit, None).unwrap();
    let sources = deposit_tx
        .output
        .iter()
        .enumerate()
        .filter(|(_, o)| o.script_pubkey == destination.script_pubkey() && o.value == sat(20000))
        .collect::<Vec<_>>();
    assert_eq!(sources.len(), 1);
    let source = format!("{}:{}", deposit, sources[0].0);
    let request = json!({"action_id":"fixture-explicit-exit","actor":"actor-01","maximum_fee_sat":2000,
        "args":{"input_vtxo_ids":[exit_id],"fee_rate_sat_per_vb":1,"fee_funding_outpoint":source}});
    write(&out.join("exit-request.json"), &request);
    exit_phase(&root, "start", &manifest, &out, &request);
    exit_phase(&root, "probe_cap", &manifest, &out, &request);
    exit_phase(&root, "inspect", &manifest, &out, &request);
    let before = exit_phase(&root, "audit", &manifest, &out, &request);
    assert_eq!(before["state"], "outcome_unknown");
    assert_eq!(before["actual_fee_sat"], Value::Null);
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let result = loop {
        assert!(
            std::time::Instant::now() < deadline,
            "explicit capped exit did not settle"
        );
        ctx.generate_blocks(1).await;
        exit_phase(&root, "automatic", &manifest, &out, &request);
        let result = exit_phase(&root, "audit", &manifest, &out, &request);
        if result["state"] == "completed" {
            break result;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    let fee = result["actual_fee_sat"].as_u64().unwrap();
    assert!(fee > 0 && fee <= 2000);
    let transactions = result["transactions"].as_object().unwrap();
    assert!(transactions.len() >= if ark { 2 } else { 1 });
    assert_eq!(
        transactions
            .values()
            .map(|t| t["fee_sat"].as_u64().unwrap())
            .sum::<u64>(),
        fee
    );
    let second = exit_phase(&root, "audit", &manifest, &out, &request);
    assert_eq!(second["resolved"], false);
    assert_eq!(second["actual_fee_sat"], fee);
    write(
        &out.join("result.json"),
        &json!({"result":"PASS","source":if ark {"Ark receipt with CPFP"} else {"confirmed board"},
        "claim":result,"fee_source":source,"original_cap_sat":2000,
        "limits":["available server positively confirmed spendability at start","offline-server exit and interrupted-round exit remain unqualified","permanently absent original wallets were never used"]}),
    );
}

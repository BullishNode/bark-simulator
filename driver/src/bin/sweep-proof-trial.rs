//! Read-only proof rejection using two genuine signed branches and an actual
//! confirmed transaction from independent signet Core. No wallet or signer.
use anyhow::{Context, Result, ensure};
use ark::{ProtocolEncoding, Vtxo, vtxo::Full};
use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoin::{Network, OutPoint, Txid, consensus::serialize, constants::genesis_block};
use serde_json::{Value, json};
use std::{collections::HashSet, io::Read, str::FromStr};
fn hex(encoded: &str) -> Result<Vec<u8>> {
    ensure!(
        encoded.len() % 2 == 0 && encoded.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid public proof hex"
    );
    (0..encoded.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).map_err(Into::into))
        .collect()
}
fn encoded(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn branch(
    core: &Client,
    raw: &str,
    expected_id: &str,
    server: &str,
) -> Result<(Vtxo<Full>, HashSet<OutPoint>, Value)> {
    let bytes = hex(raw)?;
    let coin: Vtxo<Full> = Vtxo::deserialize(&bytes)?;
    ensure!(
        coin.serialize() == bytes
            && coin.id().to_string() == expected_id
            && coin.server_pubkey().to_string() == server,
        "signed branch differs from declared coin/server"
    );
    let anchor = coin.chain_anchor();
    let tx = core.get_raw_transaction(&anchor.txid, None)?;
    ensure!(
        tx.compute_txid() == anchor.txid,
        "Core raw backing transaction ID differs"
    );
    coin.validate(&tx)
        .context("genuine signed branch invalid")?;
    let info = core.get_raw_transaction_info(&anchor.txid, None)?;
    ensure!(
        info.confirmations.unwrap_or(0) > 0,
        "branch anchor unconfirmed"
    );
    let mut points = HashSet::from([anchor, coin.point()]);
    let mut path = Vec::new();
    for node in coin.transactions() {
        let id = node.tx.compute_txid();
        points.insert(OutPoint::new(id, node.output_idx as u32));
        path.push(json!({"txid":id.to_string(),"output_index":node.output_idx,"raw_hex":encoded(&serialize(&node.tx))}));
    }
    let evidence = json!({"coin_id":coin.id().to_string(),"chain_anchor":anchor.to_string(),"raw_anchor_hex":encoded(&serialize(&tx)),"anchor_info":info,"signed_path":path});
    Ok((coin, points, evidence))
}
fn verify() -> Result<Value> {
    let args = std::env::args().collect::<Vec<_>>();
    ensure!(args.len() == 4, "declared Core/cookie/server required");
    let address = args[1]
        .strip_prefix("http://127.0.0.1:")
        .context("Core must use fixed loopback host")?;
    let port = address
        .strip_suffix('/')
        .unwrap_or(address)
        .parse::<u16>()
        .context(
            "loopback Core port must contain only decimal digits; no userinfo or remote authority",
        )?;
    ensure!(port > 0, "Core port must be nonzero");
    let core = Client::new(&args[1], Auth::CookieFile((&args[2]).into()))?;
    let genesis = core.get_block_hash(0)?;
    ensure!(
        genesis == genesis_block(Network::Signet).block_hash(),
        "production trial requires independent signet Core"
    );
    let mut raw = String::new();
    std::io::stdin()
        .take(4 * 1024 * 1024 + 1)
        .read_to_string(&mut raw)?;
    ensure!(
        raw.len() <= 4 * 1024 * 1024,
        "public proof bundle too large"
    );
    let request: Value = serde_json::from_str(&raw)?;
    let right_id = request["rightful_coin_id"]
        .as_str()
        .context("rightful ID")?;
    let other_id = request["other_coin_id"]
        .as_str()
        .context("other branch ID")?;
    ensure!(right_id != other_id, "distinct genuine branches required");
    let (right, right_points, right_evidence) = branch(
        &core,
        request["rightful_signed_vtxo"]
            .as_str()
            .context("rightful signed proof")?,
        right_id,
        &args[3],
    )?;
    let (_, other_points, other_evidence) = branch(
        &core,
        request["other_signed_vtxo"]
            .as_str()
            .context("other signed proof")?,
        other_id,
        &args[3],
    )?;
    let id = Txid::from_str(
        request["candidate_sweep_txid"]
            .as_str()
            .context("candidate ID")?,
    )?;
    let candidate = core.get_raw_transaction(&id, None)?;
    let info = core.get_raw_transaction_info(&id, None)?;
    ensure!(
        candidate.compute_txid() == id && info.confirmations.unwrap_or(0) > 0,
        "actual raw candidate sweep must be confirmed and match its ID"
    );
    let spent = candidate
        .input
        .iter()
        .map(|i| i.previous_output)
        .collect::<HashSet<_>>();
    ensure!(
        spent.is_disjoint(&right_points),
        "candidate touches rightful/shared path; not an unrelated branch scenario"
    );
    ensure!(
        !spent.is_disjoint(&other_points),
        "candidate does not spend exact independently signed other branch"
    );
    let mut input_total = 0u64;
    let mut prevouts = Vec::new();
    for input in &candidate.input {
        let point = input.previous_output;
        let tx = core.get_raw_transaction(&point.txid, None)?;
        ensure!(
            tx.compute_txid() == point.txid,
            "prevout transaction ID differs"
        );
        let output = tx
            .output
            .get(point.vout as usize)
            .context("candidate prevout missing")?;
        input_total = input_total
            .checked_add(output.value.to_sat())
            .context("candidate input overflow")?;
        prevouts.push(json!({"outpoint":point.to_string(),"raw_transaction_hex":encoded(&serialize(&tx)),"amount_sat":output.value.to_sat()}));
    }
    let output_total = candidate
        .output
        .iter()
        .try_fold(0u64, |sum, o| sum.checked_add(o.value.to_sat()))
        .context("candidate output overflow")?;
    let fee = input_total
        .checked_sub(output_total)
        .context("candidate inflates money")?;
    // Exact path check is the independent proof acceptor: the real candidate
    // cannot establish this rightful coin's path sweep despite being confirmed.
    Ok(
        json!({"scenario":"D28","rightful_coin_id":right.id().to_string(),"other_coin_id":other_id,"candidate_sweep_txid":id.to_string(),
        "actual_wrong_branch_proof_rejected":true,"candidate_mining_fee_sat":fee,"new_money_operation_fee_sat":0,
        "rightful_settlement_verified":false,"rightful_entitlement":"pending independent current arbitration/payout",
        "customer_traffic_credit":false,"raw_candidate_hex":encoded(&serialize(&candidate)),"candidate_info":info,"prevouts":prevouts,
        "rightful_branch":right_evidence,"other_branch":other_evidence,"genesis":genesis.to_string(),
        "scope":"signed protocol paths and raw confirmed transactions from declared independent Core; no new spend, rightful settlement or current unspent assertion"}),
    )
}
fn main() {
    match verify() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("wrong-branch trial unavailable: {error:#}");
            std::process::exit(1)
        }
    }
}

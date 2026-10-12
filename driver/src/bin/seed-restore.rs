//! Ordinary BIP84 recovery, without Ark SDK, original DB, index or txid hints.
//! Args: RPC URL, private cookie path, destination, sat/vB, maximum fee sat.
//! A mnemonic is supplied privately on stdin. Mainnet/testnet are refused.
//! --prepare-only accepts private JSON {mnemonic, authorized_outpoints}, scans
//! normally before selecting those frozen payouts, and never broadcasts.
use anyhow::{Context, Result, ensure};
use bdk_bitcoind_rpc::{
    Emitter,
    bitcoincore_rpc::{Auth, Client, RpcApi},
};
use bdk_wallet::{KeychainKind, SignOptions, Wallet, template::Bip84};
use bitcoin::{
    Address, FeeRate, Network, OutPoint, Transaction, bip32::Xpriv, constants::genesis_block,
};
use serde_json::Value;
use std::collections::HashSet;
use std::{io::Read, str::FromStr};

fn authorized_inputs(request: &Value) -> Result<HashSet<OutPoint>> {
    let object = request
        .as_object()
        .context("invalid private recovery request")?;
    ensure!(
        object.len() == 2
            && object.contains_key("mnemonic")
            && object.contains_key("authorized_outpoints"),
        "unsupported private recovery fields"
    );
    let inputs = request["authorized_outpoints"]
        .as_array()
        .context("frozen payouts required")?;
    ensure!(
        !inputs.is_empty() && inputs.len() <= 16,
        "invalid frozen payout count"
    );
    let mut ids = HashSet::new();
    for input in inputs {
        let id = OutPoint::from_str(input.as_str().context("invalid payout outpoint")?)?;
        ensure!(ids.insert(id), "duplicate frozen payout");
    }
    Ok(ids)
}

fn restore() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    let prepared_only = args.len() == 7 && args[6] == "--prepare-only";
    ensure!(
        args.len() == 6 || prepared_only,
        "invalid restore arguments"
    );
    let client = Client::new(&args[1], Auth::CookieFile((&args[2]).into()))?;
    let genesis = client.get_block_hash(0)?;
    let network = [Network::Signet, Network::Regtest]
        .into_iter()
        .find(|n| genesis_block(*n).block_hash() == genesis)
        .context("recovery permits only official signet or regtest")?;
    let destination = Address::from_str(&args[3])?.require_network(network)?;
    let rate = FeeRate::from_sat_per_vb(args[4].parse()?).context("fee rate overflow")?;
    let maximum_fee: u64 = args[5].parse()?;
    ensure!(
        !prepared_only || (maximum_fee > 0 && maximum_fee <= 2000),
        "prepared recovery cap exceeds 2000 sats"
    );
    let limit = if prepared_only { 65_536 } else { 4096 };
    let mut private = String::new();
    std::io::stdin()
        .take(limit + 1)
        .read_to_string(&mut private)?;
    ensure!(private.len() <= limit as usize, "invalid seed input");
    let request: Option<Value> = if prepared_only {
        Some(serde_json::from_str(&private)?)
    } else {
        None
    };
    let authorized = request.as_ref().map(authorized_inputs).transpose()?;
    let phrase = match request.as_ref() {
        Some(r) => r["mnemonic"]
            .as_str()
            .context("private mnemonic required")?,
        None => private.trim(),
    };
    let mnemonic = bip39::Mnemonic::from_str(phrase.trim())?;
    let master = Xpriv::new_master(network, &mnemonic.to_seed(""))?;
    drop(request);
    drop(private);
    let mut wallet = Wallet::create(
        Bip84(master, KeychainKind::External),
        Bip84(master, KeychainKind::Internal),
    )
    .network(network)
    .lookahead(20)
    .create_wallet_no_persist()?;
    let mut emitter = Emitter::new(
        &client,
        wallet.latest_checkpoint(),
        0,
        std::iter::empty::<Transaction>(),
    );
    while let Some(ev) = emitter.next_block()? {
        wallet.apply_block_connected_to(&ev.block, ev.block_height(), ev.connected_to())?;
    }
    // Authorized outpoints constrain signing only after the ordinary gap-20
    // full-chain scan. They are never supplied to Emitter or used for discovery.
    let found = wallet
        .list_unspent()
        .filter(|u| {
            authorized
                .as_ref()
                .is_none_or(|ids| ids.contains(&u.outpoint))
        })
        .collect::<Vec<_>>();
    if let Some(ids) = &authorized {
        ensure!(
            found.len() == ids.len(),
            "seed scan did not discover every frozen payout"
        );
    }
    ensure!(!found.is_empty(), "no seed-recovered outputs");
    ensure!(
        found.iter().all(|u| u.chain_position.is_confirmed()),
        "unconfirmed recovery input"
    );
    let evidence=found.iter().map(|u|serde_json::json!({"outpoint":u.outpoint.to_string(),
        "amount_sat":u.txout.value.to_sat(),"keychain":format!("{:?}",u.keychain),"index":u.derivation_index})).collect::<Vec<_>>();
    let mut builder = wallet.build_tx();
    for coin in &found {
        builder.add_utxo(coin.outpoint)?;
    }
    builder
        .manually_selected_only()
        .drain_to(destination.script_pubkey())
        .fee_rate(rate);
    let mut psbt = builder.finish()?;
    let fee = psbt.fee()?.to_sat();
    ensure!(fee <= maximum_fee, "restore fee exceeds budget");
    ensure!(
        wallet.sign(&mut psbt, SignOptions::default())?,
        "seed cannot sign every recovered input"
    );
    let tx = psbt.extract_tx()?;
    let txid = tx.compute_txid();
    if !prepared_only {
        ensure!(
            client.send_raw_transaction(&tx)? == txid,
            "broadcast identity changed"
        );
    }
    let outputs = tx
        .output
        .iter()
        .map(|o| {
            serde_json::json!({
                "script":o.script_pubkey.to_hex_string(), "amount_sat":o.value.to_sat()
            })
        })
        .collect::<Vec<_>>();
    let mut result = serde_json::json!({"network":network.to_string(),"standard":"BIP84","lookahead":20,
        "start_height":0,"tip":wallet.latest_checkpoint().height(),"inputs":evidence,
        "spend_txid":txid.to_string(),"fee_sat":fee,"confirmation_verified":false,
        "prepared_only":prepared_only,"broadcast":!prepared_only,"outputs":outputs});
    if prepared_only {
        result["raw_tx"] = Value::String(bitcoin::consensus::encode::serialize_hex(&tx));
    }
    println!("{}", result);
    Ok(())
}
fn main() {
    if restore().is_err() {
        eprintln!("recovery failed; preserve state and reconcile any ambiguous broadcast");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preparation_requires_unique_bounded_frozen_payouts() {
        let id = format!("{}:0", "aa".repeat(32));
        let valid = serde_json::json!({"mnemonic":"private stdin", "authorized_outpoints":[id]});
        assert_eq!(authorized_inputs(&valid).unwrap().len(), 1);
        let duplicate =
            serde_json::json!({"mnemonic":"private stdin", "authorized_outpoints":[id,id]});
        assert!(authorized_inputs(&duplicate).is_err());
        assert!(
            authorized_inputs(
                &serde_json::json!({"mnemonic":"private stdin", "authorized_outpoints":[]})
            )
            .is_err()
        );
        assert!(authorized_inputs(&serde_json::json!({"mnemonic":"private stdin", "authorized_outpoints":[id], "extra":"ignored"})).is_err());
    }
}

//! Ordinary BIP84 recovery, without Ark SDK, original DB, index or txid hints.
//! Args: RPC URL, private cookie path, destination, sat/vB, maximum fee sat.
//! A mnemonic is supplied privately on stdin. Mainnet/testnet are refused.
use anyhow::{Context, Result, ensure};
use bdk_bitcoind_rpc::{
    Emitter,
    bitcoincore_rpc::{Auth, Client, RpcApi},
};
use bdk_wallet::{KeychainKind, SignOptions, Wallet, template::Bip84};
use bitcoin::{Address, FeeRate, Network, Transaction, bip32::Xpriv, constants::genesis_block};
use std::{io::Read, str::FromStr};

fn restore() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    ensure!(args.len() == 6, "invalid restore arguments");
    let client = Client::new(&args[1], Auth::CookieFile((&args[2]).into()))?;
    let genesis = client.get_block_hash(0)?;
    let network = [Network::Signet, Network::Regtest]
        .into_iter()
        .find(|n| genesis_block(*n).block_hash() == genesis)
        .context("recovery permits only official signet or regtest")?;
    let destination = Address::from_str(&args[3])?.require_network(network)?;
    let rate = FeeRate::from_sat_per_vb(args[4].parse()?).context("fee rate overflow")?;
    let maximum_fee: u64 = args[5].parse()?;
    let mut phrase = String::new();
    std::io::stdin().take(4097).read_to_string(&mut phrase)?;
    ensure!(phrase.len() <= 4096, "invalid seed input");
    let mnemonic = bip39::Mnemonic::from_str(phrase.trim())?;
    let master = Xpriv::new_master(network, &mnemonic.to_seed(""))?;
    drop(phrase);
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
    let found = wallet.list_unspent().collect::<Vec<_>>();
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
    let txid = client.send_raw_transaction(&tx)?;
    println!(
        "{}",
        serde_json::json!({"network":network.to_string(),"standard":"BIP84","lookahead":20,
        "start_height":0,"tip":wallet.latest_checkpoint().height(),"inputs":evidence,
        "spend_txid":txid.to_string(),"fee_sat":fee,"confirmation_verified":false})
    );
    Ok(())
}
fn main() {
    if restore().is_err() {
        eprintln!("recovery failed; preserve state and reconcile any ambiguous broadcast");
        std::process::exit(1);
    }
}

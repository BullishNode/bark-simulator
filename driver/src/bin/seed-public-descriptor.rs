//! Pure seed -> public BIP84 external descriptor. No Wallet, DB, RPC or signing.
//! Args: signet|regtest, inclusive last public derivation index (0..128).
//! Private mnemonic is read ONLY from bounded stdin; errors never echo input.
use anyhow::{ensure, Result};
use bdk_wallet::{KeychainKind, template::{Bip84Public, DescriptorTemplate}};
use bitcoin::{Network, bip32::{DerivationPath, Xpriv, Xpub}, constants::genesis_block, secp256k1::Secp256k1};
use serde_json::{json, Value};
use std::{io::Read, str::FromStr};

fn describe(phrase: &str, network: Network, last: u32) -> Result<Value> {
    ensure!(matches!(network, Network::Signet | Network::Regtest), "unsupported derivation network");
    ensure!(last <= 128, "public range exceeds declared tool bound");
    let mnemonic = bip39::Mnemonic::from_str(phrase.trim())?;
    let master = Xpriv::new_master(network, &mnemonic.to_seed(""))?;
    let secp = Secp256k1::new();
    let path = DerivationPath::from_str("m/84'/1'/0'")?;
    let account = Xpub::from_priv(&secp, &master.derive_priv(&secp, &path)?);
    let fingerprint = master.fingerprint(&secp);
    // Construct from an XPUB, not an XPRV/key map. This is the same exact
    // External template used by A SDK OnchainWallet::load_from_xpriv.
    let (descriptor, secrets, _) = Bip84Public(account, fingerprint, KeychainKind::External).build(network.into())?;
    ensure!(secrets.is_empty(), "public template unexpectedly returned private keys");
    let mut scripts = Vec::new();
    for index in 0..=last {
        let concrete = descriptor.at_derivation_index(index)?.derived_descriptor(&secp)?;
        let address = concrete.address(network)?;
        scripts.push(json!({"index":index,"address":address.to_string(),"script":address.script_pubkey().to_hex_string()}));
    }
    Ok(json!({"schema_version":1,"scope":"pure public derivation only; no wallet, chain, discovery or funds proof",
        "network":network.to_string(),"declared_genesis":genesis_block(network).block_hash().to_string(),
        "standard":"BIP84","account_path":"m/84h/1h/0h","sdk_keychain":"external",
        "master_fingerprint":fingerprint.to_string(),"account_xpub":account.to_string(),
        "public_descriptor":descriptor.to_string(),"range":[0,last],"scripts":scripts}))
}
fn run() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    ensure!(args.len()==3, "expected network and inclusive last index");
    let network = Network::from_str(&args[1])?;
    let last:u32 = args[2].parse()?;
    let mut private = String::new();
    std::io::stdin().take(4097).read_to_string(&mut private)?;
    ensure!(private.len()<=4096, "private input exceeds bound");
    let public = describe(&private,network,last)?;
    drop(private);
    println!("{}",public);
    Ok(())
}
fn main() {
    if run().is_err() {
        eprintln!("public descriptor derivation refused; preserve private input and original result");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    // Public BIP39 test vector; never a campaign seed.
    const PHRASE:&str="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    #[test]
    fn matches_actual_sdk_private_external_template_without_creating_wallet() {
        let actual=describe(PHRASE,Network::Signet,2).unwrap();
        let mnemonic=bip39::Mnemonic::from_str(PHRASE).unwrap();
        let master=Xpriv::new_master(Network::Signet,&mnemonic.to_seed("")).unwrap();
        let (sdk,_,_)=bdk_wallet::template::Bip84(master,KeychainKind::External).build(Network::Signet.into()).unwrap();
        assert_eq!(actual["public_descriptor"],sdk.to_string());
        assert_eq!(actual["scripts"].as_array().unwrap().len(),3);
        assert_ne!(actual["scripts"][0]["script"],actual["scripts"][1]["script"]);
        assert!(actual["account_xpub"].as_str().unwrap().starts_with("tpub"));
        assert!(actual["public_descriptor"].as_str().unwrap().contains("/0/*)"));
    }
    #[test]
    fn test_network_aliases_do_not_silently_change_public_scope() {
        for network in [Network::Bitcoin,Network::Testnet,Network::Testnet4] {
            assert!(describe(PHRASE,network,0).is_err());
        }
        let signet=describe(PHRASE,Network::Signet,0).unwrap();
        let regtest=describe(PHRASE,Network::Regtest,0).unwrap();
        assert_eq!(signet["public_descriptor"],regtest["public_descriptor"]);
        assert_ne!(signet["declared_genesis"],regtest["declared_genesis"]);
        assert_ne!(signet["scripts"][0]["address"],regtest["scripts"][0]["address"]);
    }
    #[test]
    fn refuses_unsupported_range_and_invalid_mnemonic() {
        assert!(describe(PHRASE,Network::Signet,129).is_err());
        assert!(describe("not a mnemonic",Network::Signet,0).is_err());
    }
}

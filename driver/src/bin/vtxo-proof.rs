//! Independent public protocol/binding proof, never an original wallet/key read.
//! Args Core URL, private cookie path, pinned server key; stdin signed hex or JSON.
use anyhow::{Context, Result, ensure};
use ark::{
    ProtocolEncoding, Vtxo,
    attestations::{FallbackRecordAttestation, KeyLinkAttestation},
    vtxo::Full,
};
use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoin::{
    Network, ScriptBuf,
    constants::{ChainHash, genesis_block},
    secp256k1::PublicKey,
};
use serde_json::{Value, json};
use std::{io::Read, str::FromStr};
fn hex(raw: &str) -> Result<Vec<u8>> {
    ensure!(
        raw.len() % 2 == 0 && raw.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid proof encoding"
    );
    Ok((0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()?)
}
fn binding(request: &Value, coin_pk: PublicKey, network: Network) -> Result<Value> {
    let b = &request["binding"];
    let mailbox = PublicKey::from_str(b["mailbox_pk"].as_str().context("missing mailbox")?)?;
    let script = ScriptBuf::from_bytes(hex(b["spk"].as_str().context("missing script")?)?);
    ensure!(script.is_p2wpkh(), "simulator expects BIP84 fallback");
    let seq = b["seq"].as_u64().context("invalid sequence")?;
    ensure!(seq <= i64::MAX as u64, "sequence out of range");
    let record =
        FallbackRecordAttestation::deserialize(&hex(b["record_attestation"]
            .as_str()
            .context("missing record signature")?)?)?;
    record.verify(
        ChainHash::using_genesis_block_const(network),
        &script,
        seq,
        mailbox,
    )?;
    let link = KeyLinkAttestation::deserialize(&hex(request["key_link_attestation"]
        .as_str()
        .context("missing link signature")?)?)?;
    link.verify(mailbox, coin_pk)?;
    Ok(
        json!({"mailbox_pk":mailbox.to_string(),"spk":script.to_hex_string(),"seq":seq,"record_signature_valid":true,"key_link_signature_valid":true,
      "validation_scope":"coin key signs wallet link and wallet signs record; BIP84 ownership needs client derivation/seed recovery evidence"}),
    )
}
fn verify() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    ensure!(args.len() == 4, "invalid verifier arguments");
    let client = Client::new(&args[1], Auth::CookieFile((&args[2]).into()))?;
    let genesis = client.get_block_hash(0)?;
    let network = [Network::Signet, Network::Regtest]
        .into_iter()
        .find(|n| genesis_block(*n).block_hash() == genesis)
        .context("only official signet/regtest permitted")?;
    let mut raw = String::new();
    std::io::stdin().take(2_097_153).read_to_string(&mut raw)?;
    ensure!(raw.len() <= 2_097_152, "proof input too large");
    let raw = raw.trim();
    let request = if raw.starts_with('{') {
        Some(serde_json::from_str::<Value>(raw)?)
    } else {
        None
    };
    if let Some(ref r) = request {
        if r.get("signed_vtxo").is_none() {
            let key = PublicKey::from_str(
                r["user_pubkey"]
                    .as_str()
                    .context("missing advertised key")?,
            )?;
            let bound = binding(r, key, network)?;
            println!(
                "{}",
                json!({"user_pubkey":key.to_string(),"genesis":genesis.to_string(),"binding":bound,
                "validation_scope":"public key link and fallback record signatures; no funded coin or backing asserted"})
            );
            return Ok(());
        }
    }
    let encoded = hex(if let Some(ref r) = request {
        r["signed_vtxo"].as_str().context("missing signed proof")?
    } else {
        raw
    })?;
    let coin: Vtxo<Full> = Vtxo::deserialize(&encoded)?;
    ensure!(
        coin.server_pubkey().to_string() == args[3],
        "server key mismatch"
    );
    let bound = if let Some(ref r) = request {
        binding(r, coin.user_pubkey(), network)?
    } else {
        Value::Null
    };
    let anchor = coin.chain_anchor();
    let funding = client.get_raw_transaction(&anchor.txid, None)?;
    ensure!(funding.compute_txid() == anchor.txid, "backing transaction ID mismatch");
    coin.validate(&funding).context("signed path invalid")?;
    let confirmations = client
        .get_raw_transaction_info(&anchor.txid, None)?
        .confirmations
        .unwrap_or(0);
    ensure!(confirmations > 0, "unconfirmed backing anchor");
    let path=coin.transactions().map(|item|json!({"txid":item.tx.compute_txid().to_string(),"output_index":item.output_idx,
      "inputs":item.tx.input.iter().map(|i|i.previous_output.to_string()).collect::<Vec<_>>(),
      "output_amount_sat":item.tx.output[item.output_idx].value.to_sat(),"output_script":item.tx.output[item.output_idx].script_pubkey.to_hex_string()})).collect::<Vec<_>>();
    let output = serde_json::to_string(
        &json!({"id":coin.id().to_string(),"amount_sat":coin.amount().to_sat(),"user_pubkey":coin.user_pubkey().to_string(),
      "server_pubkey":coin.server_pubkey().to_string(),"expiry_height":coin.expiry_height().to_u32(),"chain_anchor":anchor.to_string(),
      "anchor_confirmations":confirmations,"signed_path_valid":true,"arkoor_transition_count":coin.past_arkoor_pubkeys().len(),"genesis":genesis.to_string(),"binding":bound,
      "ancestor_ids":coin.ancestor_ids().iter().map(|id|id.to_string()).collect::<Vec<_>>(),"path":path,
      "validation_scope":"protocol/optional link+record signatures and confirmed backing path; spend arbitration and seed recovery require separate evidence"}),
    )?;
    ensure!(output.len() <= 2_097_152, "proof output too large");
    println!("{}", output);
    Ok(())
}
fn main() {
    if verify().is_err() {
        eprintln!("public VTXO proof unavailable or invalid; no money state changed");
        std::process::exit(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Keypair;
    fn fixture() -> (Value, PublicKey) {
        let coin = Keypair::from_seckey_slice(&ark::SECP, &[1u8; 32]).unwrap();
        let mailbox = Keypair::from_seckey_slice(&ark::SECP, &[2u8; 32]).unwrap();
        let script =
            ScriptBuf::from_bytes(hex("00141111111111111111111111111111111111111111").unwrap());
        let encode = |v: Vec<u8>| v.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let record = FallbackRecordAttestation::new(
            ChainHash::using_genesis_block_const(Network::Regtest),
            &script,
            7,
            &mailbox,
        );
        let link = KeyLinkAttestation::new(mailbox.public_key(), &coin);
        (
            json!({"binding":{"mailbox_pk":mailbox.public_key().to_string(),"spk":script.to_hex_string(),"seq":7,"record_attestation":encode(record.serialize())},"key_link_attestation":encode(link.serialize())}),
            coin.public_key(),
        )
    }
    #[test]
    fn validates_existing_protocol_domains() {
        let (r, c) = fixture();
        let valid = binding(&r, c, Network::Regtest).unwrap();
        assert_eq!(valid["key_link_signature_valid"], true);
        assert_eq!(valid["record_signature_valid"], true);
    }
    #[test]
    fn rejects_wrong_coin_mailbox_and_network() {
        let (r, c) = fixture();
        let wrong = Keypair::from_seckey_slice(&ark::SECP, &[3u8; 32])
            .unwrap()
            .public_key();
        assert!(binding(&r, wrong, Network::Regtest).is_err());
        assert!(binding(&r, c, Network::Signet).is_err());
        let mut r = r;
        r["binding"]["mailbox_pk"] = json!(wrong.to_string());
        assert!(binding(&r, c, Network::Regtest).is_err());
    }
    #[test]
    fn rejects_tampered_record_and_missing_or_bad_link() {
        let (r, c) = fixture();
        for field in ["seq", "spk", "record_attestation"] {
            let mut bad = r.clone();
            bad["binding"][field] = match field {
                "seq" => json!(8),
                "spk" => json!("00142222222222222222222222222222222222222222"),
                _ => json!("00".repeat(64)),
            };
            assert!(binding(&bad, c, Network::Regtest).is_err());
        }
        let mut bad = r.clone();
        bad["key_link_attestation"] = json!("00".repeat(64));
        assert!(binding(&bad, c, Network::Regtest).is_err());
        assert!(binding(&json!({}), c, Network::Regtest).is_err());
    }
}

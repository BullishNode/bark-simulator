//! Compare a durable unsigned Board reservation with its registered signed coin.
//! Pure supplied-byte proof: no wallet, keys, RPC, payment or spendability verdict.
use ark::{board::BoardBuilder, vtxo::Full, ProtocolEncoding, Vtxo};
use bitcoin::{consensus, secp256k1::PublicKey, Transaction};
use serde_json::{json, Value};
use std::{io::Read, str::FromStr};

type Error = Box<dyn std::error::Error>;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    pending_vtxo: String,
    registered_vtxo: String,
    anchor_raw: String,
    server_pubkey: String,
}

fn decode_hex(value: &Value) -> Result<Vec<u8>, Error> {
    let value = value.as_str().ok_or("bounded hex required")?;
    if value.is_empty()
        || value.len() > 1024 * 1024
        || value.len() % 2 != 0
        || !value.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("bounded hex required".into());
    }
    Ok((0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()?)
}

fn path(coin: &Vtxo<Full>) -> Vec<(String, u32)> {
    coin.transactions()
        .map(|item| (item.tx.compute_txid().to_string(), item.output_idx as u32))
        .collect()
}

fn verify(value: &Value) -> Result<Value, Error> {
    let fields = value
        .as_object()
        .ok_or("exact original proof object required")?;
    if fields.len() != 4
        || ![
            "pending_vtxo",
            "registered_vtxo",
            "anchor_raw",
            "server_pubkey",
        ]
        .iter()
        .all(|field| fields.contains_key(*field))
    {
        return Err(
            "only original pending/registered coin, anchor and server key permitted".into(),
        );
    }
    let pending_raw = decode_hex(&value["pending_vtxo"])?;
    let registered_raw = decode_hex(&value["registered_vtxo"])?;
    let pending = Vtxo::<Full>::deserialize(&pending_raw)?;
    let registered = Vtxo::<Full>::deserialize(&registered_raw)?;
    let anchor: Transaction = consensus::deserialize(&decode_hex(&value["anchor_raw"])?)?;
    let server = PublicKey::from_str(
        value["server_pubkey"]
            .as_str()
            .ok_or("server key required")?,
    )?;
    if pending.server_pubkey() != server || registered.server_pubkey() != server {
        return Err("server key differs".into());
    }
    // The durable pre-registration record deliberately has no complete signature.
    // It must never receive the signed-path verdict of the registered coin.
    pending.validate_unsigned(&anchor)?;
    registered.validate(&anchor)?;
    BoardBuilder::new_from_vtxo(&registered, &anchor, server)?;
    if pending.policy_type().to_string() != "pubkey"
        || registered.policy_type().to_string() != "pubkey"
        || pending.id() != registered.id()
        || pending.chain_anchor() != registered.chain_anchor()
        || pending.user_pubkey() != registered.user_pubkey()
        || pending.amount() != registered.amount()
        || pending.expiry_height() != registered.expiry_height()
        || pending.exit_delta() != registered.exit_delta()
        || pending.unlock_hash() != registered.unlock_hash()
        || !pending.past_arkoor_pubkeys().is_empty()
        || !registered.past_arkoor_pubkeys().is_empty()
        || path(&pending) != path(&registered)
    {
        return Err("pending reservation and registered Board commitments differ".into());
    }
    // A Board may reserve its root using an expected off-chain exit edge. Derive
    // that edge from the validated signed path, never from a supplied marker.
    let mut anchor_spenders = registered.transactions().filter_map(|item| {
        item.tx
            .input
            .iter()
            .any(|input| input.previous_output == registered.chain_anchor())
            .then(|| item.tx.compute_txid())
    });
    let anchor_spender = anchor_spenders
        .next()
        .ok_or("registered Board does not spend its anchor")?;
    if anchor_spenders.next().is_some() {
        return Err("registered Board anchor spender is ambiguous".into());
    }
    Ok(json!({
        "schema_version": 2,
        "anchor_spender_txid": anchor_spender.to_string(),
        "id": registered.id().to_string(),
        "chain_anchor": registered.chain_anchor().to_string(),
        "server_pubkey": server.to_string(),
        "user_pubkey": registered.user_pubkey().to_string(),
        "amount_sat": registered.amount().to_sat(),
        "expiry_height": registered.expiry_height().to_u32(),
        "exit_delta": registered.exit_delta().to_u32(),
        "exit_depth": registered.exit_depth(),
        "pending_unsigned_structure_verified": true,
        "registered_signed_board_verified": true,
        "same_unsigned_transaction_path": true,
        "pending_signature_verified": false,
        "current_liability_or_payment_verified": false,
        "scope": "Exact unsigned Board structure and registered signed Board only; original intent, current lineage, ownership, chain confirmation and backing disposition require separate joins."
    }))
}

fn run() -> Result<(), Error> {
    let mut raw = Vec::new();
    std::io::stdin()
        .take(2 * 1024 * 1024 + 1)
        .read_to_end(&mut raw)?;
    if raw.len() > 2 * 1024 * 1024 {
        return Err("original proof exceeds byte bound".into());
    }
    let request: Request = serde_json::from_slice(&raw)?;
    let input = json!({"pending_vtxo":request.pending_vtxo,
        "registered_vtxo":request.registered_vtxo,"anchor_raw":request.anchor_raw,
        "server_pubkey":request.server_pubkey});
    println!("{}", verify(&input)?);
    Ok(())
}

fn main() {
    if run().is_err() {
        eprintln!("pending Board proof refused");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_detached_verdicts_and_unknown_fields() {
        assert!(verify(&json!({"pending_signature_verified": true})).is_err());
        assert!(verify(&json!({"pending_vtxo":"00", "registered_vtxo":"00",
            "anchor_raw":"00", "server_pubkey":"00", "complete":true}))
        .is_err());
    }

    #[test]
    fn rejects_malformed_or_oversized_originals() {
        for invalid in [
            json!(null),
            json!(""),
            json!("0"),
            json!("xz"),
            json!("00".repeat(524289)),
        ] {
            assert!(decode_hex(&invalid).is_err());
        }
    }

    #[test]
    fn refuses_duplicate_raw_request_fields() {
        let raw = r#"{"pending_vtxo":"00","pending_vtxo":"01","registered_vtxo":"00","anchor_raw":"00","server_pubkey":"00"}"#;
        assert!(serde_json::from_str::<Request>(raw).is_err());
    }
}

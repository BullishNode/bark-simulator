//! Public emissions never contain full VTXOs or transaction witnesses.
//! Private once-only intent files remain unchanged and are not public evidence.
use anyhow::{Result, ensure};
use ark::{ProtocolEncoding, Vtxo, vtxo::Full};
use bitcoin::{Transaction, Witness};
use bitcoin::consensus::{deserialize, serialize};
use serde_json::Value;

fn decode(raw: &str) -> Result<Vec<u8>> {
    ensure!(raw.len() <= 4*1024*1024 && raw.len()%2 == 0 && raw.is_ascii(), "bounded public hex required");
    (0..raw.len()).step_by(2).map(|i| u8::from_str_radix(&raw[i..i+2],16).map_err(Into::into)).collect()
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn coin(value: &mut Value) -> Result<()> {
    let bytes=decode(value.as_str().ok_or_else(||anyhow::anyhow!("encoded public coin required"))?)?;
    if bytes.first()==Some(&b'{') {
        let projection: Value=serde_json::from_slice(&bytes)?;
        ensure!(projection["format"]=="ark-public-authorization-v1", "unsupported public proof encoding");
        // The typed decoder rejects secret fields and witness-bearing bodies.
        crate::public_coin::validate_projection(&bytes)?;
    } else {
        let full=Vtxo::<Full>::deserialize(&bytes)?;
        *value=Value::String(hex(&crate::public_coin::encode(&full)?));
    }
    Ok(())
}
fn transaction(value: &mut Value) -> Result<()> {
    if value.is_null() { return Ok(()); }
    let bytes=decode(value.as_str().ok_or_else(||anyhow::anyhow!("encoded public transaction required"))?)?;
    let mut tx: Transaction=deserialize(&bytes)?;
    for input in &mut tx.input { input.witness=Witness::default(); }
    *value=Value::String(hex(&serialize(&tx)));
    Ok(())
}
pub fn project(mut value: Value) -> Result<Value> {
    fn walk(value: &mut Value, depth: usize) -> Result<()> {
        ensure!(depth<=64, "public evidence nesting exceeds bound");
        match value {
            Value::Object(object)=> {
                let mut coin_projected=false;
                let mut tx_projected=false;
                for (key,item) in object.iter_mut() {
                    ensure!(!matches!(key.as_str(), "preimage"|"seed"|"mnemonic"|"private_key"|"xprv"|"txinwitness"), "private field refused in public emission");
                    match key.as_str() {
                        "signed_vtxo"=> { coin(item)?; coin_projected=true; },
                        "signed_vtxos"|"signed_input_vtxos"=> {
                            let items=item.as_array_mut().ok_or_else(||anyhow::anyhow!("public coin array required"))?;
                            ensure!(items.len()<=1024,"public coin array exceeds bound");
                            for item in items {coin(item)?;}
                            coin_projected=true;
                        },
                        "signed_tx"|"raw_transaction"|"raw_transaction_hex"|"raw_tx"|"parent_tx"|"unsigned_tx"|"unsigned_funding_tx"|"raw_unsigned_hex"|"unsigned_offboard_hex"=> {transaction(item)?;tx_projected=true;},
                        _=>walk(item,depth+1)?,
                    }
                }
                if coin_projected { object.insert("proof_encoding".into(),Value::String("ark-public-authorization-v1".into())); }
                if tx_projected { object.insert("transaction_encoding".into(),Value::String("bitcoin-stripped-body-v1".into())); }
            },
            Value::Array(items)=>for item in items {walk(item,depth+1)?;},
            _=>{},
        }
        Ok(())
    }
    walk(&mut value,0)?;
    ensure!(serde_json::to_vec(&value)?.len()<=2*1024*1024,"public event exceeds bound");
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{absolute,transaction,TxIn,OutPoint,ScriptBuf,Sequence};
    use serde_json::json;
    #[test]
    fn secondary_event_transactions_strip_private_witness_without_changing_txid() {
        let tx=Transaction {version:transaction::Version::TWO,lock_time:absolute::LockTime::ZERO,
            input:vec![TxIn {previous_output:OutPoint::null(),script_sig:ScriptBuf::new(),sequence:Sequence::MAX,
                witness:Witness::from_slice(&[&[0xab;32]])}],output:vec![]};
        let original=hex(&serialize(&tx));
        let public=project(json!({"nested":{"signed_tx":original,"parent_tx":null}})).unwrap();
        let encoded=public["nested"]["signed_tx"].as_str().unwrap();
        assert!(!serde_json::to_string(&public).unwrap().contains(&hex(&[0xab;32])));
        let stripped:Transaction=deserialize(&decode(encoded).unwrap()).unwrap();
        assert_eq!(stripped.compute_txid(),tx.compute_txid());
        assert!(stripped.input[0].witness.is_empty());
        assert!(!tx.input[0].witness.is_empty());
    }
    #[test]
    fn explicit_private_fields_are_refused_instead_of_dropped() {
        assert!(project(json!({"nested":{"preimage":"private"}})).is_err());
        assert!(project(json!({"signed_vtxo":"deadbeef"})).is_err());
    }
}

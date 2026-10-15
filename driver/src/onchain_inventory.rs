//! Read-only public facts from the actor's currently loaded BDK graph.
//!
//! This neither syncs nor qualifies freshness, reservations, fee eligibility or
//! financial readiness. In particular, canonical UTXOs are not a confirmed-tip
//! asset inventory when an unconfirmed transaction spends confirmed backing.
use std::collections::BTreeSet;

use anyhow::{Context, Result, ensure};
use bdk_wallet::{KeychainKind, Wallet};
use bitcoin::{Transaction, Witness};
use serde_json::{Value, json};

const MAX_ROWS: usize = 2_000;
const MAX_BYTES: usize = 2 * 1024 * 1024;

fn public_transaction(tx: &Transaction) -> Result<Value> {
    ensure!(
        tx.total_size() <= MAX_BYTES,
        "onchain inventory transaction byte bound exceeded"
    );
    // Removing a scriptSig changes txid; refusing is safer than publishing a
    // potential preimage. Witness removal preserves the public txid.
    ensure!(
        tx.input.iter().all(|i| i.script_sig.is_empty()),
        "unsafe inventory scriptSig"
    );
    let mut body = tx.clone();
    for input in &mut body.input {
        input.witness = Witness::default();
    }
    Ok(json!({"txid":tx.compute_txid().to_string(),
        "transaction_body":crate::hex(&bitcoin::consensus::serialize(&body)),
        "signed_weight_wu":tx.weight().to_wu(),"encoding":"bitcoin-stripped-body-v1"}))
}

fn row(
    rows: &mut usize,
    bytes: &mut usize,
    value: &Value,
    max_rows: usize,
    max_bytes: usize,
) -> Result<()> {
    *rows += 1;
    *bytes += serde_json::to_vec(value)?.len() + 1;
    ensure!(
        *rows <= max_rows && *bytes <= max_bytes,
        "onchain inventory aggregate bound exceeded"
    );
    Ok(())
}

pub fn collect(wallet: &Wallet) -> Result<Value> {
    bounded(wallet, MAX_ROWS, MAX_BYTES)
}

fn bounded(wallet: &Wallet, max_rows: usize, max_bytes: usize) -> Result<Value> {
    let tip = wallet.latest_checkpoint().block_id();
    let mut result = json!({"schema_version":1,"read_only":true,"network":wallet.network().to_string(),
        "tip_height":tip.height,"tip_hash":tip.hash.to_string(),
        "scope":"currently loaded canonical wallet graph; no sync performed",
        "reservation_scope":"not reported; inspect persisted client actions independently",
        "confirmed_fee_eligibility":"not qualified",
        "complete":false,"descriptors":[],"utxos":[],"pending_transactions":[],
        "pending_parents":[],"unavailable_parent_txids":[]});
    let mut rows = 0;
    let mut bytes = serde_json::to_vec(&result)?.len();
    ensure!(
        bytes <= max_bytes,
        "onchain inventory aggregate bound exceeded"
    );
    for (keychain, descriptor) in wallet.keychains() {
        let name = match keychain {
            KeychainKind::External => "external",
            KeychainKind::Internal => "internal",
        };
        let value = json!({"keychain":name,"descriptor":descriptor.to_string(),
            "last_revealed_index":wallet.derivation_index(keychain)});
        row(&mut rows, &mut bytes, &value, max_rows, max_bytes)?;
        result["descriptors"].as_array_mut().unwrap().push(value);
    }
    for output in wallet.list_unspent() {
        let (keychain, index) = wallet
            .derivation_of_spk(output.txout.script_pubkey.clone())
            .context("canonical UTXO missing public derivation")?;
        let height = output.chain_position.confirmation_height_upper_bound();
        ensure!(
            height.is_none_or(|height| height <= tip.height),
            "confirmation exceeds graph tip"
        );
        let confirmations = height.map(|height| tip.height - height + 1).unwrap_or(0);
        let coinbase = wallet
            .tx_graph()
            .get_tx(output.outpoint.txid)
            .context("canonical UTXO transaction missing")?
            .is_coinbase();
        let value = json!({"outpoint":output.outpoint.to_string(),"value_sat":output.txout.value.to_sat(),
            "script_pubkey":crate::hex(output.txout.script_pubkey.as_bytes()),
            "keychain":match keychain { KeychainKind::External => "external", KeychainKind::Internal => "internal" },
            "derivation_index":index,"confirmed_height_upper_bound":height,"confirmations":confirmations,
            "coinbase":coinbase,"mature":!coinbase || confirmations >= bitcoin::constants::COINBASE_MATURITY});
        row(&mut rows, &mut bytes, &value, max_rows, max_bytes)?;
        result["utxos"].as_array_mut().unwrap().push(value);
    }
    let mut parents = BTreeSet::new();
    for local in wallet
        .transactions()
        .filter(|tx| !tx.chain_position.is_confirmed())
    {
        let value = public_transaction(&local.tx_node.tx)?;
        row(&mut rows, &mut bytes, &value, max_rows, max_bytes)?;
        result["pending_transactions"]
            .as_array_mut()
            .unwrap()
            .push(value);
        parents.extend(
            local
                .tx_node
                .tx
                .input
                .iter()
                .map(|input| input.previous_output.txid),
        );
        ensure!(
            parents.len() <= max_rows - rows,
            "onchain inventory aggregate parent bound exceeded"
        );
    }
    for txid in parents {
        match wallet
            .tx_graph()
            .get_tx(txid)
            .and_then(|tx| public_transaction(&tx).ok())
        {
            Some(value) => {
                row(&mut rows, &mut bytes, &value, max_rows, max_bytes)?;
                result["pending_parents"]
                    .as_array_mut()
                    .unwrap()
                    .push(value);
            }
            None => {
                let value = json!(txid.to_string());
                row(&mut rows, &mut bytes, &value, max_rows, max_bytes)?;
                result["unavailable_parent_txids"]
                    .as_array_mut()
                    .unwrap()
                    .push(value);
            }
        }
    }
    for (field, key) in [
        ("descriptors", "keychain"),
        ("utxos", "outpoint"),
        ("pending_transactions", "txid"),
        ("pending_parents", "txid"),
    ] {
        result[field]
            .as_array_mut()
            .unwrap()
            .sort_by(|a, b| a[key].as_str().cmp(&b[key].as_str()));
    }
    result["complete"] = json!(
        result["unavailable_parent_txids"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    ensure!(
        serde_json::to_vec(&result)?.len() <= max_bytes,
        "onchain inventory serialized bound exceeded"
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::test_utils::{get_funded_wallet_wpkh, insert_tx};
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, TxIn, TxOut, absolute, transaction};

    #[test]
    fn public_graph_inventory_does_not_mutate_or_export_signing_keys() {
        let (wallet, _) = get_funded_wallet_wpkh();
        let before = wallet.staged().cloned();
        let index = wallet.derivation_index(KeychainKind::External);
        let value = collect(&wallet).unwrap();
        assert_eq!(wallet.staged(), before.as_ref());
        assert_eq!(wallet.derivation_index(KeychainKind::External), index);
        assert_eq!(value["complete"], true);
        assert!(!value["utxos"].as_array().unwrap().is_empty());
        let body = value.to_string();
        assert!(!body.contains("tprv") && !body.contains("xprv"));
        assert_eq!(value["confirmed_fee_eligibility"], "not qualified");
        assert!(bounded(&wallet, 0, MAX_BYTES).is_err());
        assert!(bounded(&wallet, 1, MAX_BYTES).is_err());
        assert!(bounded(&wallet, MAX_ROWS, 10).is_err());
    }

    #[test]
    fn membership_is_public_before_funding_or_address_reveal() {
        let wallet =
            Wallet::create_single(bdk_wallet::test_utils::get_test_wpkh_and_change_desc().0)
                .network(bitcoin::Network::Regtest)
                .create_wallet_no_persist()
                .unwrap();
        let before = wallet.staged().cloned();
        let value = collect(&wallet).unwrap();
        assert_eq!(value["complete"], true);
        assert_eq!(value["descriptors"].as_array().unwrap().len(), 1);
        assert_eq!(value["descriptors"][0]["last_revealed_index"], Value::Null);
        assert!(value["utxos"].as_array().unwrap().is_empty());
        assert_eq!(wallet.staged(), before.as_ref());
        assert_eq!(wallet.derivation_index(KeychainKind::External), None);
    }

    #[test]
    fn pending_witness_is_removed_and_missing_parent_is_explicit() {
        let (mut wallet, _) = get_funded_wallet_wpkh();
        let mut tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array([9; 32]),
                    vout: 0,
                },
                witness: Witness::from_slice(&[vec![42; 32]]),
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: wallet
                    .peek_address(KeychainKind::External, 0)
                    .address
                    .script_pubkey(),
            }],
        };
        let public = public_transaction(&tx).unwrap();
        let bytes: Vec<u8> =
            bitcoin::hex::FromHex::from_hex(public["transaction_body"].as_str().unwrap()).unwrap();
        let stripped: Transaction = bitcoin::consensus::deserialize::<Transaction>(&bytes).unwrap();
        assert_eq!(stripped.compute_txid(), tx.compute_txid());
        assert!(stripped.input[0].witness.is_empty());
        insert_tx(&mut wallet, tx.clone());
        let value = collect(&wallet).unwrap();
        assert_eq!(value["complete"], false);
        assert_eq!(
            value["unavailable_parent_txids"].as_array().unwrap().len(),
            1
        );
        tx.input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![1, 42]);
        assert!(public_transaction(&tx).is_err());
    }

    #[test]
    fn outgoing_pending_without_change_keeps_confirmed_parent_evidence() {
        let (mut wallet, _) = get_funded_wallet_wpkh();
        let owned = wallet.list_unspent().next().unwrap();
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: owned.outpoint,
                witness: Witness::from_slice(&[vec![42; 32]]),
                ..Default::default()
            }],
            output: vec![TxOut {
                value: owned.txout.value - Amount::from_sat(1_000),
                script_pubkey: bitcoin::ScriptBuf::new_op_return([1]),
            }],
        };
        let txid = tx.compute_txid().to_string();
        insert_tx(&mut wallet, tx);
        let value = collect(&wallet).unwrap();
        assert_eq!(value["complete"], true);
        assert_eq!(value["pending_transactions"][0]["txid"], txid);
        assert_eq!(
            value["pending_parents"][0]["txid"],
            owned.outpoint.txid.to_string()
        );
        assert!(value["utxos"].as_array().unwrap().is_empty());
    }
}

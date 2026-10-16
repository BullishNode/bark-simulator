//! Public server-policy contract proof against supplied raw chain evidence.
//! No wallet, keys, node credentials or network operations.
use ark::{
    vtxo::{policy::ServerVtxoPolicy, Full},
    ProtocolEncoding, Vtxo,
};
use serde_json::{json, Value};
use std::io::Read;
use ark::{forfeit::create_hark_forfeit_tx, tree::signed::UnlockHash};
use bitcoin::{
    hashes::{sha256, Hash},
    secp256k1::schnorr,
    sighash::{Prevouts, SighashCache, TapSighashType},
};

fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if value.len() % 2 != 0
        || value.len() > 2097152
        || !value.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("invalid bounded public hex".into());
    }
    Ok((0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()?)
}

const PADDING_PUBKEY: &str = "02dfa52f6690299d2d6a08323083e290597b56fee125063e5f4e2957731639c42c";
const PADDING_UNLOCK_HASH: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
const PADDING_AMOUNT_SAT: u64 = 330;

fn padding_marker(coin: &Vtxo<Full, ServerVtxoPolicy>) -> bool {
    coin.policy_type().to_string() == "pubkey"
        && coin.policy().user_pubkey().map(|key| key.to_string()).as_deref() == Some(PADDING_PUBKEY)
        && coin.unlock_hash().map(|hash| hash.to_string()).as_deref() == Some(PADDING_UNLOCK_HASH)
        && coin.amount().to_sat() == PADDING_AMOUNT_SAT
        && coin.past_arkoor_pubkeys().is_empty()
}

/// Verify an ORIGINAL hArk forfeit without exposing its signature or preimage.
/// The original ordinary input Full has already validated against its anchor.
fn verify_original_forfeit(
    coin: &Vtxo<Full, ServerVtxoPolicy>,
    value: &Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    if coin.policy_type().to_string() != "pubkey" || padding_marker(coin) {
        return Err("forfeit requires an ordinary signed user Full".into());
    }
    let user = coin.clone().try_into_user_vtxo()
        .map_err(|_| "forfeit requires a user policy")?;
    let unlock_hash: UnlockHash = value["forfeit_unlock_hash"].as_str()
        .ok_or("forfeit unlock hash absent")?.parse()?;
    let raw = decode_hex(value["forfeit_raw"].as_str().ok_or("forfeit original absent")?)?;
    let original: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw)?;
    if original.input.len() != 1 || original.input[0].witness.len() != 1 {
        return Err("exact original forfeit key-spend witness required".into());
    }
    let signature_bytes = original.input[0].witness.iter().next()
        .ok_or("forfeit signature absent")?;
    if signature_bytes.len() != 64 {
        return Err("forfeit requires the native default 64-byte signature".into());
    }
    let signature = schnorr::Signature::from_slice(signature_bytes)?;
    let expected = create_hark_forfeit_tx(&user, unlock_hash, Some(&signature));
    if original != expected {
        return Err("forfeit transaction differs from native original construction".into());
    }
    let prevouts = [user.txout()];
    let sighash = SighashCache::new(&expected).taproot_key_spend_signature_hash(
        0, &Prevouts::All(&prevouts), TapSighashType::Default,
    )?;
    ark::SECP.verify_schnorr(
        &signature, &sighash.into(),
        &user.output_taproot().output_key().to_x_only_public_key(),
    )?;
    Ok(json!({
        "forfeit_signature_valid": true,
        "forfeit_input_coin_id": user.id().to_string(),
        "forfeit_txid": original.compute_txid().to_string(),
        "forfeit_unlock_hash": unlock_hash.to_string(),
        "forfeit_raw_sha256": sha256::Hash::hash(&raw).to_string(),
        "forfeit_scope": "exact original hArk key-spend authorization only; no confirmation, payment, current spendability or capital release"
    }))
}

fn verify_contract(value: &Value) -> Result<Value, Box<dyn std::error::Error>> {
    let fields = value.as_object().ok_or("public object required")?;
    if ![2, 3, 5].contains(&fields.len())
        || !["signed_vtxo", "server_pubkey"]
            .iter()
            .all(|field| fields.contains_key(*field))
        || (fields.len() >= 3 && !fields.contains_key("anchor_raw"))
        || (fields.len() == 5 && !["forfeit_raw", "forfeit_unlock_hash"]
            .iter().all(|field| fields.contains_key(*field)))
    {
        return Err("only public coin, raw anchor, pinned server key and paired original forfeit fields permitted".into());
    }
    let encoded = decode_hex(value["signed_vtxo"].as_str().ok_or("coin absent")?)?;
    if encoded.first()==Some(&b'{') {
        if fields.len()!=2 {
            return Err("public projection parameters are decode-only; use the client verifier for chain validation".into());
        }
        return Ok(bark_sim_driver::public_coin::parameters(&encoded,
            value["server_pubkey"].as_str().ok_or("server absent")?)?);
    }
    let coin = Vtxo::<Full, ServerVtxoPolicy>::deserialize(&encoded)?;
    if coin.server_pubkey().to_string() != value["server_pubkey"].as_str().ok_or("server absent")? {
        return Err("server key differs".into());
    }
    if fields.len() == 2 {
        return Ok(
            json!({"schema_version":1,"sdk_commit":option_env!("GIT_HASH"),"id":coin.id().to_string(),"chain_anchor":coin.chain_anchor().to_string(),
            "amount_sat":coin.amount().to_sat(),"expiry_height":coin.expiry_height().to_u32(),"policy":coin.policy_type().to_string(),"server_pubkey":coin.server_pubkey().to_string(),
            "candidate_user_pubkey":coin.policy().user_pubkey().map(|key|key.to_string()),
            "exit_delta":coin.exit_delta().to_u32(),
            "exit_depth":coin.exit_depth(),
            "unlock_hash":coin.unlock_hash().map(|hash|hash.to_string()),
            "arkoor_transition_count":coin.past_arkoor_pubkeys().len(),
            "tree_padding":padding_marker(&coin),
            "chain_contract_verified":false,"client_owner_verified":false,"scope":"decoded public candidate; backing and signatures have not been validated"}),
        );
    }
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&decode_hex(
        value["anchor_raw"].as_str().ok_or("anchor absent")?,
    )?)?;
    let anchor = coin.chain_anchor();
    if tx.compute_txid() != anchor.txid {
        return Err("raw anchor transaction identity differs".into());
    }
    let padding=padding_marker(&coin);
    if padding {
        // Protocol padding has no unlock preimage. Validate only the exact
        // committed unsigned structure; never manufacture a spendable signature.
        coin.validate_unsigned(&tx)?;
    } else {
        coin.validate(&tx)?;
    }
    let forfeit = if fields.len() == 5 {
        Some(verify_original_forfeit(&coin, value)?)
    } else {
        None
    };
    let output = tx
        .output
        .get(anchor.vout as usize)
        .ok_or("anchor output absent")?;
    if coin.point() == anchor
        && (output.value != coin.amount() || output.script_pubkey != coin.output_script_pubkey())
    {
        return Err("direct anchor contract value/script differs".into());
    }
    let mut response = json!({"schema_version":1,"sdk_commit":option_env!("GIT_HASH"),"id":coin.id().to_string(),"chain_anchor":anchor.to_string(),
        "amount_sat":coin.amount().to_sat(),"anchor_amount_sat":output.value.to_sat(),
        "anchor_script":output.script_pubkey.to_hex_string(),"policy":coin.policy_type().to_string(),
        "server_pubkey":coin.server_pubkey().to_string(),"expiry_height":coin.expiry_height().to_u32(),
        "output_script":coin.output_script_pubkey().to_hex_string(),
        "candidate_user_pubkey":coin.policy().user_pubkey().map(|key|key.to_string()),
            "exit_delta":coin.exit_delta().to_u32(),
            "exit_depth":coin.exit_depth(),
            "unlock_hash":coin.unlock_hash().map(|hash|hash.to_string()),
            "arkoor_transition_count":coin.past_arkoor_pubkeys().len(),
            "tree_padding":padding_marker(&coin),
        "chain_contract_verified":!padding,"padding_backing_structure_verified":padding,
        "signed_path_valid":!padding,"client_owner_verified":false,
        "scope":if padding {"protocol padding unsigned structure and exact raw anchor; signatures, customer ownership, confirmation and spend status are unproved"} else {"public server-policy contract and exact raw anchor; confirmations, customer ownership and current spendability are separate"}});
    if let Some(forfeit) = forfeit {
        response.as_object_mut().ok_or("contract response must be an object")?
            .extend(forfeit.as_object().ok_or("forfeit response must be an object")?.clone());
    }
    Ok(response)
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut raw = String::new();
    std::io::stdin().take(2097153).read_to_string(&mut raw)?;
    if raw.len() > 2097152 {
        return Err("public proof input bound".into());
    }
    let value: Value = serde_json::from_str(&raw)?;
    println!("{}", verify_contract(&value)?);
    Ok(())
}

fn main() {
    if run().is_err() {
        eprintln!("public server-policy proof unavailable or invalid");
        std::process::exit(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark::{
        vtxo::{policy::ServerVtxoPolicy, Bare},
        ProtocolEncoding, Vtxo,
    };
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    fn encode(bytes: Vec<u8>) -> String {
        bytes.iter().map(|v| format!("{v:02x}")).collect()
    }
    fn fixture() -> Value {
        let key = bitcoin::secp256k1::SecretKey::from_slice(&[1; 32]).unwrap();
        let server = bitcoin::secp256k1::PublicKey::from_secret_key(&ark::SECP, &key);
        let policy = ServerVtxoPolicy::new_expiry(server.x_only_public_key().0);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(80000),
                script_pubkey: policy.script_pubkey(server, 12u16.into(), 1000u32.into()),
            }],
        };
        let point = OutPoint::new(tx.compute_txid(), 0);
        let coin = Vtxo::<Bare, ServerVtxoPolicy>::new(
            point,
            policy,
            Amount::from_sat(80000),
            1000u32.into(),
            server,
            12u16.into(),
            point,
        );
        json!({"signed_vtxo":encode(coin.serialize()),"anchor_raw":encode(bitcoin::consensus::serialize(&tx)),"server_pubkey":server.to_string()})
    }
    #[test]
    fn decodes_real_public_padding_marker_without_claiming_owner_or_backing() {
        let request: Value = serde_json::from_str(include_str!("../../tests/fixtures/public-round-padding.json")).unwrap();
        let result = verify_contract(&request).unwrap();
        assert_eq!(result["tree_padding"], true);
        assert_eq!(result["unlock_hash"], "deadbeef".repeat(8));
        assert_eq!(result["amount_sat"], 330);
        assert_eq!(result["exit_delta"], 12);
        assert_eq!(result["chain_contract_verified"], false);
        assert_eq!(result["client_owner_verified"], false);
        for (from, to) in [("4a01000000000000", "4b01000000000000"),
                           ("deadbeef", "deadbeee"),
                           ("02dfa52f6690299d2d6a08323083e290597b56fee125063e5f4e2957731639c42c", "0321ee8a987797fb29574edf4f167474b6b623a7519eb8723a85c41fda533b2752")] {
            let mut changed = request.clone();
            changed["signed_vtxo"] = json!(request["signed_vtxo"].as_str().unwrap().replace(from,to));
            assert_eq!(verify_contract(&changed).unwrap()["tree_padding"], false);
        }
        let mut trailing = request.clone();
        trailing["signed_vtxo"] = json!(format!("{}00", request["signed_vtxo"].as_str().unwrap()));
        assert!(verify_contract(&trailing).is_err());
    }

    #[test]
    fn padding_raw_anchor_qualifies_structure_without_inventing_unlock_signature() {
        let request: Value = serde_json::from_str(include_str!("../../tests/fixtures/public-round-padding-anchor.json")).unwrap();
        let proof = verify_contract(&request).unwrap();
        assert_eq!(proof["tree_padding"], true);
        assert_eq!(proof["padding_backing_structure_verified"], true);
        assert_eq!(proof["chain_contract_verified"], false);
        assert_eq!(proof["signed_path_valid"], false);
        assert_eq!(proof["client_owner_verified"], false);
        let coin=Vtxo::<Full,ServerVtxoPolicy>::deserialize(&decode_hex(request["signed_vtxo"].as_str().unwrap()).unwrap()).unwrap();
        let transaction:bitcoin::Transaction=bitcoin::consensus::deserialize(&decode_hex(request["anchor_raw"].as_str().unwrap()).unwrap()).unwrap();
        assert!(coin.validate(&transaction).is_err(),"padding cannot acquire a spendable client signature");
        coin.validate_unsigned(&transaction).unwrap();
        let mut wrong=request.clone();
        let mut transaction=transaction;transaction.output[0].value=Amount::from_sat(1);
        wrong["anchor_raw"]=json!(encode(bitcoin::consensus::serialize(&transaction)));
        assert!(verify_contract(&wrong).is_err());
    }

    #[test]
    fn native_padding_full_exposes_sdk_depth_without_qualifying_its_signatures() {
        let request: Value = serde_json::from_str(include_str!("../../tests/fixtures/public-round-padding-anchor.json")).unwrap();
        let coin = Vtxo::<Full, ServerVtxoPolicy>::deserialize(&decode_hex(request["signed_vtxo"].as_str().unwrap()).unwrap()).unwrap();
        let depth = coin.exit_depth();
        assert!(usize::from(depth) > coin.past_arkoor_pubkeys().len(), "SDK exit depth includes more than OOR transitions");
        let mut decoded = request.clone();
        decoded.as_object_mut().unwrap().remove("anchor_raw");
        let decoded = verify_contract(&decoded).unwrap();
        assert_eq!(decoded["exit_depth"], depth);
        assert_eq!(decoded["chain_contract_verified"], false);
        assert_eq!(decoded["client_owner_verified"], false);
        let validated_structure = verify_contract(&request).unwrap();
        assert_eq!(validated_structure["exit_depth"], depth);
        assert_eq!(validated_structure["chain_contract_verified"], false);
        assert_eq!(validated_structure["signed_path_valid"], false);
        assert_eq!(validated_structure["padding_backing_structure_verified"], true);
    }

    /// Run explicitly against the preserved genuine native ordinary Full + raw
    /// anchor request. Missing/private fixture is a failed prerequisite, never
    /// a successful or silently skipped qualification. Raw bytes stay external.
    #[test]
    #[ignore = "requires BARK_SIM_ACTUAL_FULL_POLICY_REQUEST and preserved native provenance"]
    fn archived_native_ordinary_full_depth_and_tamper_controls() {
        let path = std::env::var_os("BARK_SIM_ACTUAL_FULL_POLICY_REQUEST")
            .expect("genuine private native fixture is required for this selector");
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert!(metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= 2 * 1024 * 1024);
        let request: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let encoded = decode_hex(request["signed_vtxo"].as_str().unwrap()).unwrap();
        let coin = Vtxo::<Full, ServerVtxoPolicy>::deserialize(&encoded).unwrap();
        assert_eq!(coin.policy_type().to_string(), "pubkey");
        assert!(!padding_marker(&coin), "actual ordinary native fixture required");
        let original: Transaction = bitcoin::consensus::deserialize(&decode_hex(request["anchor_raw"].as_str().unwrap()).unwrap()).unwrap();
        coin.validate(&original).expect("actual native ordinary signed path must validate first");
        let depth = coin.exit_depth();
        assert!(usize::from(depth) > coin.past_arkoor_pubkeys().len(), "the genuine path must distinguish SDK depth from OOR count");
        let proof = verify_contract(&request).unwrap();
        assert_eq!(proof["exit_depth"], depth);
        assert_eq!(proof["id"], coin.id().to_string());
        assert_eq!(proof["chain_contract_verified"], true);
        assert_eq!(proof["signed_path_valid"], true);
        assert_eq!(proof["client_owner_verified"], false);
        let mut decoded = request.clone();
        decoded.as_object_mut().unwrap().remove("anchor_raw");
        let decoded = verify_contract(&decoded).unwrap();
        assert_eq!(decoded["exit_depth"], depth);
        assert_eq!(decoded["chain_contract_verified"], false);
        assert_eq!(decoded["client_owner_verified"], false);
        let mut bad = request.clone();
        bad["exit_depth"] = json!(0);
        assert!(verify_contract(&bad).is_err(), "caller cannot inject a depth assertion");
        let mut bad = request.clone();
        bad["server_pubkey"] = json!("wrong-server");
        assert!(verify_contract(&bad).is_err());
        let mut changed_anchor = original;
        changed_anchor.lock_time = bitcoin::absolute::LockTime::from_consensus(changed_anchor.lock_time.to_consensus_u32() ^ 1);
        let mut bad = request.clone();
        bad["anchor_raw"] = json!(encode(bitcoin::consensus::serialize(&changed_anchor)));
        assert!(verify_contract(&bad).is_err(), "different raw anchor must not qualify a depth proof");
        let mut bad = request.clone();
        bad["signed_vtxo"] = json!(encode(encoded[..encoded.len() - 1].to_vec()));
        assert!(verify_contract(&bad).is_err(), "truncated genuine Full is not a proof");
    }

    #[test]
    fn forfeit_fields_are_paired_anchor_only_and_cannot_inject_verdicts() {
        let original = fixture();
        for fields in [vec![("forfeit_raw", "00")],
            vec![("forfeit_unlock_hash", "00")],
            vec![("forfeit_raw", "00"), ("forfeit_unlock_hash", "00"), ("forfeit_signature_valid", "true")]] {
            let mut request = original.clone();
            for (key, value) in fields { request[key] = json!(value); }
            assert!(verify_contract(&request).is_err());
        }
        let mut no_anchor = original;
        no_anchor.as_object_mut().unwrap().remove("anchor_raw");
        no_anchor["forfeit_raw"] = json!("00");
        no_anchor["forfeit_unlock_hash"] = json!("00".repeat(32));
        assert!(verify_contract(&no_anchor).is_err());
    }

    #[test]
    fn padding_cannot_acquire_a_forfeit_signature_verdict() {
        let mut request: Value = serde_json::from_str(include_str!("../../tests/fixtures/public-round-padding-anchor.json")).unwrap();
        request["forfeit_raw"] = json!("00");
        request["forfeit_unlock_hash"] = json!("00".repeat(32));
        assert!(verify_contract(&request).is_err());
    }

    /// Explicit external genuine native round fixture; absence is a failed
    /// prerequisite. Raw Full/witness bodies remain private and are never logged.
    #[test]
    #[ignore = "requires genuine private original input/forfeit and output Full fixtures"]
    fn archived_native_original_forfeit_and_leaf_controls() {
        use std::os::unix::fs::MetadataExt;
        fn private_fixture(name: &str) -> Value {
            let path = std::env::var_os(name).expect("genuine private native fixture required");
            let before = std::fs::symlink_metadata(&path).unwrap();
            assert!(before.is_file() && !before.file_type().is_symlink()
                && before.mode() & 0o077 == 0 && before.nlink() == 1
                && before.len() <= 2 * 1024 * 1024);
            let mut file = std::fs::File::open(&path).unwrap();
            let opened = file.metadata().unwrap();
            assert!(before.dev() == opened.dev() && before.ino() == opened.ino()
                && before.len() == opened.len());
            let mut raw = Vec::new();
            file.by_ref().take(2 * 1024 * 1024 + 1).read_to_end(&mut raw).unwrap();
            let opened_after = file.metadata().unwrap();
            let after = std::fs::symlink_metadata(&path).unwrap();
            assert!(raw.len() as u64 == before.len() && before.dev() == after.dev()
                && before.ino() == after.ino() && before.mode() == after.mode()
                && before.nlink() == after.nlink() && before.uid() == after.uid()
                && before.mtime() == after.mtime() && before.mtime_nsec() == after.mtime_nsec()
                && before.ctime() == after.ctime() && before.ctime_nsec() == after.ctime_nsec()
                && before.len() == after.len() && opened.dev() == opened_after.dev()
                && opened.ino() == opened_after.ino() && opened.len() == opened_after.len()
                && opened.mtime() == opened_after.mtime() && opened.mtime_nsec() == opened_after.mtime_nsec()
                && opened.ctime() == opened_after.ctime() && opened.ctime_nsec() == opened_after.ctime_nsec());
            serde_json::from_slice(&raw).unwrap()
        }
        let request = private_fixture("BARK_SIM_ACTUAL_FORFEIT_REQUEST");
        let output = private_fixture("BARK_SIM_ACTUAL_ROUND_OUTPUT_REQUEST");
        let proof = verify_contract(&request).expect("genuine original native forfeit must verify");
        assert_eq!(proof["forfeit_signature_valid"], true);
        assert_eq!(proof["signed_path_valid"], true);
        assert_eq!(proof["client_owner_verified"], false);
        let output_proof = verify_contract(&output).expect("genuine ordinary round output must verify");
        assert_eq!(output_proof["signed_path_valid"], true);
        assert_eq!(output_proof["unlock_hash"], request["forfeit_unlock_hash"]);
        assert_eq!(output_proof["server_pubkey"], request["server_pubkey"]);
        let original: Transaction = bitcoin::consensus::deserialize(
            &decode_hex(request["forfeit_raw"].as_str().unwrap()).unwrap()).unwrap();
        for mode in 0..5 {
            let mut changed = original.clone();
            match mode {
                0 => { let mut sig = changed.input[0].witness.iter().next().unwrap().to_vec();
                    sig[0] ^= 1; changed.input[0].witness = Witness::from_slice(&[sig]); },
                1 => changed.output[0].value += Amount::from_sat(1),
                2 => changed.input[0].previous_output.vout ^= 1,
                3 => changed.input[0].sequence = Sequence::ZERO,
                _ => { let mut sig = changed.input[0].witness.iter().next().unwrap().to_vec();
                    sig.push(1); changed.input[0].witness = Witness::from_slice(&[sig]); },
            }
            let mut bad = request.clone();
            bad["forfeit_raw"] = json!(encode(bitcoin::consensus::serialize(&changed)));
            assert!(verify_contract(&bad).is_err(), "changed original forfeit must refuse");
        }
        let mut foreign_hash = request.clone();
        let mut hash = decode_hex(request["forfeit_unlock_hash"].as_str().unwrap()).unwrap();
        hash[0] ^= 1; foreign_hash["forfeit_unlock_hash"] = json!(encode(hash));
        assert!(verify_contract(&foreign_hash).is_err());
        let mut detached = request.clone(); detached["forfeit_signature_valid"] = json!(true);
        assert!(verify_contract(&detached).is_err());
    }

    #[test]
    fn validates_expiry_contract_and_never_asserts_customer_owner() {
        let proof = verify_contract(&fixture()).unwrap();
        assert_eq!(proof["amount_sat"], 80000);
        assert_eq!(proof["policy"], "expiry");
        assert_eq!(proof["chain_contract_verified"], true);
        assert_eq!(proof["client_owner_verified"], false);
    }
    #[test]
    fn decoding_expiry_without_anchor_never_qualifies_backing_or_customer_owner() {
        let mut request = fixture();
        request.as_object_mut().unwrap().remove("anchor_raw");
        let proof = verify_contract(&request).unwrap();
        assert_eq!(proof["chain_contract_verified"], false);
        assert_eq!(proof["client_owner_verified"], false);
        assert_eq!(proof["candidate_user_pubkey"], Value::Null);
    }
    #[test]
    fn refuses_client_owner_claim_and_wrong_server() {
        let mut request = fixture();
        request["client_owner_verified"] = json!(true);
        assert!(verify_contract(&request).is_err());
        let mut request = fixture();
        request["server_pubkey"] = json!("wrong-server");
        assert!(verify_contract(&request).is_err());
    }
    #[test]
    fn refuses_changed_anchor_script_or_value() {
        let request = fixture();
        let raw = decode_hex(request["anchor_raw"].as_str().unwrap()).unwrap();
        let original: Transaction = bitcoin::consensus::deserialize(&raw).unwrap();
        for mode in 0..3 {
            let mut tx = original.clone();
            match mode {
                0 => tx.lock_time = bitcoin::absolute::LockTime::from_consensus(1),
                1 => tx.output[0].script_pubkey = ScriptBuf::new(),
                _ => tx.output[0].value = Amount::from_sat(79999),
            };
            let mut bad = request.clone();
            bad["anchor_raw"] = json!(encode(bitcoin::consensus::serialize(&tx)));
            assert!(verify_contract(&bad).is_err());
        }
    }
}

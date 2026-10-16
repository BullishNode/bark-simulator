//! Public server-policy contract proof against supplied raw chain evidence.
//! No wallet, keys, node credentials or network operations.
use ark::{
    vtxo::{policy::ServerVtxoPolicy, Full},
    ProtocolEncoding, Vtxo,
};
use serde_json::{json, Value};
use std::io::Read;
#[cfg(feature = "two-step")]
use ark::{forfeit::create_hark_forfeit_tx, tree::signed::UnlockHash};
#[cfg(feature = "two-step")]
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
#[cfg(feature = "two-step")]
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

/// Compare a literal stored native Full with the independently validated client
/// Full. This authenticates the supplied representations, not their SQL origin.
#[cfg(feature = "two-step")]
fn verify_native_original(
    completed: &Vtxo<Full, ServerVtxoPolicy>,
    completed_raw: &[u8],
    anchor: &bitcoin::Transaction,
    value: &Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    let native_raw = decode_hex(value["native_vtxo"].as_str().ok_or("native original absent")?)?;
    let native = Vtxo::<Full, ServerVtxoPolicy>::deserialize(&native_raw)?;
    if completed.policy_type().to_string() != "pubkey"
        || native.policy_type().to_string() != "pubkey"
        || padding_marker(completed) || padding_marker(&native)
    {
        return Err("native completion requires ordinary non-padding Fulls".into());
    }
    // Canonical original hashes must bind exactly the bytes the caller supplied.
    if completed.serialize() != completed_raw || native.serialize() != native_raw {
        return Err("native completion requires canonical original Full bytes".into());
    }
    native.validate_unsigned(anchor)?;
    if native.id() != completed.id()
        || native.chain_anchor() != completed.chain_anchor()
        || native.server_pubkey() != completed.server_pubkey()
        || native.policy().serialize() != completed.policy().serialize()
        || native.to_bare().serialize() != completed.to_bare().serialize()
    {
        return Err("native original identity or committed contract differs".into());
    }
    let relation = if native_raw == completed_raw {
        "exact_full_equality"
    } else if completed.is_final_hark_leaf_completion_of(&native) {
        "final_hark_leaf_completion"
    } else {
        return Err("native original is not an exact known-field-preserving completion".into());
    };
    Ok(json!({
        "native_vtxo_sha256": sha256::Hash::hash(&native_raw).to_string(),
        "completed_vtxo_sha256": sha256::Hash::hash(completed_raw).to_string(),
        "native_completion_relation": relation,
        "native_owner_verified": false,
        "payment_verified": false,
        "native_completion_scope": "supplied native structure and exact completed signed path only; SQL origin, ownership, confirmation, payment, current availability and retirement are separate"
    }))
}

/// Original-only context shared by the two disjoint proof modes.
#[cfg(feature = "two-step")]
struct AuthenticatedOrdinaryTree {
    raw: Vec<u8>,
    signed: ark::tree::signed::SignedVtxoTreeSpec,
    anchor: bitcoin::Transaction,
    anchor_raw: Vec<u8>,
    hash: UnlockHash,
    matching: Vec<usize>,
}

#[cfg(feature = "two-step")]
fn authenticate_ordinary_tree(value: &Value) -> Result<AuthenticatedOrdinaryTree, Box<dyn std::error::Error>> {
    use ark::tree::signed::SignedVtxoTreeSpec;
    let raw = decode_hex(value["signed_tree"].as_str().ok_or("signed tree absent")?)?;
    let signed = SignedVtxoTreeSpec::deserialize(&raw)?;
    // Bound public construction before building or detecting the hashlock version.
    // Single-leaf historical trees and conditional leaves need separate qualification.
    if signed.serialize() != raw || !(2..=4096).contains(&signed.spec.vtxos.len())
        || signed.spec.global_cosign_pubkeys.is_empty() || signed.spec.global_cosign_pubkeys.len() > 4096
        || signed.cosign_sigs.len() != signed.spec.nb_internal_nodes()
        || signed.spec.vtxos.iter().any(|leaf| leaf.vtxo.policy.policy_type().to_string() != "pubkey")
    {
        return Err("bounded canonical ordinary signed tree required".into());
    }
    let total = signed.spec.vtxos.iter().try_fold(0u64, |total, leaf| {
        total.checked_add(leaf.vtxo.amount.to_sat())
    }).ok_or("tree amount overflow")?;
    if total == 0 || total > 2_100_000_000_000_000 {
        return Err("tree amount outside bounded Bitcoin money range".into());
    }
    let server = value["server_pubkey"].as_str().ok_or("server absent")?;
    if signed.spec.server_pubkey.to_string() != server {
        return Err("signed tree server differs".into());
    }
    let anchor_raw = decode_hex(value["anchor_raw"].as_str().ok_or("anchor absent")?)?;
    let anchor: bitcoin::Transaction = bitcoin::consensus::deserialize(&anchor_raw)?;
    if bitcoin::consensus::serialize(&anchor) != anchor_raw || anchor.compute_txid() != signed.utxo.txid {
        return Err("signed tree funding identity differs".into());
    }
    let signed = signed.with_detected_hashlock_version()?;
    // Version detection checks only one signature. Verify EVERY internal node.
    let unsigned = signed.spec.clone().into_unsigned_tree(signed.utxo);
    unsigned.verify_cosign_sigs(&signed.cosign_sigs)
        .map_err(|_| "signed tree internal cosignature invalid")?;
    if anchor.output.get(signed.utxo.vout as usize) != Some(&signed.spec.funding_tx_txout()) {
        return Err("signed tree funding value or script differs".into());
    }
    let hash: UnlockHash = value["participation_unlock_hash"].as_str()
        .ok_or("participation unlock hash absent")?.parse()?;
    let matching = signed.spec.vtxos.iter().enumerate()
        .filter_map(|(index, leaf)| (leaf.unlock_hash == hash).then_some(index)).collect::<Vec<_>>();
    if matching.is_empty() || matching.len() > 256 {
        return Err("all participation leaves required within the supported bound".into());
    }
    Ok(AuthenticatedOrdinaryTree { raw, signed, anchor, anchor_raw, hash, matching })
}

/// Authenticate one complete participation's allocation against a literal signed
/// tree. SQL provenance, original input forfeits and conservation stay external.
#[cfg(feature = "two-step")]
fn verify_round_allocation(value: &Value) -> Result<Value, Box<dyn std::error::Error>> {
    use std::collections::BTreeSet;
    let fields = value.as_object().ok_or("allocation object required")?;
    let permitted = ["signed_tree", "anchor_raw", "server_pubkey", "participation_unlock_hash", "outputs"];
    if fields.len() != permitted.len() || !permitted.iter().all(|key| fields.contains_key(*key)) {
        return Err("exact signed tree, anchor, server, participation hash and output set required".into());
    }
    let AuthenticatedOrdinaryTree { raw, signed, anchor, anchor_raw, hash, matching } = authenticate_ordinary_tree(value)?;
    let server = value["server_pubkey"].as_str().ok_or("server absent")?;
    let outputs = value["outputs"].as_array().ok_or("completed output originals absent")?;
    if matching.is_empty() || outputs.len() != matching.len() || outputs.len() > 256 {
        return Err("output set must cover ALL participation leaves within bound".into());
    }
    let anchor_point = signed.utxo;
    let internal_signature_count = signed.cosign_sigs.len();
    let tree_leaf_count = signed.spec.nb_leaves();
    let cached = signed.into_cached_tree();
    let originals = matching.iter().map(|index| {
        let coin: Vtxo<Full, ServerVtxoPolicy> = cached.build_vtxo(*index).into();
        (*index, coin)
    }).collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    let mut allocations = Vec::with_capacity(outputs.len());
    let mut allocation_sat = 0u64;
    for output in outputs {
        let object = output.as_object().ok_or("output original object required")?;
        let native_mode = object.contains_key("native_vtxo");
        if object.len() != (if native_mode { 2 } else { 1 })
            || !object.contains_key("signed_vtxo")
        {
            return Err("output permits only completed Full and optional literal native Full".into());
        }
        let completed_raw = decode_hex(output["signed_vtxo"].as_str().ok_or("output Full absent")?)?;
        let completed = Vtxo::<Full, ServerVtxoPolicy>::deserialize(&completed_raw)?;
        if completed.serialize() != completed_raw || completed.server_pubkey().to_string() != server
            || completed.chain_anchor() != anchor_point || completed.unlock_hash() != Some(hash)
            || completed.policy_type().to_string() != "pubkey" || padding_marker(&completed)
        {
            return Err("completed output contract differs from participation".into());
        }
        completed.validate(&anchor)?;
        let (index, original) = originals.iter().find(|(_, native)| native.id() == completed.id())
            .ok_or("output is not a matching signed-tree leaf")?;
        if !seen.insert(*index) {
            return Err("duplicate completed output or allocation index".into());
        }
        // Existing e217 API compares every known structured signature/preimage.
        let derived_request = json!({"native_vtxo": original.serialize_hex()});
        let derived = verify_native_original(&completed, &completed_raw, &anchor, &derived_request)?;
        let literal_native = if native_mode {
            Some(verify_native_original(&completed, &completed_raw, &anchor, output)?)
        } else { None };
        allocation_sat = allocation_sat.checked_add(completed.amount().to_sat())
            .ok_or("allocation amount overflow")?;
        let user = completed.clone().try_into_user_vtxo().map_err(|_| "ordinary user policy required")?;
        let mut allocation = json!({
            "leaf_index":index,"id":completed.id().to_string(),"amount_sat":completed.amount().to_sat(),
            "policy":completed.policy_type().to_string(),"user_policy_hex":user.policy().serialize_hex(),
            "leaf_spec_sha256":sha256::Hash::hash(&cached.spec.spec.vtxos[*index].serialize()).to_string(),
            "user_pubkey":completed.policy().user_pubkey().map(|key| key.to_string()),
            "unlock_hash":hash.to_string(),
            "completed_vtxo_sha256":sha256::Hash::hash(&completed_raw).to_string(),
            "tree_native_vtxo_sha256":derived["native_vtxo_sha256"],
            "tree_completion_relation":derived["native_completion_relation"]
        });
        if let Some(native) = literal_native {
            allocation["literal_native_vtxo_sha256"] = native["native_vtxo_sha256"].clone();
            allocation["literal_native_completion_relation"] = native["native_completion_relation"].clone();
        }
        allocations.push(allocation);
    }
    if seen != matching.iter().copied().collect::<BTreeSet<_>>() {
        return Err("participation leaf coverage incomplete".into());
    }
    allocations.sort_by_key(|allocation| allocation["leaf_index"].as_u64());
    Ok(json!({"schema_version":1,"mode":"round_allocation","sdk_commit":option_env!("GIT_HASH"),
        "signed_tree_sha256":sha256::Hash::hash(&raw).to_string(),
        "anchor_raw_sha256":sha256::Hash::hash(&anchor_raw).to_string(),
        "chain_anchor":anchor_point.to_string(),"server_pubkey":server,
        "participation_unlock_hash":hash.to_string(),"tree_leaf_count":tree_leaf_count,
        "verified_internal_signature_count":internal_signature_count,
        "all_matching_leaf_indices":matching,"allocation_sat":allocation_sat,"allocations":allocations,
        "all_matching_leaves_verified":true,"client_owner_verified":false,"payment_verified":false,
        "scope":"supplied ordinary signed-tree exhaustive hash-bound output allocation only; SQL provenance, participation ownership, input forfeits, fees, retirement, confirmation and current backing require separate authenticated proof"}))
}

/// Authenticate a pending allocation without requiring a client to come online.
/// This never supplies completed-leaf, retirement, payment or owner credit.
#[cfg(feature = "two-step")]
fn verify_pending_entitlement(value: &Value) -> Result<Value, Box<dyn std::error::Error>> {
    let fields = value.as_object().ok_or("pending entitlement object required")?;
    let permitted = ["mode", "signed_tree", "anchor_raw", "server_pubkey", "participation_unlock_hash"];
    if fields.len() != permitted.len() || !permitted.iter().all(|key| fields.contains_key(*key))
        || value["mode"].as_str() != Some("pending_entitlement")
    {
        return Err("exact pending-entitlement mode and original tree context required; no completed output or verdict fields".into());
    }
    let AuthenticatedOrdinaryTree { raw, signed, anchor, anchor_raw, hash, matching } = authenticate_ordinary_tree(value)?;
    let server = signed.spec.server_pubkey.to_string();
    let anchor_point = signed.utxo;
    let tree_leaf_count = signed.spec.nb_leaves();
    let internal_signature_count = signed.cosign_sigs.len();
    let cached = signed.into_cached_tree();
    let mut pending_allocations = Vec::with_capacity(matching.len());
    let mut entitlement_sat = 0u64;
    for index in &matching {
        let user = cached.build_vtxo(*index);
        let user_policy_hex = user.policy().serialize_hex();
        let native: Vtxo<Full, ServerVtxoPolicy> = user.into();
        if native.policy_type().to_string() != "pubkey" || padding_marker(&native)
            || native.chain_anchor() != anchor_point || native.unlock_hash() != Some(hash)
            || native.server_pubkey().to_string() != server
        {
            return Err("derived pending ordinary contract differs".into());
        }
        native.validate_unsigned(&anchor)?;
        entitlement_sat = entitlement_sat.checked_add(native.amount().to_sat())
            .ok_or("pending entitlement amount overflow")?;
        let path = native.transactions().map(|item| json!({
            "txid":item.tx.compute_txid().to_string(),"output_index":item.output_idx,
            "transaction_sha256":sha256::Hash::hash(&bitcoin::consensus::serialize(&item.tx)).to_string()
        })).collect::<Vec<_>>();
        pending_allocations.push(json!({
            "leaf_index":index,"id":native.id().to_string(),"amount_sat":native.amount().to_sat(),
            "policy":native.policy_type().to_string(),"user_policy_hex":user_policy_hex,
            "user_pubkey":native.policy().user_pubkey().map(|key| key.to_string()),
            "unlock_hash":hash.to_string(),"chain_anchor":native.chain_anchor().to_string(),
            "expiry_height":native.expiry_height().to_u32(),"exit_delta":native.exit_delta().to_u32(),
            "exit_depth":native.exit_depth(),"output_script":native.output_script_pubkey().to_hex_string(),
            "leaf_spec_sha256":sha256::Hash::hash(&cached.spec.spec.vtxos[*index].serialize()).to_string(),
            "tree_native_vtxo_sha256":sha256::Hash::hash(&native.serialize()).to_string(),
            "derived_native_path":path,"unsigned_path_verified":true,
            "signed_leaf_verified":false,"current_spendability_verified":false,
            "client_owner_verified":false,"retirement_verified":false,"payment_verified":false
        }));
    }
    Ok(json!({"schema_version":1,"mode":"pending_entitlement","sdk_commit":option_env!("GIT_HASH"),
        "signed_tree_sha256":sha256::Hash::hash(&raw).to_string(),
        "anchor_raw_sha256":sha256::Hash::hash(&anchor_raw).to_string(),
        "chain_anchor":anchor_point.to_string(),"server_pubkey":server,
        "participation_unlock_hash":hash.to_string(),"tree_leaf_count":tree_leaf_count,
        "verified_internal_signature_count":internal_signature_count,
        "original_sha256":{"signed_tree":sha256::Hash::hash(&raw).to_string(),"anchor_raw":sha256::Hash::hash(&anchor_raw).to_string()},
        "all_matching_pending_leaf_indices":matching,"pending_entitlement_sat":entitlement_sat,
        "pending_allocations":pending_allocations,"pending_allocation_membership_verified":true,
        "signed_leaf_verified":false,"current_spendability_verified":false,
        "client_owner_verified":false,"retirement_verified":false,"payment_verified":false,
        "scope":"supplied signed-tree pending entitlement membership and derived unsigned native path only; no client leaf completion, SQL provenance, ownership, input retirement, payment, chain confirmation or current availability; preserve original obligations separately"}))
}

/// Public physical-point membership only. Never export witness/scriptSig/key bodies.
#[cfg(feature = "two-step")]
fn checked_public_path_size(nodes: usize, inputs: usize, outputs: usize, raw: usize)
    -> Result<(), Box<dyn std::error::Error>>
{
    let projected_bound=raw.checked_mul(2)
        .and_then(|n|inputs.checked_mul(96).and_then(|v|n.checked_add(v)))
        .and_then(|n|outputs.checked_mul(128).and_then(|v|n.checked_add(v)))
        .and_then(|n|nodes.checked_mul(256).and_then(|v|n.checked_add(v)))
        .and_then(|n|n.checked_add(16384)).ok_or("path public JSON size overflow")?;
    if nodes > 256 || inputs > 4096 || outputs > 4096 || raw > 2*1024*1024 || projected_bound > 2*1024*1024 {
        return Err("bounded validated public transaction path exceeded".into());
    }
    Ok(())
}

#[cfg(feature = "two-step")]
fn verify_public_transaction_path(value: &Value) -> Result<Value, Box<dyn std::error::Error>> {
    let fields=value.as_object().ok_or("public object required")?;
    let mut permitted=vec!["mode","signed_vtxo","anchor_raw","server_pubkey"];
    if fields.contains_key("native_vtxo") { permitted.push("native_vtxo"); }
    if fields.len()!=permitted.len() || !permitted.iter().all(|key|fields.contains_key(*key))
        || value["mode"].as_str()!=Some("validated_transaction_path")
    {
        return Err("exact validated-transaction-path request required".into());
    }
    let mut base=value.clone();base.as_object_mut().ok_or("object required")?.remove("mode");
    // Existing full/anchor/native verifier runs FIRST and preserves its exact
    // signed versus unsigned-padding and known-field-completion distinctions.
    let mut response=verify_contract(&base)?;
    let encoded=decode_hex(value["signed_vtxo"].as_str().ok_or("coin absent")?)?;
    let coin=Vtxo::<Full,ServerVtxoPolicy>::deserialize(&encoded)?;
    let mut count=0usize;let mut inputs=0usize;let mut outputs=0usize;let mut raw=0usize;
    for item in coin.transactions() {
        count=count.checked_add(1).ok_or("path count overflow")?;
        inputs=inputs.checked_add(item.tx.input.len()).ok_or("path input overflow")?;
        outputs=outputs.checked_add(item.tx.output.len()).ok_or("path output overflow")?;
        raw=raw.checked_add(item.tx.total_size()).ok_or("path raw byte overflow")?;
        checked_public_path_size(count,inputs,outputs,raw)?;
        if item.output_idx as usize>=item.tx.output.len() { return Err("path selected output absent".into()); }
    }
    // All aggregate bounds precede projection/transaction-byte materialisation.
    let path=coin.transactions().map(|item| json!({
        "txid":item.tx.compute_txid().to_string(),"output_index":item.output_idx,
        "transaction_sha256":sha256::Hash::hash(&bitcoin::consensus::serialize(&item.tx)).to_string(),
        "inputs":item.tx.input.iter().map(|input|input.previous_output.to_string()).collect::<Vec<_>>(),
        "outputs":item.tx.output.iter().enumerate().map(|(n,output)|json!({
            "n":n,"amount_sat":output.value.to_sat(),"script_pubkey":output.script_pubkey.to_hex_string()
        })).collect::<Vec<_>>()
    })).collect::<Vec<_>>();
    let object=response.as_object_mut().ok_or("public result object required")?;
    object.insert("mode".into(),json!("validated_transaction_path"));
    object.insert("validated_vtxo_sha256".into(),json!(sha256::Hash::hash(&encoded).to_string()));
    object.insert("anchor_raw_sha256".into(),json!(sha256::Hash::hash(&decode_hex(value["anchor_raw"].as_str().ok_or("anchor absent")?)?).to_string()));
    object.insert("public_transaction_path".into(),json!(path));
    object.insert("public_path_transaction_count".into(),json!(count));
    object.insert("public_path_input_count".into(),json!(inputs));
    object.insert("public_path_output_count".into(),json!(outputs));
    object.insert("public_path_raw_size_bytes".into(),json!(raw));
    object.insert("retirement_verified".into(),json!(false));
    object.insert("payment_verified".into(),json!(false));
    object.insert("current_spendability_verified".into(),json!(false));
    Ok(response)
}

#[cfg(feature = "two-step")]
fn verify_contract(value: &Value) -> Result<Value, Box<dyn std::error::Error>> {
    if value["mode"].as_str()==Some("validated_transaction_path") { return verify_public_transaction_path(value); }
    if value.get("mode").is_some() { return verify_pending_entitlement(value); }
    if value.get("signed_tree").is_some() { return verify_round_allocation(value); }
    let fields = value.as_object().ok_or("public object required")?;
    let native_mode = fields.contains_key("native_vtxo");
    let retained_projection_mode = fields.contains_key("retained_public_projection");
    let forfeit_mode = fields.contains_key("forfeit_raw") || fields.contains_key("forfeit_unlock_hash");
    let anchor_mode = fields.contains_key("anchor_raw");
    let mut permitted = vec!["signed_vtxo", "server_pubkey"];
    if anchor_mode { permitted.push("anchor_raw"); }
    if native_mode { permitted.push("native_vtxo"); }
    if retained_projection_mode { permitted.push("retained_public_projection"); }
    if forfeit_mode { permitted.extend(["forfeit_raw", "forfeit_unlock_hash"]); }
    if fields.len() != permitted.len()
        || !permitted.iter().all(|field| fields.contains_key(*field))
        || ((native_mode || forfeit_mode) && !anchor_mode)
        || (retained_projection_mode && (!native_mode || forfeit_mode))
    {
        return Err("only exact coin/server, optional anchor, native original and paired forfeit fields permitted".into());
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
    let native_original = if native_mode {
        Some(verify_native_original(&coin, &encoded, &tx, value)?)
    } else {
        None
    };
    let retained_projection = if retained_projection_mode {
        if padding || coin.policy_type().to_string() != "pubkey"
            || !coin.transactions().all(|item| item.tx.input.len() == 1
                && item.tx.input[0].witness.len() == 1
                && item.tx.input[0].witness.iter().all(|part| part.len() == 64))
        {
            return Err("retained projection join supports only fully signed ordinary key paths".into());
        }
        let raw = decode_hex(value["retained_public_projection"].as_str().ok_or("retained projection absent")?)?;
        let verified = bark_sim_driver::public_coin::verify(&raw, &tx)?;
        if verified.conditional_steps != 0 {
            return Err("conditional retained projection requires its own source join".into());
        }
        // Reuse the original public representation. Compare EVERY encoded
        // transaction, policy and signature, not just Bare fields or txids.
        // No conditional witness/preimage is omitted by this ordinary mode.
        let user = coin.clone().try_into_user_vtxo().map_err(|_| "ordinary user policy required")?;
        let expected = bark_sim_driver::public_coin::encode(&user)?;
        if serde_json::from_slice::<Value>(&raw)? != serde_json::from_slice::<Value>(&expected)? {
            return Err("retained public original differs from exact ordinary Full encoding".into());
        }
        Some(json!({"retained_public_projection_sha256":sha256::Hash::hash(&raw).to_string(),
            "retained_public_projection_relation":"exact_ordinary_public_encoding",
            "retained_public_projection_verified":true,"retained_original_owner_verified":false}))
    } else {
        None
    };
    let forfeit = if forfeit_mode {
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
    if let Some(native_original) = native_original {
        response.as_object_mut().ok_or("contract response must be an object")?
            .extend(native_original.as_object().ok_or("native response must be an object")?.clone());
    }
    if let Some(forfeit) = forfeit {
        response.as_object_mut().ok_or("contract response must be an object")?
            .extend(forfeit.as_object().ok_or("forfeit response must be an object")?.clone());
    }
    if let Some(retained_projection) = retained_projection {
        response.as_object_mut().ok_or("contract response must be an object")?
            .extend(retained_projection.as_object().ok_or("retained projection response must be an object")?.clone());
    }
    Ok(response)
}


// Other architectures retain their exact original public proof contract.
// New A-only completion/tree/forfeit modes are rejected by its strict fields.
#[cfg(not(feature = "two-step"))]
fn verify_contract(value: &Value) -> Result<Value, Box<dyn std::error::Error>> {
    let fields = value.as_object().ok_or("public object required")?;
    if ![2, 3].contains(&fields.len())
        || !["signed_vtxo", "server_pubkey"]
            .iter()
            .all(|field| fields.contains_key(*field))
        || (fields.len() == 3 && !fields.contains_key("anchor_raw"))
    {
        return Err("only public coin, raw anchor and pinned server key permitted".into());
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
    let output = tx
        .output
        .get(anchor.vout as usize)
        .ok_or("anchor output absent")?;
    if coin.point() == anchor
        && (output.value != coin.amount() || output.script_pubkey != coin.output_script_pubkey())
    {
        return Err("direct anchor contract value/script differs".into());
    }
    Ok(
        json!({"schema_version":1,"sdk_commit":option_env!("GIT_HASH"),"id":coin.id().to_string(),"chain_anchor":anchor.to_string(),
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
        "scope":if padding {"protocol padding unsigned structure and exact raw anchor; signatures, customer ownership, confirmation and spend status are unproved"} else {"public server-policy contract and exact raw anchor; confirmations, customer ownership and current spendability are separate"}}),
    )
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
    #[cfg(feature = "two-step")]
    fn retained_projection_fixture() -> Value {
        use ark::board::BoardBuilder;
        use bitcoin::secp256k1::{Keypair, SecretKey};
        let user=Keypair::from_secret_key(&ark::SECP,&SecretKey::from_slice(&[31;32]).unwrap());
        let server=Keypair::from_secret_key(&ark::SECP,&SecretKey::from_slice(&[32;32]).unwrap());
        let builder=BoardBuilder::new(user.public_key(),144u32.into(),server.public_key(),12u16.into());
        let amount=Amount::from_sat(28000);let fee=Amount::from_sat(330);
        let funding=Transaction {version:bitcoin::transaction::Version::TWO,
            lock_time:bitcoin::absolute::LockTime::ZERO,input:vec![],
            output:vec![TxOut {value:amount,script_pubkey:builder.funding_script_pubkey()}]};
        let point=OutPoint::new(funding.compute_txid(),0);
        let builder=builder.set_funding_details(amount,fee,point).unwrap().generate_user_nonces();
        let cosign=BoardBuilder::new_for_cosign(user.public_key(),144u32.into(),server.public_key(),
            12u16.into(),amount,fee,point,*builder.user_pub_nonce()).server_cosign(&server);
        let coin=builder.build_vtxo(&cosign,&user).unwrap();
        json!({"signed_vtxo":encode(coin.serialize()),"native_vtxo":encode(coin.serialize()),
            "retained_public_projection":encode(bark_sim_driver::public_coin::encode(&coin).unwrap()),
            "anchor_raw":encode(bitcoin::consensus::serialize(&funding)),"server_pubkey":server.public_key().to_string()})
    }
    #[test]
    #[cfg(feature = "two-step")]
    fn public_transaction_path_preserves_direct_expiry_contract_and_false_credit() {
        let mut request=fixture();request["mode"]=json!("validated_transaction_path");
        let result=verify_contract(&request).unwrap();
        assert_eq!(result["policy"],"expiry");assert_eq!(result["public_transaction_path"],json!([]));
        assert_eq!(result["public_path_transaction_count"],0);
        assert_eq!(result["validated_vtxo_sha256"],sha256::Hash::hash(&decode_hex(request["signed_vtxo"].as_str().unwrap()).unwrap()).to_string());
        for flag in ["client_owner_verified","payment_verified","retirement_verified","current_spendability_verified"] {
            assert_eq!(result[flag],false);
        }
    }
    #[test]
    #[cfg(feature = "two-step")]
    fn public_transaction_path_validates_signed_board_and_projects_all_outputs_without_witnesses() {
        let mut request=retained_projection_fixture();request.as_object_mut().unwrap().remove("retained_public_projection");
        request["mode"]=json!("validated_transaction_path");let result=verify_contract(&request).unwrap();
        let coin=Vtxo::<Full,ServerVtxoPolicy>::deserialize(&decode_hex(request["signed_vtxo"].as_str().unwrap()).unwrap()).unwrap();
        let expected=coin.transactions().collect::<Vec<_>>();
        assert_eq!(result["public_transaction_path"].as_array().unwrap().len(),expected.len());
        assert!(!expected.is_empty());assert_eq!(result["signed_path_valid"],true);
        for (projected,item) in result["public_transaction_path"].as_array().unwrap().iter().zip(expected) {
            assert_eq!(projected["txid"],item.tx.compute_txid().to_string());
            assert_eq!(projected["outputs"].as_array().unwrap().len(),item.tx.output.len());
            assert!(projected.get("witness").is_none() && projected.get("raw").is_none() && projected.get("script_sig").is_none());
        }
    }
    #[test]
    #[cfg(feature = "two-step")]
    fn public_transaction_path_cannot_bypass_anchor_native_or_mode_boundaries() {
        for mutation in ["anchor","native","projection","forfeit","mode","tree"] {
            let mut request=retained_projection_fixture();request.as_object_mut().unwrap().remove("retained_public_projection");
            request["mode"]=json!("validated_transaction_path");
            match mutation {
                "anchor" => request["anchor_raw"]=json!("00"),
                "native" => request["native_vtxo"]=json!("00"),
                "projection" => request["public_projection"]=json!({}),
                "forfeit" => request["forfeit_raw"]=json!("00"),
                "mode" => request["mode"]=json!("pending_entitlement"),
                "tree" => request["signed_tree"]=json!("00"),
                _ => unreachable!(),
            }
            assert!(verify_contract(&request).is_err(),"path projection must not widen accepted modes");
        }
    }
    #[test]
    #[cfg(feature = "two-step")]
    fn public_transaction_path_size_refuses_each_aggregate_limit() {
        checked_public_path_size(1,1,2,1000).unwrap();
        for tuple in [(257,1,1,1),(1,4097,1,1),(1,1,4097,1),(1,1,1,2*1024*1024+1),(256,4096,4096,1000000)] {
            assert!(checked_public_path_size(tuple.0,tuple.1,tuple.2,tuple.3).is_err());
        }
    }
    #[test]
    #[cfg(feature = "two-step")]
    fn retained_public_original_matches_every_ordinary_full_field() {
        let request=retained_projection_fixture();let result=verify_contract(&request).unwrap();
        assert_eq!(result["retained_public_projection_verified"],true);
        assert_eq!(result["retained_public_projection_relation"],"exact_ordinary_public_encoding");
        assert_eq!(result["retained_original_owner_verified"],false);
        assert_eq!(result["native_completion_relation"],"exact_full_equality");
        assert_eq!(result["amount_sat"],27670);
        let raw=decode_hex(request["retained_public_projection"].as_str().unwrap()).unwrap();
        assert_eq!(result["retained_public_projection_sha256"],sha256::Hash::hash(&raw).to_string());
    }
    #[test]
    #[cfg(feature = "two-step")]
    fn retained_public_original_refuses_signature_transaction_and_bare_substitutions() {
        for field in ["signature","transaction","bare_vtxo"] {
            let mut request=retained_projection_fixture();
            let mut projection:Value=serde_json::from_slice(&decode_hex(request["retained_public_projection"].as_str().unwrap()).unwrap()).unwrap();
            let value=if field=="signature" {&mut projection["path"][0]["authorization"]["signature"]}
                else if field=="transaction" {&mut projection["path"][0]["transaction"]} else {&mut projection["bare_vtxo"]};
            let mut raw=decode_hex(value.as_str().unwrap()).unwrap();raw[0]^=1;*value=json!(encode(raw));
            request["retained_public_projection"]=json!(encode(serde_json::to_vec(&projection).unwrap()));
            assert!(verify_contract(&request).is_err(),"known public field {field} must match and verify");
        }
    }
    #[test]
    #[cfg(feature = "two-step")]
    fn retained_public_original_requires_exact_paired_mode_and_full_signatures() {
        for field in ["native_vtxo","anchor_raw"] {
            let mut request=retained_projection_fixture();request.as_object_mut().unwrap().remove(field);
            assert!(verify_contract(&request).is_err());
        }
        let mut request=retained_projection_fixture();request["forfeit_raw"]=json!("00");
        assert!(verify_contract(&request).is_err());
        let mut request=retained_projection_fixture();request["signed_vtxo"]=request["retained_public_projection"].clone();
        assert!(verify_contract(&request).is_err(),"projection cannot be interpreted as Full");
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
    #[cfg(feature = "two-step")]
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
    #[cfg(feature = "two-step")]
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
    #[cfg(feature = "two-step")]
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

    // Uses the exact public native builder APIs exercised by e217's own
    // final_hark_completion_tests. This is an unfunded cryptographic unit
    // fixture, never a real Core/native database qualification.
    #[cfg(feature = "two-step")]
    fn native_completion_fixture() -> (Transaction, Vtxo<Full, ServerVtxoPolicy>, Vtxo<Full, ServerVtxoPolicy>) {
        use ark::{VtxoPolicy, VtxoRequest};
        use ark::tree::signed::{LeafVtxoCosignContext, LeafVtxoCosignResponse};
        use ark::tree::signed::builder::SignedTreeBuilder;
        use bitcoin::secp256k1::Keypair;
        fn key(byte: u8) -> Keypair {
            Keypair::from_secret_key(&ark::SECP, &bitcoin::secp256k1::SecretKey::from_slice(&[byte; 32]).unwrap())
        }
        let leaf_key = key(1);
        let user_cosign = key(2);
        let server = key(3);
        let server_cosign = key(4);
        let preimage = [7; 32];
        let expiry = 128u32.into();
        let delta = 12u16.into();
        let requests = [10_000, 20_000].map(|amount| VtxoRequest {
            amount: Amount::from_sat(amount),
            policy: VtxoPolicy::new_pubkey(leaf_key.public_key()),
        });
        let builder = SignedTreeBuilder::new(requests.iter().cloned(), user_cosign.public_key(), preimage,
            expiry, server.public_key(), server_cosign.public_key(), delta).unwrap();
        let funding = Transaction { version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO, input: vec![], output: vec![builder.funding_txout()] };
        let point = OutPoint::new(funding.compute_txid(), 0);
        let builder = builder.set_utxo(point).generate_user_nonces(&user_cosign);
        let response = SignedTreeBuilder::new_for_cosign(requests.iter().cloned(), user_cosign.public_key(),
            preimage, expiry, server.public_key(), server_cosign.public_key(), delta, point,
            builder.user_pub_nonces().to_vec()).unwrap().server_cosign(&server_cosign);
        builder.verify_cosign_response(&response).unwrap();
        let tree = builder.build_tree(&response, &user_cosign).unwrap().into_cached_tree();
        let original = tree.output_vtxos().next().unwrap();
        let mut complete = original.clone();
        let (context, request) = LeafVtxoCosignContext::new(&complete, &funding, &leaf_key).unwrap();
        let response = LeafVtxoCosignResponse::new_cosign(&request, &complete, &funding, &server).unwrap();
        assert!(context.finalize(&mut complete, response));
        assert!(complete.provide_unlock_preimage(preimage));
        original.validate_unsigned(&funding).unwrap();
        assert!(original.validate(&funding).is_err());
        complete.validate(&funding).unwrap();
        (funding, original.into(), complete.into())
    }

    #[cfg(feature = "two-step")]
    fn native_request(anchor: &Transaction, original: &Vtxo<Full, ServerVtxoPolicy>, complete: &Vtxo<Full, ServerVtxoPolicy>) -> Value {
        json!({"signed_vtxo":encode(complete.serialize()),
            "anchor_raw":encode(bitcoin::consensus::serialize(anchor)),
            "server_pubkey":complete.server_pubkey().to_string(),
            "native_vtxo":encode(original.serialize())})
    }

    #[test]
    #[cfg(feature = "two-step")]
    fn native_original_fields_require_anchor_exact_shape_and_ordinary_full() {
        let mut no_anchor = fixture();
        no_anchor.as_object_mut().unwrap().remove("anchor_raw");
        no_anchor["native_vtxo"] = no_anchor["signed_vtxo"].clone();
        assert!(verify_contract(&no_anchor).is_err());
        let mut expiry = fixture(); expiry["native_vtxo"] = expiry["signed_vtxo"].clone();
        assert!(verify_contract(&expiry).is_err(), "internal expiry policy is outside ordinary completion scope");
        let mut padding: Value = serde_json::from_str(include_str!("../../tests/fixtures/public-round-padding-anchor.json")).unwrap();
        padding["native_vtxo"] = padding["signed_vtxo"].clone();
        assert!(verify_contract(&padding).is_err());
        let mut projected: Value = serde_json::from_str(include_str!("../../tests/fixtures/public-round-padding.json")).unwrap();
        projected["native_vtxo"] = projected["signed_vtxo"].clone();
        assert!(verify_contract(&projected).is_err());
        let (anchor, original, complete) = native_completion_fixture();
        let request = native_request(&anchor, &original, &complete);
        for key in ["native_completion_relation", "native_owner_verified", "payment_verified", "detached_native_valid"] {
            let mut changed = request.clone(); changed[key] = json!(true);
            assert!(verify_contract(&changed).is_err());
        }
        let mut paired = request; paired["forfeit_raw"] = json!("00");
        assert!(verify_contract(&paired).is_err(), "forfeit fields remain paired in native mode");
    }

    #[test]
    #[cfg(feature = "two-step")]
    fn native_original_accepts_exact_or_only_known_field_preserving_final_leaf_completion() {
        let (anchor, original, complete) = native_completion_fixture();
        let mut variants = vec![(original.clone(), "final_hark_leaf_completion"),
            (complete.clone(), "exact_full_equality")];
        let signature = schnorr::Signature::from_slice(
            complete.transactions().last().unwrap().tx.input[0].witness.iter().next().unwrap()).unwrap();
        let mut signature_only = original.clone();
        assert!(signature_only.provide_unlock_signature(signature));
        assert!(signature_only.transactions().last().unwrap().tx.input[0].witness.is_empty());
        variants.push((signature_only, "final_hark_leaf_completion"));
        let mut preimage_only = original;
        assert!(preimage_only.provide_unlock_preimage([7; 32]));
        assert!(preimage_only.transactions().last().unwrap().tx.input[0].witness.is_empty());
        variants.push((preimage_only, "final_hark_leaf_completion"));
        for (native, relation) in variants {
            let request = native_request(&anchor, &native, &complete);
            let proof = verify_contract(&request).unwrap();
            assert_eq!(proof["native_completion_relation"], relation);
            assert_eq!(proof["native_vtxo_sha256"], sha256::Hash::hash(&native.serialize()).to_string());
            assert_eq!(proof["completed_vtxo_sha256"], sha256::Hash::hash(&complete.serialize()).to_string());
            assert_eq!(proof["signed_path_valid"], true);
            assert_eq!(proof["client_owner_verified"], false);
            assert_eq!(proof["native_owner_verified"], false);
            assert_eq!(proof["payment_verified"], false);
        }
    }

    #[test]
    #[cfg(feature = "two-step")]
    fn native_original_refuses_hidden_corrupt_partial_signature() {
        use bitcoin::secp256k1::{Keypair, Message, SecretKey};
        let (anchor, mut original, complete) = native_completion_fixture();
        let key = Keypair::from_secret_key(&ark::SECP, &SecretKey::from_slice(&[5; 32]).unwrap());
        let unrelated = ark::SECP.sign_schnorr_no_aux_rand(&Message::from_digest([99; 32]), &key);
        assert!(original.provide_unlock_signature(unrelated));
        assert!(original.transactions().last().unwrap().tx.input[0].witness.is_empty(),
            "the corrupt known signature is hidden by missing preimage");
        original.validate_unsigned(&anchor).unwrap();
        complete.validate(&anchor).unwrap();
        assert!(verify_contract(&native_request(&anchor, &original, &complete)).is_err());
    }

    #[test]
    #[cfg(feature = "two-step")]
    fn native_original_refuses_corrupt_known_preimage_or_unvalidated_completed_path() {
        let (anchor, original, complete) = native_completion_fixture();
        let mut request = native_request(&anchor, &complete, &complete);
        let mut raw = complete.serialize();
        let marker = [7u8; 32];
        let offsets = raw.windows(marker.len()).enumerate().filter_map(|(i, b)| (b == marker).then_some(i)).collect::<Vec<_>>();
        assert_eq!(offsets.len(), 1, "public synthetic preimage must have a unique encoding position");
        raw[offsets[0]] ^= 1;
        request["native_vtxo"] = json!(encode(raw));
        assert!(verify_contract(&request).is_err());
        let mut request = native_request(&anchor, &original, &complete);
        request["signed_vtxo"] = json!(encode(original.serialize()));
        assert!(verify_contract(&request).is_err(), "native structure cannot supply missing completed signatures");
        let mut foreign_anchor = anchor.clone(); foreign_anchor.lock_time = bitcoin::absolute::LockTime::from_consensus(1);
        let request = native_request(&foreign_anchor, &original, &complete);
        assert!(verify_contract(&request).is_err());
    }

    #[test]
    #[ignore = "requires a private genuine captured native-original/client-Full paired request"]
    #[cfg(feature = "two-step")]
    fn archived_native_original_completion_controls() {
        use std::os::unix::fs::MetadataExt;
        let path = std::env::var_os("BARK_SIM_ACTUAL_NATIVE_COMPLETION_REQUEST")
            .expect("genuine private native/client completion fixture required");
        let before = std::fs::symlink_metadata(&path).unwrap();
        assert!(before.is_file() && !before.file_type().is_symlink() && before.mode() & 0o077 == 0
            && before.nlink() == 1 && before.len() <= 2 * 1024 * 1024);
        let mut file = std::fs::File::open(&path).unwrap();
        let opened = file.metadata().unwrap();
        assert!(before.dev() == opened.dev() && before.ino() == opened.ino() && before.len() == opened.len());
        let mut raw = Vec::new(); file.by_ref().take(2 * 1024 * 1024 + 1).read_to_end(&mut raw).unwrap();
        let opened_after = file.metadata().unwrap(); let after = std::fs::symlink_metadata(&path).unwrap();
        assert!(raw.len() as u64 == before.len() && before.dev() == after.dev() && before.ino() == after.ino()
            && before.mode() == after.mode() && before.uid() == after.uid() && before.nlink() == after.nlink()
            && before.len() == after.len() && before.mtime() == after.mtime() && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime() && before.ctime_nsec() == after.ctime_nsec()
            && opened.dev() == opened_after.dev() && opened.ino() == opened_after.ino() && opened.len() == opened_after.len()
            && opened.mtime() == opened_after.mtime() && opened.mtime_nsec() == opened_after.mtime_nsec()
            && opened.ctime() == opened_after.ctime() && opened.ctime_nsec() == opened_after.ctime_nsec());
        let request: Value = serde_json::from_slice(&raw).unwrap();
        let proof = verify_contract(&request).expect("genuine completed/native representation relation must validate");
        assert!(matches!(proof["native_completion_relation"].as_str(),
            Some("exact_full_equality" | "final_hark_leaf_completion")));
        assert_eq!(proof["signed_path_valid"], true);
        assert_eq!(proof["client_owner_verified"], false);
        assert_eq!(proof["native_owner_verified"], false);
        assert_eq!(proof["payment_verified"], false);
        let mut changed = request.clone(); changed["native_vtxo"] = json!("00");
        assert!(verify_contract(&changed).is_err());
        let mut detached = request; detached["native_completion_relation"] = json!("exact_full_equality");
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
    // Public, unfunded SDK builder. No Core, SQL, ownership or payment credit.
    #[cfg(feature = "two-step")]
    fn allocation_fixture() -> Value {
        use ark::{VtxoPolicy, VtxoRequest};
        use ark::tree::signed::{LeafVtxoCosignContext, LeafVtxoCosignResponse};
        use ark::tree::signed::builder::SignedTreeBuilder;
        use bitcoin::secp256k1::Keypair;
        fn key(byte: u8) -> Keypair {
            Keypair::from_secret_key(&ark::SECP, &bitcoin::secp256k1::SecretKey::from_slice(&[byte; 32]).unwrap())
        }
        let leaf = key(1); let user = key(2); let server = key(3); let cosign = key(4);
        let preimage = [7; 32];
        let requests = [10_000,10_000,20_000,30_000,40_000,50_000].map(|amount| VtxoRequest {
            amount: Amount::from_sat(amount), policy: VtxoPolicy::new_pubkey(leaf.public_key()),
        });
        let builder = SignedTreeBuilder::new(requests.iter().cloned(), user.public_key(), preimage,
            128u32.into(), server.public_key(), cosign.public_key(), 12u16.into()).unwrap();
        let funding = Transaction { version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,input:vec![],output:vec![builder.funding_txout()] };
        let point = OutPoint::new(funding.compute_txid(),0);
        let builder = builder.set_utxo(point).generate_user_nonces(&user);
        let response = SignedTreeBuilder::new_for_cosign(requests.iter().cloned(), user.public_key(), preimage,
            128u32.into(), server.public_key(), cosign.public_key(), 12u16.into(), point,
            builder.user_pub_nonces().to_vec()).unwrap().server_cosign(&cosign);
        builder.verify_cosign_response(&response).unwrap();
        let signed = builder.build_tree(&response,&user).unwrap();
        let raw_tree = signed.serialize_hex();
        let tree = signed.into_cached_tree();
        let outputs = tree.output_vtxos().map(|original| {
            let mut complete = original.clone();
            let (context,request) = LeafVtxoCosignContext::new(&complete,&funding,&leaf).unwrap();
            let response = LeafVtxoCosignResponse::new_cosign(&request,&complete,&funding,&server).unwrap();
            assert!(context.finalize(&mut complete,response));
            assert!(complete.provide_unlock_preimage(preimage));
            complete.validate(&funding).unwrap();
            json!({"signed_vtxo":complete.serialize_hex(),"native_vtxo":original.serialize_hex()})
        }).collect::<Vec<_>>();
        json!({"signed_tree":raw_tree,"anchor_raw":encode(bitcoin::consensus::serialize(&funding)),
            "server_pubkey":server.public_key().to_string(),
            "participation_unlock_hash":sha256::Hash::hash(&preimage).to_string(),"outputs":outputs})
    }

    #[test]
    #[cfg(feature = "two-step")]
    fn allocation_public_builder_verifies_all_leaves_with_duplicate_requests_and_reordering() {
        let mut request = allocation_fixture();
        let proof = verify_contract(&request).unwrap();
        assert_eq!(proof["all_matching_leaf_indices"],json!([0,1,2,3,4,5]));
        assert_eq!(proof["allocations"].as_array().unwrap().len(),6);
        assert_eq!(proof["allocation_sat"],160_000);
        assert_eq!(proof["all_matching_leaves_verified"],true);
        assert_eq!(proof["client_owner_verified"],false);
        assert_eq!(proof["payment_verified"],false);
        request["outputs"].as_array_mut().unwrap().reverse();
        assert_eq!(verify_contract(&request).unwrap(),proof,"allocation is an authenticated set, not caller order");
    }

    #[test]
    #[cfg(feature = "two-step")]
    fn allocation_refuses_omission_duplicate_extra_wrong_hash_and_detached_verdicts() {
        let request = allocation_fixture();
        let mut omitted = request.clone(); omitted["outputs"].as_array_mut().unwrap().pop();
        assert!(verify_contract(&omitted).is_err());
        let mut duplicate = request.clone(); duplicate["outputs"][1] = duplicate["outputs"][0].clone();
        assert!(verify_contract(&duplicate).is_err(),"identical amounts are different authenticated leaf IDs");
        let mut extra = request.clone();let output=extra["outputs"][0].clone();extra["outputs"].as_array_mut().unwrap().push(output);
        assert!(verify_contract(&extra).is_err());
        let mut hash = request.clone();hash["participation_unlock_hash"]=json!(sha256::Hash::hash(&[8;32]).to_string());
        assert!(verify_contract(&hash).is_err());
        for key in ["all_matching_leaves_verified","client_owner_verified","participation_owned"] {
            let mut detached=request.clone();detached[key]=json!(true);assert!(verify_contract(&detached).is_err());
        }
        let mut detached=request;detached["outputs"][0]["leaf_index"]=json!(0);
        assert!(verify_contract(&detached).is_err());
    }

    #[test]
    #[cfg(feature = "two-step")]
    fn allocation_refuses_later_bad_cosignature_missing_extra_signature_and_wrong_allocation() {
        use ark::tree::signed::SignedVtxoTreeSpec;
        use bitcoin::secp256k1::{Keypair,Message,SecretKey};
        let request=allocation_fixture();
        let signed=SignedVtxoTreeSpec::deserialize(&decode_hex(request["signed_tree"].as_str().unwrap()).unwrap()).unwrap();
        assert!(signed.cosign_sigs.len()>1);
        let key=Keypair::from_secret_key(&ark::SECP,&SecretKey::from_slice(&[5;32]).unwrap());
        let unrelated=ark::SECP.sign_schnorr_no_aux_rand(&Message::from_digest([99;32]),&key);
        let mut bad=signed.clone();bad.cosign_sigs[1]=unrelated;
        assert!(bad.clone().with_detected_hashlock_version().is_ok(),"version detection alone is insufficient");
        let mut changed=request.clone();changed["signed_tree"]=json!(bad.serialize_hex());assert!(verify_contract(&changed).is_err());
        let mut bad=signed.clone();bad.cosign_sigs.pop();
        changed["signed_tree"]=json!(bad.serialize_hex());assert!(verify_contract(&changed).is_err());
        let mut bad=signed.clone();bad.cosign_sigs.push(unrelated);
        changed["signed_tree"]=json!(bad.serialize_hex());assert!(verify_contract(&changed).is_err());
        let mut bad=signed;bad.spec.vtxos[0].vtxo.amount+=Amount::from_sat(1);
        changed["signed_tree"]=json!(bad.serialize_hex());assert!(verify_contract(&changed).is_err());
    }

    #[test]
    #[cfg(feature = "two-step")]
    fn allocation_refuses_wrong_anchor_uncompleted_output_and_hidden_corrupt_native_signature() {
        use bitcoin::secp256k1::{Keypair,Message,SecretKey};
        let request=allocation_fixture();
        let mut changed=request.clone();
        let mut anchor:Transaction=bitcoin::consensus::deserialize(&decode_hex(request["anchor_raw"].as_str().unwrap()).unwrap()).unwrap();
        anchor.output[0].value+=Amount::from_sat(1);changed["anchor_raw"]=json!(encode(bitcoin::consensus::serialize(&anchor)));
        assert!(verify_contract(&changed).is_err());
        changed=request.clone();changed["outputs"][0]["signed_vtxo"]=changed["outputs"][0]["native_vtxo"].clone();
        assert!(verify_contract(&changed).is_err(),"unsigned/native-assigned output cannot receive signature credit");
        changed=request;
        let mut native=Vtxo::<Full,ServerVtxoPolicy>::deserialize(&decode_hex(changed["outputs"][0]["native_vtxo"].as_str().unwrap()).unwrap()).unwrap();
        let key=Keypair::from_secret_key(&ark::SECP,&SecretKey::from_slice(&[5;32]).unwrap());
        let unrelated=ark::SECP.sign_schnorr_no_aux_rand(&Message::from_digest([99;32]),&key);
        assert!(native.provide_unlock_signature(unrelated));
        assert!(native.transactions().last().unwrap().tx.input[0].witness.is_empty());
        changed["outputs"][0]["native_vtxo"]=json!(native.serialize_hex());
        assert!(verify_contract(&changed).is_err(),"preserve the existing hidden partial native signature");
        let mut changed=allocation_fixture();
        let mut raw=decode_hex(changed["outputs"][0]["signed_vtxo"].as_str().unwrap()).unwrap();
        let positions=raw.windows(32).enumerate().filter_map(|(i,b)|(b==[7u8;32]).then_some(i)).collect::<Vec<_>>();
        assert_eq!(positions.len(),1);raw[positions[0]]^=1;
        changed["outputs"][0]["native_vtxo"]=json!(encode(raw));
        assert!(verify_contract(&changed).is_err(),"preserve known native preimage, not only visible witness");
    }

    #[test]
    #[ignore = "requires private genuine complete signed-tree and all completed output originals"]
    #[cfg(feature = "two-step")]
    fn archived_round_allocation_all_leaves_controls() {
        use std::os::unix::fs::MetadataExt;
        let path=std::env::var_os("BARK_SIM_ACTUAL_ROUND_ALLOCATION_REQUEST").expect("genuine signed tree prerequisite required");
        let before=std::fs::symlink_metadata(&path).unwrap();
        assert!(before.is_file() && !before.file_type().is_symlink() && before.mode()&0o077==0 && before.nlink()==1 && before.len()<=2*1024*1024);
        let mut file=std::fs::File::open(&path).unwrap();let opened=file.metadata().unwrap();
        assert!(before.dev()==opened.dev() && before.ino()==opened.ino() && before.len()==opened.len());
        let mut raw=Vec::new();file.by_ref().take(2*1024*1024+1).read_to_end(&mut raw).unwrap();
        let opened_after=file.metadata().unwrap();let after=std::fs::symlink_metadata(&path).unwrap();
        assert!(raw.len()as u64==before.len() && before.dev()==after.dev() && before.ino()==after.ino()
            && before.mode()==after.mode() && before.uid()==after.uid() && before.nlink()==after.nlink()
            && before.len()==after.len() && before.mtime()==after.mtime() && before.mtime_nsec()==after.mtime_nsec()
            && before.ctime()==after.ctime() && before.ctime_nsec()==after.ctime_nsec()
            && opened.dev()==opened_after.dev() && opened.ino()==opened_after.ino() && opened.len()==opened_after.len()
            && opened.mtime()==opened_after.mtime() && opened.mtime_nsec()==opened_after.mtime_nsec()
            && opened.ctime()==opened_after.ctime() && opened.ctime_nsec()==opened_after.ctime_nsec());
        let request:Value=serde_json::from_slice(&raw).unwrap();let proof=verify_contract(&request).unwrap();
        assert_eq!(proof["all_matching_leaves_verified"],true);
        assert_eq!(proof["allocations"].as_array().unwrap().len(),request["outputs"].as_array().unwrap().len());
        assert_eq!(proof["client_owner_verified"],false);assert_eq!(proof["payment_verified"],false);
        let mut omitted=request.clone();omitted["outputs"].as_array_mut().unwrap().pop();assert!(verify_contract(&omitted).is_err());
        let mut changed=request;changed["all_matching_leaves_verified"]=json!(true);assert!(verify_contract(&changed).is_err());
    }

    // Only internal tree cosigns are created. No final leaf cosign or preimage
    // is supplied, and no client/wallet/runtime is opened.
    #[cfg(feature = "two-step")]
    fn pending_entitlement_fixture() -> Value {
        use ark::{VtxoPolicy,VtxoRequest};
        use ark::tree::signed::builder::SignedTreeBuilder;
        use bitcoin::secp256k1::Keypair;
        fn key(byte:u8)->Keypair {
            Keypair::from_secret_key(&ark::SECP,&bitcoin::secp256k1::SecretKey::from_slice(&[byte;32]).unwrap())
        }
        let leaf_pubkey=key(1).public_key();let user=key(2);let server=key(3);let cosign=key(4);
        let preimage=[7;32];
        let requests=[10_000,10_000,20_000,30_000,40_000,50_000].map(|amount|VtxoRequest {
            amount:Amount::from_sat(amount),policy:VtxoPolicy::new_pubkey(leaf_pubkey),
        });
        let builder=SignedTreeBuilder::new(requests.iter().cloned(),user.public_key(),preimage,
            128u32.into(),server.public_key(),cosign.public_key(),12u16.into()).unwrap();
        let funding=Transaction {version:bitcoin::transaction::Version::TWO,
            lock_time:bitcoin::absolute::LockTime::ZERO,input:vec![],output:vec![builder.funding_txout()]};
        let point=OutPoint::new(funding.compute_txid(),0);
        let builder=builder.set_utxo(point).generate_user_nonces(&user);
        let response=SignedTreeBuilder::new_for_cosign(requests.iter().cloned(),user.public_key(),preimage,
            128u32.into(),server.public_key(),cosign.public_key(),12u16.into(),point,
            builder.user_pub_nonces().to_vec()).unwrap().server_cosign(&cosign);
        builder.verify_cosign_response(&response).unwrap();
        let signed=builder.build_tree(&response,&user).unwrap();
        let tree=signed.clone().into_cached_tree();
        for native in tree.output_vtxos() {
            native.validate_unsigned(&funding).unwrap();
            assert!(native.validate(&funding).is_err(),"this fixture has no completed client leaf");
        }
        json!({"mode":"pending_entitlement","signed_tree":signed.serialize_hex(),
            "anchor_raw":encode(bitcoin::consensus::serialize(&funding)),"server_pubkey":server.public_key().to_string(),
            "participation_unlock_hash":sha256::Hash::hash(&preimage).to_string()})
    }

    #[test]
    #[cfg(feature = "two-step")]
    fn pending_entitlement_authenticates_all_leaves_without_final_leaf_signature_or_completed_full() {
        let request=pending_entitlement_fixture();
        assert!(request.get("outputs").is_none());
        let proof=verify_contract(&request).unwrap();
        assert_eq!(proof["mode"],"pending_entitlement");
        assert_eq!(proof["all_matching_pending_leaf_indices"],json!([0,1,2,3,4,5]));
        assert_eq!(proof["pending_entitlement_sat"],160_000);
        assert_eq!(proof["pending_allocation_membership_verified"],true);
        assert!(proof.get("all_matching_leaves_verified").is_none());
        assert!(proof.get("allocations").is_none());
        for field in ["signed_leaf_verified","current_spendability_verified","client_owner_verified","retirement_verified","payment_verified"] {
            assert_eq!(proof[field],false);
            for leaf in proof["pending_allocations"].as_array().unwrap() {assert_eq!(leaf[field],false);}
        }
        let leaves=proof["pending_allocations"].as_array().unwrap();
        assert_eq!(leaves[0]["amount_sat"],leaves[1]["amount_sat"]);
        assert_ne!(leaves[0]["id"],leaves[1]["id"],"duplicate requests are distinct allocations");
        for leaf in leaves {
            assert_eq!(leaf["unsigned_path_verified"],true);
            assert!(!leaf["derived_native_path"].as_array().unwrap().is_empty());
            assert!(leaf.get("completed_vtxo_sha256").is_none());
        }
    }

    #[test]
    #[cfg(feature = "two-step")]
    fn pending_entitlement_and_completed_path_modes_refuse_cross_mode_or_detached_inputs() {
        let request=pending_entitlement_fixture();
        assert!(verify_round_allocation(&request).is_err());
        for mode in ["round_allocation","","pending","signed_path"] {
            let mut changed=request.clone();changed["mode"]=json!(mode);assert!(verify_contract(&changed).is_err());
        }
        let mut no_mode=request.clone();no_mode.as_object_mut().unwrap().remove("mode");
        assert!(verify_contract(&no_mode).is_err());
        for field in ["outputs","signed_vtxo","client_owner_verified","signed_leaf_verified","retirement_verified","pending_allocations","all_matching_pending_leaf_indices"] {
            let mut changed=request.clone();changed[field]=json!([]);assert!(verify_contract(&changed).is_err());
        }
        let mut completed=allocation_fixture();completed["mode"]=json!("pending_entitlement");
        assert!(verify_contract(&completed).is_err(),"completed fields must not leak into pending mode");
    }

    #[test]
    #[cfg(feature = "two-step")]
    fn pending_entitlement_refuses_wrong_hash_anchor_server_and_later_corrupt_internal_signature() {
        use ark::tree::signed::SignedVtxoTreeSpec;
        use bitcoin::secp256k1::{Keypair,Message,SecretKey};
        let request=pending_entitlement_fixture();
        let mut changed=request.clone();changed["participation_unlock_hash"]=json!(sha256::Hash::hash(&[8;32]).to_string());
        assert!(verify_contract(&changed).is_err());
        changed=request.clone();changed["server_pubkey"]=json!("wrong-server");assert!(verify_contract(&changed).is_err());
        let mut anchor:Transaction=bitcoin::consensus::deserialize(&decode_hex(request["anchor_raw"].as_str().unwrap()).unwrap()).unwrap();
        anchor.output[0].value+=Amount::from_sat(1);changed=request.clone();changed["anchor_raw"]=json!(encode(bitcoin::consensus::serialize(&anchor)));
        assert!(verify_contract(&changed).is_err());
        let mut signed=SignedVtxoTreeSpec::deserialize(&decode_hex(request["signed_tree"].as_str().unwrap()).unwrap()).unwrap();
        let key=Keypair::from_secret_key(&ark::SECP,&SecretKey::from_slice(&[5;32]).unwrap());
        signed.cosign_sigs[1]=ark::SECP.sign_schnorr_no_aux_rand(&Message::from_digest([99;32]),&key);
        assert!(signed.clone().with_detected_hashlock_version().is_ok());
        changed=request;changed["signed_tree"]=json!(signed.serialize_hex());assert!(verify_contract(&changed).is_err());
    }

    #[test]
    #[cfg(feature = "two-step")]
    fn pending_and_completed_proofs_bind_same_allocation_without_transferring_completion_credit() {
        let completed=allocation_fixture();let complete_proof=verify_contract(&completed).unwrap();
        let mut pending=completed.clone();pending.as_object_mut().unwrap().remove("outputs");pending["mode"]=json!("pending_entitlement");
        let pending_proof=verify_contract(&pending).unwrap();
        assert_eq!(pending_proof["signed_tree_sha256"],complete_proof["signed_tree_sha256"]);
        assert_eq!(pending_proof["anchor_raw_sha256"],complete_proof["anchor_raw_sha256"]);
        assert_eq!(pending_proof["all_matching_pending_leaf_indices"],complete_proof["all_matching_leaf_indices"]);
        assert_eq!(pending_proof["pending_entitlement_sat"],complete_proof["allocation_sat"]);
        for (pending,complete) in pending_proof["pending_allocations"].as_array().unwrap().iter().zip(complete_proof["allocations"].as_array().unwrap()) {
            for field in ["leaf_index","id","amount_sat","user_policy_hex","leaf_spec_sha256","tree_native_vtxo_sha256"] {
                assert_eq!(pending[field],complete[field]);
            }
            assert_eq!(pending["signed_leaf_verified"],false);
            assert!(pending.get("tree_completion_relation").is_none());
        }
        let mut incomplete=completed;incomplete["outputs"][0]["signed_vtxo"]=incomplete["outputs"][0]["native_vtxo"].clone();
        assert!(verify_contract(&incomplete).is_err(),"pending proof never repairs an incomplete completed-path request");
    }

    #[test]
    #[ignore = "requires private genuine signed-tree pending-entitlement context, not synthetic or completed-path verdict"]
    #[cfg(feature = "two-step")]
    fn archived_pending_entitlement_membership_controls() {
        use std::os::unix::fs::MetadataExt;
        let path=std::env::var_os("BARK_SIM_ACTUAL_PENDING_ENTITLEMENT_REQUEST").expect("genuine signed tree prerequisite required");
        let before=std::fs::symlink_metadata(&path).unwrap();
        assert!(before.is_file() && !before.file_type().is_symlink() && before.mode()&0o077==0 && before.nlink()==1 && before.len()<=2*1024*1024);
        let mut file=std::fs::File::open(&path).unwrap();let opened=file.metadata().unwrap();
        assert!(before.dev()==opened.dev() && before.ino()==opened.ino() && before.len()==opened.len());
        let mut raw=Vec::new();file.by_ref().take(2*1024*1024+1).read_to_end(&mut raw).unwrap();
        let opened_after=file.metadata().unwrap();let after=std::fs::symlink_metadata(&path).unwrap();
        assert!(raw.len()as u64==before.len() && before.dev()==after.dev() && before.ino()==after.ino()
            && before.mode()==after.mode() && before.uid()==after.uid() && before.nlink()==after.nlink()
            && before.len()==after.len() && before.mtime()==after.mtime() && before.mtime_nsec()==after.mtime_nsec()
            && before.ctime()==after.ctime() && before.ctime_nsec()==after.ctime_nsec()
            && opened.dev()==opened_after.dev() && opened.ino()==opened_after.ino() && opened.len()==opened_after.len()
            && opened.mtime()==opened_after.mtime() && opened.mtime_nsec()==opened_after.mtime_nsec()
            && opened.ctime()==opened_after.ctime() && opened.ctime_nsec()==opened_after.ctime_nsec());
        let request:Value=serde_json::from_slice(&raw).unwrap();let proof=verify_contract(&request).unwrap();
        assert_eq!(proof["mode"],"pending_entitlement");assert_eq!(proof["pending_allocation_membership_verified"],true);
        assert_eq!(proof["signed_leaf_verified"],false);assert_eq!(proof["retirement_verified"],false);
        assert_eq!(proof["current_spendability_verified"],false);assert_eq!(proof["client_owner_verified"],false);assert_eq!(proof["payment_verified"],false);
        assert!(verify_round_allocation(&request).is_err());
        let mut changed=request;changed["signed_leaf_verified"]=json!(true);assert!(verify_contract(&changed).is_err());
    }

    #[cfg(not(feature = "two-step"))]
    #[test]
    fn new_a_proof_modes_refuse_without_the_two_step_feature() {
        assert!(verify_contract(&fixture()).is_ok(), "legacy proof must remain available");
        for field in ["native_vtxo", "forfeit_raw", "forfeit_unlock_hash", "signed_tree", "mode"] {
            let mut request = fixture();
            request[field] = json!("00");
            assert!(verify_contract(&request).is_err(), "unsupported A mode must refuse");
        }
        assert!(verify_contract(&json!({"mode":"pending_entitlement", "signed_tree":"00",
            "anchor_raw":"00", "server_pubkey":"00", "participation_unlock_hash":"00"})).is_err());
    }

}

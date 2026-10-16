//! Private, offline typed decoder. Input may contain secret witnesses; output never does.
//! This proves SDK path facts only. Current ownership and active-chain funding
//! must be joined independently to the same database observation by the caller.
use anyhow::{Context, Result, ensure};
use ark::vtxo::{Full, Policy};
use ark::{ProtocolEncoding, ServerVtxo, ServerVtxoPolicy, Vtxo, VtxoPolicy};
use bitcoin::{
    Transaction,
    hashes::{Hash, sha256},
    secp256k1::PublicKey,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{io::Read, str::FromStr};

const MAX_INPUT: usize = 8 * 1024 * 1024;
const MAX_BODY: usize = 2 * 1024 * 1024;
const MAX_STEPS: usize = 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: u8,
    kind: String,
    source_encoding: String,
    body_hex: String,
    funding_transaction_hex: String,
    expected_server_pubkey: String,
}

fn decode_hex(text: &str, limit: usize) -> Result<Vec<u8>> {
    ensure!(
        text.len() <= limit * 2
            && text.len() % 2 == 0
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "bounded canonical hexadecimal required"
    );
    Ok((0..text.len())
        .step_by(2)
        .map(|n| u8::from_str_radix(&text[n..n + 2], 16))
        .collect::<std::result::Result<Vec<_>, _>>()?)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn digest(bytes: &[u8]) -> String {
    sha256::Hash::hash(bytes).to_string()
}

fn project<P: Policy + ProtocolEncoding>(
    coin: &Vtxo<Full, P>,
    body: &[u8],
    funding: &Transaction,
    funding_bytes: &[u8],
    encoding: &str,
    expected_server: PublicKey,
    user_pubkey: Option<PublicKey>,
) -> Result<Value> {
    ensure!(coin.serialize() == body, "noncanonical native body");
    ensure!(
        coin.server_pubkey() == expected_server,
        "native server identity differs"
    );
    ensure!(
        coin.chain_anchor().txid == funding.compute_txid(),
        "funding transaction identity differs"
    );
    ensure!(
        usize::from(coin.exit_depth()) <= MAX_STEPS,
        "native path exceeds bound"
    );
    coin.validate_unsigned(funding)
        .context("invalid native geometry")?;
    let signed = coin.validate(funding).is_ok();
    let witness_complete = coin.has_all_witnesses();
    let mut paths = Vec::new();
    let mut witnessed_conditional_steps = 0usize;
    for item in coin.transactions() {
        ensure!(
            paths.len() < MAX_STEPS && item.output_idx < item.tx.output.len(),
            "invalid native path bound"
        );
        // Witness stack content stays private. Native validate checks the exact
        // hashlocked transition; these counters describe only supplied witnesses.
        if item.tx.input.iter().any(|i| i.witness.len() > 1) {
            witnessed_conditional_steps += 1;
        }
        let out = &item.tx.output[item.output_idx];
        paths.push(json!({
            "txid":item.tx.compute_txid().to_string(),
            "wtxid":item.tx.compute_wtxid().to_string(),
            "transaction_sha256":digest(&bitcoin::consensus::serialize(&item.tx)),
            "inputs":item.tx.input.iter().map(|i| i.previous_output.to_string()).collect::<Vec<_>>(),
            "witness_sha256":item.tx.input.iter().map(|i|digest(&bitcoin::consensus::serialize(&i.witness))).collect::<Vec<_>>(),
            "outpoint":format!("{}:{}",item.tx.compute_txid(),item.output_idx),
            "output_index":item.output_idx,"output_amount_sat":out.value.to_sat(),
            "output_script":out.script_pubkey.to_hex_string(),
            "outputs_public":item.tx.output.iter().enumerate().map(|(vout,o)| json!({
                "vout":vout,"value_sat":o.value.to_sat(),"script":o.script_pubkey.to_hex_string()
            })).collect::<Vec<_>>()
        }));
    }
    Ok(json!({
        "schema_version":1,"kind":"native-full-path-proof","source_encoding":encoding,
        "sdk_commit":env!("GIT_HASH"),
        "input_body_sha256":digest(body),"canonical_reencoding_sha256":digest(&coin.serialize()),
        "canonical_reencoding_equal":true,
        "funding_txid":funding.compute_txid().to_string(),"raw_funding_sha256":digest(funding_bytes),
        "id":coin.id().to_string(),"point":coin.point().to_string(),
        "chain_anchor":coin.chain_anchor().to_string(),"amount_sat":coin.amount().to_sat(),
        "expiry_height":coin.expiry_height().to_u32(),"exit_delta":coin.exit_delta().to_u16(),
        "server_pubkey":coin.server_pubkey().to_string(),"user_pubkey":user_pubkey.map(|p|p.to_string()),
        "policy_type":coin.policy_type().to_string(),"policy_hex":hex(&coin.policy().serialize()),
        "ancestor_ids":coin.ancestor_ids().iter().map(|i|i.to_string()).collect::<Vec<_>>(),
        "path_steps":paths.len(),"anchor_only":paths.is_empty(),
        "transitions":paths,"unsigned_path_valid":true,"signed_path_valid":signed,
        "all_native_witnesses_present":witness_complete,
        "witnessed_conditional_steps":witnessed_conditional_steps,
        "total_conditional_steps":null,
        "unresolved":if signed {Vec::<&str>::new()}else{vec!["native_signed_path_not_valid"]},
        "validation_scope":"Offline exact SDK decoding and supplied-funding path validation only; active chain membership, current economic ownership, retirement, pool ownership, paid status and completeness require independent same-observation proofs. No witness bytes or preimages emitted."
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark::test_util::VTXO_VECTORS;

    fn request(coin: &Vtxo<Full>, funding: &Transaction, server_encoding: bool) -> Request {
        Request {
            schema_version: 1,
            kind: "native-full-path-request".into(),
            source_encoding: if server_encoding {
                "ServerVtxoFull"
            } else {
                "VtxoFull"
            }
            .into(),
            body_hex: if server_encoding {
                hex(&ServerVtxo::from(coin.clone()).serialize())
            } else {
                hex(&coin.serialize())
            },
            funding_transaction_hex: hex(&bitcoin::consensus::serialize(funding)),
            expected_server_pubkey: coin.server_pubkey().to_string(),
        }
    }

    #[test]
    fn validates_real_sdk_signed_ordinary_path_and_preserves_exact_identity() {
        let v = &*VTXO_VECTORS;
        let p = verify(request(&v.arkoor2_vtxo, &v.anchor_tx, false)).unwrap();
        assert_eq!(p["id"], v.arkoor2_vtxo.id().to_string());
        assert_eq!(p["amount_sat"], v.arkoor2_vtxo.amount().to_sat());
        assert_eq!(p["input_body_sha256"], digest(&v.arkoor2_vtxo.serialize()));
        assert_eq!(p["signed_path_valid"], true);
        assert_eq!(p["unsigned_path_valid"], true);
        assert!(!p["transitions"].as_array().unwrap().is_empty());
        for field in ["complete", "ready", "paid", "current_owner"] {
            assert!(p.get(field).is_none());
        }
    }

    #[test]
    fn server_and_pool_encodings_are_explicit_and_native_decoded() {
        let v = &*VTXO_VECTORS;
        for server in [false, true] {
            let p = verify(request(&v.board_vtxo, &v.anchor_tx, server)).unwrap();
            assert_eq!(p["id"], v.board_vtxo.id().to_string());
            assert_eq!(
                p["source_encoding"],
                if server { "ServerVtxoFull" } else { "VtxoFull" }
            );
            assert_eq!(p["canonical_reencoding_equal"], true);
            assert_eq!(p["signed_path_valid"], true);
        }
        let mut r = request(&v.board_vtxo, &v.anchor_tx, false);
        r.source_encoding = "unknown-body-prefix".into();
        assert!(verify(r).is_err());
    }

    #[test]
    fn corrupted_signature_is_not_promoted_from_valid_geometry() {
        let v = &*VTXO_VECTORS;
        let mut coin = v.arkoor2_vtxo.clone();
        coin.invalidate_final_sig();
        let p = verify(request(&coin, &v.anchor_tx, false)).unwrap();
        assert_eq!(p["unsigned_path_valid"], true);
        assert_eq!(p["signed_path_valid"], false);
        assert_eq!(p["unresolved"], json!(["native_signed_path_not_valid"]));
    }

    #[test]
    fn identical_outputs_from_another_funding_transaction_are_refused() {
        let v = &*VTXO_VECTORS;
        let mut funding = v.anchor_tx.clone();
        funding.lock_time = bitcoin::absolute::LockTime::from_consensus(12345);
        assert_eq!(funding.output, v.anchor_tx.output);
        assert_ne!(funding.compute_txid(), v.anchor_tx.compute_txid());
        assert!(verify(request(&v.board_vtxo, &funding, false)).is_err());
    }

    #[test]
    fn server_key_and_canonical_body_are_bound() {
        let v = &*VTXO_VECTORS;
        let mut r = request(&v.board_vtxo, &v.anchor_tx, false);
        r.expected_server_pubkey = v.board_vtxo.user_pubkey().to_string();
        assert!(verify(r).is_err());
        let mut r = request(&v.board_vtxo, &v.anchor_tx, false);
        r.body_hex.push_str("00");
        assert!(verify(r).is_err());
    }

    #[test]
    fn secret_bearing_sdk_round_path_has_only_safe_projection() {
        let v = &*VTXO_VECTORS;
        let p = verify(request(&v.round2_vtxo, &v.round_tx, true)).unwrap();
        assert_eq!(p["signed_path_valid"], true);
        let projected = p.to_string();
        assert!(p.get("body_hex").is_none());
        assert!(p.get("raw_transaction").is_none());
        for item in v.round2_vtxo.transactions() {
            for input in &item.tx.input {
                for witness in input
                    .witness
                    .iter()
                    .filter(|w| w.len() == 32 || w.len() == 64)
                {
                    assert!(
                        !projected.contains(&hex(witness)),
                        "private witness appeared in safe output"
                    );
                }
            }
        }
        assert!(p["total_conditional_steps"].is_null());
    }

    #[test]
    fn actual_hashlocked_leaf_requires_preimage_and_never_discloses_it() {
        use ark::tree::signed::{HashlockVersion, LeafVtxoCosignContext, LeafVtxoCosignResponse};
        use bitcoin::secp256k1::Keypair;
        let key = |n| Keypair::from_seckey_slice(&ark::SECP, &[n; 32]).unwrap();
        let (user, cosigner, server, server_cosigner) = (key(11), key(12), key(13), key(14));
        let preimage = sha256::Hash::hash(b"public deterministic native-full-proof test fixture")
            .to_byte_array();
        let unlock_hash = sha256::Hash::hash(&preimage);
        let outputs = (0..2).map(|_| ark::VtxoRequest {
            amount: bitcoin::Amount::from_sat(10_000),
            policy: VtxoPolicy::new_pubkey(user.public_key()),
        });
        let (tree, funding) = ark::test_util::build_signed_tree(
            HashlockVersion::V1,
            outputs,
            &cosigner,
            &server,
            &server_cosigner,
            unlock_hash,
        );
        let mut coin = tree.into_cached_tree().build_vtxo(0);
        let (context, request) = LeafVtxoCosignContext::new(&coin, &funding, &user).unwrap();
        let response =
            LeafVtxoCosignResponse::new_cosign(&request, &coin, &funding, &server).unwrap();
        assert!(context.finalize(&mut coin, response));
        let missing = verify(self::request(&coin, &funding, true)).unwrap();
        assert_eq!(missing["unsigned_path_valid"], true);
        assert_eq!(missing["signed_path_valid"], false);
        assert_eq!(missing["all_native_witnesses_present"], false);
        assert!(coin.provide_unlock_preimage(preimage));
        let complete = verify(self::request(&coin, &funding, true)).unwrap();
        assert_eq!(complete["signed_path_valid"], true);
        assert_eq!(complete["all_native_witnesses_present"], true);
        assert!(complete["witnessed_conditional_steps"].as_u64().unwrap() > 0);
        assert!(!complete.to_string().contains(&hex(&preimage)));
    }

    #[test]
    fn structured_request_refuses_duplicate_unknown_and_unbounded_encoding() {
        let prefix = r#"{"schema_version":1,"schema_version":1,"kind":"native-full-path-request","source_encoding":"VtxoFull","body_hex":"","funding_transaction_hex":"","expected_server_pubkey":""}"#;
        assert!(serde_json::from_str::<Request>(prefix).is_err());
        assert!(serde_json::from_value::<Request>(json!({"schema_version":1,"kind":"native-full-path-request","source_encoding":"VtxoFull","body_hex":"","funding_transaction_hex":"","expected_server_pubkey":"","complete":true})).is_err());
        assert!(decode_hex("AA", MAX_BODY).is_err());
        assert!(decode_hex("0", MAX_BODY).is_err());
        assert!(decode_hex("00", 0).is_err());
    }
}

fn verify(request: Request) -> Result<Value> {
    ensure!(
        request.schema_version == 1 && request.kind == "native-full-path-request",
        "wrong native proof request"
    );
    let body = decode_hex(&request.body_hex, MAX_BODY)?;
    let funding_bytes = decode_hex(&request.funding_transaction_hex, MAX_BODY)?;
    let funding: Transaction = bitcoin::consensus::deserialize(&funding_bytes)?;
    ensure!(
        bitcoin::consensus::serialize(&funding) == funding_bytes,
        "noncanonical funding transaction"
    );
    let server = PublicKey::from_str(&request.expected_server_pubkey)?;
    ensure!(
        server.to_string() == request.expected_server_pubkey,
        "noncanonical server key"
    );
    match request.source_encoding.as_str() {
        "ServerVtxoFull" => {
            let coin = ServerVtxo::<Full>::deserialize(&body)?;
            let user = match coin.policy() {
                ServerVtxoPolicy::User(p) => Some(p.user_pubkey()),
                _ => None,
            };
            project(
                &coin,
                &body,
                &funding,
                &funding_bytes,
                &request.source_encoding,
                server,
                user,
            )
        }
        "VtxoFull" => {
            let coin = Vtxo::<Full, VtxoPolicy>::deserialize(&body)?;
            let user = coin.user_pubkey();
            project(
                &coin,
                &body,
                &funding,
                &funding_bytes,
                &request.source_encoding,
                server,
                Some(user),
            )
        }
        _ => anyhow::bail!("explicit native source encoding required"),
    }
}

fn main() {
    let result = (|| -> Result<Value> {
        ensure!(std::env::args_os().len() == 1, "stdin-only private proof");
        let mut raw = Vec::new();
        std::io::stdin()
            .take((MAX_INPUT + 1) as u64)
            .read_to_end(&mut raw)?;
        ensure!(raw.len() <= MAX_INPUT, "private proof input exceeds bound");
        verify(serde_json::from_slice(&raw)?)
    })();
    match result {
        Ok(value) => {
            let raw = value.to_string();
            if raw.len() > MAX_INPUT {
                std::process::exit(1);
            }
            println!("{raw}");
        }
        Err(_) => {
            eprintln!("native full proof unavailable; no money state changed");
            std::process::exit(1);
        }
    }
}

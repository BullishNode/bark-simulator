//! Independent public protocol/binding proof, never an original wallet/key read.
//! Args Core URL, private cookie path, pinned server key; stdin signed hex or JSON.
use anyhow::{Context, Result, ensure};
use ark::{
    ProtocolEncoding, Vtxo,
    fallback::{AccountChild, FallbackRecord},
    vtxo::Full,
};
use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoin::{Network, ScriptBuf, constants::genesis_block, secp256k1::PublicKey};
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
    ensure!(
        request.get("key_link_attestation").is_none(),
        "legacy signatures are not account-child evidence"
    );
    let fields = b.as_object().context("missing immutable binding")?;
    ensure!(
        fields.keys().all(|key| matches!(
            key.as_str(),
            "mailbox_pk" | "fallback_record" | "spk" | "account_xpub"
        )),
        "unexpected mutable or legacy binding field"
    );
    let mailbox = PublicKey::from_str(b["mailbox_pk"].as_str().context("missing mailbox")?)?;
    let encoded = hex(b["fallback_record"]
        .as_str()
        .context("missing canonical full-field record")?)?;
    let record = FallbackRecord::deserialize(&encoded)?;
    ensure!(record.serialize() == encoded, "noncanonical record");
    record.verify(network, mailbox)?;
    if let Some(script) = b.get("spk") {
        ensure!(
            script.as_str() == Some(record.spk.to_hex_string().as_str()),
            "record script differs from source declaration"
        );
    }
    if let Some(account) = b.get("account_xpub") {
        ensure!(
            account.as_str() == Some(record.account_xpub.to_string().as_str()),
            "record account differs from source declaration"
        );
    }
    let child_index = u32::try_from(
        request["child_index"]
            .as_u64()
            .context("missing ordinary account child")?,
    )?;
    let child = AccountChild::new(mailbox, child_index)?;
    child.verify_pubkey(&record.account_xpub, coin_pk)?;
    let stored_admission = request["origin_kind"].as_str() == Some("trusted_server_admission");
    ensure!(
        !stored_admission || request.get("signed_vtxo").is_none(),
        "a database admission reference cannot replace original funded-coin provenance"
    );
    let original_blinded = if stored_admission {
        ensure!(
            request.get("blinded_mailbox_id").is_none(),
            "server admission must not fabricate original B"
        );
        Value::Null
    } else {
        let original = request["blinded_mailbox_id"]
            .as_str()
            .context("missing original blinded mailbox")?;
        ensure!(original.len() == 66, "compressed blinded mailbox required");
        let blinded = PublicKey::from_str(original)?;
        ensure!(
            blinded.to_string() == original,
            "canonical blinded mailbox encoding required"
        );
        Value::String(original.to_owned())
    };
    Ok(
        json!({"mailbox_pk":mailbox.to_string(),"spk":record.spk.to_hex_string(),
        "account_xpub":record.account_xpub.to_string(),"fallback_record":b["fallback_record"],
        "child_index":child_index,"policy_pubkey_full":coin_pk.to_string(),"blinded_mailbox_id":original_blinded,
        "record_signature_valid":true,"account_child_verified":true,"origin_kind":if stored_admission {"trusted_server_admission"}else{"original_client_hint"},
        "validation_scope":if stored_admission {"record signatures and exact full account child; supplied trusted DB mailbox/index must be checked against the consistent bridge separately; no original B or funded coin asserted"}else{"both immutable record signatures and exact full compressed account child verified; original B retained but not publicly unblinded; trusted server admission MB/index, seed/index0 ownership, arbitration and settlement remain separate"}}),
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
                "validation_scope":"public account-child and immutable full-field record verification; no funded coin, server admission or backing asserted"})
            );
            return Ok(());
        }
    }
    let encoded = hex(if let Some(ref r) = request {
        r["signed_vtxo"].as_str().context("missing signed proof")?
    } else {
        raw
    })?;
    let public_projection=encoded.first()==Some(&b'{');
    let (coin, path, ancestor_ids, conditional_steps) = if public_projection {
        let projection:Value=serde_json::from_slice(&encoded)?;
        let bare=Vtxo::<ark::vtxo::Bare>::deserialize(&hex(projection["bare_vtxo"].as_str().context("bare projection absent")?)?)?;
        let funding=client.get_raw_transaction(&bare.chain_anchor().txid,None)?;
        let verified=bark_sim_driver::public_coin::verify(&encoded,&funding)?;
        (verified.coin,verified.path,verified.ancestor_ids,verified.conditional_steps)
    } else {
        // Historical ordinary proofs remain independently readable. A full
        // hashlocked serialization is not an allowed public journal format.
        let full=Vtxo::<Full>::deserialize(&encoded)?;
        ensure!(full.transactions().all(|item| item.tx.input.iter().all(|i|i.witness.len()==1)),
            "secret-bearing or unfinished full proof must use the public projection");
        let funding=client.get_raw_transaction(&full.chain_anchor().txid,None)?;
        full.validate(&funding).context("signed path invalid")?;
        let ancestors=full.ancestor_ids().iter().map(|id|id.to_string()).collect();
        let path=full.transactions().map(|item|json!({"txid":item.tx.compute_txid().to_string(),"output_index":item.output_idx,
            "inputs":item.tx.input.iter().map(|i|i.previous_output.to_string()).collect::<Vec<_>>(),
            "output_amount_sat":item.tx.output[item.output_idx].value.to_sat(),"output_script":item.tx.output[item.output_idx].script_pubkey.to_hex_string()})).collect();
        (full.into_bare(),path,ancestors,0)
    };
    ensure!(coin.server_pubkey().to_string()==args[3],"server key mismatch");
    let bound=if let Some(ref r)=request { binding(r,coin.user_pubkey(),network)? } else {Value::Null};
    let anchor=coin.chain_anchor();
    let confirmations=client.get_raw_transaction_info(&anchor.txid,None)?.confirmations.unwrap_or(0);
    ensure!(confirmations>0,"unconfirmed backing anchor");
    let output = serde_json::to_string(
        &json!({"id":coin.id().to_string(),"amount_sat":coin.amount().to_sat(),"user_pubkey":coin.user_pubkey().to_string(),
      "server_pubkey":coin.server_pubkey().to_string(),"expiry_height":coin.expiry_height().to_u32(),"chain_anchor":anchor.to_string(),
      "anchor_confirmations":confirmations,"authorization_path_valid":true,"signed_path_valid":conditional_steps==0,
      "hashlock_satisfaction_disclosed":conditional_steps==0,"conditional_steps":conditional_steps,
      "proof_encoding":if public_projection {"ark-public-authorization-v1"} else {"historical-full-vtxo"},"genesis":genesis.to_string(),"binding":bound,
      "ancestor_ids":ancestor_ids,"path":path,
      "validation_scope":"exact public path signature authority, committed hashlock script if present, account-child/immutable record and confirmed anchor; omitted hashlock satisfaction, current spend arbitration and seed recovery are separate"}),
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
    use bitcoin::bip32::{ChildNumber, Xpriv};
    use bitcoin::secp256k1::Keypair;

    fn fixture() -> (Value, PublicKey) {
        let account = Xpriv::new_master(Network::Regtest, &[1u8; 32]).unwrap();
        let coin = account
            .derive_priv(&ark::SECP, &[ChildNumber::from_normal_idx(25).unwrap()])
            .unwrap()
            .to_keypair(&ark::SECP);
        let mailbox = Keypair::from_seckey_slice(&ark::SECP, &[2u8; 32]).unwrap();
        let script =
            ScriptBuf::from_bytes(hex("00141111111111111111111111111111111111111111").unwrap());
        let encode = |v: Vec<u8>| v.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let full_record =
            FallbackRecord::new(Network::Regtest, script.clone(), &account, &mailbox).unwrap();
        (
            json!({"binding":{"mailbox_pk":mailbox.public_key().to_string(),"fallback_record":encode(full_record.serialize())},"child_index":25,"blinded_mailbox_id":coin.public_key().to_string()}),
            coin.public_key(),
        )
    }
    #[test]
    fn validates_immutable_record_and_exact_account_child() {
        let (r, c) = fixture();
        let valid = binding(&r, c, Network::Regtest).unwrap();
        assert_eq!(valid["account_child_verified"], true);
        assert!(valid.get("key_link_signature_valid").is_none());
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
    fn rejects_tampered_record_and_missing_or_bad_hint() {
        let (r, c) = fixture();
        let mut bad = r.clone();
        bad["binding"]["fallback_record"] = json!("00".repeat(208));
        assert!(binding(&bad, c, Network::Regtest).is_err());
        let mut bad = r.clone();
        bad["blinded_mailbox_id"] = json!("00".repeat(33));
        assert!(binding(&bad, c, Network::Regtest).is_err());
        let mut bad = r.clone();
        bad.as_object_mut().unwrap().remove("child_index");
        assert!(binding(&bad, c, Network::Regtest).is_err());
        assert!(binding(&json!({}), c, Network::Regtest).is_err());
    }
    #[test]
    fn stored_admission_never_fabricates_client_blinding_or_funded_coin_proof() {
        let (mut request, coin) = fixture();
        request["origin_kind"] = json!("trusted_server_admission");
        assert!(binding(&request, coin, Network::Regtest).is_err());
        request
            .as_object_mut()
            .unwrap()
            .remove("blinded_mailbox_id");
        let proof = binding(&request, coin, Network::Regtest).unwrap();
        assert!(proof["blinded_mailbox_id"].is_null());
        assert_eq!(proof["origin_kind"], "trusted_server_admission");
        request["signed_vtxo"] = json!("aa");
        assert!(binding(&request, coin, Network::Regtest).is_err());
    }
    #[test]
    fn rejects_wrong_registered_account_child() {
        let (mut request, coin) = fixture();
        request["child_index"] = json!(26);
        assert!(
            binding(&request, coin, Network::Regtest).is_err(),
            "a valid old coin signature cannot replace exact account-child derivation"
        );
    }
    #[test]
    fn rejects_hardened_origin_hint() {
        let (mut request, coin) = fixture();
        request["child_index"] = json!(1u64 << 31);
        assert!(
            binding(&request, coin, Network::Regtest).is_err(),
            "hardened child hints must be refused"
        );
    }
    #[test]
    fn rejects_negated_full_policy_point() {
        let (request, coin) = fixture();
        assert!(
            binding(&request, coin.negate(&ark::SECP), Network::Regtest).is_err(),
            "registered child must match the full compressed policy point"
        );
    }

    #[test]
    fn rejects_other_valid_account_record_and_a_changed_record_signature() {
        let (r, coin) = fixture();
        let mailbox = Keypair::from_seckey_slice(&ark::SECP, &[2u8; 32]).unwrap();
        let other = Xpriv::new_master(Network::Regtest, &[3u8; 32]).unwrap();
        let original = FallbackRecord::deserialize(
            &hex(r["binding"]["fallback_record"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let other_record =
            FallbackRecord::new(Network::Regtest, original.spk, &other, &mailbox).unwrap();
        let mut bad = r.clone();
        bad["binding"]["fallback_record"] = json!(
            other_record
                .serialize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        assert!(binding(&bad, coin, Network::Regtest).is_err());
        let mut bad = r;
        let mut bytes = hex(bad["binding"]["fallback_record"].as_str().unwrap()).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        bad["binding"]["fallback_record"] =
            json!(bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
        assert!(binding(&bad, coin, Network::Regtest).is_err());
    }
    #[test]
    fn accepts_sparse_child_and_preserves_blinded_source_without_claiming_unblinding() {
        let (mut r, _) = fixture();
        let account = Xpriv::new_master(Network::Regtest, &[1u8; 32]).unwrap();
        let key = account
            .derive_priv(&ark::SECP, &[ChildNumber::from_normal_idx(50).unwrap()])
            .unwrap()
            .to_keypair(&ark::SECP);
        r["child_index"] = json!(50);
        let output = binding(&r, key.public_key(), Network::Regtest).unwrap();
        assert_eq!(output["child_index"], 50);
        assert_eq!(output["blinded_mailbox_id"], r["blinded_mailbox_id"]);
        assert!(
            output["validation_scope"]
                .as_str()
                .unwrap()
                .contains("not publicly unblinded")
        );
    }
    #[test]
    fn generic_registered_standard_script_does_not_assert_seed_ownership() {
        let (mut r, coin) = fixture();
        let account = Xpriv::new_master(Network::Regtest, &[1u8; 32]).unwrap();
        let mailbox = Keypair::from_seckey_slice(&ark::SECP, &[2u8; 32]).unwrap();
        let script = ScriptBuf::from_bytes(
            hex("76a914111111111111111111111111111111111111111188ac").unwrap(),
        );
        let record =
            FallbackRecord::new(Network::Regtest, script.clone(), &account, &mailbox).unwrap();
        r["binding"]["fallback_record"] = json!(
            record
                .serialize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        assert_eq!(
            binding(&r, coin, Network::Regtest).unwrap()["spk"],
            script.to_hex_string()
        );
        r["binding"]["spk"] = json!("00141111111111111111111111111111111111111111");
        assert!(binding(&r, coin, Network::Regtest).is_err());
    }
}

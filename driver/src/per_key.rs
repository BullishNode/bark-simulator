//! Independent C binding parser/verifier and canonical SDK evidence export.
//! No index derives ownership; no wallet or secret is opened by the verifier.
use anyhow::{Context, Result, ensure};
use ark::ProtocolEncoding;
use bitcoin::{Network, ScriptBuf};
use bitcoin::constants::ChainHash;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{Message, PublicKey, schnorr};
use serde_json::{Value, json};
use std::str::FromStr;

const RECORD_DOMAIN: &[u8; 32] = b"Ark expiry per-key record v1    ";
const LINK_DOMAIN: &[u8; 32] = b"Ark expiry per-key link v1      ";

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b|format!("{b:02x}")).collect() }
fn decode(value: &Value) -> Result<Vec<u8>> {
    let raw = value.as_str().context("canonical public hex required")?;
    ensure!(raw.len() <= 256 && raw.len()%2==0 && raw.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "bounded lowercase public encoding required");
    (0..raw.len()).step_by(2).map(|i|u8::from_str_radix(&raw[i..i+2],16).map_err(Into::into)).collect()
}

pub fn verify_binding(request: &Value, coin: PublicKey, network: Network) -> Result<Value> {
    ensure!(request.get("child_index").is_none() && request.get("blinded_mailbox_id").is_none(),
        "account origin is not C per-key proof");
    let binding = request["binding"].as_object().context("immutable C binding required")?;
    ensure!(binding.len()==3 && binding.keys().all(|k|matches!(k.as_str(),"mailbox_pk"|"spk"|"fallback_record")),
        "exact immutable per-key fields required");
    let mailbox = PublicKey::from_str(binding["mailbox_pk"].as_str().context("mailbox required")?)?;
    ensure!(binding["mailbox_pk"].as_str()==Some(mailbox.to_string().as_str()), "canonical mailbox required");
    let record = decode(&binding["fallback_record"])?;
    // Standard scripts are at most42 bytes, so canonical CompactSize is one byte.
    ensure!(record.len()>=2 && record[0]==4 && (22..=42).contains(&record[1]), "C V4 record required");
    let length = usize::from(record[1]);
    ensure!(record.len()==2+length+64,"truncated/trailing record bytes refused");
    let script = ScriptBuf::from_bytes(record[2..2+length].to_vec());
    ensure!(script.is_p2pkh() || script.is_p2sh() || script.is_p2wpkh() || script.is_p2wsh() || script.is_p2tr(),
        "unsupported standard payout script");
    ensure!(binding["spk"].as_str()==Some(script.to_hex_string().as_str()),"record destination differs");
    let chain = ChainHash::using_genesis_block_const(network);
    let mut record_preimage = Vec::new();
    record_preimage.extend_from_slice(RECORD_DOMAIN);
    record_preimage.extend_from_slice(chain.as_bytes());
    record_preimage.extend_from_slice(&mailbox.serialize());
    record_preimage.push(record[1]);
    record_preimage.extend_from_slice(script.as_bytes());
    let record_digest = sha256::Hash::hash(&record_preimage).to_byte_array();
    ark::SECP.verify_schnorr(&schnorr::Signature::from_slice(&record[2+length..])?,
        &Message::from_digest(record_digest),&mailbox.x_only_public_key().0)?;
    let link = decode(&request["key_link_attestation"])?;
    ensure!(matches!(link.len(),99|103) && link[0]==1,"C V1 key link required");
    ensure!(PublicKey::from_slice(&link[1..34])?==coin,"link is for a different full compressed coin key");
    let (index, signature_offset) = match (link[34],link.len()) {
        (0,99) => (None,35),
        (1,103) => {
            let value = u32::from_le_bytes(link[35..39].try_into()?);
            ensure!(value<1<<31,"hardened recovery metadata refused");
            (Some(value),39)
        },
        _ => anyhow::bail!("noncanonical optional recovery metadata"),
    };
    let mut link_preimage = Vec::new();
    link_preimage.extend_from_slice(LINK_DOMAIN);
    link_preimage.extend_from_slice(&record_digest);
    link_preimage.extend_from_slice(&coin.serialize());
    link_preimage.extend_from_slice(&link[34..signature_offset]);
    let digest = sha256::Hash::hash(&link_preimage).to_byte_array();
    ark::SECP.verify_schnorr(&schnorr::Signature::from_slice(&link[signature_offset..])?,
        &Message::from_digest(digest),&coin.x_only_public_key().0)?;
    Ok(json!({"mailbox_pk":mailbox.to_string(),"spk":script.to_hex_string(),
        "fallback_record":hex(&record),"record_version":4,"key_link_version":1,
        "key_link_attestation":hex(&link),"recovery_index":index,"policy_pubkey_full":coin.to_string(),
        "record_signature_valid":true,"key_link_signature_valid":true,
        "validation_scope":"independent exact V4/V1 BIP340 signatures, chain and full keys; index is signed recovery metadata only; current admission, economic ownership, payment and recovery remain separate"}))
}

pub async fn wallet_binding(wallet: &bark::Wallet) -> Result<Value> {
    let record = wallet.fallback_destination().await?;
    let mailbox = wallet.mailbox_identifier().as_pubkey();
    record.verify(wallet.network().await?,mailbox)?;
    Ok(json!({"mailbox_pk":mailbox.to_string(),"spk":record.spk.to_hex_string(),
        "fallback_record":hex(&record.serialize())}))
}

pub async fn wallet_origin(wallet: &bark::Wallet, coin: PublicKey) -> Result<Value> {
    // This accessor authenticates retained server acknowledgement; never
    // regenerate a signature and pretend that it proves server admission.
    let link = wallet.fallback_key_link(coin).await?;
    ensure!(link.user_pubkey==coin,"retained acknowledgement belongs to another key");
    let binding = wallet_binding(wallet).await?;
    let request = json!({"user_pubkey":coin.to_string(),"key_link_attestation":hex(&link.serialize()),"binding":binding});
    verify_binding(&request,coin,wallet.network().await?)?;
    Ok(request)
}

pub async fn fresh_synced_prefix(wallet: &bark::Wallet) -> Result<Value> {
    // Fresh pilot only, after full sync. The independent source collector also
    // compares EVERY actual public SQLite key row, detecting any extra/hole.
    let (_, next_index) = wallet.peek_next_keypair().await?;
    let last_issued = next_index.checked_sub(1).context("missing reserved authentication key")?;
    let maximum = next_index.checked_add(49).context("C pilot key bound overflow")?;
    ensure!(maximum < 128,"fresh C pilot retained-key prefix exceeds bound");
    let mut rows = Vec::new();
    for index in 0..=maximum {
        let key = wallet.peek_keypair(index).await?.public_key();
        rows.push(json!({"native_index":index,"origin":wallet_origin(wallet,key).await?}));
    }
    Ok(json!({"schema_version":1,"scope":"fresh_synced_native_prefix",
        "last_issued_index":last_issued,"maximum_index":maximum,
        "binding":wallet_binding(wallet).await?,"rows":rows}))
}

#[cfg(test)]
mod tests {
    use super::*;
    // Independently generated public BIP340 vectors. Index50 is synthetic
    // metadata, not a claim that this fixed key derives at native index50.
    fn fixture() -> (Value, PublicKey) {
        let key = PublicKey::from_str("03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb").unwrap();
        (json!({"user_pubkey":key.to_string(),
            "binding":{"mailbox_pk":"025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc",
                "spk":"00141111111111111111111111111111111111111111",
                "fallback_record":"04160014111111111111111111111111111111111111111198168e8bd79a572fe39e84a5cb7d722492284d73e918d182876c27b03ff7023255ad2b6710d8eb4cc7610fbe32fa85fb35699f3056520ab34bdfe2a2d8d5daa4"},
            "key_link_attestation":"0103774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb0132000000bdde1c69e6731b6145a0b6bb74cd1b62416dce6d0896582dcdffa60fa7247c5c3dc37e4ca84ab3423d640a36f615a0f9106d67e9f0f4d73d46e11f800106642c"}),key)
    }
    #[test]
    fn independent_reference_signatures_bind_full_key_and_optional_index() {
        let (request,key)=fixture();
        let checked=verify_binding(&request,key,Network::Regtest).unwrap();
        assert_eq!(checked["recovery_index"],50);
        assert_eq!(checked["policy_pubkey_full"],key.to_string());
        assert_eq!(checked["key_link_signature_valid"],true);
        assert!(checked.get("account_xpub").is_none());
        assert!(checked.get("account_child_verified").is_none());
    }
    #[test]
    fn every_record_and_link_byte_mutation_is_rejected() {
        let (request,key)=fixture();
        for field in ["fallback_record","key_link_attestation"] {
            let original=if field=="fallback_record" {decode(&request["binding"][field]).unwrap()} else {decode(&request[field]).unwrap()};
            for offset in 0..original.len() {
                let mut bytes=original.clone();bytes[offset]^=1;
                let mut changed=request.clone();
                if field=="fallback_record" {changed["binding"][field]=json!(hex(&bytes));}
                else {changed[field]=json!(hex(&bytes));}
                assert!(verify_binding(&changed,key,Network::Regtest).is_err(),"{field} byte{offset}");
            }
        }
    }
    #[test]
    fn wrong_chain_full_key_parity_and_old_account_contract_refuse() {
        let (request,key)=fixture();
        assert!(verify_binding(&request,key,Network::Signet).is_err());
        let mut negated=key.serialize();negated[0]^=1;
        let other=PublicKey::from_slice(&negated).unwrap();
        let mut changed=request.clone();let mut link=decode(&request["key_link_attestation"]).unwrap();link[1]^=1;
        changed["key_link_attestation"]=json!(hex(&link));
        assert!(verify_binding(&changed,other,Network::Regtest).is_err());
        for field in ["account_xpub","seq"] {
            let mut changed=request.clone();changed["binding"][field]=json!("old");
            assert!(verify_binding(&changed,key,Network::Regtest).is_err());
        }
        let mut changed=request.clone();changed["child_index"]=json!(50);
        assert!(verify_binding(&changed,key,Network::Regtest).is_err());
    }
    #[test]
    fn truncated_trailing_noncanonical_or_hardened_metadata_refuses() {
        let (request,key)=fixture();
        let original=decode(&request["key_link_attestation"]).unwrap();
        for mutation in 0..4 {
            let mut bytes=original.clone();
            match mutation {0=>{bytes.pop();},1=>bytes.push(0),2=>bytes[34]=2,_=>bytes[38]|=128};
            let mut changed=request.clone();changed["key_link_attestation"]=json!(hex(&bytes));
            assert!(verify_binding(&changed,key,Network::Regtest).is_err());
        }
    }
}

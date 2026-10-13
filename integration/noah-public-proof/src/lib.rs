//! Offline public protocol checks. No wallet, RPC or backend transport.
use anyhow::{Context,Result,ensure,anyhow};
use bitcoin::{Network,hashes::{Hash,sha256},secp256k1::{Message,PublicKey,Secp256k1,ecdsa::Signature}};
use lightning_invoice::Bolt11Invoice;
use serde::Deserialize;
use serde_json::{Value,json};
use std::str::FromStr;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvoicePolicy {
    pub invoice:String,
    pub amount_msat:u64,
    pub metadata:String,
    pub network:String,
    pub now:u64,
}

pub fn validate_invoice(policy:&InvoicePolicy)->Result<Value> {
    ensure!(policy.invoice.len()<=65536 && policy.metadata.len()<=65536,"public invoice/metadata exceeds bound");
    let network=Network::from_str(&policy.network)?;
    ensure!(matches!(network,Network::Signet|Network::Regtest),"only owned signet/regtest invoice checks permitted");
    let invoice=Bolt11Invoice::from_str(&policy.invoice).map_err(|_|anyhow!("invalid BOLT11 syntax/semantics/signature"))?;
    invoice.check_signature().map_err(|_|anyhow!("invalid BOLT11 signature"))?;
    ensure!(invoice.network()==network,"invoice network mismatch");
    ensure!(policy.amount_msat>=1000 && policy.amount_msat%1000==0 && invoice.amount_milli_satoshis()==Some(policy.amount_msat),"invoice amount mismatch");
    let expiry=invoice.expires_at().context("invoice expiry overflow")?.as_secs();
    ensure!(expiry>policy.now,"invoice expired");
    ensure!(invoice.duration_since_epoch().as_secs()<=policy.now.saturating_add(30),"invoice issue timestamp is in the future");
    let metadata_hash=sha256::Hash::hash(policy.metadata.as_bytes());
    let signed=invoice.clone().into_signed_raw();
    let description_hash=signed.raw_invoice().description_hash().context("LNURL metadata hash missing; plain description is incompatible")?;
    ensure!(description_hash.0==metadata_hash,"LNURL metadata hash mismatch");
    Ok(json!({"signature_checked":true,"network":policy.network,"amount_msat":policy.amount_msat,
        "payment_hash":invoice.payment_hash().to_string(),"invoice_sha256":sha256::Hash::hash(policy.invoice.as_bytes()).to_string(),
        "metadata_sha256":metadata_hash.to_string(),"expires_at":expiry,"node_pubkey":invoice.recover_payee_pub_key().to_string()}))
}

/// The pinned backend signs the full issued k1 with Bitcoin's message prefix,
/// and parses an ECDSA DER signature. Ordinary LNURL raw challenge signing and
/// Ark address Schnorr signing are different protocols.
pub fn validate_login_signature(k1:&str,signature:&str,public_key:&str)->Result<()> {
    let (random,stamp)=k1.split_once('_').context("issued k1 format missing")?;
    ensure!(random.len()==64 && random.bytes().all(|b|b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        && !stamp.is_empty() && stamp.bytes().all(|b|b.is_ascii_digit()) && stamp.len()<=20,"invalid issued k1");
    let key=PublicKey::from_str(public_key)?;
    ensure!(key.to_string()==public_key,"authentication identity must be compressed canonical lowercase");
    let signature=Signature::from_str(signature)?;
    let hash=bitcoin::sign_message::signed_msg_hash(k1);
    Secp256k1::verification_only().verify_ecdsa(&Message::from_digest(hash.to_byte_array()),&signature,&key)?;
    Ok(())
}

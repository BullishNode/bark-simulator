//! Private Noah enrollment material. Call only for a declared online phone.
//!
//! This module must be invoked through private transport, never the public
//! driver-event/result capture. The backend receives a read authorization and
//! Bitcoin-message signature; no mailbox or authentication secret key leaves.
use anyhow::{Context,Result,ensure};
use ark::{ProtocolEncoding,SECP};
use bark::Wallet;
use bitcoin::{Network,hashes::Hash,secp256k1::{Message,PublicKey}};
use serde_json::{Value,json};
use std::{str::FromStr,time::{SystemTime,UNIX_EPOCH}};

pub async fn enrollment_material(wallet:&Wallet,k1:&str,expiry_rfc3339:&str,expected_server_pubkey:&str)->Result<Value> {
    ensure!(wallet.network().await?==Network::Signet,"Noah enrollment requires an owned signet phone");
    let expected=PublicKey::from_str(expected_server_pubkey)?;
    ensure!(expected.to_string()==expected_server_pubkey,"server pin is not canonical");
    ensure!(wallet.require_ark_info().await?.server_pubkey==expected,"Noah phone server differs from manifest");
    let (random,stamp)=k1.split_once('_').context("issued k1 format missing")?;
    ensure!(random.len()==64 && random.bytes().all(|b|b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        && !stamp.is_empty() && stamp.bytes().all(|b|b.is_ascii_digit()) && stamp.len()<=20,"invalid issued k1");
    let now=SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();let issued=stamp.parse::<u64>()?;
    ensure!(issued<=now && now-issued<=600,"issued k1 expired or in future");
    let expiry=expiry_rfc3339.parse()?;
    let grant=wallet.mailbox_authorization(expiry);
    let expiry=grant.expiry().timestamp();
    ensure!(expiry>now as i64 && expiry<=now as i64+90*86400,"mailbox grant expiry outside pinned bounds");
    ensure!(grant.verify(),"native mailbox authorization signature invalid");
    // Noah uses key index0. The fork requires it already present/linked; never
    // silently derive or publish another index to bypass this identity check.
    let key=wallet.peek_keypair(0).await?;
    let hash=bitcoin::sign_message::signed_msg_hash(k1);
    let signature=SECP.sign_ecdsa(&Message::from_digest(hash.to_byte_array()),&key.secret_key());
    Ok(json!({"key":key.public_key().to_string(),"sig":signature.to_string(),
        "mailbox_id":grant.mailbox().serialize_hex(),"expiry":expiry,"encoded":grant.serialize_hex()}))
}

//! Private enrollment material for a declared, already linked signet phone.
use anyhow::{Context,Result,ensure};
use ark::{ProtocolEncoding,SECP};
use bark::Wallet;
use bitcoin::{Network,hashes::Hash,secp256k1::{Message,PublicKey}};
use serde_json::{Value,json};
use std::{str::FromStr,time::{SystemTime,UNIX_EPOCH}};

pub const SDK_COMMIT:&str="8f2286ee7e1631b0ceccd1631ec3b728a1bb0a52";

pub async fn enrollment_material(wallet:&Wallet,k1:&str,expiry_unix:i64,expected_server_pubkey:&str,
    expected_ark_address:&str,expected_fallback_script:&str,expected_auth_pubkey:&str,expected_mailbox_id:&str)->Result<Value> {
    ensure!(wallet.network().await?==Network::Signet,"Noah enrollment requires a declared signet phone");
    let expected=PublicKey::from_str(expected_server_pubkey)?;
    ensure!(expected.to_string()==expected_server_pubkey,"server pin is not canonical");
    ensure!(wallet.require_ark_info().await?.server_pubkey==expected,"Noah phone server differs from manifest");
    let (random,stamp)=k1.split_once('_').context("issued k1 format missing")?;
    ensure!(random.len()==64 && random.bytes().all(|b|b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        && !stamp.is_empty() && stamp.bytes().all(|b|b.is_ascii_digit()) && stamp.len()<=20,"invalid issued k1");
    let now=SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();let issued=stamp.parse::<u64>()?;
    ensure!(issued<=now && now-issued<=600,"issued k1 expired or in future");
    ensure!(expiry_unix>now as i64 && expiry_unix<=now as i64+90*86400,"mailbox grant expiry outside pinned bounds");
    let address=wallet.peek_address(0).await?;
    ensure!(address.to_string()==expected_ark_address,"Noah phone Ark destination differs");
    let record=wallet.fallback_destination().await?;
    ensure!(record.spk.to_hex_string()==expected_fallback_script,"Noah phone fallback script differs");
    ensure!(wallet.onchain().context("Noah phone needs owned fallback")?.read().await.is_mine(&record.spk).await?,
        "Noah fallback is not owned by the declared phone");
    let key=wallet.peek_keypair(0).await?;
    ensure!(key.public_key().to_string()==expected_auth_pubkey && address.policy().user_pubkey()==key.public_key(),
        "Noah authentication key differs from linked index0");
    let expiry=chrono::DateTime::from_timestamp(expiry_unix,0).context("mailbox expiry out of range")?;
    let grant=wallet.mailbox_authorization(expiry.with_timezone(&chrono::Local));
    ensure!(grant.verify() && grant.mailbox().serialize_hex()==expected_mailbox_id,"Noah mailbox identity differs");
    let hash=bitcoin::sign_message::signed_msg_hash(k1);
    let signature=SECP.sign_ecdsa(&Message::from_digest(hash.to_byte_array()),&key.secret_key());
    Ok(json!({"key":key.public_key().to_string(),"sig":signature.to_string(),
        "mailbox_id":grant.mailbox().serialize_hex(),"expiry":grant.expiry().timestamp(),"encoded":grant.serialize_hex()}))
}

//! Current SDK bindings. Protocol encodings and signature checks belong to ark-lib.
use anyhow::{Context, Result, ensure};
use ark::{
    ProtocolEncoding,
    fallback::{FallbackRegistration, OwnerLink},
};
use bitcoin::{Network, secp256k1::PublicKey};
use serde_json::{Value, json};
use std::str::FromStr;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn decode(value: &Value) -> Result<Vec<u8>> {
    let raw = value.as_str().context("public encoding required")?;
    ensure!(
        raw.len() <= 512
            && raw.len() % 2 == 0
            && raw
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "bounded canonical hex required"
    );
    (0..raw.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&raw[i..i + 2], 16)?))
        .collect()
}

pub async fn wallet_binding(wallet: &bark::Wallet) -> Result<Value> {
    let record = wallet.fallback_destination().await?;
    let mailbox = wallet.mailbox_identifier().as_pubkey();
    record.verify(wallet.network().await?, mailbox)?;
    let info = wallet.require_ark_info().await?;
    Ok(
        json!({"mailbox_pk":mailbox.to_string(),"spk":record.spk.to_hex_string(),
        "fallback_record":hex(&record.serialize()),"server_mailbox_pubkey":info.mailbox_pubkey.to_string()}),
    )
}

pub fn verify_binding(
    request: &Value,
    coin: PublicKey,
    network: Network,
    server_mailbox: PublicKey,
) -> Result<Value> {
    let b = request["binding"]
        .as_object()
        .context("current binding required")?;
    ensure!(
        b.len() == 4
            && b.keys().all(|k| matches!(
                k.as_str(),
                "mailbox_pk" | "spk" | "fallback_record" | "server_mailbox_pubkey"
            )),
        "unexpected binding field"
    );
    ensure!(
        b["server_mailbox_pubkey"].as_str() == Some(server_mailbox.to_string().as_str()),
        "server mailbox differs from independent pin"
    );
    ensure!(
        request.get("child_index").is_none() && request.get("key_link_attestation").is_none(),
        "legacy origin refused"
    );
    let mailbox = PublicKey::from_str(b["mailbox_pk"].as_str().context("mailbox absent")?)?;
    let encoded = decode(&b["fallback_record"])?;
    let record = FallbackRegistration::deserialize(&encoded)?;
    ensure!(record.serialize() == encoded, "noncanonical registration");
    record.verify(network, mailbox)?;
    ensure!(
        b["spk"].as_str() == Some(record.spk.to_hex_string().as_str()),
        "destination mismatch"
    );
    let encoded_link = decode(&request["owner_link"])?;
    let link = OwnerLink::deserialize(&encoded_link)?;
    ensure!(link.serialize() == encoded_link, "noncanonical owner link");
    link.verify(server_mailbox, coin)?;
    if let Some(address) = request.get("address") {
        let address = ark::Address::from_str(address.as_str().context("address absent")?)?;
        ensure!(
            address.policy().user_pubkey() == coin
                && address.owner_link(server_mailbox)? == Some(link),
            "advertised address/link mismatch"
        );
    }
    Ok(
        json!({"mailbox_pk":mailbox.to_string(),"spk":record.spk.to_hex_string(),
        "fallback_record":hex(&encoded),"server_mailbox_pubkey":server_mailbox.to_string(),
        "record_version":4,"owner_link":hex(&encoded_link),"policy_pubkey_full":coin.to_string(),
        "record_signature_valid":true,"owner_link_signature_valid":true,
        "validation_scope":"SDK registration and coin link signatures; blinded mailbox unblinding, server admission and settlement are separate"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark::mailbox::MailboxIdentifier;
    use bitcoin::{
        ScriptBuf,
        secp256k1::{Keypair, rand},
    };

    #[test]
    fn sdk_proofs_bind_address_coin_server_and_chain() {
        let mailbox = Keypair::new(&ark::SECP, &mut rand::thread_rng());
        let coin = Keypair::new(&ark::SECP, &mut rand::thread_rng());
        let server = Keypair::new(&ark::SECP, &mut rand::thread_rng()).public_key();
        let address = ark::Address::builder()
            .testnet(true)
            .server_pubkey(server)
            .pubkey_policy(coin.public_key())
            .mailbox_signed(
                server,
                MailboxIdentifier::from_pubkey(mailbox.public_key()),
                &coin,
            )
            .unwrap()
            .into_address()
            .unwrap();
        let link = address.owner_link(server).unwrap().unwrap();
        let record = FallbackRegistration::new(
            Network::Regtest,
            ScriptBuf::from_hex(&format!("0014{}", "11".repeat(20))).unwrap(),
            &mailbox,
        )
        .unwrap();
        let request = json!({"address":address.to_string(),"owner_link":hex(&link.serialize()),
            "binding":{"mailbox_pk":mailbox.public_key().to_string(),"spk":record.spk.to_hex_string(),
                "fallback_record":hex(&record.serialize()),"server_mailbox_pubkey":server.to_string()}});
        assert!(verify_binding(&request, coin.public_key(), Network::Regtest, server).is_ok());
        assert!(verify_binding(&request, mailbox.public_key(), Network::Regtest, server).is_err());
        assert!(verify_binding(&request, coin.public_key(), Network::Signet, server).is_err());
        assert!(
            verify_binding(
                &request,
                coin.public_key(),
                Network::Regtest,
                mailbox.public_key()
            )
            .is_err()
        );
        let mut wrong = request.clone();
        wrong["binding"]["spk"] = json!(format!("0014{}", "22".repeat(20)));
        assert!(verify_binding(&wrong, coin.public_key(), Network::Regtest, server).is_err());
        let mut wrong = request.clone();
        wrong["owner_link"] = json!(hex(&OwnerLink::new(
            server,
            MailboxIdentifier::from_pubkey(server),
            &coin
        )
        .unwrap()
        .serialize()));
        assert!(verify_binding(&wrong, coin.public_key(), Network::Regtest, server).is_err());
    }
}

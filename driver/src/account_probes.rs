//! Explicit immutable registration probes. Removed per-key RPCs earn no credit.
use super::{InvariantFailure, Request, evidence, hex};
use anyhow::{Context, Result, bail, ensure};
use ark::{ProtocolEncoding, SECP, fallback::FallbackRecord};
use bark::Wallet;
use bitcoin::{
    Network, ScriptBuf,
    bip32::{ChildNumber, Xpriv, Xpub},
    secp256k1::PublicKey,
};
use serde_json::{Value, json};
use server_rpc::protos::{self, ark_service_client::ArkServiceClient};
use std::{path::Path, str::FromStr};
use tonic::transport::Channel;

pub(super) fn proposal(
    network: Network,
    record: &FallbackRecord,
    account: &Xpriv,
    mailbox: &bitcoin::secp256k1::Keypair,
    operation: &str,
    variant: u64,
) -> Result<Vec<u8>> {
    let mut proposed = FallbackRecord::new(network, record.spk.clone(), account, mailbox)?;
    match operation {
        "raw_wrong_chain" => {
            proposed = FallbackRecord::new(
                if network == Network::Signet {
                    Network::Regtest
                } else {
                    Network::Signet
                },
                record.spk.clone(),
                account,
                mailbox,
            )?
        }
        "raw_stale_record" => {
            let mut spk = record.spk.as_bytes().to_vec();
            spk[2] ^= 1;
            proposed = FallbackRecord::new(network, ScriptBuf::from_bytes(spk), account, mailbox)?;
        }
        _ => {}
    }
    let mut raw = proposed.serialize();
    match operation {
        "raw_record_tamper" => raw[3] ^= 1,
        "raw_sequence_tamper" => {
            let end = raw.len() - 1;
            raw[end] ^= 1;
        } // account signature, not a fictitious sequence
        "raw_mixed_link" => raw[2 + record.spk.len() + 45] ^= 1, // xpub field with original signatures
        "raw_malformed" => match variant % 3 {
            0 => {
                raw.pop();
            }
            1 => raw.push(0),
            _ => raw[0] = 255,
        },
        _ => {}
    }
    Ok(raw)
}

pub(super) async fn execute(
    wallet: &Wallet,
    rpc: &mut ArkServiceClient<Channel>,
    req: &Request,
    path: &Path,
    network: Network,
    operation: &str,
) -> Result<Value> {
    ensure!(
        req.maximum_fee_sat == 0,
        "registration probe spends no capital"
    );
    if matches!(
        operation,
        "raw_invalid_link" | "raw_mailbox_tamper" | "raw_key_replay" | "raw_relink"
    ) {
        return Ok(json!({"blocked":true,"unqualified":true,"actual_fee_sat":0,
            "reason":"removed standalone key-link RPC; a genuine per-output account-origin admission fixture is required", "operation":operation}));
    }
    let local = wallet.fallback_destination().await?;
    let mailbox = wallet.mailbox_keypair();
    let target = if operation == "raw_foreign_record" {
        let target = PublicKey::from_str(
            req.args["victim_mailbox_pk"]
                .as_str()
                .context("victim mailbox required")?,
        )?;
        ensure!(target != mailbox.public_key(), "victim must differ");
        target
    } else {
        mailbox.public_key()
    };
    let request = |record| protos::SetFallbackRequest {
        mailbox_pk: target.serialize().to_vec(),
        record,
    };
    let before = rpc.set_fallback(request(vec![])).await?.into_inner().record;
    ensure!(!before.is_empty(), "protected record must already exist");
    let protected = json!({"mailbox_pk":target.to_string(),"serialized":hex(&before)});
    if operation == "raw_bounded_queries" {
        for index in 0..8 {
            let raw = rpc.set_fallback(request(vec![])).await?.into_inner().record;
            ensure!(
                raw == before,
                InvariantFailure("query changed immutable record")
            );
            evidence(req, "raw_query", json!({"index":index,"record":hex(&raw)}))?;
        }
        return Ok(
            json!({"bounded_queries":8,"binding_unchanged":true,"protected_record":protected,"actual_fee_sat":0}),
        );
    }
    if operation == "raw_board_unlinked" {
        return Ok(json!({"blocked":true,"unqualified":true,"actual_fee_sat":0,
            "reason":"requires a valid funded board fixture with only origin removed; empty transaction cannot qualify creation refusal"}));
    }
    ensure!(
        matches!(
            operation,
            "raw_foreign_record"
                | "raw_record_tamper"
                | "raw_sequence_tamper"
                | "raw_wrong_chain"
                | "raw_stale_record"
                | "raw_equal_sequence"
                | "raw_mixed_link"
                | "raw_malformed"
        ),
        "unknown registration probe"
    );
    // Read only this already-open actor's own protected mnemonic. Never expose it.
    let mnemonic_path = path.join("mnemonic");
    ensure!(!mnemonic_path.is_symlink(), "mnemonic cannot be a symlink");
    let mnemonic = bip39::Mnemonic::from_str(&std::fs::read_to_string(mnemonic_path)?)?;
    let account = Xpriv::new_master(network, &mnemonic.to_seed(""))?.derive_priv(
        &SECP,
        &[
            ChildNumber::Hardened { index: 350 },
            ChildNumber::Hardened { index: 0 },
        ],
    )?;
    ensure!(
        Xpub::from_priv(&SECP, &account) == local.account_xpub,
        "probe account must match this actor's immutable record"
    );
    let raw = proposal(
        network,
        &local,
        &account,
        &mailbox,
        operation,
        req.args["variant"].as_u64().unwrap_or(0),
    )?;
    evidence(
        req,
        "raw_request",
        json!({"rpc":"SetFallback","mailbox_pk":target.to_string(),"record":hex(&raw),"record_before":hex(&before),
        "path_variant":match operation {"raw_sequence_tamper"=>"account-signature-tamper","raw_stale_record"=>"valid-conflicting-immutable-destination","raw_equal_sequence"=>"fresh-signature-identical-binding",_=>operation}}),
    )?;
    let response = rpc.set_fallback(request(raw)).await;
    evidence(
        req,
        "raw_response",
        json!({"code":response.as_ref().err().map(|s|format!("{:?}",s.code())),"record_returned":response.as_ref().ok().map(|r|hex(&r.get_ref().record))}),
    )?;
    let idempotent = operation == "raw_equal_sequence";
    if idempotent {
        ensure!(
            response?.into_inner().record == before,
            InvariantFailure("same immutable binding replaced canonical record")
        );
    } else {
        match response {
            Err(s)
                if matches!(
                    s.code(),
                    tonic::Code::InvalidArgument
                        | tonic::Code::FailedPrecondition
                        | tonic::Code::AlreadyExists
                ) => {}
            Err(_) => bail!("unexpected refusal class"),
            Ok(_) => {
                return Err(
                    InvariantFailure("invalid or conflicting immutable record accepted").into(),
                );
            }
        }
    }
    let after = rpc.set_fallback(request(vec![])).await?.into_inner().record;
    ensure!(
        after == before,
        InvariantFailure("probe altered protected immutable record")
    );
    Ok(
        json!({"expected_refusal":!idempotent,"idempotent":idempotent,"binding_unchanged":true,"protected_record":protected,"attempted_key_pubkeys":[],"actual_fee_sat":0,
        "scope":"registration result plus exact public readback; independent database check and source-specific qualification remain required"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Keypair;
    fn fixture() -> (FallbackRecord, Xpriv, Keypair) {
        let account = Xpriv::new_master(Network::Signet, &[9; 64]).unwrap();
        let mailbox = Keypair::from_seckey_slice(&SECP, &[4; 32]).unwrap();
        let record = FallbackRecord::new(
            Network::Signet,
            ScriptBuf::from_hex("00141111111111111111111111111111111111111111").unwrap(),
            &account,
            &mailbox,
        )
        .unwrap();
        (record, account, mailbox)
    }
    #[test]
    fn full_field_tamper_vectors_are_not_valid_registration() {
        let (record, account, mailbox) = fixture();
        for op in [
            "raw_record_tamper",
            "raw_sequence_tamper",
            "raw_wrong_chain",
            "raw_mixed_link",
        ] {
            let raw = proposal(Network::Signet, &record, &account, &mailbox, op, 0).unwrap();
            assert!(
                FallbackRecord::deserialize(&raw)
                    .and_then(|r| r
                        .verify(Network::Signet, mailbox.public_key())
                        .map_err(|_| ark::ProtocolDecodingError::invalid("signature")))
                    .is_err(),
                "{op}"
            );
        }
    }
    #[test]
    fn conflicting_and_idempotent_cases_use_real_valid_signatures() {
        let (record, account, mailbox) = fixture();
        for (op, same) in [("raw_stale_record", false), ("raw_equal_sequence", true)] {
            let raw = proposal(Network::Signet, &record, &account, &mailbox, op, 0).unwrap();
            let actual = FallbackRecord::deserialize(&raw).unwrap();
            actual
                .verify(Network::Signet, mailbox.public_key())
                .unwrap();
            assert_eq!(actual.same_binding(&record), same);
        }
    }
}

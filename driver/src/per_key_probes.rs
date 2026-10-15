//! Source-only C registration request preparation. No RPC or coverage credit.
//! Caller must freeze exact bytes once, then prove durable before/after state.
use anyhow::{Result, ensure};
use ark::{ProtocolEncoding, fallback::{FallbackRecord, KeyLink}};
use bitcoin::{Network, ScriptBuf, secp256k1::{Keypair, PublicKey}};
use prost::Message;
use server_rpc::{RequestExt, protos};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    Replay,
    ConflictingDestination,
    ForeignMailbox(PublicKey),
    TamperedScript,
    TamperedRecordSignature,
    WrongNetwork,
    TamperedRecoveryIndex,
    TamperedFullKeyParity,
    WrongCoinSignature,
    MixedValidInvalidBatch,
    Relink,
    HighValidRecoveryIndex,
    HardenedRecoveryEncoding,
    LinkBatch,
    OverLinkLimit,
    TruncatedRecord,
    TrailingRecord,
    UnsupportedRecordVersion,
}

pub struct PreparedRegistration {
    pub request: protos::SetFallbackRequest,
    pub variant: Variant,
    // This is a request expectation, not an observed outcome or scenario PASS.
    pub expects_valid_signatures: bool,
}

impl PreparedRegistration {
    pub fn exact_wire_bytes(&self) -> Vec<u8> { self.request.encode_to_vec() }
    pub fn into_request(self) -> tonic::Request<protos::SetFallbackRequest> {
        let mut request = tonic::Request::new(self.request);
        request.set_pver(server_rpc::pver::PROTOCOL_VERSION_PER_KEY_FALLBACK);
        request
    }
}

/// Keys must be privately owned probe keys, independently declared as unfunded.
/// Mixed-batch atomicity needs TWO keys absent in the authoritative before cut.
/// Relink needs this coin already bound to a DIFFERENT mailbox in that cut.
/// Fresh/concurrent initialization needs a mailbox absent in that before cut.
/// For an existing native key, pass its retained canonical recovery index;
/// an unfunded external probe key may use None. Never invent a positive native
/// derivation index. No index here derives ownership.
pub fn prepare(
    network: Network,
    canonical: &FallbackRecord,
    mailbox: &Keypair,
    keys: &[Keypair],
    recovery_index: Option<u32>,
    variant: Variant,
) -> Result<PreparedRegistration> {
    ensure!(matches!(network, Network::Signet | Network::Regtest), "probe network refused");
    ensure!(!keys.is_empty() && keys.len() <= 65, "bounded owned probe keys required");
    canonical.verify(network, mailbox.public_key())?;
    let mut signing_network = network;
    let mut record = canonical.clone();
    if variant == Variant::WrongNetwork {
        signing_network = if network == Network::Signet { Network::Regtest } else { Network::Signet };
        record = FallbackRecord::new(signing_network, canonical.spk.clone(), mailbox)?;
    }
    if variant == Variant::ConflictingDestination {
        let mut script = canonical.spk.as_bytes().to_vec();
        ensure!(script.len() >= 22, "standard immutable script required");
        let payload_offset = script.len() / 2;
        script[payload_offset] ^= 1;
        record = FallbackRecord::new(network, ScriptBuf::from_bytes(script), mailbox)?;
        ensure!(!record.same_binding(canonical), "conflicting script did not change");
    }
    let index = if variant == Variant::HighValidRecoveryIndex { Some((1 << 31) - 1) } else { recovery_index };
    if matches!(variant, Variant::TamperedRecoveryIndex | Variant::HardenedRecoveryEncoding) {
        ensure!(index.is_some(), "this vector requires an actual explicit signed recovery index");
    }
    let count = match variant {
        Variant::MixedValidInvalidBatch => { ensure!(keys.len() == 2, "two absent owned keys required"); 2 },
        Variant::LinkBatch => { ensure!(keys.len() <= 64, "ordinary batch exceeds server limit"); keys.len() },
        Variant::OverLinkLimit => { ensure!(keys.len() == 65, "negative boundary requires exactly65 links"); 65 },
        _ => 1,
    };
    ensure!(keys[..count].iter().map(Keypair::public_key).collect::<std::collections::BTreeSet<_>>().len() == count,
        "batch vectors require distinct owned keys");
    let mut links = keys[..count].iter().map(|key|
        KeyLink::new(signing_network, mailbox.public_key(), &record, key, index)
    ).collect::<Result<Vec<_>, _>>()?;
    if variant == Variant::WrongCoinSignature {
        ensure!(keys.len() >= 2 && keys[0].public_key() != keys[1].public_key(), "distinct owned signing keys required");
        links[0].signature = KeyLink::new(network, mailbox.public_key(), &record, &keys[1], index)?.signature;
    }
    let mut record_bytes = record.serialize();
    let mut link_bytes = links.iter().map(ProtocolEncoding::serialize).collect::<Vec<_>>();
    match variant {
        Variant::TamperedScript => record_bytes[2 + record.spk.len() / 2] ^= 1,
        Variant::TamperedRecordSignature => { let last = record_bytes.len() - 1; record_bytes[last] ^= 1; },
        Variant::TamperedRecoveryIndex => link_bytes[0][35] ^= 1,
        Variant::TamperedFullKeyParity => link_bytes[0][1] ^= 1,
        Variant::MixedValidInvalidBatch => { let last = link_bytes[1].len() - 1; link_bytes[1][last] ^= 1; },
        Variant::HardenedRecoveryEncoding => link_bytes[0][38] |= 128,
        Variant::TruncatedRecord => { record_bytes.pop(); },
        Variant::TrailingRecord => record_bytes.push(0),
        Variant::UnsupportedRecordVersion => record_bytes[0] = 255,
        _ => {},
    }
    let target = match variant {
        Variant::ForeignMailbox(target) => { ensure!(target != mailbox.public_key(), "victim must differ"); target },
        _ => mailbox.public_key(),
    };
    let request = protos::SetFallbackRequest {
        mailbox_pk: target.serialize().to_vec(), record: record_bytes, key_links: link_bytes,
    };
    ensure!(request.encoded_len() <= 16 * 1024, "bounded registration wire size exceeded");
    Ok(PreparedRegistration { request, variant, expects_valid_signatures: matches!(variant,
        Variant::Replay | Variant::ConflictingDestination | Variant::Relink |
        Variant::HighValidRecoveryIndex | Variant::LinkBatch | Variant::OverLinkLimit) })
}

/// D01-specific public victim destination, signed only by the attacker.
/// The victim supplies no secret to this preparation path.
pub fn prepare_impersonation(
    network: Network, victim: &FallbackRecord, victim_mailbox: PublicKey,
    attacker_mailbox: &Keypair, attacker_keys: &[Keypair],
) -> Result<PreparedRegistration> {
    victim.verify(network, victim_mailbox)?;
    ensure!(victim_mailbox != attacker_mailbox.public_key(), "distinct victim required");
    let forged = FallbackRecord::new(network, victim.spk.clone(), attacker_mailbox)?;
    prepare(network, &forged, attacker_mailbox, attacker_keys, None, Variant::ForeignMailbox(victim_mailbox))
}

/// D08-specific claim of a victim's FULL public key with an attacker signature.
/// This API cannot access a victim private key; ownership is not inferred by index.
pub fn prepare_forged_key_claim(
    network: Network, record: &FallbackRecord, mailbox: &Keypair,
    attacker: &Keypair, victim_key: PublicKey, recovery_index: Option<u32>,
) -> Result<PreparedRegistration> {
    ensure!(attacker.public_key() != victim_key, "distinct victim coin required");
    let mut prepared = prepare(network, record, mailbox, &[*attacker], recovery_index, Variant::Replay)?;
    prepared.request.key_links[0][1..34].copy_from_slice(&victim_key.serialize());
    prepared.variant = Variant::WrongCoinSignature;
    prepared.expects_valid_signatures = false;
    Ok(prepared)
}

/// Authenticate a SUCCESS reply only. This proves public signatures and exact
/// request ordering/bindings; it DOES NOT prove durable/current DB admission.
/// The controller must separately compare its sealed before/after source cuts
/// and, for existing bindings, exact earlier canonical signature bytes.
pub fn verify_acknowledgement(
    network: Network,
    request: &protos::SetFallbackRequest,
    reply: &protos::SetFallbackResponse,
) -> Result<serde_json::Value> {
    ensure!((1..=64).contains(&request.key_links.len()) && request.encoded_len() <= 16 * 1024,
        "SUCCESS acknowledgement requires a bounded nonempty ordinary registration");
    ensure!(reply.encoded_len() <= 16 * 1024, "bounded acknowledgement required");
    let mailbox = PublicKey::from_slice(&request.mailbox_pk)?;
    let proposed_record = FallbackRecord::deserialize(&request.record)?;
    proposed_record.verify(network, mailbox)?;
    let canonical_record = FallbackRecord::deserialize(&reply.record)?;
    canonical_record.verify(network, mailbox)?;
    ensure!(canonical_record.same_binding(&proposed_record), "reply changes immutable destination");
    ensure!(reply.key_links.len() == request.key_links.len(), "reply omits/adds key acknowledgements");
    let mut public = Vec::with_capacity(reply.key_links.len());
    let mut distinct = std::collections::BTreeSet::new();
    for (requested, retained) in request.key_links.iter().zip(&reply.key_links) {
        let proposed = KeyLink::deserialize(requested)?;
        proposed.verify(network, mailbox, &proposed_record)?;
        ensure!(distinct.insert(proposed.user_pubkey), "SUCCESS reply for duplicate requested key refused");
        let canonical = KeyLink::deserialize(retained)?;
        canonical.verify(network, mailbox, &canonical_record)?;
        ensure!(canonical.user_pubkey == proposed.user_pubkey && canonical.recovery_index == proposed.recovery_index,
            "reply changes/reorders full coin key or signed recovery metadata");
        let binding = serde_json::json!({"mailbox_pk":mailbox.to_string(), "spk":canonical_record.spk.to_hex_string(),
            "fallback_record":reply.record.iter().map(|b|format!("{b:02x}")).collect::<String>()});
        let checked = crate::per_key::verify_binding(&serde_json::json!({"binding":binding,
            "key_link_attestation":retained.iter().map(|b|format!("{b:02x}")).collect::<String>()}), proposed.user_pubkey, network)?;
        public.push(checked);
    }
    Ok(serde_json::json!({"mailbox_pk":mailbox.to_string(), "canonical_proofs":public,
        "scope":"independent V4/V1 signatures and exact request-order binding only; durable/current admission and economics require separate authoritative source cuts"}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark::SECP;
    use serde_json::json;
    fn setup() -> (FallbackRecord, Keypair, Vec<Keypair>) {
        let mailbox = Keypair::from_seckey_slice(&SECP, &[7; 32]).unwrap();
        let keys = [8u8, 9].into_iter().map(|n| Keypair::from_seckey_slice(&SECP, &[n; 32]).unwrap()).collect();
        (FallbackRecord::new(Network::Regtest, ScriptBuf::from_hex("00141111111111111111111111111111111111111111").unwrap(), &mailbox).unwrap(), mailbox, keys)
    }
    fn independent(request: &protos::SetFallbackRequest, key: PublicKey, raw: &[u8]) -> Result<()> {
        let record = FallbackRecord::deserialize(&request.record)?;
        let mailbox = PublicKey::from_slice(&request.mailbox_pk)?;
        let binding = json!({"mailbox_pk":mailbox.to_string(), "spk":record.spk.to_hex_string(),
            "fallback_record":request.record.iter().map(|b|format!("{b:02x}")).collect::<String>()});
        let request = json!({"binding":binding,
            "key_link_attestation":raw.iter().map(|b|format!("{b:02x}")).collect::<String>()});
        crate::per_key::verify_binding(&request, key, Network::Regtest)?;
        Ok(())
    }
    #[test]
    fn genuine_signed_replay_conflict_relink_and_high_index_have_independent_proofs() {
        let (record, mailbox, keys) = setup();
        for variant in [Variant::Replay, Variant::ConflictingDestination, Variant::Relink, Variant::HighValidRecoveryIndex] {
            let prepared = prepare(Network::Regtest, &record, &mailbox, &keys, Some(50), variant).unwrap();
            independent(&prepared.request, keys[0].public_key(), &prepared.request.key_links[0]).unwrap();
            assert_eq!(prepared.exact_wire_bytes(), prepared.request.encode_to_vec());
        }
    }
    #[test]
    fn altered_bindings_wrong_chain_parity_and_signer_fail_independent_verifier() {
        let (record, mailbox, keys) = setup();
        for variant in [Variant::TamperedScript, Variant::TamperedRecordSignature, Variant::WrongNetwork,
            Variant::TamperedRecoveryIndex, Variant::TamperedFullKeyParity, Variant::WrongCoinSignature,
            Variant::HardenedRecoveryEncoding] {
            let prepared = prepare(Network::Regtest, &record, &mailbox, &keys, Some(50), variant).unwrap();
            assert!(independent(&prepared.request, keys[0].public_key(), &prepared.request.key_links[0]).is_err(), "{variant:?}");
        }
    }
    #[test]
    fn mixed_batch_keeps_first_genuine_and_second_invalid_not_generic_malformed() {
        let (record, mailbox, keys) = setup();
        let prepared = prepare(Network::Regtest, &record, &mailbox, &keys, Some(50), Variant::MixedValidInvalidBatch).unwrap();
        independent(&prepared.request, keys[0].public_key(), &prepared.request.key_links[0]).unwrap();
        assert!(independent(&prepared.request, keys[1].public_key(), &prepared.request.key_links[1]).is_err());
    }
    #[test]
    fn script_tamper_changes_payload_but_preserves_canonical_standard_encoding() {
        let (record, mailbox, keys) = setup();
        let prepared = prepare(Network::Regtest, &record, &mailbox, &keys, Some(50), Variant::TamperedScript).unwrap();
        let decoded = FallbackRecord::deserialize(&prepared.request.record).unwrap();
        assert!(decoded.spk.is_p2wpkh());
        assert_eq!(decoded.spk.len(), record.spk.len());
        assert_ne!(decoded.spk, record.spk);
        assert!(decoded.verify(Network::Regtest, mailbox.public_key()).is_err());
    }
    #[test]
    fn victim_impersonation_and_key_claim_need_only_public_victim_material() {
        let (record, mailbox, keys) = setup();
        let victim = Keypair::from_seckey_slice(&SECP, &[10; 32]).unwrap();
        let victim_record = FallbackRecord::new(Network::Regtest,
            ScriptBuf::from_hex("00142222222222222222222222222222222222222222").unwrap(), &victim).unwrap();
        let prepared = prepare_impersonation(Network::Regtest, &victim_record, victim.public_key(), &mailbox, &keys).unwrap();
        assert_eq!(FallbackRecord::deserialize(&prepared.request.record).unwrap().spk, victim_record.spk);
        assert!(independent(&prepared.request, keys[0].public_key(), &prepared.request.key_links[0]).is_err());
        let forged = prepare_forged_key_claim(Network::Regtest, &record, &mailbox, &keys[0], victim.public_key(), Some(50)).unwrap();
        assert!(independent(&forged.request, victim.public_key(), &forged.request.key_links[0]).is_err());
    }
    #[test]
    fn genuine_64_and_65_link_requests_stay_bounded_and_use_distinct_valid_proofs() {
        let (record, mailbox, _) = setup();
        let keys = (1u8..=65).map(|n| Keypair::from_seckey_slice(&SECP, &[n; 32]).unwrap()).collect::<Vec<_>>();
        let regular = prepare(Network::Regtest, &record, &mailbox, &keys[..64], None, Variant::LinkBatch).unwrap();
        assert_eq!(regular.request.key_links.len(), 64);
        assert!(prepare(Network::Regtest, &record, &mailbox, &keys, None, Variant::LinkBatch).is_err());
        let boundary = prepare(Network::Regtest, &record, &mailbox, &keys, None, Variant::OverLinkLimit).unwrap();
        assert_eq!(boundary.request.key_links.len(), 65);
        assert!(boundary.exact_wire_bytes().len() <= 16 * 1024);
        for (key, link) in keys.iter().zip(&boundary.request.key_links) {
            independent(&boundary.request, key.public_key(), link).unwrap();
        }
    }
    #[test]
    fn acknowledgement_requires_every_actual_key_in_order_and_unchanged_signed_index() {
        let (record, mailbox, keys) = setup();
        let prepared = prepare(Network::Regtest, &record, &mailbox, &keys, Some(50), Variant::LinkBatch).unwrap();
        let reply = protos::SetFallbackResponse { record: prepared.request.record.clone(), key_links: prepared.request.key_links.clone() };
        verify_acknowledgement(Network::Regtest, &prepared.request, &reply).unwrap();
        let mut swapped = reply.clone(); swapped.key_links.swap(0, 1);
        assert!(verify_acknowledgement(Network::Regtest, &prepared.request, &swapped).is_err());
        let mut omitted = reply.clone(); omitted.key_links.pop();
        assert!(verify_acknowledgement(Network::Regtest, &prepared.request, &omitted).is_err());
        let mut changed = reply.clone(); changed.key_links[0][35] ^= 1;
        assert!(verify_acknowledgement(Network::Regtest, &prepared.request, &changed).is_err());
        assert!(verify_acknowledgement(Network::Signet, &prepared.request, &reply).is_err());
        let mut duplicate_request = prepared.request.clone();
        duplicate_request.key_links[1] = duplicate_request.key_links[0].clone();
        let duplicate_reply = protos::SetFallbackResponse { record: reply.record.clone(), key_links: duplicate_request.key_links.clone() };
        assert!(verify_acknowledgement(Network::Regtest, &duplicate_request, &duplicate_reply).is_err());
        let mut empty_request = prepared.request.clone(); empty_request.key_links.clear();
        let empty_reply = protos::SetFallbackResponse { record: reply.record, key_links: vec![] };
        assert!(verify_acknowledgement(Network::Regtest, &empty_request, &empty_reply).is_err());
    }
    #[test]
    fn explicit_protocol6_and_nonempty_record_are_required_not_an_empty_query_alias() {
        let (record, mailbox, keys) = setup();
        let prepared = prepare(Network::Regtest, &record, &mailbox, &keys, Some(50), Variant::Replay).unwrap();
        let request = prepared.into_request();
        assert_eq!(request.pver().unwrap(), 6);
        assert_eq!(request.get_ref().record[0], 4);
        assert_eq!(request.get_ref().key_links[0][0], 1);
    }
}

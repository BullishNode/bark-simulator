//! Wallet-free replay of an exact previously captured, valid SDK forfeit.
//! This consumes protected evidence, never generates a new partial signature.
use super::{evidence, phase_protocol as retained, Request};
use anyhow::{ensure, Context, Result};
use ark::{forfeit::HashLockedForfeitBundle, musig, vtxo::Full, ProtocolEncoding, Vtxo};
use prost::Message;
use serde_json::{json, Value};
use server_rpc::protos::{self, ark_service_client::ArkServiceClient};
use std::{fs, io::Read, os::unix::fs::MetadataExt, path::Path};
use tonic::transport::Channel;
fn decode_hex(value: &str) -> Result<Vec<u8>> {
    ensure!(
        value.len() % 2 == 0
            && value.len() <= 8 * 1024 * 1024
            && value.bytes().all(|b| b.is_ascii_hexdigit()),
        "bounded exact protected hex required"
    );
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(Into::into))
        .collect()
}
/// Open only an immutable hash-addressed object within the protected scope.
/// Check inode/type/owner/mode before reading; a swapped symlink cannot make
/// arbitrary signer files enter the parser. Returned bytes never reach stdout.
fn object(root: &Path, id: &str) -> Result<Vec<u8>> {
    ensure!(
        id.len() == 64
            && id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "declared immutable evidence hash required"
    );
    let mut current = std::path::PathBuf::new();
    for component in root.components() {
        current.push(component);
        ensure!(
            !fs::symlink_metadata(&current)?.file_type().is_symlink(),
            "protected root ancestor is symlink"
        )
    }
    let owner = fs::metadata(root)?.uid();
    for directory in [root.to_path_buf(), root.join("objects")] {
        let meta = fs::symlink_metadata(directory)?;
        ensure!(
            meta.is_dir() && meta.uid() == owner && meta.mode() & 0o077 == 0,
            "protected evidence directory unsafe"
        )
    }
    let path = root.join("objects").join(id);
    let expected = fs::symlink_metadata(&path)?;
    ensure!(
        expected.is_file()
            && expected.uid() == owner
            && expected.mode() & 0o077 == 0
            && expected.nlink() == 1
            && expected.len() <= 4 * 1024 * 1024,
        "protected evidence object unsafe"
    );
    let mut file = fs::File::open(&path)?;
    let actual = file.metadata()?;
    ensure!(
        actual.ino() == expected.ino() && actual.dev() == expected.dev() && actual.is_file(),
        "evidence object changed before read"
    );
    let mut bytes = Vec::new();
    file.by_ref()
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 4 * 1024 * 1024 && retained::hash(&bytes) == id,
        "protected evidence content hash differs"
    );
    Ok(bytes)
}
fn verify_bundle(
    frozen: &Value,
    readiness: &Value,
    capsule: &Value,
) -> Result<protos::ForfeitVtxosRequest> {
    ensure!(
        readiness["unlock_hash"] == frozen["context"]["unlock_hash"]
            && readiness["wire_sha256"] == frozen["context"]["captured_forfeit"]["wire_sha256"],
        "replay readiness differs from immutable prospective capture"
    );
    let frame = decode_hex(
        capsule["grpc_request_hex"]
            .as_str()
            .context("exact captured unary frame")?,
    )?;
    ensure!(
        frame.len() >= 5
            && frame[0] == 0
            && u32::from_be_bytes(frame[1..5].try_into()?) as usize == frame.len() - 5,
        "exact uncompressed captured forfeit request required"
    );
    ensure!(
        retained::hash(&frame) == readiness["wire_sha256"].as_str().context("wire hash")?,
        "cached wire changed"
    );
    let body = protos::ForfeitVtxosRequest::decode(&frame[5..])?;
    ensure!(
        body.encode_to_vec() == frame[5..],
        "unknown protobuf fields would not survive typed replay; do not silently replace capture"
    );
    let originals = frozen["inputs"]
        .as_array()
        .context("frozen original proofs")?;
    let saved = capsule["inputs"]
        .as_array()
        .context("captured signed inputs/server nonces")?;
    ensure!(
        body.forfeit_bundles.len() == originals.len()
            && saved.len() == originals.len()
            && !originals.is_empty()
            && originals.len() <= 16,
        "exact full input bundle required"
    );
    for ((encoded, item), source) in body.forfeit_bundles.iter().zip(originals).zip(saved) {
        let bundle = HashLockedForfeitBundle::from_bytes(encoded)?;
        let coin = Vtxo::<Full>::deserialize(&decode_hex(
            source["signed_vtxo"]
                .as_str()
                .context("saved signed original")?,
        )?)?;
        ensure!(
            coin.has_all_witnesses()
                && bundle.vtxo_id == coin.id()
                && coin.id().to_string() == item["coin_id"].as_str().context("original id")?
                && coin.user_pubkey().to_string()
                    == item["pubkey"].as_str().context("original key")?
                && Some(coin.amount().to_sat()) == item["amount_sat"].as_u64()
                && retained::hash(&coin.serialize())
                    == item["signed_hash"]
                        .as_str()
                        .context("original signed hash")?
                && coin.server_pubkey().to_string()
                    == frozen["server_pubkey"].as_str().context("server pin")?
                && bundle.unlock_hash.to_string()
                    == readiness["unlock_hash"]
                        .as_str()
                        .context("cancelled unlock hash")?,
            "captured forfeit does not belong to exact frozen input/hash/server"
        );
        let nonce = musig::PublicNonce::from_bytes(&decode_hex(
            source["server_public_nonce"]
                .as_str()
                .context("exact saved server public nonce")?,
        )?)?;
        bundle
            .verify(&coin, &nonce)
            .map_err(|e| anyhow::anyhow!("saved genuine forfeit partial signature invalid: {e}"))?;
    }
    Ok(body)
}
/// Root must run the positive cancellation collector before queuing this op;
/// no absent wallet, new nonce, new forfeit, or ordinary SDK sync is involved.
pub async fn execute(
    rpc: &mut ArkServiceClient<Channel>,
    req: &Request,
    private_root: &Path,
) -> Result<Value> {
    let frozen = retained::intent(req, "D27")?;
    ensure!(
        req.operation == "phase_replay_forfeit" && req.maximum_fee_sat == 0,
        "exact wallet-free forfeit replay operation required"
    );
    let Some(directory) = retained::fence(private_root, req)? else {
        return Ok(
            json!({"phase_unknown":true,"actual_fee_sat":Value::Null,"reason":"existing replay fence; independent reconciliation required; no resend"}),
        );
    };
    let readiness = &req.args["forfeit_readiness"];
    let capsule = object(
        private_root,
        readiness["private_bundle_sha256"]
            .as_str()
            .context("protected bundle hash")?,
    )?;
    let capsule: Value = serde_json::from_slice(&capsule)?;
    let body = verify_bundle(&frozen, readiness, &capsule)?;
    let wire = body.encode_to_vec();
    retained::save(&directory.join("forfeit-replay-request.bin"), &wire)?;
    retained::save(
        &directory.join("cancellation-readiness.json"),
        &serde_json::to_vec(readiness)?,
    )?;
    let started = retained::now_ns();
    evidence(
        req,
        "phase_cached_forfeit_frozen",
        json!({"trial_id":req.args["trial_id"],"rpc":"ForfeitVtxos","wire_sha256":readiness["wire_sha256"],"typed_request_sha256":retained::hash(&wire),"private_bundle_sha256":readiness["private_bundle_sha256"],"unlock_hash":readiness["unlock_hash"],"input_coin_ids":readiness["input_coin_ids"],"cancellation_sha256":readiness["cancellation_sha256"],"original_wallet_opened":false,"new_signing_session":false,"submitted_at_ns":started}),
    )?;
    let result = rpc.forfeit_vtxos(body).await;
    let finished = retained::now_ns();
    let observed = match result {
        Ok(reply) => {
            let (metadata, body, extensions) = reply.into_parts();
            retained::save(
                &directory.join("forfeit-replay-reply.bin"),
                &body.encode_to_vec(),
            )?;
            retained::save(
                &directory.join("forfeit-replay-metadata.json"),
                &serde_json::to_vec(
                    &json!({"metadata":format!("{metadata:?}"),"extensions":format!("{extensions:?}")}),
                )?,
            )?;
            json!({"kind":"unexpected_cancelled_forfeit_accepted","reply_sha256":retained::hash(&body.encode_to_vec()),"preimage_private_only":true})
        }
        Err(status) => {
            retained::save(
                &directory.join("forfeit-replay-status.json"),
                &serde_json::to_vec(
                    &json!({"code":format!("{:?}",status.code()),"message":status.message(),"details_hex":super::hex(status.details()),"metadata":format!("{:?}",status.metadata())}),
                )?,
            )?;
            json!({"kind":if status.code()==tonic::Code::InvalidArgument && status.message()=="unknown unlock hash" {"cancelled_participation_refusal"} else {"transport_or_other_refusal_unknown"},"code":format!("{:?}",status.code())})
        }
    };
    evidence(
        req,
        "phase_cached_forfeit_reply",
        json!({"trial_id":req.args["trial_id"],"wire_sha256":readiness["wire_sha256"],"submitted_at_ns":started,"reply_at_ns":finished,"kind":observed["kind"],"code":observed["code"],"customer_traffic_credit":false}),
    )?;
    Ok(
        json!({"phase_unknown":true,"actual_fee_sat":Value::Null,"protocol_observation":observed,"customer_traffic_credit":false,
        "required_audit":"positive exact cancellation plus independent spent replacement paths, original exits/payouts and current no-revival arbitration"}),
    )
}

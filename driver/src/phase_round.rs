//! One real interactive SDK round attempt races a retained arkoor or offboard.
//! The transport gate captures SDK-generated requests before forwarding;
//! private SDK round signing/forfeit safety code is never reimplemented here.
use server_rpc::TryFromBytes;
use super::{
    Request, evidence, hex, phase_protocol as retained,
    phase_transport::{ClientTransport, Gate, Plan, Validator},
};
use anyhow::{Context, Result, ensure};
use ark::arkoor::{ArkoorDestination, package::ArkoorPackageBuilder};
use ark::attestations::RoundAttemptAttestation;
use ark::rounds::{RoundAttempt, RoundEvent};
use ark::{ProtocolEncoding, SignedVtxoRequest, VtxoId, VtxoPolicy};
use bark::{Wallet, round::RoundParticipation, subsystem::RoundMovement};
use bitcoin::{Amount, secp256k1::PublicKey};
use futures::StreamExt;
use prost::Message;
use serde_json::{Value, json};
use server_rpc::protos::{self, ark_service_client::ArkServiceClient};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex},
};
use tonic::transport::Channel;

enum Partner {
    Arkoor {
        builder: retained::Prepared,
        keys: Vec<bitcoin::secp256k1::Keypair>,
        body: protos::ArkoorPackageCosignRequest,
        checkpoint: Value,
    },
    Offboard(super::phase_offboard::Partner),
}
impl Partner {
    fn checkpoint(&self) -> Value {
        match self {
            Self::Arkoor { checkpoint, .. } => checkpoint.clone(),
            Self::Offboard(partner) => partner.checkpoint.clone(),
        }
    }
    async fn dispatch(
        self,
        wallet: &Wallet,
        rpc: &mut ArkServiceClient<Channel>,
        req: &Request,
        directory: &Path,
    ) -> Result<Value> {
        match self {
            Self::Offboard(partner) => partner.finish(wallet, rpc, req, directory).await,
            Self::Arkoor {
                builder,
                keys,
                body,
                checkpoint,
            } => {
                let started = retained::now_ns();
                let wire = body.encode_to_vec();
                retained::save(
                    &directory.join("arkoor-dispatched.json"),
                    &serde_json::to_vec(
                        &json!({"wire_sha256":retained::hash(&wire),"submitted_at_ns":started}),
                    )?,
                )?;
                let reply = rpc.request_arkoor_cosign(retained::pinned_request(req,body)?).await;
                let result = retained::signed_reply(
                    directory,
                    "arkoor",
                    builder,
                    &keys,
                    reply,
                    checkpoint["wire_sha256"].as_str().context("wire hash")?,
                    started,
                    retained::now_ns(),
                )?;
                evidence(
                    req,
                    "phase_reply_observed",
                    json!({"trial_id":req.args["trial_id"],"leg_id":"arkoor","reply":result}),
                )?;
                Ok(result)
            }
        }
    }
}
#[derive(Default)]
struct Expected {
    participation: Option<RoundParticipation>,
    attempt: Option<RoundAttempt>,
    frozen_submit: Option<Value>,
    committed_fee_sat: u64,
}
pub struct Invocation {
    pub transport: ClientTransport,
    gate: Arc<Gate>,
    expected: Arc<Mutex<Expected>>,
    directory: PathBuf,
}
fn unary(wire: &[u8]) -> Result<&[u8]> {
    ensure!(
        wire.len() >= 5
            && wire[0] == 0
            && u32::from_be_bytes(wire[1..5].try_into()?) as usize == wire.len() - 5,
        "expected exact uncompressed unary SDK gRPC request"
    );
    Ok(&wire[5..])
}
fn validate_submit(expected: &mut Expected, wire: &[u8]) -> Result<Value> {
    let body = protos::SubmitPaymentRequest::decode(unary(wire)?)?;
    let participation = expected
        .participation
        .as_ref()
        .context("SDK quote not frozen")?;
    let attempt = expected
        .attempt
        .as_ref()
        .context("actual first round attempt not frozen")?;
    ensure!(
        attempt.attempt_seq == 0 && body.offboard_requests.is_empty(),
        "no alternate attempt or mixed offboard submission allowed"
    );
    let ids = body
        .input_vtxos
        .iter()
        .map(|v| VtxoId::from_bytes(&v.vtxo_id))
        .collect::<Result<Vec<_>, _>>()?;
    ensure!(
        ids == participation
            .inputs
            .iter()
            .map(|v| v.id())
            .collect::<Vec<_>>(),
        "SDK changed original race inputs"
    );
    let signed = body
        .vtxo_requests
        .iter()
        .cloned()
        .map(SignedVtxoRequest::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    ensure!(
        signed.iter().map(|r| r.vtxo.clone()).collect::<Vec<_>>() == participation.outputs,
        "SDK requested policy/value differs from actual frozen quote"
    );
    for (request, input) in body.input_vtxos.iter().zip(participation.inputs.iter()) {
        RoundAttemptAttestation::deserialize(&request.attestation)?.verify(
            attempt.challenge,
            input,
            &signed,
        )?;
    }
    let nonces = signed
        .iter()
        .map(|r| {
            r.nonces
                .iter()
                .map(|n| hex(&n.serialize()))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let frozen = json!({"leg_id":"round","rpc":"SubmitPayment","input_coin_ids":ids.iter().map(|id|id.to_string()).collect::<Vec<_>>(),
        "wire_sha256":retained::hash(wire),"private_checkpoint_sha256":retained::hash(wire),"nonce_retention":"single_process","restart_continuation":false,
        "signing_session_sha256":retained::hash(&serde_json::to_vec(&nonces)?),"input_spends":[],"outputs":[],
        "requested_outputs":participation.outputs.iter().map(|o|json!({"pubkey":o.policy.user_pubkey().to_string(),"amount_sat":o.amount.to_sat()})).collect::<Vec<_>>(),
        "committed_fee_sat":expected.committed_fee_sat,"round_attempt":{"round_seq":attempt.round_seq,"attempt_seq":attempt.attempt_seq},
        "round_output_ids_scope":"not yet funded; collect exact proposal/forfeit/signed output lineage prospectively"});
    ensure!(
        expected.frozen_submit.is_none(),
        "second SDK SubmitPayment would regenerate a signing session"
    );
    expected.frozen_submit = Some(frozen.clone());
    Ok(frozen)
}
/// Called before opening only the selected actor's SDK Wallet. Caller changes
/// only that invocation's in-memory Config clone to transport.endpoint.
pub async fn setup(
    upstream: Channel,
    req: &Request,
    private_root: &Path,
) -> Result<Option<Invocation>> {
    let scenario = req.args["phase_intent"]["scenario"]
        .as_str()
        .context("round race scenario")?;
    ensure!(
        matches!(scenario, "D18" | "D19"),
        "round race scenario differs"
    );
    let frozen = retained::intent(req, scenario)?;
    ensure!(
        req.operation == format!("phase_execute_{}", scenario.to_lowercase()),
        "round phase operation differs"
    );
    let Some(directory) = retained::fence(private_root, req)? else {
        return Ok(None);
    };
    let expected = Arc::new(Mutex::new(Expected::default()));
    let validate_expected = expected.clone();
    let validator: Validator = Arc::new(move |method, wire| {
        if method == "SubmitPayment" {
            return validate_submit(
                &mut *validate_expected
                    .lock()
                    .map_err(|_| anyhow::anyhow!("round capture state poisoned"))?,
                wire,
            );
        }
        // Other money-bearing requests are the real SDK's safety-checked tree,
        // leaf and forfeit steps. Their exact frames stay private for audit;
        // a protocol reply never becomes a financial verdict here.
        Ok(
            json!({"sdk_generated":true,"method":method,"wire_sha256":retained::hash(wire),"independent_phase_lineage_audit_required":true}),
        )
    });
    let limits = HashMap::from([
        ("GetArkInfo".into(), 16),
        ("GetVtxo".into(), 32),
        ("GetVtxos".into(), 8),
        ("GetVtxoStatus".into(), 32),
        ("SetFallback".into(), 16),
        ("SubscribeRounds".into(), 1),
        ("SubmitPayment".into(), 1),
        ("LastRoundEvent".into(), 4),
        ("RegisterVtxoTransactions".into(), 8),
        ("ProvideVtxoSignatures".into(), 16),
        ("RequestLeafVtxoCosign".into(), 16),
        ("RequestForfeitNonces".into(), 1),
        ("ForfeitVtxos".into(), 1),
        ("RoundParticipationStatus".into(), 8),
    ]);
    let gate = Gate::create(
        Plan {
            actor: frozen["actor"].as_str().context("frozen actor")?.into(),
            action_id: req.action_id.clone(),
            intent_sha256: req.args["intent_hash"]
                .as_str()
                .context("intent hash")?
                .into(),
            manifest_sha256: req.args["qualification_manifest_sha256"]
                .as_str()
                .context("manifest hash")?
                .into(),
            expected_server_pubkey: req.expected_server_pubkey.clone(),
            service_prefix: "/bark_server.ArkService/".into(),
            rpc_limits: limits,
            barrier_rpc: "SubmitPayment".into(),
            barrier_requests: 1,
        },
        directory.join("grpc-capture"),
        validator,
    )?;
    let transport = ClientTransport::start(upstream, gate.clone()).await?;
    Ok(Some(Invocation {
        transport,
        gate,
        expected,
        directory,
    }))
}

pub async fn execute(
    wallet: &Wallet,
    rpc: &mut ArkServiceClient<Channel>,
    req: &Request,
    invocation: &Invocation,
    actor: &str,
) -> Result<Value> {
    let scenario = req.args["phase_intent"]["scenario"]
        .as_str()
        .context("round race scenario")?;
    ensure!(
        matches!(scenario, "D18" | "D19"),
        "round race scenario differs"
    );
    let frozen = retained::intent(req, scenario)?;
    retained::negotiate(rpc,req,&invocation.directory).await?;
    let maximum_wait = frozen["context"]["maximum_wait_seconds"]
        .as_u64()
        .unwrap_or(900);
    ensure!(
        (30..=1800).contains(&maximum_wait),
        "round wait must be frozen and bounded before submission"
    );
    ensure!(
        frozen["actor"] == actor && !matches!(actor, "actor-03" | "actor-09" | "actor-10"),
        "round race actor differs"
    );
    ensure!(
        wallet.pending_round_states().await?.is_empty(),
        "pre-existing SDK round must reconcile before isolated race"
    );
    let items = frozen["inputs"].as_array().context("frozen inputs")?;
    let mut inputs = Vec::new();
    let mut keys = Vec::new();
    for item in items {
        let id = VtxoId::from_str(item["coin_id"].as_str().context("input ID")?)?;
        let coin = wallet.get_full_vtxo(id).await?;
        ensure!(
            coin.id() == id
                && coin.user_pubkey().to_string()
                    == item["pubkey"].as_str().context("input key")?
                && Some(coin.amount().to_sat()) == item["amount_sat"].as_u64()
                && retained::hash(&coin.serialize())
                    == item["signed_hash"].as_str().context("input hash")?,
            "actual SDK input differs from frozen independent proof"
        );
        keys.push(wallet.get_vtxo_key(&coin).await?);
        inputs.push(coin);
    }
    let participation = wallet
        .build_refresh_participation(inputs.clone())
        .await?
        .context("SDK cannot build actual refresh from original inputs")?;
    let input = participation
        .total_in()
        .context("SDK input amount overflow")?
        .to_sat();
    let output = participation
        .total_out()
        .context("SDK output amount overflow")?
        .to_sat();
    let fee = input
        .checked_sub(output)
        .context("SDK round inflated value")?;
    ensure!(
        Some(input) == frozen["principal_sat"].as_u64() && fee <= req.maximum_fee_sat,
        "actual SDK round quote exceeds declared principal/fee ceiling"
    );
    for output in &participation.outputs {
        ensure!(
            wallet
                .pubkey_keypair(&output.policy.user_pubkey())
                .await?
                .is_some(),
            "SDK refresh output is not owned by original actor"
        );
    }
    retained::save(
        &invocation.directory.join("sdk-round-participation.json"),
        &serde_json::to_vec(&participation)?,
    )?;
    {
        let mut expected = invocation
            .expected
            .lock()
            .map_err(|_| anyhow::anyhow!("capture state poisoned"))?;
        expected.participation = Some(participation.clone());
        expected.committed_fee_sat = fee;
    }
    let partner = if scenario == "D19" {
        Partner::Offboard(
            super::phase_offboard::prepare(
                wallet,
                rpc,
                req,
                &invocation.directory,
                &inputs,
                &keys,
                fee,
            )
            .await?,
        )
    } else {
        let recipients = frozen["context"]["recipients"]
            .as_array()
            .context("declared registered arkoor recipient")?;
        ensure!(
            !recipients.is_empty(),
            "registered arkoor recipient required"
        );
        let destination =
            PublicKey::from_str(recipients[0]["pubkey"].as_str().context("registered key")?)?;
        let builder = ArkoorPackageBuilder::new_with_checkpoints(
            inputs,
            vec![ArkoorDestination {
                total_amount: Amount::from_sat(input),
                policy: VtxoPolicy::new_pubkey(destination),
            }],
        )?
        .generate_user_nonces(&keys)?;
        let body = protos::ArkoorPackageCosignRequest::from(builder.cosign_request());
        retained::save(
            &invocation.directory.join("arkoor-request.bin"),
            &body.encode_to_vec(),
        )?;
        let ids = items
            .iter()
            .map(|v| v["coin_id"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        let checkpoint = retained::body_checkpoint(&builder, &body, "arkoor", &ids);
        Partner::Arkoor {
            builder,
            keys,
            body,
            checkpoint,
        }
    };
    let partner_checkpoint = partner.checkpoint();
    let ids = items
        .iter()
        .map(|v| v["coin_id"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    // join_next_round stores the real SDK intent, not a manually synthesized
    // SubmitPayment. Nonces will live in the same Wallet/process below.
    let stored = wallet
        .join_next_round(participation, Some(RoundMovement::Refresh))
        .await?;
    let round_state_id = stored.id();
    drop(stored);
    retained::save(
        &invocation.directory.join("sdk-round-state-id.json"),
        &serde_json::to_vec(
            &json!({"round_state_id":round_state_id.to_string(),"committed_fee_sat":fee,"input_coin_ids":ids}),
        )?,
    )?;
    let mut events = wallet.subscribe_round_events().await?;
    let first_attempt_deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    let attempt = loop {
        let event = tokio::time::timeout(
            first_attempt_deadline.saturating_duration_since(std::time::Instant::now()),
            events.next(),
        )
        .await
        .context("no first SDK round attempt before deadline")?
        .context("SDK round stream ended")??;
        evidence(
            req,
            "phase_round_event_observed",
            json!({"trial_id":req.args["trial_id"],"kind":event.kind(),"round_seq":event.round_seq(),"attempt_seq":event.attempt_seq()}),
        )?;
        if let RoundEvent::Attempt(attempt) = event
            && attempt.attempt_seq == 0
        {
            break attempt;
        }
    };
    {
        invocation
            .expected
            .lock()
            .map_err(|_| anyhow::anyhow!("capture state poisoned"))?
            .attempt = Some(attempt.clone());
    }
    let start_event = RoundEvent::Attempt(attempt.clone());
    let round_progress = wallet.progress_pending_rounds(Some(&start_event));
    let arkoor_future = async {
        invocation.gate.wait_prepared().await?;
        let round = invocation
            .expected
            .lock()
            .map_err(|_| anyhow::anyhow!("capture state poisoned"))?
            .frozen_submit
            .clone()
            .context("exact SDK round request not frozen")?;
        let prepared = json!({"trial_id":req.args["trial_id"],"intent_hash":req.args["intent_hash"],"legs":[partner_checkpoint,round]});
        retained::save(
            &invocation.directory.join("preparation.json"),
            &serde_json::to_vec(&prepared)?,
        )?;
        evidence(req, "phase_preparations_frozen", prepared)?;
        invocation.gate.release_once()?;
        let result = partner
            .dispatch(wallet, rpc, req, &invocation.directory)
            .await?;
        Ok::<_, anyhow::Error>(result)
    };
    let (round_result, arkoor_result) = tokio::join!(round_progress, arkoor_future);
    // Both futures have completed or retained their failure artifacts. A normal
    // SDK outer Ok is deliberately not interpreted as successful refresh.
    let result = json!({"round_outer_result":round_result.as_ref().map(|_|"ok").map_err(|e|format!("{e:#}")),"competing_result":arkoor_result.as_ref().map(|r|r.clone()).map_err(|e|format!("{e:#}"))});
    retained::save(
        &invocation.directory.join("initial-results.json"),
        &serde_json::to_vec(&result)?,
    )?;
    round_result?;
    let arkoor_result = arkoor_result?;
    // Only events from the chosen attempt are processed. A new attempt never
    // causes another signing session or SubmitPayment in this invocation.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(maximum_wait);
    for index in 0..240 {
        if std::time::Instant::now() >= deadline {
            break;
        }
        // One actual forfeit request consumes this invocation's signing fence.
        // A lost reply cannot cause a new forfeit nonce or signing attempt.
        if invocation.gate.has_failed()
            || invocation.gate.invoked("ForfeitVtxos")
            || arkoor_result["kind"] == "transport_unknown"
        {
            break;
        }
        if wallet.pending_round_states().await?.is_empty() {
            break;
        }
        let event = match tokio::time::timeout(std::time::Duration::from_secs(15), events.next())
            .await
        {
            Ok(Some(Ok(event))) => event,
            Ok(Some(Err(error))) => {
                retained::save(
                    &invocation
                        .directory
                        .join(format!("stream-error-{index}.json")),
                    &serde_json::to_vec(&json!({"error":format!("{error:#}")}))?,
                )?;
                break;
            }
            Ok(None) => {
                retained::save(
                    &invocation
                        .directory
                        .join(format!("stream-ended-{index}.json")),
                    &serde_json::to_vec(
                        &json!({"event_stream":"ended","financial_outcome":"unknown"}),
                    )?,
                )?;
                break;
            }
            Err(_deadline) => {
                retained::save(
                    &invocation
                        .directory
                        .join(format!("stream-deadline-{index}.json")),
                    &serde_json::to_vec(
                        &json!({"deadline":"no event within15s","financial_outcome":"unknown"}),
                    )?,
                )?;
                let outcome = wallet.sync_pending_rounds().await;
                retained::save(
                    &invocation
                        .directory
                        .join(format!("sdk-confirmation-sync-{index}.json")),
                    &serde_json::to_vec(
                        &json!({"outcome":format!("{outcome:?}"),"new_attempt_event_processed":false}),
                    )?,
                )?;
                if outcome.is_err() {
                    break;
                }
                continue;
            }
        };
        evidence(
            req,
            "phase_round_event_observed",
            json!({"trial_id":req.args["trial_id"],"kind":event.kind(),"round_seq":event.round_seq(),"attempt_seq":event.attempt_seq()}),
        )?;
        if event.round_seq() != attempt.round_seq || event.attempt_seq() != attempt.attempt_seq {
            retained::save(
                &invocation
                    .directory
                    .join(format!("attempt-change-held-{index}.json")),
                &serde_json::to_vec(
                    &json!({"round_seq":event.round_seq(),"attempt_seq":event.attempt_seq(),"no_re_sign_or_retry":true}),
                )?,
            )?;
            let outcome = wallet.sync_pending_rounds().await;
            retained::save(
                &invocation
                    .directory
                    .join(format!("sdk-existing-round-sync-{index}.json")),
                &serde_json::to_vec(
                    &json!({"outcome":format!("{outcome:?}"),"new_attempt_event_processed":false}),
                )?,
            )?;
            if outcome.is_err() {
                break;
            }
            continue;
        }
        wallet.progress_pending_rounds(Some(&event)).await?;
        for state in wallet.pending_round_states().await? {
            ensure!(
                state.id() == round_state_id,
                "SDK unexpectedly created another round intent"
            );
            if let Some(coins) = state.state().output_vtxos() {
                for (position, coin) in coins.iter().enumerate() {
                    let path = invocation.directory.join(format!(
                        "round-signed-{}-{position}.bin",
                        retained::hash(&coin.serialize())
                    ));
                    if !path.exists() {
                        retained::save(&path, &coin.serialize())?;
                    }
                }
            }
        }
    }
    for coin in wallet.all_vtxos().await? {
        let id = coin.vtxo.id();
        if !items
            .iter()
            .any(|item| item["coin_id"].as_str() == Some(id.to_string().as_str()))
        {
            if let Ok(full) = wallet.get_full_vtxo(id).await {
                if full.has_all_witnesses() {
                    let path = invocation.directory.join(format!(
                        "completed-sdk-{}.bin",
                        retained::hash(&full.serialize())
                    ));
                    if !path.exists() {
                        retained::save(&path, &full.serialize())?;
                    }
                }
            }
        }
    }
    Ok(
        json!({"phase_unknown":true,"trial_id":req.args["trial_id"],"competing_reply":arkoor_result,"sdk_round_state_id":round_state_id.to_string(),
        "actual_fee_sat":Value::Null,"committed_round_fee_sat":fee,"reason":"independent confirmed round/forfeit/competing-path and fee audit required; SDK outer progress success is insufficient","restart_continuation":false,"customer_traffic_credit":false}),
    )
}

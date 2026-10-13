//! Two genuine SDK delegated participations over one frozen signed input set.
//! Exact SDK frames/attestations are fsynced before either request is forwarded.
//! Arrival order is observed, never inferred from client leg names. Completion
//! and once-only financial arbitration require independent evidence collectors.
use server_rpc::TryFromBytes;
use super::{
    Request, evidence, phase_protocol as retained,
    phase_transport::{ClientTransport, Gate, Plan, Validator},
};
use anyhow::{Context, Result, ensure};
use ark::attestations::DelegatedRoundParticipationAttestation;
use ark::{ProtocolEncoding, VtxoId, VtxoRequest};
use bark::{Wallet, round::RoundParticipation, subsystem::RoundMovement};
use prost::Message;
use serde_json::{Value, json};
use server_rpc::protos;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex},
};
use tonic::transport::Channel;

#[derive(Default)]
struct Expected {
    quotes: Vec<(RoundParticipation, u64)>,
    frozen: Vec<Value>,
    scheduled_height: u32,
}
pub struct Invocation {
    pub transport: ClientTransport,
    gate: Arc<Gate>,
    expected: Arc<Mutex<Expected>>,
    directory: PathBuf,
}
fn validate(expected: &mut Expected, wire: &[u8]) -> Result<Value> {
    ensure!(
        wire.len() >= 5
            && wire[0] == 0
            && u32::from_be_bytes(wire[1..5].try_into()?) as usize == wire.len() - 5,
        "exact unary SDK delegated request required"
    );
    let body = protos::RoundParticipationRequest::decode(&wire[5..])?;
    ensure!(
        body.scheduled_height == Some(expected.scheduled_height),
        "SDK changed frozen schedule"
    );
    let outputs = body
        .vtxo_requests
        .iter()
        .cloned()
        .map(VtxoRequest::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    let index = expected
        .quotes
        .iter()
        .position(|(quote, _)| quote.outputs == outputs)
        .context("SDK output quote was not independently frozen")?;
    let (quote, fee) = &expected.quotes[index];
    let leg = if index == 0 { "first" } else { "replacement" };
    ensure!(
        !expected.frozen.iter().any(|v| v["leg_id"] == leg),
        "SDK delegated submission retry forbidden"
    );
    let ids = body
        .input_vtxos
        .iter()
        .map(|v| VtxoId::from_bytes(&v.vtxo_id))
        .collect::<Result<Vec<_>, _>>()?;
    ensure!(
        ids == quote.inputs.iter().map(|v| v.id()).collect::<Vec<_>>(),
        "SDK delegated input set changed"
    );
    for (request, input) in body.input_vtxos.iter().zip(&quote.inputs) {
        DelegatedRoundParticipationAttestation::deserialize(&request.attestation)?
            .verify(input, &outputs)?;
    }
    ensure!(
        body.unblinded_mailbox_id.is_some(),
        "SDK delegated delivery mailbox missing"
    );
    let frozen = json!({"leg_id":leg,"rpc":"SubmitRoundParticipation","input_coin_ids":ids.iter().map(|id|id.to_string()).collect::<Vec<_>>(),
        "wire_sha256":retained::hash(wire),"private_checkpoint_sha256":retained::hash(wire),"scheduled_height":expected.scheduled_height,
        "requested_outputs":outputs.iter().map(|o|json!({"pubkey":o.policy.user_pubkey().to_string(),"amount_sat":o.amount.to_sat()})).collect::<Vec<_>>(),
        "committed_fee_sat":fee,"input_spends":[],"outputs":[],"signing_scope":"SDK delegated input attestations; later forfeit nonces stay in the same process",
        "arrival_order_scope":"leg name identifies quote only; actual server processing order requires recorded request/reply and participation states"});
    expected.frozen.push(frozen.clone());
    Ok(frozen)
}
/// Before Wallet.open: select only this invocation's cloned endpoint. The
/// caller retains the original physically pinned/authenticated upstream Channel.
pub async fn setup(
    upstream: Channel,
    req: &Request,
    private_root: &Path,
) -> Result<Option<Invocation>> {
    let frozen = retained::intent(req, "D26")?;
    ensure!(
        req.operation == "phase_execute_d26",
        "delegated phase operation differs"
    );
    let Some(directory) = retained::fence(private_root, req)? else {
        return Ok(None);
    };
    let height: u32 = frozen["context"]["scheduled_height"]
        .as_u64()
        .context("explicit scheduled height")?
        .try_into()?;
    let expected = Arc::new(Mutex::new(Expected {
        scheduled_height: height,
        ..Default::default()
    }));
    let captured = expected.clone();
    let validator: Validator = Arc::new(move |method, wire| {
        if method == "SubmitRoundParticipation" {
            return validate(
                &mut *captured
                    .lock()
                    .map_err(|_| anyhow::anyhow!("delegated capture state poisoned"))?,
                wire,
            );
        }
        Ok(
            json!({"sdk_generated":true,"method":method,"wire_sha256":retained::hash(wire),"independent_phase_audit_required":true}),
        )
    });
    let gate = Gate::create(
        Plan {
            actor: frozen["actor"].as_str().context("actor")?.into(),
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
            rpc_limits: HashMap::from([
                ("GetArkInfo".into(), 8),
                ("SetFallback".into(), 4),
                ("GetVtxoStatus".into(), 32),
                ("RegisterVtxoTransactions".into(), 2),
                ("SubmitRoundParticipation".into(), 2),
            ]),
            barrier_rpc: "SubmitRoundParticipation".into(),
            barrier_requests: 2,
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
    req: &Request,
    invocation: &Invocation,
    actor: &str,
) -> Result<Value> {
    let frozen = retained::intent(req, "D26")?;
    ensure!(
        frozen["actor"] == actor && !matches!(actor, "actor-03" | "actor-09" | "actor-10"),
        "delegated actor differs"
    );
    ensure!(
        wallet.pending_round_states().await?.is_empty(),
        "existing SDK state must reconcile before isolated replacement"
    );
    let mut inputs = Vec::new();
    for item in frozen["inputs"].as_array().context("frozen inputs")? {
        let id = VtxoId::from_str(item["coin_id"].as_str().context("input id")?)?;
        let coin = wallet.get_full_vtxo(id).await?;
        ensure!(
            coin.user_pubkey().to_string() == item["pubkey"].as_str().context("key")?
                && Some(coin.amount().to_sat()) == item["amount_sat"].as_u64()
                && retained::hash(&coin.serialize())
                    == item["signed_hash"].as_str().context("signed hash")?,
            "SDK delegated input differs from frozen proof"
        );
        inputs.push(coin);
    }
    let height_u32 = invocation
        .expected
        .lock()
        .map_err(|_| anyhow::anyhow!("delegated state poisoned"))?
        .scheduled_height;
    let observed_tip = wallet.chain().tip().await?;
    ensure!(
        height_u32 > observed_tip.to_u32(),
        "scheduled replacement must remain in the future before either request"
    );
    let height = height_u32.into();
    retained::save(
        &invocation
            .directory
            .join("chain-tip-before-submission.json"),
        &serde_json::to_vec(
            &json!({"observed_tip":observed_tip.to_u32(),"scheduled_height":height_u32}),
        )?,
    )?;
    let first = wallet
        .build_scheduled_refresh_participation(inputs.clone(), height)
        .await?
        .context("first real SDK refresh quote unavailable")?;
    let second = wallet
        .build_scheduled_refresh_participation(inputs, height)
        .await?
        .context("replacement real SDK refresh quote unavailable")?;
    ensure!(
        first.outputs != second.outputs,
        "SDK must generate two distinct genuine refresh destination keys"
    );
    let mut quotes = Vec::new();
    for (index, quote) in [&first, &second].into_iter().enumerate() {
        let input = quote.total_in().context("input overflow")?.to_sat();
        let fee = input
            .checked_sub(quote.total_out().context("output overflow")?.to_sat())
            .context("SDK inflated delegated quote")?;
        ensure!(
            Some(input) == frozen["principal_sat"].as_u64() && fee <= req.maximum_fee_sat,
            "delegated quote violates whole-trial fee cap"
        );
        for output in &quote.outputs {
            ensure!(
                wallet
                    .pubkey_keypair(&output.policy.user_pubkey())
                    .await?
                    .is_some(),
                "SDK delegated refresh changes actor ownership"
            )
        }
        retained::save(
            &invocation.directory.join(format!("sdk-quote-{index}.json")),
            &serde_json::to_vec(quote)?,
        )?;
        quotes.push((quote.clone(), fee));
    }
    invocation
        .expected
        .lock()
        .map_err(|_| anyhow::anyhow!("delegated state poisoned"))?
        .quotes = quotes;
    // The pinned SDK permits outstanding participations over the same inputs;
    // the server replaces held input records. We do not patch its state machine.
    let first_future =
        wallet.join_delegated_round(first, Some(RoundMovement::Refresh), Some(height));
    let second_future =
        wallet.join_delegated_round(second, Some(RoundMovement::Refresh), Some(height));
    let release = async {
        invocation.gate.wait_prepared().await?;
        let mut legs = invocation
            .expected
            .lock()
            .map_err(|_| anyhow::anyhow!("delegated capture poisoned"))?
            .frozen
            .clone();
        legs.sort_by_key(|leg| if leg["leg_id"] == "first" { 0 } else { 1 });
        let checkpoint = json!({"trial_id":req.args["trial_id"],"intent_hash":req.args["intent_hash"],"legs":legs});
        retained::save(
            &invocation.directory.join("preparations.json"),
            &serde_json::to_vec(&checkpoint)?,
        )?;
        evidence(req, "phase_delegated_preparations_frozen", checkpoint)?;
        invocation.gate.release_once()
    };
    let (one, two, released) = tokio::join!(first_future, second_future, release);
    let mut states = Vec::new();
    for (leg, result) in [("first", one), ("replacement", two)] {
        let observed = match result {
            Ok(stored) => {
                let state = json!({"kind":format!("{:?}",stored.state().flow_kind()),"scheduled_height":stored.state().scheduled_height().map(|h|h.to_u32()),"unlock_hash":stored.state().unlock_hash().map(|h|h.to_string()),"sdk_database_persisted":true,"opaque_sdk_state_not_serialized":true});
                let id = stored.id();
                let unlock = stored.state().unlock_hash().map(|h| h.to_string());
                retained::save(
                    &invocation.directory.join(format!("sdk-{leg}-state.json")),
                    &serde_json::to_vec(&state)?,
                )?;
                json!({"leg_id":leg,"round_state_id":id.to_string(),"unlock_hash":unlock,"kind":"sdk_delegated_state_persisted","reply_at_ns":retained::now_ns(),"forfeit_sent_claim":false})
            }
            Err(error) => {
                json!({"leg_id":leg,"kind":"sdk_delegated_error","error":format!("{error:#}"),"reply_at_ns":retained::now_ns(),"financial_outcome_unknown":true})
            }
        };
        retained::save(
            &invocation.directory.join(format!("sdk-{leg}-result.json")),
            &serde_json::to_vec(&observed)?,
        )?;
        evidence(
            req,
            "phase_delegated_sdk_result",
            json!({"trial_id":req.args["trial_id"],"leg_id":leg,"kind":observed["kind"],"round_state_id":observed["round_state_id"],"unlock_hash":observed["unlock_hash"],"financial_outcome_unknown":true}),
        )?;
        states.push(json!({"leg_id":leg,"kind":observed["kind"],"round_state_id":observed["round_state_id"],"unlock_hash":observed["unlock_hash"],"protected_result_sha256":retained::hash(&serde_json::to_vec(&observed)?)}));
    }
    retained::save(
        &invocation.directory.join("barrier-result.json"),
        &serde_json::to_vec(
            &json!({"released":released.is_ok(),"error":released.err().map(|e|format!("{e:#}"))}),
        )?,
    )?;
    // No automatic round sync, re-sign, forfeit, or resend here. The caller must
    // collect both exact unlock-hash statuses and qualify later SDK progression.
    Ok(
        json!({"phase_unknown":true,"actual_fee_sat":Value::Null,"scenario":"D26","customer_traffic_credit":false,"states":states,"captured_transport_failure":invocation.gate.has_failed(),
        "required_audit":"two exact participation states, replacement ordering, prospective forfeits, confirmed signed successors and one conserved principal/fee identity"}),
    )
}

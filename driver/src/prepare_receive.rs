//! Stop one genuine native receive at its persisted pre-preimage checkpoint.
use std::str::FromStr;

use anyhow::{Context, Result, ensure};
use ark::{VtxoId, lightning::{Bolt11InvoiceExt, PaymentHash}};
use bark::actions::{Advance, AdvanceError, DriveMode, WalletAction, WalletActionCheckpoint, WalletActionId};
use bark::actions::lightning::receive::{LightningReceive, Progress};
use bark::Wallet;
use serde_json::{Value, json};

#[derive(Clone)]
struct PrepareReceive(LightningReceive);

impl From<PrepareReceive> for WalletActionCheckpoint {
    fn from(action: PrepareReceive) -> Self { action.0.into() }
}

// Preserve the native checkpoint representation, action ID, handlers and SDK
// lock. Only the executor's continuation is changed: never take a second step.
fn park_next(advance: Advance<LightningReceive>) -> Advance<PrepareReceive> {
    match advance {
        Advance::Next(state) => Advance::Park { state: PrepareReceive(state), wake_after: None, error: None },
        Advance::Park { state, wake_after, error } => Advance::Park { state: PrepareReceive(state), wake_after, error },
        Advance::Retry { state, error } => Advance::Retry { state: PrepareReceive(state), error },
        Advance::Done => Advance::Done,
        Advance::Failed(error) => Advance::Failed(error),
    }
}

#[async_trait::async_trait]
impl WalletAction for PrepareReceive {
    fn id(&self) -> WalletActionId { self.0.id() }
    fn pending_balance_vtxo_ids(&self) -> Vec<VtxoId> { self.0.pending_balance_vtxo_ids() }

    async fn advance(self, wallet: &Wallet) -> Result<Advance<Self>, AdvanceError> {
        if !matches!(self.0.progress, Progress::AwaitingPayment) {
            return Err(AdvanceError::Retry(anyhow::anyhow!("prepare_receive requires AwaitingPayment")));
        }
        self.0.advance(wallet).await.map(park_next)
    }

    async fn on_retry(self, wallet: &Wallet, error: anyhow::Error) -> Advance<Self> {
        park_next(self.0.on_retry(wallet, error).await)
    }
    async fn on_abort(self, wallet: &Wallet, error: anyhow::Error) -> Advance<Self> {
        park_next(self.0.on_abort(wallet, error).await)
    }
}

pub(crate) async fn execute(wallet: &Wallet, req: &crate::Request) -> Result<Value> {
    ensure!(std::env::var_os("BARK_DOUBLE_DRIVE_ACTIONS").is_none(),
        "prepare_receive requires BARK_DOUBLE_DRIVE_ACTIONS absent");
    let hash = PaymentHash::from_str(req.args["payment_hash"].as_str().context("payment_hash required")?)?;
    let original = wallet.lightning_receive_checkpoint(hash).await?.context("existing receive checkpoint required")?;
    ensure!(matches!(original.progress, Progress::AwaitingPayment),
        "only the original AwaitingPayment checkpoint may be advanced");
    let invoice_amount = original.invoice.get_payment_amount(None)?;
    let quote = wallet.estimate_lightning_receive_fee(invoice_amount).await?;
    ensure!(quote.fee.to_sat() <= req.maximum_fee_sat, "receive quote exceeds invocation fee budget");

    wallet.drive_action(PrepareReceive(original.clone()), DriveMode::UntilParkOrDone).await?;
    // Reload through the SDK persister-backed API, never infer readiness from a
    // reply or a locally constructed flag. No claim/sync/daemon runs afterward.
    let persisted = wallet.lightning_receive_checkpoint(hash).await?.context("receive checkpoint disappeared")?;
    let mut expected = original;
    expected.progress = persisted.progress.clone();
    ensure!(persisted == expected, "receive identity or retry budget changed");
    let Progress::HtlcsReady(ref htlcs) = persisted.progress else {
        anyhow::bail!("one native receive advance did not reach HtlcsReady; no second advance performed");
    };
    ensure!(!htlcs.vtxo_ids.is_empty() && htlcs.vtxo_ids.len() <= 1024, "invalid grant inventory bound");
    let mut grants = Vec::with_capacity(htlcs.vtxo_ids.len());
    let mut received = 0u64;
    for id in &htlcs.vtxo_ids {
        let full = wallet.get_full_vtxo(*id).await?;
        received = received.checked_add(full.amount().to_sat()).context("grant value overflow")?;
        grants.push(json!({"id":id.to_string(), "amount_sat":full.amount().to_sat(),
            "expiry_height":full.expiry_height().to_u32(),
            "signed_vtxo":crate::hex(&bark_sim_driver::public_coin::encode(&full)?),
            "proof_encoding":"ark-public-authorization-v1"}));
    }
    let prepared_fee = invoice_amount.to_sat().checked_sub(received).context("grants exceed invoice amount")?;
    ensure!(prepared_fee <= req.maximum_fee_sat, "prepared receive exceeds invocation fee budget");
    Ok(json!({"payment_hash":hash.to_string(), "checkpoint":"HtlcsReady",
        "movement_id":htlcs.movement_id.to_string(), "grant_ids":htlcs.vtxo_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "grants":grants, "invoice_amount_sat":invoice_amount.to_sat(), "grant_amount_sat":received,
        "prepared_fee_sat":prepared_fee, "actual_fee_sat":Value::Null,
        "binding":crate::fallback_binding(wallet).await?}))
}

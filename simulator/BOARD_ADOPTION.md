This phase admits only actor-01 snapshot and sync with args{} and reserve0, to
advance its one original confirmed Board checkpoint. It never admits a new
Board, Arkoor send, Lightning, round, exit or funding action. Source-only controls
are not a native observation or a payment.

The exact SDK board_psbt persists board.<funding txid>.<vout>, then best-effort
drives Broadcasting -> Confirming. A successful Board driver reply is checkpoint
acceptance. After the server's required confirmations, sync_pending_boards calls
register_board_vtxo, unlocks that VTXO and finishes its original movement. With
run_daemonfalse, a subsequent admitted sync must drive this original checkpoint.
The checkpoint is never recreated or re-signed. Near-expiry salvage is refused:
expiry must exceed current tip plus the actual wallet_runtime_parameters margin
and an additional six-block observation buffer. BARK_ environment overrides are
refused in this phase; the actual driver/config hashes and existing Lease bind
all wallet observations. No signing keymap or seed is inspected.

collect_board_adoption_sources authenticates the original Board plan/action,
proposal, quote, runtime parameters and native public VTXO proof. Core must show
the original declared confirmed50k input consumed by the exact proposal, exactly
20k in the signed Board anchor and the rest in one derived actor-01 change
output, minus the exact miner fee. The old complete cash source is the opening
inventory, not current readiness. All six descriptor wallets are scanned in one
bounded current-frontier scan, with full bounded current-mempool coverage and
fresh actual bank source. The 20k anchor is checked separately against Core and
the public signed VTXO chain: it is not invented BDK ownership. Cash plus anchor
is the physical asset total, equal to opening665454 minus funding and Board
miner fees. The net VTXO is one liability, never another physical asset. The
Board service charge is recorded separately from physical mining loss.

Actual private SQLite reads allow only one original Board VTXO/movement and its
Confirming checkpoint (or the completed, Spendable result); all other persisted
monetary paths must be empty. The complete nineteen-table server frontier may
contain only that Board anchor, its pending/registered leaf and exact owned key
binding, alongside the original three immutable records. No journal allocation,
carrier, round, pool, Lightning, offboard or unrelated historical source is
accepted. A later fresh same-process startup source supplies current operator
cash eligibility, preserving all ineligible capital and the urgent fee reserve.

record_board_adoption_readiness produces the separate scoped readiness only
from those checked facts. It binds the original Board action and actor-01; actual
preflight rechecks the current native economic projection and near-expiry guard
before each serial original zero-fee sync/snapshot intent. Completion still
requires a real snapshot: Board pending0, net balance Spendable, original
movement successful, exact confirmed cash change, and independent server state.
A sync response can log partial failures and is not adoption evidence by itself.

After adoption the practical next monetary dependency is a separately scoped
Arkoor proof: authenticated recipient address/account child, unexpired native
Spendable input, server Spendable/admitted state, no pending checkpoint and
actual complete backing/remaining cash. The existing sender preregisters input
chains, cosigns, registers output chains, delivers to the mailbox and finalizes
input debit/change. The recipient must actually sync and snapshot its received
coin; a sender success alone is not receiver adoption. No Arkoor is admitted by
this phase.

Practical existing API sequence after the genuine Board reply:

```python
# Existing read-only public proof retry and original-outcome reconciler.
await retry_public_candidates(store, config.proof_command, limit=8)
await unknown_outcomes.collect(store, config, chain=chain)
await fees.collect(store, chain)
# No new Board or monetary operation is invoked by those collectors.
source = await collect_board_adoption_sources(
    store, config, chain, bank_rpc,
    cash_source_sequence=original_pre_board_cash_source_sequence,
    current_startup_path=actual_current_public_startup_path,
)
# Owner separately refreshes/verifies its same-process public startup observation.
ready = record_board_adoption_readiness(
    store, config, chain, source_sequence=source['source_sequence'],
    runtime_source_sequence=actual_verified_runtime_sequence,
    current_startup_path=actual_current_public_startup_path,
)
# Attach readiness to a genuine same-tip observer snapshot, then use the existing
# sole Engine for one queued actor-01 snapshot or sync at a time, args{}, fee0.
```

If the original action is outcome_unknown, the existing original-outcome
reconciler must first prove it from the retained original reply/proposal,
independent public coin proof and exact confirmed Core transaction. The new
producer does not relabel unknown outcomes or issue retries. A Board reply with
feeNULL normally becomes completed with feeNULL in the existing Engine; it is
not a confirmed miner fee or a registered/spendable VTXO.

The actual signed Core weight and vsize are checked against the independently
observed20sat/vB limit using integer multiplication; they are not inferred from
the stripped unsigned proposal. All physical loss is the actual miner fee. The
separate actual Board service transfer may consume the declared customer fee
budget, but never reduces the conserved physical asset total a second time.

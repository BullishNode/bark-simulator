This phase admits only `sync`, `snapshot`, and `address` for the three original
customers, with empty arguments and fee reservation0. Board, Ark sends,
Lightning, refresh, exits, claims, progression, funding and raw operations remain
refused. Its source proof is not permission to reuse cash-only accounting after
an Ark liability appears.

The SDK sync path can drive monetary work: the native driver checks/claims
pending Lightning receives, calls `Wallet::sync`, progresses pending rounds,
then syncs the onchain wallet. `Wallet::sync` includes pending boards, offboards,
Ark sends, Lightning, force-exit/recovery and mailbox work. SDK5e returns without
driving those actions when their persisted action/VTXO/round inventories are
empty. `sync_onchain` updates the BDK graph; it does not prepare or sign a spend.
The source must establish the empty inventories, rather than infer them from
the name “sync.” Public fallback/key binding signatures are still possible.

`collect_fresh_cash_sources` reads the original immutable funding plan and unique
independently confirmed funding/cost events, rechecks that transaction through
Core, and reconstructs the six-member closing treasury. A full bounded public
descriptor scan must equal the original unspent bank inputs plus the exact five
funding outputs and at most one bank-owned change output. Every current output
must remain confirmed and unspent with the mempool included. Complete bank
observations, the bounded current-mempool fixed point, and the exact original
empty nineteen-table server frontier exclude unaccounted cash/pending/Ark/LN
state. Customer BDK graphs may still be stale: actual confirmed cash comes from
independent Core and original public descriptor provenance.

All three actual private customer SQLite files are opened read-only while this
process holds the existing wallet-root Lease. Schema43 and every persisted
economic table are checked. VTXOs/states, wallet action checkpoints, round
states, pending/settled Lightning, paid invoices, pending boards, movements and
exit state must be empty. Unknown nonmetadata `bark_` tables must also be empty;
no row payload, signing keymap or mnemonic is read. The root/config/binary hashes
are rechecked. Only original completed fee0 create/sync/snapshot/address calls
with empty args may exist; previous sync evidence must contain no Ark movements
or Lightning receives. Unknown or monetary histories hold the phase.

The collector records actual source facts, without invoking a wallet.
`record_fresh_cash_readiness` then requires fresh same-process loaded-runtime
evidence and current owning rounds/watchman inventories at the same Core tip,
with exact descriptors/scripts/amounts and no reservations or pending parents.
Every operator coin remains conserved; only native eligible, mature and trusted
coins count toward available fee funding. The eligible subset must cover all
remaining ordinary and urgent budgets, including the protected urgent reserve. It rechecks conserved closing assets, the unique funding fee,
predeclared fee paths/budgets and current fee estimate, and rereads customer
economic counts after expensive scans. Missing, stale, mismatched or unexplained
data refuses the proof. The normal Engine remains the sole wallet dispatcher.

The readiness event carries `operation_scope=['sync','snapshot','address']` and
`client_action_scope={actors:<the exact three>, operations:<same list>,
maximum_fee_sat:0, args:{}}`. Preflight verifies the actual original dispatched
action id, actor, operation, args, state and fee. An Engine readiness probe may
check these declared operations without invoking a wallet; a funding-only source
still admits no wallet operation. Existing envelopes without these restrictions
retain their previous policy.

These sources are specific to the finite fresh treasury. A later Board/Ark
phase needs its own actual backing, ownership, pending-action and liability
proof. Synthetic controls do not qualify any native source, payment or live run.

Source-only API (the caller holds the existing Engine wallet-root Lease):

```python
source = await collect_fresh_cash_sources(store, config, chain, bank_rpc)
# The owner separately refreshes its public loaded-runtime observation after
# the long Core scan, then verifies it through runtime_startup. No admin call
# or configuration mutation is made by either source function.
ready = record_fresh_cash_readiness(
    store, config, chain, source_sequence=source["source_sequence"],
    runtime_source_sequence=actual_verified_runtime_sequence,
    current_startup_path=actual_current_public_startup_path,
)
# Owner attaches ready["operating_readiness_sequence"] to a genuine observer
# snapshot at the same tip; existing Engine dispatches its serial queued intents.
```

A successful sync response alone does not prove BDK convergence: the exact driver
can log partial SDK failures and still return. The next monetary phase must read
actual native snapshots and compare their cash/Ark state against independent
Core; this proof never substitutes imported balance math for those snapshots.
An optional first-Board scope is validated by its separate producer and bound
to one original queued action, rather than inheriting this cash permission.

This producer opens one exact first Board from the finite cash cohort. It does
not account for a resulting Ark tree or authorize a second monetary action.

While paused, call `declare_first_board_plan(store, declaration)` with exactly:

```json
{"id":"finite-first-board","pins":"the existing financial pins object",
 "boundary_id":"the existing boundary ID",
 "board_actions":{"actor-01":"first-board-01","actor-02":"first-board-02","actor-04":"first-board-04"},
 "amount_sat":20000,"maximum_fee_sat":4000}
```

`pins` above is an object, not a string. All three IDs are immutable, declared
before any Board intent. This implementation admits only one of those IDs. It
refuses further admission after any Board attempt, including failure, unknown
outcome or completion. The remaining IDs do not grant future permission.

After the actual five-output funding transaction confirms and its exact miner
cost is independently verified, use the existing cash-only Engine admission to
complete three SDK syncs, then three snapshots. A sync's success response alone
does not establish convergence. Each original snapshot must follow its actor's
original post-confirmation sync, show an empty Ark balance and economic state,
and contain the exact independently observed 50,000 sat confirmed mature UTXO.
Native confirmed and trusted-spendable balances must both be 50,000 sat; pending
transactions, parents and unresolved source gaps must be empty.

Then collect fresh six-wallet cash sources and record cash readiness through
`fresh_cash_readiness`. The independent source must follow all three snapshots.
Refresh the actual startup/runtime receipt and pass its current artifact path.
Before queuing any Board, call:

```python
result = record_first_board_readiness(
    store, config, chain, cash_readiness_sequence=cash_sequence,
    current_startup_path=current_startup_path, actor='actor-01')
```

The receipt reuses original source identities, enforces full cash conservation
of 665,454 sat less the actual funding miner fee, rechecks client economic SQLite
state and independent Core UTXOs, and protects ordinary 60,000 sat and urgent
15,000 sat budgets. Ordinary holds cover the funding actual cost, three 4,000 sat
Board total fees, and three 10,000 sat normal expiry carriers. Only actual
eligible operator money backs those remaining budgets. Rounds money that is not
yet trusted remains conserved without being counted as eligible.

Attach `result['operating_readiness_sequence']` to the actual current financial
snapshot. Queue only the declared ID for the selected actor, `operation='board'`,
`args={'amount_sat':20000}`, fee reservation 4,000 sat. The existing Engine and
operating-limit preflight call `validate_board_action_scope` with the actual
dispatched reservation. A readiness probe with no action ID never dispatches.
The validator binds original immutable intent/dispatch events and rejects
another actor, regenerated ID, changed amount, changed fee, concurrency and
unresolved work. No new dispatcher exists.

The pinned client enforces a hard **total** Board fee limit of 4,000 sat including
its proposed miner and service fee. This build does not enforce a client fee
rate cap. The producer separately observes Core's target-three fee estimate at
at most 20 sat/vB immediately before admission, records that distinction, and
requires an audit of the original native quote and actual independently
observed transaction fee after the response. A contradiction holds all further
exposure. The server's downstream estimator ceiling is a separate setting.
Board submission is not confirmation or proof of a resulting VTXO amount.

Focused tests are synthetic source/control tests. They earn no live transaction,
native compatibility, full production, Lightning, claim, refresh or later-tree
accounting credit.

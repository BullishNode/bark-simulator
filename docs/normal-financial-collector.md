# Normal financial source collection

An Engine that requires financial qualification also requires a fresh normal
source collection. Bootstrap creation and an independently declared exploratory
scope retain their existing admission checks. An unprofiled historical campaign
does not acquire a new financial permission through this interface.

The admitted launcher supplies a source-qualified, in-process dependency:

```python
Engine(config, store, financial_source_collector=collector)

async def collector(store, config, chain, snapshot, observation):
    # Authenticate and independently verify the actual financial sources.
    # Return the sequence of the resulting new readiness event.
    ...
```

This is the same contract for `two_step_per_key`, `direct_xpub`, and
`direct_per_key`. There is no observer-selected module, payment-body option,
external completeness switch, or default producer. The actual collector and its
private proof tools require their own source and runtime qualification. Installing
this hook does not qualify an adapter. A missing or refusing adapter holds normal
financial dispatch.

The Engine generates `observation` with a unique `id`, `started_at`, immutable
architecture profile, full `financial_pins`, `boundary_id`, and the independently
observed `height` and `tip_hash`. The collector includes that exact object as
`source_observation` in its **new** `financial_operating_readiness` event and
returns its integer sequence. A Boolean, partial response, historical event,
changed context, or stale/future observation is refused.

The collector must first verify exhaustive declared member and asset discovery,
original customer liabilities and backing, all historical/current monetary flows
and costs, actual signed fee enforcement and cumulative native budgets, and
current R/F and unreserved fee liquidity. A native fee-policy import or an empty
row count alone is not that proof. Full paths, witnesses, authentication material,
and other private originals stay in the private evidence pipeline; journal events
and Engine snapshots contain only checked public projections and their hashes.

The hook brackets collection with the independent chain identity and tip, checks
the new source event against the declared limits, and journals its exact event
hash in `normal_financial_source_collected`. It attaches both event sequences to
the snapshot only after that bracket succeeds. Observer-provided readiness IDs
are removed. The normal preflight checks the resulting fresh collection binding
alongside its existing affordability, capital, fee, ownership and scope guards.

Each Engine observation collects again. It does not refresh the timestamp of an
old proof. Partial capture remains diagnostic and cannot replace the collection.
Real fee quotes remain real even above a quiet ceiling: the existing per-operation
preflight decides affordability, including separately bounded urgent paths. No
global minimum over unrelated path ceilings is applied by the hook.

A failed collector may leave its original source evidence in the journal. Its
unaccepted readiness event is never attached to an Engine snapshot or credited
as qualified time. Collectors do not open wallets, sign, dispatch, retry unknown
financial outcomes, reset history, renew budgets, or change deployment pins.

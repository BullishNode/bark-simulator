# Bounded native public-Signet load phases

Use fresh named campaigns and genuine native wallets on the already admitted
long-lived product endpoint. Existing two-wallet traffic and short expiry actors
retain their own wallets, journals, configuration and source pins.

The first cohort has 12 wallets, at most three concurrent disjoint actor pairs,
60 intended 1,000-sat transfers and a ten-second minimum batch interval. A later
50-wallet cohort uses at most five concurrent disjoint pairs. These are bounded
workload proposals; no throughput or scalability result exists until actual sends
are independently reconciled and timed.

The [funded scale follow-up](signet-funded-scale-proposal-20261017.md) proposes
cumulative 50/200/500 cohorts. The controller's new explicit bounds are 5/10/20
disjoint concurrent pairs and at most 1,000/1,800/7,200 transfers respectively;
the original 12-wallet defaults remain. Use `--funding-sat-per-actor 40000` only
in a newly admitted phase. `--window-seconds` bounds how long new batches can be
dispatched after the first batch; reaching it before completing the declared
count holds an incomplete campaign. It is not payment qualification or a minimum
elapsed-time requirement. Existing campaign parameters cannot be edited in place.

Before each new board, the controller now checks the exact confirmed Core
outpoints/scripts/amounts against a fresh native on-chain inventory. Undeclared
extra coins are rejected. The 40,000-sat allocation bounds a 30,000-sat board plus
10,000 sat combined fee/remaining-output capacity. Actual board miner fees are
calculated from original Core inputs/outputs; above 1,000 sat is a warning, not
an invented fee cap or guaranteed reserve. Other outputs are not automatically
called owned change. There is no native quote/max-fee API in this path.

`simulator.signet_load_phase.import_load_window` cold-copies completed non-absent
actors into a separate new journal after the original runner is dead and its STOP
and released lock are verified. It archives the old journal/wallets, pins copied
wallet configurations and retains original creation heights and native final
registrations/coins. Its allowed handoffs are 50 to 50/200 and 200 to 500.
`prepare` reads the existing actors through the actual new CLI without create
acknowledgements; their new funding request is zero. New native admission must
match the original server identity, authenticated registrations and final coins.
Any partial copy remains held for explicit reconciliation. Root must admit the
actual paired runtime and perform its independent cold server backup/deployment.

The funding request groups only new actors into at most 90-output batches, each
with a 10,000-sat maximum miner fee proposal. Root must preflight each actual
PSBT's inputs, outputs and fee; the recipient bound does not guarantee its fee.
At 3 sat/vB, one 150/300-output funding transaction would exceed that inherited
ceiling. Every batch has its own original durable intent and single broadcast.

Each actor receives at most 100,000 sat and boards 30,000 sat. Explicit wallet
configuration sets refresh threshold 144, exit margin 12, and
`fallback_fee_rate = 750` sat/kWu (3 sat/vB). The latter is Second's supported
fallback when its fee source fails, rather than a forced fee estimate. Actual
transaction fees must be measured from Core. Root dispatches one journaled funding
batch after checking actual native addresses; the proposed treasury rate is
3 sat/vB with a 10,000-sat maximum batch fee.

## Preparation and execution

`simulator.signet_load` uses the same exact durable native CLI journal. With private
configuration and the same exact runtime-pin schema used by the phase handoff:

```sh
umask 077
python -m simulator.signet_load --state NEW_PRIVATE_STATE \
  --config PRIVATE_CAMPAIGN_CONFIG --runtime-pins PRIVATE_RUNTIME_PINS \
  --wallets 12 --concurrency 3 --transfers 60 prepare > PRIVATE_FUNDING_REQUEST
```

This genuinely creates each actor, captures its authenticated payout registration,
funding address, Ark address and original creation height, and checks the actual
advertised server profile. It issues no board, transfer or treasury request. An
unknown native result holds the phase and cannot replay its intent. Retain this
preparation controller commit explicitly when recording a subsequent workload
controller milestone.

After root dispatches the single frozen batch, reconcile its actual confirmed
outpoints with the existing `funding_receipt` function. `Load.admit()` boards each
actor once, waits for actual native spendability, then requires all signed coin
paths and whole-cohort confirmed backing before storing its admission evidence.
The `admit` CLI command provides the same operation. Funding or CLI board
acknowledgements cannot stand in for genuine native board admission.

Run `Load.advance_batch(monitor_pids=...)` under one external runner file lock.
Its frozen schedule limits concurrency to disjoint actor pairs and records a
durable ten-second minimum between batch starts. Each worker owns its own journal
connection and preserves pre-dispatch intent, isolated before/after native
snapshots, original reply, received amount, conserved backing and signed paths.
An acknowledged send may be reconciled with fresh observation intents for up to
60 seconds; the send is never replayed. Unknown or failed reconciliation stops
new batches. Already dispatched independent workers finish and retain results.

The worker records native invocation duration (including wallet opening and
journaling) separately from send-through-financial-reconciliation duration. RSS
sampling records 50ms observed maxima for the controller, concurrent native
children and explicitly supplied backend PIDs; it does not claim exact peaks.
The `batch` CLI command supports manual bounded execution, while a private
operational runner supplies service PIDs and supervision.

`Load.finish()` / CLI `finish` requires every intended transfer to be reconciled,
then takes fresh whole-cohort snapshots and rejects duplicate owned coin IDs or
value changes unexplained by observed fees. It verifies current signed paths and
confirmed backing, and reports latency quantiles and achieved workload rate from
real timestamps, including pacing and pauses. Retain the private parent funding
receipt and independently measured board transaction costs alongside this result.

Separate actual preparation-controller and execution-controller commits remain
part of the trace. Source availability, stubbed Python tests, registrations,
native acknowledgements and requested rates are never reported as successful
measured load or a maximum-TPS result.

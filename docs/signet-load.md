# Bounded native public-Signet load phases

Use fresh named campaigns and genuine native wallets on the already admitted
long-lived product endpoint. Existing two-wallet traffic and short expiry actors
retain their own wallets, journals, configuration and source pins.

The first cohort has 12 wallets, at most three concurrent disjoint actor pairs,
60 intended 1,000-sat transfers and a ten-second minimum batch interval. A later
50-wallet cohort uses at most five concurrent disjoint pairs. These are bounded
workload proposals; no throughput or scalability result exists until actual sends
are independently reconciled and timed.

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

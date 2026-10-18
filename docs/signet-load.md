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

For a **future reviewed runner**, optional pacing can run immediately before
dispatch, after the previous report and current runtime preflight:

```python
progress = load.advance_batch(
    monitor_pids=actual_backend_pids,
    wait_until_due=True,
    stop_requested=lambda: owned_stop_file.exists(),
)
# Persist this result and its report. Do not add the previous fixed outer sleep.
```

The `batch --wait-until-due` CLI option uses the same path. Remaining delay is
computed from the durable previous **actual** start; completed reporting/work
consumes that interval. Slow work records lateness and never causes a catch-up
burst. Stop requests and original unknown/HOLD state are rechecked during the
wait, and the original dispatch deadline remains unchanged. Each new batch
records controller request time, nominal scheduled time, minimum permitted time
and actual start separately. CPU figures still separate the controller, native
children and backend; this timing correction changes no monetary oracle.

This follows a real first50 observation: its first 19 starts spanned 189.5255
seconds across 18 intervals. The admitted private wrapper computed its delay
before event/report writing, adding that overhead to the interval. The original
live source, 600-request/1,200-second window and all ACKs remain unchanged; a
shortfall is preserved as an incomplete offered workload. The new fake-clock
tests use real SQLite scheduling with stub transfers, including reporting cost,
late work, deadline expiry, unknown actions and a stop during waiting. They are
included in the [27 focused checks](evidence/funded-scale-pacing-checks-20261017.json).
These are controller regression evidence, not a new funded load result. A future launch
requires source review and its own explicit controller provenance.

Tip changes during a backing/signature observation have a specific
`ChainObservationChanged` classification. Only that observation can be repeated
inside the existing reconciliation retry budget, retaining the unavailable proof
and drift receipt. Signature rejection, malformed/wrong signed fields, missing or
unconfirmed backing, unknown native actions and other verification errors are
not reclassified as drift. A retry permission is not evidence that another read
ran or that payment completed. Reconciliation still needs a stable actual Core
view and the same original acknowledged send. Funding/cohort admission crossing
a tip returns an incomplete observation stage; its original board ACKs persist.

The worker records native invocation duration (including wallet opening and
journaling) separately from send-through-financial-reconciliation duration. RSS
sampling records 50ms observed maxima for the controller, concurrent native
children and explicitly supplied backend PIDs; it does not claim exact peaks.
The `batch` CLI command supports manual bounded execution, while a private
operational runner supplies service PIDs and supervision.

The existing sampler also records before/after CPU-time deltas for those exact
processes, bound to `/proc` start identity, and all reaped child-process CPU for
the batch. Child CPU includes signature verification and other native commands;
it is not send-only CPU. Missing/restarted process identities yield an explicit
gap instead of a fabricated delta. RSS and host available-memory/swap remain
sampled at 50ms; host values include other campaigns and services. The read-only
`integration/signet-load-metrics.sql` can be polled against the admitted target DB
by its existing monitoring role, for example with `psql -X --quiet --tuples-only
--no-align --dbname PRIVATE_TARGET --file integration/signet-load-metrics.sql`.
Keep connection credentials private and poll at an explicitly recorded interval
(proposed five seconds). Record sampler overhead. Unknown connection states are
reported; do not treat restricted visibility as zero activity. Database size and
database counters are distinct from cluster-wide WAL and its reset epoch. This
SQL compatibility was checked read-only on the existing owned failed-send
PostgreSQL instance at 2026-10-17T20:44:53Z; no actor or payment query ran. This
does not mean a continuous sampler or new scale campaign is running. Its exact
query/source receipt is retained in
`docs/evidence/funded-scale-resource-checks-20261017.json`.

`Load.finish()` / CLI `finish` requires every intended transfer to be reconciled,
then takes fresh whole-cohort snapshots and rejects duplicate owned coin IDs or
value changes unexplained by observed fees. It verifies current signed paths and
confirmed backing, and reports latency quantiles and achieved workload rate from
real timestamps, including pacing and pauses. Retain the private parent funding
receipt and independently measured board transaction costs alongside this result.

A dispatch window that ends before the requested count remains incomplete.
`Load.audit_closed_window()` provides a separate financial audit only after the
original runner has exited and its writer lock has been released. It requires
the original `LOAD_WINDOW_LIMIT_REACHED` hold, no unknown/dispatched actions,
and a reconciled result for every acknowledged send. It applies the same fresh
whole-cohort conservation, signed-path and Core-backing checks as `finish()` but
returns `INCOMPLETE`, preserving the original hold, requested count and deadline.
It neither resumes traffic nor qualifies the unfinished workload. Deployment of
this source and actual execution of the audit are separate recorded events.
The snapshots invoke ordinary native `vtxos --all` and therefore `Wallet::sync`:
this may progress pending native operations, claim receives or start local exit
state. It requires explicit admission for active synchronization of the original
nonabsent cohort. It is not a money-state read-only operation. Missing/extra or
absent actors and prior partially recorded final-audit actions reject before
another wallet opens.

Separate actual preparation-controller and execution-controller commits remain
part of the trace. Source availability, stubbed Python tests, registrations,
native acknowledgements and requested rates are never reported as successful
measured load or a maximum-TPS result.

## FIRST50 fixed window: 580 of 600, financially reconciled

[The immutable window and subsequent admitted audit](evidence/public-signet-first50-incomplete-window-20261018.json)
record 580 successful 1,000-sat sends, zero unknown actions and zero observed
transfer fees. The original 600-request, 1,200-second window closed normally;
20 transfers were never dispatched. Its original `HOLD`, deadline and `36cefa`
controller provenance remain unchanged. This is **INCOMPLETE**, not a 600-send
workload PASS.

A separate, reviewed active-sync audit after the original process exited and
released its lock reread all 50 active wallets. Opening and closing customer
value both equal 1,483,500 sat. All 100 current spendable coin IDs match retained
native signed-path proofs, and fresh Core backing covers 50 confirmed anchors.
The signature receipts retain their original heights; they are not relabelled
as new cryptographic checks. Before/after state/value/ID projections changed
for zero actors. Exactly 50 new native sync observations were added; explicit
send/board/create counts stayed unchanged. These projections do not exhaustively
attribute internal SDK effects.

Achieved paced throughput was 29.0775 transfers/minute over 1,196.801 seconds from
first send intent to last reconciliation. Recipient-availability p95 was 1.573 s;
full financial-reconciliation p95 was 2.839 s. The 116 actual batch starts accumulated
44.515 seconds beyond their nominal 10-second intervals. The preserved old
wrapper calculated its remaining delay before reporting/closing, then added
that overhead. The future pacing correction is source-tested and separately
published; it was not substituted into this window.

During sampled batches, captaind used 116.81 CPU seconds, the controller 1,684.38,
and all reaped native/proof children 311.29. Sampled RSS maxima were 78,640 KiB
for captaind, 37,664 for watchmand and 507,888 for the controller. Controller proof
work dominates this measurement; it does not establish backend saturation or
maximum TPS. PostgreSQL sampling observed no deadlock increase or lock waiters;
rollback counters are not failed payments, and WAL includes other profiles.
The receipt records real 5,760 sat treasury and 22,900 sat board miner fees separately
from carried tree residual, unchanged principal and unspent operator allocations.

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

## Preparation milestone

`simulator.signet_load` currently implements preparation only. With private
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

The execution milestone must retain pre-dispatch intents, original replies,
per-pair isolated before/after snapshots, actual received amounts, conserved
backing, signed paths, native invocation and total reconciliation durations,
observed process RSS and actual chain/off-chain fees. Several intended off-chain
operations per wall-clock minute replace block-paced scheduling for load work.
An admitted board still requires genuine confirmations. Unknown or failed money
reconciliation stops new batches; already dispatched independent workers finish
and preserve their results. Registration, CLI acknowledgements and requested
rates are never reported as measured successful load.

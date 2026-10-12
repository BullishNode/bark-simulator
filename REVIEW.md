# Simulator review and fixes — 2026-10-10

The prototype is a better instrument after this review, but it remains unfinished as a signet qualification program. The reviewed scope is the external simulator, native SDK driver, configuration/deployment templates, and their tests. No captaind or other agent checkout was changed; no VM commands or real transactions were run during this review.

Before-source archive: `runs/review-2026-10-10/before.tar.gz`. SDK source remains `28e6e839506b89f79fffe8bdbc97cf8a42403874`. Findings below were checked against that source and the simulator code; this is not an independent third-party audit.

## Fixed findings

| Finding | Why it mattered | Change and evidence |
|---|---|---|
| Board fees treated as spent before broadcast evidence | The SDK explicitly returns an accepted checkpoint even when the first drive/broadcast fails (`source/bark/src/board.rs:321`). Cost reports could invent miner spending. | Driver emits the proposal before signing/submission and returns planned mining/SDK service fees, not an actual total. The fee reservation stays committed until independent reconciliation. |
| One offline or future queued action stopped the whole pilot | A global queued-row check prevented every other client from getting work. | [workload.py](simulator/workload.py:13) checks runnable online requests and skips actors with their own pending/unknown work. Regression covers a queued offline actor while another client progresses. |
| Exhausting fees stopped even free observation work | An unaffordable candidate could repeatedly win scheduling. | Candidates must fit remaining fee reserves; free snapshots/record exercises remain possible. Balance sufficiency now includes the declared send reserve. |
| Missing snapshot fields became zero balances | This fabricated a measurement and could hide outstanding value. | [workload.py](simulator/workload.py:91) requires balance/coin fields and exact integers. Malformed completed replies become unknown; the original public response remains in the journal. |
| Request/results were recorded only after completion | Timeout/crash could discard the proposal or negative request needed to investigate. | [process.py](simulator/process.py:87) accepts streamed NDJSON evidence; [engine.py](simulator/engine.py:54) persists it immediately with action/snapshot context. Native hooks record public board proposals and raw record/link request/response/binding bytes. Timeout regression proves pre-timeout evidence remains. |
| Capital drawdown measured only from opening | Opening 100, later peak 500, then 200 incorrectly reported zero drawdown. | [model.py](simulator/model.py:89) now measures observed peak-to-trough drawdown (300 in that example), separately from net opening change. Incomplete attribution is separated from actual observation gaps. |
| Charts hid timing and bridged missing measurements | Equally spaced samples could imply continuous liquidity evidence. | UTC horizontal scale and broken lines at missing samples; single samples remain visible. No causal spending/insolvency explanation is invented. |
| Stale/unstable/unhealthy observations could authorize mutations | Identity alone did not establish readiness. Core outputs with zero confirmations could also count as confirmed liquidity. | [engine.py](simulator/engine.py:115) requires fresh data, stable tip, a running target and completed initial chain sync. [vm_observer.py](simulator/vm_observer.py:16) requires positive confirmations and invalidates inventory across a tip change. |
| Separate epochs could share active wallet files | A state-directory lease did not protect a reused wallet directory. | Persisted wallet-root binding, active-run root lease, and native actor lock before seed/DB open. Target/image pinning remains enforced. |
| Every tick rebuilt all historical details/exports | Long campaigns grew report memory and repeatedly rewrote the entire event journal. | [report.py](simulator/report.py:23) bounds recent detail rows, streams epoch capital totals and aggregates full fee/coverage totals. Continuous reports refresh every five minutes; explicit full exports verify/reconstruct the complete journal. Test exceeds both detail limits and checks complete totals. |
| Identical payout evidence replay raised a double-payment error | Normal repeated collection could create a false incident or count fees twice. | [store.py](simulator/store.py:246) accepts identical transaction/fee/entitlement evidence once. Conflicting evidence or another transaction resolving already paid coins still fails atomically. |
| Labels implied more payout proof than the code performed | Mathematical script/amount checks do not prove chain inclusion, exact backing, or recovery. | Journal event is `payout_amounts_checked` with explicit validation scope. No scenario is promoted into a pass. |
| Ambiguous/nonfinite/oversized JSON could reach state | Duplicate fields, NaN, missing monetary data and oversized requests are unsuitable evidence. | Strict JSON decoding, input/output bounds, typed snapshot/fee amounts, immutable unknown outcomes, and protected public-only payload recording. |

## Recorder and observations

`simulator/observations.py` interprets recorded facts every tick. Warnings include collection gaps, readiness failures, missing capital attribution, Lightning unavailable, unknown actions, unreconciled costs, exhausted fee budget, and grouped gross amounts below the configured net minimum. Offline clients retain their last observed coin references; those are not asserted to be current balances or completed payouts.

Each observation keeps severity, first/last-seen time, check count, active/cleared state, and the supporting snapshot/action reference. Open/clear transitions enter the hash-chained journal. Repeated checks do not flood it with identical warning events. Missing evidence cannot clear an earlier warning. Liquidity changes are reported as changes with their cause unclassified.

All accepted public supervisor inputs/results and explicit driver-hook artifacts are retained in SQLite. Reports/`observations.json` expose the findings; full `events.jsonl` export provides the chronology. Mnemonics, credentials, arbitrary stderr and hidden SDK internals are not recorded. This is not an interceptor for every internal SDK RPC, server log or Lightning packet. Hashes detect accidental changes; they do not resist a trusted host rewriting the whole history.

## Verification

Final results and fingerprints are in `runs/review-2026-10-10/`. The updated checkpoint lists the exact passing counts. Tests cover recorder evidence surviving a timeout, strict JSON, scheduler progress behind an offline queue, fee exhaustion without stopping free checks, malformed balances, wallet-root pinning, stale/unstable readiness, unconfirmed UTXOs, observation lifecycle, grouped thresholds, full totals behind bounded reports, graph gaps, and payout replay/conflict behavior.

The native executable was rebuilt against the pinned SDK. Signing/amount unit tests and localhost-only malformed/unavailable-endpoint smoke checks passed. The retained twelve-client integration uses a fixture driver; it proves supervisor scheduling/silence, not a real Bark payout or Bitcoin spend.

## Remaining acceptance blockers

1. Real signed-operation/entitlement extraction, including many-input/many-output transitions. The current scalar predecessor helper is insufficient for general refreshes/transfers and is not used as a complete live ownership oracle.
2. Independent settlement/nursery/chain collection, exact backing paths and current/historical address-version arbitration for all six sources. Supplied transaction amounts are not chain proof.
3. Seed-only BIP84 gap-20 find/spend after payout without waking the absent actor. No automatic recovery verification exists yet.
4. Full operator/customer/watchman/LN boundary, reserved backing, injections, recycling, revenue and realized costs. Unknown buckets remain unknown; observed drawdown is not a measured minimum capital requirement.
5. Refresh/delegated/LN execution adapters and remaining honest/adversarial phase recipes. The 80-entry catalogue remains an unqualified requirement list.
6. An approved Lightning node/topology for the target, declared fixture funds, isolated regtest vertical slice and live observation calibration before an unattended signet campaign.

No guarantee or payout source in captaind was removed or relaxed by these changes. This simulator still cannot certify that the fork meets those guarantees until the evidence adapters and real acceptance tests above exist.

# Funded public-Signet scale proposal

Status: **source-only proposal, not deployment or funding authorization**. Prepared
against simulator `23d316cdca8c29684e95b39dd299a4c26258a269`. Root must supply
the latest *jointly qualified* server/client ELF and source manifests before a
new named phase. Current C60C Lightning campaigns and 7055 ordinary traffic keep
their existing pins, actors, locks and schedules. No absent actor is reused.

## What we have actually measured

[The 50-wallet result](evidence/public-signet-load50-20261017.json) used source
7055, 50 genuine wallets, 200 reconciled 1,000-sat native transfers, concurrency
5 and a ten-second batch interval. Opening and closing customer value were both
1,483,500 sat, with zero observed off-chain fees. Its measured paced rate was
29.6938 transfers/min over 404.125 seconds; recipient-availability p95 was 1.193
seconds and financial-reconciliation p95 was 2.963 seconds. This is a measured
baseline, not maximum throughput or production capacity.

The [authenticated lookup benchmark](evidence/attribution-scale-scope-review-20261017.json)
used real signed registration RPCs and the production scanner, but generated
unfunded accounts, one pending key per case and low indices. Its 10,000-record
missing/wrong-mailbox lookups took 117.385/116.875 seconds in that shared debug
environment. It does not prove funded attribution throughput, starvation bounds
under continuous arrivals, high-index recovery, or payment completion.

## Candidate, inventory and reuse admission

Use a separately named, long-lived public-Signet workload phase on the same owned
VM, with actual default Signet genesis/challenge checks. A proposed long profile
is lifetime 4,320 / exit delta 144, native wallet refresh threshold 144 / exit
margin 12, real CLN support and a small actual pool. Validate the final combined
candidate's configuration and advertised values before creating any actor; this
proposal does not assert that the latest build is already qualified or deployed.
Short-lived attribution/fallback is a separate phase below, with distinct pins.

Prefer cumulative cohorts: 50, then 150 additional actors, then 300 additional
actors. Reusing the already funded 50 is conditional on root admitting a same-key
server upgrade, cold backups and a new phase journal that reads the existing
wallets without inventing create acknowledgements. Reconcile every current signed
coin, original on-chain funding/change receipt and usable balance first. A new
server key requires new registrations/actors and genuine transfer/boarding;
existing Ark coins cannot be silently moved between servers. Until admitted,
reuse credit is **zero**. Never use old S02/S03 or Lightning absent wallets.

Read-only inventory at height **326798**, 2026-10-17:

* Last root funding receipt: 1,194,829,585 sat trusted before allocating 100,000
  sat plus 612 miner fee. Arithmetic remainder: **1,194,728,973 sat**. This is a
  historical recorded balance, not a fresh exhaustive available-wallet balance.
* Exact known treasury change `8e60b79edef0d909c8008c3a1f1eb68384b47058a21edfae1be2254880fd7103:1`:
  **164,190,810 sat**, independently unspent at eight confirmations. The root's
  original funding script verified nonallocated change with `getaddressinfo`
  `ismine`; its retained funded PSBT records `changepos=1`.
* Five unspent nonallocated outputs across eight inspected funding receipts total
  176,628,009 sat. Do not promote this to an exhaustive treasury total or credit
  the other four as owned without their original ownership assertions.
* Core `listwallets` was empty. This inspection loaded no wallet, derived no new
  address, sent nothing and changed no services. Root performs a fresh exact
  safe/spendable/unlocked inventory and reserve check before any funding batch.

The VM had eight logical CPUs, 8,130,412 KiB RAM, 4,702,580 KiB available RAM and
load average 0.72/0.50/0.39 at observation. Those are shared-host observations,
not resources reserved for this campaign or a reason to admit concurrency blindly.

## Exact proposed ordinary workload

Each row is its own immutable named workload window, on the same retained
cumulative actor set after the previous final audit. Root admits each increase.
No new cohort starts if the preceding one has an unknown financial outcome.

| Actual funded wallets | New actors, if prior inventory admitted | Intended transfers | Concurrency cap | Minimum batch interval | Nominal window from schedule |
|---|---:|---:|---:|---:|---:|
| 50 | 0 existing, otherwise 50 fresh | 600 | 5 disjoint pairs | 10 s | 20 min |
| 200 | 150 | 1,800 | 10 disjoint pairs | 10 s | 30 min |
| 500 | 300 | 7,200 | 20 disjoint pairs | 10 s | 60 min |

Each transfer is exactly 1,000 sat; actor pairs alternate direction so repeated
payments recycle principal. Pair scheduling must visit every actor before
repeating a full round. These are offered-work schedules (30/60/120 sends per
minute at most), not promised successful rates. Actual elapsed time includes
reconciliation and pauses and can exceed the nominal window. Report the achieved
rate, every failure, unknown, and pause. A truncated/held window remains incomplete.
Report warm-up separately; retain five-minute resource/latency slices to expose
degradation rather than averaging it away. Never count only the fastest interval.

After each cohort's ordinary window and full conservation audit, run a separately
labelled Lightning subset: 2, 5 and 10 distinct admitted actors respectively.
For each subset actor, one fresh 5,000-sat native BOLT11 receive followed by one
fresh 5,000-sat successful external send, serially reconciled. These are the
amounts already exercised by the separate live native operations. Pin real invoices,
amounts, deadlines, payment hashes, source-specific CLN outcomes, fees, signed
grants/final coins and channel liquidity. This measures 4/10/20 swap operations,
not aggregate Lightning capacity or an offline-LNURL success. A failed/unknown
operation holds this subset; do not replace it with another invoice. Reserve
500 sat per actor for actual swap fees and at most 1,000 msat payer routing fee
per receive, with actual native quotes checked before dispatch. Broader failed
refund/abandoned recipient coverage stays in the existing fenced campaigns.

## Funded attribution and fallback measurement

Registration timing comes from actual native create/open/authenticated-record
operations for every new actor. Distinguish native invocation time from server
registration RPC time; collect the latter only when its actual boundary is
instrumented, never rename total CLI latency as RPC latency.

Ordinary long-lived traffic alone cannot expose expiry attribution. After the
500-wallet window, use a **separate short-profile, 16-new-owner** campaign on the
same qualified implementation, with new native actors and its own funding/pins.
Use the already validated 32/12 profile only after source/config admission, and
retain normal SDK margins. Produce genuine funded liabilities through native
boards, transfers and signed registration; do not queue synthetic keys or patch
SQL. Establish exact birth heights, signatures and confirmed backing, then fence
the chosen absent actors. Retain active controls separately.

Use genuine verified-mailbox and missing/unverified-mailbox cases only where a
reviewed native path produces them. A registered sender's payment to an
unregistered recipient is **not** automatically an unresolved owner: the accepted
source-owner rule applies. If the native recipe for a scanner case is unavailable,
that subcase is blocked rather than manufactured. Include derived indices that
are genuinely used by funded wallets; report their actual values and do not
extrapolate index 19 results to the full derivation range.

Observe committed decision/readiness times, resumable scanner work, oldest
unresolved funded entitlement age, ready-root progress despite unrelated waiting
roots, output grouping and actual per-output fees. Read-only allowlisted DB/log
observations may identify the worker phase; they do not prove payment. Completion
requires exact registered payout scripts, actual parent and fee child, canonical
six-confirmation proofs and seed-only recovery with one journaled drain. Keep
gross principal, carried board residual, fallback fee, miner cash payment and
net operator subsidy separate. Native regtest supplies controlled fee/reorg/race
evidence; continuous simulation remains public Signet.

## Proposed incremental funding, with no assumed reuse credit

Parameterize per-actor funding to **40,000 sat**, retaining the working 30,000-sat
board. Admit the actual board transaction only when its quote fits a 1,000-sat
miner ceiling, leaving at least 9,000 sat on-chain reserve/change before any
later native action. The existing 750 sat/kWu fallback setting is not a fixed
fee estimate or ceiling; implement/check an actual preflight before dispatch.
If the native path cannot enforce that preflight, root must explicitly admit a
larger measured ceiling or retain 100,000-sat funding; never silently exceed it.

| Item | Additional allocation ceiling |
|---|---:|
| First 50 fresh actors (zero if existing inventory admitted) | 2,000,000 sat |
| 150 additional actors | 6,000,000 sat |
| 300 additional actors | 12,000,000 sat |
| Separate Lightning-capable rounds wallet | 200,000 sat |
| Five distinct confirmed usable fee-wallet outputs | 100,000 sat |
| Three actor funding-batch miner fees, at most 10,000 each | 30,000 sat |
| 16 short-profile actors, 40,000 each | 640,000 sat |
| Short-profile fee-wallet allocation | 100,000 sat |
| Short-profile funding-batch miner fee ceiling | 10,000 sat |
| **Total new treasury reservation ceiling** | **21,080,000 sat** |

Board miner expense is paid from each actor's 40,000 allocation and must not be
added to the treasury allocation a second time. Pool/fee-child costs consume the
separately allocated service balances, with a fresh usable-funds check before
operations. Swap fees reduce attributed actor value and are reconciled, not
assumed free. No additional reserve is taken from existing absent wallets.
Verified reuse of all 50 reduces this reservation to 19,080,000 sat before any
separately agreed extra maintenance. These are proposed ceilings, not funds sent
or fixed economic-cost predictions. If funding remains 100,000 per actor, publish
the revised incremental budget before root's funding transaction.

## Reuse the working controller; narrow changes still required

`simulator/signet_load.py` currently accepts only 12/50 actors, concurrency at
most 5, at most 1,000 transfers, hardcoded 100,000 funding and 30,000 boards, and
the 4,320 long profile. Larger cohorts and the windows above are **not currently
executable**. Make explicit immutable limits for these named cohorts/windows,
parameterize funding, and reuse its disjoint pairs, worker-local SQLite
connections, intent/ACK/unknown journal, signed proofs and final cohort audit.
Do not broadly remove limits or add another scheduler framework.

Preserve current result files. A larger window gets a new journal with authentic
read-existing-wallet admission and prior phase provenance, never fake create
receipts. Preserve seeds, original birthdays, registrations and wallet backups.
One runner owns each campaign lock and each actor belongs to only one writer.
Existing phase/handoff and native Lightning action helpers provide the additional
operations; source compatibility and one-shot tests must pass before execution.

Collect at one-second intervals: actual process identity/ELF hashes, CPU time
deltas, host CPU/iowait, process RSS and available RAM/swap, PG activity/locks and
database/WAL growth, Core sync/height, native wallet usable balances, confirmed
fee coins, queue size/oldest age and current channel liquidity. RSS is sampled,
not an exact peak. Preserve the existing 50-ms child RSS observations separately.
Record co-resident ordinary/Lightning activity and prove the generator is not the
bottleneck before interpreting a throughput plateau. Do not compare a shared
debug lookup benchmark directly with this release workload as if identical.

Stop dispatching new batches on any unknown, wrong payee, duplicate owned coin,
unexplained value change, failed signature/backing proof, source/pin drift, or
resource emergency. Already dispatched independent workers finish and journal
their outcomes. Reconcile exact original txid/payment hash/intent; never retry a
money command merely because a process or HTTP response disappeared. Resource
holds retain the incomplete window and trigger root review before escalation.

The result is a reproducible load envelope plus remaining risks. It does not
replace the 200-case ledger, imply all edge cases passed, or turn elapsed time
into production readiness.

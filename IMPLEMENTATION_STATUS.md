# Simulator implementation — final review rulings, 2026-10-12

Objective: complete every requirement of
`/home/francis/bark-integration-2026-10-01/simulator-review-2026-10-12.md`,
as requested through the attached handoff. The full objective remains open.
Source/VM ownership remains with this agent per OWNERSHIP.md. No subagents.

Every new code item requires a meaningful failing test committed first, passing
tests, the specified native fixture and independent audit where applicable,
a frozen candidate, safe-gap deployment, and independent live evidence.
Record those separately; a local pass does not complete a live gate.

| Work item | Release | Status | Required evidence still to obtain |
|---|---|---|---|
| WI-1 empty-wallet invoice | v21 | Packaging reviewed existing candidate | Installed manifest, invoice within 30 min, preserved state/pins/absence |
| WI-2 refresh gate | v22 | Pending | Reds/greens, refreshed zero-spendable native wallet, audit, live convergence |
| WI-3 payer affordability | v22 | Pending | 3,000 refusal/4,000 scheduling regressions, live decisions |
| WI-O1 decisions/driver logs | v22 | Pending | Every rule logged, bounded sanitized stderr, timing, native logger, live growth |
| WI-8 coverage | v22 | Pending | Six statuses, exclusion of reads, verified outcomes, coverage-80.md |
| WI-5a sync reservations | v22 | Pending | Later proof closes unchanged pending sets once, native audit |
| WI-4 recycling | v22 | Pending | Real quote/ceiling, coexistence, terminal sub-floor, no combining, native conservation and live cycle |
| WI-5 clock | v22 | Pending | Separate zero-based qualified counter; legacy history retained; observed Ark receipts; 600/3,600 windows |
| WI-6b public proofs | v23 | Pending | Reverified import without original wallet calls, automatic payout verdict, chain audit |
| WI-6a operator scripts | v23 | Pending | Verified ownership of historical/spent scripts; coordinate target bridge with main agent |
| WI-6c recovery | v23 | Pending | Separate seed-only wallet, declared funding destination, 2,000 cap, recovery bucket, confirmed spend |
| WI-7 delegated entitlements | v23 | Pending | Durable submitted/replaced/paid lifecycle, reservation closure, native audit, unclaimed-output report |
| WI-O2 traces/export/cookbook | v23/v24 | Pending | All named captures, secret-pattern checks, daily trace retention, timeline, offline reproducible bundle, target log coordination |
| WI-R seeded realism | v24 | Pending | Immutable seed, replay, intervals/amounts/recipients, 0.5% daily hazard, 5% absent payments, two-candidate guard, distinct-actor overlap |
| WI-11 cohort policy | Policy gate | Pending | No new tranche before recycling; reevaluate projection; retain immutable initial/ramp declarations |
| WI-9 operations/profiles | v25 | Pending | Unilateral exit, scheduled delegated silence/late return, external LN, forwarding/addresses/devices, each fixture/audit/live profile |
| WI-10a/b capital | v26 | Pending | Historical operator ledger, classified 100,163-sat drop, named buckets/conservation, recycling projection, capital-report.md |

Additional review finding m2 (dedup after transient proof failure) remains to
fix and verify alongside v22 evidence changes. All historical failures and
proofs must remain preserved. Reorg tests remain excluded. No new grants,
relaxed ceilings, silent SDK/target repins or original absent wallet reopening.

Main-agent dependencies do not prevent independent simulator work. Prepare
concrete requirements for historical script ownership, target logs, the 41
delegated-output waiting reasons/cancellation audit, and unilateral-exit
semantics; coordinate before any product or target changes.

# S03: live payout geometry blocker

S03 has **not passed**. It transferred 10,000 sat once and fenced the absent
recipient at public-Signet height 326706 with two signed coins under distinct
roots, both expiring at 326714. The intended result was one 38,670-sat payout,
charging one 1,000-sat fee across the 39,670-sat customer value.

At the consistent owned-Core observation at **326761**, only the recipient's
original board had paid: 28,670 sat, confirmed at 326715 in transaction
`08247b6a71e60f2bdac4730c05476669f1e1c6e72b1bbc5e6cfc60ba958582ef`,
output 0, to the exact authenticated registered script. The transferred
**10,000-sat entitlement remained unpaid**. Its 30,000-sat physical root remained
confirmed and unspent. The controller has not restored the seed or spent this
case's payout. It was paused gracefully at 326761 for diagnosis; the original
absent wallet remains fenced. Ordinary traffic and product services continue.

## Confirmed cause

The accepted control refresh produced two historical 9,835-sat Hark forfeit
paths under the second anchor. The deployed preparer validates every stored
source path before selecting the current economic cut. Its actual worker warning
is `expiry source geometry is invalid` at `server/src/expiry_readiness.rs:128`.
It never reaches attribution or a payout decision for that root.

The backend's offline exact-byte diagnostic against the genuine funding
transaction found that all eight original root/board/checkpoint/recipient/change
paths pass unsigned validation. Both historical Hark forfeit descendants fail
with `point doesn't match computed exit outpoint`. A historical path therefore
blocks the unrelated current recipient entitlement before settlement selection.
The fix must preserve validation of every selected current path; skipping
unproved customer backing or inventing operator ownership is not a repair.

This is not an HTLC, watchman-funding or missing-registration wait. The real
receive mailbox matches the authenticated registration. Independent pure Core
public-descriptor derivation at account child 2 matches the signed recipient
key. No actor wallet was opened, SQL ownership changed or money command replayed
during diagnosis. The full private snapshot retains raw VTXO/policy bytes,
accepted participation, frontier, mailbox, registry and worker logs for native
reproduction, while the [public projection](evidence/public-signet-s03-blocker-20261017.json)
omits seeds, signatures, xpubs and credentials.

## Pins and outcome limits

- Product: `7055d1fce858f3112aff671d0b2a8a454d6a2214`.
- Controller: `c669367aef254ed2ba9ebf396a44a5bc01951d2e`.
- Public projection SHA256: `44b5760b6c37c64cdf0d385d68999d03656023304a1bb679e8d7f20765cbe047`.

This cohort cannot retrospectively become a single merged payout: one root has
already paid independently. A repair must reconcile the remaining entitlement
and actual per-output fee, retain this nonqualifying grouping outcome, and prove
a corrected grouping case in a new declared cohort. No new funding or deployment
was triggered by this report. The backend is preparing a bounded fix and native
regression; neither that fix nor a live repair is claimed here.

The original S02 confirmed recovery and the completed 12/50-wallet workloads
remain immutable. This failure is additional evidence about a different path,
not a reason to rewrite their receipts or claim overall production readiness.

The [short-only repair and recovery procedure](signet-s03-repair.md) records the
backup, candidate admission and original-seed recovery steps. It is prepared,
not deployed, and cannot turn this historical grouping failure into a PASS.

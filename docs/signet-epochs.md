# S05: independent settlement at two expiry heights

`simulator.signet_epochs.S05` reuses the executed native S02 lifecycle and the
S03 transfer/freeze sequence. It adds real-height setup and distinct-output
assertions. Controller tests use native/Core stubs; no live S05 is claimed.
Use a fresh phase, journal and wallets. Existing S03 and older campaigns retain
their exact pins and receipts.

1. Capture the deployed runtime/configuration/source pins and prepare two actual
   native wallets, authenticated records and original funding addresses. The
   coordinator allocates one declared funding batch; independently admit the
   exact confirmed original outputs before boarding.
2. Board the **control first**, once. Retain its actual journaled height. Wait at
   least four real Core blocks before boarding the absent actor, once. This
   deliberately makes control backing expire earlier, so the active control
   also spans the first absent-cohort expiry. No synthetic time or extra board
   is used to repair an unsuitable setup.
3. Wait for both native boards to settle with real confirmations. Verify signed
   paths and distinct backing, then require the absent original's actual expiry
   to be at least four blocks later than control's. If that actual gap is not
   present, hold and retain both boards without relabelling the case as S03.
4. Send 10,000 sat once from control to the absent actor's captured real Ark
   address, with genuine before/after financial, destination and signed-path
   checks. Absent now has its own later 29,670-sat coin and an earlier 10,000-sat
   received coin. Freeze both, preserve original seed/birthday, fence all native
   opens of the original absent actor, and keep control active.
5. Discover both payouts independently through public blocks and signed paths.
   Require two separate recipient outputs: 9,000 sat for the earlier receive,
   then 28,670 sat for the later original. Total payout is 37,670 sat after two
   actual 1,000-sat output fees. The earlier payout must confirm **before** the
   later backing expires. A single merged output or both payments postponed to
   later eligibility does not demonstrate this case.
6. Restore the original relevant seed into a fresh wallet using its original
   recorded birthday. Supply no payout transaction IDs to restoration. Require
   confirmed recovery spending both expected payout outpoints and the existing
   active-control checks. Ordinary board change is recorded separately.

Funding, miner fees, virtual board residuals, refreshed reusable operator
principal, actual watchman fee payments and net subsidy remain separate amounts.
Unknown dispatch outcomes hold the phase and never cause another money action.
Restart retains all original IDs, including the deliberately reused S02/S03
internal intent names inside this separate S05 journal.

This proves only two receipts captured before absence. Continuous post-absence
incoming payments, actual offline Noah receive, unresolved HTLC isolation, and
all script/dust/large-tree variants remain separate cases. It completes neither
those variants nor H06 until the actual S03 and S05 executions both pass on
their named candidates. Public-Signet funding/launch requires an explicit fresh
runtime handoff and current confirmed usable operator funds; this source change
does not start another campaign.

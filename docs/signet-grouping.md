# S03: one payout across two ready same-expiry roots

`simulator.signet_grouping.S03` composes the already executed S02 lifecycle.
It introduces one 10,000-sat native transfer and explicit grouping assertions;
it does not add a separate driver or ownership resolver. Python tests use native
and chain stubs and do not qualify this case on public Signet.

Use a fresh campaign journal, two fresh native wallets, and the existing
short-lived public-Signet profile. Keep all existing campaign journals, wallets,
runtime and configuration pins unchanged. Schedule its native preparation and
money actions after the separate 50-wallet timed window to avoid interfering
with that measurement.

## Sequence

1. Capture exact controller/product/ELF/configuration/network pins. Instantiate
   `S03(campaign, board_sat=30000, maximum_control_fee_sat=1000,
   recovery_destination=OWNED_SIGNET_ADDRESS)` under one external runner lock.
2. Reuse native preparation to create `absent` and `control`, capture their
   authenticated registrations and actual funding addresses, and request one
   coordinator-owned batch allocating 100,000 sat to each. Preparation without
   confirmed funding issues neither boards nor absence.
3. Independently reconcile the confirmed funding outpoints, then let the native
   lifecycle board 30,000 sat once per wallet. Wait for genuine native admission,
   actual signed coin paths and confirmed backing. Both original coins must
   have distinct tree anchors and the **same actual expiry**, measured from their
   receipts. A block boundary producing different expiries holds this S03 case;
   it does not trigger another board or discard the original transactions.
4. Journal one native 10,000-sat transfer from control to a genuine captured
   absent-wallet Ark address. The original before/after snapshots must pass the
   existing pair-conservation/backing checker. Verify the new signed coin against
   the actual destination address. The recipient must retain its original
   29,670-sat coin plus the 10,000-sat receive under the second tree.
5. Freeze the recipient's two-coin cohort and original recovery phrase. Fence
   every subsequent native open of the original recipient. The control remains
   active and refreshes its remaining value through normal native operations.
6. Discover payouts from public blocks and the frozen registered script/signed
   paths. Require **one output paying 38,670 sat**, equal to 39,670 minus one
   1,000-sat fee across both same-expiry roots. Reuse original-seed-only restore
   with the original birthday into a separate wallet, and require a confirmed
   recovery spend consuming that exact payout.

The customer's own board contributes a separate 330-sat virtual P2A residual;
miner fees and the operator remainder must be measured separately, as in S02.
An acknowledged native send remains subject to independent financial
reconciliation. An unknown original outcome holds the campaign and is never
replayed. Completed transfer checks and the frozen cohort survive a controller
restart. The S03 wrapper refuses to turn two successful, separately charged
payouts into a successful merged-output result.

## Limits

This case proves same-expiry grouping only when its actual payout and recovery
complete. It does not prove waiting-root isolation. In particular, a native
transfer to an unregistered address is unsuitable as a fabricated unknown-owner
case: the chosen C4 rule can preserve the prior input owner's entitlement.

A real registered HTLC-send grant abandoned before payment initiation is a
separate S04 boundary. It needs an independently pinned native SDK producer and
an actual future deadline; the ordinary CLI has no grant-only command. The
existing backend tests `expiry_abandoned_registered_send_needs_no_client_refund`
and `expiry_hash_provenance` demonstrate the genuine cosign/register sequence.
Do not replace it with SQL mutations or claim a new runtime helper exists before
it is built and admitted.

Different-expiry and continuing-receipt behavior remains S05, with its own
receipt set and fee assertions. A failed S03 setup remains preserved evidence;
it is not silently renamed into a passing S05 result.

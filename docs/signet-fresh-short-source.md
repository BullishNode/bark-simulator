# Independent short-exit failed-send source

This is preparation for one public-Signet native Lightning lifecycle on the
existing V11c deployment. It is not an executed case or Noah/LNURL evidence.
The prior load-002 refresh remains `FAILED_SETUP_GEOMETRY`, with its old inputs
locked and its one refresh acknowledged. There is no second refresh, forced
forfeit, cancellation, or release of those inputs.

`simulator/signet_fresh_ln.py` adds an explicit `fresh_short_board` source to
the existing failed-send controller. It creates one native wallet with recorded
pre-funding birthday, authenticated registration and privately retained original
seed. The manual CLI uses a wallet refresh threshold of 14 and exit margin 12;
the deployment stays at tree lifetime 32, exit delta 12 and send delta 18.
The existing nonempty pool and every original campaign remain unchanged.

The proposed funding uses the already recovered 58,034-sat treasury output
`0e4f2b223e99f27fef775a84811269e307fb053f7a6d8f67d1e58930f88f6fa7:0`.
An actual root-owned PSBT must spend precisely that output, send 30,000 sat to
the new native wallet, and return change to the existing treasury script. This
reuses allocated principal. The prospective funding fee is not recorded as an
actual cost until its signed transaction is measured and broadcast.

After a verified cold off-VM backup and canonical funding confirmation, one
genuine 20,000-sat board is journaled. At three canonical board confirmations,
the controller checks the full native signature/path and actual signed exit
delta 12, more than 18 blocks of source lifetime, the exact funding lineage,
and the native-owned BDK change against Core. The board receipt reports net
customer value; the funding anchor reports gross boarded value. Their residual
and the on-chain miner fee are reported separately. A board fee above 1,000 sat
is a warning; exhausting the funded reserve stops this operation.

The established flow then issues one owned external 5,000-sat hold invoice,
initiates one native send, proves actual Accepted plus signed source/change
and the real grant deadline, fences the sender, cancels once, and requires
source-specific terminal failure. The observer requires the correct fallback
parent and fee child at six confirmations before original-seed-only restore
and one recovery drain; it subsequently verifies six recovery confirmations.
No decision, spent status, command acknowledgement or invoice cancellation
alone counts as completed payment.

Operator fees use existing service funds. Admission requires at least 40,000
sat of actual native-owned confirmed usable watchman outputs; this is a funding
precondition, not a cap on operator miner fees. Report gross miner cash payments,
carried residuals, fallback fees and net subsidy separately. The apparent
19,670-sat customer value and 18,670-sat fallback are prospective numbers until
real signed transactions establish the actual cut and fees.

Unknown actions stop for reconciliation without replay. A separate fresh-wallet
lease and explicit coordinator permission to coexist with the recipient-only
observer are required. No original absent wallet may be opened. The private
one-shot wrapper and exact allocation are reviewed separately before execution.

Local Python tests use explicit native/Core stubs. They cover funding ancestry
and change, confirmations, usable fee funds, exact board accounting and wrong
exit geometry; passing them does not constitute a public-Signet lifecycle.

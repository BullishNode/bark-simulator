# Independent short-exit failed-send source

This is preparation for one public-Signet native Lightning lifecycle on the
[upgraded V18 deployment](signet-v18-upgrade-20261018.md). It is not an executed
failed-send case or Noah/LNURL evidence.
The prior load-002 refresh remains `FAILED_SETUP_GEOMETRY`, with its old inputs
locked and its one refresh acknowledged. There is no second refresh, forced
forfeit, cancellation, or release of those inputs.

Future reused-input refreshes now check actual signature-verified input exit
deltas, advertised round lifetime and wallet exit margin before their first
refresh intent. The necessary window is `2 * margin + max(input exit delta)`
while any input is unexpired. Thus the observed 144/12 inputs are rejected
against a 32-block round before a refresh is submitted. The native signed
replacement and confirmation checks remain authoritative. This added preflight
does not release or retry the already acknowledged load-002 refresh.

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

Setup completed at 11:03:20 UTC on 18 October: one fresh native wallet was
created and registered at birthday height 326879, with exactly three setup
acknowledgements and no board, invoice or send. Its full five-file wallet
archive was independently verified off the VM, including SQLite integrity,
and the verified bytes and proof were fsynced. The frozen funding request is
`ccde1dcac87197c6e8c1d7086c93a6db9c22320d21f868a8c517e7d05bf25b4a`;
the off-VM proof is
`158e7d48b7a30c41c0b5b370ecf2459a4a9095a519d46abba8aaf251f6c5b720`.
The original prepare-only capsule stays immutable. Separate run authority
binds it, the original request, actual funding receipt and backup proof.

The exact funding transaction
`1a4374e8aa1b5b5b533ab86dbb51071a32b77ab2f7c1e92fd30eb2825d2eea56`
was subsequently broadcast once with zero confirmations at acknowledgement.
It spends the original 58,034-sat recovered output into 30,000 sat for the
fresh wallet, 27,611 sat of owned treasury change and a 423-sat fee
(141 vB at 3 sat/vB). No additional principal was allocated. The treasury
wallet was unloaded after broadcast.

At 11:20:38 UTC, the separately admitted controller started once. Its first
observation was `WAITING_FOR_REAL_FUNDING_CONFIRMATION`, with the same three
setup acknowledgements and no board or Lightning action. It must wait for
the actual funding confirmation and three actual board confirmations before
the signed-source and held-payment stages. This is an operation start, not
a failed-swap, fallback, or recovery success.

At height 326884, the board reached three canonical confirmations and passed
the full signature, native ownership and accounting checks. Its actual signed
expiry is 326913 and CSV is 12. The measured cut is
`30000 = 20000 anchor + 9542 native-owned BDK change + 458 miner fee`, with
`20000 = 19670 signed customer value + 330 carried board fee`.

The subsequent single hold-invoice intent stopped with UNKNOWN at 11:50 UTC.
Ubuntu's system curl inherited the native Nix `LD_LIBRARY_PATH`, causing a
glibc loader error before curl could execute its network request. Captured
gRPC stdout is empty and no response headers exist. A read-only lookup on the
owned external CLN at 11:57 UTC found zero invoices for the exact original
payment hash. No native send, sender fence, or cancellation was dispatched.
The original intent, artifacts and HOLD remain preserved without an inferred
acknowledgement or automatic retry.

The source correction clears `LD_LIBRARY_PATH` only for curl, retaining the
admitted native ELF environment. Three environment/error controls and 49
related Python tests passed, with independent source review. A clean-loader
`curl --version` check passed on the actual VM with HTTP/2 support and zero
network requests. These checks do not prove successful invoice creation.
An explicitly reviewed reconciliation and continuation is still required.

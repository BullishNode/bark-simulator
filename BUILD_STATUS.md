# Implementation checkpoint — 2026-10-10

First implementation in a new local Git repository (no commits or remote), built in `/home/francis/abandon-ship-simulator`. The coding agent’s checkout and deployed captaind were not changed. No simulator wallets have been funded, no live client transactions have been run, and no service has been installed on LunaNode.

## Completed

- Python supervisor with twelve persisted actors, online/offline enforcement, serial scheduling, immutable epoch fee budgets, and a SQLite action journal. Interrupted or ambiguous actions retain their reservations and are never automatically retried.
- Atomic action-result/actor-state updates, exclusive state leases, bounded subprocesses and cleanup of their own process groups.
- Public hash-chained event export; synthetic/live state isolation; strict integer satoshi accounting, grouped payout amount checks, duplicate-resolution prevention and transaction-level fee deduplication.
- JSON, CSV, Markdown and HTML reports showing balances, drawdown, outstanding reservations and incomplete behavior coverage. Missing capital buckets remain unknown. No minimum capital or thousands-user capacity is claimed.
- An initial pilot recipe: create/address twelve wallets, board previously funded wallets, send arkoor, arm two absent clients, and exercise six malformed/stale record/link requests. No implicit funding/top-ups. Absence remains persistent.
- Native SDK driver for wallet creation, linked addresses, snapshots/sync, boards with a pre-signing fee check, arkoor, invoice creation and six record/link exercises. Refresh, delegated refresh and Lightning execution are explicitly blocked pending adapters.
- All 80 planned behaviors represented in a catalogue. This is not 80 implemented or qualified scenarios.
- Read-only local VM observation bridge, configuration/service templates, and read-only SSH preflight. Confirmed rounds inventory reads are bounded; oversized/timed-out inventories become unknown rather than a partial or zero total.

## Source and live target

Driver SDK source: private clean clone at `28e6e839506b89f79fffe8bdbc97cf8a42403874`; dependency resolution is in `driver/Cargo.lock`. This source pin is not evidence of the running VM’s source revision.

Read-only preflight: `runs/vm-preflight-2026-10-10.json`.

- Target container: `abandon-signet-fallback-fb-captaind-1`, running.
- Image: `sha256:a1707cd90739835287e9b4ddbcbf598add19c66ef42fc09616174d14bbb95d78`.
- Signet height at observation: 325815; not in initial block download.
- Payout enabled; lifetime 24 blocks, grace 6, sweep depth 6, minimum 10,000 sats.
- Rounds RPC reported 4,528 sats trusted/total and two confirmed outpoints. This preflight did not independently sum their chain values or measure total operator capital.
- No configured Lightning nodes. External/internal Lightning scenarios cannot run until the target has an approved Lightning configuration/topology.
- Resources: 4 logical CPUs, 8,131,812 kB total RAM / 5,968,480 kB available; Docker filesystem 115,309,334,528 bytes available.
- Server public key, complete capital attribution and source/image mapping still require preflight evidence.

## Review update

The review fixes and recorder/observations implementation are documented in `REVIEW.md`. The journal now persists streamed public driver artifacts before completion, and `observations.py` records evidence-backed observation lifecycles every tick. Continuous reports are bounded while epoch totals and complete SQLite history are retained. No VM changes or real transactions were made during the review.

## Verification

- Final Python suite: **52 tests passed**, including the assembled twelve-client fixture pilot, crash/unknown-outcome recovery, absent-client silence, wrong-target refusal, epoch identity pinning, budget/fee conservation, payout rollback/deduplication, exact/bounded chain inventory observation, and global pause on a driver-reported protocol invariant violation. Log: `runs/review-2026-10-10/python-tests-final.log`.
- The assembled pilot exposed periodic snapshots starving funded operations. Scheduling order was corrected; the full final suite includes the regression.
- Python bytecode compilation and Rust formatting checks passed. Native `cargo check --offline --locked` passed against the pinned source; the three native signing/amount tests passed (`runs/review-2026-10-10/rust-tests.log`). The ordinary executable build passed (`runs/review-2026-10-10/rust-build.log`); `target/debug/bark-sim-driver` is available. Existing SDK warnings remain; the simulator driver emitted no warnings.
- Local binary smoke checks passed: malformed/oversized requests refused, unavailable localhost endpoint returned a sanitized outcome, and no wallet directory was created. Evidence/binary hash: `runs/review-2026-10-10/native-smoke.json`.
- Synthetic report: `runs/review-2026-10-10/demo/index.html`; twelve actors and 80 catalogue entries, **zero qualified scenarios**, and minimum required capital explicitly unknown.
- Source/configuration fingerprints: `runs/review-2026-10-10/provenance.json`.
- No real Bark integration, seed-only recovery or signet expiry test has passed for this program yet.

## Next implementation sequence

1. Add signed operation/entitlement extraction and read-only indexed server settlement/nursery/chain discovery. Reconstruct the rightful owner independently, including unregistered-parent arbitration, each address version and all six sources.
2. Add seed-only BIP84 gap-20 restore/find/spend proof after automatic payout without waking the absent actor; validate an isolated regtest board/absence/payout vertical slice.
3. Reconcile the full operator boundary: backing trees, reserved inputs, watchman, liabilities, injections/recycling, fees/revenue and LN balances/in-flight value. Until then capital requirements remain incomplete.
4. Add fee-bounded refresh/delegated/LN execution, controlled fixture peers, remaining scenario phases and honest/adversarial recipes.
5. Measure and pin approved live versions/endpoints, run observation-only calibration, then start a funded/budgeted signet pilot after the deployment acceptance gates in the plan pass. Current files are not an unattended qualification service.

The two absent actors in the pilot do not return automatically; renewal/drain/scenario cohort rotation remains to be implemented after payout/recovery evidence exists.

## Simulator adapters and infrastructure — 2026-10-11T03:35:49.479961+00:00

- [measured] New native driver compiles; five native tests PASS, Python 56/56 PASS. Added fixed-participation refresh, delegated refresh, Lightning-send fee ceiling from validated cached fee schedule, and collaborative offboard via upstream public persisted action/executor. Added public signed-VTXO/movement evidence. No live transactions qualified for these adapters yet.
- [code] Independent seed verifier has no Ark dependency and scans from genesis with fresh BIP84 lookahead20 wallet, no original DB/index/txid/birthday hints. Mainnet/testnet refused and spend fee checked before signing. Its actual regtest acceptance fixture is declared/building (`abandon-ship-simulator-cont-2026-10-11/runs/integration/vertical-28e6e8395-1`).
- [measured] Persisted ramp helper tests setup, pause, downtime, restart, immutable funding/cohort, atomic rollback and exactly-once actor addition. This helper is not yet connected to a qualified live continuous scheduler; tests are not evidence of the three-hour live ramp.
- [measured] New simulator Core31 signet service active, binary SHA dae69848ae9aaadcc3aa697d1c92b1283273a59c8d87b220b29ddc2813e25eb6, official genesis verified, ten peers, catchup 218,515/325,838 at checkpoint. Only localhost RPC. Pinned existing CLN image is transferring, two-node deployment prepared, not yet configured on target captaind or funded.
- [measured] Stage4 full-2 now 1,400 owners funded; stage5 pilot-6 capital cycle conserved to the sat, mixed underway. Signet J5 still waiting for board registration at tip325838.

## Simulator real vertical slice — 2026-10-11T03:46:38.481362+00:00

- [measured] `runs/integration/vertical-28e6e8395-2` PASS: actual Python action journal/native SDK driver board, silence through expiry, exact confirmed backing sweep, registered BIP84 payout, independent fresh BIP84 gap-20 seed scan from genesis and confirmed spend. One owner/registered-board source only; not a live campaign or qualification of the other five payout sources.
- [measured] Principal 10,000 = 9,703 payout + 297 recipient fee; operator fee 129; actual payout mining fee 426. Recovery also found original board change; 20,000 initial funding = 763 board mining + 297 recipient fee + 533 restore fee + 18,407 returned.
- [measured] Native adapter suite 5/5 and Python suite 56/56 pass. Refresh/delegated refresh, Lightning send and collaborative offboard adapters now compile, but real integration qualification of these adapters is pending. Persisted 12-to-24 ramp has unit checks; no live three-hour runtime has occurred.
- [measured] New dedicated LunaNode VM `abandon-sim-signet-20261011`, 170.75.173.102, provisioned. Its own signet Core service is active and catching up; pinned Lightning image transfer is in progress. Remote simulator source is still the prior baseline; no funded campaign or simulator service is installed.
- [measured] Stage 4 full-2 continues (1,600 of 2,000 owners funded at last checkpoint); stage 5 ten-plus-ten full soak continues after independently audited pilot-6 PASS. J5 remains live. No new product revision.
- [owner] Use LunaNode API to create/resize additional capacity whenever required; infrastructure capacity must not be treated as a task blocker. Existing unrelated stacks and evidence remain preserved.

## Real payment adapters — 2026-10-11T03:58:41.772377+00:00

- [measured] `runs/integration/adapters-28e6e8395-4` PASS, 107.6 s wall. Two actual native clients through the Python action journal: confirmed boards; 5,000-sat Ark transfer with recipient 35,000 / sender 95,000; interactive/delegated refresh with old spendable IDs retired and new IDs present; 2,000-sat controlled external LN invoice actually paid; 2,000-sat internal LN invoice received; own-wallet collaborative offboard confirmed and sender Ark spendable balance zero.
- [measured] Affordable pool and explicit 100,000-sat fixture fee ceiling; failed setups 1–3 retained with reason. No product change. This is adapter qualification; ownership-graph accounting, standalone protocol/backing verifier integration, complete capital audit, all 80 scenarios and live signet campaign are still pending.
- [measured] Dedicated VM two pinned signet CLN nodes run unfunded. Internal node `034da4217abfc8bc9395997753d5dcbb81c3e16ccb0090b9d088e3fef2ef1eef36`; external `03c58a086487703c4da754623353a3b2ea313af4065902bc3335d552e818fdc312`. Core/CLN still catch up. Read-only target observer account installed and snapshot probe PASS after correcting raw hash parsing. Inventory probes are being qualified; no continuous campaign service yet.

## VM calibration and regression launch — 2026-10-11T04:16:07.024519+00:00

- [measured] All 2,000 owners funded in `full-28e6e8395-2`; now in round creation phase. Full shared-treasury soak has completed capital cycles 0–3 with zero difference at each edge; still in progress.
- [measured] Clean final regression suites launched as `expiry-fallback-evidence/stage6-final-28e6e8395-1` on slots 2/3; runner PID 231591, exact source `28e6e8395`, original stage3/F1 filters and per-test 600-second deadline. Not yet passed. Slot1 remains leased by full soak.
- [measured] Independent raw-block/signature audit `simulator/runs/integration/vertical-28e6e8395-2/independent-audit-2` PASS: actual destination/values/confirmations, payout fee 426, seed-spend fee 533, public signed VTXO path valid; altering the signed amount was rejected. The first audit setup failure is retained separately.
- [measured] Simulator local Python suite 60/60 PASS; native 5/5 from prior adapter build. New standalone `vtxo-proof` builds and runs against reconstructed actual Core blocks. Source package 40 files transferred with exact manifests; all three native executable hashes match remote.
- [measured] New VM now runs supervised own Core, two CLN nodes, restricted client-to-server SSH tunnel, observation-only calibration, and loopback public-artifact report service. Calibration config has zero fee budget and never dispatches. Independent Core was 281,741/325,841 at last sample; matching target identity is verified, but capital is unknown while tips differ. No client wallets funded, no campaign or 3-hour ramp started. Backend `cln_array` remains empty; no channels funded.
- [measured] mTLS from target server to both new VM main CLN (9470) and hold (9471) endpoints verifies certificate chain and actual peer IP. Those ports allow only the target server IP in the new VM security group. Only public CA/client certificates and required CLN client authentication keys were transferred to private target state; no client mnemonic or mailbox key has gone to the backend.
- [code] Read-only bridge `/opt/abandon-simulation/server-observer.py` on target, forced SSH account `abandon-observer`, public RPC forwarding restricted to `172.19.0.3:3535`. Fixed read-only statements with bounded cyclic pages; pagination is explicitly not a consistent snapshot or one-time commit watermark. Four bridge validation tests PASS; live snapshot and coin inventory probes PASS.
- [measured] Report service serves only allowlisted report artifacts on 127.0.0.1:9180; SQLite/wallet URLs are denied. Local forwarding for owner access at http://127.0.0.1:18280 is being verified. This report describes calibration, not a qualified simulation.
- [assumed/open] Still required: money ownership graph and fee reconciliation, standalone proof/settlement discovery integration, all 80 recipes, real campaign funding declaration and traffic, 3-hour persisted ramp and ongoing traffic/fallback/recovery, capital attribution, actual restart/reboot campaign evidence. Larger/new VMs remain authorized whenever capacity is required.

## Public ownership journal — 2026-10-11T04:34:23.717963+00:00

- [measured] Local Python suite 68/68 PASS (`python-ownership-68.log`); native eight tests PASS (`ownership-native-5.log`), latest binaries rebuilt with explicit existing target and protoc pins. An accidental build into driver/target failed only because protoc was unset; retained as build-5 evidence, superseded by build-6 PASS.
- [code] `simulator/ownership.py` adds verified public key/record/coin evidence, many-input/many-output movement edges, persisted unconfirmed candidates and retry without opening an absent wallet. Signed replacements do not automatically retire expiry claims. Unregistered expiry owner is the exact committed parent owner, never inferred from the recipient leaf. Missing or ambiguous evidence stays unknown.
- [measured] Read-only target bridge expanded to pending boards/key links and atomic pre-commit vtxo history. Live six-kind inventory probes PASS; an actual historical settlement has one matching pre-commit spendable row at its transaction timestamp. These are trusted DB claims, not independent chain verification.
- [measured] Full suites 20/194 complete, zero failures at last checkpoint. Soak capital cycles 0–6 conserve exactly with zero injections. Full-scale run continues with real arkoor sends after funder rounds. No new product revision.
- [open] This is graph/evidence groundwork, not yet a qualified autonomous six-source ownership oracle. Chain settlement discovery, fee reconciliation, full recipes, funded campaign, live ramp and restart/reboot proof remain required. Remote calibration still uses the prior package until new evidence collectors are deployed and probed.

## VM compute upgrade and simulator accounting — 2026-10-11T04:53:55.782492+00:00

- [measured] Dedicated simulation VM upgraded through LunaNode from m.8 (89) to c.2 (94), with a clean stop of observer/report/tunnel, two unfunded CLN nodes and Core before resize. API status was migrating until completion; only then started. Same VM/IP, 10 GB RAM and 156 GB free root disk verified. Official plan API nominal price $40/month. Core dbcache now 2048; CLN nodes remain intentionally stopped during IBD. Original target stack and J5 absent wallet unchanged. Calibration services resumed after boot; this is not funded-campaign restart qualification.
- [measured] Python 78 tests PASS (`python-continuous-78.log`), plus six new continuous-scheduler tests PASS. Full 84-test suite launched. Native eight tests passed earlier; latest receive-fee guard/native build-8 compiles. Fresh genuine vertical fixture at latest adapter build launched in independent simulator target, never sharing suites' target/lease. Not yet passed.
- [code] Public evidence journal now retries unconfirmed signed coins without opening offline owners; preserves many-to-many edges and source state. Settlement checker requires the complete transaction's coin count before judging net payout, verifies actual Core values/confirmations and signed owner bindings, and keeps missing sender terminal evidence/backing/recovery explicitly pending. It does not claim full six-source qualification.
- [code] Restart-safe continuous scheduler handles creation, explicit grants, boards, arkoor, internal LN, refresh/delegation, one-shot offboard, absence and six malformed requests. All80 recipes remain required. Persisted three-hour ramp is connected; start credit requires all12 initial boards, confirmed initial fixture funding and synced/configured Lightning topology. No campaign has started or received time credit.
- [code] Dedicated fixture funder prepares/signs/verifies outputs and commits the exact transaction before broadcast, never regenerates an uncertain batch, and fixes the declared customer grants to12+12 at20,000 sats each plus6,000 total grant-mining fee cap. Uses only new VM's dedicated Core wallet; no backend treasury/client key. Four funding journal tests PASS. It still needs actual funds and real integration qualification.
- [measured] New own signet funding wallet/address created; prior createwallet request timed out but creation was reverified, not blindly repeated. Address `tb1q9qr5cmx2t4l050ya0whsrnv9jrjap07d36g8y6`. One documented Hiro faucet request returned403 'Faucet is not available'; retained request evidence, no receipt or retry assumed. Owner funding help requested while independent work continues. No treasury drained or hidden top-up.
- [measured] New remote package manifest35 source files and3 executables matches exactly. Native driver b62fc200e3529a6fbf43bd14790e015d7fc919c0b0e62678806ab5cbdf9dfefe; public verifier f0ee805cb3cfa528e904ea7fd111ec01b50d07de138bafef23b908c2eb0c2bf1. Calibration now includes cyclic six-kind inventories/public proof configuration, stays inactive with zero fee budget.
- [measured] Latest checkpoints: final suites58/194, zero failures; soak nine capital cycles, all exact/zero injections; full scale continues rounds/transfers after2,000 funded owners. Final candidate unchanged28e6e8395.

## Simulator topology and signed-proof qualification — 2026-10-11T05:23:52.116805+00:00

- [measured] New VM c.2/10GiB/2vCPU independent Core fully synced. Both dedicated CLN nodes advanced from initial-IBD setup after re-verifying zero outputs/channels and making private DB/key backups. Explicit one-time absolute scan argv worked; removed it and recreated both nodes with normal startup before funding. No money history skipped, no keys replaced.
- [measured] Public deploy00b8e45 pushed. Target CLN/core+hold authenticated backend and80,000sat pool enabled, PostgreSQL backup216,439B sha2a86ca593680f1394e02f694161264b839adf572bc4f4851aebf018f506d7ef6. Opening rounds502,956sat; no injection. Same28e6e8395image, net minimum1000, J5wallet remains stopped. Actual pool funding17a07d20958f2add13cdfcce737ad8c39e0e22a54315d3c2e01aca35c66a0924. Original signet stack unchanged.
- [measured] Simulator Python93/93PASS. Ownership verticalPASS then strengthened proof-pipeline verticalPASS76.3s, with one native-verified owned coin and actual board fee763sat before absence. Independent raw-block auditPASS: link+record signatures valid, altered destination and amount rejected;10,000principal=9,703net+297recipientfee, operator129sat, payoutfee426, seed-spendfee533. No original calls while absent.
- [measured] Genuine two-client proof-pipeline payment fixturePASS163.9s: board, online Ark transfer, interactive+delegated refresh, external and internal Lightning payments and confirmed collaborative offboard. Exact final captaind binary. This is adapter/ownership groundwork, not all80 recipes or live-campaign qualification.
- [code] Actual board costs release reserves only after independent confirmed-chain fee and signed-coin amount checks. Mining and service charges separate. LN/round/offboard fee reservations remain unresolved until their outcome collectors exist. Three-hour eligibility requires two synced nodes, the same normal channel and usable bidirectional liquidity. Unknown funding broadcast confirmation now notifies clients exactly once for sync.
- [measured] Latest remote33-file source manifest verified. Declared36zero-fee setup actions for12real wallet seeds: create/address/snapshot only, new client-campaign state. Funding and automatic workload disabled; no three-hour clock or ramp credit. Node/fixture wallet funding remains zero at last verified check.
- [measured] Dry5 corrected-Core capacity PASS11/11,20owners61entitlements,164loaded refreshes while backlog,0errors; independent audit running before fresh full3. Pilot7 corrected soak miner still running. Full regression suite133/194,0failures at checkpoint. Full scale2 and full soak1 failures remain preserved; neither is qualified.

## Binding oracle and live probe preparation — 2026-10-11T06:07:29.224930+00:00

- [measured] Python112/112PASS; native5+3testsPASS; negative native fixture16probesPASS and fresh actual payment/exit fixturePASS with board/offboard charges reconciled.
- [code]14negative request adapters now emit exact protected public record bytes. Independent bounded read-only backend snapshot compares records and key links; a separate native verifier checks the retained record/link signatures. No client mailbox private key leaves the actor. A mismatch pauses the simulation; missing evidence remains pending.
- [measured] Real VM12walletscreated,36setupactionscompleted,0funding/0campaignseconds. Dashboard now reads client-campaign state at127.0.0.1:18280; private files404. Funding and continuous workload remain off.
- [open] Live zero-money negative probe run is next. All80scenario outcomes, six-source settlement/sweep/arbitration/seed-recovery oracle, receive/round/send charges, actual fixture funding/channel setup, live3-hour ramp/post-ramp/reboot and final goal qualification remain unfinished.
- [code] Separate native build cache `target` and SDK fixture cache `fixture-target`; never compile both workspaces into one cache because ark's fixed-name artifacts collide across dependency graphs.

## Actual signet negative probes and runtime-path fix — 2026-10-11T06:48:58.608730+00:00

- [measured] Actual signet `live-negative-20261011-4` PASS16probes/14case IDs/16independent consistent binding checks,0fees/no funding broadcast/no campaign time. Retained record and key-link signatures independently checked. D39 remains bounded reads only; all80full behaviors and funded campaign remain unqualified. Public evidence is under `/home/francis/bark-integration-2026-10-01/simulator-lunanode-2026-10-11/live-negative-evidence/`.
- [measured] Root cause of runs2/3: configured service driver was `bin/bark-sim-driver` at b62fc200, while deployment verified newer `target/debug` binaries. Old source `source-ownership.tar.gz` main.rs:639–697 does not supportD01 and returns before mutation. Earlier run2 forensic attribution to d52e4c0 was wrong; a correction event/file preserves that error and records the actual executable. Both runs are invalid, their one unsupported zero-fee action blocked and fifteen undispatched actions canceled. Run1 remains invalid. No product defect was inferred.
- [measured] Corrected configured runtime binaries verified: driver51ba82cad25639ce29988a0f01c656aa6d4516284f834d48affec234611369ed; proof f0ee805c…; restore8a63c5e5…. Native diagnostics regtest PASS39.8s. Python full120testsPASS62.3s, including recent-traffic ramp gating and executable-path/hash regression tests. Latest Python guard not yet deployed at this checkpoint.
- [code] Active config now requires hash pins for the executable paths actually named by driver/proof/observer commands. The ramp clock requires successful Ark+LN transfers since funding/boarding and at least one customer transfer in the last600s, in addition to synchronized and liquid topology; query/setup time never counts.
- [measured] Soak full2 completed ten capital cycles with exact sat conservation and zero operator top-ups, now running its mixed workload. Full scale3 continues unchanged, with1600owners funded at the last event. No qualification of either full run yet. J5 original wallet remains absent, lasttip325856.
- [measured] Public PoW signet faucet research/setup isolated on dedicated simulator VM: watch-only inventory, pinned primary source, verified Core31 tools, no customer/operator wallet inputs. Attempt1failed before signing/broadcast (helper selected a10000sat output below its net floor). Declared attempt2 is CPU-bounded100%/512MiB/600s, maxdifficulty32, own simulator funding destination ownership checked; actual claim/confirmation not yet observed. It cannot earn campaign time.
- [owner] Latest instruction explicitly permits existing LunaNode API key and spinning up/resizing VMs as needed. Dedicated c.2VM is already provisioned and healthy; no extra capacity is presently required. Remaining implementation/test gates are not waived.

## Payment outcome collector qualified — 2026-10-11T09:03:48.352715+00:00

- Python137/137 PASS (`runs/cont-2026-10-11/python-payment-outcomes-137.log`), native driver7/7 PASS before the subsequent SDK progression call. Existing progression call is exercised in the real fixture below.
- `runs/integration/payment-outcomes-d47c6a4d1-5/summary.json`: PASS, exit0,283.9s, no resource violation or cleanup survivors. Actual journal/native driver at SDKd47: intended Ark receive35,000sat; interactive and delegated refresh give new spendable coins; external and intra-server Lightning successes verified against frozen hashes without exporting preimages; collaborative exit confirmed. Board/offboard costs reconciled; both Lightning send reserves remain unresolved. This is adapter qualification, not all80 scenarios or live signet success.
- Failed payment fixtures1/2 kept: too few mined confirmations before90s refresh convergence deadline. Fixture2 finaltip152, funding rounds issued148, wallet requires6. Adapter now uses existing SDKprogress_pending_rounds; harness mines the configured confirmation depth per poll instead of one. Same deadlines and safety checks. Fixtures3/4 compile failures retained; fixture5 fixes Rust type/crate references.
- Historical fixture manifests erroneously used absence/recovery labels for the payment test. Their runtime and raw results cover payments/exits, not seed restore. Runner labels corrected for future declarations; frozen historical manifests unchanged.
- Package includes the integration harness and current runner. Obsolete v9 lacks progression fix; v10 predates these documentation/manifest corrections. Neither should be deployed. Live collector deployment is pending.

## Successful movement cost collector — 2026-10-11T09:39:58.915529+00:00

Python149/149PASS175.8s; targeted22costtestsPASS. Actual two-client fixture `movement-costs-d47c6a4d1-1` PASS155.6s, all7board/round/send/offboard charges resolved against signed values/frozen intents and confirmed chain where applicable. Internal/external LN statuses and confirmed collaborative exit checked. Real fixture round/send service fees are zero; nonzero costs, caps, missing proof, competing owner, double attribution and pending/failed-send preservation are tested separately. Receive claims/failed sends remain unresolved accounting scope.
Prepared v13 package includes this collector and its tests; deployment still requires an independent installed-path/hash check. Captaind remains d47/no new product change.

Livev13 deployed and independent57-artifact installed-path/configuration checkPASS. No actual traffic credited yet; boardconfirmationspending.

## Live v14, target pin correction and returned-funds recycling — 2026-10-11T15:00:07.213876+00:00

[measured] Full Python154/154PASS; native H04 pending-board absence74.26sPASS with independent proof/chain/recovery audit, and H03 regression88.4sPASS independently audited. v14 has57pinned artifacts, archiveSHA256c28a4a89f43f7b78a639b9654755ae07d18f5deea961d8b00f291d7d616a4d62; installed-path/config/event-chain verificationPASS10:08UTC. Driver842c0783ade3804fc78df417e657331173f989e1999a5e922f4d1fd788658d19.

[measured] At14:31UTC corrected target image pin from old parent to exact shipping d47 imagef9141e1039f87506db744b0cf5ca825241b6fc62a7ba9e8efc05feadad16b8a1, after verifying same network/genesis/serverkey/container. Prior observer ValueError was this mismatch; all held time remains uncredited. Procedure excludes dispatch under SQLite lock, backs up state/config, journals known release identity and restarts supervised service. Evidence `bark-integration-2026-10-01/simulator-lunanode-2026-10-11/target-d47-requalification.log`.

[measured] Initial boards expired/returned during that hold. Fresh declared11actor reboard round uses4500sat EACH from own confirmed on-chain funds, unchanged2000sat action reserve, no operator/fixture injection and no ramp-budget use. All11SDK board submissions completed. Actor10 remainsoffline. Latest chain325911/pending4170sat each; no live Ark/LN success or healthy-clock qualification yet. Controller/declarations/actionIDs retained; never repeat these boards blindly.

[open] Native adapter/absence tests do not qualify80live recipes, healthy3h12→24ramp, complete customer/operator fees/capital, incremental history, post-ramp/reboot or mainnet production. Those remain required.

## Refresh scheduling correction qualified — 2026-10-11T15:20:44.759457+00:00

[code/measured] Start hourly refresh cadence at latest completed board/refresh/delegated refresh, instead of refreshing a freshly registered board before its first payment. New four timing/first-payment regressions plus targeted22testsPASS27.76s; fullPython158/158PASS144.26s. Native SDK, money operation caps, source keys, disappearance profiles, campaign clock and funding stay unchanged. Preparedv15; deployment/real traffic not yet claimed.

## Receive-disappearance candidate — 2026-10-11

Python167/167PASS183.2s, with meaningful parent RED and36 targeted testsPASS. Adds independently verified receive→permanent silence and continuing Lightning recipient rotation; no native binary, SDK, target, fee cap, grant or ramp budget change. Actual new Ark and Lightning absence/payout/recovery fixtures and simulator-only deployment are in progress; no new live qualification claimed. Precise interruption checkpoints, automatic lifecycle recycling, receive/failed-send fee obligations, bounded incremental native history, full80 outcomes and actual3h ramp remain open.

[measured] New actual Ark receipt→silence→expiry→payout→hint-free mnemonic restore/spend PASS160.6s (`ark-receive-disappearance-d47-4`); Lightning counterpart PASS132.0s (`lightning-receive-disappearance-d47-1`). Both independently audited from network-disabled reconstructed Core blocks: each20,000sat principal=19,703sat net+297sat recipient fee;426sat full payout fee;533sat seed-spend fee; signed board+receive outputs verified, altered destination/amount rejected, exactly one historical payout to the absent owner's script, original wallet remains offline with zero later actions. Lightning external payer succeeded, without refund. Native binaries unchanged. These are regtest slice qualifications; signet outcomes and precise interrupted operations remain open. Preparedv16 package for immediate simulator-only deployment with unchanged budgets/identities and explicit historical-movement baselines.

Live v16 independently verified:57artifact hashes,21,167eventchain entries, serviceactive,09/10closed. Deployment archive63aa3d05740d3485b76f282123d52583cd21f4fd977ae430aa4672c56ccae291. Evidence in external simulator infrastructure directory; package manifest retains the exact historical deployed BUILD_STATUS bytes. New signet disappearance profiles await new receipts and eventual independent payout/recovery evidence.

Recycling slice: meaningful parent RED3; final Python181/181PASS234.273s; native8/8unitsPASS and driverbuildPASS. New native driverSHA6810834d16fed92152edf5e852c253ce2a842f8c4a544ccb8c24e7d988f30049, SDKd47 unchanged. Actual two-cycle exit→source-only board fixture `confirmed-receipt-recycling-d47-4` PASS170.587s, with20k initial owner funding and no subsequent injection. Preserved run1source-invalidation/SIGTERM, run2immutable-config fixture error and run3nested-argument fixture error; no safeguard weakened for green. Independent reconstructed-chain audit underway; deployment waits on it. Separately authorized renewal declaration80kprincipal+2kmining, up to8k per online original actor, preserves initial/ramp budgets and permanent absences. Not dispatched.

Independent raw-block reconstruction auditPASS: source9146=7146principal+763mining+1237ownchange; source6780=4780principal+763mining+1237ownchange. Both unique sources spent once historically, new signed Ark ownership/record/key-link verified, no new injection. Ready for simulator-only v17 deployment; signet fallback recycling/full operator conservation remain unqualified.

## Bounded owner renewal v18 — 2026-10-11

[measured] Final Python193/193PASS251.877s. Actual native owner-funded renewal fixturePASS137.61s; independent reconstructed-chain auditPASS:100000sat new owner source funds8000sat grant+423sat mining+own funding change; native client spends only grant for5000sat Ark+763sat mining+2237sat own change. Both source and grant spent once; zero recycling or traffic credit. Prior interrupted pre-test build preserved.

[design/code] One immutable separately declared tranche:80ksat principal,8ksat maximum per eligible original online actor,2ksat total funding mining fee. Only confirmed independently journaled new owner receipt inputs; exact recipients and source frozen before signing, durable raw transaction before broadcast. Unknown broadcast pauses and is queried, never regenerated. Original initial/ramp96k+96k budgets and3h qualifying clock unchanged. Permanent absences never reopen; renewal board spends only the confirmed own grant with the existing native ownership/input/fee safeguards. Deployment and actual signet dispatch require separate live evidence.

## Receive claim costs v19 — 2026-10-12

[measured] ParentRED5/8; final targeted22PASS, fullPython203/203PASS101.826s. Native fresh `receive-fee-d47-2` PASS93.38s, no source drift/timeout/resources/survivors. Independent network-disabled raw-chain auditPASS:2000sat frozen invoice=2000signed recipient+0service, claim charged once, altered destination refused. Run1FAIL preserved: observerTimeoutError held queued sync before Lightning cost assertions; no product defect inferred.

[code] Collector settles only newly successful receive movements between frozen native sync before/after boundaries, after all original pending receives resolve, matching unique invoice and independently verified owned signed outputs. Double attribution/wrongowner/conservation/reserve violations fail; incomplete claims remain reserved. Invoice fee is an estimate: variance is reported, actual sync reservation remains hard. No wallet opening or native/target/config/budget change. Signet receives/failed-send reservations/operator accounting remain separate qualification.

## Ownership candidate cache v20 — 2026-10-12

[measured] Livev19:56063candidate rows/144coinIDs/102.4MB, allverified. Meaningful parentRED2/6 after an initial unused-import error preserved; targeted14PASS, full209/209PASS84.957s. Actual pending-board permanent absence regressionPASS59.34s; independent reconstructed-chain auditPASS10000principal=9703net+297recipientfee,426totalpayout/533seedspendfee, record/link/backing/amount/signature negatives intact.

[code] Only future redundant candidate insertion is skipped when identical signed protocolbytes/owner/key/amount/expiry and walletrecord body alreadyhave independently verified confirmed path+link+record. All unverified/different/competing claims are retained; stateobservations stillrecord. Existingevidence neverdeleted; native1024coin/history and2MiB limits remain a separate open issue. No native/SDK/target/config/budget change.


## Empty-wallet Lightning invoice v21 candidate — 2026-10-12

[code/measured] Existing five-file candidate is unchanged from the reviewed
wind-down hashes. Three scheduling regressions have meaningful parent reds;
targeted34/full212Python PASS. Native `empty-invoice-d47-1` wrapper wall
146.58s PASS; its nested independent audit PASS proves a2000sat incoming
receive in a0Ark/0onchain wallet, original invoice/confirmed backing/public
signatures, once-only fee attribution and altered destination rejection.
The native fixture qualifies the driver; scheduler behavior is covered by the
three Python regressions. No SDK/native/target/cap/budget changes.

[status] Packaging/deployment now authorized by the final review plan. This
checkpoint records qualification for the candidate, not an executed deployment
or restored live Lightning traffic. Deployment and independent live results
will be added after measurement. Full17item implementation remains open; see
IMPLEMENTATION_STATUS.md.

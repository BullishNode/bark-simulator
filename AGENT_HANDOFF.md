# Current runtime update: successful movement costs qualified


## Successful movement cost collector — 2026-10-11T09:39:58.915529+00:00

Python149/149PASS175.8s; targeted22costtestsPASS. Actual two-client fixture `movement-costs-d47c6a4d1-1` PASS155.6s, all7board/round/send/offboard charges resolved against signed values/frozen intents and confirmed chain where applicable. Internal/external LN statuses and confirmed collaborative exit checked. Real fixture round/send service fees are zero; nonzero costs, caps, missing proof, competing owner, double attribution and pending/failed-send preservation are tested separately. Receive claims/failed sends remain unresolved accounting scope.
Prepared v13 package includes this collector and its tests; deployment still requires an independent installed-path/hash check. Captaind remains d47/no new product change.

# Agent handoff — Bark operator simulator — 2026-10-10

Current continuation checkpoint: SDK d47c6a4d1; Python137 tests and the real payment-outcome fixture5 passed. Read the latest dated entry in BUILD_STATUS.md before relying on historical checkpoints below. The live80-case campaign, ramp and production release remain incomplete. Runtime executables must match their configured path/hash pins. No client seed or mailbox private key goes to the backend.

## Start here

Continue the external simulator in this directory. The goal is to help an operator understand liquidity, capital requirements and user outcomes when approximately twelve Bark clients transact, use Lightning, and disappear. Ultimately implement and qualify the 40 honest and 40 adversarial behaviors for a continuous signet campaign on LunaNode. This is a working prototype, not a qualified unattended service.

Read, in order:

1. `BUILD_STATUS.md`: exact completed checkpoint, measured target facts and verification.
2. `REVIEW.md`: fixes and unresolved acceptance blockers.
3. `README.md`: implementation, configuration and commands.
4. `docs/signet-continuous-client-simulator-plan-2026-10-10.md`: original requirements and acceptance gates. This is the historical plan; the three documents above describe what actually exists.
5. `simulator/scenarios.json`: all 80 requirements, not evidence that they are implemented or passed.

The original plan also remains at `/home/francis/bark-integration-2026-10-01/signet-continuous-client-simulator-plan-2026-10-10.md` on the original machine.

## Files to give another agent

Give the whole simulator source directory, with these source files:

| Files | Purpose |
| --- | --- |
| `AGENT_HANDOFF.md`, `BUILD_STATUS.md`, `REVIEW.md`, `README.md`, `docs/` | Requirements, current checkpoint and instructions |
| `simulator/*.py`, `simulator/scenarios.json`, `pyproject.toml` | Supervisor, recorder, observations, workload, reports and behavior catalogue |
| `driver/Cargo.toml`, `driver/Cargo.lock`, `driver/src/main.rs` | Native Bark SDK adapter and pinned dependency resolution |
| `tests/test_simulator.py` | Python correctness and fixture tests; native tests are in the driver |
| `config.example.toml`, `config.driver.example.json`, `config.wallet.example.toml` | Deliberately invalid configuration templates |
| `deploy/preflight-readonly.sh`, `deploy/simulator.service` | Read-only preflight and observation-only service template; not installed |
| `.gitignore` | Exclusions for private/runtime/build material |

Also provide the SDK source at **`d47c6a4d115b30bf56219d69251fa9238d13f32d`**, placed in `source/`. The driver's path dependencies require it. The transfer bundle contains the SDK's Git objects separately; it does not copy Git configuration or borrow another checkout's object storage.

Selected evidence accompanies the source: final Python/Rust test and build logs, native smoke results, historical source fingerprints, the pre-review source archive, synthetic report exports and the dated read-only VM preflight. These are not live qualification results. `MANIFEST.json` fingerprints the actual transferred files; the earlier `provenance.json` is historical review evidence.

Do not transfer private configuration, mnemonics, wallets, SSH keys, a funded run's database, build outputs or arbitrary logs as part of this source handoff. An operational continuation of an existing funded campaign would need a separate protected state/wallet transfer; there is no funded simulator campaign here.

## Exact checkpoint

- Python suite: **52 passing tests**. Native suite: **3 passing tests**. The driver built and passed local malformed-input/unavailable-endpoint smoke checks.
- Twelve persisted actors, budgets, durable intents, offline enforcement, unknown-outcome handling and a hash-chained public event recorder work in local fixtures.
- Deterministic observations track evidence gaps, readiness, uncertain actions, fees, absent clients and incomplete capital measurement. Reports bound recent detail while retaining complete SQLite history and epoch totals.
- Native operations: create, address, snapshot, sync, board, arkoor and invoice creation, plus six fallback-record/link negative exercises. Refresh, delegated refresh and Lightning payment execution remain blocked.
- Basic pilot scheduling exists. Actors 09/10 remain absent after qualifying to go offline; automatic payout verification and cohort renewal/drain are not implemented.
- **Zero qualified scenarios.** No real Bark integration, signet expiry acceptance or mnemonic-only recovery has passed for this simulator.
- No wallets were funded, no live client transactions ran, and no simulator service was installed. The repository has no source commits or remote; do not assume tracked files represent the complete implementation.
- Existing scalar predecessor handling is not a general ownership graph. `payout_amounts_checked` validates supplied amounts/scripts, not chain inclusion, exact backing, rightful ownership or recovery.
- Complete capital attribution and minimum required capital remain unknown. Twelve clients do not establish thousands-user capacity.

## Working boundaries

- Work in your own simulator copy/worktree. Do not write in `/home/francis/abandon-ship-bark-fallback`; another coding agent owns it. Use the independent SDK copy in `source/`. Coordinate any proposed fork change separately.
- Never fetch from GitLab. The supplied SDK bundle is sufficient for its pinned commit. No contact with Second or mainnet work is part of this handoff.
- Build, inspect, improve and test locally. This handoff does not authorize deployment, service restarts, new Lightning infrastructure, funding, faucets, transfers, top-ups or fee-budget changes on LunaNode. Prepare concrete deployment/configuration changes for the owner before executing them.
- Preserve all payout sources: registered coins, pending boards, unregistered outputs, Lightning receives, Lightning send refunds and hArk unclaimed outputs. Do not shrink coverage to make tests pass. No legacy BIP86 migration is required; that structure was R&D.
- An absent actor must remain silent. A separate restore verifier may run only after payment; do not sync the original wallet or reveal preimages to make the abandonment path work.
- Do not automatically retry an ambiguous dispatched action. Reconcile it from independent evidence. Keep incidents and reservations; do not reset the database to hide them.
- Record public evidence. Do not give the backend the mailbox private key, and do not record mnemonics, credentials or private configuration. Hash chaining is not protection against a host rewriting its entire history.
- Missing values stay unknown. RPC success, a catalogue entry, a synthetic result, script/amount arithmetic or a generously funded trace must never be promoted into a payout guarantee or minimum-capital result.

## Next implementation sequence

First complete one real, isolated **regtest vertical slice** before expanding recipes or deploying:

1. Extract signed operation/entitlement evidence. Model many-input/many-output transitions and retire predecessors correctly, with rightful-owner arbitration for transfers and unregistered descendants. The existing scalar helper is insufficient.
2. Add bounded indexed/incremental read-only server settlement/nursery and independent chain discovery. Establish exact backing paths, record versions, payout inclusion, fees and ownership. Use the existing SDK and protocol; do not invent an alternate payout protocol in the harness.
3. Prove board → silence → expiry/sweep → automatic registered BIP84 payout. Then a fresh wallet with only the mnemonic and a gap limit of 20 must find and spend the output, without the original database, stored address index or transaction-ID hints. The original absent actor must make no calls before payment.
4. Add real integration tests that fail on wrong payee, duplicate payment, unresolved entitlement, wrong address version and invalid backing evidence. Continue accounting for all six payout sources; this first slice is a checkpoint, not permission to exclude the others.
5. Reconcile the operator boundary: rounds/watchman backing and spendable liquidity, reservations, customer liabilities, Lightning reserves/in-flight value, injections/recycling, revenue and realized fees. Separate measured liquidity/drawdown from a validated capital requirement and document remaining unknowns.
6. Implement fee-bounded refresh/delegated/Lightning adapters, controlled fixture peers, all remaining recipes, campaign phases, cohort renewal and drain. Qualify each scenario from explicit evidence.
7. Remeasure live identity/capabilities, complete acceptance gates, and prepare observation-only calibration followed by a declared and budgeted signet campaign for owner review.

The VM observer's current confirmed inventory cap is 64 outpoints, concurrency four and a 12-second budget. Exceeding it correctly yields unknown. Replace this limitation with bounded incremental collection before scale claims.

## Dated LunaNode evidence

Read `runs/vm-preflight-2026-10-10.json`; these facts are historical, not current authorization or identity pins:

- Target host: `ubuntu@172.81.182.157`.
- Deployment: `/home/ubuntu/abandon-signet-fallback/deploy`.
- Container: `abandon-signet-fallback-fb-captaind-1`.
- Image: `sha256:a1707cd90739835287e9b4ddbcbf598add19c66ef42fc09616174d14bbb95d78`.
- Signet height 325815; payout enabled, lifetime 24 blocks, grace six, sweep depth six, payout minimum **10,000 sats**.
- Reported rounds trusted/total balance 4,528 sats and two confirmed outpoints. This is not independently established total operator capital.
- **No Lightning nodes configured.** Do not assume an unrelated existing node serves this target.
- Server public key and image-to-source mapping are unmeasured. Remeasure them; do not equate the SDK source pin with the VM revision or silently lower its payout minimum.

## Reconstruct on a different machine

Put the source archive, SDK bundle and `SHA256SUMS` in an empty transfer directory:

```sh
sha256sum -c SHA256SUMS
tar -xzf abandon-ship-simulator-2026-10-10.tar.gz
cd abandon-ship-simulator
git clone --no-checkout ../bark-sdk-28e6e839506b.bundle source
git -C source checkout --detach 28e6e839506b89f79fffe8bdbc97cf8a42403874
git -C source rev-parse HEAD
```

The archive contains `MANIFEST.json` with a SHA-256 for every packaged source/evidence file. It contains no simulator `.git` directory or private configuration. Initialize your own repository if needed; commit the complete source explicitly rather than relying on the original machine's untracked state.

## Local verification

Python 3.11+; no Python runtime packages. Rust **1.92.0** was used here. The driver uses standard-library file locks, so use a compatible toolchain. Install build prerequisites needed by the SDK and a working `protoc`; replace the original host's path below on a new machine.

```sh
python3 -m unittest discover -s tests -q
python3 -m compileall -q simulator
cargo fmt --manifest-path driver/Cargo.toml -- --check
CARGO_TARGET_DIR="$PWD/target" CARGO_BUILD_JOBS=2 \
  PROTOC=/home/francis/spark-code-audit-2026-09-11/tools/protoc/bin/protoc \
  cargo test --manifest-path driver/Cargo.toml --locked --offline
CARGO_TARGET_DIR="$PWD/target" CARGO_BUILD_JOBS=2 \
  PROTOC=/home/francis/spark-code-audit-2026-09-11/tools/protoc/bin/protoc \
  cargo build --manifest-path driver/Cargo.toml --locked --offline
python3 -m simulator.cli demo --output runs/demo-handoff-001
```

Use a fresh demo directory. `--offline` works only with cached Rust dependencies; on a new machine resolve the locked dependencies first, then rerun. Templates intentionally fail identity validation; do not replace them with guessed endpoints/pubkeys. Existing SDK warnings do not constitute driver warnings.

After each implementation chunk, update the checkpoint, record exact tests/evidence and describe what remains unproved. Start with the regtest payout/recovery slice, not a VM campaign.

## Copyable instruction for the receiving agent

> Read `AGENT_HANDOFF.md`, `BUILD_STATUS.md`, `REVIEW.md`, `README.md` and the copied simulator plan. Continue this external simulator in your own workspace using the supplied pinned SDK. First complete a real isolated regtest board/absence/automatic-payout/mnemonic-only-recovery slice with independent ownership, backing, chain and fee evidence. Preserve all six payout sources and every guarantee. Then complete capital reconciliation and the 80 behavior recipes. Keep absent actors silent, uncertain actions unretried and missing values unknown. Do not alter the other agent's fork checkout or deploy/fund/change LunaNode services under this handoff. Update the checkpoint with exact test results and remaining gaps; do not call fixture results live qualification.

## Owner superseding instructions, 2026-10-11

This simulator is now a completion gate of the active fallback goal. Owner explicitly authorizes provisioning/resizing LunaNode VMs and setting up the real signet simulation. Use the new dedicated simulator VM, separate from the existing signet captaind. Complete real Lightning and Ark payments between clients, collaborative exits, refresh, offline/fallback/seed recovery, all 40 honest and 40 adversarial requirements, capital accounting and continuous observations. Start with 12 clients, add 12 after three hours of actual active campaign runtime (exclude setup, pauses and downtime), persist the decision and declared funding, then verify ongoing activity and before/after capital effects. Existing handoff approval restrictions are superseded by this owner authorization; keep its money/identity/evidence constraints. No simulator service or live scenario has yet passed.

Authoritative goal is `/home/francis/bark-integration-2026-10-01/fallback-completion-goal-2026-10-09.md`, stage 7. VM public deployment receipt: `/home/francis/bark-integration-2026-10-01/simulator-lunanode-2026-10-11/vm-public.json`. Cloud credentials/private provisioning journal remain local and never enter packages or reports. Exact signet target now verified at `28e6e839506b89f79fffe8bdbc97cf8a42403874` with min 1,000, but still no configured Lightning nodes. Finish the genuine regtest and independent money evidence before funded campaign dispatch.

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

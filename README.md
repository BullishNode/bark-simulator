# Bark continuous signet simulator

Implementation of the [operator simulator plan](/home/francis/bark-integration-2026-10-01/signet-continuous-client-simulator-plan-2026-10-10.md), isolated from the product checkout. A dedicated LunaNode VM runs its own synced signet Core, two controlled CLN nodes, twelve independently seeded Bark wallets and the observation/report services. The funded continuous campaign and its three-hour ramp have not yet qualified. See `BUILD_STATUS.md` for dated evidence and failed runs.

The program has twelve actor identities, a durable action queue, immutable epoch fee budgets, offline gating, unknown-outcome recovery, an independent payout-amount ledger, read-only VM observations, and HTML/Markdown/CSV/JSON reports. The catalogue contains all 40 honest and 40 adversarial behaviors. **The catalogue is not 80 implemented scenarios.** Reports deliberately do not turn a successful RPC into a complete scenario pass.

The deployed v21 release moves Lightning invoice creation before the dry Ark-balance
gate, after the existing sync/read requirements. Receiving is funded by the
incoming payment. This scheduler change has three red/green regressions, a
212-test Python pass, and a native empty-wallet receive fixture with an independent
public-signature/chain audit. Packaging and live deployment are recorded in
`BUILD_STATUS.md`; fixture success does not establish live traffic qualification.
Refresh scheduling, payer affordability, exact recycling quotes and revised
two-rail clock semantics are implemented in the v22 working candidate, with
native qualification and live deployment still pending. The final implementation
requirements and rulings are in the review plan dated 2026-10-12.

## Run locally without services or coins

Python 3.11+; no Python dependencies are required.

```sh
python3 -m unittest discover -s tests -v
python3 -m simulator.cli demo --output runs/demo-001
```

Use a new output directory for each demo. Open `runs/demo-001/index.html`; `report.md`, `report.json`, `capital.csv` and hash-chained `events.jsonl` are also generated. Every demo output says **synthetic**, and its state cannot be reused for live evidence.

## Build the real client driver

The private `source/` clone has independent object storage and is pinned to `d47c6a4d115b30bf56219d69251fa9238d13f32d`. The supervisor never fetches, checks out or deploys a new server version. `source/` is not committed into the simulator repository.

```sh
git clone --no-hardlinks /home/francis/abandon-ship-bark-fallback source
git -C source checkout --detach d47c6a4d115b30bf56219d69251fa9238d13f32d
CARGO_TARGET_DIR="$PWD/target" CARGO_BUILD_JOBS=2 \
  PROTOC=/home/francis/spark-code-audit-2026-09-11/tools/protoc/bin/protoc \
  cargo build --locked --manifest-path driver/Cargo.toml
```

On a different host, supply a standalone clone at that exact commit and its compiler/protoc installation. No build runs in the coding agent's checkout. `driver/Cargo.lock` pins the actual dependency resolution.

The driver reads one public JSON request from stdin and one local configuration file named by `SIM_DRIVER_CONFIG`; it streams public evidence as JSON lines, followed by one sanitized JSON result. The supervisor persists evidence as it arrives, before waiting for completion. It reuses the fork's wallet, record/link attestations, PSBT signing and public RPC. It starts **no wallet daemon** and does not automatically recover/sync an absent actor. Wallet mnemonics live in protected per-actor files and never enter report data.

Available actions:

- Create/open an isolated signet wallet and advertise a linked Ark address.
- Snapshot balances/VTXOs; explicitly sync an online wallet. A missing monetary field is unknown, never a fabricated zero.
- Build/check a board PSBT fee before signing/submitting via the existing SDK. Save its unsigned transaction and planned fee before submission; keep the fee reservation until broadcast/cost evidence exists.
- Send arkoor with a preflight server-fee estimate.
- Create a Lightning invoice (requires Lightning configured on the target).
- Interactive and delegated refresh, Lightning sends, and collaborative offboards using persisted SDK actions.
- Fourteen negative-case adapters, including forged recipient records, mixed atomic batches, immutable key links and unlinked board ingress. Sixteen bounded probes exercise their variants. Independent consistent server snapshots and public signature verification check retained records/links. D39 covers bounded reads; it does not yet implement full invoice churn.

Genuine regtest journeys have exercised board, Ark transfers, interactive/delegated refresh, external/internal Lightning and collaborative offboard against the pinned product. Board/offboard fees close only after independent chain and signed-principal checks. Round/LN cost collectors remain incomplete, so those reservations remain held. The pinned SDK charges no arkoor fee. The SDK can return an accepted checkpoint even when its first broadcast attempt failed. A generic driver error is an unknown outcome, never automatically retried. A negative request being accepted or changing a binding is a protocol incident and pauses all clients.

## Read-only LunaNode observation

A read-only SSH preflight on 2026-10-10 confirmed the running fallback container and recorded its image, signet height, rendered configuration and spare resources in `runs/vm-preflight-2026-10-10.json`. It executed no client actions and changed no VM services. On deployment, remeasure/pin the live fork container, image digest, server public key and network. The current dedicated target identity is measured and pinned in its live configuration and public deployment evidence; remeasure it before using a different target. Do not infer it from the example configuration.

The bridge runs **locally on the VM** against its existing `fallback/ops.sh`, calls only read operations, selects only public Docker identity/status fields, reads selected rendered timing settings, and sums genuinely unspent confirmed rounds outpoints using exact satoshi conversion. It does not settle holds, change configurations, send funds, read mnemonics, restart services or run arbitrary SQL.

Prepare private `config.local.toml`, `config.driver.json`, and `config.wallet.toml` from the deliberately invalid example files. Their endpoints must match the fork and its local chain RPC. Run:

```sh
SIM_DRIVER_CONFIG="$PWD/config.driver.json" \
  python3 -m simulator.cli observe --config config.local.toml --once
```

Omit `--once` for continuous observation. `observe` never dispatches a queued action, even if `runtime.active` is true. The optional systemd unit runs this observation mode. It is a template, not installed or enabled.

Currently measured live buckets: confirmed rounds UTXOs, trusted/untrusted rounds balances, chain height/tip, target image/status and rendered timings. Full tree/backing attribution, watchman liquidity, Lightning reserves/in-flight balances, global customer liabilities, reservations, real payout discovery and seed-only recovery are **unknown/not implemented**. The report does not set them to zero or claim an established minimum operator capital.

The live preflight found no configured Lightning nodes, a 24-block coin lifetime, 6-block grace and sweep depth, a 10,000-sat payout minimum, and a reported 4,528-sat trusted rounds balance. These are a dated snapshot, not a minimum capital estimate. The VM reported 4 logical CPUs, approximately 7.8 GiB RAM (5.7 GiB available), and approximately 107 GiB available in Docker's filesystem. The observer reports the rendered capability; an external Lightning peer alone cannot make an unconfigured captaind accept payments. Lightning node/channel integration is an outstanding deployment prerequisite.

Confirmed UTXO observation is bounded to 64 outpoints, four concurrent reads and a 12-second inventory budget. Larger or timed-out inventories are explicitly unknown. An indexed/incremental collector is required before scale campaigns; this first bridge cannot measure a thousands-UTXO wallet.

## Initial continuous workload

`runtime.active=true` enables the existing action dispatcher. `workload="pilot"` enables the first automatic recipe: create twelve clients, issue their Ark addresses, observe/sync online actors, board **only already funded actor wallets**, let actors 09/10 go offline after a spendable balance appears, send occasional arkoor from funded actors 02/03, and rotate six raw-record exercises on actors 11/12.

```sh
SIM_DRIVER_CONFIG="$PWD/config.driver.json" \
  python3 -m simulator.cli run --config config.local.toml
```

This is not ready for unattended qualification: automatic payout discovery/seed-only verification and the full scenario recipes remain outstanding. The two offline actors stay offline; the collector cannot wake them merely to obtain a balance. No hidden funding, faucets, recycler or captaind top-ups exist. The report displays newly created fixture funding addresses; an operator must declare/fund a test epoch separately before boards can happen.

Explicit action queue, for supported primitive experiments:

```sh
python3 -m simulator.cli enqueue --config config.local.toml \
  --id actor01-create-001 --actor actor-01 --scenario H01 \
  --operation create --fee-reserve-sat 0
python3 -m simulator.cli offline --config config.local.toml --actor actor-09
python3 -m simulator.cli report --config config.local.toml
```

Control commands acquire the same state lease. Active runs also lease the wallet root, and native drivers lock each actor before opening its seed/database, preventing separate epochs from silently sharing active wallets. Stop the supervisor before changing offline flags or enqueuing manually; the first version intentionally has no concurrent control API. Restart preserves actor silence and converts interrupted dispatched actions to `outcome_unknown`. The first verified target identity and wallet root are persisted; a different server/image requires a new state directory even if the configuration is edited. Resolve these from independently verified protocol/chain evidence before any new mutation from that actor; no automatic “reset and retry” command is provided.

## What remains from the plan

1. Independent signed-operation/entitlement extraction and bounded incremental server/LN observations.
2. Actual payout-source discovery, exact-path proofs, address-version arbitration, seed-only gap-20 find/spend and recovery evidence.
3. Pre-dispatch fee adapters and reconciled costs for refresh and external/internal Lightning, controlled fixture peers/channels.
4. The remaining honest/adversarial recipes and prerequisite gates; races/phase interruptions need real native protocol hooks.
5. Complete operator/customer/LN capital boundary, injections/recycling ledger, fees/revenue and trace-conditioned projections.
6. Complete the declared/budgeted signet epoch, real traffic for three hours, the twelve-to-twenty-four ramp, post-ramp traffic and restart/reboot qualification. Regtest vertical slices and VM setup are complete; these do not establish full live qualification. No claim of thousands-user qualification from twelve clients.

The reports show observed balances and drawdown. They do not equate total balance with usable liquidity or silently pronounce missing evidence solvent. Unexpected monetary evidence must become a preserved incident, not an automatic funding/repair operation.

## Recording and observations

`state.sqlite` retains every accepted action intent, dispatch, public driver request/result, streamed protocol artifact, server/chain snapshot, known/planned cost, uncertain outcome, actor availability change, and observation lifecycle. Events have ordered IDs, UTC times and a SHA-256 chain. Driver artifacts include the related action, nearest snapshot/height/tip, and synthetic/live mode. No SDK internal RPC interceptor, server log collector or Lightning trace collector exists yet; this records the supervisor boundary and the explicit native hooks, not every hidden SDK operation.

`simulator/observations.py` evaluates recorded facts every supervisor tick. It records first/last detection, check count, severity, status, and supporting snapshot/action references. It flags unavailable observations, readiness failures, missing capital buckets, unconfigured Lightning, unknown actions, unreconciled fees, exhausted budgets, offline clients and grouped balances below the deployed payout minimum. It reports liquidity changes without pretending to know their cause. Missing evidence cannot clear an earlier warning. These are deterministic observations, not generated explanations, automatic repairs, proof of theft, or scenario passes.

Reports include an observations section and `observations.json`. Continuous reports refresh every five minutes (incidents immediately); displayed details are limited to 1,440 snapshots, 2,000 actions and 2,000 events in `events-recent.jsonl`. Epoch capital/fee/behavior totals still use the whole database. Charts use UTC time and break at missing samples. This bounds report memory and avoids rewriting the entire journal every tick. To verify/export the complete event chain and all details, stop the supervisor and run:

```sh
python3 -m simulator.cli report --config config.local.toml
```

A full export writes `events.jsonl`. SQLite remains the authoritative record; retain it along with protected wallet backups. Mnemonics, credentials, arbitrary stderr and configuration secrets are excluded. Child responses have a 2 MiB cap and time limit; oversized/malformed replies become unknown outcomes, rather than successful or retryable transactions. Hash chaining detects accidental changes but is not tamper protection against someone who controls the host and rewrites the entire history.

A sample showing the recorder and observations is in `runs/review-2026-10-10/demo/index.html`. It is synthetic. See `REVIEW.md` for the review findings, fixes and remaining acceptance gaps.

## Pin installed executables before enabling actions

The active configuration must include an `[executables]` table with the SHA-256 of each installed native file named by `driver_command`, `proof_command`, and the observer's `--driver` argument. Include the seed-restore executable as well. Hash the actual installed paths; a hash of `target/debug/bark-sim-driver` does not qualify a service that calls `bin/bark-sim-driver`. `Config.load` rejects missing pins, symlinks and changed hashes before opening the campaign. Stop the service during deployment and preserve the previous installed files.

```toml
[executables]
"/home/ubuntu/abandon-ship-simulator/bin/bark-sim-driver" = "REPLACE_WITH_INSTALLED_SHA256"
"/home/ubuntu/abandon-ship-simulator/bin/vtxo-proof" = "REPLACE_WITH_INSTALLED_SHA256"
"/home/ubuntu/abandon-ship-simulator/bin/seed-restore" = "REPLACE_WITH_INSTALLED_SHA256"
```

The ramp clock excludes preparation, pauses and downtime. It also requires successful Ark and Lightning customer transfers after confirmed funding/boarding, with at least one customer transfer in the previous ten minutes. Read-only activity, invoice creation, raw negative probes and merely initiated Lightning sends cannot earn campaign time. The traffic window is recorded with the ramp declaration.


## Receive once, then permanently disappear

The next runtime declares ordinary Ark recipients actor03/15 and Lightning
recipients actor06/18. They stop after a newly observed successful receive whose
spendable output keys and amounts have passed the independent public verifier.
The live installation freezes already observed movement IDs: existing receipts
are not retroactively relabeled as a new experiment. Fresh ramp wallets can
therefore disappear after their first receive; existing wallets disappear after
one newly verified receive after that baseline. Merely advertising an address,
creating an invoice, receiving an HTLC grant or seeing the sender initiate a
payment does not arm this profile.

An armed original wallet remains closed permanently. Existing board-disappearance
actors09/10 stay closed as well. The Lightning sender switches to another online
recipient so the whole simulation does not stop when one phone disappears.
`report.json` and `report.md` expose the trigger, received coin IDs, waiting coins
and independently checked confirmed payout amounts. Full source arbitration,
exact sweep backing and seed-only recovery are separate mandatory gates; no flag
or successful request is reported as a complete scenario pass. Actual regtest
fixtures use the real native driver, automatic expiry payouts and hint-free
seed restore/spend. They are qualification of this slice, not signet acceptance
or all80 behavior recipes.

Receipt-linked recycling reserves a confirmed, independently checked own collaborative-exit or fallback output. Only online wallets recycle. The native BDK driver confirms ownership/script/value and spends precisely that source as the sole input, before signing. Fresh action IDs and an atomic source intent prevent double credit or blind retry after uncertainty. Confirmed Core inputs, signed new Ark principal, service charge, mining fee and own change must conserve the source value. The original board cap and per-action fee reserve stay unchanged. New Ark principal must cover the1000sat payout floor plus the unchanged fee reserve; thin returns remain in their own BIP84 wallet and are reported as finite fee exhaustion. This margin is a bounded campaign policy, not a promise against arbitrary future fee rates. No owner-funded grant is called recycling. Full operator treasury and live six-source fallback recovery are separate qualification gates.

A separately declared one-time owner renewal may fund eligible original online clients from independently confirmed new owner injections. The fixed80ksat principal/8ksat actor/2ksat funding fee caps preserve the original initial and ramp grants. Original absent phones never reopen. Recipient/source sets freeze before signing; the signed funding transaction persists before broadcast. Unknown broadcast outcomes pause dispatch and are queried, never regenerated. Renewed boards use only the actor's confirmed grant input. Reports classify this as external owner funding, with zero recycling or traffic credit. Native and reconstructed-chain tests qualify this mechanism; live signet outcomes and full capital conservation remain separate gates.

Lightning receive fees are attributed only when a native sync boundary proves every pending receive completed, each successful claim matches a unique original invoice, and independently verified owned signed outputs conserve the principal. No claim can be assigned twice. Invoice-time estimates may differ from the eventual price; variance is reported and the existing sync fee reservation remains binding. Partial or missing proof retains the reservation. This collector uses archived evidence and does not open absent wallets.

Fresh signature nonces do not create another candidate for already proven identical ownership. Candidate storage reuses only a confirmed independently verified identical signed coin, same actor/key/amount/expiry and same wallet record body. Unverified or changed evidence remains distinct. Current state observations still update, and existing raw evidence is retained. Native history pagination is a separate open limit.

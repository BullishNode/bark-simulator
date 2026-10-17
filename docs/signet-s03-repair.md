# S03 repair and recovery on the existing public-Signet VM

This is a prepared procedure, not a deployment or a successful repair. The
coordinator supplies the checked replacement build and owns service changes.
The [original S03 failure](signet-s03-blocker-20261017.md), original source pins,
controller STOP, absent-wallet fence and all completed campaign results remain
unchanged. No new treasury funding is authorized by this document.

## Scope and qualification

Upgrade only the existing short Ark profile on the owned VM. Keep Core, shared
Postgres, the long ordinary runner, CLN and Noah running. Do not open the original
absent wallet, resume its old runner, refresh its coins, re-register it or change
SQL ownership to make the case pass.

Before deployment, the replacement needs an actual native regression reproducing
this sequence: a 10,000-sat receive, accepted control-change refresh, historical
Hark forfeits under that same root, then correct fallback of the untouched
recipient. It must still reject invalid geometry on a selected current customer
path. The nine tests in product checkpoint `fb85d9a9c` are separate evidence;
they do not by themselves qualify this S03 repair. Record the full checked code
commit, captured source manifest, executable hashes and native run/result.

Backend repair `f809bc2410b40648823caea671fe52dd0c86f11b` now has a
separate native PASS (`74f395eb-f84c-42e7-b27d-3ca483d59746`, 33.658 s),
following the retained unchanged-server failure (`0abeab28`, 52.881 s). The
[exact source/evidence packet](https://github.com/BullishNode/abandon-ship-bark/blob/f809bc2410b40648823caea671fe52dd0c86f11b/docs/evidence/s03-current-economic-cut-20261017.json)
records both. No live repair is implied. The replacement bundle and deployment
are **unresolved until the coordinator's qualified handoff**. Do not substitute latest HEAD for a checked
build. Client and server can have distinct commits; record each executable's
actual build source and BIP84 compatibility.

## Preserve the stopped state

The short deployment's existing paths are:

| Item | Existing path |
|---|---|
| Original immutable executables | `/opt/abandon-fresh-short/bin` |
| Configuration | `/var/lib/abandon-fresh/short/config` |
| Server wallet/data | `/var/lib/abandon-fresh/short/server` |
| Runtime manifest | `/var/lib/abandon-fresh/short/runtime-manifest.json` |
| Postgres database | `fresh_signet_short` |
| Product units | `abandon-fresh-short-captaind.service`, `abandon-fresh-short-watchmand.service` |
| S03 journal, frozen public receipts and private artifacts | `/var/lib/abandon-fresh/simulation/s03-7055` |
| Completed S02 journal | `/var/lib/abandon-fresh/simulation/s02-7055d1fce` |

Confirm both campaign processes exited and released their respective locks;
retain their STOP files. Check unresolved actions from the journals read-only,
not from old PID files alone. Record actual Core height/hash/default Signet
challenge, server identity, physical-root outpoints, payout outpoints and the
readonly database diagnosis before changing services.

The coordinator stops **short watchman, then short captaind** and verifies both
exited. While short services and both controllers are closed, preserve:

1. A transaction-consistent `pg_dump` of `fresh_signet_short`, its schema/migration
   history and relevant role/configuration metadata. Do not stop shared Postgres.
2. The cold short server data directory, both unit definitions and drop-ins,
   configuration, original runtime manifest and original executable bundle.
3. Consistent journal SQLite backups, cold campaign wallet directories and all
   private action artifacts for S02 and S03. Include the immutable S02 first-PASS
   file and S03 original public signed-path receipts/diagnostic packet.

Use a new private backup directory, mode 0700; archives/dumps are mode 0600.
Hash them and verify they can be listed/read. They contain keys and remain
private. Never upload wallet databases, phrases, checkpoints, dumps or raw logs
to GitHub. Preserve source failure and pending-action receipts alongside the
backup manifest. A backup does not authorize financial-state rollback.

## Deploy and admit the short service repair

Stage the exact replacement bundle under a **new immutable candidate directory**;
leave `/opt/abandon-fresh-short/bin` and its old manifest untouched. Record a new
named short-service phase with actual client/server source, ELF, unit and config
hashes, old-runtime provenance and backup manifest hashes. The current short
configuration remains lifetime 12 / exit delta 3 / boards 3; any intended change
needs its own explicit phase rather than a silent repin.

Start captaind first; require successful migrations and native operator RPC,
then start watchmand. Record startup errors and restart counts. Concurrent
migration startup previously raced and must not be hidden by a successful retry.
Verify actual `/proc/<pid>/exe` hashes, loopback endpoint 3545, original server
public key, actual config hashes, synchronized Core identity and canonical
frontier. Independently check **confirmed, usable** watchman fee-wallet funds;
a nominal balance or RPC success does not establish fee-child availability.
No new treasury send is part of this repair.

Do not use `simulator.signet_phase stage/admit` on S03: that ordinary-upgrade
helper opens both sender/receiver actors and is not an absent-cohort handoff.
Do not run the original S03 controller against changed service pins. The repair
observer must use a separate named evidence phase, with original cached public
registration and signed-path receipts attributed to their original build, plus
the actual new service pins. Its reads cannot open the original absent actor.
The separate `simulator.signet_repair` entry point now performs this import and
observation, reusing the existing native campaign journal, public discovery,
strict payout checks and recovery checker. Its tests use native/Core stubs and
claim no live execution. It imports no historical action acknowledgements into
the new phase and never copies an original wallet database. Historical frozen
signature proofs keep their original provenance; new native restore/drain
actions receive the new client/runtime context.

## Reconcile the outstanding entitlement

The already-confirmed original payout remains:

- `08247b6a71e60f2bdac4730c05476669f1e1c6e72b1bbc5e6cfc60ba958582ef:0`,
  28,670 sat, first confirmed at height 326715.
- Registered payout script: `00142829de6aa80964963fce80fc9826662ccab04e75`.

The outstanding recipient coin is
`571510ee844d77cc452e9611fb26afdc00169153d857957d2679c82814640f87:0`,
10,000 sat under physical root
`6c3b62e9d8f3d3146d95577fde60778155114a2af7d3f91e0843cba116438ce4:0`.
Observe the repair through cached signed paths, readonly server evidence and
independent public Core blocks. Prove selected customer value/payee, exact
source lineage, actual zero-fee version-3 parent, unchanged parent bytes and
separate child miner payment. A stored decision, Spent status or worker success
message is not payment.

If paid separately, this remaining entitlement yields **9,000 sat** after its
actual 1,000-sat output fee. The cohort then received 37,670 sat across two
outputs/two fees, rather than the intended single 38,670-sat merged payout.
Do not rewrite the old grouping outcome as a PASS. A new declared cohort must
prove corrected same-expiry grouping later. If the actual disposition differs,
hold and report it rather than forcing these expected amounts into accounting.

Track reusable operator principal, the original 330-sat board residual, the new
1,000-sat payout fee, gross miner payment and net subsidy separately. Reused
principal is not operator revenue. Follow actual splits/conflicts if present;
an intermediate tree step alone is not a terminal user discharge.

## Original-seed recovery after actual payment

Retain the original S03 protected phrase artifact and **birthday 326700**. The
existing `recovery_source` verifier checks its original journal hash, mode and
no-symlink rule without opening the absent wallet. Use a new recovery wallet
and fresh database; copy no original wallet database. The actual native create
must include `--signet --mnemonic-file PRIVATE_SOURCE --birthday-height 326700`,
with a private explicit config for the admitted target/Core and client 4/2
thresholds. Capture the checked client ELF and new recovery-phase pins.

Supply neither payout transaction IDs nor server SQL results to seed discovery.
Require the native wallet to discover both expected confirmed payout outpoints;
the observer compares the result against independently retained expectations.
Journal one recovery drain intent to the previously owned destination
`tb1qusq7m3xctjl5csfrr5zpfzg0lqsp9q46z5pa5p`. After actual broadcast, reconcile
that exact transaction, then prove a canonical confirmed spend consumes both
payout outpoints. Report ordinary board change and recovery miner fee separately.
A lost reply holds the intent and requires reconciliation of its original bytes
or inputs; it never authorizes a second drain.

Separately retain S02 control's pending movement 11 and locked 28,320-sat input.
Its future disposition needs authentic native reconciliation on a checked client;
zero spendable value is not zero retained value. Do not silently resume its
completed controller or charge its uncompleted 150-sat refresh as a realized fee.

## Failure and next cases

Preserve every failed native/deployment attempt and the actual post-upgrade chain
state. Do not restore an old Postgres dump or wallet snapshot over new decisions,
payouts or spends. Any binary rollback must be checked against the current schema
and retained financial state by the coordinator.

After this repair: a new same-expiry grouping cohort, independently ready versus
unresolved roots, then the distinct-expiry S05 recipe. Each receives its own
source/profile/actual-funding handoff. The original S02 and 12/50-wallet results
remain immutable. Noah offline LNURL remains separate and unproven until the
strict real callback, payment, signed recipient claim and delivery trace run.

## Executable observer after coordinator deployment

Prepare private `NEW_CONFIG` and `NEW_RUNTIME_PINS` using the existing paired
manifest schema in [the phase handoff](signet-phase-upgrade.md). All four actual
ELF files and their individual sources are pinned, as are both short configs and
the exact deployment manifest. Keep the new config's original Ark/Core endpoints.
The new state must not exist. Record the SHA256 of the original canonical frozen
JSON from the read-only old journal, not a newly constructed cohort. The actual
original frozen digest read on the owned VM is
`a8142c92234dd0789b7106e304e7cf2f282c449c9cc9820266dfb534368086a5`;
its original create receipt confirms birthday 326700.

```sh
python -m simulator.signet_repair --state NEW_STATE --config NEW_CONFIG stage \
  --origin /var/lib/abandon-fresh/simulation/s03-7055 \
  --runtime-pins NEW_RUNTIME_PINS \
  --stop-file /var/lib/abandon-fresh/simulation/s03-7055-STOP \
  --lock-file /var/lib/abandon-fresh/simulation/s03-7055-runner.lock \
  --frozen-sha256 ORIGINAL_FROZEN_SHA256 \
  --destination tb1qusq7m3xctjl5csfrr5zpfzg0lqsp9q46z5pa5p
python -m simulator.signet_repair --state NEW_STATE --config NEW_CONFIG step
```

Each `step` acquires the new phase lock and checks that the original STOP and
released original lock remain present. Public discovery, exact original
28,670-sat payout plus separate 9,000-sat payout, signed-path funding and actual
confirmed fee-child arithmetic precede any restore. Fee-child public-block
scanning advances in bounded eight-block batches. Unconfirmed/missing payments
or fee children continue observation without opening a wallet. Only then does
the genuine native client create a fresh original-seed wallet at birthday
326700, discover both confirmed outputs without transaction hints, and journal
one drain. A missing expected UTXO or a changed chain before drain holds it.
Unknown actions require reconciliation and are never retried. A later step
rechecks canonical payouts/recovery without dispatching completed native actions.
A repair PASS records 37,670 sat and two fees; historical grouping stays
`NOT_QUALIFIED`. The command does not fund or create a new campaign cohort.

# Fresh public-Signet campaign

The entry point is `python3 -m simulator.signet`. It invokes the product's native
`bark` CLI, built from the same fresh source as the server. It does not build the
old simulator Rust driver or activate the old three-track financial collectors.

This path includes durable native-action transport and separate integer-value /
Core backing checks. **No public-Signet campaign or completed payment is claimed
by its unit tests.** Actual native deployment receipts and cryptographic-path
verification are subsequent milestones.

The CLI contract was checked against product commit
`bfbe6b7c3088a09dd4e81c4ac24cdc763a627a8c`:

- `bark-cli/src/bin/bark/main.rs`: create/address/board/send/refresh/vtxos/balance.
- `bark-cli/src/bin/bark/onchain.rs`: onchain address.
- `bark-json/src/primitives.rs`: coin ID, amount, owner key, anchor, expiry/state.
- `bark-json/src/cli/mod.rs`: board receipt and balance fields.

`send` emits no machine-readable payment receipt at this source revision. Its
zero exit is recorded as `acknowledged`, requiring reconciliation. A nonzero
exit, timeout, unreadable response or controller death after dispatch does not
establish failure; the actor remains held. Repeating an intent ID never repeats
the native command. The first version deliberately has no manual `clear unknown`
command: positive evidence and a specific reconciliation path must precede
release of an unknown action.

Configuration is a private local JSON file with these exact fields:

```json
{
  "source_commit": "<40-character actual product commit>",
  "binary": "/absolute/path/to/fresh/bark",
  "binary_sha256": "<64-character digest of that executable>",
  "product_config_sha256": "<64-character digest of deployed product configuration>",
  "ark_url": "http://127.0.0.1:3535",
  "core_url": "http://127.0.0.1:38332",
  "core_credential": "/absolute/private/path/to/core/auth"
}
```

The credential file holds Core's cookie or `user:password`. It is never copied
into the public journal. Use a loopback RPC endpoint, including a tunnel if the
controller is remote. Root supplies the actual deployment endpoints and pins;
the sample ports above are examples, not a deployment discovery mechanism.

Each dispatch verifies the executable digest and requires synced public Signet:
chain name, genesis, **the default Signet challenge**, current tip height/hash.
Genesis alone cannot distinguish a custom Signet. Network/configuration pins
are immutable for a campaign. An upgrade starts a versioned new segment with
the previous state retained.

```sh
python3 -m simulator.signet --state /private/campaign --config /private/run.json \
  execute create-alice alice create
python3 -m simulator.signet --state /private/campaign --config /private/run.json \
  execute address-alice alice address
python3 -m simulator.signet --state /private/campaign --config /private/run.json \
  execute inspect-alice alice vtxos
python3 -m simulator.signet --state /private/campaign --config /private/run.json report
```

Amounts are integer satoshis. This early path intentionally accepts only native
testnet Ark addresses for `send`; Lightning, Bitcoin and multiprotocol URIs need
their own outcome checks before joining this path. `create` always supplies the
fresh target explicitly, never relies on upstream's default public Ark service,
never uses `--force`, and strips inherited `BARK_*` environment overrides.

SQLite commits each dispatch before invoking the native command. Restart reads
the original intent, acknowledgement or unknown state. Raw stdout, stderr,
funding transaction bytes, seed phrases and preimages are not public receipts.
Native CLI logging is disabled and responses use narrow allowlists. Bounded raw
stdout/stderr receipts remain in the campaign's `private/` directory, mode 0600,
including on timeouts; public reports expose only their path/hash/size and any
truncation flag. Exclude that directory from public exports. This preserves
failure diagnostics without leaking preimages or authentication material.

`abandon alice` permanently fences this campaign from opening Alice's wallet,
including `--no-sync` commands: opening a wallet can itself register a record.
Observing an absent user must use cached public receipts, independent Core and
read-only product evidence. This command does not stop an external daemon;
the campaign runbook must first establish that no other wallet actor exists.

Verification of this milestone:

```sh
python3 -m unittest tests.test_signet tests.test_signet_checks tests.test_signet_s01 tests.test_signet_proof -v
```

These are local journal/fault tests with a stubbed process and Core. They verify
unknown-outcome retention, restart behavior, actor exclusion, absent-wallet
fencing, executable/network pin rejection and public receipt projections. They
are not native wallet, signature-validation, accounting, expiry or load tests.

## First two-wallet observations

Use `sync_vtxos` while wallets are active to collect current native state. This
runs `vtxos --all` without `--no-sync`. `vtxos` is the explicit cached read. Both
still open the wallet, so both are forbidden after abandonment.

Bracket one isolated transfer with four durable native snapshots: sender before
and after, receiver before and after. Obtain the destination through the receiver's
own recorded `address` action before sending. Then run:

```sh
python3 -m simulator.signet --state /private/campaign --config /private/run.json \
  check-transfer check-001 transfer-001 sender-before sender-after \
  receiver-before receiver-after --maximum-fee-sat 100
```

The maximum fee is the run's declared operation-specific bound, not a universal
default or a subsidy cap. The check rejects overlapping monetary actions,
misordered snapshots, a destination without the receiver's native receipt,
locked value, duplicate active coins, changed immutable fields, wrong received
amount, unexplained value and missing/unconfirmed/insufficient backing. It uses
the independent Core node, checks a consistent tip and never treats backing as
additional cohort money.

Each check is stored under a new ID; failed/incomplete observations stay in the
report. Native owner observations and Core backing are separate from signature
path proof, which remains explicitly `NOT_EVALUATED`. These partial checks do
not release an unknown action or label the complete S01 scenario passed.

## Resumable S01 sequence

`s01-step` advances the actual two-wallet flow until its next dependency. Amounts
below are examples; the coordinator selects the funded run's values:

```sh
python3 -m simulator.signet --state /private/campaign --config /private/run.json \
  s01-step --board-sat 50000 --transfer-sat 5000 --maximum-fee-sat 100
```

The first call creates fresh sender/receiver wallets and obtains their native
funding addresses, authenticated fallback records and receiver Ark address.
Fallback records come from the normal wallet-opening `dev fallback-record`
command while the actor is active. Core independently checks the payout address
against its recorded script, and the reserved payout address must differ from
the normal funding address. The actual native server identity, board minimum,
confirmation requirement and expiry parameters are captured through `ark-info`.
The controller stops at
`WAITING_FOR_OWNER_ALLOCATED_FUNDING`; it never withdraws from the offline
treasury or calls a faucet. The coordinator then sends a declared allocation to
each native onchain address, recording confirmed output receipts:

```sh
python3 -m simulator.signet --state /private/campaign --config /private/run.json \
  record-funding sender ACTUAL_TXID ACTUAL_OUTPUT_INDEX
python3 -m simulator.signet --state /private/campaign --config /private/run.json \
  record-funding receiver ACTUAL_TXID ACTUAL_OUTPUT_INDEX
```

`record-funding` independently checks the real output's script, exact satoshis,
confirmation and chain identity against the actor's native address receipt. One
outpoint cannot fund two actors. Fund each address above the requested board
amount to leave actual miner-fee headroom.

Repeat `s01-step` with the same parameters. It boards both wallets once, waits
for actual native board settlement, captures before snapshots, sends once, and
captures/reconciles after snapshots. A board's returned amount is **net of the
protocol board fee**; waiting for the original gross amount would never finish.
Repeated steps and controller restarts reuse all original money-moving intent
IDs. Fresh observation intents preserve each poll. Failed/incomplete checks stay
in the report; a later good observation never erases them. Uncertain dispatches
stop at `RECONCILIATION_REQUIRED` and are not repeated.

`NATIVE_TRANSFER_OBSERVED` means the actual native wallet values and independent
Core backing match. It still reports the exact signature-verification coverage;
native signed-path verification is being connected through the product's own
`dev vtxo verify` command. There is no global qualified-time gate.

Once signed-path and original-destination proofs pass, invoke `s01-step` from a
new controller process. The original transfer intent must be retained unchanged.
Only then does S01 record `COMPLETE / PASS`, scoped to this native ordinary-flow
case. It does not claim fallback or production readiness. On Linux, controller
identity hashes the actual boot ID, PID and `/proc` process start time; recreating
a Python object in the same process cannot satisfy this restart observation.
Each dispatch records that identity and its exact source/executable/config pins.

The verifier transport now invokes `bark dev vtxo verify SERIALIZED_VTXO
RAW_FUNDING_TRANSACTION` without `--datadir`, so this verification itself opens
no wallet. It uses the same pinned executable, requires the exact returned coin
fields and anchor ID to match the snapshot, and independently checks that Core
reports the funding anchor confirmed and unspent at a consistent public-Signet
tip. The raw funding transaction comes from Core, not from the product's payout
resolver. Core must be able to serve that transaction (normally with `txindex`).

`raw-vtxo` receipts are captured from active actors before abandonment; only their
digest and size enter the public reply. A cached signature proof can be checked
later without opening the absent wallet. Wrong fields, a different anchor,
changed raw artifacts, a changed executable or native signature rejection never
become a passing proof. Unavailable observations remain in history and can be
retried separately; the monetary action is never repeated.

The supervisor tests stub this native command. Availability and cryptographic
correctness of the product command require its own compiled tests and actual
campaign receipts; this source integration does not claim those are finished.

Before deliberate abandonment is supported by the deployed product, active
wallets can run the native `maintain` operation through distinct journaled
intents. It invokes upstream's one-shot `wallet.maintenance()`, using the wallet's
actual refresh policy; it is not a fabricated scheduler or a forced refresh of
every coin. Such maintenance is a monetary operation and cannot overlap an
isolated transfer checkpoint. An absent actor is never maintained.

S02 freezes an actual cohort, then checks chain outcomes independently. Keep S01
wallets active under the initial long-lifetime profile. Begin absence only after
the coordinator has deployed and checked the real allocation and payout path
(W5–W7); upstream-only reclamation is not the emergency payout implementation.
A deliberately shorter lifetime is a separate declared campaign configuration,
with real expiry heights recorded. Normal active-wallet maintenance continues
for the control cohort. An expired coin may still refresh before the server's
allocation decision; expiry height alone does not prove that decision happened.

```
python -m simulator.signet --state PRIVATE_DIR --config PRIVATE_CONFIG \
  s02-begin-absence ACTOR SNAPSHOT_INTENT REGISTRATION_INTENT
python -m simulator.signet --state PRIVATE_DIR --config PRIVATE_CONFIG \
  s02-check-payout ACTOR OBSERVED_TXID VOUT COIN_ID [COIN_ID ...]
```

The first command captures signed native receipts and their verified path
outpoints before permanently fencing the original wallet from every native open.
It requires a current spendable cohort and the authenticated public registration.
Its short transaction rejects changes after the selected snapshot. The supervisor
must be the sole owner of these wallet directories; separately started daemons
must already be stopped. Cached observations remain readable without reopening.

The second command accepts a candidate transaction ID from operation logs or a
public script observation. It independently reads Core: current public-Signet
chain, canonical confirmation at/after expiry, registered payout script, exact
sum of allocated coins minus 1,000 sat, one output to that script, version-3
zero-fee parent, previously confirmed inputs, and one actual signed path input
per allocated coin. A matching deposit to the same address is insufficient.
Different expiry heights are separate allocations. Ready subsets at the same
expiry can pay without waiting for an unresolved tree. Each failed or incomplete
observation remains in the report. This does not claim that watchman funding,
fee-child subsidy, or every ownership class has been qualified.

The controller can discover candidates independently from public blocks, without
being given payout transaction IDs or opening the absent wallet:

```
python -m simulator.signet --state PRIVATE_DIR --config PRIVATE_CONFIG \
  s02-discover-payouts ACTOR --maximum-transactions 128
```

This resumes bounded batches from the frozen cohort's first expiry. It obtains
only public transaction IDs through Core `getblock` verbosity 1, then checks
transactions paying the cached registered script with the existing signed-path
and exact-value checks. A deposit to that script cannot qualify as a payout.
The cursor checks canonical block hashes and rewinds after a reorg; a changed
tip during a batch leaves the previous cursor in place. Generic block capture
contains only the block hash, height and transaction IDs, with no block witness
bytes. Candidate discovery stays incomplete until actual phrase-only recovery,
confirmed payout spending and active-control reconciliation have also passed.

Recovery uses a distinct wallet directory created from the original recovery
phrase only, never a copied database. Native `onchain_utxos` and `onchain_drain`
operations use the existing CLI. Beginning absence retains an owner-only bounded
backup of the original phrase file. `restore` checks that protected artifact and
passes only its path through the new native `--mnemonic-file` option, alongside
an explicit birthday height. Words never enter process arguments or the public
journal. It refuses an existing recovery directory or any earlier native action
for the recovery actor. The native option and signed-path verifier are drafted
in the fresh product branch; a compiled, checked binary is still required for
real execution. No fake restore receipt is created by this runner.

```
python -m simulator.signet --state PRIVATE_DIR --config PRIVATE_CONFIG \
  execute restore-1 RESTORED_ACTOR restore \
  --arguments '{"source_actor":"ABSENT_ACTOR","birthday_height":ACTUAL_BIRTHDAY}'
python -m simulator.signet --state PRIVATE_DIR --config PRIVATE_CONFIG \
  execute drain-1 RESTORED_ACTOR onchain_drain \
  --arguments '{"destination":"EXPECTED_SIGNET_DESTINATION"}'
```

The JSON examples contain placeholders to replace with the actual actor, integer
height and destination. Once the real restore and drain are journaled:

```
python -m simulator.signet --state PRIVATE_DIR --config PRIVATE_CONFIG \
  s02-check-recovery ACTOR RESTORED_ACTOR DRAIN_INTENT \
  PAYOUT_OBSERVATION_ID EXPECTED_SIGNET_DESTINATION
```

Core must show the confirmed drain consuming the exact fallback payout outpoint.
Old boarding change is listed separately and cannot satisfy fallback recovery.
The checker rechecks the payout's canonical presence before crediting recovery;
its earlier passing observation alone cannot survive a reorg. These commands
report individual payout/recovery evidence and leave S02 incomplete until the
complete frozen cohort and active control have been reconciled. No elapsed
campaign time or restored total balance substitutes for those outcomes.

The active control has its own original snapshot, acknowledged `maintain` or
`refresh` actions, and a later snapshot. `s02-check-control` requires every
original coin to be spent, replacement coins still unexpired beyond the original
expiry, verified native signatures and current confirmed backing, and exact
cohort conservation within the declared fee bound. Additional sends/boards or
later maintenance require a new checkpoint; they cannot silently enter its sum.

```
python -m simulator.signet --state PRIVATE_DIR --config PRIVATE_CONFIG \
  s02-check-control CONTROL_ACTOR BEFORE_INTENT AFTER_INTENT --maximum-fee-sat BOUND
python -m simulator.signet --state PRIVATE_DIR --config PRIVATE_CONFIG \
  s02-reconcile ABSENT_ACTOR CONTROL_OBSERVATION_ID
```

Reconciliation rereads the current canonical chain for every payout and recovery
spend. It reports pending frozen coin IDs and real expiry heights. Only complete
non-overlapping coverage of the original cohort, confirmed spends consuming each
actual payout, and a freshly rechecked active control produce S02 PASS. The
restore must start after its payout has confirmed. A later reorg can therefore
make the current reconciliation incomplete even if historical observations
passed; both results remain visible. S02 PASS covers this declared cohort and
lifecycle, not every production scenario or any amount of qualified wall time.


### Preparing a short ordinary lifecycle

Use a new cohort and new source/binary/server-configuration pins. The running
long-lifetime S01 is preserved. A candidate server profile is lifetime 12 blocks,
exit delta 3 and required board confirmations 3. It still needs actual server
configuration validation, a checked native payout worker and confirmed usable
watchman funding before deployment or absence.

The native Signet wallet defaults to a 12-block refresh threshold and 12-block
exit margin. Keeping that exit margin with a 12-block lifetime starts a pending
board's emergency exit immediately (`bark/src/actions/board.rs`); registration
acknowledgement cannot establish this profile works. A candidate wallet uses
refresh threshold 4 and exit margin 2:

```json
{"wallet_profile":{"vtxo_refresh_expiry_threshold":4,"vtxo_exit_margin":2}}
```

Pass that object as the `create` operation's arguments for a fresh actor. The
controller journals it before writing an owner-only native `config.toml`, pins
its exact hash in the acknowledgement, and invokes genuine `create --signet`
without conflicting configuration flags. It never overwrites a wallet directory.
No product CLI flags or readiness APIs are invented. The existing unconfigured
`create` path keeps its production-timing defaults.

The server's standard watchman sweep interval is two hours. A short campaign
must explicitly record its shorter operational interval, reaction interval and
progress grace alongside actual block heights; shortening wallet lifetimes
alone does not shorten that scheduler. Active control must genuinely refresh
and confirm before its original expiry. Public Signet block spacing and mining
admission remain outside our control.

This profile covers ordinary fallback only. Its short lifetime cannot qualify
normal Lightning HTLC durations, mainnet exit safety or production timing.

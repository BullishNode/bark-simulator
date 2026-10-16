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

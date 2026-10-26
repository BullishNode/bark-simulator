# Current signature-link client path

This is the small queued path through the existing supervisor, Rust driver,
SQLite journal and reporting. It creates ten actors in a fresh campaign. Existing databases without the
current wallet marker are refused before opening SQLite. It
supports create/address/snapshot/sync, board, Ark send, refresh and offboard.
The legacy schedulers and server attribution/receipt inventories are unavailable
in this profile. Sustained scheduling is deferred until the two-wallet proof.
Lightning is unrun. No operator-capital or release-gate qualification is earned.

The selected SDK/server **source candidate** is
`BullishNode/abandon-ship-bark@8b356f8ae966e206204301b169f1d1169520d554`.
It matched public `main` when checked on 2026-10-26 UTC. The build script refuses
a different or tracked-dirty SDK checkout. This pin does not assert that any
running VM has that code: measure its image and retain deployment provenance.

Master `83b7534ba370f3ea1a98370da453635f20853ec7` has no `AGENTS.md`.
The old driver targets SDK 0.7.1 and xpub/index proofs. The minimal changes here
use the SDK's fallback script, registration, signed address, OwnerLink encoder
and verifier, typed refusals, reconciliation and recovery callback. No protocol
cryptography is implemented in the new adapter. Public link verification proves
the coin signature for the pinned server mailbox; it does not publicly unblind
the mailbox or prove server admission. Actual payments require the existing
recipient key, signed path and amount checks, independently backed by Core.

## Build

Use a new worktree and a new `source/`; do not change a funded wallet checkout.
Requires Rust 1.90+, protoc, C/C++ tooling, CMake and the native SDK dependencies
listed in the existing CI workflow.

```sh
git fetch origin master
git worktree add -b work/signature-link-client ../bark-simulator-client origin/master
cd ../bark-simulator-client
# Apply/check out this PR before the following commands.
git clone --no-checkout https://github.com/BullishNode/abandon-ship-bark.git source
git -C source checkout --detach 8b356f8ae966e206204301b169f1d1169520d554
CARGO_TARGET_DIR="$PWD/target" CARGO_BUILD_JOBS=2 cargo build --manifest-path driver/Cargo.toml --locked --features signature-link --bin bark-sim-driver --bin vtxo-proof
CARGO_TARGET_DIR="$PWD/target" CARGO_BUILD_JOBS=2 cargo test --manifest-path driver/Cargo.toml --locked --features signature-link --lib --bin bark-sim-driver --bin vtxo-proof
python3 -m unittest tests.test_signature_link tests.test_architecture_profile tests.test_ownership tests.test_unknown_outcomes
sha256sum target/debug/bark-sim-driver target/debug/vtxo-proof
```

Only these binaries are needed for the current path; do not build the legacy
raw-protocol/Noah scenario catalogue against the current SDK.

## First two wallets

Copy the two signature-link examples and `config.wallet.example.toml` into a
new private directory; set mode 0700 on that directory and 0600 on its files.
Fill the measured endpoint, server keys, container image, independent Core
cookie **path**, executable hashes, and explicitly assigned principal/fee
budgets. The new observer reads Docker state and public RPCs only. Remote VM
observation remains unavailable until its actual deployment interface is known.
It does not infer payout deadlines or Lightning readiness.

Set the actual absolute paths below. Keep all wallet material outside Git.
`enqueue` records intent only. `run --once` dispatches queued work after a fresh
healthy pinned observation. Never assign invented funding or treasury balances.

```sh
umask 077
export SIM_DRIVER_CONFIG=/ABSOLUTE/PRIVATE/config.driver.json
cfg=/ABSOLUTE/PRIVATE/config.local.toml
mkdir -p /ABSOLUTE/PRIVATE/wallets
python3 -m simulator.cli observe --config "$cfg" --once
python3 -m simulator.cli enqueue --config "$cfg" --id create-01 --actor actor-01 --scenario H01 --operation create --fee-reserve-sat 0
python3 -m simulator.cli enqueue --config "$cfg" --id create-02 --actor actor-02 --scenario H01 --operation create --fee-reserve-sat 0
# Enable active only with the assigned budget and pinned verifier in place.
python3 -m simulator.cli run --config "$cfg" --once
python3 -m simulator.cli enqueue --config "$cfg" --id address-02 --actor actor-02 --scenario H07 --operation address --fee-reserve-sat 0
python3 -m simulator.cli run --config "$cfg" --once
python3 -m simulator.cli report --config "$cfg"
```

Inspect the actual registration/address observations. Have the funding owner
fund only those fresh onchain addresses; this code never tops them up. After
independent confirmation, enqueue sync/snapshot, then board with the assigned
amount and fee reserve. For example, with **12,000 sats principal and 2,000 sats
reserve already assigned** for this board:

```sh
python3 -m simulator.cli enqueue --config "$cfg" --id sync-01 --actor actor-01 --scenario H01 --operation sync --fee-reserve-sat 2000
python3 -m simulator.cli run --config "$cfg" --once
python3 -m simulator.cli enqueue --config "$cfg" --id board-01 --actor actor-01 --scenario H01 --operation board --args '{"amount_sat":12000}' --fee-reserve-sat 2000
python3 -m simulator.cli run --config "$cfg" --once
```

Wait for the real required confirmations, then enqueue a distinct sync and
snapshot to observe registration and independently confirmed backing. Repeat
for wallet 02 if its boarding is assigned. For an Ark send, freeze the actual
recorded recipient address and `recipient_actor` in `--args`. Do not substitute an address from a
prior campaign. Refresh and offboard use the same queue. A successful RPC means
an observed operation, not a verified transfer. Reports need an
`ark_transfer_verified` event with that recipient, amount and public coin path;
offboards need the confirmed exact script/net amount and fee checks.

A lost response remains `outcome_unknown`. First enqueue SDK sync/snapshot for
that actor and collect its retained checkpoints and public chain evidence.
The existing reconciliation closes an original action only on positive proof.
Never create a replacement payment merely because the first call timed out.

For seed recovery, first take the original wallet offline. In a separate new
wallet root, provision only the original private `mnemonic` file (0600), without
copying its database. Use a separate driver configuration/root and a `create`
request with `args.restore_from_seed=true`. The driver refuses an existing
database, uses SDK recovery, and exposes the callback's recovered/skipped/failed/
foreign/not-found public IDs. Compare the frozen original IDs, balances and
payouts independently. `sdk_complete` is an observation, not recovery proof.

## Validation status

The driver and verifier build passed with Rust 1.90.0 in an isolated Nix
build environment; 76 targeted Python tests and 50 Rust unit tests passed.
One pre-existing archived-fixture test was ignored because its fixture was not
supplied. The compiled driver also refused an unsupported operation in a
no-server smoke check. No fresh wallet connection, funding,
boarding, payment, refresh, offboard, expiry return, pending restart, seed restore
or ten-wallet campaign has yet been executed through this adapter. No backend
endpoint or live budget was supplied. Expiry payout policy/deadlines and remote
observation remain unresolved. Do not interpret synthetic tests or this sample
configuration as scenario qualification.

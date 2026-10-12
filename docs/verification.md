# Verification

Run the Python suite with:

```sh
python3 -m unittest discover -s tests
```

The current supervisor behavior passed 487 Python tests and 16 native unit tests across the driver, public verifier and seed recovery adapter. Tests cover scheduling, affordability, offline-client preservation, unknown outcomes, ownership, payout replay, fee conservation, bounded diagnostics, coverage aggregation, qualified-clock rules and public trace/export integrity.

Isolated native regtest fixtures additionally exercised:

| Fixture | Verified behavior |
|---|---|
| Empty-wallet Lightning receive | A wallet with no Ark or on-chain funds receives 2,000 sats; the original invoice and signed recipient outputs agree. |
| Thin-receipt recycling | A confirmed 4,119-sat receipt becomes 3,511 sats of Ark principal plus 608 sats of mining fees, with no additional funding. |
| Zero-spendable delegated refresh | The actual scheduler queues a refresh for 0 spendable sats and 5,000 sats needing refresh; signed replacements restore spendability. |
| Payments and reservations | Ark and internal/external Lightning payments succeed; a pending-sync reservation closes once after later signed receive evidence. |
| Public payout and automatic seed recovery | Fresh native coin/link/record checks and anchored public operator derivation verify a 10,000-sat entitlement and 9,703-sat payout. A seed-only spend recovers the payout under the 2,000-sat cap, preserving absence and separate capital accounting. |
| Delegated entitlement and native boundaries | The frozen 5,000-sat delegated intent becomes a signed replacement tied to the actual round; the fee closes once. Fresh before/after evidence accompanies online native operations. |
| Concurrent clients | Two and three distinct native wallets overlap between their before/after boundaries. Five boards produce 50,000 sats of confirmed signed principal with 3,815 sats total mining fees, each under its 2,000-sat cap. |
| Public evidence export | A payout bundle replays serialized payout/input transactions and real protocol, link and record signatures through a public archive-only RPC server, with no upstream connection. |

Independent audits reconstruct isolated raw blocks in a network-disabled Bitcoin Core instance and rerun signature and ownership verification. They check frozen inputs and proposals, confirmed outputs, fees, replacement coins, and receipt reuse.

These results qualify the stated fixture behavior. They do not establish live signet convergence, every catalogue scenario, or full operator-capital accounting. Regtest's zero service fees are separate from fees quoted by a signet server.

Native fixtures require a compatible SDK test checkout, product binaries, Bitcoin Core, PostgreSQL, and Docker for Lightning tests. The runner records source and binary fingerprints, applies resource limits, and preserves raw results and failures under `runs/`, which is excluded from version control.

To run a native fixture, use an isolated checkout at the tested SDK revision. Copy `integration/simulator_vertical.rs` into its `testing/tests/bark_sdk/` directory and register `mod simulator_vertical;` in `mod.rs`. Keep that checkout free of other changes.

```sh
python3 integration/run-regtest.py refresh-check \
  --sdk-source fixture-source \
  --product-bin-dir source/target/debug \
  --test simulator_zero_spendable_scheduled_refresh
```

The runner uses its own `fixture-target/` and exclusive fixture lease. Tool locations can be supplied through `PROTOC`, `CMAKE_PREFIX_PATH`, `POSTGRES_BINS`, and `BITCOIND_EXEC`. Lightning fixture settings use `LIGHTNINGD_DOCKER_IMAGE` and `LIGHTNINGD_PLUGIN_DIR`.

For a completed board-disappearance fixture, reconstruct and audit its raw chain with:

```sh
python3 integration/verify-regtest.py runs/integration/board-check
```

For the automated public-payout fixture, use `--test simulator_public_payout_seed_recovery`.
Its exported bundle includes the public material needed for signature replay:

```sh
python3 integration/verify-recovery.py runs/integration/recovery-check \
  --bitcoind /path/to/bitcoind
python3 integration/verify-export-bundle.py \
  runs/integration/recovery-check/out/confirmed-payout-export \
  --proof-binary target/debug/vtxo-proof
```

To verify concurrent native clients and independently audit their confirmed coins and fees:

```sh
python3 integration/run-regtest.py concurrent-check \
  --sdk-source fixture-source \
  --product-bin-dir source/target/debug \
  --test simulator_concurrent_clients
python3 integration/verify-concurrency.py runs/integration/concurrent-check \
  --bitcoind /path/to/bitcoind
```

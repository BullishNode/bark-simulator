# Verification

Run the Python suite with:

```sh
python3 -m unittest discover -s tests
```

The current supervisor behavior passed 324 Python tests and eight native driver unit tests. Tests cover scheduling, affordability, offline-client preservation, unknown outcomes, ownership, payout replay, fee conservation, bounded diagnostics, coverage aggregation, and qualified-clock rules.

Isolated native regtest fixtures additionally exercised:

| Fixture | Verified behavior |
|---|---|
| Empty-wallet Lightning receive | A wallet with no Ark or on-chain funds receives 2,000 sats; the original invoice and signed recipient outputs agree. |
| Thin-receipt recycling | A confirmed 4,119-sat receipt becomes 3,511 sats of Ark principal plus 608 sats of mining fees, with no additional funding. |
| Zero-spendable delegated refresh | The actual scheduler queues a refresh for 0 spendable sats and 5,000 sats needing refresh; signed replacements restore spendability. |
| Payments and reservations | Ark and internal/external Lightning payments succeed; a pending-sync reservation closes once after later signed receive evidence. |

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

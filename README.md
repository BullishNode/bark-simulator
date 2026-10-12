# Bark Simulator

Bark Simulator exercises Ark and Lightning wallet behavior against a compatible Bark server. It runs persisted client workloads, collects public protocol and chain evidence, and reports payments, refreshes, payouts, fees, and coverage.

## Features

- Independent client wallets with persistent online and offline state.
- Ark transfers, Lightning invoices and payments, interactive and delegated refresh, boarding, and collaborative offboarding.
- A durable action queue and hash-chained SQLite event journal, including streamed proposals and bounded, sanitized driver diagnostics.
- Independent signed-coin ownership checks and confirmed-chain reconciliation of customer fees and payouts.
- Recycling of a confirmed owned payout through a transaction that spends only that receipt, with a principal minimum and fee ceiling.
- HTML, Markdown, JSON, and CSV reports. Coverage distinguishes available adapters, attempted operations, and independently verified outcomes.

The scenario catalogue contains 80 behaviors. Catalogue entries and successful operations do not imply complete scenario qualification. Full operator-capital accounting and several scenario drivers remain incomplete.

## Quick start

Requires Python 3.11 or later. The Python supervisor has no third-party runtime dependencies.

```sh
python3 -m unittest discover -s tests
python3 -m simulator.cli demo --output runs/demo
```

The demo uses synthetic data and writes its report under `runs/demo/`.

## Native driver

The driver requires Rust, a C/C++ toolchain, CMake, Protocol Buffers (`protoc`), and a compatible Bark SDK checkout in `source/`. The currently tested SDK revision is `d47c6a4d115b30bf56219d69251fa9238d13f32d`; Cargo dependencies are fixed in `driver/Cargo.lock`.

```sh
git -C source checkout d47c6a4d115b30bf56219d69251fa9238d13f32d
CARGO_TARGET_DIR="$PWD/target" cargo build --manifest-path driver/Cargo.toml --locked
CARGO_TARGET_DIR="$PWD/target" cargo test --manifest-path driver/Cargo.toml --locked
```

This builds `bark-sim-driver`, `vtxo-proof`, and `seed-restore`. The native driver accepts signet and local regtest configurations; it refuses mainnet.

## Configuration and execution

Copy `config.example.toml`, `config.driver.example.json`, and `config.wallet.example.toml` into private local configuration files. Replace their placeholders with measured server identity, endpoints, wallet paths, and executable hashes. The example configuration intentionally cannot dispatch real actions.

```sh
SIM_DRIVER_CONFIG="$PWD/config.driver.json" \
  python3 -m simulator.cli observe --config config.local.toml --once

SIM_DRIVER_CONFIG="$PWD/config.driver.json" \
  python3 -m simulator.cli run --config config.local.toml
```

`observe` collects evidence without dispatching queued actions. `run` dispatches only when enabled in the configuration and when the pinned target is healthy and its observation is fresh. Wallet funding must be explicitly declared; the scheduler does not silently top up clients.

Keep wallet directories, mnemonics, RPC credentials, local configurations, and campaign databases private. The repository contains source and configuration templates.

See [accounting and state invariants](docs/invariants.md) and [verification](docs/verification.md) for the evidence requirements and current test coverage. Deployment templates are in `deploy/`.

[Payout verification and recovery](docs/payout-verification.md) describes public
proof imports, historical operator change checks and declared seed-only recovery.

Use [public evidence exports](docs/observability.md), the [record index](docs/index.md)
and the [query cookbook](docs/cookbook.md) to inspect traffic and accounting evidence.

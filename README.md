# Bark Simulator

Bark Simulator exercises Ark and Lightning wallet behavior against a compatible Bark server. It runs persisted client workloads, collects public protocol and chain evidence, and reports payments, refreshes, payouts, fees, and coverage.

The maintained source is on the default `master` branch.

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

The driver requires Rust, a C/C++ toolchain, CMake, Protocol Buffers (`protoc`), and a compatible Bark SDK checkout in `source/`. The currently tested SDK revision is `8f2286ee7e1631b0ceccd1631ec3b728a1bb0a52`; Cargo dependencies are fixed in `driver/Cargo.lock`.

```sh
git -C source checkout 8f2286ee7e1631b0ceccd1631ec3b728a1bb0a52
CARGO_TARGET_DIR="$PWD/target" cargo build --manifest-path driver/Cargo.toml --locked
CARGO_TARGET_DIR="$PWD/target" cargo test --manifest-path driver/Cargo.toml --locked
```

This builds `bark-sim-driver`, `vtxo-proof`, `seed-restore`, `server-policy-proof`, `noah-private`, `sweep-proof-trial`, and the offline `noah-public-proof` invoice verifier. The native driver accepts signet and local regtest configurations; it refuses mainnet. Helper availability does not qualify a live scenario; Noah payments require the independently checked readiness described in [Owned Noah journeys](docs/noah.md).

## Configuration and execution

Copy `config.example.toml`, `config.driver.example.json`, and `config.wallet.example.toml` into private local configuration files. Replace their placeholders with measured server identity, endpoints, wallet paths, and executable hashes. The example configuration intentionally cannot dispatch real actions.

```sh
SIM_DRIVER_CONFIG="$PWD/config.driver.json" \
  python3 -m simulator.cli observe --config config.local.toml --once

SIM_DRIVER_CONFIG="$PWD/config.driver.json" \
  python3 -m simulator.cli run --config config.local.toml
```

`observe` collects evidence without dispatching queued actions. `run` dispatches only when enabled in the configuration and when the pinned target is healthy and its observation is fresh. Wallet funding must be explicitly declared; the scheduler does not silently top up clients.

For a continuous workload, declare a unique public `campaign_seed` in `[runtime]`. The seed and realism rates become immutable campaign metadata. Each scheduling draw is journaled: cadence deadlines vary from 0.5 to 1.5 times their base interval, payment amounts respect the available balance and fee reserve, and advertised absent recipients are selected with probability `0.05`. Ordinary clients have a `0.005` per-day disappearance hazard that takes effect only at a supported completed boundary and preserves the Lightning candidate guard. This public seed is unrelated to wallet seeds.

When pending Lightning receives exceed one sync's fee reservation, the driver polls at most 32 original checkpoints within that reservation. The next pass starts after the previous completed pass's last selected payment hash, so an unchanged backlog cannot repeatedly exclude its last invoice. Unknown actions remain held. A bounded receive pass defers full wallet synchronization; completion alone does not establish receiver readiness, payment success, or a reconciled fee.

New internal Lightning invoices are created only for an affordable, recently observed payer and a ready recipient. A fresh `pool_status` observation must prove confirmed unspent pool capacity beyond the pool expiry margin before invoicing and again before payment dispatch. Missing evidence holds new payment work; a quiet log tail is not readiness. Pool capacity is a scheduling observation, not a reservation.

The payer proposal starts a separate durable receiver sync for its exact frozen payment hash. This sync polls every 20 seconds within a bounded 180-second window while the payer runs. It does not poll unrelated invoices, raise the fee reservation, recreate an invoice or replay the payer. A canceled checkpoint completes only after the driver verifies typed server cancellation, an originally `AwaitingPayment` state and checkpoint removal; its fee stays unknown until independent accounting closes it. Ordinary refresh follows the SDK refreshable balance instead of refreshing every hour.

Live payout fee totals come from the active confirmed-chain settlement verifier, once per transaction. Recipient and operator portions must sum to the raw mining fee. Transactions without complete fee proof stay excluded, and absent proof is reported as unknown rather than zero.

Keep wallet directories, mnemonics, RPC credentials, local configurations, and campaign databases private. The repository contains source and configuration templates.

See [accounting and state invariants](docs/invariants.md) and [verification](docs/verification.md) for the evidence requirements and current test coverage. Deployment templates are in `deploy/`.

[Payout verification and recovery](docs/payout-verification.md) describes public
proof imports, historical operator change checks and declared seed-only recovery.

Use [public evidence exports](docs/observability.md), the [record index](docs/index.md)
and the [query cookbook](docs/cookbook.md) to inspect traffic and accounting evidence.

[Fee observations](docs/fee-watch.md) explain independent current-rate comparisons,
raw mining-fee verification and the limits of anonymous payout tick summaries.

[Direct settlement with per-key attribution](docs/direct-per-key.md) documents the separately built C adapter and its remaining qualification gaps.

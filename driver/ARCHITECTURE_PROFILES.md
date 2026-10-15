# Shared source, explicit native SDK builds

All profiles use the same simulator scenarios, accounting, oracles and catalogue.
Place the exact owning track SDK at `source/` and record its commit, tree and any
declared overlay alongside the simulator commit and binary hash.

| Track | Native Cargo feature | Driver architecture_profile |
| --- | --- | --- |
| A | `--features two-step` | `two_step_per_key` |
| B | default features | `direct_xpub` |
| C | `--features direct-per-key` | `direct_per_key` |

The two explicit features are mutually exclusive. The native driver rejects a
different or unknown profile before RPC or wallet operations. Only the default B
build accepts an omitted profile, preserving existing unprofiled direct campaigns.
An existing profiled campaign retains its original immutable profile on restart.

A uses rotating sequence/record attestations and per-key signatures. C uses its
immutable record and native key-link envelope. B uses its native account xpub and
child origin. Their identity evidence cannot be substituted for one another.

Qualification requires building and testing these same source bytes against all
three final SDKs with the corresponding features. Source integration, a successful
Python suite or a historical SDK build does not establish that matrix. Record
actual toolchain, resources, cache state, commands, selected tests and raw results.
Run the common Python suite once per integrated candidate; retain failures.

The inherited C adapter still refuses unqualified raw/probe operations. This is an
explicit remaining coverage gap, and supplies no credit for required hostile or
protocol scenarios. Required native adapter work and the complete original gates
must pass before release. No profile selection authorizes campaign dispatch,
alters existing funds/budgets, or starts the final qualified simulation clock.

## Continuous compatibility checks

`.github/workflows/shared-simulator.yml` runs the common Python suite and three
independent native jobs on pull requests and pushes to `master`. Each native job
checks out an exact SDK commit at `source/`, uses the shared lockfile and native
Rust 1.90.0, builds every driver binary, and runs the library/binary pure tests.
`GIT_HASH` must identify that actual SDK checkout: the Noah private helper embeds
it as `SDK_COMMIT`. The simulator commit is recorded separately.

The workflow currently pins compatibility candidates A `c73bb909`, B `69ca8cce`,
and C `8c4478cf`; those pins are not production promotion. Update them explicitly
when an owning candidate changes. The jobs retain exact commits/trees, profile,
feature, lock/catalogue hashes, compiler versions and original failed/passing
logs. Hosted build environments differ from the dedicated qualification VMs;
their elapsed time is not an architecture benchmark. These checks do not run
financial RPCs, server migration, mobile journeys or qualified simulations.

## Native regtest fixture source

`integration/run-regtest.py --sdk-commit <full-commit> --sdk-tree <full-tree>`
accepts an explicit owning SDK pin instead of pretending it is the historical
`d47c6a4d` fixture baseline. The historical default remains available. The runner
requires exactly its original two fixture overlay paths, checks the shared Rust
harness bytes, records both overlay hashes and the committed SDK tree, and
invalidates the result if SDK source or overlays change during execution.

This source guard does not port the historical harness. Its sequence fields,
two-step payout path, minimum payout and expected recovery behavior still need
review against the selected profile. An arbitrary new SDK pin, or a successful
fixture build, cannot qualify A/B/C identity and economic contracts by itself.

For an explicitly profiled fixture, pass `--architecture-profile` with the native
profile name from the table above. The wrapper clears any inherited profile
environment value; its argument flows through Rust-created configuration and
fixture manifests into Python `Config` and every fixture `Store`, including the
padding audit. The manifest and actual driver configuration must agree before
state is opened. An unknown, null, missing or mismatched explicit profile is
refused. Omitting both profile fields preserves the historical Track B fixture.
This propagation does not change the selected SDK, build the historical Rust
harness against it, or replace its architecture-specific economic assertions.

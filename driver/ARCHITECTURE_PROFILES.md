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

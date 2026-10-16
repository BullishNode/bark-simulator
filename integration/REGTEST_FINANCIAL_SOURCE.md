This contribution implements partial fixture evidence, not financial qualification.
It does not change identity_bootstrap, the observer's complete=false, any engine
admission rule, a profile flag, funding, or native actor creation.

regtest_financial.collect takes an existing loopback Core/cookie and a SHA-bound
qualified native executable plus its two owning admin endpoints. It executes only
fixed read-only Core requests and `captaind rpc --addr ENDPOINT wallet-inventory`.
A separate owned process group gives the whole collector a real25s deadline,
including native descendants. It verifies the actual REGTEST genesis, non-IBD
stable chain bracket, each native wallet tip and complete inventory, independent
Core value/script/confirmed-unspent matching and actual unreserved eligibility.
It reports observed physical rounds and fee-wallet amounts. It cannot declare
liabilities or total treasury merely from these balances. Native JSON/public
projection/128MiB executable/2000row bounds are explicit. Original immutable
TraceStore capture and protected process provenance still need integration.

freeze_declaration writes finite prospective bytes with O_EXCL0600, fsync(file)
and fsync(parent); it never raises or resets an existing declaration. The explicit
A five-wallet scenario can declare operator1M, five20k grants,10k Boards,2k caps,
lifetime432/six confirmations, pooloff/noLN. These are prospective limits, not
observed funding or native fee policy. A larger numerical marker alone grants
nothing. fresh_directory_fact proves only an empty owned private filesystem and
keeps zero_assets_verified=false. Future seed assets cannot be inferred before
native creation. A's own signed ownership proof must be retained and verified
before independent descriptor/chain zero-assets proof can admit its create.

UNIMPLEMENTED and NOT_RUN: real native pool counts, exhaustive current liability
and ownership snapshots, all six actual signed fee paths/cumulative A ledger,
A-specific two-step owner proof, fresh actor on-chain/mempool zero-assets proof,
immutable treasury/envelope admission and actual native REGTEST execution. The
collector returns complete=false, qualified=false, financial_readiness=false and
an explicit missing_sources list. These facts cannot pass financial readiness.

Actual reusable C source provenance (not A qualification): product
9025775295af3fbef51205ae5edaebaf374d8ca2, wallet/inventory.rs59 onward;
captaind/main.rs694 onward fixed wallet-inventory JSON; current native CLI emits
public descriptors and stripped transaction bodies. A must independently match
its actual native ABI and qualified product; absence must hold, not alias C.
Canonical common baseline0038; A's published SDK metadata contributiondc3b85a
provides explicit sdk_commit propagation separately. No A checkout was changed.

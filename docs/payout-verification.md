# Payout verification and recovery

Payout rows are candidates. The simulator checks confirmed Bitcoin transactions,
signed coin ownership, pre-commit state, grouped net amounts and operator change
before recording `amounts_checked`. Missing evidence leaves a pending verdict.

Public coin bundles can supply missing proofs without opening an absent client's
wallet. Configure `[proofs] bundles` with absolute JSON paths outside wallet
directories. Each version-1 bundle contains `actor`, `identity` (network, genesis
and server public key), and `coins`. Every coin includes its signed serialization,
ID, user public key, amount, expiry, key-link attestation and fallback record
binding. The native verifier checks the signatures and confirmed backing afresh.
Imports preserve actor availability and do not count as payment traffic.

For historical operator change, configure `[operator] descriptors` with absolute
paths to public JSON declarations outside wallet directories. Each declaration
contains `schema_version: 1`, `identity`, `descriptor`, `first_index` and
`last_index`. Core must identify a public, ranged, solvable descriptor. An address
derived from it must match an independently confirmed output already attributed
to the rounds wallet. Only then can confirmed payout outputs with matching
derived addresses supply historical operator scripts. The declaration is
immutable, and bounded derivation resumes between ticks. Spent change does not
need to remain an unspent output.

Seed recovery requires `[funding] recovery_address`, the funding wallet, and a
`[recovery]` declaration with a pinned `command`, per-actor `seeds`,
`maximum_fee_sat`, `fee_rate_sat_vb` and `timeout_seconds`. Seed backups must be
owned regular files with mode 0600 outside original wallet directories. The
adapter scans BIP84 from genesis with a gap of 20 in a separate directory, then
restricts signing to the already checked payout outputs. The destination must
belong to the declared funding wallet, and the fee cannot exceed 2,000 sats or
the action reservation.

The exact signed transaction is frozen before broadcast. An uncertain broadcast
is reconciled by its transaction ID; it never authorizes another signing or
broadcast attempt. Confirmed recovered principal and fees are recorded in a
separate capital bucket, with no recycling or traffic credit. Permanently absent
clients remain offline throughout.

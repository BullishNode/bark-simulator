# Direct settlement with per-key attribution

`direct_per_key` is an explicit fresh campaign profile. It reuses the common
engine, scheduling, accounting, direct-carrier checker, journal and clock.
Existing profiles and historical unprofiled campaigns retain their interfaces.
A campaign cannot change profiles or adopt an old database under this profile.

Build the same native driver with feature `direct-per-key` against a separately
declared C SDK at `source/`. Bind immutable simulator/SDK trees, lockfile, supported
build environment and binary hashes. An active checkout or changed symlink is
not build provenance. Do not repin an existing A/B driver or campaign to C.

```sh
cargo build --manifest-path driver/Cargo.toml --locked --features direct-per-key \
  --bin bark-sim-driver --bin vtxo-proof
```

Use that command only inside the declared supported build environment and
immutable paired layout. Driver configuration must include
`"architecture_profile": "direct_per_key"`. The C feature refuses other profiles
before connecting or opening a wallet; a default build refuses C configuration.
Actual product identity and observation readiness remain separate gates.

The adapter exports canonical retained mailbox records and acknowledged
key-link signatures. It never regenerates signatures to claim admission. The
independent verifier parses V4 records/V1 links and checks BIP340 with literal
domains, actual chain identity and full compressed mailbox/coin keys. Optional
signed recovery indices do not derive ownership. The common public coin
verifier checks signed authorization paths and confirmed backing. Current
economic ownership, Lightning outcomes, payment and recovery remain separate.

C bindings contain `mailbox_pk`, `spk`, `fallback_record`; coin/address evidence
also contains `key_link_attestation`. Native output binds those exact bytes and
includes `record_version=4`, `key_link_version=1`, `policy_pubkey_full`,
`recovery_index`, `record_signature_valid` and `key_link_signature_valid`.
Account xpubs, account-child flags and mutable record sequences are refused.

The direct journal preserves common allocation/carrier/mapping fields. Its C
envelope uses `fallback_protocol=4` and `architecture_profile=direct_per_key`.
Record rows are `{mailbox_pk, spk, mailbox_sig}`; link rows are
`{user_pubkey, mailbox_pk, sig, recovery_index}`. Complete consistent bounded
candidate frames are required. A journal row is not payment. Keep independent
source proofs, exact confirmed winner/vout, actual prevout fees, flat 1,000-sat
output charges, script dust and at-most-once checks.

Current direct checks support ordinary Board sources. Delegated, unregistered
and Lightning arbitration remain gaps until independent adapters qualify them.
C raw/protocol record probes are held instead of aliased to xpub probes. Public
exports preserve C proofs and optional native signature replay. Terminal direct
journal archive replay remains an explicit gap, never a legacy payout success.

Python consumer controls and Rust public vectors are not funded native/live
evidence. All 50-key/offline 25+50, eight-key, full suites, scale/soak, Noah/web,
80 live outcomes, final clock/ramp, operator and comparison gates still apply.

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

The first bounded C phase is separately declared through `c_pilot.declare`.
Its two customers receive grants of25,000sat and0sat. One original sender Board
uses20,000sat, then waits for3 confirmations and actual adoption before one
original2,000-sat Arkoor payment. Initial bank assets must equal the explicitly
declared and independently scanned opening (the current request is150,000sat,
never an observed balance). Funding miner fees are capped at1,000sat. The
conservative native Board total service-plus-miner reserve is1,000sat; these
costs are reported separately, and a larger quote holds before signing. The
ordinary60,000sat and urgent40,000sat budgets remain backed, with urgent funds
ringfenced in the bank. Initial operator wallets remain empty. Later operator
funding needs a new declared and observed transition. Existing B five-output
and three-customer phase rules remain unchanged.

Native `create` exports exactly51 existing canonical acknowledgements using
read-only key lookups (authentication0 and receiving1..50). The common verifier
checks every signature before recording creation ownership. Initial C admission
requires exactly those102 public links and2 immutable records in both consistent
frontier projections; all monetary tables must be empty. Signed indices remain
recovery metadata. No address allocation is performed to inventory these keys.

After full native sync, the fresh pilot exports every retained acknowledgement
over the required contiguous range0..last-issued+50, strictly bounded below128.
Every lookup must succeed; errors never mean end of inventory. It does not do
this immediately after Board/address issuance, when refill need not yet have
happened. Independent signature checks admit legitimate newly linked lookahead
keys. Source qualification additionally reads every bounded actual SQLite
`idx/public_key/linked_proof/issued` row under the existing wallet-root Lease and
read-only transaction, compares the exact public set and then matches the
server's complete link union. An extra row, missing key, altered proof or changed
destination holds. Initial source collection also checks exactly51 actual rows
with only authentication0 issued. Source collectors therefore require that
existing wallet-root Lease. This is a fresh-pilot seam; generic sparse restoration
and callback wallet inventory remain separate full-goal gates.

`deploy/track-c/server-observer.py` uses a declared native read-only ops transport.
It refuses until `/etc/track-c/deployment-public.json` is active, root-owned and
matches both installed observer files and the ops executable. Public SQL/wallet
validators reuse the precise B producer export recorded in adjacent
`provenance.json`; no C request selects SQL, host, RPC method or executable.
The source reports systemd unit/executable identity explicitly. The existing
identity field names `container`/`image_digest` carry that declared unit and
executable artifact digest only under `runtime_transport=systemd`.

The common startup gate routes C to `c_runtime.verify`, requiring the same
PID/boot/start-ticks/systemd invocation and high-resolution start timestamp,
exact executable/config/schema/product identity, original pre-exec configuration
capture and fresh current observations. Both lifetimes remain48blocks and Board
depth3. A manifest or disk hash alone is never loaded-configuration proof.
Use `remote_observer` with explicit C profile, SSH target, public financial
context and actual campaign config; its SDK assertion remains the reviewed
immutable paired-build provenance, never a commit inferred from an ELF.

The pilot queues its declared actions through the ordinary Engine with workload
`none`; generic continuous scheduling has no C qualification from this phase.
The native observer currently provides snapshot/financial facts, closed frontier,
direct journal and coin/pending/link/record/nursery pages. Raw binding probes,
logs, dedicated pool/Lightning sources and absent-source qualification remain
explicit holds until implemented and independently tested.

Python consumer controls and Rust public vectors are not funded native/live
evidence. All 50-key/offline 25+50, eight-key, full suites, scale/soak, Noah/web,
80 live outcomes, final clock/ramp, operator and comparison gates still apply.

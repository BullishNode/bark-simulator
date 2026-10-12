# Export and audit

Export public journal evidence for an actor, a payout transaction, or a period.
The export reads a consistent SQL backup without opening customer wallets.
Ownership parents and the whole payout group accompany a selected actor or
transaction, so grouped fees and expiry ownership can be replayed.

```sh
python3 -m simulator.export_bundle export --state runs/epoch \
  --actor actor-09 --out exports/actor-09
python3 -m simulator.export_bundle export --state runs/epoch \
  --payout TXID --out exports/payout
python3 -m simulator.export_bundle export --state runs/epoch \
  --from 2026-01-01T00:00:00Z --to 2026-01-02T00:00:00Z \
  --out exports/day
python3 integration/verify-export-bundle.py exports/actor-09
```

A bundle contains `manifest.json`, `README.md`, public actors and actions,
`events.jsonl`, `trace.jsonl`, `timeline.jsonl`, `evidence.json`, signed coin
proofs, and archived Core responses. The manifest records selection limits,
file hashes, counts, and the complete source chain tips checked during export.
A selected record retains its predecessor hash even when the selection omits
that predecessor. Independent source tips authenticate provenance; file hashes
alone detect changes relative to the supplied manifest.

The auditor reruns the grouped payout checker from bundle data alone. It reports
recipient net amounts and recipient/operator fee shares. An `amounts_checked`
result means that this arithmetic and ownership attribution replay succeeded.
`raw_chain_reverified` separately reports whether serialized Bitcoin payout and
input transactions reproduced the identities, outputs and exact mining fee.
Confirmation counts are archived Core observations, not a fresh chain query or
an independently validated header chain.

To recheck protocol, wallet-link and record signatures, use a trusted compatible
native public verifier:

```sh
python3 integration/verify-export-bundle.py exports/actor-09 \
  --proof-binary target/debug/vtxo-proof
```

This serves exported public anchor transactions through a temporary loopback
RPC fixture with no upstream connection. The native verifier receives the exact
serialized coin, signed wallet link, signed record, pinned server key and
archived genesis. The resulting identities, path and destination must match the
export. Missing raw signatures or anchors remain explicit gaps and do not
acquire trust from cached validation flags. An audit does not establish current
spendability, settlement arbitration, private seed recovery, or a complete
failure scenario.

Diagnostic writes are bounded and privacy checked. A record larger than the
configured bound, invalid UTF-8, a truncated process stream or private material
produces a redaction marker. Daily retention archives closed SQLite partitions;
it does not erase diagnostic history or alter the financial journal. Fixture
runs copy daemon stdout, stderr and Core debug logs to `daemon-logs/` and record
their hashes in `daemon-logs.json`. Original fixture logs stay local artifacts;
only privacy-checked diagnostics enter the public trace.

Capture requires the supervisor to attach the callbacks provided by
`process`, `ChainReader` and `remote_observer`. The observer's optional
`--trace-events` stream preserves public samples when a later observation fails.
Fresh native before/after evidence and target daemon logs require compatible
producer operations. Their absence is an evidence gap; archived snapshots must
not be substituted as current observations.

An operating envelope may include immutable `operation_fee_paths`, a nonempty
map from allowed operation names to nonempty lists of distinct existing fee
paths (`round`, `pool`, `sweep`, `payout`, `claim`, `progression`). Existing
envelopes without the map retain their full policy and six positive ceilings.

For scoped envelopes, the union of listed paths must have positive actual fee
ceilings. Every other path must have an explicit JSON null ceiling and remains
unavailable. An unlisted operation is refused before any native driver or pool
query. A readiness proof must match the whole ceiling map, including nulls.

The finite direct pilot lists `ordinary`, `create`, `address`, `snapshot`,
`sync`, `board`, and `send_arkoor`, each with `['sweep', 'payout']`. This does
not enable Lightning, claims, progression, refresh, exits, or raw operations.
Scoped sync is checked under its declared sync paths; legacy sync retains its
progression check. Ordinary and explicitly listed urgent readiness are checked
separately; a successful ordinary check never authorizes an unlisted urgent
operation. Existing capital, confirmed fee backing, cost deduplication, queued
reservation, freshness, exact-pin and Lightning ownership checks remain.

This map is not bootstrap permission or a financial source producer. Full
treasury/readiness remains required for funded actions. The separate opt-in
zero-principal identity phase is described in IDENTITY_BOOTSTRAP.md.

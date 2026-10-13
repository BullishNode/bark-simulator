# Accounting and state invariants

Each campaign binds its state to a wallet root, network, server key, and executable identity. State and wallet leases prevent multiple dispatchers from using the same wallets.

Deployment changes require an independently qualified epoch inside the existing campaign. A historical image mismatch between the original manifest and preserved metadata requires an explicit reconciliation with evidence for both values; it never qualifies the historical switch. The reconciliation event and registry must agree. Removing either record or editing the metadata blocks binding. Original events, funding declarations, balances and signed expiries remain intact; detecting a complete database rollback also requires the external preserved-history evidence.

Direct controllers acquire durable actor ownership under the same SQLite writer transaction used by native claims. Active or unknown actor leases and unfinished private enrollment block ordinary queueing and dispatch. Unknown ownership never expires automatically. Ordinary scheduling, grants, recovery and recycling exclude Noah participants; their explicit namespace does not establish payment readiness or transfer ordinary capital. Noah dispatch requires its separate qualified controller and protected evidence path.

Actions reserve a configured fee allowance. Interrupted requests and ambiguous SDK errors remain unknown outcomes. Silence does not prove failure, release a reservation, or authorize retry. Confirmed evidence closes fees once; service charges and mining fees are reported separately.

Ownership requires independently checked signed protocol data, wallet records, and key-link attestations. Cached ownership information does not establish a coin's current spend state. State observations and retry candidates remain journaled.

Payout checks bind each entitlement to its rightful recipient script and confirmed output. Identical evidence is idempotent; conflicting ownership, duplicate payments, and inconsistent amounts are incidents.

Recycling spends exactly one frozen, confirmed, owned on-chain receipt. Before signing, the native driver prepares and records the unsigned transaction and exact quote, checks the board cap, principal minimum, and fee ceiling. Reconciliation checks principal plus service charge, mining fee, and own change against the receipt. Sources are never combined or blindly reused.

Permanently offline clients stay offline. Public evidence collection does not open their original wallets. Seed recovery uses separate wallets and requires independently verified payout evidence.

Qualified campaign time requires a signed Ark receipt within ten minutes and verified Lightning success within sixty minutes. Setup, downtime, stale observations, and unhealthy periods earn no time. Historical clock values are retained separately.

Reports show unknown values and incomplete scenarios explicitly. A successful RPC, positive balance, or catalogue entry does not establish a complete scenario outcome or minimum capital requirement.

A dispatch pause fences both queuing and claiming. A pause committed by another process during scheduling stops new dispatch while the observer continues; it does not restart the supervisor or cancel existing prepare-only seed scans. Incident pauses retain the same fence and never resume automatically.

Existing seed-recovery jobs are polled independently of target inventory availability. A completed preparation can be recorded during a pause, while new preparation and broadcast remain blocked. A lost preparation handle after a restart stays `prepare_unknown`; it is never silently restarted or re-signed.

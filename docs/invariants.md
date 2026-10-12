# Accounting and state invariants

Each campaign binds its state to a wallet root, network, server key, and executable identity. State and wallet leases prevent multiple dispatchers from using the same wallets.

Actions reserve a configured fee allowance. Interrupted requests and ambiguous SDK errors remain unknown outcomes. Silence does not prove failure, release a reservation, or authorize retry. Confirmed evidence closes fees once; service charges and mining fees are reported separately.

Ownership requires independently checked signed protocol data, wallet records, and key-link attestations. Cached ownership information does not establish a coin's current spend state. State observations and retry candidates remain journaled.

Payout checks bind each entitlement to its rightful recipient script and confirmed output. Identical evidence is idempotent; conflicting ownership, duplicate payments, and inconsistent amounts are incidents.

Recycling spends exactly one frozen, confirmed, owned on-chain receipt. Before signing, the native driver prepares and records the unsigned transaction and exact quote, checks the board cap, principal minimum, and fee ceiling. Reconciliation checks principal plus service charge, mining fee, and own change against the receipt. Sources are never combined or blindly reused.

Permanently offline clients stay offline. Public evidence collection does not open their original wallets. Seed recovery uses separate wallets and requires independently verified payout evidence.

Qualified campaign time requires a signed Ark receipt within ten minutes and verified Lightning success within sixty minutes. Setup, downtime, stale observations, and unhealthy periods earn no time. Historical clock values are retained separately.

Reports show unknown values and incomplete scenarios explicitly. A successful RPC, positive balance, or catalogue entry does not establish a complete scenario outcome or minimum capital requirement.

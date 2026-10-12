# Explicit owner allocations

A new owner allocation uses its own immutable declaration and funding identity.
Initial and ramp grants, the first owner renewal, and their action IDs remain
unchanged. Declaring an allocation authorizes no automatic transfer: funding
requires the explicit tranche ID and a complete exact source and recipient set.

The traffic allocation `owner-renewal-2026-10-12-traffic-2` grants 9,200 sats to
each of actor-01, actor-02, actor-04, actor-06, actor-07, actor-08, actor-11 and
actor-12, and 13,200 sats to actor-05. The complete set is 86,800 sats with a
2,000-sat funding mining-fee ceiling. Each original verified funding address
and grant amount is frozen. Permanently offline actor-03, actor-09 and
actor-10 are excluded. An offline or disappearing recipient, or pending money work, holds
the frozen allocation; recipients and amounts are never silently rewritten.

One exact confirmed wallet-owned unspent source must be explicitly declared.
Wallet ownership, amount and script are checked against both wallet unspent
records and the exact Core output. Existing funding journals and allocation
intents are checked for previously committed input use. Aggregate balance
cannot qualify a source, and no extra input is allowed. Recipient outputs,
owned change and exact fees are checked before signing. Signed bytes and the
transaction ID are persisted before broadcast. A lost reply or restart queries
that same transaction and never creates or rebroadcasts a replacement.

Confirmed grants retain their own tranche metadata and board action IDs. The
native receipt-input guard spends precisely the declared actor grant. Source-only
autosizing preserves a minimum **net Ark principal** of 8,000 sats, or 12,000
for actor-05, within the original absolute 2,000-sat board-fee ceiling. Boarding requires a fresh synchronized per-actor view. Queued snapshots and
address reads do not block the fixed funding grants or get cancelled. A quote
that cannot meet the net floor holds before signing; principal is never lowered
and undeclared inputs are never combined. The separate 5,000-sat payout
recycling cap continues to govern payout recycling.

These movements allocate existing owner capital to clients. They receive no
recycling or qualified customer-traffic credit. Confirmation does not reopen a
phone that disappeared after the transfer, and that phone never queues a board.

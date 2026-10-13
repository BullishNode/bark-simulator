# Analysis cookbook

Use a public export for repeatable analysis. Its timeline includes actor-linked
trace and accounting records; its README describes evidence limits. SQLite
queries below run against `state.sqlite` or a selected trace partition.

Inspect read-only [fee observations](fee-watch.md) without summing repeated
transactions as new costs:

```sql
SELECT txid,json_extract(payload,'$.mining_fee_sat') AS mining_fee_sat,
       json_extract(payload,'$.vsize') AS vsize,
       json_extract(payload,'$.actual_sat_per_vbyte') AS actual_sat_per_vbyte
FROM fee_watch_transaction ORDER BY txid;

SELECT id,json_extract(payload,'$.estimate.sat_per_vbyte') AS current_reference,
       json_extract(payload,'$.unknowns') AS evidence_gaps
FROM fee_watch_tick ORDER BY rowid;
```

These tables exist after the fee collector is initialized. The reference is
sampled at the observer tick, not necessarily when the transaction was built.
The report keeps anonymous server counters and unbound warnings separate from
each payout's local verification reason. Server waiting reason and age require
producer evidence that binds an identified payout to unique ticks.

Find expired public-key outputs still reported unclaimed, excluding positively
decoded protocol padding. Unknown or failed decoding stays in the candidate set:

```sql
SELECT s.id,json_extract(s.payload,'$.expiry') AS expiry,
       c.classification
FROM server_item s LEFT JOIN server_coin_classification c
ON c.coin_id=s.id
AND json_extract(c.proof,'$.source_signed_vtxo')=json_extract(s.payload,'$.signed_vtxo')
AND json_extract(c.proof,'$.expiry_height')=json_extract(s.payload,'$.expiry')
WHERE s.kind='coins'
AND json_extract(s.payload,'$.policy_type')='pubkey'
AND json_extract(s.payload,'$.spend_state')='unclaimed'
AND json_extract(s.payload,'$.expiry') < :tip
AND coalesce(c.classification,'unknown') <> 'round_padding';
```

The joined classification is written only by the pinned native decoder.
`simulator.entitlements.unclaimed_expired_report(store, tip)` also checks the
serialized-byte digest, decoded identity, expiry and server-key binding.
Never filter on an unsigned server `padding` flag or on 330 sats alone.

The fixed marker is the public-key policy with key
`02dfa52f6690299d2d6a08323083e290597b56fee125063e5f4e2957731639c42c`,
a 330-sat amount, the unlock hash `deadbeef` repeated eight times and no arkoor
transition. Its source is pinned to SDK commit
`d47c6a4d115b30bf56219d69251fa9238d13f32d`. These leaves have no participant
entitlement. A server state remains an observation; independently resolve the
signed owner and settlement arbitration for every remaining customer candidate.
See [padding attribution](tree-padding.md) for separate counts and capital limits.

Inspect an actor returning after payout:

```sh
jq -s 'sort_by(.utc) | .[] | select(.actor=="actor-09")' \
  exports/actor-09/timeline.jsonl
jq '.payouts[] | {txid,state,recipient_net_sat,raw_chain_reverified}' \
  exports/actor-09-audit.json
```

Create the audit JSON with `integration/verify-export-bundle.py`. An online
actor is not proof that recovery occurred; require its separate signed intent,
confirmed broadcast, and recovered-capital entry.

Find a settlement row whose destination is absent from the payout transaction:

```sql
SELECT s.id,json_extract(s.payload,'$.txid') AS txid,
       json_extract(s.payload,'$.spk') AS destination
FROM server_item s JOIN chain_payout t
ON t.txid=json_extract(s.payload,'$.txid')
WHERE s.kind='settlements' AND NOT EXISTS (
  SELECT 1 FROM json_each(t.payload,'$.outputs') o
  WHERE json_extract(o.value,'$.script')=json_extract(s.payload,'$.spk')
);
```

The grouped checker also rejects extra unknown output scripts and excessive
fees. Inspect `raw-rpc/` and the raw-chain audit result when distinguishing a
server claim from the actual transaction.

Count dry-wallet decisions by actor:

```sql
SELECT json_extract(j.value,'$.actor') AS actor,count(*)
FROM trace t,json_each(t.payload,'$.actors') j
WHERE t.kind='scheduler.tick'
AND json_extract(j.value,'$.rule_id')='dry_wallet'
GROUP BY actor;
```

For historical financial events, use the same query against `event`, with
`kind='scheduler_tick'`. Compare wallet balance, pending invoices, fee
reservations and the recorded rule inputs before attributing sparse traffic to
funding. Submitted sends and unknown outcomes do not prove delivery.

Compare a rounds-wallet debit with the actual raw transaction and every parent
input value before treating it as a mining fee. A debit may fund new backing or
move into unconfirmed change. Padding attribution is a subset of existing
backing; missing spend or return-script evidence remains unknown. It cannot be
added to the operator asset total or a recycling receipt.

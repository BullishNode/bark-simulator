# Analysis cookbook

Use a public export for repeatable analysis. Its timeline includes actor-linked
trace and accounting records; its README describes evidence limits. SQLite
queries below run against `state.sqlite` or a selected trace partition.

Find expired spendable outputs that the server still considers unclaimed:

```sql
SELECT id,json_extract(payload,'$.amount_sat') AS amount_sat,
       json_extract(payload,'$.expiry') AS expiry
FROM server_item WHERE kind='coins'
AND json_extract(payload,'$.spend_state')='spendable'
AND json_extract(payload,'$.expiry') < :tip;
```

A server state is an observation. Resolve the signed owner and settlement
arbitration before interpreting a row as someone else's entitlement. Check the
actual inventory schema when comparing expiry heights.

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

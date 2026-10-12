# Evidence records

The financial journal is `state.sqlite`. Public diagnostics live in daily
`trace-YYYY-MM-DD.sqlite` partitions. Each file has an independent hash chain.
Archived trace partitions remain under `trace-archive/`; retention moves files
without deleting evidence. A source chain tip or bundle manifest needs an
independently trusted reference to authenticate its origin.

| Record | Contents |
| --- | --- |
| `event` | Funding, actions, accounting, settlements, and verdict decisions |
| `trace: driver.call` | Frozen public request, response, context, and timing |
| `trace: driver.stdout`, `driver.stderr` | Exact checked public output bytes; oversized or private output becomes a marker |
| `trace: driver.event` | Current operation evidence, including fresh coin evidence and explicit capture gaps |
| `trace: scheduler.tick` | Per-actor eligibility decisions and reservations |
| `trace: observer.sample.raw` | Remote snapshots, complete public Lightning responses, Core tips, mempool and output queries |
| `trace: chain.rpc`, `chain.derived` | Method, parameters, exact public response bytes, normalized values, and consumer |
| `trace: inventory.page` | Captured server inventory response and pagination cursor |
| `trace: target.log` | Public daemon logs obtained through the bounded target bridge |
| `trace: test.run` | Checked fixture daemon logs; the fixture manifest also hashes original local copies |
| `coin_observation`, `movement_evidence` | Independently verified ownership observations and wallet movements |
| `checked_settlement` | Attributed payout entries whose grouped amounts passed the checker |

Count records in each file:

```sh
sqlite3 runs/epoch/state.sqlite 'SELECT kind,count(*) FROM event GROUP BY kind;'
sqlite3 runs/epoch/trace-2026-01-01.sqlite 'SELECT kind,count(*) FROM trace GROUP BY kind;'
```

Trace `raw` is a byte stream; normalized JSON preserves Bitcoin decimals as
exact strings. Secret fields, private keys, seed patterns, credentials and
mnemonic word sequences are checked before storage. Redaction removes the raw
bytes and records a marker. Process capture never reads or stores stdin.
Recovery seed input is excluded.

An actor timeline joins actions, coin observations, movements, checked payouts,
and trace records. For an interactive SQL session, call
`install_actor_timeline(connection, current_partition)` from
`simulator.export_bundle`; the temporary `actor_timeline` view then includes
that trace partition. Bundle timelines also merge archived partitions.

```sql
SELECT actor,utc,kind,ref FROM actor_timeline
WHERE actor='actor-09' ORDER BY utc,ref;
SELECT o.observed_at,o.state,o.action_id,c.id,c.amount_sat,k.actor
FROM coin_observation o JOIN owned_coin c ON c.id=o.coin_id
JOIN owner_key k ON k.pubkey=c.pubkey
WHERE c.id='TXID:0' ORDER BY o.observed_at;
```

See [the analysis cookbook](cookbook.md) and [export and audit](observability.md).

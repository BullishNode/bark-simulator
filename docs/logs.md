# Public daemon and service logs

Log capture reads declared captaind/watchmand containers and simulator services.
It creates no customer actions, funding, payment verdicts or traffic credit.
Enable sources explicitly:

```toml
[logs]
target = true
local_sources = ["simulator"]
rows_per_page = 64
maximum_bytes = 131072
# since_us = 1760000000000000
```

The restricted inventory bridge carries target requests. Its deployed contract
returns a bounded window and tail:

```json
{"kind":"logs","service":"captaind","seconds":300,"tail":1000,"max_bytes":131072}
```

`watchmand` is also supported. Target capture uses a 1,000-line tail and the
configured source byte limit, between 4,096 and 262,144 bytes. The caller allows
45 seconds for the bridge's bounded child request and cleanup. Ordinary polls
request at least 300 seconds; after a pause the requested window extends with
an overlap, up to the producer's 86,400-second bound. A byte, tail, time or
retention bound can omit earlier logs. Every reply keeps `complete=false`.

Each reply is retained as `target.log.window` with the exact public request,
returned metadata, caller timestamps, trace reference and gaps. Every returned
line occurrence also appears as `target.log`, including repeated identical
lines within and between windows. Lines are named `returned_line`: the bridge
may already have redacted and reserialized JSON, so they are not original
Docker bytes. The local capture sequence and line index identify observations;
they are not daemon event IDs. Line hashes support comparisons across overlaps
without deleting occurrences or claiming once-only event delivery.

The producer supplies no container incarnation or resumable cursor. The report
retains this identity gap, unknown tail coverage, historical opening gaps,
disjoint windows, truncation, timeouts and clock regressions. Empty tails prove
no complete absence of events. A later successful read preserves earlier gaps.
An older or unavailable bridge remains an explicit collection gap. Merely
copying the bridge source into this repository does not install a live producer.

Local service capture uses fixed journal unit aliases, native `--after-cursor`,
bounded forward `--lines=+N`, JSON output and no follow. It needs journal read
permission. Native cursor pages retain source replacement, missing retained
cursor and ordering gaps; window tails never manufacture those cursors.
`rows_per_page` controls these local pages, which are limited to 256 rows.

Public text and nested JSON pass privacy checks before storage or hashing.
Secret-bearing lines become markers retaining their capture location and byte
count, without private text or its digest. Diagnostic records live in separate
daily trace partitions. Exports retain these global diagnostics and gaps beside
the selected financial evidence. Logs provide context; signatures, independently
verified chain data and payout adjudication remain separate evidence gates.

The same forced read-only bridge supplies `rounds_descriptor`. Enable
`bridge = true` under `[operator]` alongside immutable local `descriptors`.
The consumer retains the returned public declaration in the trace and verifies
its target identity, descriptor and range against those local declarations.
It never rewrites or extends a declaration automatically. Independent Core
derivation, a confirmed rounds-wallet anchor and the actual payout change
script are still required for operator-change qualification. A bridge gap
preserves prior evidence and leaves new change outputs unqualified.

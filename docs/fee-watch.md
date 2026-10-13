# Fee observations on signet

`simulator.fee_watch.collect(store, chain, tick_id)` samples the independently
pinned signet Core estimator once per simulator tick. It reads raw payout and
watchman claim candidates in a bounded rotating batch. The default reference is
six blocks in economical mode. This is an explicit observer reference; it does
not establish the server's live configuration or change its fee policy.

For each transaction, the observer decodes its wire bytes, derives weight and
virtual size, resolves exact parent outputs and subtracts outputs from inputs.
A log's quoted fee rate or a wallet debit cannot establish the mining fee.
The comparison describes a transaction's rate against the **current** Core
estimate, even if the transaction was constructed earlier. A missing estimate,
an unstable tip or incomplete transaction evidence produces a named gap.
No fallback, zero rate, fee ceiling or policy violation is invented.

The immutable transaction facts are indexed once by transaction ID. Repeated
observations update confirmation evidence and comparison references, without
adding costs to the operator ledger. Recipient and operator fee shares require
a unique existing `confirmed_payout_amounts_checked` event, an amounts-checked
settlement and confirmation. Their sum must match the exact mining fee. The
watch does not alter reserves, payouts, actions or balances.

The watch consumes already captured `target.log.window` records, checking their
trace hashes. Every returned line occurrence, including repetitions across
windows, remains recorded. Anonymous expiry summaries expose aggregate counters;
they cannot identify an individual payout or a unique daemon tick. Identical
summary payloads can be compared as payloads, but neither timestamps nor local
capture sequences become daemon tick IDs. Local settlement-verifier reasons
remain separate from the server's waiting reason.

Individual server waiting reasons and uninterrupted waiting ages remain unknown
until the producer supplies stable candidate/group identities, unique ticks,
authoritative decisions and explicit retained-interval coverage. Bounded tails,
unbound warnings, missing history and redacted lines preserve their gaps. No
complete scenario qualification follows from these observations.

`report(store)` returns the latest simulator-tick reference, raw transaction
facts, aggregate log diagnostics and pending verification rows. `csv_values`
uses only the selected snapshot's `snapshot:<id>` sample; it never backfills an
older row with the latest estimate. CSV comparison counts describe the bounded
transaction batch rather than all payouts or sweeps.

An audit needs the exact tick reference, raw transaction and parents, estimator
request and response, independent chain boundaries, settlement allocation event
and returned log-window references with their gaps. The hash-chained trace keeps
these records when enabled. An actor-only export must also retain the relevant
unassigned estimate and log-window records before claiming to reconstruct a fee
comparison. Missing trace capture is an explicit raw-replay gap.

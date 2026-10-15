This producer admits only the initial once-only funding transaction for the
declared closed cohort. It does not qualify subsequent Boards, wallet sync,
Arkoors, rounds, unilateral exits, Lightning or claims. The existing financial
preflight enforces `operation_scope: ["funding"]`; the existing dispatcher and
once-only funding adapter retain all authority to act.

Call, while paused and after all three original native bootstrap creations have
independent zero-asset proofs:

```python
result = await collect_initial_funding_sources(
    store, config, chain, bank_rpc,
    runtime_source_sequence=loaded_runtime_event_sequence,
    current_startup_path=actual_current_startup_receipt_path,
    boundary_id=declared_boundary_id,
)
declare_boundary(store, result['boundary_declaration'], chain)
declare_envelope(store, prospective_limits, config,
                 result['inventory_sequences'], chain)
readiness = record_initial_funding_readiness(
    store, config, chain, result['source_sequence'])
```

The bank is the actual named Core wallet in `bank_rpc`. Its complete public
source is read before and after independent observations, and the two native
views must agree. Every coin must be confirmed, safe and controlled; all locks,
pending transactions and immature balances must be absent. The exact opening
balance is 665,454 sat, included in the opening treasury. It is not new income
or an injection into the epoch.

The other five wallets are the separate owning rounds/watchman inventories from
the exact startup source and the original Engine responses for actors 01, 02 and
04. Their graphs must be empty and complete, with no input reservations or
missing parents. The original private cohort root must still contain exactly
the three customer directories and the existing supervisor lock. All owning
public descriptors are independently canonicalized and derived. The actual
owning frontier plus 20 is used, bounded below index 2,000 and 2,000 aggregate
derived scripts. No health RPC is called to reveal a new operator address.

Core scans every supplied owning descriptor prefix at one unchanged synchronized
tip. At most 12 descriptors are sent per scan, a running scan defers without
abort, each scan is at most 120 seconds, and qualification is bounded to 180
seconds. Exact public scan replies and the actual fee estimate are retained.
The complete scanned coin set must equal the exact named bank's native
coins; every other member must have no confirmed assets. Every transaction in a
current mempool is checked for owned output scripts, within the explicitly
authorized 2,500 transaction / 50,000 output / 8 MiB bounds. No prefix is
accepted. At most eight observation passes establish that every currently
present transaction was checked; unrelated removals are safe, and every new
arrival is checked. Nonconvergence defers. Public output-script projections and
the final current transaction-ID set are retained without witnesses.

The fixed forced bridge supplies a new complete `closed_frontier` snapshot.
Exactly the three original native customer signed public bindings must appear
in both record projections. All other 17 projections must be empty, including
all historical VTXOs, retained direct journal generations, nursery, pool, rounds
and Lightning records. The original response is retained even on refusal.

The resulting source event, `finite_initial_funding_sources_verified`, contains
six exact member/inventory references and a complete five-row recipient plan:

* `rounds`: 100,000 sat to the actual already-revealed owning frontier.
* `watchman`: 75,000 sat to its actual already-revealed owning frontier.
* `actor-01`, `actor-02`, `actor-04`: 50,000 sat each to their original funding
  addresses, independently matched to their native descriptors.

Each row includes role, member ID, address, script, amount, descriptor index and
child index. `funding_plan_sha256` hashes the complete canonical row array. The
once-only adapter binds this source, its freshest `bank_source_sequence`, and the
ordinary financial preflight. Neither the producer nor a balance label grants
broadcast permission.

The exact envelope reserves 60,000 sat ordinary and 15,000 sat urgent, against the
entire 665,454 sat exposure. Ordinary worst cases are funding 10,000 + three Board
miner fees 12,000 + three normal-expiry carrier fees 30,000 = 52,000 sat. Normal
expiry fees are ordinary. Urgent claim/progression capacity remains separate and
its unsupported paths stay null/refused. After holding the 325,000 sat internal
principal and maximum 10,000 sat funding fee, 330,454 sat remains to back the
75,000 sat fee budgets. The actual Core six-block estimate must be available and
at most 20 sat/vB; no estimate or monetary completeness is invented.

Any existing funding intent, paid history, extra wallet, nonempty monetary
frontier, changed bank/native source, active scan, source bound overrun, missing
fact or changed tip defers. Once the first funding intent exists this initial
producer refuses to issue another positive proof. Subsequent state needs its
own narrow, actual source qualification. Source-only tests carry no Core,
native-wallet, payment or production credit.

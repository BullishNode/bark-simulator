`create` and `snapshot` responses include `data.onchain_inventory`. The collector
borrows the loaded BDK wallet immutably under the existing onchain read lock. It
does not sync, reveal an address, sign, commit, or export a signing keymap. The
existing `create` operation still reveals its original funding address before
collection; that operation is otherwise unchanged.

The version 1 object contains:

- `schema_version: 1`, `read_only: true`, `network`, `tip_height`, `tip_hash`.
- `descriptors`: public BDK descriptors, each with `keychain`, `descriptor` and
  nullable `last_revealed_index`. Descriptors are present before funding.
- `utxos`: all currently canonical unspent wallet outputs with `outpoint`,
  `value_sat`, `script_pubkey`, `keychain`, `derivation_index`, nullable
  `confirmed_height_upper_bound`, `confirmations`, `coinbase` and `mature`.
- `pending_transactions`: every relevant canonical unconfirmed transaction,
  including outgoing transactions without change.
- `pending_parents`: available immediate parent transaction bodies, deduplicated
  by txid. Each transaction row contains `txid`, hex `transaction_body`, original
  `signed_weight_wu`, and `encoding: "bitcoin-stripped-body-v1"`. Witnesses are
  stripped without changing txid. A nonempty scriptSig in a pending transaction
  refuses the response; an unsafe or missing parent is an explicit gap.
- `unavailable_parent_txids`: sorted missing/unsafe immediate parents.
- `complete`: true only when the bounded currently loaded canonical graph has no
  such parent gaps. Aggregate descriptor/output/transaction/parent rows are
  limited to 2,000 and the serialized object to 2 MiB; overruns refuse the whole
  response. Arrays have stable ordering.

`scope`, `reservation_scope` and `confirmed_fee_eligibility` explicitly limit
this source. `complete` does not establish independent chain freshness, full
confirmed-tip assets, persisted action reservations, usable funds, or financial
readiness. Canonical UTXOs can omit confirmed inputs spent by pending
transactions; the independent collector must account for those parents and
pending projections without counting backing twice. The independent collector
must verify descriptor scripts, actual confirmed coins, tip agreement, native
action/obligation coverage and fee settings before any readiness admission.

Focused tests use synthetic BDK graphs and exercise public membership before
funding, no collector mutation/address reveal/private descriptor export,
aggregate bounds, witness stripping/txid preservation, explicit missing parents,
and outgoing pending transactions without change. They earn no live source or
payment qualification.

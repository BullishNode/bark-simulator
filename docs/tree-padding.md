# Round padding

The server adds dust leaves when a round has fewer than two real outputs. The
leaves use a fixed unspendable public key and a hash without a known preimage.
They have no participant or mailbox entitlement. Their value comes from the
operator's round funding and is already part of the tree backing.

The public decoder is pinned to SDK commit
`8f2286ee7e1631b0ceccd1631ec3b728a1bb0a52`. It strictly decodes a full VTXO,
rejects trailing bytes and the wrong server key, and identifies padding only
when all of these match:

- Public-key policy and key `02dfa52f6690299d2d6a08323083e290597b56fee125063e5f4e2957731639c42c`.
- Unlock hash `deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef`.
- Amount 330 sats, with no arkoor transition.

The constants come from `server/src/round/mod.rs`; the dust amount is
`bitcoin-ext`'s `P2WSH_DUST`, 110 virtual bytes times three sats. They are protocol
pins, not configurable spending policy.

The simulator keeps decoded classification separately from raw `server_item`
and its versions. Classification is bound to the serialized-byte hash, exact
coin ID, expiry, server key and native executable hash. Changing the serialized
coin invalidates its classification. Missing or malformed evidence remains in
the customer candidate set with unknown ownership.

`tree_padding_unclaimed` counts positively decoded unclaimed leaves;
`tree_padding_expired_unclaimed` is the expired subset.
`tree_padding_server_spent` counts the server's spent observations.
`tree_padding_swept` requires an independently confirmed, exact raw spend of
the checked backing into already declared operator scripts. A server spent
flag or null `gettxout` result alone cannot prove a sweep.

`tree_padding_locked_sat` attributes 330 sats per leaf only when the native
server-policy verifier matches the exact raw anchor and its unsigned committed
structure and independent Core
positively reports its matching backing UTXO at the current observed height.
Padding has no unlock preimage, so its proof explicitly keeps
`chain_contract_verified` and `signed_path_valid` false and sets only
`padding_backing_structure_verified`. It never becomes a signed client coin.
Each backing is counted once, and its padding subset cannot exceed its amount.
The UTXO observation must be at most 90 seconds old. An incomplete decode,
unknown backing, missing operator return ownership or missing current UTXO
leaves the total unknown. Known positive subsets remain available separately.

Padding attribution is a subset of existing backing. It is never added to the
asset identity, customer liabilities, recovery receipts, traffic or recycling
credit. Confirming a sweep shows the backing was spent, not that exactly 330
sats per leaf returned after mining fees. Paginated inventory remains partial
and cannot establish a complete operator capital requirement.

The bounded decoder and backing collectors are read-only. Configure and pin
the `server-policy-proof` executable before enabling them. Operator descriptors
must come from their owner; an undeclared return script is an evidence gap.
Historical CSV attribution is saved at the snapshot time and is never filled
using later observations.

Native tests replay a public serialized padding example and reject altered key,
hash and amount markers, plus trailing bytes. Python checks cover missing
decoding, raw-inventory preservation, current backing, unknown spends, confirmed
raw sweeps and historical attribution. An isolated round-and-expiry-sweep
fixture remains a separate qualification gate.

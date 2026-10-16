# Independent ordinary funding ownership

This contribution is source only. It does not enable funding imports, declare
financial budgets, alter an immutable treasury boundary, publish transactions or
qualify a normal campaign. The installed collector continues to call the native
money verifier with `funding_intents=()` and holds existing funding flows without
an actual ownership rejoin. Unsupported historical schemas also hold.

`simulator.normal_funding_ownership.verify_funding_ownership(store, chain, *,
qualification_sequence, boundary, packages, height, tip_hash)` returns records
compatible with `normal_money_join.journal_money_sources`. It performs no Store
writes. The caller must run the verifier against the actual retained originals
and the independently authenticated scoped `ChainReader`; a returned label,
amount, source name, payer flag or declaration alone is insufficient.

`packages` maps every admitted declaration SHA256 to its original
`declaration_bytes`, original `manifest_bytes` and exact manifest-named `files`.
The bank package is the existing bounded member-source format. All files, roles,
RPC request/response IDs, literal arguments, result aggregates, source program,
stable historical Core point and current active ancestry are checked. Decimal
Core fields retain exact decimal values. Public bank descriptors must match the
literal native list and immutable boundary. Each funding output is independently
derived by Core, matched to the original native bank address/path and exact raw
confirmed transaction. Observed confirmation/ownership booleans and foreign
batch-fee annotations never replace these checks or create a local miner cost.

The source qualification is an append-only
`normal_funding_ownership_sources_qualified` event with these fields:

- `financial_pins` and `boundary_sha256`: the exact current financial pins and
  canonical immutable boundary hash.
- `module_sha256`, `bank_ownership_sha256`: the actual verifier and shared bank
  descriptor-helper module hashes.
- `bank_member_id`: an existing `funding_bank` wallet member, independently
  verified by its original `treasury_member_verified` event and descriptors.
- `bank_source_program_sha256`: the actual admitted member-capture program.
- `declarations`: an exhaustive list of `{declaration_sha256, kind,
  bank_manifest_sha256}` entries. A prospective bank transfer additionally has
  `source_sequence`, `prepared_sequence`, `broadcast_sequence`.

For an initial external receipt, supply the actual immutable
`track-a-supplemental-funding-declaration-v1` bytes, authenticated original bank
capture and original native member proof. The declaration supplies authorized
external-capital classification; independent descriptor/raw-chain joins prove
receipt ownership. This module does not authenticate an unknown donor identity
or treat a foreign batch fee as an expense of this treasury. Original legacy
funding must have its own supported ownership join before any existing flow can
be accepted. An absent funding source cannot be replaced with zero.

Prospective `track-a-bank-transfer-intent-v1` declares exact `source_member`,
`txid`, `signed_raw_sha256`, ordered `input_outpoints`, every output and
`maximum_miner_fee_sat`, with `classification=INTERNAL_TRANSFER` and
`recycled_principal_sat=0`. Each output has `vout`, `amount_sat`, `script`,
`destination_member`, `descriptor_index`, `child_index` and `kind`. Bank-owned
outputs must be `change`; other declared ordinary wallets must be `transfer`.
Every output is accounted once; foreign, omitted or misclassified destinations
hold. Miner fee is recomputed from actual parent bytes and all actual outputs.
Only that full fee creates a miner expense. Internal principal creates neither
income nor expense. Signed-body mismatch, duplicate inputs, reserved/unsafe or
immature original inputs, later or unrelated source frames, excess fee and
unconfirmed/reorged carriers all hold.

Before publishing a prospective transfer, retain these actual journal facts:

1. `normal_bank_source_captured` binds the original bank manifest/program,
   bank member, pins, boundary SHA, actual height/tip and completed time.
2. `normal_bank_transfer_prepared` binds that source sequence, original
   declaration SHA, signed body SHA, txid, bank member, pins, boundary SHA and
   exact maximum miner fee.
3. `normal_bank_transfer_broadcast_intent` binds the prepared sequence, txid
   and financial pins.

The native inventory must be from before preparation/publication and from an
active block strictly before the carrier's confirmation block. The prepared
source and broadcast intent must remain within their original 90-second bounds.
These events record original evidence; this verifier cannot create them after
the fact, grant spend authority or reinterpret unsupported legacy records.

The result separates positive `cost_records`, `flow_records`, confirmed
`zero_fee_carriers` and reused IDs. It retains `verified_flow_records` for an
actual historical rejoin and source qualification/hash evidence. Reuse preserves
original payloads and old pins; conflicting amounts, payer, destination or
physical identities hold. Zero fee never creates a positive expense. Funding
records may be journaled through the existing append-only source-cost join;
`verified_money` must then rerun the ownership verifier with exactly the current
boundary, source height/tip, original packages and qualification sequence. A
caller-supplied checked-flow map cannot satisfy this contract.

The current pending-Board domain is explicitly unsupported. Native retained
pending bodies may be unsigned and remain after successful registration; they
must be resolved through an actual unsigned-body/registered-signed-path,
original-intent and current backing/descendant or paid-settlement join. They
cannot be omitted, compared for signed byte equality or treated as already paid.

The complete A source observation shares one measured 90-second deadline from
its original observation start. Remaining time limits reader subprocesses,
proof subprocesses and each independent Core request; final readiness admission
and transaction commit check it again. Retained partial source evidence and
known liabilities survive refusal. This does not convert synchronous work that
returns after its deadline into readiness. Reader cleanup always kills its own
session even if the leader has exited and a child retains a pipe. Private files
are read through capped, stable regular-file descriptors.

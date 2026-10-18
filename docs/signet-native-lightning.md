# Native Lightning receive and rightful fallback

This is a separate public-Signet operation, prepared after the stock Noah
callback was rejected for its missing LNURL metadata hash. It does not pay or
reuse that rejected invoice, change Noah, relax the LNURL verifier, or earn
Noah/LNURL compatibility credit. Its purpose is to follow **actual swap-created
coins** through signed recipient ownership, fallback and seed-only recovery.

The controller is `python3 -m simulator.signet_lightning`. The new Python fault
tests exercise supervision and protocol contracts with stubs. They do not prove
an actual Lightning receive. Source milestone `45b5aaa` preceded actual admission;
the later zero-funded execution is recorded below. Funding, invoice, payment and
the financial result require their own exact receipts.

## Fixed first operation

| Parameter | Declared value |
|---|---|
| Chain | Default public Signet; actual genesis, challenge and synced tip checked |
| Server / pool lifetime | 32 / 32 blocks |
| Exit delta / pool pre-expiry | 12 / 12 blocks |
| HTLC expiry delta | 6 blocks |
| SDK exit margin / claim delta | Unchanged 12 / 18 blocks |
| Invoice | One native BOLT11 invoice, 5,000 sat, directly for the absent recipient's cached Ark address |
| Receive fee | 100 sat + 2,000 ppm: 110 sat on 5,000 sat |
| Expected signed customer proceeds | 4,890 sat, verified from actual signed outputs |
| Fallback fee | 1,000 sat per actual payout output; nominal one-output payout 3,890 sat |
| Payer routing fee ceiling | 1,000 msat proposed; immutable in the operation spec |
| Proposed treasury allocation | At most 300,000 sat: 200,000 rounds liquidity and five distinct 20,000-sat confirmed watchman fee outputs |

The coordinator supplied native regression `ffa4d760` for the short receive
profile. That is controlled native evidence, not public-Signet execution.
The funded phase must record its actual paired ELF/source/configuration pins;
the old 7055 provider is not silently inherited as a compatible receive build.

The pool's actual issuance height and signed tree expiry **E**, and every real
grant's HTLC deadline **D**, are recorded separately. The accepted admission
policy permits D > E. Fully settled registered Pubkey proceeds can fall back at
E; unresolved conditional obligations remain a separate case. No multi-day
expiry claim is inferred from the old invoice-only 4,320-block profile.

## Admission and staging

The coordinator owns a separate same-VM financial profile with its own DB,
data/configuration, ports and captaind/watchmand/provider units. Long ordinary,
short S03 repair, Core, existing CLN peers and the rejected Noah operation keep
their pins. Before payment, admission must establish:

1. Qualified current backend **and client** ELFs; pure public ArkInfo's actual
   server identity and 32/12 profile; exact cap/watch configuration hashes.
2. Actual rounds liquidity, an eligible genuinely issued pool coin and confirmed
   usable watchman inputs. A wallet's nominal total is insufficient. Budget and
   real issuance/funding fees belong in the operator cost ledger.
3. Native provider and recipient registrations against that exact identity.
   Retain the recipient's authenticated public fallback record, Ark address,
   original pre-create birthday and protected original phrase. Close its native
   wallet, with no daemon/background process. Do not hand its database to the
   controller or wake it to learn whether a swap succeeded.
4. Both actual CLN peers synchronized, the existing private channel NORMAL,
   current payer spendable/receiver receivable liquidity sufficient for 5,000
   sat, exact payer/payee identities and pinned CLN ELF.

Create a private operation directory/config/spec, using the existing Campaign
configuration and paired-runtime-pin schemas. `spec` has exactly these fields:

```
profile, amount_sat, max_payment_fee_msat, provider_url, provider_token_file,
cln_binary, cln_binary_sha256, cln_directory, payer_pubkey, invoice_payee,
recipient_address, recipient_registration_sha256, birthday_height,
recovery_destination, admission, admission_sha256, database
```

`profile` is the literal `PROFILE` mapping in the module. Registration SHA256
is over its canonical JSON. `admission` is a retained coordinator receipt with
at least actual `network: "signet"` and `server_pubkey`, plus the independent
runtime/funding evidence above. Paths and credential files stay private; they
are not GitHub artifacts. Both token and original-phrase files must be regular,
owner-only files. The source is copied into protected recovery storage, with
only the absent actor fence created. No create/snapshot ACK is manufactured.

```
python3 -m simulator.signet_lightning --state "$STATE" --config "$CFG" stage \
  --spec "$SPEC" --runtime-pins "$PINS" --registration "$RECORD" \
  --source "$ORIGINAL_PHRASE_FILE"
```

Staging verifies actual 32/12/6/pool/fee configuration and exact runtime hashes.
It does not replace the coordinator's genuine operational admission or send
funds. The original birthday remains unchanged through recovery.

## One invoice, one payment

Only after the coordinator admits invoice/payment execution:

```
python3 -m simulator.signet_lightning --state "$STATE" --config "$CFG" invoice
python3 -m simulator.signet_lightning --state "$STATE" --config "$CFG" pay
```

The first command POSTs the existing authenticated
`/api/v1/lightning/receives/invoice/for-address`. The second dispatches external
CLN's existing `xpay` with an explicit maximum fee and 30-second retry budget.
Both commit a durable action before the effect and retain original raw replies
privately. An uncertain or invalid post-effect response becomes UNKNOWN/HOLD,
not a second invoice/payment. A lost response is reconciled from the original
payment hash using payer listpays/listsendpays and the provider's existing state;
this controller never retries an uncertain action automatically.

CLN 26.06.6 actually exposes `decode`, not `decodepay`. The controller requires
`type: "bolt11 invoice"`, `valid: true`, Signet currency `tbs`, exact 5,000,000
msat, the actual internal CLN payee, payment hash and enough remaining expiry.
All machine calls disable progress notifications with
`--notifications=none --json`; a prior infrastructure payment exposed that
notifications can precede otherwise valid JSON. A returned payment preimage
is checked privately against the original hash. It is never a public field.
These are BOLT11 checks, distinct from the unchanged stricter LNURL verifier.

## Observe grants and recipient ownership without waking the recipient

```
python3 -m simulator.signet_lightning --state "$STATE" --config "$CFG" observe
```

This reads the provider's existing receive status and `/api/v1/wallet/movements`.
The final receive view clears grant IDs, but durable Lightning movement metadata
retains them by exact payment hash. That metadata also contains a preimage:
only the exact hash and public IDs are projected. Raw history remains private.

Each grant is fetched from public `bark_server.ArkService/GetVtxo`, then decoded
and signature-verified with the exact native CLI and independently obtained raw
Core funding transaction. These pure `dev vtxo` commands do not open any wallet.
The signed public ID and actual anchor/expiry are retained. The VtxoInfo API
does not expose HTLC deadline. For that administrative observation only, the
controller executes an explicit READ ONLY projection:

```
SELECT v.vtxo_id, h.payment_hash, h.direction, h.htlc_expiry
FROM htlc_vtxo h JOIN vtxo v ON v.id = h.id
WHERE v.vtxo_id IN (<validated exact public grant IDs>);
```

The actual implementation returns only those four named fields as JSON, checks
the original payment hash and `outgoing` receive direction, and records schema
`server/src/database/migrations/V63__htlc_vtxo.sql` and paired server source.
This query cannot establish ownership/payment by itself. No preimage query,
table mutation, payout decision injection or server-derived readiness flag is
used.

The provider's existing `Got arkoors from lightning: <IDs>` info log occurs
after real signed claim registration and validation. Preserve its exact source
and public IDs privately, then:

```
python3 -m simulator.signet_lightning --state "$STATE" --config "$CFG" \
  freeze-claim <actual signed recipient claim ID> [<further actual IDs>]
```

Every final public body must pass native signature verification **with the
original cached recipient Ark address**; the native path must contain an actual
observed grant. Its Pubkey policy, server, exact total 4,890 sat and actual tree
expiry are checked. The frozen cohort records public signed-body evidence, not
a fabricated recipient-wallet snapshot. Signed registration and mailbox
delivery remain distinct boundaries. Provider possession of bytes does not
make it the fallback owner.

The initial operation uses a bounded explicit signed-ID handoff. If provider
logging does not expose those IDs, report that collection gap and use an actual
retained signed delivery checkpoint; do not open the recipient or invent IDs.

## Actual expiry, independent payout and seed-only recovery

```
python3 -m simulator.signet_lightning --state "$STATE" --config "$CFG" recover
```

The existing public-Core block scanner independently discovers exact registered
payout outputs from signed coin paths. The existing check requires a canonical
version-3 zero-fee parent, exact per-output fee/value/script, and actual signed
funding lineage. The existing fee-child scanner independently finds its real
positive-fee version-3 P2A child. Both parent and child require **six actual
confirmations** before any recovery wallet opens.

Recovery creates a distinct empty native DB using only the protected original
phrase and original birthday. It receives no payout outpoint hints or original
wallet DB. A real native UTXO observation must discover every expected payout.
Only then does a single durable onchain-drain intent spend to the declared
owner-controlled address. Canonical Core inclusion must prove the drain spent
the actual fallback output. A spent/decision/RPC acknowledgment never counts as
completed payment. Preserve first-PASS confirmation depth, then observe deeper
confirmation separately. The physical recovery fee is counted once even if
several payout inputs are independently checked.

One confirmed native receive/fallback does not prove failed-send refunds,
pre-registration cancellation, interrupted claim delivery, all 80 risk IDs,
load capacity or production readiness. A separate failed-send case remains
required, using its actual refundable customer claim and no duplicate payment.

## Actual zero-funded admission on 17 October

[The measured admission projection](evidence/native-ln-receive-zero-funded-admission-20261017.json)
records a distinct real 32/12 profile, matched new server/client ELF pins,
authenticated native provider/recipient registrations, zero balances and six
distinct Core-validated operator funding addresses. All three new services had
zero restarts; the original recipient closed and was fenced before any invoice.
Existing campaigns and the rejected Noah operation were unchanged.

Two setup failures remain recorded. The watchman binary has no `check-config`
command; its correct native validation is
`captaind check-config FILE --watchman`, which passed before startup. A read-only
genesis check initially tried parsing raw CLI hash output as JSON; that was
corrected before any operator address read or funding-request creation. Neither
failure dispatched funds, an invoice or a payment.

The zero-funded admission is operational evidence only. It does not establish
an actual swap, signed recipient proceeds, fallback or recovery. The next phase
must verify the coordinator's original funding transaction, two confirmations
for rounds funds, usable confirmed watchman inputs and genuine signed pool
backing before the single invoice/payment sequence.

## Actual funded receive on 17 October

[The immutable receive projection](evidence/public-signet-native-ln-receive-20261017.json)
records exactly one 5,000-sat invoice and one successful external payment at
height 326785, with zero routing fee. Public GetVtxo and the actual native
signature/address verifier prove a 4,890-sat Pubkey coin for the original absent
recipient. Its signed path includes the actual receive grant and the confirmed
pool root. The original recipient wallet remained closed throughout.

The observed grant deadline is **326833**, while its backing tree expires at
**326816**. These are actual separate observations; the configured delta alone
does not establish the grant deadline. After settlement, the registered Pubkey
proceeds are the customer entitlement being followed toward fallback.

Pre-invoice proof found an important collection distinction. The public VTXO
table's ungranted pool copy is still hash locked, and full native verification
correctly rejected it for a missing preimage. That failed proof is retained.
The server's canonical `vtxo_pool` inventory stores the completed signed copy.
An authorized read-only observation of only the two owned inventory bodies,
retained privately, passed native full-signature verification against the
confirmed Core anchor. No standalone preimage query, database write or invented
signature result was used. The later grant and final recipient proofs use
public GetVtxo bodies.

The 300,000-sat operator allocation incurred an actual 894-sat treasury funding
fee and 233-sat initial pool issuance fee. The receive fee was 110 sat. The
prospective one-output fallback is 3,890 sat after its separate 1,000-sat fee;
it has **not yet been paid** in this receipt. A lock-owning observer now follows
actual public Signet heights. Fallback parent and fee child each need six
confirmations before original-seed-only restore and one recovery drain. This
milestone proves the native swap and signed rightful owner; fallback, recovery,
failed-send refunds and Noah/LNURL success remain unproven by this receipt.

## Actual fallback broadcast at expiry

[The later public-Core observation](evidence/native-ln-receive-fallback-broadcast-20261017.json)
records a real 3,890-sat payout to the cached authenticated recipient script at
height 326816. The parent spends the original 20,000-sat pool root, pays 16,110
sat to the operator, and has zero miner fee. Its actual fee child pays 363 sat.
Both were **unconfirmed** in this immutable observation; no recovery wallet had
opened and no completed-payment or scenario PASS is claimed.

The operator output includes 15,110 sat already attributed to the operator and
the new 1,000-sat fallback output fee. It is not all new revenue. The watchman
cash payment of 363 sat is distinct from net subsidy, which is zero under the
existing remainder-based accounting. The new fallback fee less this miner fee
is 637 sat, separate from the earlier 110-sat receive fee and pool issuance cost.

This broadcast occurs at the backing expiry, before the old receive HTLC
deadline of 326833, after genuine settlement into the recipient's Pubkey coin.
The original recipient remains absent. The existing observer still requires
six canonical confirmations on both parent and fee child before the separate
original-seed-only restore and one drain. Noah/LNURL, failed-send recovery and
controlled interrupted-settlement scenarios remain separate.

## Confirmed fallback and seed-only recovery on 18 October

[The additive completed-case proof](evidence/public-signet-native-ln-recovery-20261018.json)
records the complete native receive path. The real 4,890-sat recipient coin
became one 3,890-sat fallback output. Parent and fee child each had six canonical
confirmations before the separate native wallet restored from only the original
seed and original birthday 326782. No original wallet DB or payout outpoint hint
was supplied. One drain spent that exact payout output, delivered 3,780 sat to
the declared owned destination and paid 110 sat miner fee. This miner fee is
separate from the earlier 110-sat receive service fee.

The immutable first PASS at height 326823 had seven parent/child confirmations
and one recovery confirmation. A later independent read-only Core proof at
326842 verifies 26 parent/child confirmations and 20 recovery confirmations.
The [verification script](evidence/verify-native-ln-current-core-20261018.py)
checks actual canonical blocks, registered-script constants, input lineage,
transaction arithmetic, original birthdays and single acknowledged restore/drain
counts without opening native wallets. The original first-PASS depth remains
unchanged. No additional invoice, payment, restore or drain was dispatched.

This is a completed **native BOLT11 receive → absent recipient → fallback →
seed-only recovery** case. Stock Noah/LNURL remains incompatible in its actual
metadata-hash evaluation; interrupted delivery, provider backup/identity faults,
controlled reorgs and the complete money-loss catalogue remain separate oracles.

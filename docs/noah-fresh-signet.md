# Offline LNURL backend observation

This is S09 of the fresh campaign. It does not enable the old Noah campaign or
make its thirteen scenarios, phone enrollment infrastructure or mobile builds
startup prerequisites. No Noah client fork, Expo app, Android or iOS build is
needed to exercise the backend forwarding behavior.

Source inspection, not a running compatibility result:

- Noah `8e68ba5c3f032d9fd55e2f2f1f2af1441395eff0`,
  `server/src/routes/public_api_v0.rs`, `lnurlp_request`: for a registered active
  user with an Ark address, the amount callback first asks the configured
  forwarding provider for an invoice. Only provider failure takes the device
  notification path. An Ark-capable payer can negotiate a direct Ark transfer;
  that bypass is not the Lightning swap behavior S09 intends to test.
- At that same Noah pin, `server/src/barkd_client.rs` posts `address`,
  `amount_sat` and optional plain `description` to
  `api/v1/lightning/receives/invoice/for-address` and checks returned invoice
  network and amount. It communicates over HTTP; this path does not require
  linking the Noah server to the fresh Bark wallet SDK.
- Product `bfbe6b7c3088a09dd4e81c4ac24cdc763a627a8c`,
  `bark-rest/src/api/v1/lightning.rs`, `generate_invoice_for_address`, still
  accepts that request schema. `bark/src/lightning/receive.rs`,
  `bolt11_invoice_for_address`, and `bark/src/actions/lightning/receive.rs`,
  `prepare_lightning_receive_claim`, build the claim directly against the
  recipient address policy. The backend has no key that can spend those claim
  outputs. `claim_lightning_receive_htlcs` registers the signed claim outputs
  with the server before `deliver_lightning_receive` posts them to the recipient
  mailbox. Recipient ownership and mailbox availability are separate boundaries.

There is a concrete compatibility concern before payment: Noah supplies a plain
memo, while LNURL-pay requires the invoice's description hash to commit to the
returned metadata bytes. The existing independent invoice verifier rejects a
plain-memo invoice. An actual callback and invoice must establish whether the
selected backend has this issue. Record the failure; do not relax verification,
pay a different invoice or call a generic CLN payment a successful LNURL case.

## Minimal owned deployment handoff

After ordinary S01/S02, the coordinator supplies an owned compatible Noah
backend HTTP origin, its exact source/binary/configuration pins, and its funded
fresh Bark daemon on the same public Signet server. Authenticate and register a
fresh backend test identity through normal backend APIs, with a pre-registered
recipient Ark address and public payout record. Retain authentication material
privately. Do not edit the product database to manufacture a receive.

The recipient wallet is then stopped and never opened by the campaign observer.
Leave the Noah backend and its forwarding wallet running. Fetch LNURL metadata
and its Lightning callback **without Ark negotiation**, independently verify the
actual invoice, and dispatch the declared Lightning payment once. Preserve an
uncertain original payment hash rather than fetching a replacement invoice.

The trace needs these actual transitions:

1. LNURL metadata and callback bind the declared user and exact amount.
2. The original Lightning payment settles or fails with a canonical outcome.
3. The backend drives the conditional HTLC claim/refund. Capture the actual
   claim destination policy and the server-registered signed output lineage.
4. Recipient-bound signed outputs are delivered to the absent recipient's
   mailbox, or delivery remains parked. An undelivered output does not become
   backend-owned merely because its signed bytes are in the backend checkpoint.
5. If forwarded coins expire, the registered recipient receives their fallback;
   verify it on chain without waking the original wallet.

Three ownership and availability boundaries matter for interrupted results:

| Boundary | What the fallback can establish |
|---|---|
| Before signed claim registration | Conditional HTLC/forwarding operation; payment settlement alone does not establish recipient discharge. Resolve from the actual policy and immutable settlement facts. |
| Recipient claim registered; mailbox not delivered | Outputs are signed to the recipient policy; the provider cannot spend them. Verify those signed bytes and canonical server lineage. Permanent registered-xpub fallback search may identify the recipient despite missing mailbox evidence; this requires an actual native qualification case. Never pay the provider merely because it ran the receive. |
| Recipient mailbox delivery committed | Verify the recipient's actual coin/registration and eventual fallback independently of the backend's success reply. Delivery makes the signed output available; it is not a second ownership transfer. |

Distinguish **recipient offline with backend running** from **backend forwarding
wallet stopped**. They are different conditions. Do not claim wallet delivery
merely because Lightning settled, nor infer coin ownership from the process
holding a parked checkpoint.

Add the native window after signed claim registration and before separate
mailbox delivery. Keep the recipient absent; read the active provider wallet's
existing `lightning_receive_checkpoint`/`lightning_receive_state` SDK view.
`Progress::Delivering(Delivery)` exposes actual signed `Delivery.vtxos` for
policy/key verification without opening the recipient or querying product SQL.
The eventual payout must follow the recipient's authenticated xpub record.
Before claim registration, classify the operation separately as conditional.

On the unchanged long Signet profile a normal LN coin may retain up to 4,320
blocks before expiry. A successful offline receive or native missing-mailbox
test does not prove this entire public expiry occurred. Report prompt monetary
integration, controlled native ownership tests and the separate ordinary short
S02 lifecycle with their actual scopes and heights.

## Actual preparation, not a completed receive

The old deployment is retired. On the fresh owned VM the coordinator prepared
stock backend `8e68ba5c3f032d9fd55e2f2f1f2af1441395eff0` with its own Postgres
and Redis, controlled HTTPS origin `https://noah-fresh-signet.test` and a retained
private CA. This is a locally trusted controlled origin, not public DNS/TLS.
A genuine single-use-k1/Bitcoin-message authentication registered the test
identity. The real backend API attached its recipient Ark address.

Separate native provider and recipient wallets were created on the long 7055
endpoint. Both have authenticated BIP84 fallback records; provider barkd has
real bearer authentication, and the recipient command exited. The private
native-preparation manifest SHA256 is
`ae9da3bb2fd149347736b6c10af2f6b644ac9e6a071f3bb845bd089abf5d56fb`.
Forwarding remained disabled; no invoice, Lightning payment, recipient claim or
mailbox delivery has been qualified by this preparation.

Two actual CLN peers have a confirmed private 200,000-sat channel and a reconciled
100,000-sat balancing payment. Those are CLN infrastructure results, not Bark
or offline-LNURL results. A separate Lightning-enabled product profile on the
same VM awaits the coordinator's checked backend/configuration/pool handoff;
it must not repin either running campaign. At that preparation checkpoint, S09 had **not executed its callback**. The
17 October invoice-only execution below now establishes a concrete compatibility
failure; no financial receive case is complete. The independent verifier's five
unit tests are not live callback proof. This gap does not block ordinary traffic.


## Next execution order: stock Noah and strict invoice compatibility

Use a separate profile on the same owned VM. The coordinator owns its checked
ELF/configuration admission, database, units and actual funding. Suggested unused
loopback ports are public Ark 3565, captaind admin 3566 and watchmand admin 3567;
verify availability before use. Preserve long ordinary and short repair pins.
Use a new server data directory and `fresh_signet_ln` database, with confirmed
rounds liquidity and confirmed usable watchman fee inputs recorded separately.

Reuse internal CLN's mutually authenticated `https://localhost:39736` and its
hold plugin `https://localhost:39738`, each with its own CA/client certificate
and key. Both actual peers must remain synchronized and `CHANNELD_NORMAL` with
sufficient current receivable/spendable liquidity. A live plugin or nominal
channel capacity alone is insufficient. Native receive additionally needs real
upstream pool issuance and a pool VTXO meeting the actual SDK tree headroom.
The accepted decision-boundary design permits an HTLC deadline to outlive its
backing tree: track both heights separately. Settled registered Pubkey proceeds
may fallback at the tree expiry; unresolved liabilities must remain blocked.
Never insert pool coins with SQL or infer eligibility from a lifetime alone.

Create new provider/recipient native wallets only after that public identity is
admitted, and retain their authenticated records and original birthdays. The
old zero-funded 7055-long wallets stay preserved: changing their endpoint does
not change their authenticated server identity. Stock Noah's configuration at
`8e68ba5` requires **`http://noah-barkd-signet.internal:3000`** on Signet; it
rejects arbitrary ports. The coordinator must explicitly hand over that existing
provider listener to the new provider wallet and update the recipient through
Noah's normal login/register API. Preserve its controlled HTTPS origin/private
CA and do not bypass TLS. No mobile application is involved.

The first callback needs the new provider/server identity and working hold-node
connection, but **does not need confirmed wallet funding or issued pool coins**.
`start_lightning_receive` only creates/stores a hold invoice; the SDK stores
`AwaitingPayment`. Pool acquisition and ownership proof belong to the later
claim. Capture this first useful compatibility result while funding confirms;
actual payment remains gated on confirmed usable funds and eligible pool supply.

The first test does not pay an invoice:

1. GET `https://noah-fresh-signet.test/.well-known/lnurlp/offline-recipient`
   with no Ark negotiation. Retain the exact response and exact UTF-8 bytes of
   its `metadata` string; do not reserialize that string before hashing.
2. Journal one callback request at `amount=5000000` msat, after verifying that
   this amount is within the actual metadata bounds. Do not replace an invoice
   after a lost callback response; reconcile the retained operation first.
3. Independently decode the actual returned invoice with the existing checked
   verifier. Require Signet, exactly 5,000 sat, a valid invoice signature,
   unexpired payment terms and a **description hash equal to SHA256(metadata)**.
   Save the invoice/payment hash and verifier source/ELF/output privately.
4. If the returned invoice contains only the expected plain memo, record a real
   LNURL compatibility failure and stop payment. Do not substitute a new invoice,
   alter stock Noah or relax the verifier to obtain a green result.
5. Only a passing invoice may proceed to a separately journaled exact-hash payment,
   settled/failed reconciliation and genuine signed recipient claim/delivery.

The recipient remains offline throughout that receive. Lightning settlement,
provider API success, recipient policy registration and mailbox delivery are
separate facts. Continue using the ownership boundaries above for any failure
or interruption. A strict invoice failure is useful compatibility evidence,
not a dead campaign to hide or a completed offline receive.


The [actual metadata preflight](evidence/noah-metadata-preflight-20261017.json)
was recorded on 17 October at 15:34:43 UTC. Verified HTTPS returned real metadata;
both CLN peers were `CHANNELD_NORMAL` at height 326769, with 98,000 sat external
spendable/internal receivable liquidity. This still has no callback invoice or
payment. The exact metadata hash will be compared against the eventual invoice;
the pre-existing old-profile recipient binding is not a new-profile handoff.


The existing [standalone verifier was rebuilt unchanged](evidence/noah-invoice-verifier-20261017.json)
inside the project's Nix environment, using its exact lockfile and the shared
build target. All five offline protocol tests passed. New ELF
`e97c422b5ee894b3d5486ff139039d46107cc0e723adb9dea5a94ccd501798b1`
was independently verified and executed on the Signet VM. Its malformed-input
smoke rejected the input as expected. The earlier reported `f96...` artifact
was not found; this new binary has its own measured provenance. The verifier
accepts one JSON policy on stdin and no arguments; it still rejects plain-memo
invoices without the exact LNURL metadata hash. No live invoice was requested
by the rebuild or smoke test.


## Actual callback rejection — 17 October

[The single actual callback failed strict LNURL invoice verification](evidence/noah-actual-invoice-rejection-20261017.json)
at 16:11:48 UTC, public Signet height 326772. Stock Noah returned HTTP 200 and
an actual 5,000-sat invoice through a newly admitted isolated Ark/CLN profile,
authenticated fresh native provider and absent recipient. The unchanged verifier
rejected it with `LNURL metadata hash missing; plain description is incompatible`.
This replaces the source prediction above with measured invoice evidence.

The exact original response, invoice, metadata bytes, policy and verifier outputs
are retained privately and bound by public hashes. No payment was made, no invoice
was regenerated, and verification was not relaxed. The old zero-funded provider
was stopped cleanly and cold-backed up before port handover. Existing ordinary,
short-repair, Core and CLN service identities remained unchanged.

This is a compatibility blocker for the stock LNURL path, not a completed swap
or fallback test. The financial goal still requires an actual paid native swap,
correct conditional/recipient ownership, mailbox delivery or its interruption,
real expiry, rightful fallback and seed-only confirmed recovery. A genuine
failed-send/refundable path is separately required. Invoice and CLN results
cannot substitute for those proofs; any different financial test needs its own
explicit scope and source/profile/funding pins.


## Corrected receive-only financial profile research

The earlier requirement that the pool tree outlive the whole HTLC was wrong.
Current `validate_htlc_duration` bounds the HTLC deadline by tip and configured
maximum; SDK `htlc_recv_tree_blocks_needed` requires only `vtxo_exit_margin`.
Neither imposes tree expiry later than HTLC expiry. Record both actual heights.

The coordinator is qualifying a separately pinned native BOLT11 receive profile:
server/pool lifetime 32, exit delta 12, pool pre-expiry 12 and HTLC expiry delta 6,
with unchanged SDK exit margin 12 and claim delta 18. Actual prepare slack is 2,
so the requested receive CLTV is 50, approximate grant deadline is claim tip +48,
and invoice final CLTV adds 6 to make 56. A 32-block root can therefore expire
before its former HTLC deadline. Fully settled signed recipient Pubkey proceeds
can still fallback at that root expiry. These are source-derived parameters;
actual eligibility, amounts, deadlines and claim/fallback need the coordinator's
native gate and later funded public-Signet execution. No profile was changed by
this analysis. This future native case receives no Noah/LNURL completion credit.

[Metadata-hash support options](noah-metadata-hash-support.md) are source-only.
No Noah source was patched or rebuilt to alter the measured rejected callback.

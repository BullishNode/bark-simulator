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

The old deployment has been retired. Until a real compatible backend is supplied
and this path runs on public Signet, report S09 `BLOCKED: owned compatible backend
not deployed`, retaining the source-level findings above. It does not block S01.

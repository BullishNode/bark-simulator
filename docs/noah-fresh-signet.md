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
  accepts that request schema. Its documented operation claims the Lightning
  receive in the backend wallet, then forwards the Ark VTXO to the supplied
  address's mailbox.

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
3. The backend wallet receives/claims or refunds the actual HTLC.
4. The backend forwards the value to the absent recipient's Ark key, or records
   a still-outstanding forwarding obligation.
5. If forwarded coins expire, the registered recipient receives their fallback;
   verify it on chain without waking the original wallet.

Three custody boundaries matter when recording interrupted results:

| Boundary | What the fallback can establish |
|---|---|
| HTLC not terminal | The payment/claim/refund outcome is still unresolved. |
| Backend claimed; forwarding not committed | The backend owns the Ark coins. A payout to its registered script does not discharge its obligation to the intended recipient. |
| Forward committed to recipient | Verify the recipient's real coin/registration and eventual fallback, independently of the backend's success reply. |

Distinguish **recipient offline with backend running** from **backend forwarding
wallet stopped**. They are different conditions. Do not claim the recipient
received value merely because Lightning settled or the backend recovered funds.

The old deployment has been retired. Until a real compatible backend is supplied
and this path runs on public Signet, report S09 `BLOCKED: owned compatible backend
not deployed`, retaining the source-level findings above. It does not block S01.

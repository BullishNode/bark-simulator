# LNURL metadata-hash support: source-only options

The actual stock callback rejection is recorded in
[evidence](evidence/noah-actual-invoice-rejection-20261017.json). This note
proposes no running change, new invoice or payment. The rejected invoice remains
an immutable unpaid artifact and must not be reused for a financial test.

The existing hold 0.3.3 `InvoiceRequest` already provides a description oneof:
`memo` field 3 or `hash` field 4. Product `server/src/ln/node_manager.rs` always
selects `Description::Memo`. `StartLightningReceiveRequest` in
`server-rpc/protos/bark_server.proto` exposes only optional string `description`
at field 5. SDK receive methods and REST `LightningInvoiceForAddressRequest`
also accept memo strings only. Stock Noah `8e68ba5` constructs metadata in the
no-amount branch, but its amount callback sends the plain memo through
`server/src/barkd_client.rs`. There is no existing configuration switch that
passes the required exact metadata hash through this pipeline.

The smallest generic API option is an optional exact 32-byte description hash:

1. Add hash support to the provider REST request and SDK receive entry point,
   preserving existing ordinary memo callers.
2. Carry the hash explicitly through the product RPC (field 6 is currently free)
   and select the existing hold `Description::Hash` variant. Reject malformed
   lengths and simultaneous memo/hash inputs before creating an invoice.
3. In Noah, share one function producing the exact metadata string between the
   metadata response and callback. SHA256 those exact UTF-8 bytes, then pass that
   hash to the forwarding provider. Hashing only the plain memo is incorrect.
4. Bind the returned invoice to the requested hash in the SDK/provider checks;
   keep the independent strict observer unchanged.

An alternative provider API accepts the exact metadata UTF-8 string and computes
SHA256 at that boundary. It still requires typed hash support through SDK/RPC
and the existing hold Hash variant, plus Noah passing its exact metadata string.
It moves hash computation into the provider but does not remove the end-to-end
commitment or the need for common metadata construction.

There is no way to repair an already signed memo invoice by altering callback
JSON or adding the hash after signing. A separate native BOLT11 financial test
can exercise the swap without LNURL, but must be labeled separately and use a
new admitted operation; it cannot turn this stock Noah callback into a PASS.

Any future implementation needs actual positive invoice/hash binding and
negative changed-metadata/amount/network/expiry/signature tests, plus ordinary
memo compatibility and the real offline recipient swap/fallback lifecycle.
No Noah mobile wallet, build, source patch or verifier relaxation was performed
for this analysis.

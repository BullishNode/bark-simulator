# Prepared native failed external send

Preparation only: no new actor, funding, invoice, send or cancellation has been
executed. This is a separate operation from the successful native receive and
the rejected stock Noah callback. Existing observers and recipient fences stay
in place.

## Exact existing runtime and actual timing

Reuse the admitted 32/12 public-Signet profile and its unchanged configuration,
server identity and four ELFs recorded in
[the native receive receipt](evidence/public-signet-native-ln-receive-20261017.json).
Actual build HEAD is `6950be5a6855625d76d04e33c86a6b030cd9406e`, dirty captured
source `c60c5cd4c9d8cc0fbeaa8f8f6a71ba4102a46075cd2d9515fb505d9ba2dc882b`.
Do not relabel a newer source publication as the deployed runtime.

**This profile's send deadline is 258 blocks, even though its tree lifetime is
32 blocks.** The native SDK chooses `send_tip + htlc_send_expiry_delta`. The
server rejects a new deadline below its configured minimum, allowing one block
of tip tolerance. Record the actual signed grant deadline D and backing expiry
E independently; never infer D from the invoice wall-clock expiry.

In this exact source, failed/unattempted sender ownership additionally requires
both captaind and watchmand completed tips to reach D. An actual terminal CLN
failure does not remove that deadline gate. Therefore this offline, unrevoked
case cannot qualify at E or merely when the hold invoice is cancelled. If sent
at height 326787, the SDK would choose D=327045; this is an illustration, not an
issued grant or promised completion height. A shorter campaign would require a
separately admitted configuration and its own native qualification. Neither is
authorized or silently substituted here.

Source references checked against the captured build manifest:

| File | SHA256 / checked behavior |
|---|---|
| `server/src/database/expiry_ownership.rs` | `e1723bb6efc0db4f18e5438f6882fd5e5d98bc58b470baa1b48f65e51c49e68a`: failed source still waits for actual HTLC deadline |
| `server/src/ln/cln/xpay.rs` | `7ea3fcee5ab94b9e74759171ef55fbe2c12b9a814de83d8513377901779a3ceb`: source-specific observed sendpay failure |
| `server/src/database/expiry_lightning.rs` | `dc1b884df561bd08287b9dda1953d5dd7abe896cb8da7ade723c2c59e530b9bf`: exact build-HEAD file; current checkout differs |
| `bark/src/actions/lightning/pay.rs` | `55daadb631de69c322d79b767ff2808f537c55f94fe8b39858fff632169478a6`: signed grants, persisted checkpoint and default nonwaiting send |
| `bark-cli/src/bin/bark/lightning.rs` | `c3fb729785ce3f9dbf2cfc3d4052ce812ff51e7a6a0fe02e2e4625f8e0a3ddbc`: `--retry-for` and optional `--wait` |
| `bark-cli/src/wallet.rs` | `c6bf4786b84acb0afe95fa267a103c35ce5844437c230421d9613ed0b3209223`: native CLI opens with `run_daemon: false` |

## Stock plugin compatibility

Actual VM processes were checked, rather than borrowing native-regtest adapter
labels: CLN26.06.6 ELF `0979efd4…`, stock gRPC `421c19f3…`, hold0.3.3
`cef52444…`. Both peers were synchronized and CHANNELD_NORMAL. At height326785,
the internal peer had 93,694,000msat spendable and the external peer the same
receivable capacity, sufficient for this proposed 5,000-sat outbound payment.
These balances must be observed again immediately before execution.

The desired Accepted→Cancelled case creates a real sendpay group. The backend
requires actual own-dispatch label, payment hash, positive created index, all
same-hash groups failed and no preimage. That observed-group proof uses ordinary
`listpays`; it does not require the modified adapter's typed error metadata.
This is source compatibility, not a completed failed-send proof on this VM.
The no-attempt205/207 case does require the qualified typed metadata and remains
separately unqualified on the stock VM adapter.

Read-only VM help confirmed `holdinvoice payment_hash amount`,
`listholdinvoices [payment_hash] [bolt11]`, and
`cancelholdinvoice payment_hash`. In the
[hold0.3.3 implementation](https://github.com/BoltzExchange/hold/blob/v0.3.3/src/commands/invoice.rs),
the integer `amount` is passed to `amount_msat`; its
[protocol test](https://github.com/BoltzExchange/hold/blob/v0.3.3/tests-regtest/hold/regtest_rpc.py)
checks the decoded amount. Proposed command argument is therefore **5000000**,
followed by independent CLN BOLT11 decode/hash/network/payee/expiry checks.
No hold invoice has been created by this preparation.

## Bounded execution after separate admission

1. Create one separate random-seed native sender with explicit SDK12/12/18
   configuration, preserving its original pre-create birthday and protected
   phrase. Retain its authentic fallback registration and native funding
   address. Do not reuse the absent receive recipient or either ordinary actor.
2. Request at most100,000sat new actor principal plus an explicit bounded
   treasury transaction fee. Root dispatches funding once. Existing profile
   watchman funds must remain actually confirmed and usable; no new operator
   allocation is presumed. Board30,000sat once after real funding inclusion,
   then require the actual three board confirmations, signatures and backing.
3. Journal one fresh external hold-invoice intent before its RPC, retaining the
   protected original preimage privately. Decode the returned invoice: exact
  5,000,000msat, new payment hash, external node identity, public Signet and
   usable expiry. Do not reveal the preimage or pay through another payer.
4. Journal exactly one native `lightning pay invoice <original invoice>
   --no-sync --retry-for 120` call, **without `--wait`**. Preserve its actual
   stdout/stderr: this CLI command does not promise a JSON payment receipt.
   Require successful parked `PaymentInitiated` checkpoint and actual external
   hold state `accepted` with the exact hash/amount. Stop if it already failed,
   settled, revoked, or never became accepted; those are different outcomes.
5. Close and fence the original native sender before cancellation. Preserve
   its original checkpoint and signed grant/change IDs through a read-only,
   explicit projection. Do not invoke native `lightning pay status`, sync,
   maintenance or reopen: those SDK calls can perform cooperative revocation.
   Read public signed bodies and verify the original sender's grant/change
   paths; retain actual E, D, amounts and authenticated payout script.
6. Only after the actor is genuinely offline and the matching hold is accepted,
   journal one external `cancelholdinvoice <hash>`. Require its original hold
   entry to become `cancelled`, then independently observe the original
   internal CLN own-label groups all failed, no preimage and positive created
   index. An administrative source-specific terminal-proof projection can
   corroborate backend ingestion; it cannot establish payment by itself.
7. Keep the owner offline until both chain listeners reach D, then independently
   discover its correct fallback from public Core transactions and frozen
   signed paths. Require exact script, amount/fee conservation and canonical
   parent plus positive-fee child each at least six confirmations. Only then
   restore a fresh DB from the original phrase/birthday and execute one
   journaled drain whose confirmed input includes the fallback output.

At each external mutation, commit intent before dispatch. A lost or invalid
reply becomes UNKNOWN/HOLD. Reconcile the original payment hash/invoice/txid;
never repeat create, board, send or cancel automatically. Retain the first
failure and all source pins. No SQL mutation, artificial deadline, injected
settlement or wrong-payee reproduction is part of this case.

## Expected economics, not observed results

One30,000-sat board has historically created a29,670-sat customer coin and a
330-sat explicit board residual; actual transactions decide the new values.
For the short-lifetime fee band, a5,000-sat send is provisionally75sat fee:
5,075sat HTLC plus24,595sat change. If that entire source remains the same
customer's refundable entitlement, one eventual payout would be28,670sat after
one1,000-sat output fee. Do not book the provisional75sat as earned send revenue
when the payment fails. Confirm the actual full economic cut and any split
outputs before fixing an expectation. Actor onchain change, board miner fee,
fallback fee, operator fee-child cash payment and one physical recovery fee
must remain separate amounts.

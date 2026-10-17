# Prepared native failed external send

At the retained zero-funded admission, no funding, invoice, send or cancellation
had occurred. A separate server/watchman profile and one genuine zero-funded
sender had been prepared, as recorded below. This is separate
from the successful native receive and the rejected stock Noah callback.
Existing observers and recipient fences stay in place.

## Exact existing runtime and actual timing

The original preparation considered the admitted 32/12 public-Signet profile
with its unchanged configuration, server identity and four ELFs recorded in
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
issued grant or promised completion height. This explains why the financial
operation now uses a distinct, explicitly configured 18-block send profile.
The original receive profile remains unchanged and still waits for its own
real expiry. The shorter profile is not evidence that the 258-block operation
finishes at tree expiry.

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
No hold invoice has been created by this preparation. The short profile must
use the existing gRPC override described below: the JSON-RPC command's default
80-block final CLTV cannot fit an 18-block send deadline.

## Actual zero-funded 18/32 profile

[The immutable historical admission](evidence/native-ln-failed-send-zero-funded-admission-20261017.json)
records the actual configuration, binaries, services and zero balances before
the proposed funding. Later funding and financial execution need separate
receipts; they do not rewrite this observation.

The separately authorized profile uses the **same four c60c source/ELF pins**,
its own empty database and directories, distinct ports and fresh server key.
Native `check-config` passed. Captaind and watchmand started serially with zero
restarts; both real operator wallets have zero balance and no UTXOs. Public
GetArkInfo independently reports lifetime32, exit12, send delta18, settlement
margin6 and ordinary board confirmations3. The maximum accepted HTLC duration
is explicitly288; the pool target is empty because the source will be an
actor-funded board, not a receive grant.

The one new sender completed native create, authentic registration and actual
18/32 SDK handshake, with zero coins/balance and original birthday326787. Its
CLI opens use `run_daemon:false`; no watch/background process was started.
The protected original phrase was backed up and independently hash checked.
All15 existing protected services retained their PIDs/restart counts, and the
original receive observer remained alive with its own lock. These observations
do not establish an accepted outbound HTLC or refund.

The selected funding proposal is **100,000sat total principal**:60,000 to this
sender and two distinct20,000-sat watchman outputs. Funding miner fees will be
recorded separately. No rounds allocation is assumed for this empty-pool case.
The sender's eventual HTLC/change/refund expectation must be derived from its
actual board and native send fee; no assumed29,000-sat refund is a readiness
condition. Root owns the single treasury allocation and final money admission.

One pre-funding parser failure is retained. Native `onchain address` returns
JSON`{address:...}`, and the first read-only preflight incorrectly passed that
serialized object to Core. Core rejected it. The correction parsed the cached
native reply and resumed from the existing create ACK without repeating create
or address generation; no funding or invoice was dispatched.

### Existing stock hold RPC, with a short invoice

The actual external hold0.3.3 plugin answered **read-only GetInfo over verified
mTLS and HTTP/2**, with successful gRPC status0. Its certificate includes
localhost/127.0.0.1; no TLS bypass is required. The existing `hold.Hold/Invoice`
request supports protobuf fields:

| Field | Number | Proposed value |
|---|---|---|
| payment_hash | 1, bytes | Protected original operation's32-byte hash |
| amount_msat | 2, uint64 | 5000000 |
| memo | 3, string | Native failed external send qualification |
| expiry | 5, optional uint64 | 3600 seconds |
| min_final_cltv_expiry | 6, optional uint64 | 6 blocks |

Only after durable intent and financial admission may the original framed
request be sent once to that existing mTLS endpoint. Retain exact original
request/response/header bytes privately; require HTTP/2 success and gRPC
status0, then independently decode the original invoice's signature, network,
amount, hash, external node, expiry and **actual final CLTV6**. A lost response
is reconciled by original hash, not another invoice.

With send delta18 and server margin6, same-tip xpay maxdelay is12. An actual
read-only `getroutes` call for5,000,000msat, finalCLTV6 and maxdelay12 returned
the owned direct private channel with zero fee. This proves route computation,
not payment or acceptance. Immediately before a real send, recheck the exact
channel/liquidity/tips and retain the actual deadline D. Require D<E for this
declared short experiment, without imposing that restriction on the product's
general accepted design. Native SDK sets D=send_tip+18; a board created atH has
E=H+32. No signed D or E exists yet for this unfunded sender.

## Bounded execution after separate admission

The initial `python3 -m simulator.signet_failed_send` controller implements
`stage`, `funding`, `board` and `ready`. It binds the genuine original sender
directory to the existing durable Campaign executor, pins its real
configuration and imports only cached registration plus the protected original
source. It does not copy a wallet or fabricate a create ACK. Staging requires
the original root funding receipt/request and retained financial admission.
The native board command is:

```
python3 -m simulator.signet_failed_send --state "$STATE" --config "$CFG" board
python3 -m simulator.signet_failed_send --state "$STATE" --config "$CFG" ready
```

The first command waits for the actual exact funding outputs and native usable
confirmed watchman inputs, then journals one30,000-sat board. The second waits
for three real canonical confirmations before any sender wallet observation,
then requires the real SDK handshake, spendable coin, full signature/backing
proof and sufficient short-profile headroom. Zero exit and a proposed deadline
are never held-HTLC or refund proof. Invoice/send/cancel/recovery phases are not
implemented by this initial controller milestone; they require their own
checked continuation before financial execution proceeds.

1. Create one separate random-seed native sender with explicit SDK12/12/18
   configuration, preserving its original pre-create birthday and protected
   phrase. Retain its authentic fallback registration and native funding
   address. Do not reuse the absent receive recipient or either ordinary actor.
2. Request the selected60,000-sat actor allocation and two20,000-sat fee outputs,
   plus an explicit bounded treasury transaction fee. Root dispatches funding
   once. The new profile's own watchman inputs must be actually confirmed and
   usable. Board30,000sat once after real funding inclusion,
   then require the actual three board confirmations, signatures and backing.
3. Journal one fresh external hold-invoice intent before its existing gRPC
   Invoice RPC with minfinalCLTV6, retaining the protected original preimage
   privately. Decode the returned invoice: exact
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

## Funding and controller preparation checkpoint

Root broadcast exactly one separate allocation transaction,
`8e60b79edef0d909c8008c3a1f1eb68384b47058a21edfae1be2254880fd7103`:
sender vout0 is60,000sat; watchman vouts2 and3 are20,000sat each. The actual
funding miner fee is612sat. At the retained controller observation at326790 it
had **zero confirmations**. Allocation is not board admission or a Lightning
proof. The [additive receipt](evidence/native-ln-failed-send-controller-preparation-20261017.json)
keeps this separate from the earlier zero-funded receipt.

Published controller03a5b57 was frozen separately, passed81 focused tests on
the VM and imported only the actual cached registration and protected original
phrase. It fabricated no create ACK and opened no sender wallet. The original
bdefb5c stage refusal is retained: the root funding receipt spells its network
`public signet`, while the initial parser expected `signet`. The narrow fix
accepts those two labels and still requires independently synced Core with the
exact default public-Signet challenge and genesis; a regtest receipt is refused.

The reviewed03a5b57 supervisor waits for actual canonical funding inclusion and
both selected watchman inputs to be confirmed and natively usable. Only then
may it journal one30,000-sat board. It waits for three actual board confirmations
before one manual SDK/signature/backing readiness observation. It exits there.
It has **no invoice/send/cancel authorization**. Existing receive and ordinary
runners, original actors, configurations and source pins are unchanged.

The continuation in `simulator.signet_failed_send` is a new source phase, pending
coordinator review and separate live admission. Its commands are deliberately
sequential: `transport`, `invoice`, `send`, `observe-hold`, `fence`, `cancel`,
`observe-failure`, `recover`. The same original journal persists across the
explicit controller phase transition; the existing03a5b57 checkout stays intact.

- `transport` pins the actual stock CLN/plugin executables and owned mTLS files.
  A single protected random preimage fixes the original invoice hash; it is
  never sent to the payment receiver or copied into public reports.
- `invoice` journals before one original hold gRPC request, requires strict
  successful framing, and checks the original BOLT11 using actual CLN decode.
  `send` journals one native nonwaiting CLI call. Empty stdout and zero exit
  acknowledge initiation only. Unknown outcomes stop without another effect.
- `fence` requires the original external Accepted state, parked original SDK
  checkpoint, full signed grant/change paths, conservation, and the actual
  registered grant/hash/direction/deadline join. It records actual D/E and
  permanently fences the original sender before cancellation. No subsequent
  original native status, sync, maintenance or wallet open is allowed.
- `cancel` journals one original external cancellation. `observe-failure`
  requires the exact own dispatch label, positive observed-group index, all
  same-hash payer groups failed, no external success, and no preimage. Coarse
  `failed` or a typed no-attempt shortcut cannot qualify this experiment.
- `recover` waits for actual D/E and independently discovers one correct
  registered-script payout of the complete frozen source/change amount minus
  one1,000-sat fee. Both the immutable parent and actual positive-fee child must
  have six confirmations before fresh original-seed-only restore, with the
  original326787 birthday and no payout/outpoint hints. One journaled drain
  must consume the actual payout and confirm. Ordinary onchain change and the
  physical recovery miner fee are accounted separately.

The added tests exercise controller faults and guards. They are not public
Signet failed-send, fallback, Noah or LNURL success. Live invoice/send/cancel
remain unexecuted at this source checkpoint.

Local focused validation passed92 tests after the continuation was added. One
first aggregate run failed an existing receive test because its fake invoice
creation timestamp changed between successive decode calls across a wall-clock
second. The fixture now retains the original timestamp, like a real immutable
invoice; production identity comparisons and live receive code were unchanged.
The failed local run is not a Signet payment failure or evidence of a refund.

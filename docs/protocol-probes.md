# Explicit client protocol probes

Protocol probes require an explicitly frozen intent. They are disabled in the automatic raw-request rotation. Each intent binds the actor, server key, signed input identities, principal, RPC, expected guard and a fee ceiling of at most 2,000 sat. The original absent actors 03, 09 and 10 stay closed. Busy or unknown actions prevent another probe from that owner.

The native adapters use typed SDK/protobuf messages. The integrated adapters compile against the qualified SDK8f interfaces and protocol-version headers. Real signet execution, independent reconciliation and scenario-specific financial checks remain separate requirements; compilation and mocked tests do not establish production acceptance.

The following table contains every required scenario. "Typed source" means the adapter exists; it does not mean a live verdict. Phase cases require their real economic checkpoint and controller. The report retains mechanism, attempts, evidence, fees and unresolved liabilities for every row.

| Scenario | RPC/mechanism | Source adapter | Required behavior |
| --- | --- | --- | --- |
| D13 | `SubmitPayment` | Compiled adapter; live gates pending | frozen round output with an unlinked key |
| D14 | `RequestArkoorCosign` | Compiled adapter; live gates pending | valid checkpointed arkoor with an unlinked destination |
| D15 | `PrepareLightningReceiveClaim` | Compiled adapter; live gates pending | Accepted actual receive; valid ownership anti-DoS proof; unlinked HTLC-recv key |
| D16 | `RequestLightningPayHtlcCosign` | Compiled adapter; live gates pending | valid HTLC-send and unlinked change output |
| D17 | `race` | Phase controller pending | two frozen arkoor packages spend the identical owned input to distinct registered recipients |
| D18 | `race` | Phase controller pending | arkoor package races an active interactive round on the identical input |
| D19 | `race` | Phase controller pending | offboard preparation races refresh; reconcile forfeit and chain winner |
| D20 | `race` | Phase controller pending | unilateral exit races cooperative spend; independent confirmed chain arbitration |
| D21 | `RequestArkoorCosign` | Compiled adapter; live gates pending | replay an input with independently checked expiry settlement |
| D22 | `RegisterVtxoTransactions` | Compiled adapter; live gates pending | replay the identical previously delivered signed transaction chain; mailbox replay is a separate variant |
| D23 | `RegisterVtxoTransactions` | Compiled adapter; live gates pending | truncate an independently signed original chain |
| D24 | `RegisterVtxoTransactions` | Phase controller pending | deliver a saved unregistered successor only after its input-owner payout commits |
| D25 | `RegisterVtxoTransactions` | Compiled adapter; live gates pending | combine two independent owner chains with an altered foreign payee policy |
| D26 | `SubmitRoundParticipation` | Phase controller pending | race two distinct signed delegated requests on identical inputs; retain winner exchange |
| D27 | `ForfeitVtxos` | Phase controller pending | replay exact cached forfeit after recorded expiry cancellation |
| D28 | `proof oracle` | Phase controller pending | supply another confirmed sweep branch; rightful coin remains pending |
| D29 | `RequestLightningPayHtlcRevocation` | Compiled adapter; live gates pending | paid same-hash send with retained owned HTLCs |
| D30 | `RequestLightningPayHtlcRevocation` | Compiled adapter; live gates pending | known pending same-hash send; timeout alone never enables refund |
| D31 | `ClaimLightningReceive` | Compiled adapter; live gates pending | Settled same-hash receive with retained private preimage and identical destination |
| D32 | `ClaimLightningReceive` | Compiled adapter; live gates pending | HtlcsReady actual receive; valid cosign request and deliberately mismatching preimage |
| D33 | `ClaimLightningReceive` | Phase controller pending | saved rightful claim after the matching sender refund commits |
| D34 | `race` | Phase controller pending | valid internal claim races same-hash revocation under one immutable intent |
| D35 | `PrepareLightningReceiveClaim` | Compiled adapter; live gates pending | legitimately collected Accepted receive requests uint32 maximum expiry |
| D36 | `deadline profile` | Phase controller pending | withhold prepared internal claim; measure actual lock until rightful refund or claim |

A generic `InvalidArgument`, a timeout or an unavailable transport does not count as an expected refusal. Missing-fallback refusals bind the exact attempted key and RPC. Paid and pending refund guards are distinct. D35 requires the collected-receive expiry guard; the held-invoice overflow guard belongs to another path.

D31 can return an idempotent successful reply. It binds the original hash, retained private preimage, exact granted HTLC inputs and original signed output IDs. Rebuilt unsigned output IDs must match those original outputs. A reply alone does not prove that fees, credit, liabilities or payouts were booked once. D22 includes transaction-chain registration replay; exact mailbox-envelope replay remains a separate missing variant.

`CheckLightningReceive` returns HTLC IDs in SDK8f, while `PrepareLightningReceiveClaim` returns signed coin bytes. The adapter checks both identities and same-hash HTLC policy rather than matching amount alone. D15 and D35 require an actual Accepted invoice and valid owned anti-DoS proof. An arbitrary fabricated payment hash cannot exercise these paths.

Public post-request checks verify protected record/key mappings and their signatures. Missing authenticated status remains a gap; a sentinel never means unchanged state. Foreign-registration cases require an independent current public-state audit. Duplicate entitlement, conservation and payout arbitration remain separate acceptance gates. No probe produces customer traffic credit.

Native request/reply bytes, private output keys, round nonces and any preimages are retained in protected actor-private preparations. Public events carry hashes, status and references. Preparation precedes dispatch and fences repeat execution after a lost reply. Arkoor builders do not expose serializable secret nonces in this SDK: after an unexpected acceptance, their exact public request/destination and output key remain retained, but same-package recovery requires an explicit reconciliation workflow. Automatic nonce regeneration or RPC retry is prohibited.

Fallback rotation uses the SDK setter with a declared seed-owned script. It requires a checked original payout and freezes the original record, destination and zero fee intent. It preserves historical signed records and payout proofs. The SDK must verify ownership before registration; the adapter reserves no new address on retry. Lost replies remain fenced. The pinned SDK setter bounds reconciliation at three registrations. Inner SDK registration capture is still unavailable; actual public readbacks and the frozen SDK intent are retained separately. H29 still requires later-coin and payout evidence before qualification.

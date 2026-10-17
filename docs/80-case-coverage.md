# Original 80-case coverage map

No: all 80 original behaviors have not been tested. **Two IDs are fully demonstrated on public Signet (H03, H07), and one additional ID on a pinned fresh native-regtest snapshot (H36). The other 77 are not fully demonstrated as written.**

These are ID-specific claims, not a count of completed S-campaigns. The 81 automated Python tests check controller logic; they are not 81 live product behaviors. The [machine-readable rows](80-case-coverage.json) preserve every original ID, behavior, expected outcome and driver from [the catalogue](../simulator/scenarios.json). Its SHA256 is `fd01b08c72abb9cf61c5f93aa2c43362fa7e8b58788a7fbc54d0e1ab85de86b4`.

The table combines evidence from **separately pinned fresh snapshots**, not one fully retested release candidate: live Signet 7055, specific native backend manifests, and client 626dcc28d against archived 7055 servers. No old A/B/C PASS is inherited. A later branch HEAD does not inherit every older execution result.

## Category counts

Categories identify the highest relevant evidence, including partial subcases. They are **not scenario PASS totals**.

| Category | IDs |
|---|---:|
| public signet | 8 |
| native regtest | 24 |
| unit only | 10 |
| source only | 16 |
| not run | 9 |
| failed | 1 |
| needs adaptation | 12 |

The measured failure is D39: at 10,000 authenticated accounts, the positive owner search with no verified mailbox missed its 120-second budget. The 10,000 wrong-mailbox case was not run. Registration count is not payout-coin capacity. Twelve rows contain replaced legacy expectations, principally hints, mandatory per-key admission and old carrier terminology. Their new expectations and concrete execution recipes are defined below; none is dropped or counted as passed.

## Revision-5 expectation overlay

The original catalogue stays unchanged for provenance. Every JSON row adds `design_expectation` and `required_proof`. Server acceptance covers authenticated application-supplied standard scripts; external BIP84 seed recovery is a client case. Expired ordinary refresh/offboard can win before decision, while new Lightning grants/first attempts have narrow expiry admission. Existing admitted liabilities remain recoverable. An unfinished nonbinding exchange is atomically cancelled; a binding commitment keeps its actual obligation.

The following legacy-policy rows explicitly change recipe. Their evidence category remains `needs_adaptation` to expose the changed baseline; the mapping is now defined and its required executions remain unproven. Additional wording corrections for BIP84, decision boundaries, Lightning and claim provenance appear in the JSON for the other affected IDs.

| ID | Original expectation | Current expectation | Required actual proof |
|---|---|---|---|
| H01 | Board works only with the valid link/record; principal and actual fees reconcile. | Authenticated immutable xpub/application-supplied standard payout registration works before native boarding; principal and actual fees reconcile. The server has no blanket per-key publication prerequisite. | Create/register/board normally; separately exercise absent, changed and invalid registration states and prove the selected original-owner rule without inventing a mandatory no-record creation refusal. |
| H08 | Bounded on-demand hint validates the exact registered account child; rightful recipient paid. | An absent registered recipient at child 25/50 is attributed by verified mailbox plus exact xpub derivation, falling back to resumable complete search; no payer hint is required. | Capture genuine high-index addresses while active, close the recipient, register real signed transfers, remove no evidence artificially, and prove mailbox and missing/wrong-mailbox attribution plus rightful payout without recipient opens. |
| D07 | No unauthorized partial coin creation; record initialization remains explicit and attributable. | Registration authorization and subsequent native coin creation are checked on their actual separate interfaces; removed hint/proof fields are not a composite creation contract. | Submit altered authenticated record via actual current RPC; assert no unauthorized canonical record/entitlement, then create through the genuine supported path and reconcile original ownership. |
| D08 | Derived compressed key equality fails; victim value cannot be redirected. | Mailbox identifies only a candidate; exact compressed policy key must derive from the authenticated xpub, otherwise fallback search continues without attacker redirection. | Use a genuine victim coin with adversarial candidate mailbox/account and derivation indices; verify wrong candidate rejection, resumable fallback and exact rightful final payout. |
| D10 | Exact derived compressed key matches actual required policy; otherwise refused. | Attribution verifies exact derived compressed policy key, including parity, against signed coin policy; no caller child hint is trusted. | Exercise current mailbox/xpub lookup with a different child and x-only parity lookalike; prove no wrong owner/payout and eventual correct search result. |
| D11 | Old ownership survives; no mutable relink. | Canonical account/mailbox registration is immutable and xpub aliases cannot acquire another owner; no mutable per-key link API is required. | Race authentic conflicting registrations and semantic xpub aliases; assert one canonical record, persistent old entitlement and no wrong payout after restart. |
| D12 | Creation refusal; no funded uncovered coin. | An original board without a verified registration is not silently operator-owned or gifted: genuine funding and original ownership must resolve before its own payout decision. | Create through the actual no-record board interface if supported, fund only declared backing, test late registration before/after decision and confirm rightful outcome or explicit unresolved blocker; no synthetic SQL. |
| D13 | Creation refusal. | A round output does not require payer-side per-key publication; actual signed policy/registration or original-owner lineage determines rightful settlement. | Generate a genuine no-recipient-record round output, retain signed forfeits/unlock and mailbox evidence, then prove exact current ownership and no unfunded customer/operator gift. |
| D14 | Creation refusal. | Unregistered Ark-to-Ark output preserves its input owner under C4 until an authenticated recipient wins before decision; blanket creation refusal is not expected. | Capture authentic signed transfer before and after registration, race recipient registration with decision, then verify the selected owner once with real on-chain discharge. |
| D15 | Creation refusal before unfunded/incorrect entitlement. | A receive grant needs real funded/source-specific obligation and allowed new-grant admission; missing per-key publication is not itself blanket creation refusal. | Use actual no-record recipient receive API, distinguish provider HTLC from signed recipient claim registration, and prove correct source owner/no unbacked payout for both outcomes. |
| D16 | Creation refusal for the actual output path under test. | Send/change ownership follows actual registered source and change policy; new grants on expired backing are refused, but admitted safe retries/revocations remain recoverable. | Exercise the genuine no-record output path, narrow send admission and eventual source-specific resolution; verify unchanged source on refusal and rightful change/refund. |
| D40 | Controlled refusal; no daemon failure or recipient amount change; orphan carrier recovered. | Current malformed record/amount/encoding is refused safely; immutable payout parent survives fee-child conflict/replacement, stale notifications and reorgs. No legacy carrier/hint API is assumed. | Inject malformed current RPC payloads and overflow boundaries, real confirmed-fee-input conflicts/child RBF and stale/orphan callbacks; independently prove unchanged recipient parent/amount and recoverable canonical allocation. |

This overlay grants no new PASS. A BIP84 payout observed on one candidate does not prove every supported script, and a written scenario recipe is not a native execution.

## All 80 original behaviors

The behavior column is copied verbatim. `complete` means the full named behavior on its explicitly pinned evidence only. Every other row remains unproven as a whole. Evidence keys link to the catalogue below; exact run IDs, source/ELF/manifest hashes, scopes and remaining requirements are in the JSON.

| ID | Original behavior | Evidence / scope | Demonstrated and remaining gap |
|---|---|---|---|
| H01 | Create a wallet, register fallback, then board confirmed funds. | needs adaptation / **needs_adaptation**; [SIG](#sig), [REG](#reg) | Native registration and confirmed boards work. Old mandatory per-key/link admission is not the new server contract; negative no-record admission must be respecified. |
| H02 | Attempt boarding while the funding confirmation requirement is unmet, then retry. | public signet / **partial**; [SIG](#sig) | Once-only boards waited for genuine three-confirmation native admission. No deliberately premature funding-confirmation request and explicit retry/refusal trace. |
| H03 | Board, finish registration, and never return. | public signet / **complete**; [SIG](#sig) | Absent registered board expired and paid its exact registered script once; public history checked and recovery spent it. Only the pinned 7055 simple-board cohort, not every candidate or ownership class. |
| H04 | Fund pending board, stop before final registration; expiry consumes exact funded backing into owner output. | not run / **unproven**; [SOURCE](#source) | No fresh native execution of funded pending-board abandonment is established. Upstream cosign does not persist the required pending-board ownership record; full funded/unfunded cases remain. |
| H05 | Get board cosign/proposal but never broadcast its funding transaction. | not run / **unproven**; [SOURCE](#source) | No fresh captured cosign-only/unbroadcast-board run is established. Prove absence of invented principal and operator-funded gifts on actual pending proposals. |
| H06 | Several boards of same wallet expire in the same eligible claim batch; repeat with different expiry batches. | source only / **unproven**; [GROUP](#group), [UNIT](#unit) | S03 source and stub tests require one output/fee across two ready same-expiry roots. Neither real grouped payout nor different-expiry repeat has executed in the new Signet cohort. |
| H07 | Send arkoor to an online recipient. | public signet / **complete**; [SIG](#sig) | Online native sends reconcile recipient value, sender change, signatures and backing; load12 completed 60/60. Measured bounded ordinary workload, not maximum throughput or future fallback coverage. |
| H08 | Pay absent recipient at advertised child 25 and child 50 without its database. | needs adaptation / **needs_adaptation**; [FLOW](#flow), [SOURCE](#source) | Native250-key scan evidence is related to high-index attribution. Hints were removed; offline child 25/50 ownership must be retested with mailbox verification/full xpub fallback. |
| H09 | Receive at all eight previously advertised addresses while permanently offline, then return only after direct payouts. | not run / **unproven**; none | No eight-advertised-address offline receive campaign executed. All receipts, rightful payouts and stale original-wallet adoption remain. |
| H10 | Spend only part of a coin through arkoor. | public signet / **partial**; [SIG](#sig) | Real partial spends preserve recipient and sender change amounts/signatures. Future fallback payouts of both resulting entitlements have not been demonstrated. |
| H11 | Forward received value across three owners. | source only / **unproven**; [SOURCE](#source) | Ownership/lineage source exists. No captured three-owner forwarding chain and final expiry settlement. |
| H12 | Many payments to one reused recipient address under one ancestor and across ancestors. | public signet / **partial**; [SIG](#sig) | Load12 reuses captured native receive addresses for repeated payments. No fallback fee/grouping settlement across the requested ancestor geometries. |
| H13 | Accept an arkoor, disconnect before local sync finishes, then reconnect. | not run / **unproven**; none | Controller restart is not recipient disconnect during synchronization. Inject the actual delivery/sync interruption and reconcile wallet/server state. |
| H14 | Lose the response to a money-moving request. | native regtest / **partial**; [K3](#k3) | An accepted forfeit with a held/lost reply retained signed replacements durably. No general lost-send-response campaign proving driver reconciliation before retry across money APIs. |
| H15 | Disconnect the sender before signed transfer delivery/posting. | source only / **unproven**; [SOURCE](#source) | Chosen C4 input-owner handling is implemented in source. No fresh captured sender-disconnect-before-delivery race covering both registration outcomes. |
| H16 | Deliver/register that transfer before the expiry settlement commits. | source only / **unproven**; [SOURCE](#source) | Registered recipient ownership is represented in the resolver. No captured recipient-registration versus actual allocation-commit race. |
| H17 | Perform an ordinary interactive refresh. | public signet / **partial**; [SIG](#sig), [K3](#k3) | Active control genuinely refreshed and preserved signed backed value. Temporary round capital lock is not fully measured for the whole original behavior. |
| H18 | Keep refreshing for several lifetimes. | public signet / **partial**; [SIG](#sig) | The short-profile control refreshed across successive expiry boundaries; fees are recorded. Complete old/new backing-overlap and reusable-principal cost accounting is missing. |
| H19 | Refresh close to the real eligibility boundary. | native regtest / **partial**; [K3](#k3), [W2](#w2) | Early protective refresh, actual late exit and typed decision refusals are exercised. No complete native refresh-versus-payout-decision boundary race with both winners. |
| H20 | Delegate then disappear after server acceptance, before client completion. Test both original/new expiry orders. | native regtest / **partial**; [K3](#k3) | Pre-forfeit cancellation and lost accepted-forfeit checkpoint cases execute. Not delegated refresh in both original/new expiry orders with full final settlement. |
| H21 | Schedule delegated refresh for later height, then permanent silence. | source only / **unproven**; [SOURCE](#source) | Delegated scheduling and expiry paths exist in source. No future-height scheduled delegation with permanent silence and complete payout. |
| H22 | Disappear after tree creation before forfeits/unlock; include live accepted-but-unfinished exchange states. | native regtest / **partial**; [K3](#k3), [W2](#w2) | Actual unfinished pre-forfeit state and signed-forfeit retention are exercised. All accepted/tree/forfeit/unlock windows and bounded final old/new economic discharge are not proven. |
| H23 | Go offline for less than a lifetime and return. | not run / **unproven**; none | No fresh captured short-absence-and-return campaign is established. Prove normal sync/refresh after that absence and no phantom on-chain payment. |
| H24 | Return after expiry but before authorized allocation commit; repeat after allocation before broadcast. | native regtest / **partial**; [K3](#k3), [W2](#w2) | Decision-aware protection/refusal and genuinely unfunded payout retention execute. Both actual return windows around allocation commit and broadcast remain incomplete. |
| H25 | Return after direct payout confirmation and use immutable index 0 again in later expiry epoch. | native regtest / **partial**; [EXT](#ext), [K3](#k3) | Confirmed payout adoption/history and new-database recovery are exercised. No later expiry epoch reusing the original immutable payout destination in the same run. |
| H26 | Recover an absent paid owner using the mnemonic alone. | public signet / **partial**; [SIG](#sig), [EXT](#ext) | Actual original-seed/new-database discovery and confirmed payout spend succeeded. Forced gap20 and no Ark-state/server hints are not proven; Ark was online. |
| H27 | Same seed on two devices; simultaneous initialization and restored older client backup. | native regtest / **partial**; [REG](#reg) | Sequential same-seed second device and cached reopen preserve the exact record. Concurrent initialization and restoration of an older client backup remain unproven. |
| H28 | Restart a wallet before the reserved fallback address receives anything. | native regtest / **partial**; [REG](#reg), [UNIT](#unit) | Native reopen preserves reserved coin-key indices; BIP84 reservation units exist. The complete ordinary on-chain receive reservation behavior across restart is not separately qualified. |
| H29 | Two expiry payout epochs to same immutable index 0, followed by mnemonic-only restore and rejected rotation attempt. | unit only / **partial**; [UNIT](#unit), [REG](#reg) | Immutable record/signature binding and reservation logic have unit evidence. Two real payout epochs, mnemonic restore and refused rotation in one lifecycle remain. |
| H30 | Several individually tiny leaves form payable group; include lowest-ID leaf<1000. | unit only / **partial**; [ALLOC](#alloc) | Allocator tests cover conserving grouped values and deductions. No native tiny-leaf expiry group including lowest-ID leaf below 1,000. |
| H31 | Same gross around1000+script-dust−1, =, +1 for all supported script types. | unit only / **partial**; [ALLOC](#alloc) | Script-sensitive allocation/dust rules have focused unit evidence. All supported script types at each -1/equal/+1 boundary need actual full settlement traces. |
| H32 | Add genuine later receipt after prior small entitlement was forfeited; then expire. | not run / **unproven**; none | No fresh later-receipt-after-forfeiture lifecycle is established. Prove the old sub-dust disposition never revives and the new receipt pays its own fee. |
| H33 | Offboard voluntarily while online. | source only / **unproven**; [OPSRC](#opsrc) | Real offboard/decision race tests are written and typechecked only at this checkpoint. No completed captured voluntary offboard plus absence of predecessor fallback. |
| H34 | Unilateral exit own coin; repeat partial branch exit leaving sibling fallback allocations. | native regtest / **partial**; [CONFLICT](#conflict), [K3](#k3) | Real terminal user claim, watchman restart and unaffected sibling payout execute. Full unilateral/cooperative variants and conflict-reorg variant remain unproven. |
| H35 | Pay a controlled external LN invoice successfully, then disappear. | native regtest / **partial**; [LIGHT](#light) | Actual successful external source cannot receive an extra customer payout/refund. No full disappear-with-change recovery lifecycle for this original ID. |
| H36 | Have an external LN send fail terminally, then disappear before revocation. | native regtest / **complete**; [OLDLIGHT](#oldlight) | Actual failed external send, no client revocation, automatic 99k refund with six confirmations. Pinned earlier fresh native snapshot; not public Signet and not a full rerun on every later candidate. |
| H37 | Receive an external LN payment and finish the claim normally. | native regtest / **partial**; [LIGHT](#light) | Real receive-grant/refusal regressions execute. Normal completed external receive and full channel/on-chain capital reconciliation are not demonstrated. |
| H38 | Reveal valid preimage, disappear before subscription settled or claim response delivered. | source only / **unproven**; [SOURCE](#source) | Receive preimage/claim paths exist. No actual valid-preimage interruption before subscription/claim delivery with completed rightful recovery. |
| H39 | Prepare receive without revealing preimage; external timeout and internal same-ancestor sender/receiver. | native regtest / **partial**; [LIGHT](#light), [MIX](#mix) | Granted receive timing/refusal and unresolved sibling behavior have native evidence. External timeout plus internal same-ancestor sender/receiver final refund are not fully covered. |
| H40 | Internal LN complete; recipient disappears before preimage; repeat sender and receiver under same ancestor. | native regtest / **partial**; [LIGHT](#light), [MIX](#mix) | Intra-Ark receive commitment/refusal and a waiting HTLC sibling are exercised. Both same-ancestor final monetary outcomes and bounded honest-sender release remain incomplete. |
| D01 | Register another wallet's fallback using the attacker's signature. | unit only / **partial**; [UNIT](#unit) | Record field/role/signature binding rejects incorrect authorization in units. No fresh raw adversarial RPC trace proving victim database record unchanged. |
| D02 | Alter the script in a signed fallback record. | unit only / **partial**; [UNIT](#unit) | Every serialized record byte is mutation-tested against verification. Raw server request plus immutable stored-record assertion is not a live scenario result. |
| D03 | Change signed account xpub bytes while keeping address/mailbox and signatures. | unit only / **partial**; [UNIT](#unit) | Account xpub field bytes are cryptographically bound in units. No raw changed-xpub request with database/attribution side-effect assertions. |
| D04 | Replay a correctly signed record bound to another genesis hash. | unit only / **partial**; [UNIT](#unit) | Cross-network record verification rejects the alternate network/genesis context. No raw cross-chain record replay against the deployed candidate. |
| D05 | Replay identical valid initialization; replay it after conflicting initialization attempt. | native regtest / **partial**; [REG](#reg) | Native canonical registration and sequential conflict/idempotence behavior execute. The exact identical replay after conflicting initialization sequence is not fully captured as this ID. |
| D06 | Concurrent correctly signed same-mailbox initializations with different account/address fields. | source only / **unproven**; [SOURCE](#source), [REG](#reg) | Registry locking and sequential immutable conflict behavior exist. No concurrent same-mailbox distinct-account/address initialization race. |
| D07 | Valid registration plus invalid account proof/hint in composite creation request. | needs adaptation / **needs_adaptation**; [SOURCE](#source) | Authenticated registration remains relevant. Composite account-proof/hint creation API was removed; specify the new atomic authorization risk. |
| D08 | Claim victim public key derives from attacker account using fabricated child index. | needs adaptation / **needs_adaptation**; [SOURCE](#source) | Exact policy-key derivation is required in attribution. Fabricated caller child-index hints are not accepted by this design; retest hostile mailbox/xpub attribution instead. |
| D09 | Replace mailbox identity in otherwise valid account/address binding. | unit only / **partial**; [UNIT](#unit) | Mailbox identity and signing role are cryptographically bound. No raw scoped-read-grant substitution with stored-row side-effect assertions. |
| D10 | Use valid account child hint for a different coin policy key; include x-only parity substitution. | needs adaptation / **needs_adaptation**; [SOURCE](#source), [UNIT](#unit) | Compressed policy-key equality remains relevant. Hint fields were removed; parity and wrong-policy checks need a new current-interface scenario. |
| D11 | Reassign known key to another mailbox/account, including concurrent creation. | needs adaptation / **needs_adaptation**; [REG](#reg), [SOURCE](#source) | Account uniqueness/immutable registration has native evidence. No mutable per-key link table exists; adapt concurrency and unauthorized account-rebinding expectations. |
| D12 | Request board creation without a link/record. | needs adaptation / **needs_adaptation**; [SOURCE](#source) | Native client registration precedes ordinary board use. Mandatory server link/record refusal is an old expectation; specify original unknown-owner board treatment. |
| D13 | Request a round output without a link/record. | needs adaptation / **needs_adaptation**; [SOURCE](#source) | New architecture uses xpub attribution, not mandatory per-key links. Old no-record round-output refusal is not the selected contract; retain rightful-owner/no-gift risk. |
| D14 | Request arkoor creation without a link/record. | needs adaptation / **needs_adaptation**; [SOURCE](#source) | C4 can preserve the source owner for an unregistered recipient. Old mandatory no-record arkoor refusal must be replaced with exact selected ownership rules. |
| D15 | Request a Lightning receive output without a link/record. | needs adaptation / **needs_adaptation**; [SOURCE](#source) | Receive grants use actual mailbox/registration and obligation evidence. Do not inherit the old unconditional no-link creation-refusal expectation. |
| D16 | Request a Lightning-send/change output without a link/record. | needs adaptation / **needs_adaptation**; [SOURCE](#source) | Send/change attribution uses the selected current rules. Old mandatory per-key link refusal must be respecified for the actual output path. |
| D17 | Race two arkoor spends of the same input to different owned recipients. | source only / **unproven**; [SOURCE](#source) | Shared spend/decision writer fences exist. No captured two-recipient same-input arkoor race on the fresh candidate. |
| D18 | Race arkoor against interactive refresh of the same input. | source only / **unproven**; [SOURCE](#source), [W2](#w2) | Shared writer fencing and typed refusals exist. No complete actual arkoor-versus-refresh race and losing-entitlement payout proof. |
| D19 | Race offboard against refresh of the same input. | source only / **unproven**; [OPSRC](#opsrc) | Offboard decision-race source is typechecked, not run at this checkpoint. Actual offboard-versus-refresh race is a different additional case. |
| D20 | Race unilateral exit against cooperative spending. | native regtest / **partial**; [CONFLICT](#conflict), [K3](#k3) | Real user exit and actual fallback conflict/regroup have monetary evidence. Not all direct cooperative-spend versus unilateral-exit race variants. |
| D21 | Replay spend after frozen allocation, after broadcast, and after confirmed claim on restored stale DB. | native regtest / **partial**; [W2](#w2), [K3](#k3) | Typed full/bare decision refusals and actual client protection execute. All post-decision/broadcast/confirmed stale-database replay admission sites remain unproven; use decision boundary wording. |
| D22 | Replay a delivered chain/mailbox message. | not run / **unproven**; none | No captured duplicate delivered-chain/mailbox-message replay is established. Assert no second wallet credit, liability and eventual payout. |
| D23 | Submit an altered/incomplete signed transfer chain for registration. | unit only / **partial**; [SIMUNIT](#simunit), [UNIT](#unit) | Native verifier unit negatives reject altered signatures/unrelated funding and malformed records. Not a full raw server registration request with immutable payee/side-effect assertions. |
| D24 | Deliver unregistered signed recipient transfer after input-owner allocation or direct claim confirms. | source only / **unproven**; [SOURCE](#source) | Durable source-owner decisions and registration fences exist. No late actual signed-recipient delivery after source-owner allocation or confirmed claim. |
| D25 | Combine independent input-owner chains and try to attribute all outputs to one owner. | source only / **unproven**; [SOURCE](#source) | Ownership resolver tracks actual lineage and conserving backing. No malicious combined multi-input-owner native request with rightful terminal outcomes. |
| D26 | Race two delegated refresh requests on identical inputs. | source only / **unproven**; [SOURCE](#source) | Native action/decision serialization is implemented. No actual concurrent delegated refresh requests on identical inputs. |
| D27 | Late delegated forfeit/completion after cancellation or original owner settlement. | native regtest / **partial**; [K3](#k3), [W2](#w2) | Real pre-forfeit cancellation/late-forfeit checkpoint and status refusal cases execute. Late delegated completion after cancellation or original settlement is not fully discharged. |
| D28 | Present another branch claim, registered-script lookalike outputs, or unrelated backing as this entitlement carrier. | unit only / **partial**; [SIMUNIT](#simunit) | Independent payout verifier has wrong-payee/value/backing negatives in controller tests. No complete raw branch/lookalike/unrelated-backing hostile native campaign. |
| D29 | Request a refund for a successful Lightning send. | native regtest / **partial**; [LIGHT](#light) | Actual paid-source refund is refused, including coarse-status regression. The exact lost-success-response/preimage client scenario is not separately injected and fully captured. |
| D30 | Pending/unknown Lightning status, silent node, or temporarily ineligible refund later terminal failure. | native regtest / **partial**; [LIGHT](#light), [OLDLIGHT](#oldlight) | Real terminal failures, source-specific receipts and behind-watchman refusal are exercised. Silent-node/ambiguous transport and all temporarily ineligible-to-terminal transitions remain incomplete. |
| D31 | Replay a completed receive claim. | not run / **unproven**; none | No captured completed receive-claim replay is established. Assert no second credit or fallback payment after a genuine completed receive. |
| D32 | Submit a wrong preimage for a prepared receive. | not run / **unproven**; none | No captured wrong-preimage receive request is established. Exercise the actual current server request and preserve rightful later resolution. |
| D33 | Late valid receive claim after sender refund allocated/broadcast/confirmed. | source only / **unproven**; [SOURCE](#source) | Receive/refund decision and retained-secret rules exist. No full late valid claim after allocated/broadcast/confirmed sender refund. |
| D34 | Race sender refund with receiver preimage/subscription commit, both orders. | source only / **unproven**; [SOURCE](#source) | Atomic source/receive state transitions are implemented. Both actual refund-versus-preimage/subscription commit race winners remain unproven. |
| D35 | Request an excessive or invalid block-height expiry on a legitimately collected receive. | native regtest / **partial**; [W2](#w2), [LIGHT](#light) | Actual excessive HTLC-send duration is refused without spending the input. That does not prove the original legitimately collected receive's excessive-expiry path. |
| D36 | Malicious prepared receive never completes while honest sender and unrelated sibling share backing. | native regtest / **partial**; [MIX](#mix), [LIGHT](#light) | A real ordinary sibling pays while a grant-only HTLC sibling waits, then later refunds. Not the complete malicious prepared-receive plus honest-sender same-backing scenario. |
| D37 | 101+ and >10,000 tiny coins to absent owner; 253+ distinct recipients and wallet fragmentation; repeated failed batch construction. | native regtest / **partial**; [MIX](#mix), [SIG](#sig) | Small genuine mixed-tree progress and bounded 12-wallet traffic execute. No 101+/10000-tiny-coin and253-recipient/fragmentation repeated-build capacity campaign; registration count is not coin count. |
| D38 | Abandon successive delegated rounds at acceptance/tree/forfeit/unlock boundaries. | native regtest / **partial**; [K3](#k3), [W2](#w2) | Actual pre-forfeit cancellation and accepted lost-forfeit reply preserve state. Successive delegated rounds at every boundary with measured lock/dependency costs remain. |
| D39 | Bounded repeated authenticated/unauthenticated derivation requests; high-index hints and account-registration amplification. | failed / **failed**; [SCALE](#scale) | Authenticated 100/1,000-account cases passed; 10,000 missing-mailbox positive search missed the 120-second budget. Wrong-mailbox 10,000 was not run; hints are obsolete; no production bound/capacity claim. |
| D40 | Malformed/truncated oversized hint/record, integer overflow, unsupported child encoding; supplemental fee input conflict and stale carrier callback variants. | needs adaptation / **needs_adaptation**; [UNIT](#unit), [FEE](#fee) | Malformed record units and genuine fee-child replacement have separate evidence. Hints/legacy carriers are removed; overflow, current fee-input conflict and stale callback/orphan cases need adaptation and actual runs. |

## Evidence references

### SIG

- reference: [reference](signet-results-20261017.md).
- controller commit: `9f57c79be0e42028e951a1bb21f4208da3ce78bb`.
- product commit: `7055d1fce858f3112aff671d0b2a8a454d6a2214`.

### REG

- source: [reference](https://github.com/BullishNode/abandon-ship-bark/blob/cf32afccb8582e915c39cc20b6d830f1d5aecc5a/testing/tests/bark_sdk/fallback.rs).
- run id: `88496753-505d-438d-8c31-1cd6008b0556`.
- result: 4/4 PASS.
- product commit: `cf32afccb8582e915c39cc20b6d830f1d5aecc5a`.
- limits: Sequential second-device/reopen and immutable registration, not concurrent devices/older backup.

### K3

- source: [reference](https://github.com/BullishNode/abandon-ship-bark/blob/626dcc28dc0250df38f73cc7594b35b179a0de74/testing/tests/bark_sdk/fallback_act_by.rs).
- run id: `00f209ef-79b0-4985-b23f-f5d2826d7c2f`.
- result: 5/5 PASS in 70.483 s.
- source manifest sha256: `59a19dbf25ae1a76e81b98fcbdcfe100cb191549b29456daa6ad0f5b1275edb6`.
- client commit: `626dcc28dc0250df38f73cc7594b35b179a0de74`.
- limits: Public protection methods called directly; no autonomous default-daemon end-to-end credit.

### UNIT

- source: [reference](https://github.com/BullishNode/abandon-ship-bark/blob/626dcc28dc0250df38f73cc7594b35b179a0de74/lib/src/fallback.rs).
- run id: `de10affd-1f6d-4a91-845f-96c51e4864f0`.
- result: 785 PASS/1skip reported in client handoff.
- limits: Record byte/network/role/signature/decoder tests; not raw hostile endpoint scenarios.

### ALLOC

- source: [reference](https://github.com/BullishNode/abandon-ship-bark/blob/568b30d0c84216111f5344e6fc729ccc2ff4d052/docs/fallback-implementation-evidence.md).
- run id: `e48fbe5a-49d3-486f-b497-f93e528c4096`.
- result: 24 focused units PASS.
- limits: Conservation, geometry, allocation, dust, remainder/subsidy; not whole native boundary matrix.

### FLOW

- source: [reference](https://github.com/BullishNode/abandon-ship-bark/blob/568b30d0c84216111f5344e6fc729ccc2ff4d052/docs/fallback-implementation-evidence.md).
- run id: `27d5e036-045e-497a-a376-9692d569d50a`.
- result: 1 PASS in 32.313 s.
- limits: Actual 250-wallet-key, chunk 1 generic ordinary fallback/seed recovery; not offline child 25/50 or huge registry scale.

### EXT

- source: [reference](https://github.com/BullishNode/abandon-ship-bark/blob/7055d1fce858f3112aff671d0b2a8a454d6a2214/testing/tests/bark_sdk/fallback_external.rs).
- run id: `8f297156-7884-47da-8a19-640730082b72`.
- result: 1 PASS in 24.186 s.
- limits: Distinct app/Ark seeds, new DBs, actual payout and confirmed BIP84 spend. Ark online; no forced gap20/no-hint claim.

### W2

- source: [reference](https://github.com/BullishNode/abandon-ship-bark/blob/568b30d0c84216111f5344e6fc729ccc2ff4d052/docs/fallback-implementation-evidence.md).
- run id: `b45cad52-44a3-4cf3-829b-09e4d68198e0`.
- result: 3 PASS in 25.053 s.
- limits: Generation/restart, typed full/bare RPC refusals using isolated inserted fence, unattempted HTLC deadline; not complete actual payout-operation races.

### MIX

- source: [reference](https://github.com/BullishNode/abandon-ship-bark/blob/7055d1fce858f3112aff671d0b2a8a454d6a2214/testing/tests/server/expiry_split.rs).
- run id: `9d9ee14a-71c4-41da-a18e-32c6189dc6a6`.
- result: 1 PASS in 42.928 s.
- limits: Explicit first split, genuine ordinary 49,000 and later HTLC 49,000 confirmed payouts. Not automatic oversized capacity or actual malicious receive.

### LIGHT

- source: [reference](https://github.com/BullishNode/abandon-ship-bark/blob/8127251798752570948b1808d91e01ce0aa8c88f/docs/fallback-lightning-evidence.md).
- run id: `d3025d92-06ad-44b3-8649-4a0848d3452e`.
- result: 5/5 PASS in 99.128 s.
- source manifest sha256: `f41c7d958e3f4acfddf9cf629bbb84f0f4e79b1f6e42a22b27936129b461ce1c`.
- published code: `8127251798752570948b1808d91e01ce0aa8c88f`.
- limits: Specific real source/hash refund/refusal cases, not all Lightning composites or ambiguous transport closure.

### OLDLIGHT

- source: [reference](https://github.com/BullishNode/abandon-ship-bark/blob/8127251798752570948b1808d91e01ce0aa8c88f/docs/fallback-lightning-evidence.md).
- run id: `d4286ba5-946c-4877-8401-3194cb3cd67c`.
- result: 6 PASS;2 other tests FAILED on refusal wording in this run.
- source manifest sha256: `d27d35dd169a3d8fd44109fdd1e657f8ca8ee87456667c56a0c20bcebf852e02`.
- limits: Passing named failed/no-part offline-refund subtests retain credit only on their pinned earlier fresh snapshot; no 8/8 claim or inferred rerun.

### CONFLICT

- source: [reference](https://github.com/BullishNode/abandon-ship-bark/blob/42e33146432f8413bb9d11e498d2de1811b53473/testing/tests/server/expiry_conflict.rs).
- run id: `93fd48ad-2b19-47e5-98fd-d88fc9dcd337`.
- result: 1/1 PASS in 24.140 s.
- evidence manifest sha256: `7cc997fbe6a659cd1401f66ad233fd4008c4710630a14ac254482860f69d443f`.
- published source: `42e33146432f8413bb9d11e498d2de1811b53473`.
- limits: Real partial user terminal claim, restart/regroup, untouched 99,000-sat six-confirmation payout. No conflict-reorg variant.

### FEE

- source: [reference](https://github.com/BullishNode/abandon-ship-bark/blob/2ecc7b23967975f04f870c12dca21a9cf2923393/testing/tests/server/expiry_reorg.rs).
- run id: `48226daf-0b2d-470b-b354-ca309b8f7de9`.
- result: 1 PASS in 18.816 s.
- limits: Actual Core child RBF, unchanged parent/payees and confirmed-only cost. Not every fee-input/conflict/stale callback variant.

### SCALE

- source: [reference](https://github.com/BullishNode/abandon-ship-bark/blob/f1d1947ef322233ae013174dd4610ced96d0de08/docs/fallback-registration-scale.md).
- public report: [reference](https://github.com/BullishNode/abandon-ship-bark/blob/f1d1947ef322233ae013174dd4610ced96d0de08/docs/evidence/registration-scale-first-20261017.json).
- run id: `a8928dcf-a33a-400b-a37e-8306b6e5b4f0`.
- result: FAIL in 250.494 s: 10,000 no-mailbox positive search exceeded 120 s; 100/1,000 positive cases passed; 10,000 wrong-mailbox NOT RUN.
- limits: Account registrations/attribution, not 10,000 payout coins; debug shared-host result, not production capacity.

### SOURCE

- source: [reference](https://github.com/BullishNode/abandon-ship-bark/blob/8127251798752570948b1808d91e01ce0aa8c88f/docs/fallback-implementation-evidence.md).
- policy source: [reference](https://github.com/BullishNode/abandon-ship-bark/blob/8127251798752570948b1808d91e01ce0aa8c88f/server/src/database/expiry_ownership.rs).
- limits: Source is not an execution result; no old A/B/C campaign credit inherited.

### OPSRC

- limits: New actual offboard both-winner and post-backing-expiry revoke tests are written/typechecked, not passed.

### GROUP

- reference: [reference](signet-grouping.md).
- controller commit: `c669367aef254ed2ba9ebf396a44a5bc01951d2e`.
- limits: S03 controller 7 stub tests and 81 focused totalPASS, no live S03 actor initialized at snapshot.

### SIMUNIT

- reference: [reference](../tests/test_signet_s02.py).
- controller commit: `c669367aef254ed2ba9ebf396a44a5bc01951d2e`.
- limits: 81 Python controller tests, including negative chain/payee checks; never 80 live behavior cases.

## Interpretation and next work

H26 is deliberately partial: the actual seed restore and confirmed payout spend succeeded, but neither forced gap20 nor recovery independent of Ark-state/server hints was established. H27 sequential second-device restoration does not prove concurrent devices or an older backup. H34 has genuine partial-exit/regroup proof but no conflict-reorg variant. H36 is native regtest evidence, not public-Signet Lightning qualification.

Current Signet 50-wallet work waits for actual native admission before its 200-transfer window; it is not another completed 80-ID behavior. Passive S03 preparation remains behind that complete timed window and final audit. Real grouped payouts, applicable settlement/interruption/scale cases and strict Noah offline LNURL remain separate execution work. No new readiness gate or framework is introduced by this inventory.

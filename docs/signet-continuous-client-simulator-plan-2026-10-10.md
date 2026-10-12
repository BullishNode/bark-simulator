# Continuous Bark client simulator and operator capital report

2026-10-10. **Plan only: nothing implemented, deployed, funded, or changed on LunaNode.**

Build a small external test program against the **existing expiry-fallback captaind on signet on LunaNode**. Run twelve independent Bark wallets continuously, rotate through **40 honest and 40 adversarial behaviors**, and produce an operator report answering:

> When clients connect, deposit, refresh, transfer, use Lightning, disappear, and return, what capital does captaind need, where is it tied up, how much do fees consume, and do users get the right funds?

Recommend a **28-day first campaign**, followed by a drain period determined by actual coin/HTLC expiries. Keep it running afterwards in renewable, budgeted epochs. Separate ordinary operating profiles from scheduled adversarial exercises so an operator can distinguish normal capital demand from abuse. Every epoch declares its opening capital and fee budget; there are no hidden top-ups.

Twelve clients provide a useful operating rehearsal and longitudinal evidence. They do **not** demonstrate capacity for thousands of simultaneous clients. Reports for 100/1,000/10,000 users are explicitly modeled projections, informed by the separate scale qualification, never described as signet measurements.

## 1. Scope, target, and evidence

The target is the **fork's fallback stack**, not the old sidecar stack. The stage-2 VM helper identifies `~/abandon-signet-fallback/deploy`, project `abandon-signet-fallback`, and services prefixed `fb-` ([vmlib.py](/home/francis/bark-integration-2026-10-01/signet-stage2-evidence-2026-10-10/vmlib.py)). The older 2026-10-07 guides are useful background but contain superseded images, sidecar accounting, and routing. Do not copy their funding/recycling commands into this program.

Planning source snapshot: Bark branch `expiry-fallback` at **`592fb8cbbba3753eed0dc6d3f5c4a00806bcf1e0`**, read through explicit-revision Git commands. This is a source reference, not a claim about the VM's deployed image. Other coding agents are still working. At deployment, pin the actual approved server/client/watchman image digests and code hashes in the campaign manifest.

Current documents disagree on the rendered minimum: the updated [goal](/home/francis/bark-integration-2026-10-01/fallback-completion-goal-2026-10-09.md) records an owner-approved **1,000 sat** minimum, while the local deployment env still explicitly sets **10,000 sat**. The local fallback env sets lifetime **24 blocks**, grace **6**, sweep depth **6**, board confirmations **2**, rounds **30 seconds**. These are inspected configuration files, not live VM measurements. Preflight must read the running configuration and server information. A default in source must never substitute for the deployed value.

On signet, schedule against observed chain heights and protocol states. Never mine blocks, change the clock, invalidate blocks, manipulate node mempool policy, or assume a deadline is met because six hours elapsed. With a 24-block lifetime, an ordinary expiry journey is on the order of several hours, but grace, sweep timing/depth, and payout confirmation can overlap; calculate each entitlement's actual conditions rather than adding constants as a universal deadline.

Source facts affecting this plan, at the snapshot above:

| Mechanism | Verified basis | Implication for the simulator |
|---|---|---|
| Six payout sources | `server/src/database/expiry_settlement.rs:68–102`, plus delegated predecessor handling at `:120` | Track registered coins, pending boards, unregistered outputs, LN receives, LN-send refunds, and unclaimed hArk outputs separately. |
| Unregistered output payee | Same file `:131–155` | An unregistered output belongs to its actual input owner until registration/posting changes the entitlement. The oracle must not assume the destination of an undelivered transfer already owns it. |
| Confirmed payout funding | `server/src/expiry_payout.rs:178–189` | Trusted/unconfirmed wallet balance is not all immediately usable payout liquidity. |
| Payout fee split and guaranteed change | Same file `:193–218` | Recipients pay the recipient share; operator change pays its own output weight. Extra change liquidity is required even when gross payout backing is present. |
| Durable settlement | Same file `:232–260` | Reconcile raw payout transactions, paid scripts, coin retirement, and nursery records; do not depend on removed receipt files. |
| Repeated fee value in settlement rows | `server/src/database/expiry_settlement.rs:243–245` | `fee_sat` is a transaction-level recipient-fee total repeated across settled inputs. **Do not sum it per coin.** Deduplicate by payout transaction and derive wallet shares independently. |
| Wallet status | `server/src/rpcserver/admin.rs:26–36`; `server-rpc/protos/bark_server.proto:679–690` | Rounds status exposes balances and confirmed/unconfirmed outpoints; watchman is absent from this captaind reply. Collect watchman through a separately verified read interface, or label its liquidity unknown. |

Use the [updated goal](/home/francis/bark-integration-2026-10-01/fallback-completion-goal-2026-10-09.md) as the policy source. The [independent review](/home/francis/bark-integration-2026-10-01/review-stage2-independent-2026-10-10.md) is historical: several findings have since been fixed or turned into explicit operator rules. The simulator must test the final behavior, not reintroduce old assumptions about separate record keys or legacy sweep recovery.

## 2. Program structure: reuse clients, change no server code

Keep the program **outside the Bark fork**, next to the other integration tooling. It does not add a settlement engine, a service to captaind, or another source of payout authority.

Use two small pieces:

1. **Python supervisor**, using `asyncio`, SQLite, JSONL, and TOML configuration. Owns scheduling, persistent scenario state, budgets, read-only observation, reconciliation, and report generation. No Redis, Kubernetes, message broker, or new metrics stack is needed.
2. **Rust client driver**, built against the pinned fork's existing `bark`, `ark`, and `server-rpc` libraries. Runs a real Bark wallet and exposes typed actions to the supervisor over a private local socket. Normal actions call existing SDK methods. A restricted adversarial module constructs raw RPC requests or pauses at protocol stages that the normal wallet completes automatically.

The Rust helper is needed because ordinary CLI commands cannot express “prepare this receive, then disappear before claiming” or “submit this incorrectly signed link.” Reuse the existing test request construction and cryptography; do not reimplement Bitcoin signing in Python. The existing integration tests supply examples, but their `TestContext` launches regtest daemons and must not be pointed blindly at the VM.

Proposed external repository layout:

```text
abandon-ship-simulator/
  supervisor/            # scheduler, observations, ledger, reports
  driver/                # existing SDK + restricted raw-RPC scenarios
  scenarios.toml         # H01–H40, D01–D40 and their prerequisites
  profiles/              # ordinary, refresh-heavy, Lightning, abandonment
  sql/                   # bounded SELECTs for each supported server schema
  deploy/                # simulator-only container/unit and resource limits
  tests/                 # scheduler/ledger fixtures and small regtest smoke tests
  README.md
```

On the VM use a new simulator-owned directory, for example `~/abandon-ship-simulator/`, and its own service/container project. Attach only the necessary private network interfaces to the existing stack. No public simulator API is needed. Serve the generated HTML report through an SSH tunnel if desired.

**One wallet directory per actor, one writer per directory.** Twelve wallet identities exist; a subset of drivers runs at any moment. Online drivers perform explicit maintenance according to the actor's behavior. Offline drivers are stopped, have no maintenance task or outgoing request, and remain stopped until their scenario explicitly allows a return.

The observer watches the chain and server independently while an actor is absent. It must not sync, refresh, claim, or sweep on behalf of that actor. A later isolated seed-only BIP84 restore proves the payout was recoverable; it does not count as client activity before payment.

Use a seed-only restore helper with the standard signet BIP84 external/change descriptors and stop gap 20, no original Ark DB, address index, or payout txid as a scanning hint. Compare its findings to the oracle only **after** scanning. Construct a spend from recovered funds; batch confirmation of such proof spends when possible to limit fees. Restore verification/recycling must not race a live writer of the same wallet.

## 3. Twelve actors and workload profiles

These are starting assignments, not twelve different software implementations:

| Actor | Typical behavior |
|---|---|
| 01 daily wallet | Board, occasional transfer, ordinary maintenance. |
| 02 spender | Frequent small arkoor payments. |
| 03 merchant | Receives from several actors, consolidates/refreshes. |
| 04 saver | Holds most value, infrequent connection. |
| 05 Lightning sender | Pays external controlled-peer invoices. |
| 06 Lightning recipient | Receives from the controlled peer. |
| 07 intermittent phone | Disconnects/reconnects at inconvenient stages. |
| 08 delegated wallet | Scheduled/delegated refresh and hArk completion. |
| 09 absent wallet A | Goes silent through expiry and payout. |
| 10 absent wallet B | Receives while silent or disappears during Lightning. |
| 11 adversarial client A | Raw invalid/replayed requests, bounded races. |
| 12 adversarial client B | Conflicting spends and liquidity/resource abuse. |

Honest/adversarial roles can rotate between **new scenario cohorts**, preserving ownership and accounting. Do not switch an actor's role while it has unresolved value. Maintain at least four ordinary active actors as a progress control during abuse exercises. Same-seed/device cases use one owner with a second isolated driver instance, not an extra funded owner.

Two optional **simulator-owned CLN signet peers** supply external payer/payee behavior and a small controlled channel topology. Reuse an existing dedicated fixture peer if one is available. Internal Ark-to-Ark Lightning is tested separately; it must not be used as evidence that external channel liquidity works. Channel establishment, inbound provision, fees and peer capital are declared setup costs. Never settle captaind's hold invoices through an external admin call; that violates the approved operating rule.

All numerical workload settings below are **proposed initial settings, not measurements**:

| Profile | Workload | Operator question |
|---|---|---|
| Ordinary | 8–10 online actors; 20 successful money-moving actions/hour across the cohort; at most 3 simultaneous actions. About 50% arkoor, 20% external LN, 10% internal LN, 15% refresh, 5% board/offboard. Deposit opportunities may be deferred by budget. | What does routine usage cost, and what float prevents waits? |
| Refresh-heavy | Same principal and transfer rate; compare early, ordinary maintenance-triggered, and latest-safe refresh schedules derived from **actual** lifetime and client/server safety margins. Retain original backing until it really returns. | How much temporary capital does frequent refresh consume? |
| Lightning directional | Separate send-heavy, receive-heavy and balanced periods, 10 payments/hour initially, at most 2 in flight. | How much outbound/inbound liquidity is needed, and how quickly does it deplete? |
| Abandonment | Stagger 2, then 4, then 6 absent owners; later align several expiry heights within available timing. | Can sweeps finance payouts, and what extra liquidity/fees are required? |
| Bounded adversarial | Schedule D-catalog exercises alongside ordinary traffic; initially <=1 raw invalid request/second across adversaries, max 4 requests in flight and finite request bytes. | Can a cheap client impair honest service or impose a disproportionate cost? |

Request rate and money-moving rate are distinct. Scenario preparatory calls, retries and syncs are all counted, even when only the final transaction counts toward the successful-action rate. Start below these rates during calibration. The program must never fund a scenario merely to meet an actions/hour target.

Only change one principal profile dimension at a time; otherwise capital attribution is unclear. A mixed profile follows isolated profiles. Record cohort size, balances, funding age, round geometry, UTXO fragmentation and external peers for each comparison; these can matter as much as action counts.

Short signet lifetimes can make a seemingly ordinary percentage-of-lifetime schedule unsafe: for example, at age 18 of 24 blocks only six remain. Derive valid refresh windows from the actual SDK/server constraints during preflight; late-boundary refusals belong to H19, not the ordinary workload. The report must show when rehearsal timing forces unusually frequent refreshes and therefore inflates capital usage relative to a longer-lifetime deployment.

## 4. The eighty behaviors

Every scenario has a durable ID, trigger, participating owners, phase boundaries, public artifacts, expected ownership/outcome, fee budget, and a prerequisite list. Variants are intentional: each probes a distinct money or availability transition. An attempted setup that never reaches its target phase is **blocked/not exercised**, not a pass.

Driver labels: **SDK** = normal wallet calls; **Phase** = SDK/raw-RPC stage control; **Raw** = restricted crafted public requests; **Peer** = only simulator-owned external LN peer control. All can target signet without changing captaind's production code. Some need waits or extra declared funds and may not run in a small-budget epoch.

### Forty honest behaviors

| ID | Behavior | Expected result / observation | Driver |
|---|---|---|---|
| H01 | Create a wallet, register fallback, then board confirmed funds. | Board works only with the valid link/record; principal and actual fees reconcile. | SDK |
| H02 | Attempt boarding while the funding confirmation requirement is unmet, then retry. | Expected wait/refusal; one eventual funded board, no duplicate liability. | SDK |
| H03 | Board, finish registration, and never return. | Exactly one expiry payout to this owner's registered BIP84 script. | SDK |
| H04 | Broadcast a board, disappear before board registration finishes. | Pending-board source eventually pays its owner after real sweep evidence. | Phase |
| H05 | Get board cosign/proposal but never broadcast its funding transaction. | No fictitious principal, sweep or payout; no server-funded gift. | Phase |
| H06 | Create and use several boards in one wallet. | Distinct real entitlements; expiry grouping/fees reconcile. | SDK |
| H07 | Send arkoor to an online recipient. | Recipient owns transferred value; sender change remains sender's. | SDK |
| H08 | Send to a previously advertised address of a now-offline recipient. | Posted/registered recipient output pays the recipient at expiry without returning. | SDK |
| H09 | Receive several payments while offline. | All delivered entitled amounts group correctly, once. | SDK |
| H10 | Spend only part of a coin through arkoor. | Recipient and change have correct links, amounts, and future payouts. | SDK |
| H11 | Forward received value across three owners. | Final live entitlement is counted once; predecessors cannot receive it again. | SDK |
| H12 | Send several payments to the same offline wallet. | One destination group rather than a per-coin minimum test. | SDK |
| H13 | Accept an arkoor, disconnect before local sync finishes, then reconnect. | Server/local state converges without duplicate spend or balance. | Phase |
| H14 | Lose the response to a money-moving request. | Driver reconciles IDs/status before retry; actual committed action counted once. | Phase |
| H15 | Disconnect the sender before signed transfer delivery/posting. | Unregistered source follows the input-owner rule unless recipient registration wins first. | Phase |
| H16 | Deliver/register that transfer before the expiry settlement commits. | Recipient entitlement wins; sender receives only legitimate change. | Phase |
| H17 | Perform an ordinary interactive refresh. | Replacement appears once; temporary round capital lock is measured. | SDK |
| H18 | Keep refreshing for several lifetimes. | Old/new backing overlaps are measured; fees and reusable principal remain distinct. | SDK |
| H19 | Refresh close to the real eligibility boundary. | One valid refresh or one payout; stale inputs are never funded twice. | SDK |
| H20 | Start a delegated refresh and immediately go offline. | Server completes it or resolves its unclaimed source under actual protocol rules. | SDK |
| H21 | Schedule a delegated refresh for a later valid height, then disappear. | Scheduled output is linked; later expiry pays the correct wallet. | SDK |
| H22 | Drop an hArk completion/unlock step. | Unclaimed replacements/predecessors resolve once under the documented rules. | Phase |
| H23 | Go offline for less than a lifetime and return. | Sync/refresh works; no phantom on-chain payment. | SDK |
| H24 | Return after expiry but before durable payout commitment. | Valid return action and payout arbitrate; at most one resulting entitlement. | SDK |
| H25 | Return after payout confirmation. | Ark value removed, on-chain value visible, address rotation recorded. | SDK |
| H26 | Recover an absent paid owner using the mnemonic alone. | Gap-20 BIP84 scan finds and spends the real output with no Ark-state hints. | Phase |
| H27 | Reopen on a second device with the same seed. | Fallback state converges; no competing record or double entitlement. | SDK |
| H28 | Restart a wallet before the reserved fallback address receives anything. | Ordinary receives do not reuse its reservation improperly. | SDK |
| H29 | Rotate fallback after a payout, then abandon a later coin. | Committed old payout stays at its old script; later payout uses the new record. | SDK |
| H30 | Receive amounts that are individually small but jointly payable. | Grouped net threshold releases them exactly once. | SDK |
| H31 | Hold an aggregate balance below the actual net minimum. | Explicit retained obligation, unpaid age and fee sensitivity; never reported as paid. | SDK |
| H32 | Add later eligible value to that retained wallet. | It becomes payable after grouping when the actual net reaches the minimum. | SDK |
| H33 | Offboard voluntarily while online. | One on-chain entitlement; no expiry refund for offboarded predecessors. | SDK |
| H34 | Start a unilateral exit on this actor's own coin. | Exact backing path prevents an overlapping automatic payout; watchman burden measured. | SDK |
| H35 | Pay a controlled external LN invoice successfully, then disappear. | Payee paid; no sender refund of successful principal; change still recoverable. | SDK/Peer |
| H36 | Have an external LN send fail terminally, then disappear before revocation. | Failed send is automatically paid back to sender when independently eligible. | SDK/Peer |
| H37 | Receive an external LN payment and finish the claim normally. | Collected value appears once; channel/on-chain capital changes reconcile. | SDK/Peer |
| H38 | Complete the collection-enabling receive phase, then disappear before final claim delivery. | Verified collected receive gets the correct automatic payout; return drops stale claimable value. | Phase/Peer |
| H39 | Prepare a receive but never reveal/commit what permits collection. | External payment fails back or internal sender eventually gets the rightful refund; no unfunded recipient payout. | Phase/Peer |
| H40 | Pay another Bark actor through internal LN: exercise both normal completion and a disappearing recipient. | Correct internal settlement or refund; do not fabricate external channel movement. | Phase |

H38 and H39 must record the actual grant/subscription/preimage/collection states. “Killed a process during receive” is insufficient evidence that the intended case was reached.

### Forty adversarial behaviors

Here “dishonest” means the actor tries to redirect value, collect twice, bypass protocol rules, or impose cheap resource costs. Ordinary network failure is covered in honest scenarios. An actor owns its own keys; it does not receive another actor's mnemonic, mailbox private key, server keys, DB credentials or host permissions. Some valid requests are abusive without being cryptographically invalid; assess their service/capital impact separately.

| ID | Attempt | Required outcome / invariant | Driver |
|---|---|---|---|
| D01 | Register another wallet's fallback using the attacker's signature. | Refused; victim record unchanged. | Raw |
| D02 | Alter the script in a signed fallback record. | Signature verification rejects it. | Raw |
| D03 | Alter the sequence in a signed fallback record. | Signature verification rejects it. | Raw |
| D04 | Replay a correctly signed record bound to another genesis hash. | Refused; no cross-chain record replay. | Raw |
| D05 | Replay an older valid record after a newer record exists. | Stored newer record survives; no rollback. | Raw |
| D06 | Submit a different script with the same record sequence. | Deterministic stored-record rule; no unsigned/ambiguous replacement. | Raw |
| D07 | Mix a valid record with invalid links in one request. | No unauthorized record/link partial application. | Raw |
| D08 | Forge a coin-key link for a victim public key. | Refused; coin cannot be redirected. | Raw |
| D09 | Replace the mailbox in an otherwise signed key link. | Refused; signature binds the wallet identity. | Raw |
| D10 | Replay one coin key's link for another key. | Refused. | Raw |
| D11 | Relink an already linked key using another mailbox. | Immutable link survives. | Raw |
| D12 | Request board creation without a link/record. | Creation refusal; no funded uncovered coin. | Raw |
| D13 | Request a round output without a link/record. | Creation refusal. | Raw |
| D14 | Request arkoor creation without a link/record. | Creation refusal. | Raw |
| D15 | Request a Lightning receive output without a link/record. | Creation refusal before unfunded/incorrect entitlement. | Raw |
| D16 | Request a Lightning-send/change output without a link/record. | Creation refusal for the actual output path under test. | Raw |
| D17 | Race two arkoor spends of the same input to different owned recipients. | At most one accepted successor path. | Phase |
| D18 | Race arkoor against interactive refresh of the same input. | One winner; losing request cannot claim another payout. | Phase |
| D19 | Race offboard against refresh of the same input. | One paid/successor entitlement. | Phase |
| D20 | Race unilateral exit against cooperative spending. | Chain and protocol arbitration prevent two funded claims; exact path recorded. | Phase |
| D21 | Replay a spend of an expiry-settled coin. | Settled refusal; no new amount or service crash. | Raw |
| D22 | Replay a delivered chain/mailbox message. | No duplicate credit, liability, or future payout. | Raw |
| D23 | Submit an altered/incomplete signed transfer chain for registration. | Invalid proof rejected; no payee change. | Raw |
| D24 | Deliver a previously unregistered chain after its input-owner payout committed. | Delivery/registration refused as settled; no second recipient payment. | Phase |
| D25 | Combine independent input-owner chains and try to attribute all outputs to one owner. | Each actual parent controls its entitlement; attacker cannot collect another parent's amount. | Raw |
| D26 | Race two delegated refresh requests on identical inputs. | One exchange or consistent refusal, never duplicated replacements. | Phase |
| D27 | Resubmit cached forfeit/completion data after expiry cancellation. | Canceled/settled participation cannot be revived for another payment. | Phase |
| D28 | Present an unrelated branch's confirmed sweep as proof for this coin. | This coin stays unpaid until its own path satisfies the proof. | Raw/Phase |
| D29 | Request a refund for a successful Lightning send. | Refused even if a client missed its successful response/preimage. | Raw |
| D30 | Request a refund while the Lightning result is still unknown/pending. | No refund based only on silence or a client timeout. | Raw/Peer |
| D31 | Replay a completed receive claim. | No second credit/payout. | Raw |
| D32 | Submit a wrong preimage for a prepared receive. | Cannot collect or redirect value; rightful resolution remains possible. | Raw |
| D33 | Claim an internal receive after a sender refund committed. | Refused; no late recipient creation over refunded funds. | Phase |
| D34 | Revoke the sender while a valid internal recipient claim is committing. | Recipient's valid claim and refund arbitrate once. | Phase |
| D35 | Request an excessive or invalid block-height expiry on a legitimately collected receive. | Bounded refusal, no panic; no attacker-chosen far-future reclaim lock. | Raw |
| D36 | Keep a prepared internal receive unfinished to immobilize sender funds. | Refund/claim deadline resolves ownership; lock duration and capital cost measured. | Phase |
| D37 | Send many small valid coins to an absent owner (bounded fragmentation). | Grouped payment remains possible; old 101-coin blockage must not recur. | SDK |
| D38 | Repeatedly join and abandon round participation at different client stages. | Bounded lock duration, eventual valid-source resolution; ordinary actors still progress. | Phase |
| D39 | Repeated valid read/record/invoice requests with capped rate and count. | Measure amplification, row growth, RPC latency and operator costs; no loss/misdirection. | Raw |
| D40 | Malformed/truncated/oversized requests within the declared test cap. | Controlled refusal/size limit; captaind stays healthy and honest actors progress. | Raw |

Clarifications:

- D28 cannot inject a server sweep proof or DB hint through a nonexistent public API. Exercise it using actor-owned sibling branches and genuine exits/sweeps, then observe which coins the server pays. If constructing that geometry requires unsupported fixture changes, mark it blocked and retain it in the regtest qualification; never forge server state on the VM.
- D27 needs a genuinely canceled delegated participation. D35 needs a legitimately collected receive **through captaind**, not an out-of-band hold settle. D37's 101-coin case may require a larger **declared** actor budget than the ordinary pilot; do not exceed the pilot funding cap silently. A >10,000-coin oversized-wallet test belongs to separate scale qualification, not a cheap twelve-client signet campaign.
- D39 is a bounded cost experiment against our own endpoint, not uncontrolled flooding. D40 must obey an explicit byte cap, initially 256 KiB or the server's lower supported limit. No requests to third-party Ark servers, wallets, or LN victims.
- A properly authorized actor changing **its own** fallback to a different address is not a theft finding. The honest SDK must enforce its wallet's ownership check. Victim redirection cases lack the victim's signing keys.

## 5. Scheduler, offline periods, and restart behavior

Scenarios are state machines: `planned -> prerequisites -> armed -> running -> waiting -> verifying -> complete`. Separate terminal outcomes: `passed`, `failed`, `blocked`, `expected_refusal`, and `policy_hold`. A policy hold does not satisfy a test requiring eventual automatic payment.

Before every mutation persist the intent, actor, funds/coin IDs, input ownership and request fingerprint. After the request, persist the result and any signed artifacts. An ambiguous timeout becomes `outcome_unknown`; query/reconcile it before any retry. Client-driver actions must report request identity even when a response is lost. Do not pretend RPCs become idempotent because the simulator gave them an action ID.

Only one normal money-mutating action per actor runs at a time. Conflicts are deliberately enabled for named race cases and use copied transaction requests/isolated drivers with separate stores, not concurrent writers corrupting a shared Bark DB.

Create an offline cohort at least once per completed lifetime, staggering departures. Stop all its client tasks and record the final call/time/height. Continue ordinary traffic from other actors. Verify payout on-chain before returning or seed-only recovery. Keep one absent owner absent for several payout cycles while others send to a previously issued address, exercising post-loss receives.

An inexpensive deterministic scheduler seed makes choices reproducible. A signet outcome cannot be perfectly replayed because block timing and network fees are external; preserve enough artifacts to reproduce the protocol sequence on regtest.

The long scenario waits are persisted deadlines/triggers, not sleeping worker processes. Crash/restart of the supervisor resumes observation and state reconciliation before sending anything. Restart must not wake offline actors automatically. Use exponential backoff with jitter and finite retries per action; keep observing unsettled value indefinitely instead of hiding it behind a retry exhaustion marker.

Height-based alert proposal: once **all actually observable eligibility conditions** are satisfied, alert if no settlement appears after two further observed blocks; do not call this a proven eventual-payment SLA. Confirmation alerts use the configured confirmation target plus six observed blocks. Wall-clock alerts separately flag stalled chain progress after 60 minutes. All thresholds are configurable and labeled proposals until calibrated.

## 6. Independent fund and ownership ledger

The ledger is an audit/test oracle, not production payout state. SQLite stores the scheduler and durable facts; JSONL stores an append-only public event trail. Raw evidence is content-hashed. Persist integer sats and integer msats; never use floating-point BTC arithmetic. Record fee units explicitly (sat/vB versus sat/kwu).

Each event includes epoch, scenario/action/actor, monotonic order, UTC, chain height/hash, operation/phase, input/output IDs, payment hash if applicable, amounts, destination script, request outcome, evidence hash, and versions. Seed material and credentials are stored separately on the VM and never appear in reports or action logs.

Keep three distinct views:

1. **Expected ownership**, constructed from funded inputs and independently verified signed operations. Parse amounts, parents, signatures and actual registration outcomes. Server tables confirm a transition, but do not define the sole expected payee. For contested races preserve the accepted proof and commit/chain evidence; if the winner cannot be independently established, report uncertainty rather than choosing the server's answer automatically.
2. **Server observations**, including live/pending coin sources, links/records, LN payment/subscription state, participations, expiry settlements and nursery transactions. Query with read-only credentials and bounded statement timeouts. Incremental queries/keyset cursors avoid repeatedly scanning the full VTXO history.
3. **Chain and LN observations**, including transaction inputs/outputs, confirmations, exact sweep paths, invoice/payment terminal outcomes, channels and in-flight HTLCs. Reconcile observation timestamps/heights; these sources are not an atomic global snapshot.

Ownership rules:

- Board principal belongs to the board key holder after genuine funding. A never-broadcast proposal is not a funded entitlement.
- Refresh predecessors and successors represent one evolving entitlement; never sum both as user principal.
- A valid registered/posted transfer moves recipient value to the recipient; sender change remains the sender's.
- An unregistered transfer follows the actual input-owner rule until valid registration wins. A recipient merely possessing a signed chain is recorded as a disputed/pending transition, not silently classified as already paid or irrevocably lost.
- A collected, unclaimed LN receive belongs to its authenticated recipient; preimage knowledge alone does not prove external payment collection.
- A successful LN send leaves no refundable sender principal. Failed sends refund only on sufficient terminal/evidence rules. Unknown states retain an unresolved entitlement.
- A canceled hArk exchange and its replacements must not be counted together. Track whole participation plus predecessor paths.
- An expired paid entitlement is represented by its committed transaction and later chain output; do not count that output and the retired Ark coin as two assets.

Assertions run after every relevant event and at stable checkpoints:

- Every recipient script matches the authorized record selected for the winning settlement, or the explicitly labeled legacy floor case. New campaign keys must have records and links before use.
- For each payout destination, verified gross minus its independently reconstructed recipient fee share equals the output amount. Operator change-output fee and CPFP are separate operator costs.
- Exactly one funded resolution per entitlement: ordinary successor, offboard/exit, expiry payout, or valid Lightning fulfillment/refund. Multiple ledger rows sharing one payout txid are not multiple payments.
- A registered transfer cannot later be paid to its sender merely because the sender also had a record.
- A genuinely unregistered transfer cannot be relabeled as a recipient payment after its input-owner settlement.
- Unknown evidence or observer outage must never become `failed`, `zero obligations`, or `operator surplus` by default.
- The seed-only restore finds the payout, and the recovery spend verifies control.

Legacy pre-campaign coins, server-created padding and pool inventory are explicitly classified. Never classify a small amount as padding just because it is 330 sat. The campaign does not create legacy unlinked keys or assume the removed coin-key sweep is available.

## 7. Capital measurement: the main operator deliverable

Report **capital stock**, **capital tied up**, **liquidity immediately available**, and **irreversible operating expense** separately. Also report customer liabilities. A large total wallet balance or cumulative payment volume is not a capital requirement.

### 7.1 Balance-sheet boundary and categories

Create one report for captaind plus watchmand plus its operator LN node, and a separate whole-test report including customer actors, test treasury and external LN peers. Consolidated test conservation detects a leak, but can conceal movement from the operator to customer fixtures unless the operator boundary is kept distinct.

| Bucket | Record | Why an operator needs it |
|---|---|---|
| Rounds confirmed liquidity | Confirmed unspent outpoints/value, recognized reservations/committed spends, available UTXO shape. | Funds available for rounds, offboards and expiry payouts. |
| Rounds unconfirmed liquidity | Change/incoming outputs, ancestors, spendability constraints and confirmation age. | Total balance can overstate what the payout builder can spend. |
| Locked tree/board backing | Distinct actual unspent backing outpoints, value and expected release conditions. | Measures round/refresh capital tied up until real sweep/exit. |
| Watchman fee liquidity | Confirmed/unconfirmed fee-wallet funds, anchors/fees/reservations where observable. | Sweep/exit liveness needs its own budget. |
| Operator LN ownership | Local channel value plus LN on-chain funds, deduplicated from funding outpoints. | Equity/stock in Lightning, not all immediately sendable. |
| LN outbound/inbound liquidity | Per-channel spendable/receivable estimates, reserves, pending HTLCs and direction. | A net solvent node can still be unable to send or receive. |
| Unpaid user liabilities | Gross by source, policy holds, disputed/unknown LN outcomes, age and expected owner. | Swept user backing is not operator surplus. |
| Committed payout pipeline | Raw tx, recipients, fee split, reserved/consumed inputs, operator change and descendants. | Pending payouts and CPFP consume liquidity without creating a new liability twice. |
| Treasury and fixture capital | Initial actor funds, external-peer capital, recycling transfers, any top-up. | Prevents test funding from disguising server capital needs. |
| Unattributed value | Incoming/spent value not yet linked to evidence. | Explicit uncertainty, unavailable for a surplus claim. |

Round roots, board outputs, descendants and LN funding outputs are an **outpoint graph**: count only distinct current assets at a common chain position, not every historic tree node. Part of a root may back users and part may be operator overhead; when a split cannot be justified, label it mixed/unknown. Track replacement funding overlaps without double-counting user liabilities.

Core `getbalances` distinguishes trusted and untrusted-pending amounts; it does not replace transaction/outpoint spendability analysis ([official RPC](https://bitcoincore.org/en/doc/30.0.0/rpc/wallet/getbalances/)). CLN `listpeerchannels` exposes channel balance, reserve, in-flight and spendable/receivable estimates; those are estimates and per-channel constraints matter ([official RPC](https://docs.corelightning.org/reference/listpeerchannels)). `listfunds` supplies LN on-chain/funding context ([official RPC](https://docs.corelightning.org/reference/listfunds)). Probe the deployed CLN version's actual fields before making any optional field mandatory.

### 7.2 Cash-flow events and cost attribution

Record actual transaction input values, outputs and fees for board funding, rounds, sweeps, offboards, exits, expiry payouts, CPFP, channel opening/closing and proof/recycling spends. Deduplicate shared transaction fees once; when assigning per-scenario cost, declare the allocation and retain the exact total.

Split costs into user-paid mining fees, operator-paid mining fees, LN routing fees, Ark/service fee revenue, and harness-only costs. Channel rebalancing and extra funding fees are costs even when principal eventually returns. A user deposit is not operator equity; repayment is not an operating loss; an internal recycling transfer is not new capital; a swept root is not automatically all operator profit.

For the rounds-wallet cash view:

```text
closing observed balance
  = opening balance
  + actual incoming value
  - actual value paid outside this wallet
  - actual mining fees
```

Do not subtract fees again if recording an already fee-inclusive transaction debit. Use per-outpoint spend/confirmation events for **available confirmed liquidity**: a selected input becomes unavailable before its change confirms, which can create a larger temporary shortage than the transaction's net debit. An external LN send and a refresh also move capital between categories; do not label all moved principal as fee burn.

For a profile, calculate the cumulative liquidity deficit from the ordered spendability events and its peak. Under a fixed observed event trace, opening liquidity sufficient to cover that peak plus the required change/reserves gives a **trace-conditioned funding estimate**. Validate it against the actual successful builder input selections and any observed refusals. It is not the globally minimal capital: different UTXO shapes, selection, timing or lower funding can change the trace.

Do not announce a measured minimum merely because a generously funded run never failed. Report opening capital, observed peak deployed/locked amounts, minimum headroom, and all assumptions. A controlled smaller-capital epoch can tighten the estimate only on a dedicated/coordinated budget; the routine program must not withdraw existing operator reserves to manufacture a shortage.

### 7.3 Required operator numbers

Every daily and per-profile report includes:

1. Opening/closing operator assets and customer liabilities, with unknowns and reconciliation residuals.
2. Peak and p50/p95/p99 rounds liquidity used/locked; confirmed headroom; UTXO count/size/fragmentation.
3. Refresh replacement capital and lock duration, including how long old backing waits to be reusable.
4. Sweep receipts: user gross backing, proven recovered operator overhead, actual fee, time to usability.
5. Gross/net expiry obligations, payout/change funding required, and backlog by real deferral reason.
6. Operator change-output cost and operator CPFP spend; fixed recipient net checked after every child.
7. LN local capital, outbound/inbound demand, in-flight amount/time, direction depletion and required rebalance.
8. Fee burn per day, per completed action, per boarded sat and per abandoned wallet, with fixed versus variable costs.
9. Ark/service fee revenue versus operating costs, excluding customer principal and unclassified value.
10. Capital-turnover time, capital-days (time integral of locked sats), and recycle efficiency.
11. Shortfalls: observed funding refusals, how much usable funding was missing when determinable, which operation waited, and when it recovered.
12. Adversarial cost amplification: attacker requests/principal/fees versus operator work, locked capital, costs and honest latency.
13. Out-of-band funding/activity, observer gaps and contamination from other VM users.

Example **report format, with no invented measured numbers**:

```text
Profile: refresh-heavy; actual lifetime __ blocks; __ active owners
Opening operator capital: __ sats; additional injections: __ sats
Peak confirmed rounds requirement (trace estimate): __ sats
Peak tree/backing lock: __ sats for __ blocks; LN local capital: __ sats
Minimum confirmed rounds headroom: __ sats
Operator irreversible fees: __ sats/day; fee revenue: __ sats/day
Eligible payouts waiting for funds: __ sats, oldest __ blocks
Policy-held balances: __ sats across __ owners
Wrong-payee / duplicate resolution / unknown-value residual: __ / __ / __
Recommended liquidity envelope: __; conditions and uncertainty: __
```

### 7.4 Capacity planning and mainnet extrapolation

Fit separate observed relationships for new deposits, refreshes, offboards, abandoned principal and LN direction. Use real round sizes/overlap/recovery delays, rather than a single “sats per user” constant. Customer activity and outstanding principal are inputs; registered dormant account count alone is insufficient.

Produce scenarios for normal, refresh-heavy, send-heavy and mass-abandonment days, varying customer balances, new deposit rates, offline fraction, fee rates and actual/target coin lifetimes. Include bursts and periods without sweeps or LN rebalancing. Show sensitivity ranges instead of false confidence intervals from twelve correlated actors.

For the 100/1,000/10,000-user tables, distinguish **measured signet rows**, **modeled rows**, and **unqualified capacity limits**. Account for batching changes and database/runtime limits from independent scale tests. A linear 12-to-10,000 extrapolation does not qualify throughput.

Mainnet timing is a separate modeled input. Signet's short lifetimes/exit margins, fee market, channel routing and test-user balances do not establish a mainnet reserve. Reprice actual measured transaction weights at proposed mainnet fee rates, but disclose that fee rates also change batching, deferrals and timing. Any recommendations need the resulting sensitivity analysis, not a conversion of signet coins to dollars.

## 8. Funding discipline and continuous operation

Keep three independent budgets: **customer actor principal**, **operator liquidity/fee reserve**, and **external LN peer capital**. Define them before starting. The historical signet guide allows at most 25,000 sat per ordinary test wallet: a twelve-wallet pilot is therefore up to **300,000 sat of customer fixture funding**, not the proposed captaind capital requirement. Confirm the current shared funding policy before implementation. D37 or other larger cases have their own declared budget and remain blocked if it is unavailable.

Do not specify an invented “sufficient operator balance.” Start by observing the existing authorized liquidity and concurrent users, estimate funded workload feasibility, then declare the test envelope. If there is inadequate capital for a profile, record that and reduce/start a different profile; do not consume someone else's test reserves.

Before any new scenario, reserve its worst declared **harness** fees and customer amount in the supervisor's budget ledger. This does not reserve captaind inputs or rewrite production accounting. Record every funding/recycle transfer and its source. Disable automatic faucets and top-ups. A deliberate capital addition starts a new labeled funding epoch and remains visible in the cumulative report.

After payout verification and seed-only spend proof, recycle only this simulator's settled actor funds into its own customer treasury. Do not silently fund captaind from customer wallets. Optional operator top-up/rebalance is a separately declared action, not the response to a balance alarm. Ordinary offboarding is a user behavior, not a method to drain an absent test subject.

An indefinitely running system burns fees. Principal can circulate, but fees cannot be recycled. When the authorized fee budget is exhausted, stop creating new fee-bearing obligations, continue monitoring/reconciling existing obligations, and report the exhausted budget. Renewal/top-up is explicit. “Runs continuously” cannot honestly mean “makes paid transactions forever with finite funds.”

An actual below-minimum balance may remain unpaid indefinitely under current policy. Preserve it as a liability with amount and age; H32 tests its release. Never call an epoch fully paid if its absent owners still have such obligations. A later test-actor top-up proves conditional release, not automatic recovery of a permanently absent low-balance user.

## 9. Instrumentation and VM operation

Initial collection cadence: actor/action events immediately; lightweight balances/health/channel snapshots every 30 seconds; new blocks/known transactions on each tip change; bounded incremental DB deltas every 60 seconds. Full reconciliations at stable checkpoints and daily. Record source heights and query start/end times. If heights change during reconciliation, retry a bounded number of times or label the snapshot provisional; never manufacture equality by editing the ledger.

No repeated full-table scans or unbounded historical SQL from the soak program. Use existing indexes where available and validate query cost before enabling it. Query/log collection load is measured separately from client workload. Optional existing captaind telemetry can supply RPC latency, errors, open invoices and runtime delay; do not deploy Prometheus solely for this simulator.

Measure captaind/watchmand/CLN CPU, RSS, restarts, open connections, DB/query growth and latency, disk size/free space, host memory and simulator overhead. Partition actor-action elapsed time into client wait, rounds, chain confirmation, LN outcome and actual RPC latency.

The simulator supervisor is singleton and runs under systemd or a simulator-only Compose project with automatic restart and a durable volume. Prefer existing deployment conventions. Track its exact child processes/containers; cleanup never uses global `pkill`, command-line substring matching, or `docker prune`.

The exact VM CPU/RAM/free disk have not been inspected. Proposed starting ceilings: two active Rust drivers concurrently for expensive operations, max three ordinary mutations in flight, and at most 1 GiB combined simulator memory during calibration. If twelve persistent drivers exceed the ceiling, activate them on demand while retaining the twelve wallet identities. Set container/cgroup limits and validate that the host has sufficient spare memory; an OOM/restart is a failed operating condition, not an acceptable way to maintain the simulator budget.

Rotate routine logs and compact old derived snapshots. Keep all funding/transaction identifiers, event ledger, evidence hashes, campaign manifests and failures. Report disk growth/day. Before storage exhaustion, pause new funded work and preserve evidence; do not delete unresolved wallet state or incidents. Archive public evidence on a declared schedule; test seeds remain in protected VM storage under the existing seed policy.

Adversarial drivers get only their own keys and the public captaind endpoint. The observer gets read-only chain/LN/DB visibility through constrained adapters. Treasury/recycling authorization is separate. Never mount the Docker socket or the captaind secrets directory into an adversarial driver. VM co-location must not turn a dishonest-client test into a privileged-host attack.

No simulator-triggered captaind/watchmand/database shutdown, upgrade, config rewrite, payout abandon, WAL rollback, funding withdrawal or server hold-settle in the continuous profile. Real maintenance events can be observed and reported. Crash/recovery/CPFP/package-pressure experiments that require changing the server environment stay in the separate qualification campaign unless explicitly scheduled for a dedicated maintenance window.

## 10. Operator-facing outputs and incident handling

Generate **one static HTML dashboard**, a daily Markdown summary, and CSV/JSON exports. Avoid building a custom web application for the first version. Suggested views:

- Twelve actors: online/offline, behavior phase, balances, next expiry and any unresolved amount.
- Capital timeline: free confirmed rounds funds, pending change, locked backing, LN direction liquidity, fees and user liabilities.
- Payout pipeline: expiry -> own-path sweep -> sufficient depth -> durable payout -> mempool -> confirmation -> recovery proof.
- Scenario catalogue: H/D coverage, expected refusals, exercised protocol phase, blocked prerequisites, first/last success and incidents.
- Capacity worksheet: operator enters expected active users, balance/activity mix, lifetimes, abandonment rate and fees; generated modeled capital envelope includes its assumptions.

No fabricated green status for unrunnable cases. Keep “observed correct so far,” “waiting legitimately,” “policy-held,” “unknown,” “failed,” and “not exercised” distinct.

On suspected wrong payee, double funded resolution, unexplained value or service crash: persist a self-contained incident bundle and pause **new simulator mutations**. Continue read-only observation; do not stop captaind or interfere with legitimate payout workers. No auto-repair or top-up hides a failure. On ordinary funding shortage/expected refusal, record the reason and affected action without falsely declaring theft.

Incident bundle: manifest, versions/config hashes, scenario seed, last actions, signed public artifacts, owner mapping, relevant read-only server rows, chain/LN evidence, sanitized logs and capital timeline. Keep secret material separate. Notifications initially stay in the dashboard/local logs; external messages need a later explicit notification configuration.

Unexpected errors from ordinary actors are incidents. Expected D-catalog refusals are successful only if the specific invariant and lack of unauthorized side effects are checked. Track ordinary p50/p95/p99 completion/RPC latency during adversarial windows versus matched clean periods; chain waits are a separate latency category.

## 11. Implementation and acceptance sequence

Each step is small enough for a coding agent to implement and review without modifying the server fork.

1. **Manifest and read-only collector.** Validate signet genesis, exact target stack identity, live version/digests, schema, minimum/timings, sweep destination, fixture ownership and observer permissions. Capture 24 hours of health/capital before funded simulation. Never infer deployment state from a local env file.
2. **Independent ledger and report.** Build fixtures for transaction fee splits, repeated settlement-row fees, predecessor/successor deduplication, channel reserves/in-flight accounting, observation gaps and unrelated operator traffic. Show the opening balance-sheet boundary and unknowns before changing funds.
3. **Normal driver.** Create isolated wallet stores and explicit SDK actions. Prove restart reconciliation and that an offline actor makes no calls. Begin H01/H03/H07/H08/H25/H26 with two or three actors.
4. **Pilot capital cycle.** One funded board -> transfer -> absent expiry -> payout -> seed-only find/spend -> treasury recycle, with operator/counterparty boundaries reconciled to exact integer units. Record fees; no implicit top-up. This is the vertical slice.
5. **Twelve actors and scheduler.** Persist/restore the queue, enforce budgets and concurrency, add ordinary and refresh-heavy profiles. Prove a supervisor restart neither duplicates mutations nor wakes absent actors.
6. **External/internal Lightning.** Use declared owned peers/channels, collect exact hold/payment transitions, add H35–H40 and corresponding D cases. The external peer's balance is not captaind's capital. Refuse privileged out-of-band server settlement.
7. **Restricted raw/phase scenarios.** Add D01–D40 and remaining honest catalog in small groups: records/links; creation refusal; transfers/races; delegated/exit paths; LN; bounded resource abuse. Unit tests use protocol fixtures; small isolated regtest runs validate expensive timing/failure mechanisms before scheduling them on signet.
8. **Profile campaign.** Suggested 28-day allocation: 2 days observe/calibrate; 6 ordinary; 5 refresh-heavy; 5 directional LN; 5 abandonment; 5 mixed/adversarial. These are windows, not promises all long-running cases finish within them. Tag actions at profile boundaries and retain the overlapping outstanding cohorts in capital accounting.
9. **Drain and reconcile.** Stop new creation, allow already armed absence scenarios to finish, verify/spend payouts and reconcile remaining live/held/disputed amounts. Drain duration is the latest outstanding real eligibility/claim/confirmation condition, not a fixed 24-hour sleep. Preserved intentional policy holds are reported, not swept under the rug.
10. **Operator report and renewal.** Summarize measured workload, cost/capital envelopes, all 80 coverage statuses, failures and projection assumptions. Renew with another declared budget. Version changes create a new comparison segment after baseline capture, with no automatic stack deployment.

Acceptance for initial deployment: preflight refuses wrong network/stack; no shared wallet writes; ordinary vertical slice pays the rightful owner once; independently reconstructable operator/customer/LN accounting; restart safe; real offline evidence; exact fee/UTXO ledger; spendable seed-only recovery; finite budgets and failure-preserving logs.

Acceptance for a first campaign report: every claimed passed scenario actually reached its target state; every eligible funded source has a supported resolution or a clearly evidenced incident; no unexplained accounting residual at stable reconciliation; all blocked/held/unknown cases remain visible. A 28-day uptime statistic alone is not a pass. All six payout sources remain coverage requirements; an unsupported source is an unfinished requirement, not a simplification.

## 12. What this will let the operator conclude

The delivered program should provide a statement of this form:

> Under this measured client count, principal, deposit/refresh/payment mix, coin lifetime, fees and LN topology, captaind needed this peak liquidity, locked this amount for this duration, burned these fees, and served these actions/payouts within these delays. These adversarial behaviors imposed these additional costs or caused these failures. Here is the modeled envelope for a proposed larger deployment, and here are the conditions we have not qualified.

It will make the practical question “what happens when clients connect?” measurable without creating more server machinery. It cannot establish that no funds can ever be stranded under every fee, funding, chain, client-authorization or policy condition. Where current policy retains low balances, or operational evidence is unavailable, the report must say so plainly.

Open implementation inputs: actual VM spare resources; available simulator-only signet customer/fee/channel funds; a dedicated external LN fixture peer; final approved image versions. None prevents completing this plan. There is no request to deploy, build, start clients, or move coins in this document.

# Public-Signet execution results, 17 October 2026

The first native fallback lifecycle and a bounded 12-wallet load phase completed
on public Signet. These are measured capabilities, not production approval.
The [public transaction and result projection](evidence/public-signet-s02-load12-20261017.json)
has SHA256 `3098c5ea78f52742b1e47f491f52f8f408b8eca73d2a935962e9dcca10483481`.
Private journals, seeds, authenticated service credentials and wallet databases
are retained separately and are not published.

## Executed versions

| Component | Exact source |
|---|---|
| Native product, all four executable files | `7055d1fce858f3112aff671d0b2a8a454d6a2214` |
| Short expiry controller | `7d6a61568cf67f663b190b55fb739e00ee651629` |
| 12-wallet execution controller | `9f57c79be0e42028e951a1bb21f4208da3ce78bb` |
| 12-wallet preparation controller | `a6cc9892886578f1b2f583c494330781e2de52c9` |

The product native CLI SHA256 is
`8f2aff06b0edfa9427b1fa7894e13da8e8d471a57836031455d3924ae7b9ff04`.
The independent Core node is version 31 with txindex enabled on default public
Signet. The two campaign profiles use separate wallet databases and journals.
The short profile advertises lifetime 12 blocks, exit delta 3, and 3 board
confirmations, with client refresh threshold 4 and exit margin 2. The long load
profile advertises lifetime 4320 blocks, exit delta 144, and 3 board confirmations;
its client thresholds are 144 and 12. Native registrations, signed coin paths and
actual confirmed funding were admitted before either workload.

## Abandonment, payout and original-seed recovery

The absent actor was fenced at height **326677** with one signed, spendable
29,670-sat customer coin, backed by a confirmed 30,000-sat board. Its expiry was
**326684**. No native action opened the original absent wallet after the fence.
Public block discovery used its previously authenticated payout script and
signed coin path; it did not read the server's payout database.

| Observation | Actual outcome |
|---|---|
| Fallback payout confirmation | Height 326685 |
| Customer payout | 28,670 sat = 29,670 minus one 1,000-sat payout fee |
| Parent miner fee / shape | 0 sat / version 3, 174 vB |
| Watchman-funded child miner fee | 916 sat / version 3, 153 vB |
| Parent operator remainder | 1,330 sat = 1,000 payout fee + 330 earlier board residual |
| Operator net chain proceeds | 414 sat = 1,330 minus 916; net subsidy is zero |
| Fresh original-seed restore | Original birthday 326671; new wallet database |
| Confirmed recovery spend | Height 326686, consuming the exact 28,670-sat payout outpoint |
| Recovery miner fee | 178 sat |

The recovery transaction also consumes **69,847 sat of ordinary board change**.
Its destination receives 98,339 sat: 28,670 payout + 69,847 change − 178 miner fee.
That change is not a second fallback payout. The earlier 330-sat board residual
is not counted again as new fallback revenue. Considering only the new
1,000-sat fallback fee and the 916-sat miner payment gives 84 sat.

Public transactions:

- Payout: `7e6fc92a2dd6a7422eacf340d1555f45bfa7945c22027de6b92672b2b200cea7`, output 0.
- Fee child: `ee22e1a94127f9917251e1813f7198f07e8bb3ad60ab852b717573d2a6c5c467`.
- Recovery spend: `4147d72db6958f05705d3d4386597d6a06168ac72e119fdc1b88b485c1679c0b`.

The immutable first-pass report was recorded at **326686**, with only **two payout
confirmations** and one recovery-spend confirmation. Its SHA256 is
`18c876d882211e62fb748ce5bd4f153fc349bdcc78797488554bc0a5e99d9de5`.
The later independent public projection at **326696** observes 12 payout and 11
recovery confirmations. This preserves the original evidence depth.

The [independent public output scan](evidence/s02-public-payout-history-20261017.json)
checked all 6,147 transactions at heights 326684–326696 against both authenticated
registered scripts. It found exactly one absent-user payout and no control payout
in that interval. This bounded observation is not a permanent no-duplicate guarantee.

The active control refreshed beyond its original expiry, retained independently
verified signed backing, and paid 150 sat of observed refresh fees by first pass
(300 sat by height 326696). Restore received only the protected original phrase
and original birthday, not the original database or a payout transaction hint.
The Ark server remained available; server-independent restoration is a separate
acceptance case.

The concrete checks are implemented in
[`begin_absence`, `observe_payout`, `check_recovery`, and `reconcile`](../simulator/signet_s02.py),
[public block discovery](../simulator/signet_discovery.py),
and the [native lifecycle sequence](../simulator/signet_s02_case.py).
[Native signature verification](../simulator/signet_proof.py) invokes the actual
product verifier with signed coin and funding transaction bytes.

The coordinator independently rechecked the canonical scripts, actual payout input,
recovery destination, fee child and gross/net economics. Its [original proof](evidence/root-s02-current-chain-proof-20261017.json)
is preserved unchanged (SHA256 `8b01950d72d63d0caa2e451b87b65cdedeb9e25f9b0314913556ee1ebeb40b53`).
The [standalone verifier](evidence/verify-s02-public-chain.py) also explicitly checks
the default Signet challenge; its [separate rerun](evidence/root-s02-challenge-verified-proof-20261017.json)
does not replace the original receipt. Run the verifier on the owned target with
its retained campaign journal and Core data: `python3 verify-s02-public-chain.py`.
It reads the cookie only in memory, opens the journal read-only, never opens an
actor wallet, and prints a public JSON proof to stdout. An external observer can
independently check the listed transaction bytes and amounts on public Signet;
seed-only methodology also requires the retained controller/native artifacts.

## Bounded 12-wallet load

Twelve fresh native wallets each received 100,000 sat and boarded 30,000 sat.
All twelve boards reached three real confirmations before timed transfers.
The scheduled workload was **60 transfers of 1,000 sat**, using at most **three
concurrent disjoint actor pairs** with ten seconds minimum between batch starts.
The source [load runner](../simulator/signet_load.py) retained each original money
intent and independently reconciled received amounts, signed paths and backing;
its final audit checked the whole cohort, including duplicate coin ownership.

| Measurement | Actual result |
|---|---|
| Financially reconciled transfers | 60 of 60 |
| Failed or unknown transfers | 0 |
| Opening / closing customer coin value | 356,040 / 356,040 sat |
| Observed off-chain fees | 0 sat |
| Scheduled workload elapsed time, including pacing | 250.095 seconds |
| Achieved scheduled transfer rate | 14.395 transfers/minute |
| Native invocation p50 / p95 | 0.273 / 0.326 seconds |
| Send intent to observed receiver availability p50 / p95 | 1.036 / 1.104 seconds |
| Send intent to financial reconciliation p50 / p95 | 1.669 / 2.767 seconds |
| Treasury funding batch miner fee | 1,446 sat |
| Twelve board funding miner fees | 5,496 sat total, 458 each |

The final result SHA256 is
`036e753725b6872c87faf6c0c829818bfec3475f8ce2e17e1d2f049c0ce779d5`.
The declared 3 sat/vB client fallback is a fallback fee-source setting, not a
forced fee estimate; the values above come from actual transaction inputs and
outputs. Each board also carries a separate 330-sat virtual P2A residual.

The shared VM has 8 logical CPUs, 8,130,412 KiB RAM and Python 3.12.3. Core, two
Ark profiles, two CLN peers, the stock Noah backend and its databases, and a
provider barkd coexist on this machine. Across 1,529 50ms RSS samples, observed
maxima were controller 266,816 KiB, concurrent native children 120,976 KiB,
captaind 74,088 KiB and watchmand 37,024 KiB. These are sampled maxima that may
miss short peaks; they are not isolated capacity measurements.

## Remaining scope

A separate 50-wallet phase is funded and executing its once-only board admission;
its 200-transfer, five-worker timed workload has no successful result yet.
These results establish neither maximum TPS nor every production scenario.
Splitting, merged ownership cases, interruptions, controlled regtest reorg/fee
pressure, external application recovery, and actual Noah offline LNURL remain
separate evidence requirements. The earlier concurrent migration startup defect
and known browser issue remain explicit release concerns until their own fixes
and acceptance tests pass. No mobile wallet was built for Noah.

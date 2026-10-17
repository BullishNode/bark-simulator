# First sustained 50-wallet phase: admission proposal

The original proposal and its admission boundaries are retained below. Stage A
subsequently completed: [the actual zero-funded preparation receipt](evidence/first50-native-preparation-20261017.json)
records the new isolated services, 50 native wallets and authenticated
registrations, 56 genuine funding destinations, and verified off-VM backups.
There were no boards, sends or treasury funding in that snapshot. Stage B and
any subsequent traffic need their own actual receipts. Existing campaigns retain
their runtime pins, absent-wallet fences and immutable results.

The coordinator selected four captured products whose source bytes match
published product commit `e443d415ee7b0d512203bd56f85e22cdec69d35f`. The actual
captured build source HEAD remains **2f070b60a870b5d02edd8b5b0a5b0289a2edd11c, dirty**;
source-manifest SHA256 is
`1e28b175d8ee83aed24246b229831cfb926dc8003e4a40a049f262e5fa3f6dff` and
build-manifest SHA256 is
`a36140cbc86bdc395b0b9524b9731d80daea044db19a0ccf198ccbd894586264`.
All four actual binaries separately report executable version label
`9ea05f9680be2757e875ee81f4546fd24e5b6354`. That label does not identify the
captured source HEAD. Source equivalence does not make the original build clean
or turn native qualification into public-Signet execution.

The phase uses a new server identity, database and actor set, with lifetime
4,320, exit delta 144 and three board confirmations. Its pool and CLN lists are
empty. Lightning requires a separately admitted configuration and workload; it
is not a prerequisite for this ordinary-only measurement. The original 50-wallet
baseline remains on its own source and is not reused as new-candidate evidence.

| Parameter | Proposed value |
|---|---:|
| Fresh native wallets | 50 |
| Allocation per wallet / native board | 40,000 / 30,000 sat |
| Intended transfers | 600 × 1,000 sat |
| Concurrent disjoint pairs | 5 |
| Minimum batch-start interval | 10 seconds |
| Maximum interval for new batch dispatch | 1,200 seconds |
| New rounds / fee-wallet allocation | 200,000 / 100,000 sat |
| Total proposed new principal | 2,300,000 sat |
| Funding-batch miner-fee ceiling | 10,000 sat |

This is an offered twenty-minute schedule, not qualified elapsed time or a
promised completion rate. Reaching the dispatch deadline with fewer than 600
reconciled transfers leaves an incomplete result. Already dispatched workers
finish; unknown outcomes and failed monetary/signature checks stop new batches.
Report actual first-to-last timing, every hold and the complete final audit.

Stage A admits only zero-funded service initialization and genuine native
registrations. Exact product/process/configuration hashes, public Signet identity,
zero native balances and seed/wallet/journal backups precede funding. Real actor
addresses and five distinct native fee-wallet addresses then form the immutable
request for stage B. Stage B independently verifies actual treasury ownership,
safe confirmed inputs, exact signed PSBT outputs/change/fee and recovery reserves
before one journaled broadcast. An old balance or unspent-output observation is
not a fresh unlocked-wallet inventory or a funding transaction quote.

The frozen workload controller is
`36cefa12fceab6f5ec496d727208f94efcc38f46`;
[its complete CI run passed](https://github.com/BullishNode/bark-simulator/actions/runs/39070077103).
Its [44 focused checks](evidence/funded-scale-chain-observation-checks-20261017.json)
test controller contracts with stub native/Core. Only typed moving-chain
observations can be repeated within the original reconciliation budget; the
acknowledged money action is never repeated. These checks are not live scale
proof. The private deployment packet additionally verified actual captured
captaind/watchmand help and complete `-C CONFIG start --help` parsing after
correcting missing `start` subcommands in the first draft. Runtime configuration
validation and service admission still must happen on the owned VM.

Collect actual CPU/process identity, sampled memory, read-only PostgreSQL metrics,
latencies, board miner costs, isolated transfer conservation and signed backing.
The [cumulative scale proposal](signet-funded-scale-proposal-20261017.md) retains
later 200/500-wallet phases and separate Lightning/attribution work. This first
phase supplies no maximum-TPS, Noah/LNURL, browser, all-200-case or production
readiness claim.

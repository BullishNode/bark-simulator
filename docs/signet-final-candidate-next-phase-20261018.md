# Existing50: same-candidate upgrade, sustained ordinary traffic, then native Lightning

Prepared 2026-10-18. SOURCE/DEPLOYMENT PREPARATION ONLY. No candidate bytes are
assumed qualified or staged. No new actor, funding, import, service mutation,
invoice or payment is authorized by this document.

## Proposed useful next workload

Reuse the genuine 50 active wallets after the reviewed explicit audited-shortfall
cold handoff. Keep the original 580/600/HOLD and every prior proof immutable.
Upgrade the existing scale server identity, DB and all four product ELFs to ONE
root-qualified candidate. A separate new journal runs 900 offered 1,000-sat
ordinary transfers, concurrency 5 disjoint pairs, minimum 5-second batch-start
spacing, 900-second dispatch ceiling. This offers 60/min rather than the earlier
30/min, within the existing Load bounds. Actual dispatched/reconciled/missed
counts and three five-minute slices are the outcome; 900 green is not the goal.
No clock duration substitutes for money evidence or capacity qualification.

Keep full monetary intent/ACK/unknown, per-pair arithmetic, signed paths and Core
backing. The a7 dispatch-time pacing replaces the old outer sleep. Write bounded
progress summaries per batch and full reports at start/end. Record controller
pin/hash, native subprocess, proof and report timings separately; keep the same
runtime/hash verification guarantees. Sample actual CPU/RSS, PG activity/locks,
DB growth, resource pressure and native/service funds. Distinguish nominal due
requests not yet dispatched (generator delay) from native in-flight ACKs and
financially unresolved outcomes. This is closed-loop admitted workload, not an
open-loop maximum-TPS proof. Stable backend latency plus high generator overhead
must not be called backend saturation.

After the entire ordinary window is terminal and financially audited, close its
writer and admit a separately pinned SAME-candidate Lightning lifecycle phase.
This phase reuses existing funded actors: recipient load-000, failed sender
load-002 and (only if the existing working REST adapter is needed) provider
load-049. They are exclusive aliases of the existing cold wallets, not new users
or concurrent copies. All original birth heights, seeds, registrations and cuts
remain preserved. No new cohort or treasury principal is proposed.

### P09 final-candidate automatic Lightning milestones

1. Admit a separate configuration phase on the SAME upgraded DB/server identity
   and qualified four-ELF candidate: life32/exit12, pool pre-expiry12, receive
   HTLC delta6, send delta18/max288, a small 2x10,000-sat pool and the existing
   internal CLN mTLS connection. Retain unchanged SDK margins12/18. Native
   config/handshake and source-specific financial gates must pass before actions.
   Root can instead require a distinct profile if changing this existing service
   has an unqualified effect; no automatic alternative deployment is authorized.
2. RECEIVE: use the cached authenticated load-000 address and registration. Fence
   its original and copied native wallet paths before ONE 5,000-sat native
   invoice-for-address and ONE external xpay. Provider, if needed, is load-049 on
   the same candidate, never the recipient. Retain the genuine signed grant,
   actual D, confirmed anchor and E, fee quote, payment hash and final registered
   recipient Pubkey path after swap settlement. Do not wake the recipient to
   claim/deliver it. Source receipt/DB diagnostics corroborate the true owner but
   cannot replace native signatures or Core payment proof. Track real height
   through E, exact registered payout script, immutable payout parent and fee
   child, actual miner/subsidy accounting and >=6 canonical confirmations.
3. Only after independently verified payout/child depth may a NEW empty wallet
   restore load-000's original seed and birthday, with no DB copy, server SQL,
   supplied payout txid/outpoint or private recovery hint. Independently discover
   the expected payout, journal ONE drain to the owned declared destination and
   require >=6 confirmations with the expected payout actually consumed. Separate
   ordinary on-chain change/other original funds from this fallback amount.
4. FAILED SEND: load-002's existing coins expire around331133. Merely changing the
   server lifetime does NOT shorten them. Under a separately admitted one-shot
   native refresh, genuinely move the selected existing value into a new short
   tree. Record actual refresh fee, signed value/ownership, confirmed anchor and
   E. Then issue ONE owned external hold invoice5,000sat/minCLTV6 and ONE actual
   native send. Require the actual signed grant deadline D<E with sufficient
   admission headroom; record both real heights. If not, HOLD rather than invent
   a deadline/config override. Observe the owned external node's Accepted state,
   fence every original sender writer, then ONE cancellation and source-specific
   own-node label/index terminal failure. No coarse Failed-only or typed
   no-attempt substitute. Sender stays absent through automatic fallback at E.
5. Independently verify exact refundable ownership/value and real payout parent,
   child and >=6 confirmation proofs; original-seed-only restore plus ONE drain
   then >=6 confirmations, as above. Quote/grant/change/refresh fees determine the
   actual refund; never assume the old C60C28670sat fixture amount. Keep the
   recipient's concurrent absence fence intact until its own milestone completes.
6. Optional five successful receive/send controls are separate receipts and cannot
   replace either automatic lifecycle. This P09 profile intentionally tests an
   actual18-block HTLC horizon and32-block tree lifetime. It does NOT qualify the
   production default258-block send horizon, Noah/LNURL, all risks or maxTPS.

Existing one-shot LN controller stage functions are pinned to their old C60C
funding/board/profile receipts. They cannot simply be fed synthetic funding or
board ACKs for these reused wallets. Add a narrow explicit reused-inventory
handoff only after candidate source/CLI review: real old-to-new cut, original
births/registrations, exclusive writer lease and independently hashed cold files.
Retain the strict historical stage unchanged. The existing failed-send validator
also requires empty pool targets; a new shared receive/send profile needs an
explicit reviewed validator for its actual invariants, never a hidden bypass.
Reuse working one-shot invoice/pay/cancel/failure/recovery helpers after this
admission. These are concrete source-adapter blockers, not completed campaigns.

## Actual funds/headroom (read-only18October observations)

* Existing customer coins: 1,483,500 sat, 100 signed current IDs, 50 confirmed anchors;
  independently audited at 326842. Minimum observed expiry 331133 (4,291 blocks of
  headroom then). New admission must revalidate every actual registration/coin.
* Existing known service allocation: 200,000 sat rounds plus five 20,000-sat watch
  outputs, all six still confirmed/unspent 33 deep at the captured inventory read.
  Root funding b9cbce6f...:51..56; exact full outpoints/scripts are in the receipt.
  Native new-runtime usable balances must confirm this before pool issuance.
* The 50 other board outputs total 477,100 sat and remain unspent in Core. This
  collection does NOT establish current wallet ownership/usability, so none is
  counted as spendable new allocation/reserve. A read-only BDK ownership-table
  join yielded no rows for actor 000; no funds-loss conclusion or workaround.
* Existing CLN channel is NORMAL/connected, no HTLCs. Internal spendable 98,694,000
  msat; external 93,000,000msat. Each receive/send round trip uses 5,000,000msat,
  so sequential execution recycles liquidity instead of requiring new treasury.
* No incremental treasury principal proposed. Existing rounds 200k funds a small
  pool; watch 100k preserves actual confirmed fee capacity. Swap fees are measured
  from actual quotes/movements and cohort deltas, never assumed free. At current
  configured fees a 5k receive is 110 sat and a far-expiry 5k send base is 75 sat, but
  actual candidate grant/input age/quotes decide. 500 sat per selected actor is an
  operational proposal, not a changed watchman miner-fee cap. Owner policy is
  uncapped watchman miner fees with warning. No automatic top-up or unknown retry.
* Captured host: 8 logical CPUs, 4,472,728 KiB MemAvailable, 87,590,191,104 bytes free.
  Recheck immediately before admission. Ordinary 7055 and old C60C profiles stay live
  and are reported as co-resident activity, never stopped to improve the result.

Receipts on VM:
`scale/next-phase-existing-inventory-20261018.json` SHA
7a7050752bd7fa2c6f44e8572e3a10f3b39b6b0bbc2227050b5f536c98ce0960;
`scale/next-phase-current-ln-liquidity-20261018.json` SHA
97cdd468c42c903021bb8dd45de6a2e64f986e64bbaa7b42cefaa3ceabd7fb0a;
`next-phase-controller-readonly-profile-20261018.json` SHA
57c3cd292152c921060e70c1ec0f770c1952bbbbeb12b8566377d9c44aebbb78.
All are observations, not future usability/ownership guarantees.

## Exact current target and root upgrade sequence

1. Root hands off one qualified four-ELF archive plus artifact SHA, per-ELF hashes,
   actual build label/source-capture manifest/published equivalence and native
   qualification receipts. v10 is currently source-only. Stage into a NEW immutable
   candidate directory; never overwrite `/staging/scale-e443-20261017`. Verify Nix
   loader/runtime closure, SQLite dependency and four actual `--version` outputs.
   Copy ordinary TOMLs into a NEW config directory byte-for-byte; retain old files.
   Native checks: `CAND/captaind check-config CAP_CONFIG` and
   `CAND/captaind check-config WATCH_CONFIG --watchman` (not watchmand check-config).
2. Existing target: DB `fresh_signet_scale_20261017`; data
   `/var/lib/abandon-fresh/scale/server`; public/admin/integration/watch ports
   3595/3596/3598/4596. Identity must remain
   0264e92ccc0051ae9f089117768be08d942919e4552e8d0ec0b3f3ab9d3483510e.
   Config remains 4320/144/3, initially cln_array=[] and pool targets[]. Old cap
   SHA 8549584e70553202af42f8a7ac7c2c7eb7884ebe064b9cf214d70c74ff14d3d5;
   watch 4340b3c4f6b3bb2d5c0b79f5d212cd84a6f987838cec718f0ac367ad51a8593a.
3. Under the root's exclusive whole-cohort upgrade lease, verify old runner 228597
   and audit 309973 are terminal, original lock released, no other `/proc/*/cmdline`
   native process owns ANY of the original 50 wallet paths, no barkd/daemon writer,
   no unknown/dispatched intent. Keep original load HOLD. Add an explicit old-runner
   STOP/control record without rewriting the historical terminal outcome. Retain
   the lease until the admitted new writer takes ownership; a released old runner
   lock alone is insufficient to exclude another native wallet writer.
4. Gracefully stop ONLY `abandon-fresh-scale-watchmand.service` then
   `abandon-fresh-scale-captaind.service`. Require inactive/MainPID0/exit0. Core,
   PG, CLN and every other profile/ordinary observer remain running. Persist old
   unit files, actual process start identities/ELF hashes, config/manifests,
   server mnemonic SHA (not seed output), current service addresses and receipts.
5. Create NEW private backup directory, e.g.
   `/var/lib/abandon-fresh/scale/backups/pre-v10-<UTC>`. Commands are the existing
   verified patterns: `sudo -n -u postgres pg_dump -Fc -d fresh_signet_scale_20261017`
   and root-owned `sudo -n tar -cz -C /var/lib/abandon-fresh/scale server config`.
   Keep required role metadata privately. Back up the stopped original campaign
   journal consistently via SQLite backup and EVERY original wallet file, seeds,
   configs and private receipts. Independently SHA256 every wallet file before,
   in the archive and after cold-copy; verify 50 SQLite integrity checks. Copy
   backup OFF the VM and independently rehash it before restart/import. The
   journal's own backup hash alone does not verify wallet files.
6. Read and preserve migration history: actual upstream refinery versions 0..69;
   fork `expiry_refinery_schema_history` versions 1..12. Candidate is expected to
   add V13 fair scan and V14 fee sponsor, but root must compare the exact admitted
   candidate's migration vector/checksums; no guessed/mismatched table edit.
   NEVER run captaind create, drop/reseed DB or restore old financial state live.
7. Install NEW unit copies with exact `ExecStart=CAND/captaind -C NEW_CAP start`
   and `CAND/watchmand -C NEW_WATCH start`. Start cap ALONE, wait actual migration
   completion/native RPC and new history rows before starting watch. Preserve any
   failed startup, stop only these units on failure and diagnose; do not enter a
   restart loop or pretend the backup is a safe financial rollback after new work.
8. Independently pin actual `/proc/PID/exe`, process start IDs, versions/configs,
   unchanged seed hash, native server identity/4320/144/3 and actual service funds.
   Write a NEW runtime manifest/pins file; do not overwrite old e443 manifest.
   No wallet/campaign action before this root runtime admission.
9. Use reviewed `import_load_window(...,allow_audited_shortfall=True)` from 38bde7d
   or reviewed successor, old state `simulation/scale50-e443-ordinary`, new named
   state `simulation/scale50-final-candidate-ordinary`, separate cold archive.
   Peer review 15a7605a7a02894ae429abd7c70c9721113e60ff0bbfa64171362bf971e0d687.
   Original580/600/HOLD must remain byte-for-byte. New journal contains no copied
   create/send ACKs, keeps original births/config/registration/final inventory,
   and records old incomplete truth. Recheck independent wallet-file copy hashes.
10. New actual candidate `Load.prepare/admit` opens only the cold-copied existing
    active 50 wallets. Its real signed registrations/coin inventories must equal
    their captured predecessors. It requests ZERO new actor principal and issues
    ZERO boards for imported actors. Preserve original birth heights. No absent
    S02/S03/Lightning actors are reused. Start one new lock-owning runner only
    after root admits exact controller hash, candidate pins and workload.
11. After ordinary audit, close that writer and retain its result. A separately
    pinned SAME-candidate Lightning config enables the existing internal CLN mTLS
    connection and small pool. No seed/DB reset. Recheck TLS/node/channel/source,
    native usable 200k/100k funds and confirmed signed eligible pool anchors. The
    selected P09 actors follow their distinct active/absent fences above. Journal
    each invoice/pay/claim/cancel exactly once; lost replies retain original hash/UNKNOWN and halt new actions. Use
    current source-specific CLN payment records and preimage checks privately.
12. Final money proof accounts ordinary value, actual receive/send fees, external
    CLN debits/credits, signed registered final ownership, pool/fee-wallet changes
    and actual miner costs. Keep initial window and all prior receipts immutable.
    Credit candidate fallback-at-expiry only after the actual P09 lifecycles and
    independent confirmed recovery succeed; never infer Noah/reorg/all200 coverage.

## Existing profiling and limited source work

At the actual closed snapshot, old `c.report()` serialized 20,658,567 bytes and took
0.833 s wall / 0.728 CPU. One full four-ELF SHA pass took 1.178 s wall / 1.087 CPU on the VM.
The actual old 116 batches accumulated 44.515 s scheduling delay because reporting
ran after remaining delay was calculated. Keep source/executable verification;
change only report frequency, bounded progress/timing projection and dispatch-time
pacing. Do not add a metrics platform, generic scheduler or framework gate.

## Remaining blockers

* Exact root-qualified v10/source/artifact/CLI/feature handoff; currently source-only.
* Root runtime/backup/lease admission and actual V12→candidate migration verification.
* Focused tests/peer/CI for bounded summary + timing, then exact one-writer runner.
* Explicit reused-inventory Lightning stage and pool-aware failed-send validator,
  plus native command/source-specific terminal oracles, reviewed against the actual
  candidate. No new operation before root admission and confirmed service/pool/
  channel gates. Existing actor long expiries require genuine short-tree refresh.

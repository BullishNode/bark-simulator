# Public Signet V18 upgrade — 18 October 2026

At 10:52:26 UTC, the existing scale profile completed its controlled V18 upgrade at public Signet height 326879. Captain and watchman are active with zero restarts. Fork migration 16 was applied serially; the original migrations 1–15, server identity, fees, profile and wallet seeds were retained. The primary ordinary runner on the other profile continued unchanged: independently observed 190 reconciled transfers, 190 send acknowledgements and zero unknown/dispatched outcomes at height 326879.

The cold backup contains 249 files. Its PostgreSQL archive decoded completely both on the VM and off the VM. Independent off-VM verification checked all archived file hashes and four copied SQLite databases, then durably published the gate before any new writer started. This verifies backup bytes and archive decoding; it is not a restored-database application test.

The new readiness service reached a current generation-10 rebuilt view autonomously at 10:52:22 UTC. No manual sweep trigger was used. The two historical load outcomes remain 580/600 and 720/900, both INCOMPLETE/HOLD. Upgrading does not change those results.

The first wrapper stopped the old recipient observer and then held because a protected wallet root was matched as a substring of a sibling config directory. The exact path-boundary correction was reviewed independently; its continuation preserved the original hold and reused the same financial state. Earlier admission-format and missing-upload startup failures also remain recorded.

The already-paid receive remains a separate lifecycle. Its invoice, payment and signed 4,890-sat recipient claim were produced on V11c; the recipient has remained absent. Its actual tree expiry is 326894. The prospective payout is 3,890 sat after one 1,000-sat payout-output fee. This upgrade proves neither payout nor recovery. A separately allocated observer must independently verify the exact registered payout and fee child at six canonical confirmations before restoring from the original seed and making one recovery spend.

[Sanitized actual deployment evidence](evidence/signet-v18-upgrade-20261018.json) records the captured dirty build source, published equivalent code, real ELF/config hashes, deployed process identities, migration history, backup hashes and current-view observation. No production or Noah/LNURL qualification is claimed.

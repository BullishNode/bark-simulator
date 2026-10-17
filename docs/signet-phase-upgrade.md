# Upgrading the live native traffic phase

The executable handoff is `python -m simulator.signet_phase`. The coordinator supplies the exact checked paired
client/server candidate and admits the deployment. No live upgrade is implied by
publishing this document. The separate short S02 server, database, wallet cohort
and configuration remain independent on the same owned public-Signet VM.

The original S01 PASS used product
`901617a4ec500b4d0990d132aa6c818f93b80c7a` and controller
`ffc9bd79942ba26487f69c80f6bba50e32b5f6bd`. Its private immutable result SHA256 is
`79b65619e1acd156c8345e66e681bc926140ab778bb559a806a62614665fcc24`.
Its later bounded traffic is separate evidence, with one alternating 5,000-sat
transfer per new real public block and independent conservation/backing proofs.

## Handoff and preservation

1. Record the current canonical chain tip, exact source/binary/config hashes,
   original journal, registrations, public signed-path receipts and operation
   costs. Check for dispatched or unknown actions and unresolved transfers.
2. Request the runner's graceful stop. Let an active native process finish and
   reconcile it; do not terminate a monetary command. Prove the runner exited
   and its file lock is released. Do not sweep actor funds as part of this pause.
3. With the old runtime, take fresh native snapshots and authenticated fallback
   records under explicit observation intents. Require settled states and
   independent confirmed backing. These become the before-upgrade baseline.
4. Close native wallet processes and the journal, then archive the original
   journal including a consistent SQLite backup, its private retained artifacts,
   wallet directories and configuration. Record hashes and restrictive file
   permissions. Backups contain secrets and stay private on the owned VM.
   The coordinator separately preserves the server database/data and deployment
   receipts before migrating services.
5. Preserve the original first-PASS bytes, source checkout, original executable
   bundle and all existing phase pins. Original results stay historical evidence
   for that original build.

## Admit the paired candidate

The coordinator deploys the actual checked BIP84-compatible server/client bundle
to the existing long-lived Ark deployment. This is a source upgrade, not a third
Ark profile. Verify exact executable hashes, service configuration, server public
key, public-Signet identity, sync height and endpoint health before actor work.

Use a new named campaign directory and fresh journal for the new phase. Initialize
it with the new source/executable/server-configuration pins; do not rewrite the
old journal's immutable pins. With every old runner stopped, copy the cold wallet
directories into this phase. These are the existing actors: do not run `create`,
do not generate seeds and do not fabricate initialization or restore receipts.
The native commands can open an existing wallet under its actual new phase path.
Keep the actual wallet configuration hashes in the phase manifest and check them
before each wallet open. The copied database is a normal actor upgrade; S02's
separate seed-only recovery continues to forbid database copying.

Before maintenance or a transfer, run genuine new-candidate reads of each actor's
authenticated fallback record and coin snapshot. Require:

- identical canonical signed registrations, reserved payout scripts, account
  xpubs and mailbox identities;
- the same settled coin identities, values, ownership keys, anchors and expiry
  heights as the paused baseline, with conserved current ownership;
- actual new-candidate native signature verification for each spendable coin,
  with independently confirmed Core backing at a consistent tip;
- no unresolved operation or unexpected change from migration/opening.

Any mismatch holds this new phase for diagnosis. Passing the old build's S01
does not qualify the new one. Publish the new named phase and its own pins, then
resume the bounded ordinary traffic on the next new real height after handoff.
Record its fees and outcomes separately while preserving cross-phase continuity
of the same funds and registrations. Do not resume the old runner concurrently.

## Executable handoff

Use a separate controller checkout at the newly checked controller commit. Keep
the original S01 and short S02 checkouts pinned. Prepare a private new campaign
configuration and runtime-pin JSON before stopping anything. The new configuration
retains the old Ark/Core endpoints and declares the new client source, client ELF
SHA256 and aggregate service-config SHA256. Its state and archive directories must
be new, disjoint paths. No command overwrites an existing destination.

The private runtime-pin file has exactly these fields:

```json
{
  "binary_directory": "/opt/abandon-fresh/bin",
  "elf_sha256": {"bark": "SHA256", "barkd": "SHA256", "captaind": "SHA256", "watchmand": "SHA256"},
  "elf_source": {"bark": "CLIENT_COMMIT", "barkd": "CLIENT_COMMIT", "captaind": "SERVER_COMMIT", "watchmand": "SERVER_COMMIT"},
  "configuration_directory": "/var/lib/abandon-fresh/config",
  "config_hashes": {"captaind": "SHA256", "watchmand": "SHA256"},
  "runtime_manifest": "/opt/abandon-fresh/runtime-manifest.json",
  "runtime_manifest_sha256": "SHA256"
}
```

Replace every placeholder with exact measured hashes and full source commits.
The service-config aggregate is SHA256 of canonical JSON of `config_hashes`.
The coordinator retains original source and ELF bundles separately; the handoff
archives the original journal, wallet bytes, private action artifacts and first-PASS
bytes. Do not copy these private archives into GitHub.

After the original runner has exited gracefully, but before replacing its runtime:

```sh
python -m simulator.signet_phase --state OLD_STATE --config OLD_CONFIG stage \
  --new-state NEW_STATE --new-config NEW_CONFIG --archive PRIVATE_ARCHIVE \
  --handoff-id long-7055-ordinary --stop-file OLD_STOP --lock-file OLD_LOCK \
  --pid-file OLD_PID --first-pass-file ORIGINAL_PASS --runtime-pins NEW_RUNTIME_PINS
```

This acquires the original runner lock, rejects live/unknown actions and symlinks,
observes the actual old native wallets and stages the cold copies. Staging creates
no initialization acknowledgements and dispatches no money. The coordinator then
backs up the server database/data, deploys the declared candidate and verifies
service identity. After that:

```sh
python -m simulator.signet_phase --state NEW_STATE --config NEW_CONFIG admit
python -m simulator.signet_phase --state NEW_STATE --config NEW_CONFIG traffic-step
```

Admission performs genuine candidate reads and signature/backing checks against
the baseline. `traffic-step` checks all four ELF hashes, service configurations,
manifest and retained actor-config hashes before wallet activity. Call it under
one runner lock on a bounded polling schedule; it waits for a new real block and
then performs at most one alternating 5,000-sat transfer for that height. An
unfinished send is reconciled first; failed accounting cannot dispatch it again.
Keep the original stop flag in place. Any unknown, mismatch or failed reconciliation
holds this phase and preserves the actual state for diagnosis.

Python fault tests exercise these gates with explicitly stubbed native proofs.
They establish controller behavior, not a successful live product upgrade.

## Later Lightning and Noah phase

The coordinator subsequently selected a separate isolated Lightning-enabled Ark
profile on the same owned VM. Stage its own data, database, ports, configuration
and checked executable manifest; do not mutate the ordinary or short campaign
pins. Actual activation waits for its qualified backend handoff, native parser
admission, usable confirmed fee funds and genuine pool issuance/funding receipts.
The existing CLN/Noah infrastructure alone does not establish that this product
profile is deployed. Node plugin startup or a CLN-only payment cannot substitute
for native Bark Lightning tests.

The existing private CLN bootstrap has a confirmed 200,000-sat channel and an
independently reconciled 100,000-sat balancing payment. This is infrastructure
evidence only. Future command-line machine calls should disable notifications
with the actual CLN `--notifications=none` option; a progress line caused the
original bootstrap's parser error after its successful payment. Preserve that
original intent/reply and use payment-hash reconciliation, never payment replay.

For Noah, use the coordinator's clean, pinned backend-only build. Record actual
LNURL metadata/invoice consistency, one intended external payment, conditional
HTLC resolution, recipient-signed claim registration and actual mailbox delivery.
Keep the recipient wallet truly
offline while the backend remains online; capture its public destination before
absence. No mobile or Noah client build is part of this phase. A for-address
claim is signed directly to the recipient before its separate mailbox delivery;
the backend does not own that claim output. Distinguish conditional HTLC state,
recipient ownership and actual delivery using the signed policy and lineage.

## A failed upgrade

Stop new actions, preserve the actual post-upgrade state and reconcile every
original intent. Do not restore an old financial database or wallet snapshot
after new actions and thereby forget spending or payout decisions. The
coordinator chooses a checked recovery or forward fix from the retained state;
an old source bundle alone is not a safe financial-state rollback.

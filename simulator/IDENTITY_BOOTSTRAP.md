The optional `identity_bootstrap.declare(store, config, declaration)` API admits
only zero-principal identity creation in a fresh isolated campaign. It retains
`direct_xpub`, exact SDK/target pins, and `financial_qualification_required`.
It does not emit financial readiness or qualify funded actions.

Declare while paused, before all client actions and funding. The exact fields
are `id`, `pins` (the existing five financial pins), `identity` (network, genesis,
container, image_digest, server_pubkey), `wallet_root`, `actors`,
`driver_config_sha256`, and `wallet_config_sha256`. The native driver must be a
single absolute executable matching pins.driver_sha256. SIM_DRIVER_CONFIG must
name the absolute JSON file with the declared hash; its wallet_root/network and
the referenced absolute wallet_config hash are checked. This binds the reviewed
native create path (run_daemon=false, create_if_not_exists=true,
skip_recovery=true), which contains no Board, Lightning, or broadcast operation.
The root must independently qualify the exact binary/code mapping.

The verifier observes the actual filesystem: a current-user-owned mode0700
absolute wallet root, no symlink component, initially empty, and fresh ordinary
actors without prior action/controller state. The original hash-chained
declaration includes root device/inode/owner/mode and its SHA256. Context and
root identity are rechecked before each attempt. The existing Engine wallet-root
Lease must be held by this process (checked against its actual Linux FLOCK).
Bootstrap dispatch is serial. Only create with empty args and fee reservation0
at a predeclared absent actor directory is admitted. A durable original intent
precedes the existing native call. Every actor can be attempted once. An unknown
outcome remains parked, with no seed regeneration or retry.

After each attempt, further creation and every financial action remain held.
A completed original create is passed directly to
`closed_cohort_sources.verify_bootstrap_zero_assets` after context/root
revalidation. That separate producer must authenticate the original native
public frame and perform the independent Core confirmed/mempool descriptor
checks; native graph completeness or an empty balance cannot clear the hold.
Its original `identity_bootstrap_zero_assets_verified` receipt binds the
bootstrap id, all financial pins, actor/action, original driver-response event
and exact response digest, with complete=true and zero_assets=true. Missing
producer/import, scan overflow, unexpected assets, source gaps, mismatched
context, unknown actions, or no completed original create all retain the hold.
The source producer is a separate integration prerequisite for this commit.

After every declared actor has an original verified zero-asset receipt, the
normal full treasury/envelope/readiness gate applies. An envelope cannot be
declared and financial preflight cannot succeed while bootstrap is pending.
No twelve/twenty-four-client campaign, funding-plan, dispatcher, monetary SDK
operation, or global completion rule changes.

The controls use synthetic files and denied/unknown calls only. They establish
filesystem and admission behavior; they do not establish a real native create,
Core scan, payment, or production qualification.

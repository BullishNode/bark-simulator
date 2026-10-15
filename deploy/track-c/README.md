# C native public observer

Root installs these two Python files together, then writes the root-owned
`/etc/track-c/deployment-public.json`. The manifest is a public declaration;
it contains no RPC credentials, database credentials or wallet keys. It does not
qualify a financial action. The installed parent directories, manifest, observer
files and ops executable must be root-owned and not writable by group/others.

The exact manifest fields are:

```json
{
  "schema_version": 1,
  "track": "C",
  "architecture_profile": "direct_per_key",
  "active": true,
  "deployment_id": "ROOT_ASSIGNED_ID",
  "genesis": "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
  "financial_pins": {
    "product_commit": "40_LOWERCASE_HEX",
    "sdk_commit": "40_LOWERCASE_HEX",
    "driver_sha256": "64_LOWERCASE_HEX",
    "configuration_sha256": "64_LOWERCASE_HEX",
    "schema_sha256": "64_LOWERCASE_HEX"
  },
  "observer_files": {
    "server-observer.py": "64_LOWERCASE_HEX",
    "public_observer.py": "64_LOWERCASE_HEX"
  },
  "ops": {"path": "/opt/track-c/ROOT_SELECTED_OPS_PATH", "sha256": "64_LOWERCASE_HEX"},
  "services": {
    "captaind": {
      "unit": "ROOT_SELECTED.service",
      "executable_path": "/opt/track-c/runtime/captaind",
      "executable_sha256": "64_LOWERCASE_HEX",
      "config_path": "/etc/track-c/ROOT_SELECTED_CONFIG",
      "config_sha256": "64_LOWERCASE_HEX",
      "admin_address": "127.0.0.1:3536"
    },
    "watchmand": {
      "unit": "ROOT_SELECTED.service",
      "executable_path": "/opt/track-c/runtime/watchmand",
      "executable_sha256": "64_LOWERCASE_HEX",
      "config_path": "/etc/track-c/ROOT_SELECTED_CONFIG",
      "config_sha256": "64_LOWERCASE_HEX",
      "admin_address": "127.0.0.1:ROOT_SELECTED_PORT"
    }
  }
}
```

Placeholders deliberately fail validation. Root chooses and records actual paths,
ports, hashes, build provenance and deployment identity. The wrapper accepts no
request-selected SQL, RPC method, service executable or host. Its ops allowlist is:

| Verb | Exact arguments |
|---|---|
| `sql` | one generated fixed public read-only SQL string; use a read-only PG role |
| `cli` | `getblockchaininfo`; `getblockhash 0`; `getdescriptorinfo PUBLIC_DESCRIPTOR`; `decoderawtransaction STRIPPED_BODY` |
| `runtime-identity` | `captaind` or `watchmand` |
| `public-config` | `captaind` or `watchmand` |
| `wallet-inventory` | `rounds` or `watchman` |
| `logs` | reserved interface: service/fromUTC/untilUTC/tail/maxbytes; producer currently holds logs requests |

`runtime-identity` returns exactly `RUNTIME_FIELDS` from the wrapper, optionally
with `public_loaded_config_provenance`. It contains unit/PID/start timestamp,
boot ID/start ticks/32-hex invocation ID, restart count/running, binary and actual
process executable identity, exact command argv, config stat/hash, version,
environment names and only allowlisted log-level overrides. It includes the
original `pre_exec_config` from root's systemd ExecStartPre capture:
`path,sha256,device,inode,mtime_ns,ctime_ns,captured_at_ns,invocation_id`.
No environment values outside those harmless log levels may be returned.

`public-config` returns an allowlisted projection of the actual declared config
file plus its SHA256. Its `pool_lifetime_blocks` comes from the actual resolved
`vtxopool.vtxo_lifetime`, which must be explicitly48 for this C pilot. It includes
ordinary lifetime48, Board confirmations3, network/database, fee policy, direct
route/payout flags, pool targets and Lightning-enabled flag. Defaults require
actual resolved product evidence. Config hashes and same-process pre-exec facts
are independently verified by `simulator.c_runtime`; merely returning this
projection never proves loaded configuration.

`wallet-inventory` returns the existing separate-owner native JSON contract;
`public_observer.validate_wallet_frame` checks its complete field whitelist,
public descriptors, UTXOs, reservations, pending bodies and parents. The two
wallet sources are never represented as globally atomic.

Supported requests are snapshot, financial_readiness, closed_frontier,
claimant_inventory, direct_journal and coin/pending/link/record/nursery pages.
Unsupported log, raw binding and other source requests refuse. Every financial
frame remains `complete=false` and `qualified=false`; actual source collectors
and common financial preflight decide their much narrower operation scope.

`observer-role.sql` is a root-reviewed installation proposal, not executed by
this source. It grants explicit public columns on17 base tables and2 owner-defined
security-barrier views. The views expose only whether a round unlock preimage or
signed forfeit exists; the observer gets no privilege on either private base
column. `observer-role.json` records the full table/column allowlist. Install
the matching producer and views together, then capture the resulting observed
schema identity. Additive grants do not remove pre-existing grants or role
memberships, which root must inspect. No C legacy settlement path receives
extra privileges. SQL generation and the read-only PG role are separate controls.

On the simulator host, use the existing `simulator.remote_observer` with
`--architecture-profile direct_per_key`, explicit `--target-ssh USER@HOST`,
`--financial-context ABSOLUTE_PUBLIC_JSON` and `--campaign-config ACTUAL_TOML`,
plus its existing pinned SSH/Core/native-driver arguments. `SIM_DRIVER_CONFIG`
must select the actual C native JSON. The public context contains exactly
`financial_pins,driver_config_path,driver_config_sha256,wallet_config_path,wallet_config_sha256`.
The collector checks actual local artifact bytes and the target's matching
declarations and running release versions; SDK lineage remains the reviewed
immutable paired-build assertion. Missing context or changed artifacts hold.

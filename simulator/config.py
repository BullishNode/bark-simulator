from __future__ import annotations

import tomllib
import hashlib
import math
from dataclasses import dataclass
from pathlib import Path

from .padding import PADDING_PUBKEY, PADDING_UNLOCK_HASH, PADDING_AMOUNT_SAT
from .model import SIGNET_GENESIS, integer, public_payload
from .architecture import validate as validate_architecture

def verify_executables(runtime: dict, pins: dict) -> None:
    """Verify the commands actually invoked, not a different build directory."""
    if runtime.get('active') is not True and not pins and not runtime.get('server_policy_command'):
        return
    required = []
    for name in ('driver_command', 'proof_command', 'recovery_command', 'server_policy_command'):
        if runtime.get(name):
            required.append(runtime[name][0])
    observer = runtime.get('observer_command', [])
    if '--driver' in observer:
        index = observer.index('--driver') + 1
        if index >= len(observer):
            raise ValueError('observer driver argument is missing')
        required.append(observer[index])
    if runtime.get('active') is True and not runtime.get('driver_command'):
        raise ValueError('active configuration requires a pinned driver')
    if not isinstance(pins, dict) or any(path not in pins for path in required):
        raise ValueError('pin every configured native executable in [executables]')
    for path, expected in pins.items():
        file = Path(path)
        if (not file.is_absolute() or not file.is_file() or file.is_symlink()
                or not isinstance(expected, str) or len(expected) != 64
                or any(c not in '0123456789abcdef' for c in expected)):
            raise ValueError('invalid executable pin')
        with file.open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        if actual != expected:
            raise ValueError('configured executable hash mismatch')


@dataclass(frozen=True)
class Config:
    state_dir: Path
    observer_command: tuple[str, ...]
    driver_command: tuple[str, ...]
    wallet_root: Path
    expected_genesis: str
    expected_container: str
    expected_image: str
    expected_server_pubkey: str
    fee_budget_sat: int
    interval_seconds: int
    action_timeout_seconds: int
    active: bool
    workload: str = "none"
    board_amount_sat: int = 12000
    action_fee_reserve_sat: int = 2000
    network: str = "signet"
    proof_command: tuple[str, ...] = ()
    inventory_command: tuple[str, ...] = ()
    funding_wallet: str = ""
    funding_credential_file: str = ""
    proof_bundles: tuple[Path, ...] = ()
    recovery_command: tuple[str, ...] = ()
    recovery_destination: str = ""
    recovery_seeds: tuple[tuple[str, Path], ...] = ()
    recovery_maximum_fee_sat: int = 2000
    recovery_fee_rate_sat_vb: int = 3
    recovery_timeout_seconds: int = 86400
    operator_descriptors: tuple[Path, ...] = ()
    operator_bridge_enabled: bool = False
    log_target_enabled: bool = False
    log_local_sources: tuple[str, ...] = ()
    log_since_us: int | None = None
    log_rows_per_page: int = 64
    log_maximum_bytes: int = 131072
    server_policy_command: tuple[str, ...] = ()
    expected_padding_pubkey: str = PADDING_PUBKEY
    expected_padding_unlock_hash: str = PADDING_UNLOCK_HASH
    expected_padding_amount_sat: int = PADDING_AMOUNT_SAT
    trace_enabled: bool = True
    trace_retention_days: int = 30
    campaign_seed: str = ""
    absence_hazard_per_day: float = 0.005
    absent_payment_probability: float = 0.05
    dispatch_per_tick: int = 1
    phase_enabled: bool = False
    phase_manifest_sha256: str | None = None
    architecture_profile: str | None = None
    expected_sdk_commit: str | None = None

    def __post_init__(self):
        validate_architecture(self.architecture_profile)
        if self.architecture_profile is not None:
            sdk=self.expected_sdk_commit
            if not isinstance(sdk,str) or len(sdk)!=40 or any(c not in '0123456789abcdef' for c in sdk):
                raise ValueError('explicit architecture requires the actual qualified SDK commit')
        elif self.expected_sdk_commit is not None:
            raise ValueError('SDK pin requires an explicit campaign architecture profile')
        if type(self.phase_enabled) is not bool:raise ValueError('phase enablement must be boolean')
        if self.phase_manifest_sha256 is not None and (not isinstance(self.phase_manifest_sha256,str) or len(self.phase_manifest_sha256)!=64 or any(c not in '0123456789abcdef' for c in self.phase_manifest_sha256)):
            raise ValueError('phase qualification requires an exact manifest SHA256')
        if self.phase_enabled and (self.network!='signet' or not self.active or self.phase_manifest_sha256 is None):
            raise ValueError('phase dispatch requires an active signet configuration and independently qualified manifest')
        if (self.expected_padding_pubkey,self.expected_padding_unlock_hash,self.expected_padding_amount_sat)!=(PADDING_PUBKEY,PADDING_UNLOCK_HASH,PADDING_AMOUNT_SAT):
            raise ValueError('round padding constants must match the pinned SDK')
        integer(self.dispatch_per_tick,"dispatch per tick",1)
        if self.dispatch_per_tick>3:raise ValueError("dispatch per tick must not exceed 3")
        if not isinstance(self.campaign_seed,str) or len(self.campaign_seed)>128:raise ValueError("campaign seed must be public text of at most 128 characters")
        public_payload(self.campaign_seed)
        for value in (self.absence_hazard_per_day,self.absent_payment_probability):
            if type(value) not in (int,float) or not math.isfinite(value) or not 0<=value<=1:
                raise ValueError("realism probabilities must be finite values in [0,1]")

    @classmethod
    def load(cls, path: Path):
        data = tomllib.loads(path.read_text())
        target, runtime = data["target"], data["runtime"]
        logs=data.get('logs',{})
        if not isinstance(logs,dict) or set(logs)-{'target','local_sources','since_us','rows_per_page','maximum_bytes'} or type(logs.get('target',False)) is not bool:
            raise ValueError('invalid declared log capture settings')
        local_sources=logs.get('local_sources',[])
        if not isinstance(local_sources,list) or len(local_sources)>2 or any(not isinstance(v,str) or v not in {'simulator','observer'} for v in local_sources) or len(local_sources)!=len(set(local_sources)):
            raise ValueError('local logs require unique declared service aliases')
        since_us=integer(logs['since_us'],'log opening UTC') if 'since_us' in logs else None
        log_rows=integer(logs.get('rows_per_page',64),'log page rows',1)
        log_bytes=integer(logs.get('maximum_bytes',131072),'log page bytes',1024)
        if log_rows>256 or log_bytes>262144:raise ValueError('log page resource bound')
        for name, expected in [('padding_pubkey',PADDING_PUBKEY),('padding_unlock_hash',PADDING_UNLOCK_HASH),('padding_amount_sat',PADDING_AMOUNT_SAT)]:
            if target.get(name,expected)!=expected:
                raise ValueError('round padding constants must match the pinned SDK')
        policy=runtime.get('server_policy_command',[])
        if not isinstance(policy,list) or len(policy)>1 or any(not isinstance(x,str) for x in policy):
            raise ValueError('server_policy_command must contain one pinned public executable')
        if policy:
            executable=Path(policy[0])
            if not executable.is_absolute() or executable.is_symlink() or not executable.is_file():
                raise ValueError('unsafe server-policy executable')
        trace=data.get('trace',{})
        if not isinstance(trace,dict) or set(trace)-{'enabled','retention_days'} or type(trace.get('enabled',True)) is not bool:
            raise ValueError('trace requires enabled boolean and retention_days')
        trace_retention=integer(trace.get('retention_days',30),'trace retention days',1)
        if target.get("network") != "signet" or target.get("genesis") != SIGNET_GENESIS:
            raise ValueError("live configuration must use the official signet")
        container, image = target["container"], target["image_digest"]
        if not container.startswith("abandon-signet-fallback-") or not image.startswith("sha256:") or len(image) != 71:
            raise ValueError("pin the exact fallback container and image digest")
        pubkey = target["server_pubkey"]
        if len(pubkey) != 66 or any(c not in "0123456789abcdef" for c in pubkey):
            raise ValueError("pin the server compressed public key")
        paths = [Path(runtime[k]).expanduser().resolve() for k in ("state_dir", "wallet_root")]
        for name in ("observer_command", "driver_command", "proof_command", "inventory_command"):
            args = runtime.get(name, [])
            if not isinstance(args, list) or any(not isinstance(x, str) for x in args):
                raise ValueError(f"{name} must be an argument array, never a shell string")
        workload = runtime.get("workload", "none")
        if workload not in {"none", "pilot", "continuous"}:
            raise ValueError("only none/pilot/continuous workloads are implemented")
        recovery = data.get('recovery', {})
        if not isinstance(recovery, dict) or set(recovery) - {'command', 'seeds', 'maximum_fee_sat', 'fee_rate_sat_vb', 'timeout_seconds'}:
            raise ValueError('unsupported recovery declaration')
        recovery_command = recovery.get('command', [])
        if (not isinstance(recovery_command, list) or any(not isinstance(x, str) for x in recovery_command)
                or (recovery_command and len(recovery_command) != 3)):
            raise ValueError('recovery command must be adapter, loopback RPC and private credential path')
        from .recovery import declared_seeds
        recovery_seeds = declared_seeds(recovery.get('seeds', {}), paths[1])
        recovery_destination = data.get('funding', {}).get('recovery_address', '')
        recovery_maximum_fee_sat = integer(recovery.get('maximum_fee_sat', 2000), 'recovery cap', 1)
        reserve = integer(runtime.get('action_fee_reserve_sat', 2000), 'action fee reserve', 1)
        if recovery_command and recovery_maximum_fee_sat > min(2000, reserve):
            raise ValueError('recovery cap exceeds the action reservation or 2000 sats')
        if recovery_command and (not recovery_seeds or not isinstance(recovery_destination, str)
                or not recovery_destination or not data.get('funding', {}).get('wallet')
                or not recovery_command[1].startswith('http://127.0.0.1:')):
            raise ValueError('recovery requires declared backups and funding-wallet destination')
        if recovery_seeds and not recovery_command:
            raise ValueError('recovery seed sources require a pinned prepare-only adapter')
        verify_executables({**runtime, 'recovery_command': recovery_command}, data.get('executables', {}))
        from .proof_import import declared_paths
        proofs = data.get('proofs', {})
        if not isinstance(proofs, dict) or set(proofs) - {'bundles'}:
            raise ValueError('proofs supports declared local bundles only')
        proof_bundles = declared_paths(proofs.get('bundles', []), paths[1])
        from .operator_scripts import declaration_paths
        operator = data.get('operator', {})
        if not isinstance(operator, dict) or set(operator) - {'descriptors', 'bridge'} or type(operator.get('bridge', False)) is not bool:
            raise ValueError('operator supports declared public descriptors only')
        operator_descriptors = declaration_paths(operator.get('descriptors', []), paths[1])
        if operator.get('bridge', False) and (not operator_descriptors or not runtime.get('inventory_command') or not trace.get('enabled', True)):
            raise ValueError('operator bridge requires public descriptors, inventory command and trace')
        return cls(architecture_profile=target.get('architecture_profile'),expected_sdk_commit=target.get('sdk_commit'),phase_enabled=runtime.get('phase_enabled',False),phase_manifest_sha256=runtime.get('phase_manifest_sha256'),log_target_enabled=logs.get('target',False),log_local_sources=tuple(local_sources),log_since_us=since_us,log_rows_per_page=log_rows,log_maximum_bytes=log_bytes,server_policy_command=tuple(policy), state_dir=paths[0], observer_command=tuple(runtime["observer_command"]),
                   driver_command=tuple(runtime.get("driver_command", [])), wallet_root=paths[1],
                   expected_genesis=target["genesis"], expected_container=container,
                   expected_image=image, expected_server_pubkey=pubkey,
                   fee_budget_sat=integer(runtime["fee_budget_sat"], "fee budget"),
                   interval_seconds=integer(runtime.get("interval_seconds", 30), "interval", 1),
                   action_timeout_seconds=integer(runtime.get("action_timeout_seconds", 120), "action timeout", 1),
                   active=runtime.get("active", False) is True, workload=workload,
                   recovery_command=tuple(recovery_command), recovery_seeds=recovery_seeds,
                   recovery_destination=recovery_destination, recovery_maximum_fee_sat=recovery_maximum_fee_sat,
                   recovery_fee_rate_sat_vb=integer(recovery.get('fee_rate_sat_vb', 3), 'recovery fee rate', 1),
                   recovery_timeout_seconds=integer(recovery.get('timeout_seconds', 86400), 'recovery timeout', 1),
                   operator_descriptors=operator_descriptors, operator_bridge_enabled=operator.get('bridge', False),
                   proof_bundles=proof_bundles, proof_command=tuple(runtime.get("proof_command",[])), inventory_command=tuple(runtime.get("inventory_command",[])),
                   funding_wallet=data.get("funding",{}).get("wallet",""),funding_credential_file=data.get("funding",{}).get("credential_file",""),
                   board_amount_sat=integer(runtime.get("board_amount_sat", 12000), "board amount", 1),
                   action_fee_reserve_sat=integer(runtime.get("action_fee_reserve_sat", 2000), "action fee reserve"),
                   trace_enabled=trace.get('enabled',True), trace_retention_days=trace_retention,
                   campaign_seed=runtime.get("campaign_seed",""),
                   absence_hazard_per_day=runtime.get("absence_hazard_per_day",0.005),
                   absent_payment_probability=runtime.get("absent_payment_probability",0.05),
                   dispatch_per_tick=integer(runtime.get("dispatch_per_tick",2 if runtime.get("campaign_seed") else 1),"dispatch per tick",1))

    def validate_identity(self, snapshot: dict):
        identity = snapshot["identity"]
        expected = {"genesis": self.expected_genesis, "container": self.expected_container,
                    "image_digest": self.expected_image, "server_pubkey": self.expected_server_pubkey}
        for key, value in expected.items():
            if identity.get(key) != value:
                raise ValueError(f"target identity mismatch: {key}")
        expected_genesis = {"signet": SIGNET_GENESIS, "regtest": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"}
        if self.network not in expected_genesis or self.expected_genesis != expected_genesis[self.network]:
            raise ValueError("configuration network/genesis mismatch")
        if identity.get("network") != self.network:
            raise ValueError("observer network mismatch")
        if self.architecture_profile is not None:
            pins=snapshot.get('financial_pins')
            if snapshot.get('architecture_profile')!=self.architecture_profile:
                raise ValueError('observed architecture profile differs from configuration')
            if not isinstance(pins,dict) or pins.get('sdk_commit')!=self.expected_sdk_commit:
                raise ValueError('observed native SDK differs from explicit configuration pin')

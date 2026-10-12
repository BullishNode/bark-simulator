from __future__ import annotations

import tomllib
import hashlib
from dataclasses import dataclass
from pathlib import Path

from .model import SIGNET_GENESIS, integer

def verify_executables(runtime: dict, pins: dict) -> None:
    """Verify the commands actually invoked, not a different build directory."""
    if runtime.get('active') is not True and not pins:
        return
    required = []
    for name in ('driver_command', 'proof_command'):
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

    @classmethod
    def load(cls, path: Path):
        data = tomllib.loads(path.read_text())
        target, runtime = data["target"], data["runtime"]
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
        verify_executables(runtime, data.get('executables', {}))
        return cls(state_dir=paths[0], observer_command=tuple(runtime["observer_command"]),
                   driver_command=tuple(runtime.get("driver_command", [])), wallet_root=paths[1],
                   expected_genesis=target["genesis"], expected_container=container,
                   expected_image=image, expected_server_pubkey=pubkey,
                   fee_budget_sat=integer(runtime["fee_budget_sat"], "fee budget"),
                   interval_seconds=integer(runtime.get("interval_seconds", 30), "interval", 1),
                   action_timeout_seconds=integer(runtime.get("action_timeout_seconds", 120), "action timeout", 1),
                   active=runtime.get("active", False) is True, workload=workload,
                   proof_command=tuple(runtime.get("proof_command",[])), inventory_command=tuple(runtime.get("inventory_command",[])),
                   funding_wallet=data.get("funding",{}).get("wallet",""),funding_credential_file=data.get("funding",{}).get("credential_file",""),
                   board_amount_sat=integer(runtime.get("board_amount_sat", 12000), "board amount", 1),
                   action_fee_reserve_sat=integer(runtime.get("action_fee_reserve_sat", 2000), "action fee reserve"))

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

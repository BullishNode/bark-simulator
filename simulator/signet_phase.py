"""Explicit existing-wallet phase handoff; no initialization acknowledgements.

The coordinator owns server backup/deployment. Staging requires the original
runner stopped; admission performs genuine new-runtime native wallet reads.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import tomllib

from .model import canonical
from .signet import Campaign, network_identity
from .signet_checks import confirmed_backing
from .signet_proof import verify_coin

ACTORS = ("sender", "receiver")


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _native(campaign, intent, actor, operation, args=None):
    row = campaign.execute(intent, actor, operation, args or {})
    if row["state"] != "acknowledged":
        raise ValueError("original native outcome requires reconciliation: " + intent)
    return json.loads(row["reply"])


def _quiescent(campaign):
    if campaign.db.execute("SELECT 1 FROM action WHERE state IN ('dispatched','unknown')").fetchone():
        raise ValueError("original in-flight or unknown action requires reconciliation")


def _verify_runtime(campaign):
    row = campaign.db.execute("SELECT value FROM meta WHERE key='phase_runtime_pins'").fetchone()
    if not row:
        raise ValueError("explicit paired runtime pins required")
    pins = json.loads(row[0])
    if pins["elf_source"]["bark"] != campaign.config["source_commit"]:
        raise ValueError("client source differs from admitted phase")
    binary_dir = Path(pins["binary_directory"])
    if binary_dir / "bark" != Path(campaign.config["binary"]):
        raise ValueError("client binary differs from paired runtime")
    for name, digest in pins["elf_sha256"].items():
        if _sha(binary_dir / name) != digest:
            raise ValueError("paired runtime executable changed: " + name)
    actual = {name: _sha(Path(pins["configuration_directory"]) / (name + ".toml"))
              for name in pins["config_hashes"]}
    if (actual != pins["config_hashes"] or hashlib.sha256(canonical(actual).encode()).hexdigest() != campaign.config["product_config_sha256"]
            or _sha(pins["runtime_manifest"]) != pins["runtime_manifest_sha256"]):
        raise ValueError("paired runtime configuration or manifest changed")


def _private_tree(path):
    for entry in [path, *path.rglob("*")]:
        if entry.is_symlink():
            raise ValueError("cold wallet/archive tree cannot contain symlinks")


def _secure_tree(path):
    for entry in [path, *path.rglob("*")]:
        entry.chmod(0o700 if entry.is_dir() else 0o600)


def _observations(campaign, prefix, expected=None):
    initial_chain = network_identity(campaign.core)
    actors, snapshots, proofs = {}, [], []
    for actor in ACTORS:
        registration = _native(campaign, prefix + "-" + actor + "-registration", actor, "fallback_record")
        coins = _native(campaign, prefix + "-" + actor + "-snapshot", actor, "sync_vtxos")
        if not coins or not any(coin["state"] == "spendable" for coin in coins) or any(
                coin["state"] not in {"spendable", "spent"} for coin in coins):
            raise ValueError("settled existing native cohort required")
        if expected:
            if registration != expected[actor]["registration"]:
                raise ValueError("authenticated registration changed during upgrade")
            if sorted(coins, key=lambda coin: coin["id"]) != expected[actor]["coins"]:
                raise ValueError("native coin cohort changed during upgrade")
        actors[actor] = {"registration": registration, "coins": sorted(coins, key=lambda coin: coin["id"])}
        snapshots.append(coins)
        proofs.extend(verify_coin(campaign, actor, coin) for coin in coins if coin["state"] == "spendable")
    if not proofs or any(proof.get("status") != "PASS" for proof in proofs):
        raise ValueError("existing cohort native signature proof unavailable")
    backing = confirmed_backing(campaign.core, snapshots)
    if network_identity(campaign.core) != initial_chain:
        raise ValueError("chain changed during native phase observation")
    return {"actors": actors, "signature_proofs": proofs, "backing": backing, "chain": initial_chain}


def stage_existing_phase(old, new_directory: Path, new_config: dict, archive: Path, *,
                         handoff_id: str, stop_file: Path, lock_file: Path,
                         pid_file: Path, first_pass_file: Path, runtime_pins: dict) -> dict:
    """Cold-copy an existing cohort after its actual runner has exited."""
    if not re.fullmatch(r"[a-z0-9-]{1,48}", handoff_id):
        raise ValueError("simple explicit handoff ID required")
    if (set(runtime_pins) != {"binary_directory", "elf_sha256", "elf_source", "configuration_directory",
                              "config_hashes", "runtime_manifest", "runtime_manifest_sha256"}
            or set(runtime_pins["elf_sha256"]) != {"bark", "barkd", "captaind", "watchmand"}
            or set(runtime_pins["elf_source"]) != set(runtime_pins["elf_sha256"])
            or set(runtime_pins["config_hashes"]) != {"captaind", "watchmand"}
            or any(not re.fullmatch("[0-9a-f]{40}", value) for value in runtime_pins["elf_source"].values())
            or any(not re.fullmatch("[0-9a-f]{64}", value) for value in [*runtime_pins["elf_sha256"].values(),
                       *runtime_pins["config_hashes"].values(), runtime_pins["runtime_manifest_sha256"]])
            or runtime_pins["elf_sha256"]["bark"] != new_config["binary_sha256"]
            or runtime_pins["elf_source"]["bark"] != new_config["source_commit"]):
        raise ValueError("exact client/server paired runtime pin packet required")
    new_directory, archive = Path(new_directory).absolute(), Path(archive).absolute()
    if new_directory.exists() or archive.exists():
        raise ValueError("new phase/archive must not already exist; never overwrite")
    if (new_directory == old.root or old.root in new_directory.parents or new_directory in old.root.parents
            or archive == old.root or old.root in archive.parents or archive in old.root.parents
            or new_directory == archive or new_directory in archive.parents or archive in new_directory.parents):
        raise ValueError("old, new and archive directories must be separate")
    if any(new_config[key] != old.config[key] for key in ("ark_url", "core_url", "core_credential")):
        raise ValueError("existing actors must retain their declared Ark/Core endpoints")
    if not stop_file.is_file() or stop_file.is_symlink() or not lock_file.is_file() or lock_file.is_symlink():
        raise ValueError("actual runner stop request and existing lock required")
    pid = int(pid_file.read_text())
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        pass
    else:
        raise ValueError("original runner is still alive; wait for graceful exit")
    with lock_file.open("r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _quiescent(old)
        _private_tree(old.root)
        original_pass = json.loads(first_pass_file.read_text())
        if original_pass.get("progress", {}).get("case_verdict") != "PASS":
            raise ValueError("actual immutable original S01 PASS required")
        baseline = _observations(old, "phase-baseline-" + handoff_id)
        last = old.db.execute("SELECT actor FROM action WHERE operation='send' AND state='acknowledged' ORDER BY created DESC LIMIT 1").fetchone()
        first_sender = "receiver" if last is None or last[0] == "sender" else "sender"
        wallet_hashes = {}
        for actor in ACTORS:
            config_file = old.actor_path(actor) / "config.toml"
            values = tomllib.loads(config_file.read_text())
            if (values.get("server_address") != new_config["ark_url"]
                    or values.get("bitcoind_address") != new_config["core_url"]
                    or values.get("bitcoind_cookiefile") != new_config["core_credential"]):
                raise ValueError("copied wallet native configuration does not match declared target")
            wallet_hashes[actor] = _sha(config_file)
        def ignore(directory, names):
            return set(names).intersection({"signet.sqlite", "signet.sqlite-wal", "signet.sqlite-shm"}) if Path(directory) == old.root else set()
        shutil.copytree(old.root, archive, ignore=ignore)
        backup = sqlite3.connect(archive / "signet.sqlite")
        try:
            old.db.backup(backup)
        finally:
            backup.close()
        shutil.copy2(first_pass_file, archive / "original-s01-first-pass.json")
        (archive / "upgrade-baseline.json").write_text(canonical(baseline) + "\n")
        _secure_tree(archive)
        phase = Campaign(new_directory, new_config)
        try:
            (new_directory / "wallets").mkdir(mode=0o700)
            for actor in ACTORS:
                shutil.copytree(old.actor_path(actor), phase.actor_path(actor))
                _secure_tree(phase.actor_path(actor))
                phase.db.execute("INSERT INTO meta VALUES (?,?)", ("existing_wallet_config:" + actor, wallet_hashes[actor]))
            provenance = {"handoff_id": handoff_id, "old_product_source": old.config["source_commit"],
                          "old_binary_sha256": old.config["binary_sha256"],
                          "old_product_config_sha256": old.config["product_config_sha256"],
                          "new_product_source": new_config["source_commit"],
                          "original_first_pass_sha256": _sha(first_pass_file),
                          "archived_journal_sha256": _sha(archive / "signet.sqlite"),
                          "baseline_sha256": _sha(archive / "upgrade-baseline.json"),
                          "wallet_config_sha256": wallet_hashes, "baseline": baseline,
                          "first_traffic_sender": first_sender,
                          "scope": "Cold existing wallets and real old-runtime observations; new candidate not admitted yet."}
            phase.db.execute("INSERT INTO meta VALUES ('phase_upgrade',?)", (canonical(provenance),))
            phase.db.execute("INSERT INTO meta VALUES ('phase_runtime_pins',?)", (canonical(runtime_pins),))
            return {"kind": "phase_staging", "handoff_id": handoff_id, "stage": "STAGED_AWAITING_NATIVE_ADMISSION",
                    "new_product_source": new_config["source_commit"], "provenance": provenance,
                    "native_create_or_restore_receipts": 0, "money_dispatched": False}
        finally:
            phase.close()


def admit_existing_phase(campaign) -> dict:
    """Run genuine candidate reads against the frozen old-runtime baseline."""
    _quiescent(campaign)
    _verify_runtime(campaign)
    admitted = campaign.db.execute("SELECT value FROM meta WHERE key='phase_admitted'").fetchone()
    if admitted:
        return json.loads(admitted[0])
    row = campaign.db.execute("SELECT value FROM meta WHERE key='phase_upgrade'").fetchone()
    if not row:
        raise ValueError("cold phase provenance required")
    provenance = json.loads(row[0])
    observations = _observations(campaign, "phase-admit-" + provenance["handoff_id"], provenance["baseline"]["actors"])
    value = {"kind": "phase_admission", "stage": "EXISTING_NATIVE_COHORT_ADMITTED",
             "source_commit": campaign.config["source_commit"], "binary_sha256": campaign.config["binary_sha256"],
             "product_config_sha256": campaign.config["product_config_sha256"],
             "observations": observations, "chain": observations["chain"],
             "scope": "Actual candidate registration, unchanged native coin cohort, signed paths and confirmed backing; no new-build S01 or fallback claim."}
    campaign.db.execute("INSERT INTO meta VALUES ('phase_admitted',?)", (canonical(value),))
    return value


def advance_phase(campaign) -> dict:
    from .signet_traffic import advance
    _quiescent(campaign)
    _verify_runtime(campaign)
    row = campaign.db.execute("SELECT value FROM meta WHERE key='phase_admitted'").fetchone()
    if not row:
        raise ValueError("actual new-runtime admission required before traffic")
    height = network_identity(campaign.core)["height"]
    if height <= json.loads(row[0])["chain"]["height"]:
        return {"stage": "WAITING_FOR_NEW_HEIGHT_AFTER_ADMISSION", "height": height, "money_dispatched": False}
    pending = []
    for action in campaign.db.execute("SELECT id FROM action WHERE operation='send' AND id LIKE 'traffic-%-send'"):
        prefix = action[0][:-5]
        if not campaign.db.execute("SELECT 1 FROM result WHERE id=?", (prefix + "-complete",)).fetchone():
            pending.append(int(prefix.split("-")[1]))
    if pending:
        return advance(campaign, min(pending))
    for actor in ACTORS:
        for operation in ["maintain", "sync_vtxos"]:
            _native(campaign, f"active-{actor}-{height}-{operation}", actor, operation)
    return advance(campaign, height)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    stage = commands.add_parser("stage")
    for name in ["new-state", "new-config", "archive", "stop-file", "lock-file", "pid-file", "first-pass-file", "runtime-pins"]:
        stage.add_argument("--" + name, type=Path, required=True)
    stage.add_argument("--handoff-id", required=True)
    commands.add_parser("admit")
    commands.add_parser("traffic-step")
    args = parser.parse_args()
    campaign = Campaign(args.state, json.loads(args.config.read_text()))
    try:
        if args.command == "stage":
            result = stage_existing_phase(campaign, args.new_state, json.loads(args.new_config.read_text()), args.archive,
                                          handoff_id=args.handoff_id, stop_file=args.stop_file, lock_file=args.lock_file,
                                          pid_file=args.pid_file, first_pass_file=args.first_pass_file,
                                          runtime_pins=json.loads(args.runtime_pins.read_text()))
        elif args.command == "admit":
            result = admit_existing_phase(campaign)
        else:
            result = advance_phase(campaign)
        print(json.dumps(result, indent=2))
    finally:
        campaign.close()


if __name__ == "__main__":
    main()

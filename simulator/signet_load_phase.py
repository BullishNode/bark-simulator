"""Cold handoff between bounded cumulative load windows; no native dispatch."""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tomllib

from .model import canonical
from .signet_phase import _private_tree, _quiescent, _secure_tree, _sha


def import_load_window(old, new, *, stop_file, lock_file, pid_file, result_file, archive):
    """Copy only genuinely completed, non-absent actors after the old writer exits.

    Coordinator admits services/configuration and the new paired runtime separately.
    This function never creates actors through the SDK or copies acknowledgements
    into the new journal. New admission must observe the actual registration/coins.
    """
    archive = Path(archive).absolute()
    paths = [old.root.absolute(), new.root.absolute(), archive]
    if any(a == b or a in b.parents or b in a.parents for n, a in enumerate(paths) for b in paths[n + 1:]):
        raise ValueError("old, new and archive must be separate trees")
    if archive.exists() or (new.root / "wallets").exists() or new.db.execute("SELECT 1 FROM action").fetchone():
        raise ValueError("new load window/archive must be unused; reconcile a partial import")
    if new.db.execute("SELECT 1 FROM meta WHERE key='load_import_pending'").fetchone():
        raise ValueError("original load import must be reconciled, never repeated")
    if any(old.config[key] != new.config[key] for key in ("ark_url", "core_url", "core_credential")):
        raise ValueError("existing load wallets must retain actual server/Core endpoints")
    for p in [Path(stop_file), Path(lock_file), Path(pid_file), Path(result_file)]:
        if p.is_symlink() or not p.is_file():
            raise ValueError("original stop, lock, pid and immutable result files required")
    pid = int(Path(pid_file).read_text())
    if pid <= 0:
        raise ValueError("positive original runner PID required")
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        pass
    else:
        raise ValueError("original load runner is still alive")
    with Path(lock_file).open("r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _quiescent(old)
        if old.db.execute("SELECT 1 FROM actor WHERE absent=1").fetchone() or old.db.execute(
                "SELECT 1 FROM meta WHERE key='load_hold'").fetchone():
            raise ValueError("held or absent original actors cannot be reused")
        previous = json.loads(old.db.execute("SELECT value FROM meta WHERE key='load_parameters'").fetchone()[0])
        current = json.loads(new.db.execute("SELECT value FROM meta WHERE key='load_parameters'").fetchone()[0])
        if (previous["wallets"], current["wallets"]) not in {(50, 50), (50, 200), (200, 500)}:
            raise ValueError("only explicit 50 to 50/200 or 200 to 500 handoff supported")
        result = json.loads(Path(result_file).read_text())
        count = old.db.execute("SELECT count(*) FROM result WHERE id LIKE 'load-transfer-%-complete'").fetchone()[0]
        if (result.get("stage") != "LOAD_WORKLOAD_FINANCIALLY_RECONCILED"
                or result.get("parameters") != previous or count != previous["transfers"]
                or result.get("successful_reconciled_transfers") != count
                or result.get("failed_or_unknown_transfers") != 0
                or result.get("closing_coin_sat", -1) + result.get("observed_offchain_fee_sat", -1) != result.get("opening_coin_sat")):
            raise ValueError("actual completed previous load result and conservation required")
        _private_tree(old.root)
        actors = {}
        for number in range(previous["wallets"]):
            actor = f"load-{number:03d}"
            def reply(intent):
                row = old.db.execute("SELECT reply FROM action WHERE id=? AND state='acknowledged'", (intent,)).fetchone()
                if not row:
                    raise ValueError("original authentic load receipt missing: " + intent)
                return json.loads(row[0])
            original = old.db.execute("SELECT chain FROM action WHERE id=? AND state='acknowledged'", (actor + "-create",)).fetchone()
            prior = old.db.execute("SELECT value FROM meta WHERE key=?", ("load_existing:" + actor,)).fetchone()
            if not original and not prior:
                raise ValueError("original creation height provenance missing")
            config_file = old.actor_path(actor) / "config.toml"
            values = tomllib.loads(config_file.read_text())
            if any(values.get(k) != new.config[v] for k, v in {
                    "server_address": "ark_url", "bitcoind_address": "core_url", "bitcoind_cookiefile": "core_credential"}.items()):
                raise ValueError("actual existing wallet endpoints differ")
            actors[actor] = {"registration": reply(actor + "-registration"),
                "coins": sorted(reply("load-final-" + actor), key=lambda v: v["id"]),
                "original_pre_create_height": json.loads(original[0])["height"] if original else json.loads(prior[0])["original_pre_create_height"],
                "wallet_config_sha256": _sha(config_file)}
        if sum(v["amount_sat"] for a in actors.values() for v in a["coins"] if v["state"] == "spendable") != result["closing_coin_sat"]:
            raise ValueError("retained native final inventories differ from the completed result")
        server = json.loads(old.db.execute("SELECT reply FROM action WHERE id='load-native-target-info' AND state='acknowledged'").fetchone()[0])["server_pubkey"]
        new.db.execute("INSERT INTO meta VALUES ('load_import_pending',?)", (canonical({"old": str(old.root)}),))
        def ignore(directory, names):
            return set(names).intersection({"signet.sqlite", "signet.sqlite-wal", "signet.sqlite-shm"}) if Path(directory) == old.root else set()
        shutil.copytree(old.root, archive, ignore=ignore)
        backup = sqlite3.connect(archive / "signet.sqlite")
        try:
            old.db.backup(backup)
        finally:
            backup.close()
        _secure_tree(archive)
        (new.root / "wallets").mkdir(mode=0o700)
        for actor, data in actors.items():
            shutil.copytree(old.actor_path(actor), new.actor_path(actor))
            _secure_tree(new.actor_path(actor))
            new.db.execute("INSERT INTO meta VALUES (?,?)", ("existing_wallet_config:" + actor, data["wallet_config_sha256"]))
            new.db.execute("INSERT INTO meta VALUES (?,?)", ("load_existing:" + actor, canonical(data)))
        provenance = {"server_pubkey": server, "reused_wallets": len(actors),
            "old_product_source": old.config["source_commit"], "new_product_source": new.config["source_commit"],
            "previous_result_sha256": _sha(result_file), "archived_journal_sha256": _sha(archive / "signet.sqlite"),
            "scope": "Cold copied real completed wallets; actual new-runtime native admission still required."}
        new.db.execute("INSERT INTO meta VALUES ('load_import_complete',?)", (canonical(provenance),))
        return provenance

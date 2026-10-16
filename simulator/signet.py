"""Small public-Signet native CLI campaign journal.

Transport acknowledgements are deliberately not scenario passes. The existing
three-track collectors are not imported by this path.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import time

from .chain import ChainReader
from .model import SIGNET_GENESIS, canonical, integer, public_payload

PUBLIC_SIGNET_CHALLENGE = (
    "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430"
    "210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae"
)
OBSERVATIONS = {"vtxos", "balance"}
OPERATIONS = OBSERVATIONS | {"create", "address", "onchain_address", "board", "send", "refresh"}


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def network_identity(core) -> dict:
    info = core.call("getblockchaininfo")
    if (info.get("chain") != "signet" or info.get("initialblockdownload") is not False
            or info.get("signet_challenge") != PUBLIC_SIGNET_CHALLENGE
            or core.call("getblockhash", 0) != SIGNET_GENESIS):
        raise ValueError("synced default public Signet required")
    integer(info["blocks"], "chain height")
    if not re.fullmatch(r"[0-9a-f]{64}", info.get("bestblockhash", "")):
        raise ValueError("chain tip hash required")
    return {"chain": "signet", "genesis": SIGNET_GENESIS,
            "challenge": PUBLIC_SIGNET_CHALLENGE,
            "height": info["blocks"], "hash": info["bestblockhash"]}


def command(operation: str, args: dict, config: dict) -> list[str]:
    """Map typed intents to the real bfbe6b7c3 bark CLI; never execute a shell."""
    if operation not in OPERATIONS:
        raise ValueError("unsupported native operation")
    expected = {"board": {"amount_sat"}, "send": {"destination", "amount_sat"}}.get(operation, set())
    if set(args) != expected:
        raise ValueError("unexpected operation arguments")
    if "amount_sat" in args:
        integer(args["amount_sat"], "amount_sat", 1)
    if operation == "create":
        return ["create", "--signet", "--ark", config["ark_url"], "--bitcoind",
                config["core_url"], "--bitcoind-cookie", config["core_credential"]]
    if operation in OBSERVATIONS:
        return [operation, *(["--all"] if operation == "vtxos" else []), "--no-sync"]
    if operation == "onchain_address":
        return ["onchain", "address"]
    if operation == "board":
        return ["board", f'{args["amount_sat"]} sat']
    if operation == "send":
        destination = args["destination"]
        # S01 supports only an Ark address, not a URI that could select another
        # payment method or prompt interactively. CLI validates address encoding.
        if not isinstance(destination, str) or not re.fullmatch(r"tark1[0-9a-z]+", destination):
            raise ValueError("native Signet Ark address required")
        return ["send", destination, f'{args["amount_sat"]} sat', "--method-index", "0"]
    if operation == "refresh":
        return ["refresh", "--all"]
    return [operation]


def project_reply(operation: str, raw: bytes):
    """Public allowlist; raw CLI logs/replies may contain sensitive material."""
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError("native reply exceeds bound")
    if operation == "address":
        address = raw.decode().strip()
        if not re.fullmatch(r"tark1[0-9a-z]+", address):
            raise ValueError("unexpected Ark address output")
        return {"address": address}
    if operation in {"create", "send", "refresh"}:
        # send intentionally emits no machine receipt at bfbe6b7c3. A zero exit
        # is only acknowledgement, never payment completion.
        return {"native_exit_zero": True, "completion": "requires_reconciliation"}
    value = json.loads(raw)
    if operation == "vtxos":
        if not isinstance(value, list):
            raise ValueError("VTXO list required")
        result = []
        seen = set()
        for coin in value:
            item = {key: coin[key] for key in (
                "id", "amount_sat", "user_pubkey", "chain_anchor", "expiry_height", "state")}
            integer(item["amount_sat"], "coin amount", 1)
            integer(item["expiry_height"], "coin expiry")
            for key in ("id", "chain_anchor"):
                if not re.fullmatch(r"[0-9a-f]{64}:[0-9]+", item[key]):
                    raise ValueError("native outpoint required")
            if item["id"] in seen:
                raise ValueError("duplicate wallet coin")
            seen.add(item["id"])
            if not re.fullmatch(r"0[23][0-9a-f]{64}", item["user_pubkey"]):
                raise ValueError("native owner key required")
            state = item["state"].get("type")
            if state not in {"spendable", "spent", "exited", "locked"}:
                raise ValueError("unknown native wallet state")
            item["state"] = state
            result.append(item)
        return result
    if operation == "balance":
        result = {key: value[key] for key in (
            "spendable_sat", "needs_refresh_sat", "pending_lightning_send_sat",
            "claimable_lightning_receive_sat", "pending_in_round_sat", "pending_board_sat",
            "pending_arkoor_send_sat", "pending_offboard_sat", "pending_exit_sat")}
        for key, amount in result.items():
            integer(amount, key)
        return result
    if operation == "onchain_address":
        address = value["address"]
        if not isinstance(address, str) or not re.fullmatch(r"tb1[0-9a-z]+", address):
            raise ValueError("native Signet onchain address required")
        return {"address": address}
    if operation == "board":
        # Preserve public IDs and integer amount, not funding transaction bytes.
        txid = value["funding_tx"]["txid"]
        if not re.fullmatch(r"[0-9a-f]{64}", txid):
            raise ValueError("funding transaction ID required")
        return {"funding_txid": txid, "vtxos": value["vtxos"],
                "amount_sat": integer(value["amount_sat"], "board amount", 1),
                "movement_id": integer(value["movement_id"], "movement ID")}
    raise ValueError("unsupported reply")


class Campaign:
    def __init__(self, directory: Path, config: dict):
        directory = directory.absolute()
        if directory.is_symlink():
            raise ValueError("campaign directory cannot be a symlink")
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)
        self.root = directory
        self.config = config
        if (set(config) != {"source_commit", "binary", "binary_sha256", "ark_url", "core_url",
                           "core_credential", "product_config_sha256"}
                or not re.fullmatch(r"[0-9a-f]{40}", config["source_commit"])
                or any(not re.fullmatch(r"[0-9a-f]{64}", config[key])
                       for key in ("binary_sha256", "product_config_sha256"))
                or not config["ark_url"].startswith(("http://", "https://"))):
            raise ValueError("explicit source, executable, product configuration and target pins required")
        self.core = ChainReader(config["core_url"], config["core_credential"], SIGNET_GENESIS)
        database = directory / "signet.sqlite"
        if database.is_symlink():
            raise ValueError("campaign database cannot be a symlink")
        self.db = sqlite3.connect(database, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        os.chmod(database, 0o600)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS actor(id TEXT PRIMARY KEY, absent INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS action(
                id TEXT PRIMARY KEY, actor TEXT NOT NULL, operation TEXT NOT NULL,
                arguments TEXT NOT NULL, state TEXT NOT NULL, created REAL NOT NULL,
                updated REAL NOT NULL, chain TEXT, reply TEXT, diagnostic TEXT);
            CREATE UNIQUE INDEX IF NOT EXISTS actor_dispatch ON action(actor)
                WHERE state IN ('dispatched','unknown');
        """)
        fingerprint = canonical(config)
        self.db.execute("INSERT OR IGNORE INTO meta VALUES ('config',?)", (fingerprint,))
        if self.db.execute("SELECT value FROM meta WHERE key='config'").fetchone()[0] != fingerprint:
            self.close()
            raise ValueError("campaign pins changed: use a new versioned campaign")

    def close(self):
        self.db.close()

    def actor_path(self, actor: str) -> Path:
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", actor):
            raise ValueError("invalid actor ID")
        return self.root / "wallets" / actor

    def execute(self, intent: str, actor: str, operation: str, args: dict, *, timeout=120):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", intent):
            raise ValueError("invalid intent ID")
        if type(timeout) not in (int, float) or not 0 < timeout <= 600:
            raise ValueError("timeout outside supported bound")
        path = self.actor_path(actor)
        native_args = command(operation, args, self.config)
        public_payload(args)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            previous = self.db.execute("SELECT * FROM action WHERE id=?", (intent,)).fetchone()
            if previous:
                if (previous["actor"], previous["operation"], previous["arguments"]) != (actor, operation, canonical(args)):
                    raise ValueError("intent ID reused with different action")
                self.db.execute("COMMIT")
                return dict(previous)  # Never replay even a failed/unknown action.
            self.db.execute("INSERT OR IGNORE INTO actor(id) VALUES (?)", (actor,))
            if self.db.execute("SELECT absent FROM actor WHERE id=?", (actor,)).fetchone()[0]:
                raise ValueError("absent actor: no native wallet process may open it")
            if self.db.execute("SELECT 1 FROM action WHERE actor=? AND state IN ('dispatched','unknown')", (actor,)).fetchone():
                raise ValueError("actor has an in-flight or unknown action; reconcile first")
            if digest(Path(self.config["binary"])) != self.config["binary_sha256"]:
                raise ValueError("native executable hash changed")
            chain = network_identity(self.core)
            now = time.time()
            self.db.execute("INSERT INTO action VALUES (?,?,?,?,?,?,?,?,?,?)", (
                intent, actor, operation, canonical(args), "dispatched", now, now,
                canonical(chain), None, None))
            self.db.execute("COMMIT")  # Durable before starting the native process.
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise
        try:
            path.parent.mkdir(mode=0o700, exist_ok=True)
            # Do not inherit BARK_DATADIR / daemon endpoints / RPC passwords.
            environment = {key: value for key, value in os.environ.items()
                           if not key.startswith("BARK_")}
            result = subprocess.run([
                self.config["binary"], "--quiet", "--no-logfile", "--datadir", str(path), *native_args,
            ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env=environment, timeout=timeout, check=False)
            if result.returncode:
                raise ValueError("native_nonzero_exit")
            reply = project_reply(operation, result.stdout)
            public_payload(reply)
            self.db.execute("UPDATE action SET state='acknowledged',reply=?,updated=? WHERE id=?",
                            (canonical(reply), time.time(), intent))
        except Exception as error:
            # An exception, malformed reply or nonzero exit can follow a committed
            # payment. No speculative failure classification or second attempt.
            self.db.execute("UPDATE action SET state='unknown',diagnostic=?,updated=? WHERE id=?",
                            (type(error).__name__, time.time(), intent))
        return dict(self.db.execute("SELECT * FROM action WHERE id=?", (intent,)).fetchone())

    def abandon(self, actor: str):
        self.actor_path(actor)
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO actor(id) VALUES (?)", (actor,))
            self.db.execute("UPDATE actor SET absent=1 WHERE id=?", (actor,))

    def report(self) -> dict:
        rows = [dict(row) for row in self.db.execute("SELECT * FROM action ORDER BY created,id")]
        for row in rows:
            for key in ("arguments", "chain", "reply"):
                if row[key] is not None:
                    row[key] = json.loads(row[key])
        return {"source_commit": self.config["source_commit"],
                "binary_sha256": self.config["binary_sha256"],
                "product_config_sha256": self.config["product_config_sha256"],
                "network": "public-signet", "actions": rows,
                "case_verdict": "NOT_EVALUATED",
                "note": "Native acknowledgements are not proof of terminal payment or fallback."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("report")
    execute = commands.add_parser("execute")
    execute.add_argument("intent")
    execute.add_argument("actor")
    execute.add_argument("operation", choices=sorted(OPERATIONS))
    execute.add_argument("--arguments", type=json.loads, default={})
    absent = commands.add_parser("abandon")
    absent.add_argument("actor")
    args = parser.parse_args()
    campaign = Campaign(args.state, json.loads(args.config.read_text()))
    try:
        if args.command == "execute":
            campaign.execute(args.intent, args.actor, args.operation, args.arguments)
        elif args.command == "abandon":
            campaign.abandon(args.actor)
        print(json.dumps(campaign.report(), indent=2))
    finally:
        campaign.close()


if __name__ == "__main__":
    main()

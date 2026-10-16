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
import tempfile
import time

from .chain import ChainReader
from .model import SIGNET_GENESIS, canonical, integer, public_payload

PUBLIC_SIGNET_CHALLENGE = (
    "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430"
    "210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae"
)
OBSERVATIONS = {"vtxos", "sync_vtxos", "balance", "ark_info"}
OPERATIONS = OBSERVATIONS | {"create", "address", "onchain_address", "board", "send", "refresh", "maintain", "raw_vtxo", "fallback_record"}


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
    expected = {"board": {"amount_sat"}, "send": {"destination", "amount_sat"},
                "raw_vtxo": {"coin_id"}}.get(operation, set())
    if set(args) != expected:
        raise ValueError("unexpected operation arguments")
    if "amount_sat" in args:
        integer(args["amount_sat"], "amount_sat", 1)
    if operation == "create":
        return ["create", "--signet", "--ark", config["ark_url"], "--bitcoind",
                config["core_url"], "--bitcoind-cookie", config["core_credential"]]
    if operation == "sync_vtxos":
        return ["vtxos", "--all"]
    if operation == "ark_info":
        return ["ark-info"]
    if operation in OBSERVATIONS:
        return [operation, *(["--all"] if operation == "vtxos" else []), "--no-sync"]
    if operation == "onchain_address":
        return ["onchain", "address"]
    if operation == "fallback_record":
        return ["dev", "fallback-record"]
    if operation == "raw_vtxo":
        if not re.fullmatch(r"[0-9a-f]{64}:[0-9]+", args["coin_id"]):
            raise ValueError("native coin ID required")
        return ["raw-vtxo", args["coin_id"]]
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
    if operation == "raw_vtxo":
        text = raw.decode().strip()
        if not text or not re.fullmatch(r"(?:[0-9a-f]{2})+", text):
            raise ValueError("native serialized VTXO required")
        serialized = bytes.fromhex(text)
        return {"serialized_sha256": hashlib.sha256(serialized).hexdigest(),
                "serialized_bytes": len(serialized)}
    if operation in {"create", "send", "refresh", "maintain"}:
        # send intentionally emits no machine receipt at bfbe6b7c3. A zero exit
        # is only acknowledgement, never payment completion.
        return {"native_exit_zero": True, "completion": "requires_reconciliation"}
    value = json.loads(raw)
    if operation == "fallback_record":
        result = {key: value[key] for key in ("network", "mailbox_pk", "payout_address", "record_hex", "record")}
        if (result["network"] != "signet"
                or not re.fullmatch(r"0[23][0-9a-f]{64}", result["mailbox_pk"])
                or not re.fullmatch(r"tb1q[0-9a-z]+", result["payout_address"])
                or not re.fullmatch(r"(?:[0-9a-f]{2})+", result["record_hex"])):
            raise ValueError("native Signet public registration required")
        record = result["record"]
        result["record"] = {key: record[key] for key in (
            "spk", "account_xpub", "mailbox_signature", "account_signature")}
        if not re.fullmatch(r"0014[0-9a-f]{40}", record["spk"]) or not record["account_xpub"].startswith("tpub"):
            raise ValueError("native BIP84 payout script and testnet account required")
        for field in ("mailbox_signature", "account_signature"):
            if not re.fullmatch(r"[0-9a-f]{128}", record[field]):
                raise ValueError("public registration signature required")
        return result
    if operation == "ark_info":
        keys = ("network", "server_pubkey", "required_board_confirmations", "vtxo_lifetime",
                "vtxo_exit_delta", "htlc_send_expiry_delta", "htlc_expiry_delta", "min_board_amount_sat")
        result = {key: value[key] for key in keys}
        if result["network"] != "signet" or not re.fullmatch(r"0[23][0-9a-f]{64}", result["server_pubkey"]):
            raise ValueError("native server Signet identity required")
        for key in keys[2:]:
            integer(result[key], key)
        return result
    if operation in {"vtxos", "sync_vtxos"}:
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
        # Linux process identity survives object recreation but changes on a
        # real controller restart, including PID reuse after reboot.
        start_ticks = Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()[19]
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self.controller_id = hashlib.sha256(f"{boot}:{os.getpid()}:{start_ticks}".encode()).hexdigest()
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
            CREATE TABLE IF NOT EXISTS result(
                id TEXT PRIMARY KEY, observed REAL NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS native_artifact(
                intent TEXT NOT NULL, kind TEXT NOT NULL, relative_path TEXT NOT NULL,
                sha256 TEXT NOT NULL, bytes INTEGER NOT NULL, truncated INTEGER NOT NULL,
                PRIMARY KEY(intent,kind));
            CREATE TABLE IF NOT EXISTS action_context(
                intent TEXT PRIMARY KEY, controller_id TEXT NOT NULL,
                source_commit TEXT NOT NULL, binary_sha256 TEXT NOT NULL,
                product_config_sha256 TEXT NOT NULL);
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

    def _retain_private(self, intent: str, kind: str, stream):
        private = self.root / "private"
        private.mkdir(mode=0o700, exist_ok=True)
        if private.is_symlink():
            raise ValueError("private artifacts directory cannot be a symlink")
        os.chmod(private, 0o700)
        stream.seek(0)
        raw = stream.read(4 * 1024 * 1024 + 1)
        truncated = len(raw) > 4 * 1024 * 1024
        raw = raw[:4 * 1024 * 1024]
        relative = f"private/{intent}.{kind}"
        fd = os.open(self.root / relative, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        self.db.execute("INSERT INTO native_artifact VALUES (?,?,?,?,?,?)", (
            intent, kind, relative, hashlib.sha256(raw).hexdigest(), len(raw), int(truncated)))

    def execute(self, intent: str, actor: str, operation: str, args: dict, *, timeout=120):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", intent):
            raise ValueError("invalid intent ID")
        if type(timeout) not in (int, float) or not 0 < timeout <= 600:
            raise ValueError("timeout outside supported bound")
        path = self.actor_path(actor)
        native_args = command(operation, args, self.config)
        public_payload(args)
        previous = self.db.execute("SELECT * FROM action WHERE id=?", (intent,)).fetchone()
        if previous:
            if (previous["actor"], previous["operation"], previous["arguments"]) != (actor, operation, canonical(args)):
                raise ValueError("intent ID reused with different action")
            return dict(previous)
        # Potentially slow file hashing and Core reads happen before the short
        # SQLite write transaction. Actor exclusion is rechecked atomically below.
        if digest(Path(self.config["binary"])) != self.config["binary_sha256"]:
            raise ValueError("native executable hash changed")
        chain = network_identity(self.core)
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
            now = time.time()
            self.db.execute("INSERT INTO action VALUES (?,?,?,?,?,?,?,?,?,?)", (
                intent, actor, operation, canonical(args), "dispatched", now, now,
                canonical(chain), None, None))
            self.db.execute("INSERT INTO action_context VALUES (?,?,?,?,?)", (
                intent, self.controller_id, self.config["source_commit"], self.config["binary_sha256"],
                self.config["product_config_sha256"]))
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
            # Use an anonymous private file, rather than accumulating unbounded
            # stdout in memory or retaining raw potential secrets on disk.
            with tempfile.TemporaryFile(dir=self.root) as output, tempfile.TemporaryFile(dir=self.root) as errors:
                try:
                    result = subprocess.run([
                        self.config["binary"], "--quiet", "--no-logfile", "--datadir", str(path), *native_args,
                    ], stdin=subprocess.DEVNULL, stdout=output, stderr=errors,
                        env=environment, timeout=timeout, check=False)
                finally:
                    self._retain_private(intent, "stdout", output)
                    self._retain_private(intent, "stderr", errors)
                output.seek(0)
                raw = output.read(4 * 1024 * 1024 + 1)
            if result.returncode:
                self.db.execute("UPDATE action SET diagnostic=? WHERE id=?",
                                (f"NativeExit:{result.returncode}", intent))
                raise ValueError("native_nonzero_exit")
            reply = project_reply(operation, raw)
            public_payload(reply)
            self.db.execute("UPDATE action SET state='acknowledged',reply=?,updated=? WHERE id=?",
                            (canonical(reply), time.time(), intent))
        except Exception as error:
            # An exception, malformed reply or nonzero exit can follow a committed
            # payment. No speculative failure classification or second attempt.
            self.db.execute("UPDATE action SET state='unknown',diagnostic=COALESCE(diagnostic,?),updated=? WHERE id=?",
                            (type(error).__name__, time.time(), intent))
        return dict(self.db.execute("SELECT * FROM action WHERE id=?", (intent,)).fetchone())

    def abandon(self, actor: str):
        self.actor_path(actor)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            if self.db.execute("SELECT 1 FROM action WHERE actor=? AND state IN ('dispatched','unknown')", (actor,)).fetchone():
                raise ValueError("actor has an in-flight or unknown action; cannot declare absent")
            self.db.execute("INSERT OR IGNORE INTO actor(id) VALUES (?)", (actor,))
            self.db.execute("UPDATE actor SET absent=1 WHERE id=?", (actor,))
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def check_transfer(self, check_id: str, intent: str, sender_before: str, sender_after: str,
                       receiver_before: str, receiver_after: str, maximum_fee_sat: int):
        from .signet_checks import confirmed_backing, transfer_values
        names = [sender_before, sender_after, receiver_before, receiver_after]
        if len(set(names)) != 4:
            raise ValueError("four distinct wallet snapshot intents required")
        snapshots = []
        for name in names:
            row = self.db.execute("SELECT * FROM action WHERE id=?", (name,)).fetchone()
            if not row or row["state"] != "acknowledged" or row["operation"] not in {"vtxos", "sync_vtxos"}:
                raise ValueError("acknowledged native VTXO snapshot required")
            snapshots.append(row)
        payment = self.db.execute("SELECT * FROM action WHERE id=?", (intent,)).fetchone()
        if not payment or payment["operation"] != "send":
            raise ValueError("original send intent required")
        sb, sa, rb, ra = snapshots
        if (sb["actor"] != sa["actor"] or rb["actor"] != ra["actor"]
                or sb["actor"] == rb["actor"] or payment["actor"] != sb["actor"]
                or max(sb["updated"], rb["updated"]) > payment["created"]
                or min(sa["created"], ra["created"]) < payment["updated"]):
            raise ValueError("snapshots do not bracket an isolated two-wallet payment")
        arguments = json.loads(payment["arguments"])
        if not self.db.execute("""SELECT 1 FROM action WHERE actor=? AND operation='address'
            AND state='acknowledged' AND updated<=? AND json_extract(reply,'$.address')=?""", (
                rb["actor"], payment["created"], arguments["destination"])).fetchone():
            raise ValueError("payment destination not bound to the receiver's native address receipt")
        other = self.db.execute("""SELECT id FROM action
            WHERE actor IN (?,?) AND operation IN ('create','send','board','refresh','maintain')
              AND created>=? AND created<=? AND id!=?""", (
            sb["actor"], rb["actor"], min(sb["created"], rb["created"]),
            max(sa["updated"], ra["updated"]), intent)).fetchall()
        if other:
            raise ValueError("other monetary operations overlap the checkpoint")
        coins = [json.loads(row["reply"]) for row in snapshots]
        outcome = {"kind": "S01_transfer_observation", "intent": intent, "snapshots": names,
                   "native_state": payment["state"], "maximum_fee_sat": maximum_fee_sat,
                   "case_verdict": "NOT_EVALUATED"}
        try:
            outcome.update(transfer_values(*coins, arguments["amount_sat"], maximum_fee_sat))
            outcome.update(confirmed_backing(self.core, [coins[1], coins[3]]))
        except ValueError as error:
            outcome.update({"observation": "FAILED_OR_INCOMPLETE", "reason": str(error)})
        public_payload(outcome)
        self.db.execute("INSERT INTO result VALUES (?,?,?)", (check_id, time.time(), canonical(outcome)))
        return outcome

    def report(self) -> dict:
        rows = [dict(row) for row in self.db.execute("SELECT * FROM action ORDER BY created,id")]
        for row in rows:
            for key in ("arguments", "chain", "reply"):
                if row[key] is not None:
                    row[key] = json.loads(row[key])
        results = [json.loads(row[0]) for row in self.db.execute("SELECT payload FROM result ORDER BY observed,id")]
        cases = [result for result in results if result.get("kind") == "case_result"]
        return {"source_commit": self.config["source_commit"],
                "binary_sha256": self.config["binary_sha256"],
                "product_config_sha256": self.config["product_config_sha256"],
                "network": "public-signet", "actions": rows,
                "results": results, "cases": cases,
                "action_contexts": [dict(row) for row in self.db.execute("SELECT * FROM action_context ORDER BY intent")],
                "protected_artifacts": [dict(row) for row in self.db.execute(
                    "SELECT * FROM native_artifact ORDER BY intent,kind")],
                "case_verdict": "SEE_CASE_RESULTS" if cases else "NOT_EVALUATED",
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
    check = commands.add_parser("check-transfer")
    for field in ("check_id", "intent", "sender_before", "sender_after", "receiver_before", "receiver_after"):
        check.add_argument(field)
    check.add_argument("--maximum-fee-sat", type=int, required=True)
    funding = commands.add_parser("record-funding")
    funding.add_argument("actor")
    funding.add_argument("txid")
    funding.add_argument("index", type=int)
    s01 = commands.add_parser("s01-step")
    s01.add_argument("--board-sat", type=int, required=True)
    s01.add_argument("--transfer-sat", type=int, required=True)
    s01.add_argument("--maximum-fee-sat", type=int, required=True)
    args = parser.parse_args()
    campaign = Campaign(args.state, json.loads(args.config.read_text()))
    try:
        progress = None
        if args.command == "execute":
            campaign.execute(args.intent, args.actor, args.operation, args.arguments)
        elif args.command == "abandon":
            campaign.abandon(args.actor)
        elif args.command == "check-transfer":
            campaign.check_transfer(args.check_id, args.intent, args.sender_before, args.sender_after,
                                    args.receiver_before, args.receiver_after, args.maximum_fee_sat)
        elif args.command == "record-funding":
            from .signet_s01 import funding_receipt
            progress = funding_receipt(campaign, args.actor, args.txid, args.index)
        elif args.command == "s01-step":
            from .signet_s01 import S01
            progress = S01(campaign, board_sat=args.board_sat, transfer_sat=args.transfer_sat,
                           maximum_fee_sat=args.maximum_fee_sat).advance()
        report = campaign.report()
        if progress is not None:
            report["progress"] = progress
        print(json.dumps(report, indent=2))
    finally:
        campaign.close()


if __name__ == "__main__":
    main()

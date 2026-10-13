from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from contextlib import nullcontext
from pathlib import Path

from .model import InvariantError, SOURCES, canonical, fee_allocation, integer, public_payload, timestamp, transaction_fee

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS actor(id TEXT PRIMARY KEY, role TEXT NOT NULL, online INTEGER NOT NULL, details TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scenario(id TEXT PRIMARY KEY, description TEXT NOT NULL, implemented INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS action(
 id TEXT PRIMARY KEY, actor_id TEXT REFERENCES actor(id), scenario_id TEXT REFERENCES scenario(id),
 operation TEXT NOT NULL, args TEXT NOT NULL, state TEXT NOT NULL, due_at REAL NOT NULL,
 fee_reservation_sat INTEGER NOT NULL, actual_fee_sat INTEGER, result TEXT,
 created_at REAL NOT NULL, updated_at REAL NOT NULL);
CREATE INDEX IF NOT EXISTS action_queue ON action(state,due_at);
CREATE INDEX IF NOT EXISTS action_actor_history ON action(actor_id,created_at);
CREATE TABLE IF NOT EXISTS negative_check(action_id TEXT PRIMARY KEY,state TEXT NOT NULL,payload TEXT NOT NULL,updated_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS event(sequence INTEGER PRIMARY KEY, observed_at REAL NOT NULL,
 kind TEXT NOT NULL, payload TEXT NOT NULL, previous_hash TEXT NOT NULL, hash TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS snapshot(id INTEGER PRIMARY KEY, observed_at REAL NOT NULL, payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS snapshot_time ON snapshot(observed_at,id);
CREATE TABLE IF NOT EXISTS entitlement(id TEXT PRIMARY KEY, owner TEXT NOT NULL REFERENCES actor(id),
 source TEXT NOT NULL, gross_sat INTEGER NOT NULL, script TEXT NOT NULL, state TEXT NOT NULL,
 predecessor TEXT REFERENCES entitlement(id), evidence TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS payout(txid TEXT PRIMARY KEY, recipient_fee_sat INTEGER NOT NULL,
 operator_fee_sat INTEGER NOT NULL, transaction_data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS resolution(entitlement_id TEXT PRIMARY KEY REFERENCES entitlement(id),
 txid TEXT NOT NULL REFERENCES payout(txid), script TEXT NOT NULL, kind TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS observation(
 key TEXT PRIMARY KEY, severity TEXT NOT NULL, status TEXT NOT NULL, summary TEXT NOT NULL,
 evidence TEXT NOT NULL, first_seen REAL NOT NULL, last_seen REAL NOT NULL, occurrences INTEGER NOT NULL);
"""


class CampaignPaused(ValueError):
    """An atomic queue fence, including pauses committed by another process."""


class Store:
    def __init__(self, root: Path, mode: str, fee_budget_sat: int | None = None):
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if root.is_symlink():
            raise ValueError("state directory must not be a symlink")
        self.root = root
        self.trace = None
        self.db = sqlite3.connect(root / "state.sqlite", isolation_level=None)
        os.chmod(root / "state.sqlite", 0o600)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript(SCHEMA)
        from .ownership import initialize as initialize_ownership
        initialize_ownership(self)
        from .settlements import initialize as initialize_settlements
        initialize_settlements(self)
        from .entitlements import initialize as initialize_delegated_entitlements
        initialize_delegated_entitlements(self)
        previous = self.get_meta("mode")
        if previous is not None and previous != mode:
            self.close()
            raise ValueError("cannot mix synthetic and live evidence in one state directory")
        self.db.execute("INSERT OR IGNORE INTO meta VALUES ('mode',?)", (mode,))
        if fee_budget_sat is not None:
            integer(fee_budget_sat, "fee budget")
            previous_budget = self.get_meta("fee_budget_sat")
            if previous_budget is not None and int(previous_budget) != fee_budget_sat:
                raise ValueError("fee budget is immutable within an epoch; use a new state directory")
            self.db.execute("INSERT OR IGNORE INTO meta VALUES ('fee_budget_sat',?)", (str(fee_budget_sat),))

    def attach_trace(self, retention_days=30):
        if self.trace is None:
            from .trace import TraceStore
            self.trace=TraceStore(self.root,retention_days=retention_days)

    def trace_capture(self, kind, payload, *, actor=None, action_id=None, raw=None):
        if self.trace is not None:
            return self.trace.capture(kind,payload,actor=actor,action_id=action_id,raw=raw)

    def trace_sample(self, record):
        return self.trace_capture(record['kind'],record['payload'],raw=record.get('raw'))

    def close(self):
        if self.trace is not None:self.trace.close()
        self.db.close()

    def get_meta(self, key: str):
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def _event(self, kind: str, payload: dict):
        public_payload(payload)
        last = self.db.execute("SELECT sequence,hash FROM event ORDER BY sequence DESC LIMIT 1").fetchone()
        seq, previous = (last[0] + 1, last[1]) if last else (1, "0" * 64)
        at = time.time()
        serialized = canonical(payload)
        digest = hashlib.sha256(canonical([seq, at, kind, serialized, previous]).encode()).hexdigest()
        self.db.execute("INSERT INTO event VALUES (?,?,?,?,?,?)", (seq, at, kind, serialized, previous, digest))

    def event(self, kind: str, payload: dict):
        with self.transaction():
            self._event(kind, payload)
        if kind=='scheduler_tick':self.trace_capture('scheduler.tick',payload)

    def transaction(self):
        class Transaction:
            def __enter__(inner):
                self.db.execute("BEGIN IMMEDIATE")
            def __exit__(inner, kind, value, traceback):
                self.db.execute("ROLLBACK" if kind else "COMMIT")
        return Transaction()

    def register_catalog(self, catalog: list[dict], implemented: set[str]):
        with self.transaction():
            for case in catalog:
                self.db.execute("INSERT INTO scenario VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET implemented=excluded.implemented",
                                (case["id"], case["behavior"], case["id"] in implemented))

    def actor(self, actor_id: str, role: str):
        with self.transaction():
            self.db.execute("INSERT OR IGNORE INTO actor VALUES (?,?,1,'{}')", (actor_id, role))

    def set_online(self, actor_id: str, online: bool):
        with self.transaction():
            if self.db.execute("UPDATE actor SET online=? WHERE id=?", (online, actor_id)).rowcount != 1:
                raise ValueError("unknown actor")
            self._event("actor_online" if online else "actor_offline", {"actor": actor_id})

    def online(self, actor_id: str) -> bool:
        row = self.db.execute("SELECT online FROM actor WHERE id=?", (actor_id,)).fetchone()
        return bool(row[0]) if row else False

    def queue(self, action_id: str, actor: str, scenario: str, operation: str, args: dict,
              fee_reservation_sat: int, due_at: float | None = None):
        public_payload(args)
        if not isinstance(args, dict) or len(canonical(args).encode()) > 192 * 1024:
            raise ValueError("action arguments must be an object of at most 192 KiB")
        if not isinstance(action_id, str) or not 1 <= len(action_id) <= 128:
            raise ValueError("action id must contain 1–128 characters")
        integer(fee_reservation_sat, "fee reservation")
        at = time.time()
        due = at if due_at is None else timestamp(due_at, "action due time")
        with (nullcontext() if self.db.in_transaction else self.transaction()):
            if self.get_meta("paused"):
                raise CampaignPaused("campaign dispatch paused")
            if self.get_meta("fee_budget_sat") is None:
                raise ValueError("an explicit fee budget is required for actions")
            used = self.db.execute("SELECT COALESCE(SUM(COALESCE(actual_fee_sat,fee_reservation_sat)),0) FROM action WHERE state!='canceled'").fetchone()[0]
            if used + fee_reservation_sat > int(self.get_meta("fee_budget_sat")):
                raise ValueError("declared fee budget exhausted")
            self.db.execute("INSERT INTO action VALUES (?,?,?,?,?,'queued',?,?,NULL,NULL,?,?)",
                            (action_id, actor, scenario, operation, canonical(args), due,
                             fee_reservation_sat, at, at))
            self._event("action_intent", {"action_id": action_id, "actor": actor, "scenario": scenario,
                                          "operation": operation, "args": args, "fee_reservation_sat": fee_reservation_sat, "due_at": due})

    def claim(self, supported: set[str]):
        with self.transaction():
            if self.get_meta("paused"):
                return None
            rows = self.db.execute("SELECT a.* FROM action a JOIN actor u ON u.id=a.actor_id WHERE a.state='queued' AND a.due_at<=? AND u.online=1 ORDER BY a.due_at,a.id", (time.time(),)).fetchall()
            for row in rows:
                if row["operation"] not in supported:
                    continue
                busy = self.db.execute("SELECT 1 FROM action WHERE actor_id=? AND state IN ('dispatched','outcome_unknown')", (row["actor_id"],)).fetchone()
                if busy:
                    continue
                self.db.execute("UPDATE action SET state='dispatched',updated_at=? WHERE id=?", (time.time(), row["id"]))
                self._event("action_dispatched", {"action_id": row["id"], "actor": row["actor_id"]})
                result = dict(row)
                result["args"] = json.loads(result["args"])
                return result
        return None

    def remaining_fee_budget(self) -> int:
        used = self.db.execute("SELECT COALESCE(SUM(COALESCE(actual_fee_sat,fee_reservation_sat)),0) FROM action WHERE state!='canceled'").fetchone()[0]
        return int(self.get_meta("fee_budget_sat") or 0) - used

    def has_runnable_queue(self) -> bool:
        return self.db.execute("""SELECT 1 FROM action a JOIN actor u ON u.id=a.actor_id
            WHERE a.state='queued' AND u.online=1 AND a.due_at<=?
            AND NOT EXISTS(SELECT 1 FROM action b WHERE b.actor_id=a.actor_id
                           AND b.state IN ('dispatched','outcome_unknown')) LIMIT 1""", (time.time(),)).fetchone() is not None

    def finish(self, action_id: str, state: str, result: dict, actual_fee_sat: int | None = None, on_completed=None):
        if state not in {"completed", "expected_refusal", "blocked", "failed", "outcome_unknown"}:
            raise ValueError("invalid action terminal state")
        public_payload(result)
        if actual_fee_sat is not None:
            integer(actual_fee_sat, "actual fee")
        with self.transaction():
            row = self.db.execute("SELECT * FROM action WHERE id=?", (action_id,)).fetchone()
            if row is None or row["state"] != "dispatched":
                raise ValueError("only a dispatched action may finish")
            if actual_fee_sat is not None and actual_fee_sat > row["fee_reservation_sat"]:
                state = "failed"
                result = {**result, "incident": "fee exceeds declared action reserve"}
            self.db.execute("UPDATE action SET state=?,result=?,actual_fee_sat=?,updated_at=? WHERE id=?",
                            (state, canonical(result), actual_fee_sat, time.time(), action_id))
            if state == "completed" and on_completed is not None:
                on_completed()
            self._event("action_result", {"action_id": action_id, "state": state, "result": result, "actual_fee_sat": actual_fee_sat})
            if state == "failed":
                self.db.execute("INSERT OR REPLACE INTO meta VALUES ('paused','incident')")

    def recover_dispatched(self):
        with self.transaction():
            rows = self.db.execute("SELECT id FROM action WHERE state='dispatched'").fetchall()
            for row in rows:
                self.db.execute("UPDATE action SET state='outcome_unknown',updated_at=? WHERE id=?", (time.time(), row[0]))
                self._event("restart_unknown_outcome", {"action_id": row[0]})
        return len(rows)

    def add_snapshot(self, snapshot: dict):
        public_payload(snapshot)
        timestamp(snapshot["observed_at"], "snapshot time")
        for name in ("rounds_confirmed_sat", "rounds_trusted_sat", "rounds_untrusted_sat", "rounds_unconfirmed_sat",
                     "tree_locked_sat", "watchman_confirmed_sat", "ln_spendable_msat", "ln_receivable_msat"):
            if snapshot.get(name) is not None:
                integer(snapshot[name], name)
        with self.transaction():
            self.db.execute("INSERT INTO snapshot(observed_at,payload) VALUES (?,?)", (snapshot["observed_at"], canonical(snapshot)))
            self._event("snapshot", snapshot)

    def bind_target(self, identity: dict):
        """Require the original deployment or an explicitly qualified epoch."""
        public_payload(identity)
        encoded = canonical(identity)
        with self.transaction():
            from .target_epochs import active_identity
            previous = active_identity(self)
            if previous is not None and canonical(previous) != encoded:
                raise ValueError("target changed without a verified same-campaign epoch declaration")
            if previous is None:
                self.db.execute("INSERT INTO meta VALUES ('target_identity',?)", (encoded,))
                self._event("target_manifest", identity)

    def bind_wallet_root(self, root: Path):
        value = str(root.resolve())
        existing = self.get_meta("wallet_root")
        if existing is not None and existing != value:
            raise ValueError("wallet root changed within epoch; use a new state directory")
        if existing is None:
            with self.transaction():
                self.db.execute("INSERT INTO meta VALUES ('wallet_root',?)", (value,))
                self._event("wallet_root_manifest", {"wallet_root":value})

    def add_entitlement(self, coin_id: str, owner: str, source: str, gross_sat: int,
                        script: str, evidence: dict, predecessor: str | None = None):
        if source not in SOURCES:
            raise ValueError("unknown payout source")
        integer(gross_sat, "gross amount", 1)
        public_payload(evidence)
        with self.transaction():
            if predecessor is not None:
                row = self.db.execute("SELECT * FROM entitlement WHERE id=?", (predecessor,)).fetchone()
                if row is None or row["state"] != "live" or row["owner"] != owner:
                    raise InvariantError("invalid replacement predecessor")
                if gross_sat > row["gross_sat"]:
                    raise InvariantError("replacement creates value")
                self.db.execute("UPDATE entitlement SET state='replaced' WHERE id=?", (predecessor,))
            self.db.execute("INSERT INTO entitlement VALUES (?,?,?,?,?,'live',?,?)",
                            (coin_id, owner, source, gross_sat, script, predecessor, canonical(evidence)))
            self._event("entitlement", {"id": coin_id, "owner": owner, "source": source,
                                         "gross_sat": gross_sat, "script": script, "predecessor": predecessor})

    def record_payout(self, tx: dict, coin_ids: list[str], recipient_fee_sat: int, operator_fee_sat: int):
        """Check supplied amounts/scripts; chain inclusion and seed recovery need separate evidence."""
        integer(operator_fee_sat, "operator fee")
        if not coin_ids or len(coin_ids) != len(set(coin_ids)):
            raise InvariantError("payout input entitlement list is empty or duplicated")
        public_payload(tx)
        if transaction_fee(tx) != recipient_fee_sat + operator_fee_sat:
            raise InvariantError("payout mining fee does not reconcile")
        with self.transaction():
            existing = self.db.execute("SELECT * FROM payout WHERE txid=?", (tx["txid"],)).fetchone()
            if existing is not None:
                resolved = {row[0] for row in self.db.execute("SELECT entitlement_id FROM resolution WHERE txid=?", (tx["txid"],))}
                if (existing["transaction_data"] == canonical(tx) and existing["recipient_fee_sat"] == recipient_fee_sat
                        and existing["operator_fee_sat"] == operator_fee_sat and resolved == set(coin_ids)):
                    return # Identical observation replay is not a second payment.
                raise InvariantError("contradictory evidence for an existing payout")
            gross: dict[str, int] = {}
            rows = []
            for coin_id in coin_ids:
                row = self.db.execute("SELECT * FROM entitlement WHERE id=?", (coin_id,)).fetchone()
                if row is None or row["state"] != "live":
                    raise InvariantError("payout resolves an unknown or already resolved entitlement")
                rows.append(row)
                gross[row["script"]] = gross.get(row["script"], 0) + row["gross_sat"]
            shares = fee_allocation(gross, recipient_fee_sat)
            for script, amount in gross.items():
                matching = [o for o in tx["outputs"] if o["script"] == script]
                if len(matching) != 1 or matching[0]["amount_sat"] != amount - shares[script]:
                    raise InvariantError("wrong destination or net amount in payout")
            self.db.execute("INSERT INTO payout VALUES (?,?,?,?)", (tx["txid"], recipient_fee_sat, operator_fee_sat, canonical(tx)))
            for row in rows:
                self.db.execute("INSERT INTO resolution VALUES (?,?,?,'expiry_payout')", (row["id"], tx["txid"], row["script"]))
                self.db.execute("UPDATE entitlement SET state='paid' WHERE id=?", (row["id"],))
            self._event("payout_amounts_checked", {"txid": tx["txid"], "coin_ids": coin_ids,
                "recipient_fee_sat": recipient_fee_sat, "operator_fee_sat": operator_fee_sat,
                "validation_scope":"amounts and scripts only; chain inclusion and seed recovery unverified"})

    def export_events(self, full: bool = True):
        if full:
            from .export_bundle import export_event_days
            return export_event_days(self)
        name = "events.jsonl" if full else "events-recent.jsonl"
        temp = self.root / (name + ".tmp")
        query = "SELECT * FROM event ORDER BY sequence" if full else "SELECT * FROM (SELECT * FROM event ORDER BY sequence DESC LIMIT 2000) ORDER BY sequence"
        with temp.open("w", encoding="utf-8") as file:
            for row in self.db.execute(query):
                file.write(canonical({**dict(row), "payload": json.loads(row["payload"])}) + "\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temp, self.root / name)

    def verify_event_chain(self):
        previous = "0" * 64
        for expected, row in enumerate(self.db.execute("SELECT * FROM event ORDER BY sequence"), 1):
            digest = hashlib.sha256(canonical([row["sequence"], row["observed_at"], row["kind"], row["payload"], previous]).encode()).hexdigest()
            if row["sequence"] != expected or row["previous_hash"] != previous or row["hash"] != digest:
                raise InvariantError("event chain is damaged")
            previous = digest
        return previous

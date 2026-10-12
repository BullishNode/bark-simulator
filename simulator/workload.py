"""Initial funded pilot: no treasury credentials, no hidden funding or top-ups."""
from __future__ import annotations

import json
import time
from contextlib import nullcontext

from .config import Config
from .model import integer
from .store import Store
from .raw_cases import next_case


def schedule_pilot(store: Store, config: Config):
    if store.get_meta("paused"):
        return
    if store.has_runnable_queue() or store.db.execute("SELECT 1 FROM action WHERE state='dispatched' LIMIT 1").fetchone():
        return
    last = store.db.execute("SELECT MAX(created_at) FROM action").fetchone()[0]
    if last is not None and time.time() - last < config.interval_seconds:
        return
    next_action = None
    budget = store.remaining_fee_budget()
    # Least-recently-served actor first prevents cold wallets starving behind syncs.
    rows = store.db.execute("SELECT u.* FROM actor u WHERE online=1 ORDER BY COALESCE((SELECT MAX(updated_at) FROM action WHERE actor_id=u.id),0),u.id").fetchall()
    for row in rows:
        actor = row["id"]
        details = json.loads(row["details"])
        history = store.db.execute("SELECT operation,state,updated_at FROM action WHERE actor_id=? ORDER BY created_at DESC", (actor,)).fetchall()
        if any(a["state"] in {"outcome_unknown", "queued"} for a in history):
            continue
        if not details.get("created"):
            if history and history[0]["state"] in {"blocked", "failed"}:
                continue
            next_action = (actor, "H01", "create", {}, 0)
            break
        if not details.get("ark_address"):
            next_action = (actor, "H07", "address", {}, 0)
            break
        if actor in {"actor-09", "actor-10"} and details.get("registered_spendable_sat", 0) > 0:
            store.set_online(actor, False)
            store.event("pilot_absence_armed", {"actor": actor, "scenario": "H03", "coins": details.get("coin_ids", [])})
            continue
        confirmed = details.get("onchain_confirmed_sat", 0)
        if (budget >= config.action_fee_reserve_sat and not details.get("board_submitted")
                and confirmed >= config.board_amount_sat + config.action_fee_reserve_sat):
            blocked = any(a["operation"] == "board" and a["state"] == "blocked" for a in history[:3])
            if not blocked:
                next_action = (actor, "H01", "board", {"amount_sat": config.board_amount_sat}, config.action_fee_reserve_sat)
                break
        if (budget >= config.action_fee_reserve_sat and actor in {"actor-02", "actor-03"}
                and details.get("registered_spendable_sat", 0) >= 1000 + config.action_fee_reserve_sat):
            previous = [a["updated_at"] for a in history if a["operation"] == "send_arkoor"]
            if not previous or time.time() - max(previous) >= 900:
                target = "actor-09" if len(previous) % 2 else "actor-01"
                recipient = store.db.execute("SELECT details FROM actor WHERE id=?", (target,)).fetchone()
                destination = json.loads(recipient[0]).get("ark_address")
                if destination:
                    next_action = (actor, "H08" if target == "actor-09" else "H07", "send_arkoor",
                                   {"destination": destination, "amount_sat": 1000}, config.action_fee_reserve_sat)
                    break
        if actor in {"actor-11", "actor-12"}:
            previous = [a["updated_at"] for a in history if a["operation"].startswith("raw_")]
            if not previous or time.time() - max(previous) >= 600:
                scenario, op, args = next_case(store, actor, len(previous))
                next_action = (actor, scenario, op, args, 0)
                break
        # Previously, a 5-minute snapshot check came before funded work. With
        # twelve serial actors and a 30-second tick, every snapshot had become
        # stale on the actor's next turn, so boards and payments never ran.
        # SDK mutations still recheck funds/fees before signing or submitting.
        if time.time() - details.get("snapshot_at", 0) > 300:
            operation = "sync" if details.get("needs_sync") else "snapshot"
            if operation == "sync" and budget < config.action_fee_reserve_sat:
                operation = "snapshot"
            next_action = (actor, "H01", operation, {}, config.action_fee_reserve_sat if operation == "sync" else 0)
            break
    if next_action is None:
        return
    actor, scenario, operation, args, fee = next_action
    seq = store.db.execute("SELECT COUNT(*) FROM action").fetchone()[0] + 1
    try:
        store.queue(f"pilot-{seq:08}", actor, scenario, operation, args, fee)
    except ValueError:
        if not store.get_meta("budget_stop_recorded"):
            store.event("pilot_budget_stop", {"reason": "no additional funded work fits the declared fee budget"})
            store.db.execute("INSERT OR REPLACE INTO meta VALUES ('budget_stop_recorded','true')")


def record_actor_result(store: Store, actor: str, operation: str, data: dict):
    with (nullcontext() if store.db.in_transaction else store.transaction()):
        row = store.db.execute("SELECT details FROM actor WHERE id=?", (actor,)).fetchone()
        details = json.loads(row[0])
        if operation == "create":
            for key in ("funding_address", "fallback_script"):
                if not isinstance(data[key], str) or not data[key]:
                    raise ValueError("missing wallet identity evidence")
            integer(data["fallback_seq"], "fallback sequence")
            details.update(created=True, needs_sync=True, **{k: data[k] for k in ("funding_address", "fallback_script", "fallback_seq", "binding") if k in data})
        elif operation == "address":
            details["ark_address"] = data["address"]
            if "binding" in data:
                details["advertised_key_proof"]={k:data[k] for k in ("user_pubkey","key_link_attestation","binding")}
        elif operation == "snapshot":
            details["snapshot_at"] = time.time()
            details["registered_spendable_sat"] = integer(data["balance"]["spendable_sat"], "client spendable balance")
            details["onchain_confirmed_sat"] = integer(data["onchain"]["confirmed_sat"], "client confirmed balance")
            details["coin_ids"] = [v["id"] for v in data["vtxos"]]
            if any(not isinstance(coin, str) or not coin for coin in details["coin_ids"]):
                raise ValueError("invalid coin identity evidence")
            # A read-only snapshot must not invent another synchronization debt.
            # Mutations, incoming transfers and declared grants set this flag.
            details["needs_sync"] = details.get("needs_sync", False)
        elif operation == "sync":
            details["needs_sync"] = False
            details["snapshot_at"] = 0
        elif operation == "board":
            details["board_submitted"] = True
            details["snapshot_at"] = 0
            details["needs_sync"] = True
        elif operation in {"send_arkoor","refresh","refresh_delegated","offboard_all","pay_invoice"}:
            details["snapshot_at"] = 0
            details["needs_sync"] = True
        elif operation == "invoice":
            details["latest_invoice"] = data["invoice"]
            details["invoice_at"] = time.time()
            details["needs_sync"] = True
        store.db.execute("UPDATE actor SET details=? WHERE id=?", (json.dumps(details), actor))

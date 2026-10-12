"""Repeatable observations from recorded facts; never a payout/solvency oracle."""
from __future__ import annotations

import json
import time

from .model import canonical
from .store import Store


def observe(store: Store):
    findings = {}
    row = store.db.execute("SELECT id,payload FROM snapshot ORDER BY id DESC LIMIT 1").fetchone()
    snapshot = json.loads(row["payload"]) if row else {}
    ref = {"snapshot_id": row["id"] if row else None}
    ready = False

    def add(key, severity, summary, **evidence):
        findings[key] = (severity, summary, {**ref, **evidence})

    if snapshot.get("error"):
        add("observer_gap", "warning", "Observation failed; client dispatch was held.", reason=snapshot["error"])
    elif row:
        ready = (snapshot.get("stable_tip") is True and snapshot.get("initial_block_download") is False
                 and snapshot.get("server_status",{}).get("status") == "running"
                 and 0 <= time.time()-snapshot["observed_at"] <= 90)
        if not ready:
            add("dispatch_readiness", "warning", "This snapshot cannot authorize client actions: freshness, stable chain or server readiness is unverified.",
                stable_tip=snapshot.get("stable_tip"), initial_block_download=snapshot.get("initial_block_download"),
                server_status=snapshot.get("server_status",{}).get("status"), observed_at=snapshot["observed_at"])
        if snapshot.get("complete") is not True:
            add("capital_incomplete", "warning", "Operator capital requirements cannot be established from these measurements.",
                unknown_buckets=snapshot.get("unknown_buckets", ["full capital attribution"]))
        if snapshot.get("capabilities", {}).get("lightning_configured") is False:
            add("lightning_unconfigured", "warning", "The target has no configured Lightning node; Lightning behavior is untested.")
        if snapshot.get("stable_tip") is False:
            add("chain_changed", "info", "The chain tip changed during collection; this is not a stable accounting snapshot.")
        if snapshot.get("initial_block_download") is True:
            add("chain_initial_sync", "warning", "The chain node is still in initial sync; client dispatch is held.")
        status = snapshot.get("server_status", {}).get("status")
        if status is not None and status != "running":
            add("server_unavailable", "warning", "The target container is not running; client dispatch is held.", status=status)
        if snapshot.get("confirmed_inventory_gap"):
            add("confirmed_inventory_gap", "warning", "Confirmed rounds liquidity is unknown for this sample.",
                reason=snapshot["confirmed_inventory_gap"])

    previous = store.db.execute("SELECT id,payload FROM snapshot ORDER BY id DESC LIMIT 1 OFFSET 1").fetchone()
    if previous:
        earlier = json.loads(previous["payload"])
        before, after = earlier.get("rounds_confirmed_sat"), snapshot.get("rounds_confirmed_sat")
        if before is not None and after is not None and before != after:
            add("rounds_balance_change", "info", "Observed confirmed rounds balance changed; the cause is not yet attributed.",
                previous_snapshot_id=previous["id"], before_sat=before, after_sat=after, change_sat=after-before)

    if store.get_meta("paused"):
        add("campaign_paused", "critical", "The campaign is paused after an incident; no new client action may be dispatched.")
    remaining = store.remaining_fee_budget()
    if remaining <= 0:
        add("fee_budget_exhausted", "warning", "The declared fee budget has no remaining headroom; observations can continue.",
            remaining_sat=remaining)
    for action in store.db.execute("SELECT id,actor_id,operation FROM action WHERE state='outcome_unknown'"):
        add("unknown:"+action["id"], "warning", "A client action has an unknown outcome; this actor is blocked from further actions.",
            action_id=action["id"], actor=action["actor_id"], operation=action["operation"])
    unresolved = store.db.execute("""SELECT COUNT(*),COALESCE(SUM(fee_reservation_sat),0)
        FROM action WHERE state='completed' AND actual_fee_sat IS NULL""").fetchone()
    if unresolved[0]:
        add("fees_unreconciled", "warning", "Completed actions still have unverified costs; their fee reservations remain committed.",
            actions=unresolved[0], reserved_sat=unresolved[1])
    pending=store.db.execute("SELECT COUNT(*) FROM negative_check WHERE state='pending'").fetchone()[0]
    if pending:
        add('negative_checks_pending','warning','Negative requests still need independent post-request record and link verification.',actions=pending)
    for actor in store.db.execute("SELECT id,details FROM actor WHERE online=0"):
        details = json.loads(actor["details"])
        add("absent:"+actor["id"], "info", "Client is offline. Last observed coins are not proof of a current balance or successful payout.",
            actor=actor["id"], last_coin_ids=details.get("coin_ids", []), last_snapshot_at=details.get("snapshot_at"),
            payout_verification="not implemented")
    minimum = snapshot.get("timings", {}).get("min_payout_sat")
    if type(minimum) is int and minimum > 0:
        for group in store.db.execute("SELECT script,SUM(gross_sat) gross FROM entitlement WHERE state='live' GROUP BY script"):
            if group["gross"] < minimum:
                add("below_minimum:"+group["script"], "warning", "Known gross entitlement is below the configured net payout minimum; automatic payment cannot be qualified.",
                    script=group["script"], gross_sat=group["gross"], min_payout_sat=minimum)

    from .round_adoption import observation_findings,observation_can_clear
    for finding in observation_findings(store,snapshot):
        key=finding.pop('key')
        summary=('Confirmed refresh cannot be adopted within the SDK exit safety window.'
            if key.startswith('round_adoption_security_window:') else
            'A frozen refresh replacement remains unclaimed close to its expiry.')
        add(key,'warning',summary,**finding)

    # Only lifecycle transitions add events. Repeated checks update last_seen and
    # retain the latest evidence without flooding the log with the same warning.
    now = time.time()
    with store.transaction():
        for key, (severity, summary, evidence) in findings.items():
            existing = store.db.execute("SELECT * FROM observation WHERE key=?", (key,)).fetchone()
            encoded = canonical(evidence)
            if existing is None:
                store.db.execute("INSERT INTO observation VALUES (?,?,'active',?,?,?,?,1)",
                    (key,severity,summary,encoded,now,now))
            else:
                store.db.execute("UPDATE observation SET severity=?,status='active',summary=?,evidence=?,last_seen=?,occurrences=occurrences+1 WHERE key=?",
                    (severity,summary,encoded,now,key))
            if existing is None or existing["status"] != "active" or existing["summary"] != summary:
                store._event("observation_opened", {"key":key,"severity":severity,"summary":summary,"evidence":evidence})
        for existing in store.db.execute("SELECT key FROM observation WHERE status='active'").fetchall():
            if existing["key"] not in findings:
                can_clear = {
                    "capital_incomplete":snapshot.get("complete") is True,
                    "lightning_unconfigured":snapshot.get("capabilities",{}).get("lightning_configured") is True,
                    "chain_changed":snapshot.get("stable_tip") is True,
                    "chain_initial_sync":snapshot.get("initial_block_download") is False,
                    "server_unavailable":snapshot.get("server_status",{}).get("status") == "running",
                    "confirmed_inventory_gap":snapshot.get("rounds_confirmed_sat") is not None,
                    "dispatch_readiness":ready,
                }
                if existing['key'].startswith(('round_unclaimed_near_expiry:','round_adoption_security_window:')) and not observation_can_clear(store,existing['key'],snapshot):
                    continue
                if can_clear.get(existing["key"]) is False:
                    continue # Missing evidence cannot establish that a problem was fixed.
                if existing["key"].startswith("below_minimum:") and type(minimum) is not int:
                    continue
                store.db.execute("UPDATE observation SET status='cleared',last_seen=? WHERE key=?", (now,existing["key"]))
                store._event("observation_cleared", {"key":existing["key"],"evidence":ref})


def recorded_observations(store: Store) -> list[dict]:
    return [{**dict(row), "evidence": json.loads(row["evidence"])}
            for row in store.db.execute("SELECT * FROM observation ORDER BY status,key")]

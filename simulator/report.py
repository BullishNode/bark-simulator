from __future__ import annotations

import csv
import html
import json
import os
from pathlib import Path

from .model import capital_summary
from .observations import observe, recorded_observations
from .store import Store
from .continuous import absence_report
from .recycling import report as recycling_report


def atomic_text(path: Path, text: str):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as file:
        file.write(text)
        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary, path)


def generate(store: Store, full: bool = False, evaluate: bool = True) -> dict:
    if full:
        store.verify_event_chain()
    if evaluate:
        observe(store)
    snapshot_query = "SELECT payload FROM snapshot ORDER BY observed_at,id" if full else "SELECT payload FROM (SELECT * FROM snapshot ORDER BY observed_at DESC,id DESC LIMIT 1440) ORDER BY observed_at,id"
    action_query = "SELECT * FROM action ORDER BY created_at,id" if full else "SELECT * FROM (SELECT * FROM action ORDER BY created_at DESC,id DESC LIMIT 2000) ORDER BY created_at,id"
    snapshots = [json.loads(r[0]) for r in store.db.execute(snapshot_query)]
    fields = ("id","actor_id","scenario_id","operation","state","fee_reservation_sat","actual_fee_sat")
    actions = [{key:r[key] for key in fields} for r in store.db.execute(action_query)]
    counts = {(r[0],r[1]):r[2] for r in store.db.execute("SELECT scenario_id,state,COUNT(*) FROM action GROUP BY scenario_id,state")}
    coverage = []
    for row in store.db.execute("SELECT * FROM scenario ORDER BY id"):
        states = {state:count for (scenario,state),count in counts.items() if scenario == row["id"]}
        coverage.append({"id": row["id"], "behavior": row["description"],
                         "driver_available": bool(row["implemented"]), "actions": sum(states.values()),
                         "action_states": states,
                         "scenario_verdict": "not_qualified" if states else "not_exercised"})
    liabilities = [dict(r) for r in store.db.execute("SELECT owner,source,state,SUM(gross_sat) AS amount_sat,COUNT(*) AS coins FROM entitlement GROUP BY owner,source,state")]
    fees = store.db.execute("SELECT COALESCE(SUM(recipient_fee_sat),0),COALESCE(SUM(operator_fee_sat),0) FROM payout").fetchone()
    known_fees, unresolved = store.db.execute("SELECT COALESCE(SUM(actual_fee_sat),0),COALESCE(SUM(CASE WHEN actual_fee_sat IS NULL THEN fee_reservation_sat ELSE 0 END),0) FROM action WHERE state!='canceled'").fetchone()
    last = store.db.execute("SELECT hash FROM event ORDER BY sequence DESC LIMIT 1").fetchone()
    tip = last[0] if last else "0" * 64
    result = {
        "mode": store.get_meta("mode"), "capital": capital_summary(json.loads(r[0]) for r in store.db.execute("SELECT payload FROM snapshot ORDER BY observed_at,id")),
        "target_identity": json.loads(store.get_meta("target_identity") or "null"),
        "paused": store.get_meta("paused"), "actors": [{**dict(r), "details": json.loads(r["details"])} for r in store.db.execute("SELECT id,role,online,details FROM actor ORDER BY id")],
        "actions": actions, "coverage": coverage, "entitlements": liabilities,
        "permanent_receive_absences":absence_report(store),
        "capital_recycling":recycling_report(store),
        "owner_funded_renewal":{kind:[json.loads(r[0]) for r in store.db.execute('SELECT payload FROM event WHERE kind=? ORDER BY sequence',(kind,))]
            for kind in ['owner_renewal_allocation_intent','owner_renewal_confirmed','owner_renewal_board_intent']},
        "ownership_evidence": {"verified_keys":store.db.execute("SELECT COUNT(*) FROM owner_key").fetchone()[0],
             "negative_binding_checks":[dict(r) for r in store.db.execute('SELECT action_id,state,updated_at FROM negative_check ORDER BY updated_at')],
             "verified_coins":store.db.execute("SELECT COUNT(*) FROM owned_coin").fetchone()[0],
             "pending_candidates":store.db.execute("SELECT COUNT(*) FROM client_coin_candidate WHERE verified=0").fetchone()[0],
             "settlement_checks":[dict(r) for r in store.db.execute("SELECT * FROM settlement_check ORDER BY txid")],
             "scope":"public signatures/backing and amount checks; full source/seed recovery qualification remains separate"},
        "campaign": {"active_seconds":float(store.get_meta("campaign_active_seconds") or "0"),"ramp_applied":store.get_meta("ramp_applied")=="true"},
        "payout_recipient_fees_sat": fees[0], "payout_operator_change_fees_sat": fees[1],
        "fee_budget_sat": int(store.get_meta("fee_budget_sat") or 0),
        "known_action_fees_sat": known_fees, "unreconciled_action_fee_reserves_sat": unresolved,
        "event_chain_tip": tip, "observations": recorded_observations(store),
        "report_scope": {"epoch_totals":True, "complete_event_export":full,
                         "snapshot_rows":len(snapshots), "action_rows":len(actions),
                         "detail_limits": None if full else {"snapshots":1440,"actions":2000,"events":2000}},
        "limitations": ["Action completion is not a full scenario pass.",
                        "Absent/unknown capital buckets remain unknown, not zero.",
                        "No minimum capital or thousands-user capacity is established by these observations.",
                        "Live payout-source qualification and seed-only restore are separate evidence gates."],
    }
    atomic_text(store.root / "report.json", json.dumps(result, indent=2) + "\n")
    atomic_text(store.root / "observations.json", json.dumps(result["observations"], indent=2) + "\n")
    mode = "SYNTHETIC DEMONSTRATION — NOT SIGNET EVIDENCE" if result["mode"] == "synthetic" else "LIVE OBSERVATIONS — QUALIFICATION INCOMPLETE"
    summary = "\n".join(f"- {key}: {value if value is not None else 'unknown'}" for key, value in result["capital"].items())
    markdown = f"# Bark operator report\n\n**{mode}**\n\n{summary}\n\n"
    markdown += f"Known payout recipient fees: {fees[0]} sat. Operator change fees: {fees[1]} sat.\n\n"
    markdown += "Observations (facts and missing evidence, not scenario verdicts):\n\n"
    markdown += "\n".join(f"- [{o['severity']}, {o['status']}] {o['summary']} Evidence: {json.dumps(o['evidence'],sort_keys=True)}" for o in result["observations"]) + "\n\n"
    markdown += "Permanent receive absences (ordinary users; payout/recovery qualification stays explicit):\n\n"
    markdown += "\n".join(f"- {a['actor']}: {a['rail']} received {a['received_sat']} sat, permanently offline; {a['payout_verdict']}; {len(a['waiting_coin_ids'])} received coins waiting" for a in result["permanent_receive_absences"]) + "\n\n"
    markdown += "Coverage lists 80 behaviors; available drivers and action results do not certify complete scenarios.\n\n"
    markdown += "\n".join(f"- {c['id']}: {c['scenario_verdict']}; {c['actions']} action(s)" for c in coverage) + "\n"
    atomic_text(store.root / "report.md", markdown)
    rows = "".join(f"<tr><td>{c['id']}</td><td>{html.escape(c['behavior'])}</td><td>{c['actions']}</td><td>{c['scenario_verdict']}</td></tr>" for c in coverage)
    actor_rows = "".join(f"<tr><td>{html.escape(a['id'])}</td><td>{html.escape(a['role'])}</td><td>{'online' if a['online'] else 'offline'}</td><td>{html.escape(a['details'].get('funding_address', 'not created'))}</td></tr>" for a in result["actors"])
    samples = [s for s in snapshots if s.get("rounds_confirmed_sat") is not None]
    chart = "<p>No confirmed-liquidity observations.</p>"
    if samples:
        from datetime import datetime, timezone
        high = max(1, max(s["rounds_confirmed_sat"] for s in samples))
        start, end = snapshots[0]["observed_at"], snapshots[-1]["observed_at"]
        span = max(1, end-start)
        segments, points = [], []
        for snapshot in snapshots:
            if snapshot.get("rounds_confirmed_sat") is None:
                if points:
                    segments.append(points)
                    points = []
                continue
            points.append((20+(snapshot["observed_at"]-start)*760/span,
                           190-snapshot["rounds_confirmed_sat"]*160/high))
        if points:
            segments.append(points)
        lines = ""
        for segment in segments:
            coordinates = " ".join(f"{x:.2f},{y:.2f}" for x,y in segment)
            lines += f'<polyline points="{coordinates}" fill="none" stroke="#2761af" stroke-width="3"/>'
            if len(segment) == 1:
                x,y = segment[0]
                lines += f'<circle cx="{x:.2f}" cy="{y:.2f}" r="3" fill="#2761af"/>'
        def label(value):
            try:
                return datetime.fromtimestamp(value, timezone.utc).strftime("%m-%d %H:%M UTC")
            except (ValueError,OverflowError,OSError):
                return "timestamp out of range"
        chart = f'<svg viewBox="0 0 800 220" role="img" aria-label="Confirmed rounds balance over UTC time; missing samples break the line"><text x="20" y="20">{high} sats</text>{lines}<text x="20" y="215">{label(start)}</text><text x="610" y="215">{label(end)}</text></svg>'
    observations_html = "".join(f"<li><strong>{html.escape(o['severity'])} / {o['status']}</strong>: {html.escape(o['summary'])}<br><code>{html.escape(json.dumps(o['evidence'],sort_keys=True))}</code></li>" for o in result["observations"])
    document = f"""<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>
<title>Bark operator observations</title><style>body{{font:16px system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem}}table{{border-collapse:collapse;width:100%}}td,th{{padding:.6rem;border-bottom:1px solid #ccc;text-align:left}}pre{{white-space:pre-wrap}}.banner{{padding:1rem;background:#fff0bd}}</style>
<h1>Bark operator observations</h1><p class=banner>{mode}</p><h2>Capital</h2><pre>{html.escape(summary)}</pre>
{chart}
<p>Minimum required capital: unknown. A funded successful run does not prove a minimum.</p>
<h2>Observations</h2><ul>{observations_html}</ul>
<p>Capital, fee and behavior counts cover the epoch. Chart, CSV, action and event details may be bounded; use the report command for a full export.</p>
<h2>Actors</h2><table><tr><th>Owner</th><th>Role</th><th>Status</th><th>Fixture funding address</th></tr>{actor_rows}</table>
<h2>Behavior catalogue</h2><p>Action results do not establish complete scenario qualification.</p><table><tr><th>ID</th><th>Behavior</th><th>Actions</th><th>Verdict</th></tr>{rows}</table></html>"""
    atomic_text(store.root / "index.html", document)
    temp = store.root / "capital.csv.tmp"
    with temp.open("w", newline="", encoding="utf-8") as file:
        fields = ["observed_at", "height", "complete", "rounds_confirmed_sat", "rounds_unconfirmed_sat", "tree_locked_sat", "watchman_confirmed_sat", "ln_spendable_msat", "ln_receivable_msat"]
        writer = csv.DictWriter(file, fields)
        writer.writeheader()
        for snapshot in snapshots:
            writer.writerow({key: snapshot.get(key) for key in fields})
    os.replace(temp, store.root / "capital.csv")
    store.export_events(full=full)
    return result

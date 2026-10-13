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
from .raw_cases import RAW_CASES
from .raw_protocol import scenario_rows as protocol_scenario_rows
from .recovery import report as recovery_report
from .padding import report as padding_report, csv_values as padding_csv_values
from .entitlements import unclaimed_expired_report
from .fee_watch import report as fee_watch_report, csv_values as fee_watch_csv_values


# Primitive operations can exercise part of a behavior. Their availability and
# accounting evidence never imply that its full expected outcome is qualified.
SCENARIO_OPERATIONS = {
    'H29': {'fallback_rotate'},
    'D17': {'phase_execute_d17'}, 'D24': {'phase_register_saved'},
    'H01': {'board'}, 'H02': {'board'}, 'H03': {'board'},
    'H04': {'board'}, 'H06': {'board'},
    **{case:{'send_arkoor'} for case in
       ('H07','H08','H09','H10','H11','H12','H30','H32','D37')},
    **{case:{'refresh'} for case in ('H17','H18','H19')},
    'H20': {'refresh_delegated','refresh_scheduled'},
    **{case:{'sync'} for case in ('H23','H24','H25','H31')},
    'H26': {'seed_recovery'},
    'H28': {'create'}, 'H33': {'offboard_all'}, 'H34': {'exit'},
    'H35': {'pay_invoice'}, 'H36': {'pay_invoice'}, 'H37': {'invoice','sync'},
    'H40': {'invoice','pay_invoice','sync'},
    **{case:{operation} for operation,case in RAW_CASES.items()},
}

# One SQL aggregate covers epoch totals; window ranks bound proof IDs and block
# reasons independently of the bounded action-detail export. Evidence must join
# its persisted action and the independently recorded ownership/movement/chain
# records, rather than merely share a scenario or actor.
COVERAGE_QUERY = """
WITH relevant_events AS MATERIALIZED (
 SELECT sequence,kind,payload FROM event WHERE kind IN
 ('client_fee_reconciled','recycle_confirmed','confirmed_payout_amounts_checked')
), fee AS MATERIALIZED (
 SELECT a.id action_id,e.sequence,e.payload FROM relevant_events e JOIN action a
 ON a.id=json_extract(e.payload,'$.action_id')
 WHERE e.kind='client_fee_reconciled' AND a.state='completed'
 AND a.actual_fee_sat=json_extract(e.payload,'$.actual_fee_sat')
 AND (a.actor_id=json_extract(e.payload,'$.actor') OR
  (a.operation IN ('board','offboard_all') AND json_type(e.payload,'$.actor') IS NULL)) AND (
  (a.operation='board' AND json_extract(e.payload,'$.chain_transaction.confirmations')>=1
   AND json_extract(e.payload,'$.txid')=json_extract(e.payload,'$.chain_transaction.txid')
   AND EXISTS(SELECT 1 FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey
    WHERE c.id=json_extract(e.payload,'$.coin_id') AND k.actor=a.actor_id
    AND substr(json_extract(c.proof,'$.chain_anchor'),1,64)=json_extract(e.payload,'$.txid')))
  OR (a.operation IN ('refresh','refresh_delegated','refresh_scheduled','pay_invoice')
   AND EXISTS(SELECT 1 FROM movement_evidence m WHERE m.actor=a.actor_id
    AND m.movement_id=json_extract(e.payload,'$.movement_id')
    AND json_extract(m.payload,'$.status')='successful'
    AND json_extract(m.payload,'$.offchain_fee_sat')=a.actual_fee_sat
    AND json_extract(m.payload,'$.subsystem')=CASE WHEN a.operation='pay_invoice'
      THEN 'bark.lightning_send' ELSE 'bark.round' END)
   AND json_array_length(e.payload,'$.input_coin_ids')>0
   AND NOT EXISTS(SELECT 1 FROM json_each(e.payload,'$.input_coin_ids') i
    LEFT JOIN owned_coin c ON c.id=i.value LEFT JOIN owner_key k ON k.pubkey=c.pubkey
    WHERE k.actor IS NULL OR k.actor<>a.actor_id)
   AND NOT EXISTS(SELECT 1 FROM json_each(e.payload,'$.output_coin_ids') i
    LEFT JOIN owned_coin c ON c.id=i.value LEFT JOIN owner_key k ON k.pubkey=c.pubkey
    WHERE k.actor IS NULL OR k.actor<>a.actor_id))
  OR (a.operation='offboard_all' AND json_extract(e.payload,'$.chain_transaction.confirmations')>=1
   AND json_extract(e.payload,'$.txid')=json_extract(e.payload,'$.chain_transaction.txid')
   AND json_array_length(e.payload,'$.coin_ids')>0
   AND NOT EXISTS(SELECT 1 FROM json_each(e.payload,'$.coin_ids') i
    LEFT JOIN owned_coin c ON c.id=i.value LEFT JOIN owner_key k ON k.pubkey=c.pubkey
    WHERE k.actor IS NULL OR k.actor<>a.actor_id))
  OR (a.operation='sync' AND json_array_length(e.payload,'$.claims')>0
   AND NOT EXISTS(SELECT 1 FROM json_each(e.payload,'$.claims') claim
    WHERE COALESCE(json_array_length(claim.value,'$.output_coin_ids'),0)=0)
   AND NOT EXISTS(SELECT 1 FROM json_each(e.payload,'$.claims') claim
    LEFT JOIN movement_evidence m ON m.actor=a.actor_id
      AND m.movement_id=json_extract(claim.value,'$.movement_id')
    WHERE m.movement_id IS NULL OR json_extract(m.payload,'$.status')<>'successful'
      OR json_extract(m.payload,'$.subsystem')<>'bark.lightning_receive')
   AND NOT EXISTS(SELECT 1 FROM json_each(e.payload,'$.claims') claim
    JOIN json_each(claim.value,'$.output_coin_ids') output
    LEFT JOIN owned_coin c ON c.id=output.value LEFT JOIN owner_key k ON k.pubkey=c.pubkey
    WHERE k.actor IS NULL OR k.actor<>a.actor_id)))
), evidence AS (
 SELECT action_id,sequence FROM fee
 UNION ALL SELECT f.action_id,e.sequence FROM relevant_events e JOIN fee f
 ON f.action_id=json_extract(e.payload,'$.action_id')
 WHERE e.kind='recycle_confirmed'
 AND json_extract(e.payload,'$.board_txid')=json_extract(f.payload,'$.txid')
 AND json_extract(e.payload,'$.source_credit_count')=1
 AND json_array_length(f.payload,'$.chain_transaction.inputs')=1
 AND json_extract(f.payload,'$.chain_transaction.inputs[0].outpoint')=json_extract(e.payload,'$.source.outpoint')
 UNION ALL SELECT a.id,e.sequence FROM relevant_events e JOIN json_each(e.payload,'$.coins') coin
 JOIN coin_observation o ON o.coin_id=coin.value JOIN action a ON a.id=o.action_id
 JOIN checked_settlement s ON s.coin_id=coin.value AND s.actor=a.actor_id
 JOIN owned_coin c ON c.id=s.coin_id JOIN owner_key k ON k.pubkey=c.pubkey AND k.actor=a.actor_id
 JOIN chain_payout tx ON tx.txid=s.txid
 WHERE e.kind='confirmed_payout_amounts_checked' AND a.state='completed'
 AND s.txid=json_extract(e.payload,'$.txid') AND s.amount_sat=c.amount_sat
 AND json_extract(tx.payload,'$.confirmations')>=1
 AND EXISTS(SELECT 1 FROM owner_record r WHERE r.actor=a.actor_id AND r.script=s.script)
), proof AS (
 SELECT action_id,MIN(sequence) sequence FROM evidence GROUP BY action_id
), ranked AS (
 SELECT a.scenario_id,a.operation,a.state,a.id,p.sequence,e.kind,
 substr(COALESCE(json_extract(a.result,'$.data.reason'),json_extract(a.result,'$.reason'),''),1,400) reason,
 ROW_NUMBER() OVER(PARTITION BY a.scenario_id,a.operation,a.state ORDER BY a.created_at DESC,a.id DESC) detail_rank,
 ROW_NUMBER() OVER(PARTITION BY a.scenario_id,a.operation ORDER BY p.sequence DESC,a.id DESC) proof_rank
 FROM action a LEFT JOIN proof p ON p.action_id=a.id LEFT JOIN event e ON e.sequence=p.sequence
)
SELECT scenario_id,operation,state,COUNT(*) actions,COUNT(sequence) verified_actions,
 SUM(state='blocked' AND (lower(reason) LIKE '%fund%' OR lower(reason) LIKE '%balance%'
  OR lower(reason) LIKE '%afford%' OR lower(reason) LIKE '%reserve%'
  OR lower(reason) LIKE '%dust%' OR lower(reason) LIKE '%minimum%')) funds_blocked,
 SUM(state='blocked' AND (lower(reason) LIKE '%unsupported%' OR lower(reason) LIKE '%not implemented%'
  OR lower(reason) LIKE '%adapter%')) adapter_blocked,
 json_group_array(json_object('action_id',id,'event_sequence',sequence,'kind',kind,'reason',reason))
 FILTER(WHERE (sequence IS NOT NULL AND proof_rank<=10) OR (state='blocked' AND detail_rank<=10)) details
FROM ranked GROUP BY scenario_id,operation,state ORDER BY scenario_id,operation,state
"""


def _coverage_status(states, verified, available, funds_blocked=0, adapter_blocked=0):
    if verified:return 'exercised-verified'
    if any(states.get(state,0) for state in ('completed','expected_refusal','dispatched','outcome_unknown','failed')):
        return 'executed-unverified'
    if funds_blocked:return 'blocked-by-funds'
    if not available or adapter_blocked:return 'blocked-by-adapter'
    if states.get('blocked'):return 'executed-unverified'
    return 'enumerated'


def coverage(store):
    # Engine imports report, so resolve its actual dispatch allowlist only after
    # module initialization. Catalogue flags alone covered only the raw cases.
    from .engine import OPERATIONS, catalog
    catalogue = {case['id']:case for case in catalog()}
    aggregates = {}
    for row in store.db.execute(COVERAGE_QUERY):
        key = (row['scenario_id'],row['operation'])
        item = aggregates.setdefault(key, {'states':{},'actions':0,'verified':0,
            'funds_blocked':0,'adapter_blocked':0,'details':[]})
        item['states'][row['state']] = row['actions']
        for source,target in [('actions','actions'),('verified_actions','verified'),
                              ('funds_blocked','funds_blocked'),('adapter_blocked','adapter_blocked')]:
            item[target] += row[source]
        item['details'].extend(json.loads(row['details']))
    result = []
    for row in store.db.execute('SELECT * FROM scenario ORDER BY id'):
        case = catalogue.get(row['id'], {})
        driver = case.get('driver')
        operations = SCENARIO_OPERATIONS.get(row['id'],set()) if driver in {
            'SDK','SDK/Peer','Phase','Phase/Peer','Raw','Raw/Phase','Raw/Peer'} else set()
        controlled = {'seed_recovery'} if store.get_meta('seed_recovery_declaration') else set()
        supported = operations & (OPERATIONS | controlled)
        states, breakdown, proofs, reasons = {}, [], [], []
        excluded = verified = funds_blocked = adapter_blocked = total = 0
        for (scenario,operation),item in aggregates.items():
            if scenario != row['id']:continue
            if scenario == 'H01' and operation in {'snapshot','sync'}:
                excluded += item['actions']
                breakdown.append({'operation':operation,'status':'not-applicable','actions':0,
                    'excluded_actions':item['actions'],'reason':'H01 maintenance does not exercise its confirmed board behavior'})
                continue
            available = operation in supported
            verified_count = item['verified'] if available else 0
            status = _coverage_status(item['states'],verified_count,available,
                                      item['funds_blocked'],item['adapter_blocked'])
            breakdown.append({'operation':operation,'actions':item['actions'],'action_states':item['states'],
                'status':status,'verified_actions':verified_count,
                'reason':'Independent action evidence; complete scenario remains unqualified.' if verified_count else
                    'No matching independent action evidence.' if available else
                    'Operation is preparatory or has no supported primitive for this catalogue behavior.'})
            total += item['actions'];verified += verified_count
            funds_blocked += item['funds_blocked'];adapter_blocked += item['adapter_blocked']
            for state,count in item['states'].items():states[state] = states.get(state,0)+count
            for detail in item['details']:
                if available and detail['event_sequence'] is not None:
                    proofs.append({k:detail[k] for k in ('action_id','event_sequence','kind')})
                if detail['reason']:
                    reasons.append({'action_id':detail['action_id'],'reason':detail['reason']})
        status = _coverage_status(states,verified,bool(supported),funds_blocked,adapter_blocked)
        reason = ('Independent evidence verifies these action outcomes; the complete catalogue behavior remains unqualified.'
            if verified else 'No matching independent action outcome evidence.' if total else
            'Catalogue behavior has not been exercised.' if supported else
            f'Catalogue driver {driver or "unknown"} has no supported operation for this behavior.')
        result.append({'id':row['id'],'behavior':row['description'],'catalogue_driver':driver,
            'driver_available':bool(supported),'supported_operations':sorted(supported),
            'actions':total,'action_states':states,'excluded_maintenance_actions':excluded,
            'status':status,'verified_actions':verified,'reason':reason,'block_reasons':reasons[:10],
            'evidence_ids':proofs[:10],'operations':breakdown,
            'scenario_verdict':'not_qualified' if total else 'not_exercised'})
    return result


def atomic_text(path: Path, text: str):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as file:
        file.write(text)
        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary, path)


def payout_fees(store):
    """Count each independently checked transaction once, never each coin row."""
    from .model import InvariantError, integer
    verified={}
    for event in store.db.execute("SELECT payload FROM event WHERE kind='confirmed_payout_amounts_checked'"):
        item=json.loads(event['payload']);txid=item['txid']
        chain=store.db.execute('SELECT payload FROM chain_payout WHERE txid=?',(txid,)).fetchone()
        rows=store.db.execute('SELECT coin_id FROM checked_settlement WHERE txid=?',(txid,)).fetchall()
        if chain is None or not rows:continue
        tx=json.loads(chain['payload'])
        if tx.get('confirmations',0)<1 or tx.get('fee_sat') is None:continue
        if set(item['coins'])!={r['coin_id'] for r in rows}:continue
        recipient=integer(item['recipient_fee_sat'],'verified recipient fee')
        operator=integer(item['operator_fee_sat'],'verified operator fee')
        if recipient+operator!=integer(tx['fee_sat'],'raw transaction fee'):
            raise InvariantError('payout fee receipt does not conserve actual mining fee')
        fees=(recipient,operator)
        if txid in verified and verified[txid]!=fees:
            raise InvariantError('payout transaction has conflicting verified fee receipts')
        verified[txid]=fees
    pending=store.db.execute("SELECT COUNT(*) FROM settlement_check WHERE state!='amounts_checked'").fetchone()[0]
    if verified:
        recipient=sum(x[0] for x in verified.values());operator=sum(x[1] for x in verified.values())
    elif store.get_meta('mode')=='synthetic':
        recipient,operator=store.db.execute("SELECT COALESCE(SUM(recipient_fee_sat),0),COALESCE(SUM(operator_fee_sat),0) FROM payout").fetchone()
    else:recipient=operator=None
    return {'recipient_fee_sat':recipient,'operator_fee_sat':operator,
        'verified_transactions':len(verified),'pending_transactions':pending,
        'scope':'verified transaction totals only; pending and unobserved fees remain unknown'}


def generate(store: Store, full: bool = False, evaluate: bool = True) -> dict:
    from .log_capture import report as log_capture_report
    if full:
        store.verify_event_chain()
    if evaluate:
        observe(store)
    snapshot_query = "SELECT id,payload FROM snapshot ORDER BY observed_at,id" if full else "SELECT id,payload FROM (SELECT * FROM snapshot ORDER BY observed_at DESC,id DESC LIMIT 1440) ORDER BY observed_at,id"
    action_query = "SELECT * FROM action ORDER BY created_at,id" if full else "SELECT * FROM (SELECT * FROM action ORDER BY created_at DESC,id DESC LIMIT 2000) ORDER BY created_at,id"
    snapshot_records = list(store.db.execute(snapshot_query))
    snapshots = [json.loads(r['payload']) for r in snapshot_records]
    fields = ("id","actor_id","scenario_id","operation","state","fee_reservation_sat","actual_fee_sat")
    actions = [{key:r[key] for key in fields} for r in store.db.execute(action_query)]
    coverage_rows = coverage(store)
    liabilities = [dict(r) for r in store.db.execute("SELECT owner,source,state,SUM(gross_sat) AS amount_sat,COUNT(*) AS coins FROM entitlement GROUP BY owner,source,state")]
    payout_fee_summary=payout_fees(store)
    fees=(payout_fee_summary['recipient_fee_sat'],payout_fee_summary['operator_fee_sat'])
    known_fees, unresolved = store.db.execute("SELECT COALESCE(SUM(actual_fee_sat),0),COALESCE(SUM(CASE WHEN actual_fee_sat IS NULL THEN fee_reservation_sat ELSE 0 END),0) FROM action WHERE state!='canceled'").fetchone()
    last = store.db.execute("SELECT hash FROM event ORDER BY sequence DESC LIMIT 1").fetchone()
    tip = last[0] if last else "0" * 64
    result = {
        "mode": store.get_meta("mode"), "capital": capital_summary(json.loads(r[0]) for r in store.db.execute("SELECT payload FROM snapshot ORDER BY observed_at,id")),
        "target_identity": json.loads(store.get_meta("target_identity") or "null"),
        "paused": store.get_meta("paused"), "actors": [{**dict(r), "details": json.loads(r["details"])} for r in store.db.execute("SELECT id,role,online,details FROM actor ORDER BY id")],
        "actions": actions, "coverage": coverage_rows, "entitlements": liabilities,
        "permanent_receive_absences":absence_report(store),
        "capital_recycling":recycling_report(store),
        "seed_recovery_capital":recovery_report(store),
        "delegated_refresh_entitlements":{
            "state_counts":{r['state']:r['count'] for r in store.db.execute('SELECT state,COUNT(*) count FROM delegated_entitlement GROUP BY state')},
            "rows":[{**dict(r),"input_coin_ids":json.loads(r['input_coin_ids']),"replacement_ids":json.loads(r['replacement_ids'])}
                for r in store.db.execute('SELECT action_id,actor_id,state,input_coin_ids,replacement_ids,round_txid,server_round_id FROM delegated_entitlement ORDER BY updated_at DESC,action_id LIMIT 1000')],
            "scope":"durable intent history; successive refresh amounts are not additive capital"},
        "protocol_probes":protocol_scenario_rows(store),
        "tree_padding":padding_report(store),
        "log_capture":log_capture_report(store),
        "fee_watch":fee_watch_report(store),
        "expired_unclaimed_outputs":unclaimed_expired_report(store,snapshots[-1]['height'])
            if snapshots and type(snapshots[-1].get('height')) is int else {"status":"unknown_height","inventory_consistent":False},
        "owner_funded_renewal":{kind:[json.loads(r[0]) for r in store.db.execute('SELECT payload FROM event WHERE kind=? ORDER BY sequence',(kind,))]
            for kind in ['owner_renewal_allocation_intent','owner_renewal_confirmed','owner_renewal_board_intent']},
        "ownership_evidence": {"verified_keys":store.db.execute("SELECT COUNT(*) FROM owner_key").fetchone()[0],
             "negative_binding_checks":[dict(r) for r in store.db.execute('SELECT action_id,state,updated_at FROM negative_check ORDER BY updated_at')],
             "verified_coins":store.db.execute("SELECT COUNT(*) FROM owned_coin").fetchone()[0],
             "pending_candidates":store.db.execute("SELECT COUNT(*) FROM client_coin_candidate WHERE verified=0").fetchone()[0],
             "settlement_checks":[dict(r) for r in store.db.execute("SELECT * FROM settlement_check ORDER BY txid")],
             "scope":"public signatures/backing and amount checks; full source/seed recovery qualification remains separate"},
        "campaign": {
            "active_seconds":float(store.get_meta("qualified_campaign_active_seconds")
                if store.get_meta("qualified_campaign_active_seconds") is not None
                else store.get_meta("campaign_active_seconds") or "0"),
            "active_seconds_scope":"qualified dual-rail clock" if store.get_meta("qualified_campaign_active_seconds") is not None
                else "legacy clock; qualification rule not migrated",
            "qualified_campaign_active_seconds":float(store.get_meta("qualified_campaign_active_seconds"))
                if store.get_meta("qualified_campaign_active_seconds") is not None else None,
            "legacy_clock_seconds":float(store.get_meta("legacy_clock_seconds") or "0"),
            "campaign_active_seconds":float(store.get_meta("campaign_active_seconds") or "0"),
            "ramp_applied":store.get_meta("ramp_applied")=="true"},
        "payout_fees":payout_fee_summary, "payout_recipient_fees_sat": fees[0], "payout_operator_change_fees_sat": fees[1],
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
    padding=result['tree_padding']
    padding_summary=(f"Protocol padding: {padding['tree_padding_unclaimed']} unclaimed; {padding['tree_padding_expired_unclaimed']} expired; "
        f"{padding['tree_padding_swept']} confirmed swept. Operator padding locked within existing backing: "
        +(str(padding['tree_padding_locked_sat'])+' sat' if padding['tree_padding_locked_sat'] is not None else 'unknown')
        +'. Padding is not a customer entitlement or an additional asset.')
    markdown = f"# Bark operator report\n\n**{mode}**\n\n{summary}\n\n"
    markdown += padding_summary+"\n\n"
    fee_sample=result['fee_watch']['latest_simulator_tick']
    fee_reference=fee_sample['estimate']['sat_per_vbyte'] if fee_sample else None
    fee_summary=(f"Independent current fee reference: {fee_reference if fee_reference is not None else 'unknown'} sat/vB. "
        f"Recorded summary occurrences: {result['fee_watch']['server_diagnostics']['summary_occurrences']}; "
        "unique daemon ticks and individual server waiting ages unknown. "
        "Rates are comparisons, not a declared policy verdict or additive operator costs.")
    markdown += fee_summary+"\n\n"
    markdown += f"Verified payout recipient fees: {fees[0] if fees[0] is not None else 'unknown'} sat. Operator change fees: {fees[1] if fees[1] is not None else 'unknown'} sat. Unverified transactions: {payout_fee_summary['pending_transactions']}; their fees are excluded.\n\n"
    markdown += "Observations (facts and missing evidence, not scenario verdicts):\n\n"
    markdown += "\n".join(f"- [{o['severity']}, {o['status']}] {o['summary']} Evidence: {json.dumps(o['evidence'],sort_keys=True)}" for o in result["observations"]) + "\n\n"
    markdown += "Permanent receive absences (ordinary users; payout/recovery qualification stays explicit):\n\n"
    markdown += "\n".join(f"- {a['actor']}: {a['rail']} received {a['received_sat']} sat, permanently offline; {a['payout_verdict']}; {len(a['waiting_coin_ids'])} received coins waiting" for a in result["permanent_receive_absences"]) + "\n\n"
    clock = result['campaign']
    markdown += f"Campaign active seconds ({clock['active_seconds_scope']}): {clock['active_seconds']}. "
    markdown += f"Legacy clock seconds: {clock['legacy_clock_seconds']}; original campaign counter: {clock['campaign_active_seconds']}.\n\n"
    markdown += "Coverage lists 80 behaviors; independently verified action outcomes do not certify complete scenarios.\n\n"
    markdown += "\n".join(f"- {c['id']}: {c['status']}; {c['actions']} action(s); {c['scenario_verdict']}" for c in coverage_rows) + "\n"
    atomic_text(store.root / "report.md", markdown)
    coverage_md = (f"# Coverage of {len(coverage_rows)} catalogue behaviors\n\n**{mode}**\n\n"
        "Statuses describe available primitives and independently verified action outcomes. "
        "Every complete scenario remains unqualified. Epoch counts exclude H01 snapshot/sync maintenance; "
        "create, address and board attempts remain visible. Maintenance operations are not-applicable "
        "to H01 board coverage; no catalogue behavior is inferred out of scope.\n\n"
        "Statuses: exercised-verified, executed-unverified, enumerated, blocked-by-adapter, "
        "blocked-by-funds, not-applicable. Proof IDs and block reasons are bounded to ten per behavior.\n\n"
        "| ID | Behavior | Status | Actions | Verified actions | Excluded maintenance | Evidence | Reason |\n"
        "| --- | --- | --- | ---: | ---: | ---: | --- | --- |\n")
    for case in coverage_rows:
        refs = ', '.join(f"{p['action_id']} / event {p['event_sequence']} ({p['kind']})" for p in case['evidence_ids']) or 'none'
        reason = case['reason'] + ' ' + '; '.join(f"{b['action_id']}: {b['reason']}" for b in case['block_reasons'])
        cells = [case['id'],case['behavior'],case['status'],str(case['actions']),str(case['verified_actions']),
                 str(case['excluded_maintenance_actions']),refs,reason.strip()]
        coverage_md += '| ' + ' | '.join(value.replace('|','\\|').replace('\n',' ') for value in cells) + ' |\n'
    atomic_text(store.root / 'coverage-80.md', coverage_md)
    rows = "".join(f"<tr><td>{c['id']}</td><td>{html.escape(c['behavior'])}</td><td>{c['actions']}</td><td>{c['status']}<br>{c['scenario_verdict']}</td></tr>" for c in coverage_rows)
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
<h1>Bark operator observations</h1><p class=banner>{mode}</p><h2>Capital</h2><pre>{html.escape(summary)}</pre><p>{html.escape(padding_summary)}</p>
{chart}
<p>{html.escape(fee_summary)}</p>
<p>Minimum required capital: unknown. A funded successful run does not prove a minimum.</p>
<p>Campaign active seconds ({html.escape(clock['active_seconds_scope'])}): {clock['active_seconds']}. Legacy clock seconds: {clock['legacy_clock_seconds']}; original campaign counter: {clock['campaign_active_seconds']}.</p>
<h2>Observations</h2><ul>{observations_html}</ul>
<p>Capital, fee and behavior counts cover the epoch. Chart, CSV, action and event details may be bounded; use the report command for a full export.</p>
<h2>Actors</h2><table><tr><th>Owner</th><th>Role</th><th>Status</th><th>Fixture funding address</th></tr>{actor_rows}</table>
<h2>Behavior catalogue</h2><p>Action results do not establish complete scenario qualification.</p><table><tr><th>ID</th><th>Behavior</th><th>Actions</th><th>Verdict</th></tr>{rows}</table></html>"""
    atomic_text(store.root / "index.html", document)
    temp = store.root / "capital.csv.tmp"
    with temp.open("w", newline="", encoding="utf-8") as file:
        fields = ["observed_at", "height", "complete", "rounds_confirmed_sat", "rounds_unconfirmed_sat", "tree_locked_sat", "tree_padding_locked_sat", "tree_padding_unclaimed", "tree_padding_swept", "watchman_confirmed_sat", "ln_spendable_msat", "ln_receivable_msat", "independent_fee_reference_sat_vbyte", "fee_watch_observed_transaction_count", "fee_watch_above_current_reference_count", "fee_watch_gap_count"]
        writer = csv.DictWriter(file, fields)
        writer.writeheader()
        for record in snapshot_records:
            values={**json.loads(record['payload']),**padding_csv_values(store,record['id']),**fee_watch_csv_values(store,record['id'])}
            writer.writerow({key: values.get(key) for key in fields})
    os.replace(temp, store.root / "capital.csv")
    store.export_events(full=full)
    return result

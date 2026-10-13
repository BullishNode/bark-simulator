"""Read-only fee comparisons and unbound payout diagnostics on signet.

A current independent estimate is a reference, not a historical quote or an
operator ceiling. Anonymous log summaries cannot identify a payout or prove a
unique daemon tick. This module never changes an action, reserve or balance.
"""
from __future__ import annotations
import asyncio
import hashlib
import json
import time
from decimal import Decimal
from .bundle_audit import decode_transaction
from .model import SIGNET_GENESIS, canonical, integer, public_payload, transaction_fee, btc_to_sat
from .trace import normalized, partition_paths, readonly, record_hash

SCHEMA = '''
CREATE TABLE IF NOT EXISTS fee_watch_tick(id TEXT PRIMARY KEY,payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS fee_watch_transaction(txid TEXT PRIMARY KEY,payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS fee_watch_window(source TEXT NOT NULL,capture_sequence INTEGER NOT NULL,
 reference TEXT NOT NULL,PRIMARY KEY(source,capture_sequence));
CREATE TABLE IF NOT EXISTS fee_watch_log_occurrence(source TEXT NOT NULL,capture_sequence INTEGER NOT NULL,
 line_index INTEGER NOT NULL,kind TEXT NOT NULL,fingerprint TEXT,payload TEXT NOT NULL,
 PRIMARY KEY(source,capture_sequence,line_index));
'''


def initialize(store):
    for statement in SCHEMA.split(';'):
        if statement.strip(): store.db.execute(statement)


def _hash(value): return hashlib.sha256(canonical(value).encode()).hexdigest()


def _txid(value):
    if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('invalid public transaction identity')
    return value


def _parse(line):
    try:
        event = json.loads(line)
        public_payload(event)
        if not isinstance(event, dict): return 'unparsed', {}
        target, message = event.get('target'), event.get('message')
        if target == 'server::expiry_payout' and message == 'expiry payout tick summary':
            from .target_log_window import utc
            utc(event['timestamp'])
            for key in ('tip', 'candidates', 'waiting', 'paid'): integer(event[key], 'logged ' + key)
            if type(event.get('success')) is not bool: raise ValueError('invalid tick success')
            duration = event['duration_ms']
            if isinstance(duration, str) and duration.isdecimal(): duration = int(duration)
            integer(duration, 'logged tick duration')
            return 'anonymous_summary', event
        if target == 'server::expiry_payout' and isinstance(message, str) and (
                message.startswith('expiry batch deferred:') or message in {
                    'expiry send refund held', 'expiry destination held', 'unregistered expiry input owner unavailable',
                    'no real fee estimate; expiry payouts wait'}):
            return 'unbound_warning', event
        if (target == 'server::watchman' and event.get('slog_id') == 'ClaimBroadcast'
                and message == 'Broadcast claim transaction'):
            _txid(event['slog_data']['txid'])
            return 'watchman_claim_candidate', event
        return 'other', {}
    except (ValueError, TypeError, KeyError, OverflowError):
        return 'unparsed', {}


def record_window(store, source, capture_sequence, payload, reference):
    initialize(store)
    integer(capture_sequence, 'local log capture sequence', 1)
    public_payload(payload); public_payload(reference)
    old = store.db.execute('SELECT reference FROM fee_watch_window WHERE source=? AND capture_sequence=?', (source, capture_sequence)).fetchone()
    if old:
        if old['reference'] != canonical(reference): raise ValueError('frozen log window reference changed')
        return
    occurrences = []
    for line in payload['response']['lines']:
        kind, event = ('redacted', {}) if line.get('redacted') is True else _parse(line.get('returned_line', ''))
        fingerprint = _hash(event) if kind == 'anonymous_summary' else None
        evidence = {'event': event, 'window_reference': reference, 'component': payload['component'],
            'gaps': payload.get('gaps', []), 'producer_incarnation': None,
            'scope': 'returned occurrence only; fingerprint is not a daemon tick ID or complete history'}
        occurrences.append((source, capture_sequence, integer(line['line_index'], 'log line index'), kind, fingerprint, canonical(evidence)))
    with store.transaction():
        store.db.executemany('INSERT INTO fee_watch_log_occurrence VALUES (?,?,?,?,?,?)', occurrences)
        store.db.execute('INSERT INTO fee_watch_window VALUES (?,?,?)', (source, capture_sequence, canonical(reference)))


def collect_windows(store, limit=4):
    """Consume bounded already-captured windows, preserving every occurrence."""
    initialize(store)
    if not store.db.execute("SELECT 1 FROM sqlite_master WHERE name='target_log_window'").fetchone(): return
    integer(limit, 'fee diagnostic window limit', 1)
    if limit > 16: raise ValueError('fee diagnostic window bound')
    paths = {path.name: path for path in partition_paths(store.root)}
    rows = store.db.execute('''SELECT w.* FROM target_log_window w LEFT JOIN fee_watch_window f
        ON f.source=w.source AND f.capture_sequence=w.capture_sequence WHERE f.source IS NULL
        ORDER BY w.capture_sequence,w.source LIMIT ?''', (limit,)).fetchall()
    for row in rows:
        reference = json.loads(row['trace_reference'])
        db=readonly(paths[reference['partition']])
        try:record = db.execute('SELECT * FROM trace WHERE seq=?', (reference['seq'],)).fetchone()
        finally:db.close()
        if record is None or record['kind'] != 'target.log.window' or record['hash'] != reference['hash'] or record_hash(record) != reference['hash']:
            raise ValueError('fee diagnostic window trace reference differs')
        record_window(store, row['source'], row['capture_sequence'], json.loads(record['payload']), reference)


def _candidates(store, unknowns=None):
    candidates = {}
    def add(txid, kind, source):
        _txid(txid)
        value = candidates.setdefault(txid, {'kinds': set(), 'sources': [], 'source_occurrences': 0})
        value['kinds'].add(kind)
        value['source_occurrences'] += 1
        if len(value['sources']) < 16: value['sources'].append(source)
    for row in store.db.execute("SELECT kind,id,payload FROM server_item WHERE kind IN ('settlements','nursery')"):
        try:
            item = json.loads(row['payload'])
            if row['kind'] == 'settlements' or item.get('kind') == 'expiry-payout':
                add(item['txid'], 'payout_candidate', {'kind': row['kind'], 'id': row['id']})
        except (ValueError, TypeError, KeyError):
            if unknowns is not None: unknowns.append({'bucket':'candidate_identity','kind':row['kind'],'id':row['id'],'reason':'invalid public candidate identity'})
    for row in store.db.execute("SELECT source,capture_sequence,line_index,payload FROM fee_watch_log_occurrence WHERE kind='watchman_claim_candidate'"):
        item = json.loads(row['payload'])
        add(item['event']['slog_data']['txid'], 'watchman_claim_candidate',
            {key: row[key] for key in ('source', 'capture_sequence', 'line_index')})
    return candidates


def _estimate(response, target, mode):
    public_payload(normalized(response))
    value = {'target_blocks': target, 'mode': mode, 'response': normalized(response),
             'sat_per_kvb': None, 'sat_per_vbyte': None, 'policy_ceiling_sat_per_vbyte': None}
    if response.get('feerate') is not None:
        rate = btc_to_sat(response['feerate'])
        if rate <= 0: raise ValueError('nonpositive independent estimate')
        value.update(sat_per_kvb=rate, sat_per_vbyte=str(Decimal(rate) / 1000))
    return value


def _measure(chain, txid, cached=None):
    info = chain.tx(txid); raw = decode_transaction(info['hex'])
    if raw['txid'] != txid or info['txid'] != txid: raise ValueError('fee raw transaction identity differs')
    for field in ('vsize', 'weight', 'size'):
        if field in info and (type(info[field]) is not int or info[field] != raw[field]):
            raise ValueError('fee Core size differs from exact wire bytes')
    raw_hash = hashlib.sha256(bytes.fromhex(info['hex'])).hexdigest()
    raw_transactions={txid:info['hex']}
    if cached:
        facts = cached
        if facts['raw_sha256'] != raw_hash: raise ValueError('fee transaction witness/body changed')
    else:
        if len(raw['inputs']) > 16: raise ValueError('fee parent batch exceeds bounded read budget')
        points = [item['outpoint'] for item in raw['inputs']]
        if len(points) != len(set(points)): raise ValueError('fee transaction repeats an input')
        inputs, parents = [], {}
        started = time.monotonic()
        for point in points:
            if time.monotonic() - started > 10: raise ValueError('fee parent read time budget exhausted')
            parent_id, index = point.split(':')
            if parent_id not in parents:
                parent_info = chain.tx(parent_id); parent = decode_transaction(parent_info['hex'])
                if parent['txid'] != parent_id: raise ValueError('fee raw parent identity differs')
                parents[parent_id] = parent
                raw_transactions[parent_id]=parent_info['hex']
            output = parents[parent_id]['outputs'][integer(int(index), 'fee parent index')]
            inputs.append({'outpoint': point, 'amount_sat': output['amount_sat'], 'script': output['script']})
        mining_fee = transaction_fee({'inputs': inputs, 'outputs': raw['outputs']})
        facts = {'txid': txid, 'raw_sha256': raw_hash, 'mining_fee_sat': mining_fee,
            'vsize': raw['vsize'], 'weight': raw['weight'], 'input_count': len(inputs),
            'actual_sat_per_vbyte': str(Decimal(mining_fee) / raw['vsize']),
            'raw_chain_fee_verified': True,'network':'signet','genesis':SIGNET_GENESIS, 'scope': 'exact serialized transaction and parent values; fee payer and customer payout verdict are separate'}
    confirmations = integer(info.get('confirmations', 0), 'observed fee transaction confirmations')
    row = {**facts, 'confirmations': confirmations, 'chain_state': 'confirmed' if confirmations else 'unconfirmed',
           'recipient_fee_sat': None, 'operator_fee_sat': None, 'policy_verdict': 'undeclared'}
    return facts, row, raw_transactions


def _allocate(store, facts, row):
    txid=facts['txid'];confirmations=row['confirmations']
    checked = store.db.execute('SELECT state FROM settlement_check WHERE txid=?', (txid,)).fetchone()
    events = store.db.execute("SELECT sequence,payload FROM event WHERE kind='confirmed_payout_amounts_checked' AND json_extract(payload,'$.txid')=?", (txid,)).fetchall()
    if confirmations and checked and checked['state'] == 'amounts_checked' and len(events) == 1:
        proof = json.loads(events[0]['payload'])
        recipient = integer(proof['recipient_fee_sat'], 'checked recipient fee')
        operator = integer(proof['operator_fee_sat'], 'checked operator fee')
        if recipient + operator != facts['mining_fee_sat']: raise ValueError('checked fee allocation differs from raw mining fee')
        row.update(recipient_fee_sat=recipient, operator_fee_sat=operator, allocation_event_sequence=events[0]['sequence'])
    return row


async def collect(store, chain, tick_id, *, target_blocks=6, mode='economical', transaction_limit=2, window_id=None):
    """Sample one independent reference each simulator tick, with bounded tx reads."""
    initialize(store)
    if getattr(chain, 'expected', None) != SIGNET_GENESIS: raise ValueError('fee watch requires independently pinned signet')
    if not isinstance(tick_id, str) or not tick_id or len(tick_id) > 128: raise ValueError('bounded simulator tick identity required')
    integer(target_blocks, 'fee reference confirmation target', 1)
    if target_blocks > 1008 or mode not in {'economical', 'conservative'}: raise ValueError('invalid independent estimate reference')
    integer(transaction_limit, 'fee watch transaction limit', 1)
    if transaction_limit > 4: raise ValueError('fee watch transaction read bound')
    public_payload(window_id)
    previous = store.db.execute('SELECT payload FROM fee_watch_tick WHERE id=?', (tick_id,)).fetchone()
    if previous: return json.loads(previous['payload'])
    unknowns, transactions, facts = [], [], []
    estimate = _estimate({}, target_blocks, mode)
    before = after = None
    chain_ready=False
    try:
        before = await asyncio.to_thread(chain.identity)
        if before.get('chain') != 'signet' or before.get('initialblockdownload') is not False:
            raise ValueError('independent fee reference chain is not synced signet')
        chain_ready=True
        response = await asyncio.to_thread(chain.call, 'estimatesmartfee', target_blocks, mode)
        estimate = _estimate(response, target_blocks, mode)
    except Exception as error:
        unknowns.append({'bucket': 'independent_fee_estimate', 'reason': type(error).__name__})
    try:collect_windows(store)
    except Exception as error:unknowns.append({'bucket':'server_log_binding','reason':type(error).__name__})
    candidates = _candidates(store, unknowns)
    cursor = store.get_meta('fee_watch_transaction_cursor') or ''
    ordered = sorted(k for k in candidates if k > cursor) + sorted(k for k in candidates if k <= cursor)
    for txid in (ordered[:transaction_limit] if chain_ready else []):
        try:
            cached=store.db.execute('SELECT payload FROM fee_watch_transaction WHERE txid=?',(txid,)).fetchone()
            fact, row, wires = await asyncio.to_thread(_measure, chain, txid, json.loads(cached['payload']) if cached else None)
            row=_allocate(store,fact,row)
            if cached is None:
                fact['trace_reference']=store.trace_capture('fee.watch.transaction',{'facts':fact.copy(),'raw_transactions':wires})
            if fact.get('trace_reference') is None:
                unknowns.append({'bucket':'transaction_raw_capture','txid':txid,'reason':'raw replay trace unavailable'})
            facts.append(fact)
            row.update(candidate_kinds=sorted(candidates[txid]['kinds']), sources=candidates[txid]['sources'],
                source_occurrences=candidates[txid]['source_occurrences'], raw_evidence_reference=fact.get('trace_reference'),
                above_current_reference=None if estimate['sat_per_kvb'] is None else
                    row['mining_fee_sat'] * 1000 > row['vsize'] * estimate['sat_per_kvb'],
                reference_scope='transaction rate versus current independent estimate; not a contemporaneous construction quote or a policy verdict')
            transactions.append(row)
        except Exception as error:
            unknowns.append({'bucket': 'transaction_fee_evidence', 'txid': txid, 'reason': type(error).__name__})
        store.db.execute("INSERT OR REPLACE INTO meta VALUES ('fee_watch_transaction_cursor',?)", (txid,))
    try:
        after = await asyncio.to_thread(chain.identity)
        if before is None or after.get('chain') != 'signet' or after.get('initialblockdownload') is not False or (before.get('blocks'), before.get('bestblockhash')) != (after.get('blocks'), after.get('bestblockhash')):
            raise ValueError('fee reference sampled across an unstable or unverified chain tip')
    except Exception as error:
        estimate['sat_per_kvb'] = estimate['sat_per_vbyte'] = None
        for row in transactions: row['above_current_reference'] = None
        unknowns.append({'bucket': 'fee_reference_boundary', 'reason': type(error).__name__})
    if estimate['sat_per_vbyte'] is None:
        unknowns.append({'bucket': 'independent_fee_estimate', 'reason': 'no qualified estimate; no zero or fallback rate invented'})
    value = {'simulator_tick_id': tick_id, 'observed_at': time.time(), 'window_id': window_id,
        'estimate': estimate, 'chain_before': normalized(before), 'chain_after': normalized(after),
        'transactions': transactions, 'candidate_transaction_count': len(candidates), 'transaction_limit': transaction_limit,
        'unknowns': unknowns, 'complete': False, 'operator_policy': 'undeclared',
        'scope': 'read-only fee diagnostic; no operator asset, spending authorization, traffic or payout verdict; repeated transaction observations are not additive costs'}
    public_payload(value)
    reference = store.trace_capture('fee.watch.tick', value)
    value['trace_reference'] = reference
    with store.transaction():
        for fact in facts:
            store.db.execute('INSERT OR IGNORE INTO fee_watch_transaction VALUES (?,?)', (fact['txid'], canonical(fact)))
        store.db.execute('INSERT INTO fee_watch_tick VALUES (?,?)', (tick_id, canonical(value)))
    return value


def report(store, limit=100):
    initialize(store)
    integer(limit, 'fee watch report limit', 1)
    if limit > 1000: raise ValueError('fee watch report bound')
    counts = {row['kind']: row['count'] for row in store.db.execute('SELECT kind,count(*) count FROM fee_watch_log_occurrence GROUP BY kind')}
    distinct = store.db.execute("SELECT count(DISTINCT fingerprint) FROM fee_watch_log_occurrence WHERE kind='anonymous_summary'").fetchone()[0]
    latest = store.db.execute('SELECT payload FROM fee_watch_tick ORDER BY rowid DESC LIMIT 1').fetchone()
    last_summary=store.db.execute("SELECT payload FROM fee_watch_log_occurrence WHERE kind='anonymous_summary' ORDER BY rowid DESC LIMIT 1").fetchone()
    warnings=[json.loads(row[0]) for row in store.db.execute("SELECT payload FROM fee_watch_log_occurrence WHERE kind='unbound_warning' ORDER BY rowid DESC LIMIT ?",(limit,))]
    pending = [dict(row) for row in store.db.execute("SELECT txid,reason local_verification_reason,updated_at FROM settlement_check WHERE state='pending' ORDER BY updated_at DESC LIMIT ?", (limit,))]
    for row in pending:
        row.update(server_waiting_reason=None, same_reason_age_ticks=None, server_tick_id=None,
            binding_status='aggregate logs lack payout/group identity and unique daemon ticks')
    return {'latest_simulator_tick': json.loads(latest[0]) if latest else None,
        'known_transaction_facts': [json.loads(row[0]) for row in store.db.execute('SELECT payload FROM fee_watch_transaction ORDER BY txid LIMIT ?', (limit,))],
        'server_diagnostics': {'summary_occurrences': counts.get('anonymous_summary', 0),
            'distinct_summary_payloads': distinct, 'unique_daemon_ticks': None,
            'latest_returned_summary':json.loads(last_summary[0]) if last_summary else None,
            'unbound_warnings':warnings,
            'warning_occurrences': counts.get('unbound_warning', 0),
            'unparsed_occurrences': counts.get('unparsed', 0) + counts.get('redacted', 0),
            'complete': False, 'waiting_reason_binding': 'unavailable; fork-owned tick_summary required'},
        'pending_payouts': pending, 'operator_policy': 'undeclared', 'additive_operator_cost': False,
        'unknowns':[{'bucket':'operator_fee_policy','reason':'no independently declared ceiling or contemporaneous construction estimate'},
                    {'bucket':'individual_waiting_age','reason':'anonymous summaries and bounded tails lack stable candidate/tick identity and coverage'}],
        'scope': 'bounded fee facts and returned log occurrences; no complete history, individual waiting age, scenario qualification or minimum-capital conclusion'}


def csv_values(store, snapshot_id):
    """Only that snapshot's recorded reference; never backfill older rows."""
    initialize(store)
    row=store.db.execute('SELECT payload FROM fee_watch_tick WHERE id=?',('snapshot:'+str(snapshot_id),)).fetchone()
    if row is None:return {}
    value=json.loads(row['payload'])
    measured=value['transactions']
    return {'independent_fee_reference_sat_vbyte':value['estimate']['sat_per_vbyte'],
        'fee_watch_observed_transaction_count':len(measured),
        'fee_watch_above_current_reference_count':None if value['estimate']['sat_per_kvb'] is None
            else sum(item['above_current_reference'] is True for item in measured),
        'fee_watch_gap_count':len(value['unknowns'])}

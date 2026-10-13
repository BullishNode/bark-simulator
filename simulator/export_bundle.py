"""Export and replay public campaign evidence without reading client wallets."""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import time
from pathlib import Path

from .model import InvariantError, canonical, public_payload, timestamp
from .settlements import check_payment
from .trace import iter_records, normalized, partition_paths, record_hash, readonly, verify_partition


class ReadOnlyCampaign:
    """Public journal reader; unlike Store, construction never initializes state."""
    def __init__(self, root):
        self.root = Path(root)
        self.db = readonly(self.root / 'state.sqlite')
    def close(self): self.db.close()
    def get_meta(self, key):
        row = self.db.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
        return row[0] if row else None
    def verify_event_chain(self): return verify_events(self.db.execute('SELECT * FROM event ORDER BY sequence'))


def verify_events(rows):
    previous = '0' * 64
    for sequence, row in enumerate(rows, 1):
        payload = row['payload'] if isinstance(row['payload'], str) else canonical(row['payload'])
        digest = hashlib.sha256(canonical([row['sequence'], row['observed_at'], row['kind'], payload, previous]).encode()).hexdigest()
        if row['sequence'] != sequence or row['previous_hash'] != previous or row['hash'] != digest:
            raise InvariantError('financial event chain is damaged')
        previous = digest
    return previous


def _public(value):
    value = normalized(value)
    try: public_payload(value)
    except ValueError: return {'redacted': True}
    return value


def file_hash(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def _json(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(canonical(_public(value)) + '\n')


def _rows(db, table, where="", params=()):
    for row in db.execute('SELECT * FROM ' + table + (' WHERE ' + where if where else ''), params):
        value = dict(row)
        for field in ('payload', 'proof', 'details', 'evidence', 'args', 'result'):
            if value.get(field) is not None:
                try: value[field] = json.loads(value[field])
                except (ValueError, TypeError): pass
        yield value


def _contains(value, references):
    if isinstance(value, str): return value in references
    if isinstance(value, dict): return any(_contains(item, references) for item in value.values())
    if isinstance(value, list): return any(_contains(item, references) for item in value)
    return False


def _period(at, after, before):
    return (after is None or at >= after) and (before is None or at <= before)


def install_actor_timeline(db, current_partition=None):
    """A SQL timeline view for public state plus the optional current trace day.

    Historical trace days are merged by actor_timeline(); SQLite's attachment
    limit never forces every retained partition to remain open.
    """
    db.execute('DROP VIEW IF EXISTS temp.actor_timeline')
    if current_partition is not None:
        attached = {row[1] for row in db.execute('PRAGMA database_list')}
        if 'trace_live' in attached: db.execute('DETACH DATABASE trace_live')
        db.execute('ATTACH DATABASE ? AS trace_live', (str(current_partition),))
    queries = ["SELECT actor_id AS actor,updated_at AS utc,NULL AS seq,'action' AS kind,id AS ref FROM action",
        """SELECT k.actor,o.observed_at,NULL,'coin_observation',o.action_id||':'||o.coin_id
            FROM coin_observation o JOIN owned_coin c ON c.id=o.coin_id JOIN owner_key k ON k.pubkey=c.pubkey""",
        """SELECT m.actor,(SELECT MIN(a.updated_at) FROM action a,json_each(a.result,'$.data.evidence.movements') j
             WHERE a.actor_id=m.actor AND json_extract(j.value,'$.id')=m.movement_id),NULL,'movement_evidence',m.movement_id
             FROM movement_evidence m""",
        """SELECT c.actor,(SELECT MIN(e.observed_at) FROM event e WHERE e.kind='confirmed_payout_amounts_checked'
             AND json_extract(e.payload,'$.txid')=c.txid),NULL,'checked_settlement',c.txid||':'||c.coin_id FROM checked_settlement c"""]
    if current_partition is not None:
        queries += ["SELECT actor,utc,seq,'trace.'||kind,'trace:'||seq FROM trace_live.trace WHERE actor IS NOT NULL",
            """SELECT json_extract(j.value,'$.actor'),t.utc,t.seq,'trace.scheduler.tick','trace:'||t.seq
              FROM trace_live.trace t,json_each(t.payload,'$.actors') j WHERE t.kind='scheduler.tick'"""]
    db.execute('CREATE TEMP VIEW actor_timeline AS ' + ' UNION ALL '.join(queries))


def actor_timeline(store, actors, trace_root=None, *, after=None,before=None,trace_tips=None):
    install_actor_timeline(store.db)
    db=store.db
    db.execute('DROP TABLE IF EXISTS temp.selected_timeline')
    db.execute('CREATE TEMP TABLE selected_timeline(actor,utc,seq,kind,ref)')
    period='';params=[]
    if after is not None:period+=' AND (utc IS NULL OR utc>=?)';params.append(after)
    if before is not None:period+=' AND (utc IS NULL OR utc<=?)';params.append(before)
    for actor in actors:
        db.execute('INSERT INTO selected_timeline SELECT * FROM actor_timeline WHERE actor=?'+period,[actor,*params])
    if trace_root:
        for record in iter_records(trace_root,after=after,before=before):
            if trace_tips is not None and record['seq']>trace_tips.get(record['partition'],0):continue
            linked={record['actor']}
            if isinstance(record['payload'],dict):
                linked.update(item.get('actor') for item in record['payload'].get('actors',[]) if isinstance(item,dict))
            db.executemany('INSERT INTO selected_timeline VALUES (?,?,?,?,?)',((actor,record['utc'],record['seq'],
                'trace.'+record['kind'],record['partition']+':'+str(record['seq'])) for actor in linked.intersection(actors)))
    for row in db.execute('SELECT * FROM selected_timeline ORDER BY utc IS NULL,utc,kind,ref'):
        yield dict(row)


def export_bundle(store, out, *, actor=None, payout=None, after=None, before=None, trace_root=None):
    """Build an immutable, self-describing selection from a consistent SQL backup."""
    out = Path(out)
    if out.exists() or out.is_symlink(): raise FileExistsError('export destination already exists')
    if actor is not None and payout is not None: raise ValueError('select actor or payout, not both')
    if after is not None: timestamp(after, 'export beginning')
    if before is not None: timestamp(before, 'export ending')
    if after is not None and before is not None and after > before: raise ValueError('invalid export period')
    trace_root = Path(trace_root) if trace_root else store.root
    trace_tips = [verify_partition(path) for path in partition_paths(trace_root)]
    trace_limits={tip['partition']:tip['records'] for tip in trace_tips}
    out.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.public-export-', dir=out.parent))
    snapshot_path=staging/'.source-snapshot.sqlite'
    snapshot = sqlite3.connect(snapshot_path); snapshot.row_factory = sqlite3.Row
    store.db.backup(snapshot)
    source_tip=verify_events(snapshot.execute('SELECT * FROM event ORDER BY sequence'))
    frozen = type('FrozenCampaign', (), {'db': snapshot})()
    try:
        # Restrict large ownership/candidate tables inside SQLite. Only the
        # selected ownership graph and payout group are materialized in Python.
        snapshot.executescript("""
          CREATE TEMP TABLE selected_actor(id TEXT PRIMARY KEY);
          CREATE TEMP TABLE selected_txid(id TEXT PRIMARY KEY);
          CREATE TEMP TABLE selected_coin(id TEXT PRIMARY KEY);
        """)
        if actor:
            snapshot.execute('INSERT INTO selected_actor VALUES (?)',(actor,))
            snapshot.execute('INSERT OR IGNORE INTO selected_txid SELECT txid FROM checked_settlement WHERE actor=?',(actor,))
        elif payout:snapshot.execute('INSERT INTO selected_txid VALUES (?)',(payout,))
        else:
            snapshot.execute('INSERT INTO selected_actor SELECT id FROM actor')
            snapshot.execute("INSERT OR IGNORE INTO selected_txid SELECT json_extract(payload,'$.txid') FROM server_item WHERE kind='settlements'")
        settlement_rows=[row['payload'] for row in _rows(snapshot,'server_item',
            "kind='settlements' AND json_extract(payload,'$.txid') IN (SELECT id FROM selected_txid)")]
        snapshot.executemany('INSERT OR IGNORE INTO selected_coin VALUES (?)',((row['id'],) for row in settlement_rows))
        snapshot.execute('INSERT OR IGNORE INTO selected_coin SELECT c.id FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey WHERE k.actor IN (SELECT id FROM selected_actor)')
        while True:
            inserted=snapshot.execute("""INSERT OR IGNORE INTO selected_coin
                SELECT i.value FROM owned_coin c,json_each(c.proof,'$.path') p,json_each(p.value,'$.inputs') i
                WHERE c.id IN (SELECT id FROM selected_coin)""").rowcount
            if not inserted:break
        coins=list(_rows(snapshot,'owned_coin','id IN (SELECT id FROM selected_coin)'))
        keys=list(_rows(snapshot,'owner_key','pubkey IN (SELECT pubkey FROM owned_coin WHERE id IN (SELECT id FROM selected_coin))'))
        snapshot.executemany('INSERT OR IGNORE INTO selected_actor VALUES (?)',((key['actor'],) for key in keys))
        actors={row[0] for row in snapshot.execute('SELECT id FROM selected_actor')}
        txids={row[0] for row in snapshot.execute('SELECT id FROM selected_txid')}
        coin_ids={row[0] for row in snapshot.execute('SELECT id FROM selected_coin')}
        tables={name:list(_rows(snapshot,name,where)) for name,where in (
            ('actor','id IN (SELECT id FROM selected_actor)'),
            ('owner_record','actor IN (SELECT id FROM selected_actor)'),
            ('checked_settlement','txid IN (SELECT id FROM selected_txid)'),
            ('chain_payout','txid IN (SELECT id FROM selected_txid)'),
            ('operator_script',''),('server_item',"kind='coins' AND id IN (SELECT id FROM selected_coin)"))}
        period='actor_id IN (SELECT id FROM selected_actor)';period_params=[]
        if after is not None:period+=' AND updated_at>=?';period_params.append(after)
        if before is not None:period+=' AND updated_at<=?';period_params.append(before)
        chosen_actions=list(_rows(snapshot,'action',period,period_params))
        action_ids = {row['id'] for row in chosen_actions}
        references = actors | txids | coin_ids | action_ids
        references.update(coin['proof'].get('chain_anchor','').split(':')[0] for coin in coins)
        references.update(point['outpoint'].split(':')[0] for row in tables['chain_payout'] for point in row['payload']['inputs'])
        _json(staging / 'actor.json', [{**row,'details':_public(row['details'])} for row in tables['actor'] if row['id'] in actors])
        _json(staging / 'actions.json', chosen_actions)
        evidence = {'owner_keys': keys,
            'owner_records': [row for row in tables['owner_record'] if row['actor'] in actors],
            'settlements': settlement_rows,
            'checked_settlements': [row for row in tables['checked_settlement'] if row['txid'] in txids],
            'chain_payouts': [row for row in tables['chain_payout'] if row['txid'] in txids],
            'operator_scripts': tables['operator_script'],
            'server_coins': [row for row in tables['server_item'] if row['kind'] == 'coins' and row['id'] in coin_ids]}
        _json(staging / 'evidence.json', evidence)
        (staging / 'proofs').mkdir(); (staging / 'raw-rpc').mkdir()
        gaps = []
        for coin in coins:
            requests = [row['payload'] for row in _rows(snapshot,'client_coin_candidate','id=? AND verified=1',(coin['id'],))]
            value = {**coin, 'actor': next(key['actor'] for key in keys if key['pubkey'] == coin['pubkey']),
                     'requests': requests}
            _json(staging / 'proofs' / (hashlib.sha256(coin['id'].encode()).hexdigest() + '.json'), value)
            if not requests: gaps.append({'kind': 'missing_raw_signature_request', 'coin_id': coin['id']})
        counts = {'events': 0, 'trace': 0, 'actors': len(actors), 'actions': len(chosen_actions), 'proofs': len(coins)}
        with (staging / 'events.jsonl').open('w') as stream:
            for row in snapshot.execute('SELECT * FROM event ORDER BY sequence'):
                payload = json.loads(row['payload'])
                if _period(row['observed_at'], after, before) and (not (actor or payout) or _contains(payload, references)):
                    value = _public({**dict(row), 'payload': payload})
                    stream.write(canonical(value) + '\n'); counts['events'] += 1
        with (staging / 'trace.jsonl').open('w') as stream:
            for record in iter_records(trace_root, after=after, before=before):
                if record['seq']>trace_limits.get(record['partition'],0):continue
                if (actor or payout) and record['actor'] not in actors and record['action_id'] not in action_ids:
                    if record['kind'] not in {'observer.sample.raw', 'target.log', 'target.log.window', 'target.rounds_descriptor', 'operator.bridge.call', 'operator.bridge.stdout', 'operator.bridge.stderr', 'service.log', 'chain.rpc', 'log.capture.gap', 'log.capture.declared', 'log.capture.opening', 'log.producer.call', 'log.producer.stdout', 'log.producer.stderr', 'log.producer.rejected'} and not _contains(record['payload'], references): continue
                raw = record.pop('raw')
                value = {**record, 'raw_base64': base64.b64encode(raw).decode() if raw is not None else None}
                stream.write(canonical(_public(value)) + '\n'); counts['trace'] += 1
                if record['kind'] == 'chain.rpc':
                    name = record['partition'][6:16] + '-' + str(record['seq'])
                    _json(staging / 'raw-rpc' / (name + '.json'), record['payload'])
                    if raw is not None: (staging / 'raw-rpc' / (name + '.raw')).write_bytes(raw)
        with (staging / 'timeline.jsonl').open('w') as stream:
            for entry in actor_timeline(frozen, actors, trace_root,after=after,before=before,trace_tips=trace_limits):
                if entry['utc'] is None or _period(entry['utc'], after, before): stream.write(canonical(_public(entry)) + '\n')
        README = ('# Public campaign evidence\n\n'
            'This bundle contains a selected public journal, diagnostic traces, ownership proofs, and payout evidence. '
            'It contains no client wallet databases, seeds, or credentials.\n\n'
            'manifest.json lists file hashes, counts, source chain tips, and selection limits. '
            'Trace raw bytes use Base64 in trace.jsonl; Core RPC responses also appear under raw-rpc/. '
            'Decimal values remain exact strings in normalized JSON.\n\n'
            'Run `python3 -m simulator.export_bundle audit BUNDLE` to check hashes and replay payout amounts. '
            'An amount replay uses exported previously verified ownership data; it does not by itself rerun native signatures, '
            'prove live spendability, sweep arbitration, seed recovery, or a complete scenario. '
            'Missing raw signature requests and backing records remain explicit gaps.\n\n'
            'Selections can omit hash-chain links. Each included record remains checkable against its own recorded predecessor; '
            'the complete source event and trace chains were checked before export. Source tips need an independently trusted '
            'reference to authenticate provenance.\n')
        (staging / 'README.md').write_text(README)
        snapshot.close();snapshot_path.unlink()
        files = {str(path.relative_to(staging)): file_hash(path)
                 for path in sorted(staging.rglob('*')) if path.is_file()}
        manifest = {'schema_version': 1, 'created_at': time.time(),
            'selection': {'actor': actor, 'payout': payout, 'after': after, 'before': before},
            'source': {'mode': store.get_meta('mode'), 'event_tip': source_tip,
                       'trace_partitions': trace_tips, 'selected_chain_links': True},
            'counts': counts, 'files': files, 'gaps': gaps,
            'native_protocol_reverified': False,'raw_chain_reverified':False}
        _json(staging / 'manifest.json', manifest)
        staging.rename(out)
        return manifest
    except BaseException:
        shutil.rmtree(staging); raise
    finally:
        snapshot.close()


def _verified_files(root):
    root = Path(root)
    if any(path.is_symlink() for path in [root,root/'manifest.json',*root.parents]):raise InvariantError('unsafe bundle manifest path')
    manifest = json.loads((root / 'manifest.json').read_text())
    if manifest.get('schema_version') != 1: raise InvariantError('unsupported export schema')
    actual={str(path.relative_to(root)) for path in root.rglob('*') if path.is_file()}
    if actual!=set(manifest['files'])|{'manifest.json'}:raise InvariantError('bundle contains unlisted or missing evidence')
    for name, expected in manifest['files'].items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts: raise InvariantError('unsafe bundle manifest path')
        path = root / relative
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents) or not path.is_file() or file_hash(path) != expected:
            raise InvariantError('bundle file is missing or changed')
    return manifest


def json_lines(path):
    with Path(path).open() as stream:
        yield from stream


def audit_bundle(root, *, proof_binary=None):
    """Replay grouped amounts from the bundle, with no RPC or client access."""
    root = Path(root); manifest = _verified_files(root)
    for line in json_lines(root/'trace.jsonl'):
        row = json.loads(line)
        if row.get('redacted'): continue
        row['raw'] = base64.b64decode(row.pop('raw_base64')) if row.get('raw_base64') is not None else None
        row['payload'] = canonical(row['payload'])
        if record_hash(row) != row['hash']: raise InvariantError('exported trace record hash differs')
    for line in json_lines(root/'events.jsonl'):
        row = json.loads(line)
        if row.get('redacted'): continue
        serialized = canonical(row['payload'])
        digest = hashlib.sha256(canonical([row['sequence'], row['observed_at'], row['kind'], serialized, row['previous_hash']]).encode()).hexdigest()
        if digest != row['hash']: raise InvariantError('exported event record hash differs')
    evidence = json.loads((root / 'evidence.json').read_text())
    from .bundle_audit import archived_transactions,replay_chain_payout,verify_native_proofs
    transactions=archived_transactions(root/'raw-rpc')
    proofs=[json.loads(path.read_text()) for path in sorted((root/'proofs').glob('*.json'))]
    protocol=verify_native_proofs(proofs,transactions,proof_binary) if proof_binary else {
        'native_protocol_reverified':False,'gaps':[{'kind':'native_verifier_not_run'}]}
    gaps=[*manifest['gaps'],*protocol['gaps']]
    db = sqlite3.connect(':memory:'); db.row_factory = sqlite3.Row
    from .ownership import SCHEMA as OWNERSHIP_SCHEMA
    from .settlements import SCHEMA as SETTLEMENT_SCHEMA
    db.executescript(OWNERSHIP_SCHEMA + SETTLEMENT_SCHEMA)
    try:
        for row in evidence['owner_keys']:
            db.execute('INSERT INTO owner_key VALUES (?,?,?,?)', (row['pubkey'], row['actor'], row['mailbox'], canonical(row['proof'])))
        for row in evidence['owner_records']:
            db.execute('INSERT INTO owner_record VALUES (?,?,?,?,?)', (row['actor'], row['mailbox'], row['seq'], row['script'], canonical(row['proof'])))
        for row in proofs:
            db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)', (row['id'], row['pubkey'], row['amount_sat'], row['signed_hash'], row['signed_vtxo'], canonical(row['proof'])))
        for row in evidence['operator_scripts']:
            db.execute('INSERT INTO operator_script VALUES (?,?)', (row['script'], canonical(row['evidence'])))
        for row in evidence['server_coins']:
            db.execute('INSERT INTO server_item VALUES (?,?,?,?)', (row['kind'], row['id'], canonical(row['payload']), row['observed_at']))
        for row in evidence['checked_settlements']:
            db.execute('INSERT INTO checked_settlement VALUES (?,?,?,?,?,?)',(row['coin_id'],row['txid'],row['actor'],row['script'],row['amount_sat'],canonical(row['evidence'])))
        replay = type('EvidenceStore', (), {'db': db})()
        payouts = []
        for entry in evidence['chain_payouts']:
            tx = entry['payload']; raw_audit=replay_chain_payout(tx,transactions);gaps.extend(raw_audit['gaps'])
            rows = [r for r in evidence['settlements'] if r['txid'] == tx['txid']]
            try:
                result = check_payment(replay, rows, tx)
                destinations={}
                for settlement,owner in result['owners']:
                    destinations.setdefault(settlement['spk'],set()).add(owner['actor'])
                if any(len(owners)!=1 for owners in destinations.values()):
                    raise ValueError('payout destination belongs to multiple exported actors')
                net={}
                for script,owners in destinations.items():
                    owner=next(iter(owners));net[owner]=net.get(owner,0)+sum(output['amount_sat'] for output in tx['outputs'] if output['script']==script)
                payouts.append({'txid': tx['txid'], 'state': 'amounts_checked', 'recipient_net_sat': net,
                    'recipient_fee_sat': result['recipient_fee_sat'], 'operator_fee_sat': result['operator_fee_sat'],
                    'raw_chain_reverified':raw_audit['raw_chain_reverified']})
            except InvariantError: raise
            except ValueError as error:
                payouts.append({'txid': tx['txid'], 'state': 'pending', 'reason': str(error)})
        return {'schema_version': 1, 'files_verified': len(manifest['files']), 'payouts': payouts,
                'native_protocol_reverified':protocol['native_protocol_reverified'], 'gaps':gaps}
    finally: db.close()


def _last_exported(path):
    if not path.exists():return None
    with path.open('rb') as stream:
        stream.seek(0,os.SEEK_END);size=stream.tell()
        if not size:return None
        stream.seek(max(0,size-16*1024*1024));tail=stream.read()
    if not tail.endswith(b'\n'):raise InvariantError('daily event export has a partial record')
    return json.loads(tail.splitlines()[-1])


def export_event_days(store):
    """Incremental full financial export; immutable closed days are never rewritten."""
    directory=store.root/'events';directory.mkdir(mode=0o700,exist_ok=True)
    manifest_path=store.root/'events-manifest.json'
    if directory.is_symlink() or manifest_path.is_symlink():raise ValueError('unsafe daily event export path')
    manifest=json.loads(manifest_path.read_text()) if manifest_path.exists() else {
        'schema_version':1,'last_sequence':0,'event_tip':'0'*64,'days':{}}
    cursor=manifest['last_sequence']
    if cursor:
        row=store.db.execute('SELECT hash FROM event WHERE sequence=?',(cursor,)).fetchone()
        if row is None or row[0]!=manifest['event_tip']:raise InvariantError('daily event export cursor differs from journal')
    stream=None;current=None;last=None
    try:
        for row in store.db.execute('SELECT * FROM event WHERE sequence>? ORDER BY sequence',(cursor,)):
            day=dt.datetime.fromtimestamp(row['observed_at'],dt.timezone.utc).date().isoformat()
            name='events-'+day+'.jsonl';path=directory/name
            if path.is_symlink():raise ValueError('unsafe daily event export file')
            if current!=name:
                if stream is not None:stream.flush();os.fsync(stream.fileno());stream.close()
                last=_last_exported(path);stream=path.open('ab');current=name
            value={**dict(row),'payload':json.loads(row['payload'])};public_payload(value)
            # A crash after fsync but before cursor replacement can leave the
            # selected tail already present. Compare its journal hash, then skip.
            if last is not None and last['sequence']>=row['sequence']:
                source=store.db.execute('SELECT hash FROM event WHERE sequence=?',(last['sequence'],)).fetchone()
                if source is None or source[0]!=last['hash']:raise InvariantError('daily event export tail differs from journal')
                if last['sequence']==row['sequence'] and last['hash']!=row['hash']:
                    raise InvariantError('daily event export record differs from journal')
            else:stream.write((canonical(value)+'\n').encode());last=value
            manifest['last_sequence']=row['sequence'];manifest['event_tip']=row['hash']
            manifest['days'][name]={'last_sequence':last['sequence'],'tip':last['hash']}
        if stream is not None:stream.flush();os.fsync(stream.fileno())
        temporary=manifest_path.with_suffix('.json.tmp')
        if temporary.is_symlink():raise ValueError('unsafe daily export temporary file')
        with temporary.open('w') as file:
            file.write(canonical(manifest)+'\n');file.flush();os.fsync(file.fileno())
        os.replace(temporary,manifest_path)
        return manifest
    finally:
        if stream is not None:stream.close()


def parse_utc(value):
    try:return timestamp(float(value),'export UTC')
    except ValueError:pass
    try:
        parsed=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
        if parsed.tzinfo is None:raise ValueError('timezone required')
        return timestamp(parsed.timestamp(),'export UTC')
    except (ValueError,OverflowError):raise argparse.ArgumentTypeError('UTC timestamp with timezone required') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    export = sub.add_parser('export'); export.add_argument('--state', type=Path, required=True)
    export.add_argument('--out', type=Path, required=True)
    group = export.add_mutually_exclusive_group(); group.add_argument('--actor'); group.add_argument('--payout')
    export.add_argument('--from', dest='after', type=parse_utc); export.add_argument('--to', dest='before', type=parse_utc)
    audit = sub.add_parser('audit'); audit.add_argument('bundle', type=Path);audit.add_argument('--proof-binary',type=Path)
    args = parser.parse_args(); os.umask(0o077)
    if args.command == 'audit': result = audit_bundle(args.bundle,proof_binary=args.proof_binary)
    else:
        source = ReadOnlyCampaign(args.state)
        try: result = export_bundle(source, args.out, actor=args.actor, payout=args.payout, after=args.after, before=args.before)
        finally: source.close()
    print(json.dumps(result, indent=2))

if __name__ == '__main__': main()

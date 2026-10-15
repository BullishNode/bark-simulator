"""Explicit Track C pilot policy within the common simulator admission path.

Declarations describe limits. They never establish an observed bank balance,
loaded runtime, accepted key link, or completed operation.
"""
import json
import re

from .architecture import DIRECT_PER_KEY, profile
from .final_campaign import _pins, _source_event
from .model import canonical, public_payload

KEY = 'direct_per_key_bounded_pilot'
CUSTOMERS = {'actor-01', 'actor-02'}
GRANTS = {'actor-01': 25000, 'actor-02': 0}
FIXED = {'schema_version': 1, 'architecture_profile': DIRECT_PER_KEY,
         'sender': 'actor-01', 'recipient': 'actor-02', 'grants_sat': GRANTS,
         'board_amount_sat': 20000, 'arkoor_amount_sat': 2000,
         'funding_max_miner_fee_sat': 1000, 'board_max_miner_fee_sat': 1000,
         'operator_fee_grants_sat': {'rounds': 0, 'watchman': 100000},
         'client_principal_sat': 25000, 'funding_total_transfer_sat': 125000,
         'fee_signer_member': 'watchman', 'urgent_isolation_qualified': False,
         'ordinary_fee_budget_sat': 60000, 'urgent_fee_budget_sat': 40000,
         'board_confirmations': 3, 'ordinary_lifetime_blocks': 48,
         'pool_lifetime_blocks': 48}


def validate(value):
    fields = set(FIXED) | {'id', 'pins', 'boundary_id', 'bank_opening_sat',
                           'board_action_id', 'arkoor_action_id'}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('complete explicit C bounded pilot declaration required')
    public_payload(value); _pins(value['pins'])
    for key, expected in FIXED.items():
        if value[key] != expected or type(expected) in (int, bool) and type(value[key]) is not type(expected):
            raise ValueError('C pilot fixed scope differs: '+key)
    if (set(value['grants_sat']) != CUSTOMERS
            or any(type(amount) is not int for amount in value['grants_sat'].values())
            or any(type(amount) is not int for amount in value['operator_fee_grants_sat'].values())
            or type(value['bank_opening_sat']) is not int
            or not 126000 <= value['bank_opening_sat'] <= 900000):
        raise ValueError('C pilot actual declared opening cannot cover principal and protected budgets')
    for key in ('id', 'boundary_id', 'board_action_id', 'arkoor_action_id'):
        if not isinstance(value[key], str) or re.fullmatch('[a-zA-Z0-9:_-]{1,100}', value[key]) is None:
            raise ValueError('bounded original C pilot identifiers required')
    if value['board_action_id'] == value['arkoor_action_id']:
        raise ValueError('C pilot distinct original monetary action IDs required')
    return value


def declaration(store):
    if profile(store) != DIRECT_PER_KEY:
        raise ValueError('C pilot requires the actual direct_per_key namespace')
    encoded = store.get_meta(KEY)
    if encoded is None:
        raise ValueError('explicit C bounded pilot declaration missing')
    value = validate(json.loads(encoded))
    rows = store.db.execute("SELECT sequence FROM event WHERE kind='direct_per_key_bounded_pilot_declared'").fetchall()
    if len(rows) != 1 or _source_event(store, rows[0][0])[1] != value:
        raise ValueError('C pilot differs from its immutable original declaration')
    return value


def declare(store, value):
    validate(value)
    if profile(store) != DIRECT_PER_KEY:
        raise ValueError('C pilot requires the actual direct_per_key namespace')
    with store.transaction():
        if store.get_meta(KEY) is not None:
            if declaration(store) != value:
                raise ValueError('C bounded pilot declaration is immutable')
            return False
        if (not store.get_meta('paused')
                or store.db.execute("SELECT 1 FROM action WHERE operation NOT IN ('create','sync','snapshot','address') OR state IN ('dispatched','outcome_unknown') LIMIT 1").fetchone()
                or store.db.execute("SELECT 1 FROM event WHERE kind IN ('fixture_funding_intent','financial_cost_verified') LIMIT 1").fetchone()):
            raise ValueError('pause C pilot before any monetary or uncertain work')
        store.db.execute('INSERT INTO meta VALUES (?,?)', (KEY, canonical(value)))
        store._event('direct_per_key_bounded_pilot_declared', value)
    return True


def funding_policy(store):
    """Only the source policy varies; Core signing/once-only state stays common."""
    value = declaration(store)
    return {'customers': CUSTOMERS, 'amounts': {'actor-01': 25000, 'watchman': 100000},
            'opening_sat': value['bank_opening_sat'], 'principal_sat': 125000,
            'client_principal_sat': 25000, 'operator_fee_grants_sat': value['operator_fee_grants_sat'],
            'fee_signer_member': 'watchman', 'urgent_isolation_qualified': False,
            'maximum_fee_sat': 1000, 'maximum_rate_sat_kvb': 20000,
            'ordinary_budget_sat': 60000, 'urgent_budget_sat': 40000,
            'grant_sat': 25000, 'board_sat': 20000, 'board_fee_reserve_sat': 1000,
            'pilot_id': value['id'], 'pins': value['pins'], 'boundary_id': value['boundary_id']}


def board_policy(store=None):
    """Phase policy only; all native dispatch and monetary checks stay shared."""
    if store is not None and profile(store)==DIRECT_PER_KEY:
        pilot=declaration(store)
        return {'actors':['actor-01','actor-02'],'board_actors':['actor-01'],
            'maximum_fee_sat':1000,'grants':pilot['grants_sat'],'opening_sat':pilot['bank_opening_sat'],
            'urgent_budget_sat':40000,'board_action_id':pilot['board_action_id']}
    actors=['actor-01','actor-02','actor-04']
    return {'actors':actors,'board_actors':actors,'maximum_fee_sat':4000,
        'grants':{actor:50000 for actor in actors},'opening_sat':665454,'urgent_budget_sat':15000}


def retained_links(store):
    """Exact original native prefix/proof union; server rows cannot bless extras."""
    from .per_key import initial_origins,retained_origins,binding_matches,proof_matches
    pilot=declaration(store);result={}
    for actor in sorted(CUSTOMERS):
        creates=0;origins=None;binding=None
        rows=store.db.execute("SELECT a.id,a.operation,a.result,e.sequence FROM action a JOIN event e ON e.kind='driver_response' AND json_extract(e.payload,'$.action_id')=a.id WHERE a.actor_id=? AND a.state='completed' AND a.operation IN ('create','sync') ORDER BY e.sequence",(actor,)).fetchall()
        for row in rows:
            _,source=_source_event(store,row['sequence']);reply=source['response']
            if (reply!=json.loads(row['result']) or reply.get('status')!='ok'
                    or reply.get('action_id')!=row['id'] or reply.get('actual_fee_sat')!=0):
                raise ValueError('original C native key inventory response differs')
            data=reply['data']
            if row['operation']=='create':
                creates+=1
                if creates!=1:raise ValueError('one original fresh C create required')
                origins=initial_origins(data);binding=data['binding']
            else:
                current=retained_origins(data.get('c_key_links'))
                if binding is None or not binding_matches(binding,data['c_key_links']['binding']):
                    raise ValueError('C synced key prefix changed immutable destination')
                if origins is None or any(item not in current for item in origins):
                    raise ValueError('C synced key prefix lost or changed acknowledged keys')
                origins=current
        if creates!=1 or origins is None:raise ValueError('original C creation and retained key prefix required')
        verify_public_key_rows(store,actor,origins)
        links=[]
        for origin in origins:
            owned=store.db.execute('SELECT * FROM owner_key WHERE pubkey=?',(origin['user_pubkey'],)).fetchone()
            checked=json.loads(owned['proof']) if owned else {}
            if (not owned or owned['actor']!=actor or checked.get('financial_pins')!=pilot['pins']
                    or not proof_matches(checked,origin) or not binding_matches(checked.get('binding',{}),binding)):
                raise ValueError('C retained native key lacks original independent signature proof')
            raw=bytes.fromhex(origin['key_link_attestation'])
            links.append({'user_pubkey':origin['user_pubkey'],'mailbox_pk':binding['mailbox_pk'],
                'sig':raw[-64:].hex(),'recovery_index':checked['binding']['recovery_index']})
        result[actor]={'binding':binding,'links':links,'count':len(links)}
    return result


def verify_public_key_rows(store,actor,origins,*,initial=False):
    """Read every bounded public key/proof row, never a seed or monetary payload."""
    import os
    import sqlite3
    import stat
    import time
    from pathlib import Path
    from .identity_bootstrap import declaration as bootstrap,_root,_sole_writer
    original=bootstrap(store)
    if original is None or actor not in CUSTOMERS:raise ValueError('original C customer context required')
    value=original['declaration'];_sole_writer(value['wallet_root'])
    if _root(value['wallet_root'])!=original['filesystem']:raise ValueError('original C wallet root identity changed')
    path=Path(value['wallet_root'])/actor/'db.sqlite'
    if any(stat.S_ISLNK(p.lstat().st_mode) for p in (path,*path.parents)):raise ValueError('C key inventory SQLite symlink refused')
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600:
        raise ValueError('actual private C key inventory SQLite required')
    connection=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=2)
    connection.execute('PRAGMA query_only=ON');started=time.monotonic()
    connection.set_progress_handler(lambda:time.monotonic()-started>5,1000)
    try:
        connection.execute('BEGIN')
        rows=connection.execute('SELECT idx,public_key,lower(hex(linked_proof)),issued FROM bark_vtxo_key ORDER BY idx LIMIT 129').fetchall()
        expected=[(index,origin['user_pubkey'],origin['key_link_attestation']) for index,origin in enumerate(origins)]
        if (len(rows)>128 or [row[:3] for row in rows]!=expected
                or any(type(row[3]) is not int or row[3] not in (0,1) for row in rows)
                or not rows or rows[0][3]!=1
                or initial and any(row[3]!=(1 if index==0 else 0) for index,row in enumerate(rows))):
            raise ValueError('complete actual C public key/proof rows differ from original native inventory')
        return {'actor':actor,'row_count':len(rows),'device':info.st_dev,'inode':info.st_ino,
            'read_only':True,'scope':'all bounded public key/index/retained-proof rows only; no private keys or wallet payloads'}
    finally:connection.close()

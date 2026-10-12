"""Independent post-request public binding checks; no private client key read."""
import json,time
from .model import InvariantError,canonical,integer
from .ownership import EvidenceGap
from .process import json_command
from .raw_cases import RAW_CASES

def request_for(store,action):
    data=json.loads(action['result'])['data'];record=data['protected_record']
    keys=list(data.get('attempted_key_pubkeys',[]))
    expected={}
    for key in keys:
        known=store.db.execute('SELECT mailbox FROM owner_key WHERE pubkey=?',(key,)).fetchone()
        expected[key]=known['mailbox'] if known else None
    if action['operation']=='raw_relink':
        keys=[data['user_pubkey']];expected={keys[0]:data['original_mailbox_pk']}
    if len(keys)>32 or len(keys)!=len(set(keys)):raise InvariantError('negative request key bound')
    mailboxes=list(dict.fromkeys([record['mailbox_pk'],*(mb for mb in expected.values() if mb is not None)]))
    if len(mailboxes)>2:raise InvariantError('negative request mailbox bound')
    return {'kind':'binding_check','mailboxes':mailboxes,'keys':keys},expected,record

def check(request,expected,protected,observed):
    if observed.get('kind')!='binding_check' or observed.get('inventory_consistent') is not True:
        raise EvidenceGap('no consistent post-request binding snapshot')
    if observed.get('mailboxes')!=request['mailboxes'] or observed.get('keys')!=request['keys']:
        raise InvariantError('binding snapshot belongs to a different request')
    records=observed['records'];links=observed['links']
    if len({r['mailbox_pk'] for r in records})!=len(records) or {r['mailbox_pk'] for r in records}!=set(request['mailboxes']):
        raise InvariantError('protected wallet record disappeared or changed identity')
    record=next(r for r in records if r['mailbox_pk']==protected['mailbox_pk'])
    serialized=record['spk']+integer(record['seq'],'stored record sequence').to_bytes(8,'little').hex()+record['sig']
    if serialized!=protected['serialized']:raise InvariantError('negative request altered a protected wallet record')
    if len({l['user_pubkey'] for l in links})!=len(links):raise InvariantError('duplicated key mapping in snapshot')
    if any(l['user_pubkey'] not in expected for l in links):raise InvariantError('snapshot contains an unrequested key')
    actual={l['user_pubkey']:l['mailbox_pk'] for l in links}
    if any((key in actual if mailbox is None else actual.get(key)!=mailbox) for key,mailbox in expected.items()):
        raise InvariantError('negative request inserted or redirected a protected coin key')
    return {'protected_record_unchanged':True,'key_mappings_unchanged':True,
        'scope':'post-request independent database record/link check; source-specific scenario qualification remains separate'}

async def collect(store,command,proof_command=(),limit=2):
    store.db.execute('CREATE TABLE IF NOT EXISTS negative_check(action_id TEXT PRIMARY KEY,state TEXT NOT NULL,payload TEXT NOT NULL,updated_at REAL NOT NULL)')
    if not command:return
    rows=store.db.execute("SELECT a.* FROM action a LEFT JOIN negative_check c ON c.action_id=a.id WHERE a.operation LIKE 'raw_%' AND a.state IN ('completed','expected_refusal') AND (c.state IS NULL OR c.state NOT IN ('checked','invalidated')) ORDER BY a.updated_at").fetchall()
    after=store.get_meta('negative_check_cursor') or ''
    rows=[r for r in rows if r['id']>after]+[r for r in rows if r['id']<=after]
    for action in rows[:limit]:
        state='pending';evidence={}
        try:
            if RAW_CASES.get(action['operation'])!=action['scenario_id']:raise InvariantError('negative adapter/catalogue mismatch')
            request,expected,protected=request_for(store,action)
            observed=await json_command(list(command),request,timeout=25)
            evidence={**check(request,expected,protected,observed),'snapshot':observed}
            for link in observed['links']:
                if not proof_command:raise EvidenceGap('independent signature verifier unavailable')
                record=next(r for r in observed['records'] if r['mailbox_pk']==link['mailbox_pk'])
                proof=await json_command(list(proof_command),{'user_pubkey':link['user_pubkey'],'key_link_attestation':link['sig'],
                    'binding':{'mailbox_pk':record['mailbox_pk'],'spk':record['spk'],'seq':record['seq'],'record_attestation':record['sig']}},timeout=30)
                bound=proof.get('binding',{})
                if proof.get('user_pubkey')!=link['user_pubkey'] or bound.get('mailbox_pk')!=record['mailbox_pk'] or bound.get('spk')!=record['spk'] or bound.get('seq')!=record['seq']:
                    raise InvariantError('independent binding verifier returned another identity')
                if bound.get('record_signature_valid') is not True or bound.get('key_link_signature_valid') is not True:
                    raise EvidenceGap('signature validation incomplete')
            state='checked'
            store.event('negative_binding_checked',{'action_id':action['id'],'scenario':action['scenario_id'],**evidence})
        except InvariantError:raise
        except Exception as error:evidence={'reason':type(error).__name__}
        store.db.execute('INSERT OR REPLACE INTO negative_check VALUES (?,?,?,?)',(action['id'],state,canonical(evidence),time.time()))
        store.db.execute("INSERT OR REPLACE INTO meta VALUES ('negative_check_cursor',?)",(action['id'],))

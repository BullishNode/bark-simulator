"""Public ownership evidence and many-input/many-output graph.

A signed replacement is NOT a durable transfer of the expiry entitlement.
Registration/settlement arbitration is checked separately from this graph. No
client wallet is opened while collecting server or chain observations.
"""
from __future__ import annotations
import hashlib,json,time
from contextlib import nullcontext
from .model import InvariantError,canonical,integer,public_payload
from .process import json_command, public_command_capture

SCHEMA='''
CREATE TABLE IF NOT EXISTS client_coin_candidate(id TEXT NOT NULL, actor TEXT NOT NULL REFERENCES actor(id), action_id TEXT NOT NULL REFERENCES action(id), digest TEXT NOT NULL, payload TEXT NOT NULL, verified INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(id,digest));
CREATE TABLE IF NOT EXISTS owner_key(pubkey TEXT PRIMARY KEY, actor TEXT NOT NULL REFERENCES actor(id), mailbox TEXT NOT NULL, proof TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS owner_record(actor TEXT NOT NULL REFERENCES actor(id), mailbox TEXT NOT NULL, seq INTEGER NOT NULL, script TEXT NOT NULL, proof TEXT NOT NULL, PRIMARY KEY(mailbox,seq));
CREATE TABLE IF NOT EXISTS owned_coin(id TEXT PRIMARY KEY, pubkey TEXT NOT NULL REFERENCES owner_key(pubkey), amount_sat INTEGER NOT NULL, signed_hash TEXT NOT NULL, signed_vtxo TEXT NOT NULL, proof TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS coin_observation(coin_id TEXT NOT NULL REFERENCES owned_coin(id), action_id TEXT NOT NULL REFERENCES action(id), state TEXT NOT NULL, observed_at REAL NOT NULL, PRIMARY KEY(coin_id,action_id));
CREATE TABLE IF NOT EXISTS movement_evidence(actor TEXT NOT NULL REFERENCES actor(id), movement_id TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(actor,movement_id));
CREATE TABLE IF NOT EXISTS movement_edge(actor TEXT NOT NULL, movement_id TEXT NOT NULL, coin_id TEXT NOT NULL, direction TEXT NOT NULL CHECK(direction IN ('input','output')), PRIMARY KEY(actor,movement_id,coin_id,direction));
CREATE TABLE IF NOT EXISTS server_item(kind TEXT NOT NULL, id TEXT NOT NULL, payload TEXT NOT NULL, observed_at REAL NOT NULL, PRIMARY KEY(kind,id));
CREATE TABLE IF NOT EXISTS server_item_version(kind TEXT NOT NULL, id TEXT NOT NULL, digest TEXT NOT NULL, payload TEXT NOT NULL, observed_at REAL NOT NULL, PRIMARY KEY(kind,id,digest));
'''

def initialize(store):store.db.executescript(SCHEMA)
def digest(value):return hashlib.sha256(canonical(value).encode()).hexdigest()

async def verify_client_evidence(store, actor, operation, data, proof_command):
    """Independent verifier must run before accepting an ownership claim.

    Returns validated public objects only. Cached immutable proofs still do not
    establish current registration, absence of a competing spend, or settlement.
    """
    if not proof_command:return None
    evidence=data.get('evidence',{})
    binding=evidence.get('binding',data.get('binding'))
    if not isinstance(binding,dict):return None
    verified=[]
    if operation=='address':
        request={k:data[k] for k in ('user_pubkey','key_link_attestation','binding')}
        proof=await json_command(list(proof_command),request,timeout=30,**public_command_capture(store,'proof.verify',request,actor=actor))
        if proof['user_pubkey']!=data['user_pubkey']:raise InvariantError('advertised key verification mismatch')
        verified.append({'kind':'key','proof':proof})
    for coin in evidence.get('coins',[]):
        request={**coin,'binding':binding}
        signed_hash=hashlib.sha256(bytes.fromhex(coin['signed_vtxo'])).hexdigest()
        old=store.db.execute('SELECT * FROM owned_coin WHERE id=?',(coin['id'],)).fetchone()
        if old:
            if old['pubkey']!=coin['user_pubkey'] or old['amount_sat']!=coin['amount_sat']:
                raise InvariantError('immutable signed coin changed')
            cached=json.loads(old['proof'])
            if old['signed_hash']==signed_hash and cached['binding']['mailbox_pk']==binding['mailbox_pk'] and cached['binding']['seq']==binding['seq'] and cached['binding']['spk']==binding['spk']:
                proof=cached
            else:proof=await json_command(list(proof_command),request,timeout=30,**public_command_capture(store,'proof.verify',request,actor=actor))
        else:proof=await json_command(list(proof_command),request,timeout=30,**public_command_capture(store,'proof.verify',request,actor=actor))
        if (proof['id'],proof['user_pubkey'],proof['amount_sat'])!=(coin['id'],coin['user_pubkey'],integer(coin['amount_sat'],'coin amount',1)):
            raise InvariantError('independent coin evidence mismatch')
        if proof.get('signed_path_valid') is not True or proof.get('anchor_confirmations',0)<1:
            raise ValueError('backing not confirmed')
        verified.append({'kind':'coin','coin':coin,'proof':proof,'signed_hash':signed_hash,'request_binding':binding})
    return {'objects':verified,'movements':evidence.get('movements',[])}

def record_verified(store, actor, action_id, verified):
    if verified is None:return
    with (nullcontext() if store.db.in_transaction else store.transaction()):
        for item in verified['objects']:
            proof=item['proof'];pub=proof['user_pubkey'];bound=proof['binding']
            if bound.get('record_signature_valid') is not True or bound.get('key_link_signature_valid') is not True:
                raise InvariantError('unverified owner proof')
            old=store.db.execute('SELECT actor,mailbox FROM owner_key WHERE pubkey=?',(pub,)).fetchone()
            if old and (old['actor'],old['mailbox'])!=(actor,bound['mailbox_pk']):
                raise InvariantError('coin key claimed by competing actors')
            old_record=store.db.execute('SELECT script FROM owner_record WHERE mailbox=? AND seq=?',(bound['mailbox_pk'],bound['seq'])).fetchone()
            if old_record and old_record['script']!=bound['spk']:raise InvariantError('same signed sequence has conflicting scripts')
            store.db.execute('INSERT OR IGNORE INTO owner_key VALUES (?,?,?,?)',(pub,actor,bound['mailbox_pk'],canonical(proof)))
            store.db.execute('INSERT OR IGNORE INTO owner_record VALUES (?,?,?,?,?)',(actor,bound['mailbox_pk'],bound['seq'],bound['spk'],canonical(bound)))
            if item['kind']=='coin':
                coin=item['coin']
                store.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET signed_hash=excluded.signed_hash,signed_vtxo=excluded.signed_vtxo,proof=excluded.proof',
                    (coin['id'],pub,coin['amount_sat'],item['signed_hash'],coin['signed_vtxo'],canonical(proof)))
                store.db.execute('UPDATE client_coin_candidate SET verified=1 WHERE id=? AND actor=? AND digest=?',(coin['id'],actor,digest({**coin,'binding':item['request_binding']})))
                store.db.execute('INSERT OR IGNORE INTO coin_observation VALUES (?,?,?,?)',(coin['id'],action_id,coin['state'],time.time()))
        for movement in verified['movements']:
            public_payload(movement)
            store.db.execute('INSERT INTO movement_evidence VALUES (?,?,?) ON CONFLICT(actor,movement_id) DO UPDATE SET payload=excluded.payload',
                (actor,movement['id'],canonical(movement)))
            for direction,field in [('input','input_vtxos'),('output','output_vtxos')]:
                ids=movement[field]
                if len(ids)!=len(set(ids)):raise InvariantError('duplicate movement edge')
                for coin in ids:
                    store.db.execute('INSERT OR IGNORE INTO movement_edge VALUES (?,?,?,?)',(actor,movement['id'],coin,direction))
        store._event('public_ownership_verified',{'actor':actor,'action_id':action_id,'objects':len(verified['objects']),
            'movements':len(verified['movements']),'scope':'signatures and confirmed backing; durable ownership/spend arbitration checked separately'})

def record_server_page(store, page):
    kind=page['kind'];fields={'coins':'vtxo_id','pending':'vtxo_id','links':'user_pubkey','settlements':'id','records':'mailbox_pk','nursery':'txid'}
    if kind not in fields or page.get('inventory_consistent') is not False:raise ValueError('unsupported inventory evidence')
    rows=page['rows']
    if not isinstance(rows,list) or len(rows)>100:raise ValueError('inventory page cap')
    public_payload(rows)
    with store.transaction():
        for row in rows:
            key=row[fields[kind]];encoded=canonical(row);at=time.time();hashed=digest(row)
            store.db.execute('INSERT INTO server_item VALUES (?,?,?,?) ON CONFLICT(kind,id) DO UPDATE SET payload=excluded.payload,observed_at=excluded.observed_at',(kind,key,encoded,at))
            inserted=store.db.execute('INSERT OR IGNORE INTO server_item_version VALUES (?,?,?,?,?)',(kind,key,hashed,encoded,at)).rowcount
            if inserted:store._event('server_inventory_item',{'kind':kind,'id':key,'digest':hashed,'evidence':row})
        store._event('server_inventory_page',{'kind':kind,'rows':len(rows),'next':page['next'],'inventory_consistent':False})

class EvidenceGap(ValueError):pass

def expiry_owner(store, coin_id, pre_state):
    """Never substitute leaf recipient for an unregistered input's owner."""
    row=store.db.execute('SELECT * FROM owned_coin WHERE id=?',(coin_id,)).fetchone()
    if row is None:raise EvidenceGap('no independently validated signed coin')
    proof=json.loads(row['proof'])
    key=proof['user_pubkey']
    if pre_state=='unregistered':
        last=proof['path'][-1] if proof.get('path') else None
        if last is None or len(last['inputs'])!=1:raise EvidenceGap('unregistered parent is ambiguous')
        parent=last['inputs'][0]
        prior=store.db.execute('SELECT pubkey FROM owned_coin WHERE id=?',(parent,)).fetchone()
        state=store.db.execute("SELECT payload FROM server_item WHERE kind='coins' AND id=?",(parent,)).fetchone()
        if prior is None or state is None:raise EvidenceGap('unregistered parent evidence missing')
        if json.loads(state['payload']).get('oor_spent_txid')!=coin_id.split(':')[0]:raise EvidenceGap('parent did not commit this virtual spend')
        key=prior['pubkey']
    elif pre_state not in {'spendable','unclaimed','htlc-recv-unclaimed','pending-board'}:
        raise EvidenceGap('unknown pre-settlement spend state')
    owner=store.db.execute('SELECT actor,mailbox FROM owner_key WHERE pubkey=?',(key,)).fetchone()
    if owner is None:raise EvidenceGap('rightful owner key lacks verified wallet link')
    return {'actor':owner['actor'],'mailbox':owner['mailbox'],'pubkey':key,'amount_sat':row['amount_sat']}


def record_candidates(store, actor, action_id, data, verification_failed=False):
    evidence=data.get('evidence',{});binding=evidence.get('binding',data.get('binding'))
    if not isinstance(binding,dict):return
    for coin in evidence.get('coins',[]):
        value={**coin,'binding':binding};public_payload(value)
        # Signature nonces can differ on every read while the signed coin and
        # proven owner record stay identical. Keep every unverified request;
        # a confirmed, independently verified immutable ownership proof makes
        # another candidate unnecessary. State observations still pass through
        # record_verified, and existing raw evidence is never deleted.
        old=store.db.execute('SELECT c.*,k.actor FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey WHERE c.id=?',(coin['id'],)).fetchone()
        if not verification_failed and old and old['actor']==actor and old['signed_vtxo']==coin['signed_vtxo'] and old['pubkey']==coin['user_pubkey'] and old['amount_sat']==coin['amount_sat']:
            cached=json.loads(old['proof']);bound=cached.get('binding',{})
            if (cached.get('signed_path_valid') is True and cached.get('anchor_confirmations',0)>=1
                    and cached.get('expiry_height')==coin['expiry_height']
                    and bound.get('key_link_signature_valid') is True and bound.get('record_signature_valid') is True
                    and all(bound.get(k)==binding.get(k) for k in ('mailbox_pk','seq','spk'))):
                continue
        store.db.execute('INSERT OR IGNORE INTO client_coin_candidate(id,actor,action_id,digest,payload) VALUES (?,?,?,?,?)',
            (coin['id'],actor,action_id,digest(value),canonical(value)))

async def retry_public_candidates(store, proof_command, limit=8):
    if not proof_command:return
    # Rotation prevents one unconfirmed/bad candidate starving later ones. Each
    # stored proof is public; absence never causes an original-wallet call.
    rows=store.db.execute('SELECT rowid,* FROM client_coin_candidate WHERE verified=0 ORDER BY rowid').fetchall()
    if not rows:return
    after=int(store.get_meta('ownership_retry_cursor') or '0')
    ordered=[r for r in rows if r['rowid']>after]+[r for r in rows if r['rowid']<=after]
    for row in ordered[:limit]:
        value=json.loads(row['payload'])
        try:
            proof=await verify_client_evidence(store,row['actor'],'snapshot',{'evidence':{'binding':value['binding'],'coins':[value]}},proof_command)
            record_verified(store,row['actor'],row['action_id'],proof)
        except InvariantError:raise
        except Exception:
            pass # An unavailable/unconfirmed proof stays explicitly unverified.
        store.db.execute("INSERT OR REPLACE INTO meta VALUES ('ownership_retry_cursor',?)",(str(row['rowid']),))

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
from .architecture import profile, TWO_STEP, DIRECT_PER_KEY

SCHEMA='''
CREATE TABLE IF NOT EXISTS client_coin_candidate(id TEXT NOT NULL, actor TEXT NOT NULL REFERENCES actor(id), action_id TEXT NOT NULL REFERENCES action(id), digest TEXT NOT NULL, payload TEXT NOT NULL, verified INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(id,digest));
CREATE TABLE IF NOT EXISTS owner_key(pubkey TEXT PRIMARY KEY, actor TEXT NOT NULL REFERENCES actor(id), mailbox TEXT NOT NULL, proof TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS owner_record(actor TEXT NOT NULL REFERENCES actor(id), mailbox TEXT NOT NULL, account_xpub TEXT NOT NULL, script TEXT NOT NULL, proof TEXT NOT NULL, PRIMARY KEY(mailbox));
CREATE TABLE IF NOT EXISTS owned_coin(id TEXT PRIMARY KEY, pubkey TEXT NOT NULL REFERENCES owner_key(pubkey), amount_sat INTEGER NOT NULL, signed_hash TEXT NOT NULL, signed_vtxo TEXT NOT NULL, proof TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS coin_observation(coin_id TEXT NOT NULL REFERENCES owned_coin(id), action_id TEXT NOT NULL REFERENCES action(id), state TEXT NOT NULL, observed_at REAL NOT NULL, PRIMARY KEY(coin_id,action_id));
CREATE TABLE IF NOT EXISTS client_movement_candidate(actor TEXT NOT NULL REFERENCES actor(id), action_id TEXT NOT NULL REFERENCES action(id), movement_id TEXT NOT NULL, digest TEXT NOT NULL, payload TEXT NOT NULL, promoted INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(actor,movement_id,digest));
CREATE TABLE IF NOT EXISTS movement_evidence(actor TEXT NOT NULL REFERENCES actor(id), movement_id TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(actor,movement_id));
CREATE TABLE IF NOT EXISTS movement_edge(actor TEXT NOT NULL, movement_id TEXT NOT NULL, coin_id TEXT NOT NULL, direction TEXT NOT NULL CHECK(direction IN ('input','output')), PRIMARY KEY(actor,movement_id,coin_id,direction));
CREATE TABLE IF NOT EXISTS server_item(kind TEXT NOT NULL, id TEXT NOT NULL, payload TEXT NOT NULL, observed_at REAL NOT NULL, PRIMARY KEY(kind,id));
CREATE TABLE IF NOT EXISTS server_item_version(kind TEXT NOT NULL, id TEXT NOT NULL, digest TEXT NOT NULL, payload TEXT NOT NULL, observed_at REAL NOT NULL, PRIMARY KEY(kind,id,digest));
'''

def initialize(store):
    legacy = profile(store) == TWO_STEP
    per_key = profile(store) == DIRECT_PER_KEY
    columns={row[1] for row in store.db.execute('PRAGMA table_info(owner_record)')}
    if columns and ('seq' if legacy else 'record_version' if per_key else 'account_xpub') not in columns:
        raise ValueError('ownership schema differs from campaign profile; no historical database migration')
    schema = SCHEMA
    if legacy:
        schema = schema.replace(
            'account_xpub TEXT NOT NULL, script TEXT NOT NULL, proof TEXT NOT NULL, PRIMARY KEY(mailbox)',
            'seq INTEGER NOT NULL, script TEXT NOT NULL, proof TEXT NOT NULL, PRIMARY KEY(mailbox,seq)')
    elif per_key:
        schema = schema.replace('account_xpub TEXT NOT NULL', 'record_version INTEGER NOT NULL CHECK(record_version=4)')
    store.db.executescript(schema)

def binding_matches(bound, source, *, legacy=False, per_key=False):
    if per_key:
        from .per_key import binding_matches as matches
        return matches(bound, source)
    return all(bound.get(k) is not None and bound.get(k)==source.get(k)
               for k in (('mailbox_pk','seq','spk') if legacy else ('mailbox_pk','account_xpub','spk','fallback_record')))

def account_origin_matches(proof, source):
    bound=proof.get('binding',{})
    return (bound.get('record_signature_valid') is True and bound.get('account_child_verified') is True
        and type(bound.get('child_index')) is int and 0<=bound['child_index']<2**31
        and bound.get('policy_pubkey_full')==source.get('user_pubkey')
        and bound.get('child_index')==source.get('child_index')
        and bound.get('blinded_mailbox_id')==source.get('blinded_mailbox_id'))

def proof_matches_profile(store, proof, source):
    """Consume the selected native verifier's authentic identity contract.

    Per-key proof flags describe record and key-link signatures, never account
    derivation. Cryptographic checks run in the pinned native verifier, not here.
    """
    if profile(store) == DIRECT_PER_KEY:
        from .per_key import proof_matches
        return proof_matches(proof, source)
    if profile(store) != TWO_STEP:
        return account_origin_matches(proof, source)
    bound = proof.get('binding', {})
    return (bound.get('record_signature_valid') is True
        and bound.get('key_link_signature_valid') is True
        and type(bound.get('seq')) is int and 0 <= bound['seq'] <= 2**63-1
        and all(isinstance(bound.get(k), str) and bound[k] for k in ('mailbox_pk','spk'))
        and 'account_xpub' not in bound and 'account_child_verified' not in bound
        and proof.get('user_pubkey') == source.get('user_pubkey'))

def digest(value):return hashlib.sha256(canonical(value).encode()).hexdigest()


def has_owner_record(store, actor, bound):
    """Match already independently verified owner evidence; never create it."""
    selected = profile(store)
    if selected == DIRECT_PER_KEY:
        row = store.db.execute('SELECT script,proof FROM owner_record WHERE actor=? AND mailbox=? AND record_version=4',
            (actor,bound.get('mailbox_pk'))).fetchone()
        return bool(row and row['script']==bound.get('spk')
            and json.loads(row['proof'])['fallback_record']==bound.get('fallback_record'))
    field = 'seq' if selected == TWO_STEP else 'account_xpub'
    return bool(store.db.execute(f'SELECT 1 FROM owner_record WHERE actor=? AND mailbox=? AND {field}=? AND script=?',
        (actor,bound.get('mailbox_pk'),bound.get(field),bound.get('spk'))).fetchone())

async def verify_client_evidence(store, actor, operation, data, proof_command):
    """Independent verifier must run before accepting an ownership claim.

    Returns validated public objects only. Cached immutable proofs still do not
    establish current registration, absence of a competing spend, or settlement.
    """
    legacy = profile(store) == TWO_STEP
    per_key = profile(store) == DIRECT_PER_KEY
    from .target_epochs import active_runtime_manifest
    runtime_transition=active_runtime_manifest(store)
    if not proof_command:
        if per_key and operation == 'create':
            raise ValueError('C create requires independent original key signature verification')
        return None
    evidence=data.get('evidence',{})
    binding=evidence.get('binding',data.get('binding'))
    if not isinstance(binding,dict):return None
    verified=[]
    original_context=store.financial_context()
    if per_key and operation == 'create':
        from .per_key import initial_origins
        for request in initial_origins(data):
            proof = await json_command(list(proof_command),request,timeout=30,
                **public_command_capture(store,'proof.verify',request,actor=actor))
            proof = {**proof,'financial_pins':original_context}
            if (not proof_matches_profile(store,proof,request)
                    or not binding_matches(proof.get('binding',{}),binding,per_key=True)):
                raise InvariantError('initial C acknowledged key signature mismatch')
            verified.append({'kind':'key','proof':proof,'request_origin':request})
    if operation=='address':
        fields = ('user_pubkey','key_link_attestation','binding') if legacy or per_key else ('user_pubkey','child_index','blinded_mailbox_id','binding')
        request={k:data[k] for k in fields}
        proof=await json_command(list(proof_command),request,timeout=30,**public_command_capture(store,'proof.verify',request,actor=actor))
        if proof['user_pubkey']!=data['user_pubkey']:raise InvariantError('advertised key verification mismatch')
        proof={**proof,'financial_pins':original_context}
        if not proof_matches_profile(store,proof,data) or not binding_matches(proof.get('binding',{}),binding,legacy=legacy,per_key=per_key):raise InvariantError('advertised ownership origin mismatch')
        verified.append({'kind':'key','proof':proof,'request_origin':data})
    for coin in evidence.get('coins',[]):
        request={**coin,'binding':binding}
        signed_hash=hashlib.sha256(bytes.fromhex(coin['signed_vtxo'])).hexdigest()
        old=store.db.execute('SELECT * FROM owned_coin WHERE id=?',(coin['id'],)).fetchone()
        if old:
            if old['pubkey']!=coin['user_pubkey'] or old['amount_sat']!=coin['amount_sat']:
                raise InvariantError('immutable signed coin changed')
            cached=json.loads(old['proof'])
            if (runtime_transition is None and old['signed_hash']==signed_hash and binding_matches(cached.get('binding',{}),binding,legacy=legacy,per_key=per_key)
                    and proof_matches_profile(store,cached,coin) and cached.get('financial_pins')==original_context):
                proof=cached
            else:proof=await json_command(list(proof_command),request,timeout=30,**public_command_capture(store,'proof.verify',request,actor=actor))
        else:proof=await json_command(list(proof_command),request,timeout=30,**public_command_capture(store,'proof.verify',request,actor=actor))
        proof={**proof,'financial_pins':original_context}
        if not proof_matches_profile(store,proof,coin) or not binding_matches(proof.get('binding',{}),binding,legacy=legacy,per_key=per_key):raise InvariantError('coin ownership origin mismatch')
        if (proof['id'],proof['user_pubkey'],proof['amount_sat'])!=(coin['id'],coin['user_pubkey'],integer(coin['amount_sat'],'coin amount',1)):
            raise InvariantError('independent coin evidence mismatch')
        if (proof.get('authorization_path_valid') is not True and proof.get('signed_path_valid') is not True) or proof.get('anchor_confirmations',0)<1:
            raise ValueError('backing not confirmed')
        verified.append({'kind':'coin','coin':coin,'proof':proof,'signed_hash':signed_hash,'request_binding':binding})
    if store.financial_context()!=original_context:raise ValueError('financial build changed during original proof observation')
    return {'objects':verified,'movements':evidence.get('movements',[]),'financial_pins':original_context}

def record_verified(store, actor, action_id, verified):
    legacy = profile(store) == TWO_STEP
    per_key = profile(store) == DIRECT_PER_KEY
    from .target_epochs import active_runtime_manifest
    runtime_transition=active_runtime_manifest(store)
    if verified is None:return
    with (nullcontext() if store.db.in_transaction else store.transaction()):
        for item in verified['objects']:
            proof=item['proof'];pub=proof['user_pubkey'];bound=proof['binding']
            source=item.get('coin',item.get('request_origin',{}))
            fields = ('mailbox_pk','seq','spk') if legacy else ('mailbox_pk','record_version','spk','fallback_record') if per_key else ('mailbox_pk','account_xpub','spk','fallback_record')
            if not proof_matches_profile(store,proof,source) or not all(bound.get(k) is not None for k in fields):
                raise InvariantError('unverified owner proof')
            old=store.db.execute('SELECT actor,mailbox FROM owner_key WHERE pubkey=?',(pub,)).fetchone()
            if old and (old['actor'],old['mailbox'])!=(actor,bound['mailbox_pk']):
                raise InvariantError('coin key claimed by competing actors')
            if legacy:
                competing=store.db.execute('SELECT 1 FROM owner_record WHERE mailbox=? AND actor!=? LIMIT 1',(bound['mailbox_pk'],actor)).fetchone()
                if competing:raise InvariantError('mailbox claimed by competing actors across signed sequences')
                old_record=store.db.execute('SELECT actor,script FROM owner_record WHERE mailbox=? AND seq=?',(bound['mailbox_pk'],bound['seq'])).fetchone()
                if old_record and (old_record['actor'],old_record['script'])!=(actor,bound['spk']):raise InvariantError('same signed sequence has conflicting owner or script')
            elif per_key:
                old_record=store.db.execute('SELECT actor,script,proof FROM owner_record WHERE mailbox=?',(bound['mailbox_pk'],)).fetchone()
                if old_record and ((old_record['actor'],old_record['script'])!=(actor,bound['spk'])
                        or json.loads(old_record['proof'])['fallback_record']!=bound['fallback_record']):
                    raise InvariantError('immutable per-key wallet identity conflict')
            else:
                old_record=store.db.execute('SELECT actor,script,account_xpub FROM owner_record WHERE mailbox=?',(bound['mailbox_pk'],)).fetchone()
                if old_record and (old_record['actor'],old_record['script'],old_record['account_xpub'])!=(actor,bound['spk'],bound['account_xpub']):raise InvariantError('immutable wallet identity conflict')
            store.db.execute('INSERT OR IGNORE INTO owner_key VALUES (?,?,?,?)',(pub,actor,bound['mailbox_pk'],canonical(proof)))
            store.db.execute('INSERT OR IGNORE INTO owner_record VALUES (?,?,?,?,?)',(actor,bound['mailbox_pk'],bound['seq'] if legacy else 4 if per_key else bound['account_xpub'],bound['spk'],canonical(bound)))
            if item['kind']=='coin':
                coin=item['coin']
                original=store.db.execute('SELECT * FROM owned_coin WHERE id=?',(coin['id'],)).fetchone()
                if runtime_transition is not None and original is not None:
                    if (original['pubkey']!=pub or original['amount_sat']!=coin['amount_sat']
                            or original['signed_hash']!=item['signed_hash'] or original['signed_vtxo']!=coin['signed_vtxo']):
                        raise InvariantError('runtime transition cannot replace original signed object')
                    store._event('public_ownership_reverified',{'actor':actor,'action_id':action_id,'coin_id':coin['id'],
                        'signed_hash':item['signed_hash'],'original_proof_sha256':hashlib.sha256(original['proof'].encode()).hexdigest(),
                        'current_proof':proof,'scope':'current verification of unchanged signed object; original proof retained'})
                else:
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
            'movements':len(verified['movements']),'financial_pins':verified.get('financial_pins'),'scope':'signatures and confirmed backing; durable ownership/spend arbitration checked separately'})

def record_server_page(store, page):
    kind=page['kind'];fields={'coins':'vtxo_id','pending':'vtxo_id','links':'user_pubkey','settlements':'id','records':'mailbox_pk','nursery':'txid'}
    if kind not in fields or page.get('inventory_consistent') is not False:raise ValueError('unsupported inventory evidence')
    rows=page['rows']
    if not isinstance(rows,list) or len(rows)>100:raise ValueError('inventory page cap')
    public_payload(rows)
    with (nullcontext() if store.db.in_transaction else store.transaction()):
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
    legacy = profile(store) == TWO_STEP
    per_key = profile(store) == DIRECT_PER_KEY
    evidence=data.get('evidence',{});binding=evidence.get('binding',data.get('binding'))
    if not isinstance(binding,dict):return
    action=store.db.execute('SELECT actor_id FROM action WHERE id=?',(action_id,)).fetchone()
    if evidence.get('movements') and (action is None or action['actor_id']!=actor):raise InvariantError('public movement source belongs to another actor')
    # Keep original SDK claims even if an unrelated coin rejects the proof
    # batch. These are pending metadata, not signed evidence or fee credit.
    for movement in evidence.get('movements',[]):
        public_payload(movement)
        if not isinstance(movement,dict) or not isinstance(movement.get('id'),str) or not 1<=len(movement['id'])<=128:
            raise ValueError('bounded original movement identity required')
        payload=canonical(movement)
        existing=store.db.execute('SELECT payload FROM movement_evidence WHERE actor=? AND movement_id=?',(actor,movement['id'])).fetchone()
        if existing is not None and existing['payload']==payload:continue
        store.db.execute('INSERT OR IGNORE INTO client_movement_candidate(actor,action_id,movement_id,digest,payload) VALUES (?,?,?,?,?)',
            (actor,action_id,movement['id'],digest(movement),payload))
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
                    and proof_matches_profile(store,cached,coin) and binding_matches(bound,binding,legacy=legacy,per_key=per_key)
                    and cached.get('financial_pins')==store.financial_context()):
                continue
        store.db.execute('INSERT OR IGNORE INTO client_coin_candidate(id,actor,action_id,digest,payload) VALUES (?,?,?,?,?)',
            (coin['id'],actor,action_id,digest(value),canonical(value)))

def promote_public_movements(store,limit=64):
    """Use the original observation only after every referenced coin is proved.

    Never open a wallet, discard a batch failure, close a fee reservation or
    infer a missing movement from an amount. Contradictory source observations
    and conflicting existing movement versions remain pending.
    """
    from .campaign import _signed_coin
    after=int(store.get_meta('movement_retry_cursor') or '0')
    # Use stable candidate rowids for bounded round-robin work.
    rows=store.db.execute("""SELECT c.rowid AS candidate_rowid,c.*,a.state,a.actor_id,a.updated_at
        FROM client_movement_candidate c JOIN action a ON a.id=c.action_id
        WHERE c.promoted=0 ORDER BY c.rowid""").fetchall()
    ordered=[r for r in rows if r['candidate_rowid']>after]+[r for r in rows if r['candidate_rowid']<=after]
    for row in ordered[:limit]:
        with (nullcontext() if store.db.in_transaction else store.transaction()):
            store.db.execute("INSERT OR REPLACE INTO meta VALUES ('movement_retry_cursor',?)",(str(row['candidate_rowid']),))
            if row['state']!='completed' or row['actor_id']!=row['actor']:continue
            if store.db.execute("""SELECT 1 FROM event WHERE kind IN ('ownership_incident','ownership_contradiction')
                AND json_extract(payload,'$.action_id')=? LIMIT 1""",(row['action_id'],)).fetchone():continue
            source=json.loads(store.db.execute('SELECT result FROM action WHERE id=?',(row['action_id'],)).fetchone()[0] or '{}')
            original=source.get('data',{}).get('evidence',{}).get('movements',[])
            if not any(canonical(value)==row['payload'] for value in original):continue
            movement=json.loads(row['payload'])
            if movement.get('id')!=row['movement_id'] or digest(movement)!=row['digest']:
                raise InvariantError('frozen public movement claim changed')
            refs=[]
            for field in ('input_vtxos','output_vtxos'):
                values=movement.get(field)
                if not isinstance(values,list) or any(not isinstance(v,str) or not v for v in values) or len(values)!=len(set(values)):break
                refs.extend(values)
            else:
                if not refs or len(refs)!=len(set(refs)) or any(_signed_coin(store,v,row['actor']) is None for v in refs):continue
                existing=store.db.execute('SELECT payload FROM movement_evidence WHERE actor=? AND movement_id=?',(row['actor'],row['movement_id'])).fetchone()
                if existing is not None and existing['payload']!=row['payload']:continue
                record_verified(store,row['actor'],row['action_id'],{'objects':[],'movements':[movement]})
                store.db.execute('UPDATE client_movement_candidate SET promoted=1 WHERE rowid=?',(row['candidate_rowid'],))
                store._event('public_movement_claim_promoted',{'actor':row['actor'],'action_id':row['action_id'],
                    'movement_id':row['movement_id'],'claim_digest':row['digest'],'original_action_updated_at':row['updated_at'],
                    'independently_verified_coin_ids':refs,'fee_reservation_released':False,
                    'scope':'original SDK metadata linked to already accepted same-owner signed proofs; payment and traffic require their separate exact oracles'})

async def retry_public_candidates(store, proof_command, limit=8):
    if not proof_command:return
    # Rotation prevents one unconfirmed/bad candidate starving later ones. Each
    # stored proof is public; absence never causes an original-wallet call.
    rows=store.db.execute('SELECT rowid,* FROM client_coin_candidate WHERE verified=0 ORDER BY rowid').fetchall()
    if not rows:
        promote_public_movements(store)
        return
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
    promote_public_movements(store)

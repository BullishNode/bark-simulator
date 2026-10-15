"""Resolve unknown actions from positive public proofs, never by monetary retry.

Stored signed proofs were independently validated by the ownership collector.
Chain transactions passed to resolve must come from an identity-checked reader.
Reconciliation preserves the original activity time and client online state.
"""
import asyncio,base64,datetime,hashlib,json,re,sqlite3
from .model import InvariantError,canonical,integer,public_payload,transaction_fee
from .ownership import EvidenceGap, binding_matches, proof_matches_profile
from .architecture import profile, TWO_STEP
from .fees import movement_fee,board_fee,offboard_fee,_proposal
from .campaign import _receipt_origin
from .process import json_command


def _intent(store,action):
    rows=store.db.execute("SELECT payload FROM event WHERE kind='action_intent' AND json_extract(payload,'$.action_id')=?",(action['id'],)).fetchall()
    if len(rows)!=1:raise EvidenceGap('unknown action lacks one original authorizing intent')
    original=json.loads(rows[0][0])
    expected=(action['actor_id'],action['operation'],json.loads(action['args']),action['fee_reservation_sat'])
    actual=(original['actor'],original['operation'],original['args'],original['fee_reservation_sat'])
    if actual!=expected:raise InvariantError('unknown action identity, arguments or fee budget changed since authorization')


def _owner_record_matches(store,actor,binding):
    legacy=profile(store)==TWO_STEP
    field='seq' if legacy else 'account_xpub'
    if legacy and (type(binding.get('seq')) is not int or not 0<=binding['seq']<=2**63-1):
        return False
    row=store.db.execute('SELECT proof FROM owner_record WHERE actor=? AND mailbox=? AND '+field+'=? AND script=?',
        (actor,binding.get('mailbox_pk'),binding.get(field),binding.get('spk'))).fetchone()
    return row is not None and binding_matches(json.loads(row['proof']),binding,legacy=legacy)


def _coins(store,ids,actor):
    if not ids or len(ids)!=len(set(ids)):raise EvidenceGap('signed principal set is empty or ambiguous')
    coins=[]
    for coin_id in ids:
        coin=store.db.execute('SELECT c.*,k.actor,k.mailbox FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey WHERE c.id=?',(coin_id,)).fetchone()
        if coin is None:raise EvidenceGap('unknown outcome awaits independent signed coin proof')
        if coin['actor']!=actor:raise InvariantError('unknown outcome uses another actor principal')
        proof=json.loads(coin['proof']);binding=proof.get('binding') or {}
        integer(proof.get('amount_sat'),'signed proof amount',1)
        if (proof.get('id'),proof.get('user_pubkey'),proof.get('amount_sat'))!=(coin['id'],coin['pubkey'],coin['amount_sat']):
            raise InvariantError('unknown outcome signed identity or value changed')
        if (proof.get('signed_path_valid') is not True or type(proof.get('anchor_confirmations')) is not int
                or proof['anchor_confirmations']<1
                or not proof_matches_profile(store,proof,{'user_pubkey':coin['pubkey'],
                    'child_index':binding.get('child_index'),'blinded_mailbox_id':binding.get('blinded_mailbox_id')})):
            raise EvidenceGap('unknown outcome signed proof is incomplete')
        if binding.get('mailbox_pk')!=coin['mailbox'] or not _owner_record_matches(store,actor,binding):
            raise EvidenceGap('unknown outcome lacks checked owner record')
        if hashlib.sha256(bytes.fromhex(coin['signed_vtxo'])).hexdigest()!=coin['signed_hash']:
            raise InvariantError('unknown outcome signed bytes changed')
        coins.append((coin,proof))
    return coins


def _reply(store,action):
    rows=store.db.execute("SELECT sequence,payload FROM event WHERE kind='driver_response' AND json_extract(payload,'$.action_id')=?",(action['id'],)).fetchall()
    if len(rows)!=1:raise EvidenceGap('unknown outcome lacks one preserved native reply')
    response=json.loads(rows[0]['payload'])['response'];public_payload(response)
    if response.get('action_id')!=action['id']:raise InvariantError('unknown native reply has another action identity')
    if response.get('status')=='incident':raise InvariantError('unknown native reply reported an invariant failure')
    if response.get('status')!='ok':raise EvidenceGap('a native error/refusal cannot prove a monetary outcome')
    return response,rows[0]['sequence']


def boundary_evidence(store,action,phase,data):
    """Load one exact fresh boundary, including a journal-pinned trace record."""
    if data.get('fresh') is not True:raise EvidenceGap('unknown read evidence is not a current wallet capture')
    if 'trace_ref' not in data:return data['evidence']
    reference=data['trace_ref']
    if not isinstance(reference,dict) or set(reference)!={'partition','seq','hash'}:raise EvidenceGap('incomplete native boundary trace reference')
    name=reference['partition'];sequence=integer(reference['seq'],'trace reference sequence',1);digest=reference['hash']
    if not isinstance(name,str) or re.fullmatch(r'trace-\d{4}-\d{2}-\d{2}\.sqlite',name) is None:raise EvidenceGap('invalid boundary trace partition')
    datetime.date.fromisoformat(name[6:16])
    if not isinstance(digest,str) or re.fullmatch(r'[0-9a-f]{64}',digest) is None:raise EvidenceGap('invalid boundary trace hash')
    root=store.root;paths=[root/name,root/'trace-archive'/name]
    if any(p.is_symlink() for path in paths for p in [path,*path.parents]):raise InvariantError('boundary trace path is a symlink')
    present=[path for path in paths if path.is_file()]
    if not present:raise EvidenceGap('native boundary trace partition is unavailable')
    if len(present)!=1:raise InvariantError('native boundary trace partition is duplicated')
    connection=sqlite3.connect(present[0].resolve().as_uri()+'?mode=ro',uri=True);connection.row_factory=sqlite3.Row
    try:
        row=connection.execute('SELECT * FROM trace WHERE seq=? AND length(CAST(payload AS BLOB))+COALESCE(length(raw),0)<=?',(sequence,16*1024*1024)).fetchone()
    except sqlite3.Error:raise EvidenceGap('native boundary trace record is unavailable') from None
    finally:connection.close()
    if row is None:raise EvidenceGap('native boundary trace record is missing or oversized')
    raw=row['raw']
    if raw is not None and not isinstance(raw,bytes):raise InvariantError('native boundary trace raw bytes changed')
    calculated=hashlib.sha256(canonical([row['seq'],row['utc'],row['schema_version'],row['kind'],row['actor'],row['action_id'],row['payload'],
        base64.b64encode(raw).decode() if raw is not None else None,row['previous_hash']]).encode()).hexdigest()
    if row['seq']!=sequence or row['schema_version']!=1 or row['hash']!=digest or calculated!=digest:raise InvariantError('native boundary trace reference/hash changed')
    if datetime.datetime.fromtimestamp(row['utc'],datetime.timezone.utc).date().isoformat()!=name[6:16]:raise InvariantError('native boundary trace record changed its UTC partition')
    payload=json.loads(row['payload']);public_payload(payload)
    if raw is not None:public_payload(raw.decode('utf-8'))
    if ((row['kind'],row['actor'],row['action_id'])!=('driver.event',action['actor_id'],action['id'])
            or (payload.get('kind'),payload.get('action_id'),payload.get('operation'),payload.get('event'))!=
                ('driver_event',action['id'],action['operation'],'client_evidence_'+phase)):
        raise InvariantError('native boundary trace was rebound to another actor, action, operation or phase')
    full=payload['data']
    if full.get('fresh') is not True:raise EvidenceGap('native boundary trace is not fresh')
    if 'evidence' in data and canonical(data['evidence'])!=canonical(full['evidence']):raise InvariantError('inline and referenced native boundaries differ')
    return full['evidence']


def _frame(store,action,phase):
    rows=store.db.execute("SELECT sequence,payload FROM event WHERE kind='driver_evidence' AND json_extract(payload,'$.action_id')=? AND json_extract(payload,'$.event')=?",
        (action['id'],'client_evidence_'+phase)).fetchall()
    if len(rows)!=1:raise EvidenceGap('unknown read lacks unique fresh native evidence boundaries')
    data=json.loads(rows[0]['payload'])['data']
    evidence=boundary_evidence(store,action,phase,data);binding=evidence['binding']
    if not _owner_record_matches(store,action['actor_id'],binding):
        raise EvidenceGap('unknown native boundary lacks verified actor binding')
    ids=[c['id'] for c in evidence['coins']]
    if len(ids)!=len(set(ids)):raise InvariantError('native boundary duplicates a coin')
    if ids:
        signed={c['id']:c for c,_ in _coins(store,ids,action['actor_id'])}
        for c in evidence['coins']:
            known=signed[c['id']]
            if (c['signed_vtxo'],c['amount_sat'],c['user_pubkey'])!=(known['signed_vtxo'],known['amount_sat'],known['pubkey']):
                raise InvariantError('native boundary differs from independently signed ownership')
    return evidence,rows[0]['sequence']


def _tx(transactions,txid):
    if txid not in transactions:raise EvidenceGap('unknown outcome awaits confirmed independent transaction')
    tx=transactions[txid]
    if tx.get('txid')!=txid:raise InvariantError('unknown transaction proof has another identity')
    if type(tx.get('confirmations')) is not int or tx['confirmations']<1:raise EvidenceGap('unknown transaction is unconfirmed')
    if transaction_fee(tx)!=integer(tx['fee_sat'],'confirmed fee'):raise InvariantError('unknown transaction fee does not conserve')
    if len({i['outpoint'] for i in tx['inputs']})!=len(tx['inputs']):raise InvariantError('unknown transaction repeats an input')
    return tx


def _refresh(store,action,data):
    proposal=_proposal(store,action,'refresh_proposal')
    fee=integer(proposal['committed_fee_sat'],'frozen refresh fee')
    if data.get('committed_fee_sat') not in (None,fee):raise InvariantError('native refresh outcome changed its frozen charge')
    data['committed_fee_sat']=fee
    proxy={**action,'result':canonical({'data':data})};proof=movement_fee(store,proxy)
    _coins(store,proof['input_coin_ids'],action['actor_id'])
    if proof['output_coin_ids']:_coins(store,proof['output_coin_ids'],action['actor_id'])
    return proof


def _lightning(store,action,data,status):
    proposal=_proposal(store,action,'lightning_proposal');value=proposal['payment_hash']
    if proposal['amount_sat']!=json.loads(action['args'])['amount_sat']:raise InvariantError('native Lightning principal changed from authorized request')
    if not isinstance(value,str) or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):raise EvidenceGap('unknown Lightning hash is malformed')
    if status is None:raise EvidenceGap('unknown Lightning send awaits native preimage verification')
    public_payload(status)
    if status.get('action_id')!='unknown-status:'+action['id']:raise InvariantError('unknown payment status has another query identity')
    if status.get('status')=='incident':raise InvariantError('native unknown payment status failed its invariant checks')
    if status.get('status')!='ok':raise EvidenceGap('unknown payment status unavailable')
    observed=status['data']
    if (observed.get('payment_hash')!=value or observed.get('read_only') is not True
            or type(status.get('actual_fee_sat')) is not int or status['actual_fee_sat']!=0):raise InvariantError('unknown payment status is not the exact readonly frozen query')
    state=observed.get('state')
    if state not in {'pending','failed','succeeded'}:raise InvariantError('unknown payment status has unsupported state')
    if observed.get('success_preimage_hash_valid') is not (state=='succeeded'):raise InvariantError('unknown payment success lacks validated preimage hash')
    if state!='succeeded':raise EvidenceGap('pending/failed status is not a checked success or refund')
    data.update(payment_hash=value,payment_state='succeeded',payment_status_verified=True,paid=True)
    proof=movement_fee(store,{**action,'result':canonical({'data':data})})
    _coins(store,proof['input_coin_ids'],action['actor_id'])
    if proof['output_coin_ids']:_coins(store,proof['output_coin_ids'],action['actor_id'])
    proof['native_payment_status']=status
    return proof


def _ark(store,action,data):
    args=json.loads(action['args']);proposal=_proposal(store,action,'arkoor_request');ids=proposal['input_vtxo_ids']
    amount=integer(args['amount_sat'],'frozen Ark payment',1);recipient=args.get('recipient_actor')
    if proposal.get('destination')!=args['destination'] or proposal['amount_sat']!=amount:raise InvariantError('Ark proposal changed the original destination or amount')
    if not recipient or recipient==action['actor_id']:raise EvidenceGap('unknown Ark send lacks an exact prior recipient identity')
    inputs=_coins(store,ids,action['actor_id'])
    for row in store.db.execute("SELECT payload FROM event WHERE kind='driver_evidence' AND json_extract(payload,'$.event')='arkoor_request' AND json_extract(payload,'$.action_id')!=?",(action['id'],)):
        if set(ids)&set(json.loads(row[0])['data'].get('input_vtxo_ids',[])):raise EvidenceGap('unknown Ark inputs belong to another frozen send')
    sender=[]
    for row in store.db.execute('SELECT payload FROM movement_evidence WHERE actor=?',(action['actor_id'],)):
        m=json.loads(row[0])
        if (m.get('subsystem')=='bark.arkoor' and m.get('status')=='successful' and sorted(m.get('input_vtxos',[]))==sorted(ids)
                and m.get('offchain_fee_sat')==0 and m.get('effective_balance_sat')==-amount):sender.append(m)
    if len(sender)!=1:raise EvidenceGap('unknown Ark send lacks unique successful input movement')
    addresses=store.db.execute("SELECT result FROM action WHERE actor_id=? AND operation='address' AND state='completed' AND updated_at<=? AND json_extract(result,'$.data.address')=?",
        (recipient,action['updated_at'],args['destination'])).fetchall()
    keys={json.loads(r[0])['data'].get('user_pubkey') for r in addresses}
    if len(keys)!=1 or None in keys:raise EvidenceGap('unknown Ark recipient lacks one prior advertised key')
    key=next(iter(keys));receipts=[]
    claimed={json.loads(r[0]).get('receipt_movement_id') for r in store.db.execute("SELECT payload FROM event WHERE kind='ark_transfer_verified' AND json_extract(payload,'$.recipient_actor')=? AND json_extract(payload,'$.action_id')!=?",(recipient,action['id']))}
    for row in store.db.execute('SELECT payload FROM movement_evidence WHERE actor=?',(recipient,)):
        m=json.loads(row[0]);outs=m.get('output_vtxos',[])
        if (m.get('subsystem')!='bark.arkoor' or m.get('status')!='successful' or m.get('input_vtxos')!=[]
                or not outs or m.get('offchain_fee_sat')!=0 or m.get('effective_balance_sat')!=amount or m['id'] in claimed):continue
        proved=_coins(store,outs,recipient)
        if all(c['pubkey']==key and _receipt_origin(p,set(ids)) is not None for c,p in proved) and sum(c['amount_sat'] for c,_ in proved)==amount:
            receipts.append((m,proved))
    if len(receipts)!=1:raise EvidenceGap('unknown Ark send lacks a unique directly linked signed recipient receipt')
    change=_coins(store,sender[0]['output_vtxos'],action['actor_id']) if sender[0]['output_vtxos'] else []
    if sum(c['amount_sat'] for c,_ in inputs)!=amount+sum(c['amount_sat'] for c,_ in change):raise InvariantError('unknown Ark signed principal does not conserve')
    data.update(submitted='send_arkoor',amount_sat=amount)
    return {'actor':action['actor_id'],'actual_fee_sat':0,'input_coin_ids':ids,'output_coin_ids':sender[0]['output_vtxos'],
        'movement_id':sender[0]['id'],'recipient_actor':recipient,'receipt_movement_id':receipts[0][0]['id'],
        'receipt_coin_ids':[c['id'] for c,_ in receipts[0][1]],'scope':'directly linked signed recipient receipt and signed payer change; no absence inference'}


def _exit(store,action,data,transactions):
    rows=[json.loads(r[0])['data'] for r in store.db.execute("SELECT payload FROM event WHERE kind='driver_evidence' AND json_extract(payload,'$.action_id')=? AND json_extract(payload,'$.event')='exit_proposal' ORDER BY sequence",(action['id'],))]
    starts=[p for p in rows if p.get('stage')=='start'];claims=[p for p in rows if p.get('stage')=='claim'];cpfps=[p for p in rows if p.get('stage')=='cpfp']
    if len(starts)!=1 or len(claims)!=1:raise EvidenceGap('unknown exit lacks a unique frozen start and complete claim')
    start=starts[0];args=json.loads(action['args']);ids=start['input_vtxo_ids']
    if (ids!=args['input_vtxo_ids'] or start['fee_funding_outpoint']!=args['fee_funding_outpoint']
            or start['fee_rate_kwu']!=integer(args['fee_rate_sat_per_vb'],'authorized exit fee rate',1)*250
            or start.get('no_automatic_fee_bumps') is not True):raise InvariantError('exit proposal changed the exact original inputs, fee rate or source')
    coins=_coins(store,ids,action['actor_id'])
    if start['signed_vtxos']!=[c['signed_vtxo'] for c,_ in coins]:raise InvariantError('exit original signed input set changed')
    cap=integer(start['fee_cap_sat'],'exit frozen fee budget')
    if cap!=action['fee_reservation_sat']:raise InvariantError('exit budget differs from original reservation')
    script=start['destination_script']
    if not store.db.execute('SELECT 1 FROM owner_record WHERE actor=? AND script=?',(action['actor_id'],script)).fetchone():raise EvidenceGap('exit destination lacks independently checked owner record')
    seen=set();fee=0;confirmed=[];source=start['fee_funding_outpoint']
    for step in cpfps+claims:
        tx=_tx(transactions,step['txid'])
        if tx['txid'] in seen:raise InvariantError('exit repeats a reserved transaction')
        seen.add(tx['txid'])
        if step['fee_cap_sat']!=cap or step['destination_script']!=script or step['input_vtxo_ids']!=ids:
            raise InvariantError('exit step changed its immutable budget or destination')
        if tx['fee_sat']!=step['fee_sat']:raise InvariantError('confirmed exit fee differs from pre-sign exact fee')
        if len(tx['outputs'])!=1 or tx['outputs'][0]['script']!=script:raise InvariantError('exit step does not pay exactly its declared owner')
        expected=[{'outpoint':point,'amount_sat':integer(out['value'],'frozen exit input'),'script':out['script_pubkey']} for point,out in step['inputs']]
        if sorted(tx['inputs'],key=lambda i:i['outpoint'])!=sorted(expected,key=lambda i:i['outpoint']):raise InvariantError('exit confirmation changed the pre-sign input values/scripts')
        if step['stage']=='cpfp':
            if len(expected)!=2 or sum(i['outpoint']==source for i in expected)!=1:raise InvariantError('exit expanded its exact fee source')
            anchor=next(i for i in expected if i['outpoint']!=source)
            path_txids={p['txid'] for _,proof in coins for p in proof.get('path',[])}
            if anchor['script']!='51024e73' or anchor['outpoint'].split(':')[0] not in path_txids:
                raise InvariantError('exit CPFP is not the anchor of an independently signed original exit path')
            source=tx['txid']+':0'
        else:
            if {i['outpoint'] for i in expected}!=set(ids):raise InvariantError('exit claim consumed another principal')
            for c,p in coins:
                leaf=p.get('path',[])[-1] if p.get('path') else None
                if not leaf or str(leaf['txid'])+':'+str(leaf['output_index'])!=c['id']:raise EvidenceGap('exit claim awaits complete signed leaf path')
                value=next(i for i in expected if i['outpoint']==c['id'])
                if (value['amount_sat'],value['script'])!=(c['amount_sat'],leaf['output_script']):raise InvariantError('exit claim differs from independently signed leaf principal')
        if step['prior_reserved_fee_sat']!=fee:raise InvariantError('exit reserved fee order changed')
        fee+=tx['fee_sat'];confirmed.append(tx)
    if fee>cap:raise InvariantError('exit confirmed fees exceeded its immutable cap')
    data.update(finished=True,exit_action_id=action['id'],input_vtxo_ids=ids,txid=claims[0]['txid'])
    return {'actor':action['actor_id'],'actual_fee_sat':fee,'input_coin_ids':ids,'chain_transactions':confirmed,
        'scope':'all pre-sign exit CPFP fees and one whole-principal claim independently confirmed; no wallet reopen or retry'}


def _prove(store,action,transactions,status):
    operation=action['operation'];original=json.loads(action['result'] or '{}');data={}
    _intent(store,action)
    native=None
    replies=store.db.execute("SELECT payload FROM event WHERE kind='driver_response' AND json_extract(payload,'$.action_id')=?",(action['id'],)).fetchall()
    if replies and operation!='exit':
        if len(replies)!=1:raise EvidenceGap('unknown action has ambiguous preserved replies')
        native=json.loads(replies[0][0])['response']
        if native.get('action_id')!=action['id'] or native.get('status')=='incident':raise InvariantError('unknown preserved reply contradicts native action identity')
        if native.get('status')=='ok':data=dict(native.get('data',{}))
    if operation in {'refresh','refresh_delegated'}:proof=_refresh(store,action,data)
    elif operation=='pay_invoice':proof=_lightning(store,action,data,status)
    elif operation=='send_arkoor':proof=_ark(store,action,data)
    elif operation=='exit':proof=_exit(store,action,data,transactions)
    elif operation in {'board','offboard_all'}:
        response,sequence=_reply(store,action);data=dict(response['data'])
        if operation=='board':
            ids=data['board']['vtxos'];coins=_coins(store,ids,action['actor_id']);txid=coins[0][1]['chain_anchor'].split(':')[0]
            proposal=_proposal(store,action,'board_proposal')
            if proposal['funding_txid']!=txid:raise InvariantError('board differs from frozen funding transaction')
            proof=board_fee(store,{**action,'result':canonical({'data':data})},_tx(transactions,txid))
        else:
            proposal=_proposal(store,action,'offboard_proposal');_coins(store,proposal['input_vtxo_ids'],action['actor_id'])
            proof=offboard_fee(store,{**action,'result':canonical({'data':data})},_tx(transactions,data['txid']))
        proof.update(native_response_event_sequence=sequence,chain_transaction=_tx(transactions,txid if operation=='board' else data['txid']))
    elif operation in {'create','address','snapshot','invoice'}:
        response,sequence=_reply(store,action);before,bseq=_frame(store,action,'before');after,aseq=_frame(store,action,'after')
        if not bseq<aseq<sequence:raise EvidenceGap('native read boundaries do not bracket the reply')
        if type(response.get('actual_fee_sat')) is not int or response['actual_fee_sat']!=0:raise InvariantError('readonly/initiation outcome has an unexpected charge')
        if canonical(before['coins'])!=canonical(after['coins']) or canonical(before['movements'])!=canonical(after['movements']):raise EvidenceGap('read/initiation boundary changed money inventory; retain uncertainty')
        data=dict(response['data'])
        if operation=='create' and profile(store)==TWO_STEP:
            checked=after['binding']
            if (not isinstance(data.get('binding'),dict)
                    or not binding_matches(data['binding'],checked,legacy=True)
                    or data.get('fallback_script')!=checked['spk']):
                raise EvidenceGap('create reply differs from independently checked per-key binding')
            data['binding']=dict(checked)
        proof={'actor':action['actor_id'],'actual_fee_sat':0,'native_response_event_sequence':sequence,
            'before_event_sequence':bseq,'after_event_sequence':aseq,'scope':'explicit native acknowledgement and unchanged independently bound fresh wallet inventory; no failed-action inference'}
    else:raise EvidenceGap('unknown operation has no complete independent resolver')
    if native and native.get('status')=='ok' and native.get('actual_fee_sat') is not None:
        if type(native['actual_fee_sat']) is not int or native['actual_fee_sat']!=proof['actual_fee_sat']:raise InvariantError('preserved native fee contradicts independent reconciliation')
    return data,proof,original


def resolve(store,action_id,chain_transactions=None,payment_status=None):
    row=store.db.execute('SELECT * FROM action WHERE id=?',(action_id,)).fetchone()
    if row is None or row['state']!='outcome_unknown' or store.get_meta('paused'):return False
    action=dict(row)
    try:data,proof,original=_prove(store,action,chain_transactions or {},payment_status)
    except InvariantError:raise
    except (EvidenceGap,KeyError,TypeError,ValueError):return False
    cost=integer(proof['actual_fee_sat'],'resolved actual fee')
    if cost>action['fee_reservation_sat']:raise InvariantError('resolved cost exceeds the original reservation')
    if action['actual_fee_sat'] is not None and action['actual_fee_sat']!=cost:raise InvariantError('resolved fee contradicts previously checked accounting')
    result={'action_id':action_id,'status':'ok','data':data,'actual_fee_sat':cost,
        'resolution':{'original_result':original,'proof':proof,'scope':'positive outcome accounting; full scenario guarantees remain unqualified'}}
    public_payload(result)
    with store.transaction():
        changed=store.db.execute("UPDATE action SET state='completed',result=?,actual_fee_sat=? WHERE id=? AND state='outcome_unknown'",
            (canonical(result),cost,action_id)).rowcount
        if not changed:return False
        prior=store.db.execute("SELECT payload FROM event WHERE kind='client_fee_reconciled' AND json_extract(payload,'$.action_id')=?",(action_id,)).fetchall()
        if prior:
            if len(prior)!=1 or json.loads(prior[0][0])['actual_fee_sat']!=cost:raise InvariantError('unknown action has contradictory prior cost events')
        else:store._event('client_fee_reconciled',{'action_id':action_id,**proof})
        actor=store.db.execute('SELECT details FROM actor WHERE id=?',(action['actor_id'],)).fetchone();detail=json.loads(actor['details'])
        detail.update(needs_sync=True,snapshot_at=0)
        if action['operation']=='board':detail['board_submitted']=True
        if action['operation']=='create':
            fields=('funding_address','fallback_script','binding') if profile(store)==TWO_STEP else ('funding_address','fallback_script','account_xpub')
            detail.update(created=True,**{k:data[k] for k in fields if k in data})
        if action['operation']=='address':detail['ark_address']=data['address']
        if action['operation']=='invoice':detail.update(latest_invoice=data['invoice'],invoice_action_id=action_id,invoice_at=action['updated_at'])
        store.db.execute('UPDATE actor SET details=? WHERE id=?',(canonical(detail),action['actor_id']))
        store._event('unknown_outcome_resolved',{'action_id':action_id,'actor':action['actor_id'],'proof':proof,
            'original_updated_at':action['updated_at'],'original_result':original,'wallet_opened':False,'monetary_request_retried':False,'scenario_verdict':'not_qualified'})
    return True


def resolve_arkoor_limit_rejection(store,action_id,server_raw,server_sha256,client_raw,client_sha256):
    """Explicit lead-reviewed authenticated source receipts; never an automatic retry.

    This narrow disposition accepts only the pre-cosign input-limit rejection.
    Hashes must come from the separately authenticated, reviewed read-only
    receipts. A generic native error or an absent movement is insufficient.
    """
    row=store.db.execute('SELECT * FROM action WHERE id=?',(action_id,)).fetchone()
    if row is None or row['state']!='outcome_unknown':return False
    if not store.get_meta('paused'):raise EvidenceGap('reconcile rejection while dispatch remains paused')
    if (hashlib.sha256(server_raw.encode()).hexdigest()!=server_sha256
            or hashlib.sha256(client_raw.encode()).hexdigest()!=client_sha256):raise InvariantError('reviewed rejection source bytes changed')
    from .exploratory import scope
    declaration=scope(store);action=dict(row);_intent(store,action)
    if declaration is None or profile(store)!=TWO_STEP or action['operation']!='send_arkoor' or action['fee_reservation_sat']!=0:
        raise EvidenceGap('not the declared zero-fee ordinary Ark rejection')
    server=json.loads(server_raw);clients=json.loads(client_raw)
    if server['query_cut']!='REPEATABLE READ READ ONLY' or server['config_sha256']!=declaration['configuration_sha256']:
        raise EvidenceGap('actual rejection source configuration differs')
    proposal=_proposal(store,action,'arkoor_request');ids=proposal['input_vtxo_ids'];args=json.loads(action['args'])
    if len(ids)!=1 or proposal['destination']!=args['destination'] or proposal['amount_sat']!=args['amount_sat']:
        raise EvidenceGap('one exact original ordinary input and destination required')
    before,bseq=_frame(store,action,'before');after,aseq=_frame(store,action,'after')
    replies=store.db.execute("SELECT sequence,payload FROM event WHERE kind='driver_response' AND json_extract(payload,'$.action_id')=?",(action_id,)).fetchall()
    if len(replies)!=1 or not bseq<aseq<replies[0]['sequence'] or json.loads(replies[0]['payload'])['response'].get('status')!='error':
        raise EvidenceGap('original native error and complete boundaries required')
    money=lambda frame:[{k:c[k] for k in ('id','amount_sat','state','expiry_height','user_pubkey','signed_vtxo')} for c in frame['coins']]
    if money(before)!=money(after) or before['movements']!=after['movements'] or any(c['state']!='Spendable' for c in after['coins']):
        raise EvidenceGap('native principal, lock or movement changed')
    input_coin,proof=_coins(store,ids,action['actor_id'])[0]
    if proof['anchor_confirmations']<3:raise EvidenceGap('confirmed original board proof required')
    limit=integer(int(server['max_arkoor_amount'].removesuffix(' sat')),'actual input limit',1)
    if input_coin['amount_sat']<=limit or server['selected_original_input']!=ids[0]:raise EvidenceGap('not an input-limit rejection')
    logs=[]
    for line in server['logs_stdout'].splitlines():
        try:entry=json.loads(line[line.index('{'):])
        except (ValueError,json.JSONDecodeError):continue
        spans=[entry.get('span',{}),*entry.get('spans',[])]
        if any(v.get('rpc.method')=='RequestArkoorCosign' for v in spans):logs.append(entry)
    traces={v.get('openTelemetry',{}).get('traceId') for v in logs}
    expected='RPC ERROR: bad user input: arkoor send amount exceeds limit of '+format(limit/100000000,'.8f')+' BTC'
    errors=[v for v in logs if v.get('message')==expected]
    if len(traces)!=1 or None in traces or len(errors)!=1 or len(logs)!=3 or not any('status=Client specified an invalid argument' in v.get('message','') for v in logs):
        raise EvidenceGap('one authenticated terminal pre-validation RPC rejection required')
    error_time=datetime.datetime.fromisoformat(errors[0]['timestamp'].replace('Z','+00:00')).timestamp()
    times=[store.db.execute('SELECT observed_at FROM event WHERE sequence=?',(seq,)).fetchone()[0] for seq in (bseq,aseq)]
    if not times[0]-1<=error_time<=times[1]+1:raise EvidenceGap('server rejection not bound to original native call')
    rows=server['source_rows'];coins=rows['coin']
    if len(coins)!=1 or coins[0]['vtxo_id']!=ids[0] or coins[0]['amount']!=input_coin['amount_sat'] or coins[0]['spend_state']!='spendable' or any(coins[0][k] is not None for k in ('spent_in_round','oor_spent_txid','offboarded_in','onchain_spent_txid')):
        raise EvidenceGap('server original principal is not proven unspent')
    known=store.db.execute('SELECT id,amount_sat,proof FROM owned_coin').fetchall()
    virtual=set();known_ids={r['id'] for r in known}
    for coin in known:
        p=json.loads(coin['proof']);virtual.add(coin['id'].split(':')[0]);virtual.add(p['chain_anchor'].split(':')[0]);virtual.update(v['txid'] for v in p['path'])
    counts=rows['spend_publication_counts']
    if (len(counts)!=1 or counts[0]['arkoor_mailbox']!=len(rows['arkoor_mailbox'])
            or counts[0]['mailbox']!=len(rows['mailbox'])
            or counts[0]['nonfunding_virtual_transactions']!=sum(not v['is_funding'] for v in rows['virtual_transactions'])
            or any(counts[0][k]!=0 for k in ('offboards','nursery','rounds'))
            or len(rows['virtual_transactions'])>=129 or len(rows['mailbox'])>=129):
        raise EvidenceGap('complete bounded global publication inventory required')
    if (set(v['txid'] for v in rows['virtual_transactions'])!=virtual or len(rows['virtual_transactions'])!=len(virtual)
            or rows['arkoor_mailbox'] or any(v['mailbox_type']!='recovery-vtxo-id' or v['vtxo_id'] not in known_ids for v in rows['mailbox'])):
        raise EvidenceGap('new virtual package or recipient delivery cannot be excluded')
    if clients.get('read_only_native_sqlite') is not True or clients.get('mutations') is not False:
        raise EvidenceGap('actual native read-only checkpoint source required')
    for actor in (action['actor_id'],args['recipient_actor']):
        current=clients['actors'][actor]
        expected={r[0] for r in store.db.execute('SELECT c.id FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey WHERE k.actor=?',(actor,))}
        if (not expected or {v['id'] for v in current['coins']}!=expected or len(current['coins'])!=len(expected)
                or {v['vtxo_id'] for v in current['current_states']}!=expected or len(current['current_states'])!=len(expected)):
            raise EvidenceGap('native holdings and states omit independently signed principal')
        expected_movements=[json.loads(r[0]) for r in store.db.execute('SELECT payload FROM movement_evidence WHERE actor=?',(actor,))]
        expected_contract={(str(v['id']),v['status'],v['subsystem'],v['effective_balance_sat'],v['offchain_fee_sat']) for v in expected_movements}
        current_contract={(str(v['id']),v['status'],v['subsystem_name'],v['effective_balance'],v['offchain_fee']) for v in current['movements']}
        if not expected_contract or current_contract!=expected_contract or len(current['movements'])!=len(expected_contract):
            raise EvidenceGap('native movement inventory omits original board history')
        if current['checkpoints'] or current['pending_boards'] or current['pending_rounds'] or any(v['state_kind']!='Spendable' for v in current['current_states']) or any(v['subsystem_name']!='bark.board' or v['status']!='successful' for v in current['movements']):
            raise EvidenceGap('native pending action, lock or transfer movement remains')
        for coin in current['coins']:
            owned=_coins(store,[coin['id']],actor)[0][0]
            if (coin['amount_sat'],coin['expiry_height'])!=(owned['amount_sat'],json.loads(owned['proof'])['expiry_height']):raise InvariantError('native principal differs from signed proof')
    original=json.loads(action['result']);rejection={'server_source_sha256':server_sha256,'native_client_source_sha256':client_sha256,
        'server_trace_id':next(iter(traces)),'before_sequence':bseq,'after_sequence':aseq,'input_coin_ids':ids,
        'disposition':'known pre-cosign policy rejection; no Ark transfer','actual_fee_sat':0,
        'legitimate_board_registration_preserved':True,'scenario_verdict':'failed','qualified_seconds':0}
    result={'action_id':action_id,'status':'error','original_result':original,'rejection_reconciliation':rejection}
    with store.transaction():
        changed=store.db.execute("UPDATE action SET state='failed',result=?,actual_fee_sat=0 WHERE id=? AND state='outcome_unknown'",(canonical(result),action_id)).rowcount
        if changed!=1:raise EvidenceGap('original unknown state changed before rejection reconciliation')
        store._event('unknown_outcome_rejected',{'action_id':action_id,'original_updated_at':action['updated_at'],'original_result':original,**rejection,'monetary_request_retried':False})
    return True


async def collect(store,config,chain=None,limit=2):
    if store.get_meta('paused'):return
    after=store.get_meta('unknown_outcome_cursor') or ''
    rows=store.db.execute("SELECT * FROM action WHERE state='outcome_unknown' AND id>? ORDER BY id LIMIT ?",(after,limit)).fetchall()
    if len(rows)<limit:rows+=store.db.execute("SELECT * FROM action WHERE state='outcome_unknown' AND id<=? ORDER BY id LIMIT ?",(after,limit-len(rows))).fetchall()
    for row in rows:
        action=dict(row);transactions={};status=None
        try:
            if action['operation']=='pay_invoice':
                value=_proposal(store,action,'lightning_proposal')['payment_hash']
                request={'operation':'lightning_payment_status','action_id':'unknown-status:'+action['id'],'actor_dir':None,
                    'expected_server_pubkey':config.expected_server_pubkey,'maximum_fee_sat':0,'args':{'payment_hash':value}}
                status=await json_command(list(config.driver_command),request,timeout=15)
            if chain and action['operation'] in {'board','offboard_all','exit'}:
                await asyncio.to_thread(chain.identity)
                txids=[]
                if action['operation']=='exit':
                    txids=[json.loads(r[0])['data']['txid'] for r in store.db.execute("SELECT payload FROM event WHERE kind='driver_evidence' AND json_extract(payload,'$.action_id')=? AND json_extract(payload,'$.event')='exit_proposal' AND json_extract(payload,'$.data.stage') IN ('cpfp','claim')",(action['id'],))]
                elif action['operation']=='board':txids=[_proposal(store,action,'board_proposal')['funding_txid']]
                else:txids=[_reply(store,action)[0]['data']['txid']]
                for txid in set(txids):transactions[txid]=await asyncio.to_thread(chain.transaction,txid)
            resolve(store,action['id'],transactions,status)
        except InvariantError:raise
        except Exception:pass # Transport failure/absence never releases money or retries an action.
        finally:store.db.execute("INSERT OR REPLACE INTO meta VALUES ('unknown_outcome_cursor',?)",(action['id'],))

"""Explicit client protocol probes; raw replies never certify production outcomes."""
from __future__ import annotations
from contextlib import nullcontext
import hashlib,json,re,time
from .model import InvariantError,canonical,integer,public_payload
from .ownership import EvidenceGap
from .process import json_command,public_command_capture

# Phase cases deliberately retain their actual economic prerequisite. A malformed
# request to another endpoint cannot replace a race, refund, delivery or payout.
MECHANISMS={
 'D13':('SubmitPayment','missing_fallback','frozen round output with an unlinked key'),
 'D14':('RequestArkoorCosign','missing_fallback','valid checkpointed arkoor with an unlinked destination'),
 'D15':('PrepareLightningReceiveClaim','missing_fallback','Accepted actual receive; valid ownership anti-DoS proof; unlinked HTLC-recv key'),
 'D16':('RequestLightningPayHtlcCosign','missing_fallback','valid HTLC-send and unlinked change output'),
 'D17':('race','phase','two frozen arkoor packages spend the identical owned input to distinct registered recipients'),
 'D18':('race','phase','arkoor package races an active interactive round on the identical input'),
 'D19':('race','phase','offboard preparation races refresh; reconcile forfeit and chain winner'),
 'D20':('race','phase','unilateral exit races cooperative spend; independent confirmed chain arbitration'),
 'D21':('RequestArkoorCosign','settled','replay an input with independently checked expiry settlement'),
 'D22':('RegisterVtxoTransactions','replay_candidate','replay the identical previously delivered signed transaction chain; mailbox replay is a separate variant'),
 'D23':('RegisterVtxoTransactions','invalid_chain','truncate an independently signed original chain'),
 'D24':('RegisterVtxoTransactions','phase','deliver a saved unregistered successor only after its input-owner payout commits'),
 'D25':('RegisterVtxoTransactions','invalid_chain','combine two independent owner chains with an altered foreign payee policy'),
 'D26':('SubmitRoundParticipation','phase','race two distinct signed delegated requests on identical inputs; retain winner exchange'),
 'D27':('ForfeitVtxos','phase','replay exact cached forfeit after recorded expiry cancellation'),
 'D28':('proof oracle','phase','supply another confirmed sweep branch; rightful coin remains pending'),
 'D29':('RequestLightningPayHtlcRevocation','paid_refund','paid same-hash send with retained owned HTLCs'),
 'D30':('RequestLightningPayHtlcRevocation','pending_refund','known pending same-hash send; timeout alone never enables refund'),
 'D31':('ClaimLightningReceive','replay_candidate','Settled same-hash receive with retained private preimage and identical destination'),
 'D32':('ClaimLightningReceive','wrong_preimage','HtlcsReady actual receive; valid cosign request and deliberately mismatching preimage'),
 'D33':('ClaimLightningReceive','phase','saved rightful claim after the matching sender refund commits'),
 'D34':('race','phase','valid internal claim races same-hash revocation under one immutable intent'),
 'D35':('PrepareLightningReceiveClaim','collected_expiry_cap','legitimately collected Accepted receive requests uint32 maximum expiry'),
 'D36':('deadline profile','phase','withhold prepared internal claim; measure actual lock until rightful refund or claim'),
}
NATIVE_SCENARIOS=frozenset({'D13','D14','D15','D16','D21','D22','D23','D25','D29','D30','D31','D32','D35'})
OPERATIONS={f'raw_protocol_{scenario.lower()}':scenario for scenario in NATIVE_SCENARIOS}
PAYMENT_SCENARIOS={'D15','D16','D29','D30','D31','D32','D35'}
SCHEMA='''CREATE TABLE IF NOT EXISTS raw_protocol_intent(
 action_id TEXT PRIMARY KEY REFERENCES action(id),intent_hash TEXT NOT NULL UNIQUE,
 scenario TEXT NOT NULL,payload TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS raw_protocol_check(action_id TEXT PRIMARY KEY REFERENCES action(id),
 state TEXT NOT NULL,payload TEXT NOT NULL,updated_at REAL NOT NULL);'''


def _initialize(store):
    for statement in SCHEMA.split(';'):
        if statement.strip():store.db.execute(statement)


def _hash(value):return hashlib.sha256(canonical(value).encode()).hexdigest()
def _hex(value,length):return isinstance(value,str) and re.fullmatch('[0-9a-f]{'+str(length)+'}',value) is not None


def queue_probe(store,config,actor,scenario,context):
    """Freeze once before dispatch; only a declared operator/profile invokes this."""
    public_payload(context)
    if getattr(config,'network',None)!='signet':raise EvidenceGap('explicit signet declaration required')
    if scenario not in MECHANISMS:raise ValueError('unknown protocol scenario')
    if scenario not in NATIVE_SCENARIOS:raise EvidenceGap(MECHANISMS[scenario][2]+' requires its real phase checkpoint')
    fee=integer(context.get('maximum_fee_sat',2000),'protocol probe fee ceiling')
    if fee>2000:raise ValueError('protocol probe fee ceiling exceeds2000')
    if actor in {'actor-03','actor-09','actor-10'}:raise EvidenceGap('original absent wallet must remain closed')
    user=store.db.execute('SELECT online,details FROM actor WHERE id=?',(actor,)).fetchone()
    if user is None or not user['online'] or json.loads(user['details']).get('permanent_absence'):
        raise EvidenceGap('probe requires an online non-absent owner')
    if store.get_meta('paused'):raise EvidenceGap('campaign paused')
    ids=context.get('input_coin_ids',[])
    if not isinstance(ids,list) or not ids or len(ids)>16 or len(ids)!=len(set(ids)):
        raise EvidenceGap('probe requires exact bounded retained inputs')
    inputs=[]
    for identity in ids:
        coin=store.db.execute('SELECT c.*,k.actor FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey WHERE c.id=?',(identity,)).fetchone()
        if coin is None:raise EvidenceGap('input lacks independently verified signed identity')
        if coin['actor']!=actor and scenario!='D25':raise InvariantError('probe input belongs to another actor')
        state=store.db.execute("SELECT o.state FROM coin_observation o JOIN action a ON a.id=o.action_id WHERE o.coin_id=? AND a.state='completed' AND a.operation!='public_proof_import' ORDER BY o.observed_at DESC LIMIT 1",(identity,)).fetchone()
        if state is None or state['state']=='PublicProof':raise EvidenceGap('probe needs native client observation')
        if scenario not in {'D21','D22','D29','D30','D31','D32'} and state['state']!='Spendable':raise EvidenceGap('input is not observed spendable')
        if hashlib.sha256(bytes.fromhex(coin['signed_vtxo'])).hexdigest()!=coin['signed_hash']:raise InvariantError('retained input bytes changed')
        inputs.append({'coin_id':identity,'signed_hash':coin['signed_hash'],'pubkey':coin['pubkey'],'amount_sat':coin['amount_sat'],'owner':coin['actor']})
    if scenario=='D25' and (len(inputs)!=2 or inputs[0]['owner']!=actor or inputs[1]['owner']==actor):
        raise EvidenceGap('mixed-owner probe requires this owner first and exactly one independently verified foreign owner')
    if scenario=='D22':
        delivered=[json.loads(row[0]) for row in store.db.execute('SELECT payload FROM movement_evidence WHERE actor=?',(actor,))]
        if not any(m.get('subsystem')=='bark.arkoor' and m.get('status')=='successful' and m.get('input_vtxos')==[]
                and set(ids).issubset(m.get('output_vtxos',[])) for m in delivered):
            raise EvidenceGap('delivery replay lacks actual successful receipt movement')
    payment_hash=context.get('payment_hash');source_action=context.get('source_action_id')
    if scenario in PAYMENT_SCENARIOS:
        if not _hex(payment_hash,64) or not isinstance(source_action,str):raise EvidenceGap('existing immutable payment hash/action required')
        source=store.db.execute('SELECT * FROM action WHERE id=?',(source_action,)).fetchone()
        if source is None or source['state']!='completed' or source['operation'] not in {'invoice','pay_invoice'}:
            raise EvidenceGap('actual invoice/send checkpoint required; unknown outcome stays fenced')
        data=json.loads(source['result']).get('data',{})
        if data.get('payment_hash')!=payment_hash:raise InvariantError('probe payment hash differs from original action')
        if scenario!='D16' and source['actor_id']!=actor:raise InvariantError('probe checkpoint belongs to another actor')
    if scenario=='D16':
        htlc=integer(context.get('htlc_amount_sat',0),'frozen HTLC amount')
        if htlc<330 or sum(v['amount_sat'] for v in inputs)-htlc<330:raise EvidenceGap('HTLC-send and change require declared non-dust principals')
        if json.loads(source['args']).get('amount_sat')!=htlc:raise EvidenceGap('HTLC principal must match actual immutable invoice amount')
        if not data.get('invoice') or context.get('original_invoice')!=data['invoice']:
            raise EvidenceGap('HTLC send requires exact original invoice for native hash/amount validation')
    if scenario in {'D31','D32'}:
        key=context.get('original_destination_pubkey')
        if not isinstance(key,str) or re.fullmatch('(02|03)[0-9a-f]{64}',key) is None:
            raise EvidenceGap('original exact claim destination required')
        if scenario=='D31':
            outputs=context.get('original_output_coin_ids')
            receipts=[json.loads(r[0]) for r in store.db.execute('SELECT payload FROM movement_evidence WHERE actor=?',(actor,))]
            if not isinstance(outputs,list) or not outputs or len(outputs)!=len(set(outputs)) or not any(
                m.get('status')=='successful' and m.get('payment_hash')==payment_hash
                and m.get('output_vtxos')==outputs and set(m.get('input_vtxos',[]))==set(ids) for m in receipts):
                raise EvidenceGap('claim replay requires exact successful original HTLC and output identities')
            for output in outputs:
                proof=store.db.execute('SELECT pubkey FROM owned_coin WHERE id=?',(output,)).fetchone()
                if proof is None or proof[0]!=key:raise EvidenceGap('original claim destination lacks signed output proof')
    if scenario=='D21':
        for identity in ids:
            if store.db.execute('SELECT 1 FROM checked_settlement WHERE coin_id=? AND actor=?',(identity,actor)).fetchone() is None:
                raise EvidenceGap('expiry-settled replay requires checked original settlement')
    intent={'schema_version':1,'scenario':scenario,'actor':actor,'server_pubkey':config.expected_server_pubkey,
        'inputs':inputs,'input_amount_sat':sum(value['amount_sat'] for value in inputs),'maximum_fee_sat':fee,
        'context':context,'rpc':MECHANISMS[scenario][0],'expected_guard':MECHANISMS[scenario][1],
        'automatic_retry':False,'production_qualified':False}
    digest=_hash(intent);identity='raw-protocol-'+digest;_initialize(store)
    previous=store.db.execute('SELECT action_id,intent_hash FROM raw_protocol_intent WHERE intent_hash=?',(digest,)).fetchone()
    if previous:return dict(previous)
    if store.db.execute("SELECT 1 FROM action WHERE actor_id=? AND state IN ('queued','dispatched','outcome_unknown')",(actor,)).fetchone():
        raise EvidenceGap('owner has a busy or unknown action')
    if store.remaining_fee_budget()<fee:raise EvidenceGap('probe fee reservation unavailable')
    operation='raw_protocol_'+scenario.lower();args={**context,'probe_intent':intent,'intent_hash':digest}
    with (nullcontext() if store.db.in_transaction else store.transaction()):
        store.queue(identity,actor,scenario,operation,args,fee)
        store.db.execute('INSERT INTO raw_protocol_intent VALUES (?,?,?,?)',(identity,digest,scenario,canonical(intent)))
        store._event('raw_protocol_intent_frozen',{'action_id':identity,'intent_hash':digest,'scenario':scenario,
            'actor':actor,'input_coin_ids':ids,'principal_exposed_sat':intent['input_amount_sat'],'maximum_fee_sat':fee,
            'mechanism':MECHANISMS[scenario][2],'rpc':intent['rpc'],'live_qualified':False})
    return {'action_id':identity,'intent_hash':digest}


def validate_response(action,data):
    args=action['args'] if isinstance(action['args'],dict) else json.loads(action['args']);intent=args['probe_intent'];probe=data.get('probe',{})
    public_payload(probe)
    if (probe.get('scenario'),probe.get('actor'),probe.get('intent_hash'))!=(intent['scenario'],intent['actor'],args['intent_hash']):
        raise InvariantError('protocol probe response belongs to another frozen intent')
    for key in ('request_hash','response_message_hash','response_hash'):
        if not _hex(probe.get(key),64):raise InvariantError('protocol probe evidence hash missing')
    if probe.get('input_coin_ids')!=[value['coin_id'] for value in intent['inputs']]:raise InvariantError('protocol probe changed inputs')
    if probe.get('rpc')!=intent['rpc']:raise InvariantError('probe used another RPC')
    before=probe.get('input_status_before');after=probe.get('input_status_after')
    if not isinstance(before,list) or len(before)!=len(intent['inputs']) or before!=after:
        raise InvariantError('negative probe changed protected input state or lacks status evidence')
    if any(type(value) is not int or value not in {1,2,3,4,5} for value in before):
        raise EvidenceGap('input status unavailable; independent public state audit remains pending')
    if (probe.get('rpc_attempted') is not True or probe.get('guard')!=intent['expected_guard']
            or probe.get('code') not in ({'Ok'} if intent['expected_guard']=='replay_candidate' else {'InvalidArgument'})):
        raise EvidenceGap('actual intended guard or same-path idempotent reply not observed')
    if probe.get('actual_fee_sat')!=0:raise EvidenceGap('negative protocol fee remains unknown')
    return {'action_id':action['id'],'scenario':intent['scenario'],'intent_hash':args['intent_hash'],
        'response_hash':probe['response_hash'],'request_hash':probe['request_hash'],'response_message_hash':probe['response_message_hash'],
        'rpc':probe['rpc'],'guard':probe['guard'],'code':probe['code'],'native_state_unchanged':True,
        'actual_fee_sat':0,'live_qualified':False,
        'scope':'native reply and authenticated status only; independent bindings, chain, duplicate entitlement and liability audit remain pending'}


def scenario_rows(store):
    """Exactly one row per scenario; implementation and production are separate."""
    has_intents=store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='raw_protocol_intent'").fetchone() is not None
    rows=[]
    for scenario,(rpc,guard,mechanism) in MECHANISMS.items():
        attempts=list(store.db.execute('SELECT id,operation,state,actual_fee_sat,fee_reservation_sat FROM action WHERE scenario_id=? ORDER BY created_at,id',(scenario,)))
        rows.append({'scenario':scenario,'mechanism':mechanism,'rpc':rpc,'expected_guard':guard,
            'adapter_implemented':scenario in NATIVE_SCENARIOS,'result':'live-qualification-pending',
            'evidence':[value['id'] for value in attempts],'attempts':[dict(value) for value in attempts],
            'fees':{'verified_sat':sum(value['actual_fee_sat'] for value in attempts if value['actual_fee_sat'] is not None),
                'reserved_unknown_sat':sum(value['fee_reservation_sat'] for value in attempts if value['actual_fee_sat'] is None)},
            'liabilities':{'status':'requires independent original/successor/payment/chain reconciliation',
                'intent_history_is_additive_capital':False,
                'exposure_intents':[{'action_id':r['action_id'],'input_coin_ids':[v['coin_id'] for v in json.loads(r['payload'])['inputs']],
                    'declared_input_principal_sat':json.loads(r['payload'])['input_amount_sat']}
                    for r in (store.db.execute('SELECT action_id,payload FROM raw_protocol_intent WHERE scenario=? ORDER BY action_id',(scenario,)) if has_intents else [])],
                'no_synthetic_refusal_credit':True}})
    return rows


async def collect(store,observer_command,proof_command=(),limit=2):
    """Read public post-request bindings; never convert a reply into traffic credit.

    This checker records partial evidence even if a later status/signature gate
    remains pending. It does not arbitrate duplicate claims or future payouts.
    """
    from .negative_checks import request_for,check
    _initialize(store)
    if not observer_command:return
    if type(limit) is not int or not 1<=limit<=4:raise ValueError('protocol check limit1..4')
    rows=store.db.execute("""SELECT a.* FROM action a LEFT JOIN raw_protocol_check c ON c.action_id=a.id
        WHERE a.operation LIKE 'raw_protocol_%' AND a.state IN ('completed','expected_refusal')
        AND (c.state IS NULL OR c.state!='public_checked') ORDER BY a.id""").fetchall()
    cursor=store.get_meta('raw_protocol_check_cursor') or ''
    rows=[r for r in rows if r['id']>cursor]+[r for r in rows if r['id']<=cursor]
    for action in rows[:limit]:
        evidence={'live_qualified':False,'remaining_gates':['independent monetary conservation','duplicate entitlement/payout arbitration','signet production qualification']}
        state='pending'
        try:
            args=json.loads(action['args']);data=json.loads(action['result'])['data']
            if OPERATIONS.get(action['operation'])!=action['scenario_id']:raise InvariantError('protocol adapter/catalogue mismatch')
            protected={**data,'attempted_key_pubkeys':list(dict.fromkeys([
                *data.get('attempted_key_pubkeys',[]),*[i['pubkey'] for i in args['probe_intent']['inputs']]]))}
            request,expected,record=request_for(store,{**dict(action),'result':canonical({'data':protected})})
            observed=await json_command(list(observer_command),request,timeout=25,
                **public_command_capture(store,'protocol.binding',request,actor=action['actor_id'],action_id=action['id']))
            evidence['bindings']={**check(request,expected,record,observed),'snapshot':observed}
            for link in observed['links']:
                if not proof_command:raise EvidenceGap('independent binding signature verifier unavailable')
                signed=next(r for r in observed['records'] if r['mailbox_pk']==link['mailbox_pk'])
                proof_request={'user_pubkey':link['user_pubkey'],'key_link_attestation':link['sig'],
                    'binding':{'mailbox_pk':signed['mailbox_pk'],'spk':signed['spk'],'seq':signed['seq'],'record_attestation':signed['sig']}}
                proof=await json_command(list(proof_command),proof_request,timeout=30,
                    **public_command_capture(store,'protocol.proof',proof_request,actor=action['actor_id'],action_id=action['id']))
                binding=proof.get('binding',{})
                if (proof.get('user_pubkey'),binding.get('mailbox_pk'),binding.get('spk'),binding.get('seq'))!=(link['user_pubkey'],signed['mailbox_pk'],signed['spk'],signed['seq']):
                    raise InvariantError('protocol binding verifier returned another identity')
                if binding.get('record_signature_valid') is not True or binding.get('key_link_signature_valid') is not True:
                    raise EvidenceGap('protocol binding signatures incomplete')
            evidence['protocol']=validate_response(action,data)
            state='public_checked'
        except InvariantError as error:
            evidence['contradiction']=str(error);state='invalidated'
            store.db.execute("INSERT OR REPLACE INTO meta VALUES ('paused','protocol contradiction')")
        except Exception as error:
            evidence['gap']={'class':type(error).__name__,'reason':str(error)}
        public_payload(evidence)
        with (nullcontext() if store.db.in_transaction else store.transaction()):
            store.db.execute('INSERT OR REPLACE INTO raw_protocol_check VALUES (?,?,?,?)',
                (action['id'],state,canonical(evidence),time.time()))
            store.db.execute("INSERT OR REPLACE INTO meta VALUES ('raw_protocol_check_cursor',?)",(action['id'],))
            store._event('raw_protocol_public_check',{'action_id':action['id'],'scenario':action['scenario_id'],'state':state,**evidence})
        if state=='invalidated':raise InvariantError(evidence['contradiction'])

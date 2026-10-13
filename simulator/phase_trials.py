"""Explicit multi-step client trials with independent once-only money checks.

Every network operation remains behind the declared SDK qualification gate.
A protocol reply never substitutes for a signed successor or a confirmed payout.
"""
from __future__ import annotations
import hashlib,json,re,time
from contextlib import nullcontext
from .model import canonical,integer,InvariantError,public_payload,fee_allocation,transaction_fee
from .ownership import EvidenceGap

ABSENT={'actor-03','actor-09','actor-10'}
RPCS={'D17':['RequestArkoorCosign','RequestArkoorCosign'],
 'D18':['RequestArkoorCosign','SubmitPayment'],
 'D19':['FinishOffboard','SubmitPayment'],
 'D20':['unilateral exit','RequestArkoorCosign'],
 'D24':['RegisterVtxoTransactions'],
 'D26':['SubmitRoundParticipation','SubmitRoundParticipation'],
 'D27':['ForfeitVtxos'], 'D28':['independent payout proof'],
 'D33':['ClaimLightningReceive'],
 'D34':['ClaimLightningReceive','RequestLightningPayHtlcRevocation'],
 'D36':['withhold prepared claim','read-only reconciliation']}
REQUIREMENTS={
 'D17':['identical signed input set','distinct registered recipient keys','one-process SDK nonce retention and durable exact public checkpoint','overlapping actual requests','independently signed winning successor','one conserved entitlement'],
 'D18':['identical signed input set','active interactive round challenge','one-process arkoor and round nonce retention with durable exact public checkpoints','round forfeits and confirmed signed outputs','one conserved entitlement'],
 'D19':['exact offboard input set and owned destination','server-validated prepared transaction and forfeit session','matching refresh inputs','actual chain or refresh winner'],
 'D20':['same signed input and exit intent','actual unilateral exit state and package','matching cooperative spend','confirmed chain arbitration'],
 'D24':['saved fully signed unregistered successor','exact original parent ownership','checked confirmed original payout','wallet-free delayed registration','no new payee entitlement'],
 'D26':['same input set','distinct signed scheduled participation requests','saved unlock/forfeit session','exact changed/replaced entitlement lineage'],
 'D27':['exact saved cached forfeit','independently observed expiry cancellation','no revived output or payout liability'],
 'D28':['actual confirmed sweep from another branch','exact rightful coin and signed anchor','independent proof rejection','rightful settlement remains pending'],
 'D33':['same payment hash and saved valid claim','checked sender refund commitment','retained private preimage checkpoint','no receiver credit'],
 'D34':['same payment hash and exact sender/receiver HTLC identities','valid claim and revocation checkpoints','durable private preimage/nonces','one winning conserved payment'],
 'D36':['actual prepared internal claim','declared observed block deadline','no claim dispatch before deadline','read-only claim/refund reconciliation','measured actual locked principal']}
SCHEMA='''CREATE TABLE IF NOT EXISTS phase_trial(id TEXT PRIMARY KEY,scenario TEXT NOT NULL,actor TEXT NOT NULL,intent_hash TEXT NOT NULL UNIQUE,intent TEXT NOT NULL,state TEXT NOT NULL,release_action TEXT,updated_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS phase_preparation(trial_id TEXT NOT NULL REFERENCES phase_trial(id),leg_id TEXT NOT NULL,digest TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(trial_id,leg_id));
CREATE TABLE IF NOT EXISTS phase_reply(trial_id TEXT NOT NULL REFERENCES phase_trial(id),leg_id TEXT NOT NULL,digest TEXT NOT NULL,payload TEXT NOT NULL,observed_at REAL NOT NULL,PRIMARY KEY(trial_id,leg_id,digest));
CREATE TABLE IF NOT EXISTS phase_reconciliation(trial_id TEXT NOT NULL REFERENCES phase_trial(id),coin_id TEXT NOT NULL,payload TEXT NOT NULL,observed_at REAL NOT NULL,PRIMARY KEY(trial_id,coin_id));
CREATE TABLE IF NOT EXISTS phase_verdict(trial_id TEXT PRIMARY KEY REFERENCES phase_trial(id),payload TEXT NOT NULL,updated_at REAL NOT NULL);'''


def requirements(scenario):
    if scenario not in REQUIREMENTS:raise ValueError('unknown phase scenario')
    return list(REQUIREMENTS[scenario])
def digest(value):return hashlib.sha256(canonical(value).encode()).hexdigest()
def hash64(value):return isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value) is not None

class Controller:
    def __init__(self,store,config,*,nonce_verifier=None):
        self.store,self.config,self.nonce_verifier=store,config,nonce_verifier
        for statement in SCHEMA.split(';'):
            if statement.strip():store.db.execute(statement)
    def atomic(self):return nullcontext() if self.store.db.in_transaction else self.store.transaction()
    def online(self,actor):
        row=self.store.db.execute('SELECT online,details FROM actor WHERE id=?',(actor,)).fetchone()
        if actor in ABSENT or row is None or not row['online'] or json.loads(row['details']).get('permanent_absence'):
            raise EvidenceGap('phase operation cannot open an absent or offline wallet')
    def declare(self,scenario,actor,context):
        public_payload(context);requirements(scenario)
        if getattr(self.config,'network',None)!='signet':raise EvidenceGap('explicit signet declaration required')
        if scenario!='D24':self.online(actor)
        else:self.online(context.get('courier_actor'))
        ids=context.get('input_coin_ids',[])
        if not isinstance(ids,list) or not ids or len(ids)>16 or len(ids)!=len(set(ids)):
            raise EvidenceGap('exact bounded signed inputs required')
        inputs=[]
        for identity in ids:
            row=self.store.db.execute('SELECT c.*,k.actor FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey WHERE c.id=?',(identity,)).fetchone()
            if row is None:raise EvidenceGap('independently verified original input missing')
            if row['actor']!=actor:raise InvariantError('phase original input belongs to another actor')
            proof=json.loads(row['proof'])
            if proof.get('signed_path_valid') is not True or proof.get('anchor_confirmations',0)<1:raise EvidenceGap('original signed path or confirmed anchor missing')
            if hashlib.sha256(bytes.fromhex(row['signed_vtxo'])).hexdigest()!=row['signed_hash']:raise InvariantError('original input serialization changed')
            inputs.append({'coin_id':identity,'pubkey':row['pubkey'],'amount_sat':row['amount_sat'],'signed_hash':row['signed_hash'],'actor':actor})
        recipients=context.get('recipients',[])
        if scenario=='D17':
            if len(recipients)!=2 or len({r['pubkey'] for r in recipients})!=2:raise InvariantError('race requires distinct registered recipient keys')
            for recipient in recipients:
                self.online(recipient['actor'])
                own=self.store.db.execute('SELECT actor FROM owner_key WHERE pubkey=?',(recipient['pubkey'],)).fetchone()
                if own is None:raise EvidenceGap('recipient key signature proof missing')
                if own[0]!=recipient['actor']:raise InvariantError('recipient key belongs to another actor')
        if scenario=='D24' and (not isinstance(context.get('saved_successor_ids'),list) or not context['saved_successor_ids'] or len(context['saved_successor_ids'])>16 or any(not isinstance(v,str) for v in context['saved_successor_ids']) or len(set(context['saved_successor_ids']))!=len(context['saved_successor_ids'])):
            raise EvidenceGap('delayed delivery requires exact saved signed successor IDs')
        maximum=integer(context.get('maximum_fee_sat',0 if scenario in {'D24','D27','D28','D33','D36'} else 2000),'whole trial fee ceiling')
        if maximum>2000:raise ValueError('whole trial fee ceiling exceeds2000')
        frozen={'schema_version':1,'scenario':scenario,'actor':actor,'network':'signet','server_pubkey':self.config.expected_server_pubkey,
            'inputs':inputs,'principal_sat':sum(i['amount_sat'] for i in inputs),'maximum_fee_sat':maximum,'rpcs':RPCS[scenario],
            'context':context,'requirements':requirements(scenario),'automatic_retry':False,'live_qualified':False}
        checksum=digest(frozen);identity='phase-'+checksum
        old=self.store.db.execute('SELECT id FROM phase_trial WHERE intent_hash=?',(checksum,)).fetchone()
        if old:return identity
        with self.atomic():
            self.store.db.execute('INSERT INTO phase_trial VALUES (?,?,?,?,?,?,NULL,?)',(identity,scenario,actor,checksum,canonical(frozen),'declared',time.time()))
            self.store._event('phase_trial_declared',{'trial_id':identity,'intent_hash':checksum,**frozen,'principal_counted_once':True})
        return identity
    def row(self,trial):
        row=self.store.db.execute('SELECT * FROM phase_trial WHERE id=?',(trial,)).fetchone()
        if row is None:raise ValueError('unknown phase trial')
        return row
    def intent(self,trial):
        row=self.row(trial);return {**json.loads(row['intent']),'intent_hash':row['intent_hash']}
    def preparations(self,trial):return [json.loads(r[0]) for r in self.store.db.execute('SELECT payload FROM phase_preparation WHERE trial_id=? ORDER BY leg_id',(trial,))]
    def validate_round_quote(self,intent,leg):
        requested=leg.get('requested_outputs',[])
        if not requested or len(requested)>16:raise EvidenceGap('exact SDK requested round outputs missing')
        principal=sum(integer(v['amount_sat'],'requested round principal',1) for v in requested)
        fee=integer(leg.get('committed_fee_sat'),'frozen SDK round fee')
        if fee>intent['maximum_fee_sat'] or principal+fee!=intent['principal_sat']:raise InvariantError('requested SDK round value/fee differs from whole-trial identity')
        attempt=leg.get('round_attempt',{})
        if type(attempt.get('round_seq')) is not int or attempt['round_seq']<0 or attempt.get('attempt_seq')!=0:raise EvidenceGap('exact first interactive round attempt required; no retries')
        if leg.get('input_spends') or leg.get('outputs'):raise InvariantError('submission cannot assert not-yet-funded round outputs or forfeit identities')
        return {'requested_principal_sat':principal,'committed_fee_sat':fee}
    def prepare(self,trial,prepared):
        public_payload(prepared);intent=self.intent(trial)
        if prepared.get('trial_id')!=trial or prepared.get('intent_hash')!=intent['intent_hash']:raise InvariantError('preparation belongs to another frozen trial')
        legs=prepared.get('legs',[])
        if len(legs)!=len(intent['rpcs']) or len({v['leg_id'] for v in legs})!=len(legs):raise InvariantError('prepared race leg count differs')
        ids=[v['coin_id'] for v in intent['inputs']]
        for index,leg in enumerate(legs):
            if leg.get('rpc')!=intent['rpcs'][index] or leg.get('input_coin_ids')!=ids:raise InvariantError('prepared RPC/input set differs from frozen phase')
            if not hash64(leg.get('wire_sha256')) or not hash64(leg.get('private_checkpoint_sha256')):raise EvidenceGap('exact request and private checkpoint hashes required')
            round_submission=intent['scenario']=='D18' and index==1
            spends=leg.get('input_spends',[])
            if round_submission:self.validate_round_quote(intent,leg)
            if not round_submission and ([v.get('coin_id') for v in spends]!=ids or any(not hash64(v.get('txid')) for v in spends)):raise EvidenceGap('exact unsigned input spending identities missing')
            outputs=leg.get('outputs',[])
            if not round_submission and (not outputs or len({v['coin_id'] for v in outputs})!=len(outputs)):raise EvidenceGap('exact unsigned successor IDs missing')
            if not round_submission:
                coverage=set()
                for output in outputs:coverage.update(self.output_inputs(output,intent))
                if coverage!=set(ids):raise InvariantError('prepared successor lineage omits frozen inputs')
            if sum(integer(v['amount_sat'],'prepared output principal') for v in outputs)>intent['principal_sat']:raise InvariantError('prepared branch inflates principal')
            if intent['scenario']=='D17' and any(v['pubkey']!=intent['context']['recipients'][index]['pubkey'] for v in outputs):raise InvariantError('prepared race changes registered destination')
            old=self.store.db.execute('SELECT digest FROM phase_preparation WHERE trial_id=? AND leg_id=?',(trial,leg['leg_id'])).fetchone()
            if old and old[0]!=digest(leg):raise InvariantError('prepared leg was replaced after freeze')
        if len(legs)==2 and legs[0]['input_spends']==legs[1]['input_spends']:raise InvariantError('race must use distinct unsigned spends of identical inputs')
        with self.atomic():
            for leg in legs:self.store.db.execute('INSERT OR IGNORE INTO phase_preparation VALUES (?,?,?,?)',(trial,leg['leg_id'],digest(leg),canonical(leg)))
            self.store.db.execute("UPDATE phase_trial SET state='prepared',updated_at=? WHERE id=?",(time.time(),trial))
            self.store._event('phase_preparations_frozen',{'trial_id':trial,'legs':legs,'live_qualified':False})
        return prepared
    def native_prepared(self,trial,action_id,prepared):
        row=self.row(trial)
        if row['release_action']!=action_id:raise InvariantError('native preparation belongs to another released action')
        legs=prepared.get('legs',[])
        sessions=[leg.get('signing_session_sha256') for leg in legs]
        if any(leg.get('nonce_retention')!='single_process' or leg.get('restart_continuation') is not False for leg in legs):
            raise InvariantError('native nonce lifecycle must be one-process with no restart continuation')
        if any(not hash64(value) for value in sessions) or len(set(sessions))!=len(sessions):
            raise InvariantError('competing signing sessions must use distinct exact public nonces')
        return self.prepare(trial,prepared)
    def delivery_prepared(self,trial,action_id,prepared):
        public_payload(prepared);intent=self.intent(trial)
        if self.row(trial)['release_action']!=action_id or intent['scenario']!='D24' or prepared.get('intent_hash')!=intent['intent_hash']:
            raise InvariantError('delayed registration preparation differs from released intent')
        if prepared.get('original_wallet_opened') is not False or prepared.get('saved_successor_ids')!=intent['context']['saved_successor_ids'] or not hash64(prepared.get('wire_sha256')):
            raise InvariantError('delayed registration changed paid successors or original-wallet rule')
        leg={**prepared,'leg_id':'delivery','rpc':'RegisterVtxoTransactions'};checksum=digest(leg)
        old=self.store.db.execute('SELECT digest FROM phase_preparation WHERE trial_id=? AND leg_id=?',(trial,'delivery')).fetchone()
        if old and old[0]!=checksum:raise InvariantError('actual delayed registration request changed')
        with self.atomic():
            self.store.db.execute('INSERT OR IGNORE INTO phase_preparation VALUES (?,?,?,?)',(trial,'delivery',checksum,canonical(leg)))
            self.store._event('phase_delivery_preparation_frozen',{'trial_id':trial,**leg})
    def reconcile_coin(self,trial,action_id,observed):
        public_payload(observed);intent=self.intent(trial)
        if self.row(trial)['release_action']!=action_id:raise InvariantError('reconciliation belongs to another action')
        ids={v['coin_id'] for p in self.preparations(trial) for v in p.get('outputs',[])}
        if observed.get('coin_id') not in ids or observed.get('rpc')!='GetVtxo' or observed.get('server_pubkey')!=intent['server_pubkey']:
            raise InvariantError('read-only reconciliation differs from exact frozen candidate')
        if not hash64(observed.get('wire_sha256')) or not hash64(observed.get('response_sha256')) or type(observed.get('observed_at_ns')) is not int or observed['observed_at_ns']<=0 or observed.get('state') not in {'absent','present','unknown'}:
            raise EvidenceGap('exact pinned read-only request/reply evidence missing')
        if observed['state']=='absent' and observed.get('code')!='NotFound':raise InvariantError('transport failure is not output absence')
        with self.atomic():
            self.store.db.execute('INSERT OR REPLACE INTO phase_reconciliation VALUES (?,?,?,?)',(trial,observed['coin_id'],canonical(observed),time.time()))
            self.store._event('phase_coin_reconciliation',{'trial_id':trial,**observed})
    def output_inputs(self,output,intent):
        frozen=[v['coin_id'] for v in intent['inputs']]
        inputs=output.get('input_coin_ids',frozen if len(frozen)==1 else None)
        if not isinstance(inputs,list) or not inputs:raise EvidenceGap('exact per-output SDK unsigned input lineage missing')
        if len(inputs)!=len(set(inputs)) or not set(inputs).issubset(frozen):raise InvariantError('unsigned output lineage differs from frozen inputs')
        return inputs
    def exact_path(self,proof,leg,output,intent):
        expected=set(self.output_inputs(output,intent))
        return all(any(node.get('txid')==spend['txid'] and spend['coin_id'] in node.get('inputs',[]) for node in proof.get('path',[])) for spend in leg['input_spends'] if spend['coin_id'] in expected)
    def linked_coin(self,identity,intent,expected=None):
        row=self.store.db.execute('SELECT c.*,k.actor FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey WHERE c.id=?',(identity,)).fetchone()
        if row is None:return None
        proof=json.loads(row['proof'])
        if proof.get('signed_path_valid') is not True or proof.get('anchor_confirmations',0)<1:return None
        lineage={v['coin_id'] for v in intent['inputs']}.intersection(proof.get('ancestor_ids',[]))
        if not lineage or (expected is not None and lineage!=set(self.output_inputs(expected,intent))):return None
        if hashlib.sha256(bytes.fromhex(row['signed_vtxo'])).hexdigest()!=row['signed_hash']:raise InvariantError('signed successor bytes changed')
        return dict(row)
    def original_payouts(self,intent):
        found=[]
        subjects=intent['inputs']
        if intent['scenario']=='D24':
            subjects=[];covered=set()
            for identity in intent['context']['saved_successor_ids']:
                successor=self.linked_coin(identity,intent)
                if successor is None:raise EvidenceGap('paid successor lacks exact signed parent linkage')
                covered.update(set(v['coin_id'] for v in intent['inputs']).intersection(json.loads(successor['proof']).get('ancestor_ids',[])))
                subjects.append({'coin_id':identity,'amount_sat':successor['amount_sat']})
            if covered!={v['coin_id'] for v in intent['inputs']} or sum(v['amount_sat'] for v in subjects)!=intent['principal_sat']:raise EvidenceGap('saved successor package does not cover the exact frozen input principal')
        for coin in subjects:
            row=self.store.db.execute('SELECT * FROM checked_settlement WHERE coin_id=?',(coin['coin_id'],)).fetchone()
            if row is None:raise EvidenceGap('original payout is not independently checked and confirmed')
            if row['actor']!=intent['actor'] or row['amount_sat']!=coin['amount_sat']:raise InvariantError('checked payout has another original owner or gross principal')
            found.append(dict(row))
        return found
    def release(self,trial):
        row=self.row(trial);intent=self.intent(trial)
        if row['release_action']:return row['release_action']
        if not getattr(self.config,'phase_enabled',False) or not hash64(getattr(self.config,'phase_manifest_sha256',None)):
            raise EvidenceGap('qualified SDK manifest and explicit phase enablement required')
        if self.store.get_meta('paused'):raise EvidenceGap('campaign paused')
        actor=intent['actor'];args={'trial_id':trial,'phase_intent':intent,'intent_hash':intent['intent_hash'],'qualification_manifest_sha256':self.config.phase_manifest_sha256}
        if intent['scenario']=='D24':
            actor=intent['context']['courier_actor'];self.online(actor);args['checked_original_payouts']=self.original_payouts(intent)
            successors=[]
            for identity in intent['context']['saved_successor_ids']:
                coin=self.linked_coin(identity,intent)
                if coin is None:raise EvidenceGap('saved successor lacks independently signed exact parent linkage')
                successors.append({'id':identity,'signed_vtxo':coin['signed_vtxo'],'signed_hash':coin['signed_hash'],'pubkey':coin['pubkey'],'amount_sat':coin['amount_sat']})
            args['successors']=successors;operation='phase_register_saved'
        else:
            self.online(actor)
            if intent['scenario'] not in {'D17'}:raise EvidenceGap('exact native phase controller is not yet available')
            if self.preparations(trial):raise EvidenceGap('existing signing preparation cannot resume opaque SDK nonces; reconcile without retry')
            args['native_prepare_before_submit']=True
            args['nonce_retention']='single_process';args['restart_continuation']=False
            operation='phase_execute_'+intent['scenario'].lower()
        if self.store.db.execute("SELECT 1 FROM action WHERE actor_id=? AND state IN ('queued','dispatched','outcome_unknown')",(actor,)).fetchone():raise EvidenceGap('phase actor has busy or unknown action')
        identity=trial+'-release'
        with self.atomic():
            self.store.queue(identity,actor,intent['scenario'],operation,args,intent['maximum_fee_sat'])
            self.store.db.execute("UPDATE phase_trial SET state='released',release_action=?,updated_at=? WHERE id=?",(identity,time.time(),trial))
            self.store._event('phase_trial_released',{'trial_id':trial,'action_id':identity,'actor':actor,'operation':operation,'principal_sat':intent['principal_sat'],'maximum_fee_sat':intent['maximum_fee_sat'],'manifest_sha256':self.config.phase_manifest_sha256})
        return identity
    def reply(self,trial,leg,observed):
        public_payload(observed);self.row(trial)
        known=next((p for p in self.preparations(trial) if p['leg_id']==leg),None)
        if known and known['wire_sha256']!=observed.get('wire_sha256'):raise InvariantError('phase reply belongs to another signed request')
        with self.atomic():
            self.store.db.execute('INSERT OR IGNORE INTO phase_reply VALUES (?,?,?,?,?)',(trial,leg,digest({**observed,'leg_id':leg}),canonical({**observed,'leg_id':leg}),time.time()))
            self.store._event('phase_reply_observed',{'trial_id':trial,'leg_id':leg,**observed,'live_qualified':False})
    def race_identity(self,trial,intent,prepared,replies,winners):
        if len(winners)!=1:raise EvidenceGap('one independently signed exact branch required')
        intervals=[]
        for leg in prepared:
            reply=next((r for r in replies if r.get('leg_id')==leg['leg_id'] and r.get('wire_sha256')==leg['wire_sha256']),None)
            if reply is None or type(reply.get('submitted_at_ns')) is not int or type(reply.get('reply_at_ns')) is not int or not 0<reply['submitted_at_ns']<reply['reply_at_ns']:
                raise EvidenceGap('actual per-leg dispatch/reply interval missing')
            intervals.append((reply['submitted_at_ns'],reply['reply_at_ns']))
        if len(intervals)!=2 or max(v[0] for v in intervals)>=min(v[1] for v in intervals):raise EvidenceGap('actual requests did not overlap')
        chosen=next(p for p in prepared if p['leg_id']==winners[0]['leg_id'])
        others=[p for p in prepared if p['leg_id']!=chosen['leg_id']]
        if len(others)!=1:raise EvidenceGap('two exact prepared competing branches required')
        for expected in chosen['outputs']:
            coin=self.linked_coin(expected['coin_id'],intent,expected)
            proof=json.loads(coin['proof'])
            if not self.exact_path(proof,chosen,expected,intent):
                raise EvidenceGap('exact signed prepared spending path unavailable')
        loser=others[0]
        refusal=next((r for r in replies if r.get('leg_id')==loser['leg_id'] and r.get('kind')=='protocol_refusal' and r.get('wire_sha256')==loser['wire_sha256'] and r.get('code')=='InvalidArgument' and set(r.get('rejected_coin_ids',[])).intersection(v['coin_id'] for v in intent['inputs'])),None)
        if refusal is None:raise EvidenceGap('exact competing-input protocol refusal unavailable')
        for expected in loser['outputs']:
            observation=self.store.db.execute('SELECT payload FROM phase_reconciliation WHERE trial_id=? AND coin_id=?',(trial,expected['coin_id'])).fetchone()
            if observation is None:raise EvidenceGap('exact losing-output read-only reconciliation unavailable')
            observed=json.loads(observation[0])
            if observed.get('observed_at_ns',0)<max(v[1] for v in intervals):raise EvidenceGap('losing-output reconciliation predates actual race replies')
            if observed.get('state')!='absent':raise EvidenceGap('prepared losing output is present or unknown; secondary liability reconciliation required')
        latest=self.store.db.execute('SELECT MAX(observed_at) FROM phase_reply WHERE trial_id=?',(trial,)).fetchone()[0]
        def fresh(identity):
            row=self.store.db.execute("SELECT payload,observed_at FROM server_item WHERE kind='coins' AND id=?",(identity,)).fetchone()
            if row is None or latest is None or row['observed_at']<latest:raise EvidenceGap('fresh exact post-race input/successor state unavailable')
            return json.loads(row['payload'])
        for spend in chosen['input_spends']:
            row=fresh(spend['coin_id'])
            if row.get('spend_state')!='spent' or row.get('oor_spent_txid')!=spend['txid']:raise EvidenceGap('original input does not name the exact winning spend')
            if row.get('onchain_spent_txid') or row.get('spent_in_round') or row.get('offboarded_in'):raise InvariantError('winning cooperative spend also has a chain or exchange claim')
            if self.store.db.execute('SELECT 1 FROM checked_settlement WHERE coin_id=?',(spend['coin_id'],)).fetchone():raise InvariantError('original input was paid as well as cooperatively spent')
        successor=0
        for expected in chosen['outputs']:
            row=fresh(expected['coin_id'])
            if row.get('spend_state')!='spendable':raise EvidenceGap('signed winner is not yet a registered active entitlement')
            if row.get('oor_spent_txid') or row.get('onchain_spent_txid') or row.get('spent_in_round') or row.get('offboarded_in'):raise EvidenceGap('winner advanced beyond this isolated arbitration; successor reconciliation required')
            if self.store.db.execute('SELECT 1 FROM checked_settlement WHERE coin_id=?',(expected['coin_id'],)).fetchone():raise InvariantError('active race successor was also paid')
            successor+=expected['amount_sat']
        if successor!=intent['principal_sat']:raise InvariantError('race successor principal is not conserved')
        action=self.store.db.execute('SELECT actual_fee_sat FROM action WHERE id=?',(self.row(trial)['release_action'],)).fetchone()
        if action is None or action[0] is None:raise EvidenceGap('independently booked attempt fee unavailable')
        if action[0]!=0:raise InvariantError('race fee is inconsistent with exact full-principal signed outputs')
        return {'opening_principal_sat':intent['principal_sat'],'registered_successor_sat':successor,'original_payout_sat':0,'attempt_fee_sat':0,'identity_residual_sat':0,
            'winning_leg_id':chosen['leg_id'],'losing_wire_sha256':loser['wire_sha256'],'scope':'signed exact input-spend path plus fresh current server arbitration and checked payout ledger through post-reply observation; customer receipt and traffic credit are separate'}

    def paid_delivery_identity(self,trial,intent,replies):
        paid=self.original_payouts(intent)
        latest=self.store.db.execute('SELECT MAX(observed_at) FROM phase_reply WHERE trial_id=?',(trial,)).fetchone()[0]
        known=next((p for p in self.preparations(trial) if p.get('leg_id')=='delivery'),None)
        if known is None:raise EvidenceGap('exact wallet-free registration request checkpoint missing')
        if not any(r.get('kind')=='expiry_settled_refusal' and r.get('wire_sha256')==known['wire_sha256'] for r in replies):raise EvidenceGap('actual expiry-settled guard is unobserved')
        action=self.store.db.execute('SELECT actual_fee_sat FROM action WHERE id=?',(self.row(trial)['release_action'],)).fetchone()
        if action is None or action[0] is None:raise EvidenceGap('independently booked attempt fee unavailable')
        if action[0]!=0:raise InvariantError('wallet-free registration charged a fee')
        totals={'confirmed_original_net_sat':0,'recipient_fee_sat':0,'new_payee_entitlement_sat':0,'attempt_fee_sat':0}
        evidence=[]
        for payment in paid:
            current=self.store.db.execute("SELECT payload,observed_at FROM server_item WHERE kind='coins' AND id=?",(payment['coin_id'],)).fetchone()
            if current is None or latest is None or current['observed_at']<latest:raise EvidenceGap('fresh post-reply exact paid successor state missing')
            coin=json.loads(current['payload'])
            if coin.get('spend_state')!='spent':raise InvariantError('paid successor was reactivated after expiry-settled refusal')
            if coin.get('oor_spent_txid') or coin.get('spent_in_round') or coin.get('offboarded_in'):
                raise InvariantError('paid successor also carries a cooperative spend liability')
            checked=self.store.db.execute('SELECT state FROM settlement_check WHERE txid=?',(payment['txid'],)).fetchone()
            chain=self.store.db.execute('SELECT payload FROM chain_payout WHERE txid=?',(payment['txid'],)).fetchone()
            if checked is None or checked[0]!='amounts_checked' or chain is None:raise EvidenceGap('confirmed complete grouped payout amount audit missing')
            tx=json.loads(chain[0])
            if tx.get('confirmations',0)<1:raise EvidenceGap('payout confirmation missing')
            if tx.get('txid')!=payment['txid'] or transaction_fee(tx)!=tx.get('fee_sat'):raise InvariantError('payout raw-chain fee identity changed')
            group=self.store.db.execute('SELECT * FROM checked_settlement WHERE txid=?',(payment['txid'],)).fetchall()
            gross={};fees=set()
            for item in group:
                gross[item['script']]=gross.get(item['script'],0)+item['amount_sat']
                fees.add(json.loads(item['evidence']).get('row',{}).get('fee_sat'))
            if len(fees)!=1 or None in fees:raise EvidenceGap('exact grouped recipient fee unavailable')
            shares=fee_allocation(gross,fees.pop())
            outputs=[o for o in tx['outputs'] if o['script']==payment['script']]
            if len(outputs)!=1 or outputs[0]['amount_sat']!=gross[payment['script']]-shares[payment['script']]:raise InvariantError('checked payout destination or net amount changed')
            # Several coins may share a destination. Split its already checked
            # fee deterministically by exact coin identity, once, not per tx.
            same={v['coin_id']:v['amount_sat'] for v in group if v['script']==payment['script']}
            coin_share=fee_allocation(same,shares[payment['script']]) if shares[payment['script']] else {v:0 for v in same}
            fee=coin_share[payment['coin_id']]
            totals['recipient_fee_sat']+=fee;totals['confirmed_original_net_sat']+=payment['amount_sat']-fee
            evidence.append({'coin_id':payment['coin_id'],'payout_txid':payment['txid'],'current_row_sha256':digest(coin),'chain_payment_sha256':digest(tx),
                'onchain_spender_txid':coin.get('onchain_spent_txid'),'onchain_spender_scope':'separate sweep/exit fact; never equated with payout transaction'})
        if totals['confirmed_original_net_sat']+totals['recipient_fee_sat']!=intent['principal_sat']:
            raise EvidenceGap('saved successor payouts do not cover the exact once-only frozen principal')
        return {**totals,'opening_principal_sat':intent['principal_sat'],'identity_residual_sat':0,'evidence':evidence,
            'scope':'exact saved successor registration guard and checked original-owner payout through post-reply observation; sweep backing is a separate gate'}

    def judge(self,trial):
        intent=self.intent(trial);prepared=self.preparations(trial);unknowns=[];winners=[]
        for leg in prepared:
            if not leg.get('outputs'):continue
            matched=[]
            for expected in leg['outputs']:
                coin=self.linked_coin(expected['coin_id'],intent,expected)
                if coin and (coin['pubkey'],coin['amount_sat'])==(expected['pubkey'],expected['amount_sat']):
                    proof=json.loads(coin['proof'])
                    exact=self.exact_path(proof,leg,expected,intent)
                    if exact:matched.append(coin['id'])
                    else:unknowns.append('exact signed prepared spending path unavailable')
            if len(matched)==len(leg['outputs']):winners.append({'leg_id':leg['leg_id'],'signed_output_ids':matched})
            else:unknowns.append('signed_successor_linkage')
        replies=[json.loads(r[0]) for r in self.store.db.execute('SELECT payload FROM phase_reply WHERE trial_id=?',(trial,))]
        if any(r.get('kind') in {'transport_unknown','generic_refusal'} for r in replies):unknowns.append('ambiguous_protocol_outcome')
        if intent['scenario'] in {'D18','D19','D20','D26'}:unknowns.append('round_forfeit_and_confirmed_outputs' if intent['scenario']=='D18' else 'exact_chain_or_exchange_arbitration')
        financial=None
        if intent['scenario']=='D17':
            try:financial=self.race_identity(trial,intent,prepared,replies,winners)
            except EvidenceGap as error:unknowns.append(str(error))
            except InvariantError:
                self.store.db.execute("INSERT OR REPLACE INTO meta VALUES ('paused','phase contradiction')");raise
            if financial is not None:unknowns=[]
        if intent['scenario']=='D24':
            try:financial=self.paid_delivery_identity(trial,intent,replies)
            except EvidenceGap as error:unknowns.append(str(error))
            except InvariantError:
                self.store.db.execute("INSERT OR REPLACE INTO meta VALUES ('paused','phase contradiction')");raise
        # Signed competing spends are already a material contradiction. A single
        # signed branch still needs fresh server ownership and once-only money.
        if len(winners)>1:
            self.store.db.execute("INSERT OR REPLACE INTO meta VALUES ('paused','phase contradiction')")
            self.store.event('phase_trial_incident',{'trial_id':trial,'competing_signed_branches':winners})
            raise InvariantError('multiple independently signed competing successors spend the identical input')
        if financial is None:unknowns+=['independent_fee_booking','fresh_entitlement_and_input_state','complete_once_only_financial_identity']
        verdict={'trial_id':trial,'scenario':intent['scenario'],'state':'verified' if financial is not None and not unknowns else 'pending','signed_candidates':winners,
            'principal_sat':intent['principal_sat'],'principal_counted_once':True,'maximum_fee_sat':intent['maximum_fee_sat'],
            'financial_identity':financial,'unknowns':list(dict.fromkeys(unknowns)),'live_qualified':False,'customer_traffic_credit':False}
        prior=self.store.db.execute('SELECT payload FROM phase_verdict WHERE trial_id=?',(trial,)).fetchone()
        if prior is not None and prior[0]==canonical(verdict):return verdict
        with self.atomic():
            self.store.db.execute('INSERT OR REPLACE INTO phase_verdict VALUES (?,?,?)',(trial,canonical(verdict),time.time()))
            self.store._event('phase_trial_adjudication',verdict)
        return verdict

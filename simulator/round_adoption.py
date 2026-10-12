"""Prioritize existing confirmed round intents without claiming money outcomes.

Frozen SDK keys and exact public funding anchors identify a sync candidate.
Decoder metadata and nursery confirmation heights remain trusted scheduling
observations; signed client adoption and original fees use their existing oracles.
"""
from __future__ import annotations
from pathlib import Path
from collections import Counter
from contextlib import nullcontext
import hashlib
import json
import re
import time
from .bundle_audit import decode_transaction
from .model import InvariantError,canonical,integer,public_payload
from .ownership import EvidenceGap
from .process import json_command,public_command_capture

SCHEMA='''
CREATE TABLE IF NOT EXISTS round_confirmed_sync(
 refresh_action_id TEXT NOT NULL REFERENCES action(id),round_txid TEXT NOT NULL,
 attempt INTEGER NOT NULL,sync_action_id TEXT NOT NULL UNIQUE REFERENCES action(id),
 evidence TEXT NOT NULL,queued_at REAL NOT NULL,
 PRIMARY KEY(refresh_action_id,round_txid,attempt));
CREATE TABLE IF NOT EXISTS round_input_params(signed_hash TEXT PRIMARY KEY,verifier_hash TEXT NOT NULL,proof TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS round_sync_diagnostic(action_id TEXT PRIMARY KEY REFERENCES action(id),payload TEXT NOT NULL);
'''


def diagnose_stderr(text,*,redacted=False,truncated=False):
    """Summarize actual SDK log categories, never turn a warning into success."""
    result={'complete':not (redacted or truncated),'waiting_funding_txids':[],
        'confirmed_funding_txids':[],'pending_round_counts':[],'round_error_count':0,'exit_window_rejections':[]}
    if not result['complete']:return result
    if not isinstance(text,str) or len(text.encode())>262144:raise ValueError('bounded SDK stderr required')
    public_payload(text)
    result['waiting_funding_txids']=sorted(set(re.findall(r'Waiting for confirmations for round funding tx ([0-9a-f]{64})\b',text)))
    result['confirmed_funding_txids']=sorted(set(re.findall(r'Round confirmed\. Funding tx ([0-9a-f]{64})\b',text)))
    counts=re.findall(r'(?:Syncing ([0-9]+) pending round states|Processing ([0-9]+) rounds)',text)
    result['pending_round_counts']=sorted({int(first or second) for first,second in counts})
    result['round_error_count']=len(re.findall(r'(?:Error syncing round(?: #[^:]+)?|Error locking round state|Error storing round state|Error updating pending round state|Error while trying to progress rounds awaiting confirmations|Error fetching round event)',text))
    for expiry,minimum in re.findall(r'round VTXO tree expiry height ([0-9]+) is below the required minimum ([0-9]+)',text):
        value={'kind':'delegated_tree_exitability','expiry_height':int(expiry),'minimum_expiry_height':int(minimum)}
        if value not in result['exit_window_rejections']:result['exit_window_rejections'].append(value)
    for coin,expiry,tip,margin in re.findall(r'VTXO ([0-9a-f]{64}:[0-9]+) expires at height ([0-9]+), which doesn.t leave us room for a unilateral exit \(tip ([0-9]+), exit margin ([0-9]+)\)',text):
        value={'kind':'forfeit_exitability','coin_id':coin,'expiry_height':int(expiry),'tip':int(tip),'exit_margin_blocks':int(margin)}
        if value not in result['exit_window_rejections']:result['exit_window_rejections'].append(value)
    return result


def _initialize(store):
    # Never executescript(): this helper can run inside the scheduler transaction.
    for statement in SCHEMA.split(';'):
        if statement.strip():store.db.execute(statement)


def _decoder(store,row,decoder,server):
    if decoder is None:
        try:from .padding import decoded_coin
        except ImportError:return None
        decoder=decoded_coin
    value=json.loads(row['payload'])
    proof=decoder(store,value,server_pubkey=server)
    if proof is None:return None
    try:hashed=hashlib.sha256(bytes.fromhex(value['signed_vtxo'])).hexdigest()
    except (KeyError,TypeError,ValueError):return None
    if (proof.get('schema_version')!=1 or proof.get('id')!=row['id'] or value.get('vtxo_id')!=row['id']
            or proof.get('signed_hash')!=hashed or proof.get('server_pubkey')!=server
            or proof.get('expiry_height')!=value.get('expiry') or proof.get('tree_padding') is not False
            or proof.get('client_owner_verified') is not False or proof.get('chain_contract_verified') is not False
            or type(proof.get('arkoor_transition_count')) is not int or proof['arkoor_transition_count']!=0):return None
    key=proof.get('candidate_user_pubkey');point=proof.get('chain_anchor')
    if (not isinstance(key,str) or re.fullmatch('(02|03)[0-9a-f]{64}',key) is None
            or not isinstance(point,str) or re.fullmatch('[0-9a-f]{64}:[0-9]+',point) is None):return None
    return proof


def _intent(store,action):
    proposals=store.db.execute("""SELECT sequence,payload FROM event WHERE kind='driver_evidence'
        AND json_extract(payload,'$.action_id')=? AND json_extract(payload,'$.event')='refresh_proposal'""",(action['id'],)).fetchall()
    if len(proposals)!=1:raise EvidenceGap('refresh has no unique frozen proposal')
    proposal=json.loads(proposals[0]['payload'])['data'];participation=proposal['participation'];inputs=[]
    for signed in participation['inputs']:
        rows=store.db.execute('SELECT c.*,k.actor FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey WHERE signed_vtxo=?',(signed,)).fetchall()
        if len(rows)!=1:raise EvidenceGap('frozen input has no unique recorded identity')
        coin=rows[0]
        if coin['actor']!=action['actor_id']:raise InvariantError('frozen round input belongs to another actor')
        if hashlib.sha256(bytes.fromhex(signed)).hexdigest()!=coin['signed_hash']:raise InvariantError('frozen round input hash differs')
        inputs.append(coin)
    if not inputs or len({coin['id'] for coin in inputs})!=len(inputs):raise EvidenceGap('round inputs empty or ambiguous')
    outputs=[]
    for output in participation['outputs']:
        policy=output['policy']
        if not isinstance(policy,str) or re.fullmatch('00(02|03)[0-9a-f]{64}',policy) is None:raise EvidenceGap('round output is not a frozen pubkey policy')
        outputs.append((policy[2:],integer(output['amount'],'frozen round output',1)))
    fee=integer(proposal['committed_fee_sat'],'frozen round fee')
    if not outputs or sum(coin['amount_sat'] for coin in inputs)!=sum(amount for _,amount in outputs)+fee:
        raise InvariantError('frozen round does not conserve its input/output values')
    if fee>action['fee_reservation_sat']:raise InvariantError('frozen round exceeds its original reservation')
    return {'inputs':[coin['id'] for coin in inputs],'input_coins':inputs,'outputs':Counter(outputs),'proposal_sequence':proposals[0]['sequence']}


def _locked(store,actor,inputs):
    matches=[]
    for row in store.db.execute('SELECT payload FROM movement_evidence WHERE actor=?',(actor,)):
        movement=json.loads(row[0])
        if movement.get('subsystem')=='bark.round' and movement.get('status')=='pending' and sorted(movement.get('input_vtxos',[]))==sorted(inputs):matches.append(movement)
    return matches[0] if len(matches)==1 else None


def _outputs(store,action,intent,server,decoder):
    matches=[]
    for row in store.db.execute("SELECT * FROM server_item WHERE kind='coins' AND observed_at>=?",(action['created_at'],)):
        value=json.loads(row['payload'])
        if value.get('spend_state')!='unclaimed' or value.get('policy_type')!='pubkey':continue
        proof=_decoder(store,row,decoder,server)
        if proof is None or (proof['candidate_user_pubkey'],proof['amount_sat']) not in intent['outputs']:continue
        earliest=store.db.execute("SELECT MIN(observed_at) FROM server_item_version WHERE kind='coins' AND id=?",(row['id'],)).fetchone()[0]
        if earliest is not None and earliest<action['created_at']:continue
        owner=store.db.execute('SELECT actor FROM owner_key WHERE pubkey=?',(proof['candidate_user_pubkey'],)).fetchone()
        if owner is not None and owner['actor']!=action['actor_id']:raise InvariantError('frozen replacement key belongs to another actor')
        matches.append({'coin_id':row['id'],'pubkey':proof['candidate_user_pubkey'],'amount_sat':proof['amount_sat'],
            'expiry_height':proof['expiry_height'],'chain_anchor':proof['chain_anchor'],'signed_hash':proof['signed_hash'],
            'verifier_hash':proof['verifier_hash'],'inventory_observed_at':row['observed_at']})
    actual=Counter((coin['pubkey'],coin['amount_sat']) for coin in matches)
    if actual!=intent['outputs']:return []
    if len({coin['chain_anchor'].split(':')[0] for coin in matches})!=1:return []
    # Distinct unresolved proposals cannot claim the same frozen output tuple.
    for other in store.db.execute("SELECT * FROM action WHERE operation IN ('refresh','refresh_delegated') AND id<>? AND actual_fee_sat IS NULL AND state IN ('completed','dispatched','outcome_unknown')",(action['id'],)):
        try:competing=_intent(store,other)
        except InvariantError:raise
        except (EvidenceGap,KeyError,TypeError,ValueError):continue
        if set(competing['outputs'])&set(intent['outputs']):return []
    return matches


def candidate_rounds(store,config,*,decoder=None):
    """No wallet reads and no new ownership claims; caller supplies actual tip."""
    result=[]
    for action in store.db.execute("SELECT * FROM action WHERE operation IN ('refresh','refresh_delegated') AND state='completed' AND actual_fee_sat IS NULL ORDER BY created_at,id"):
        try:intent=_intent(store,action)
        except InvariantError:raise
        except (EvidenceGap,KeyError,TypeError,ValueError):continue
        locked=_locked(store,action['actor_id'],intent['inputs'])
        if locked is None:continue
        outputs=_outputs(store,action,intent,config.expected_server_pubkey,decoder)
        if not outputs:continue
        anchor=outputs[0]['chain_anchor'].split(':')[0]
        nursery=store.db.execute("SELECT * FROM server_item WHERE kind='nursery' AND id=?",(anchor,)).fetchone()
        if nursery is None:continue
        value=json.loads(nursery['payload'])
        if value.get('kind')!='round' or value.get('abandoned_at') is not None or value.get('txid')!=anchor:continue
        height=value.get('confirmed_at_height')
        if type(height) is not int or height<0:continue
        decoded=decode_transaction(value['raw_tx'])
        if decoded['txid']!=anchor:raise InvariantError('nursery raw funding transaction identity differs')
        if any(int(coin['chain_anchor'].split(':')[1])>=len(decoded['outputs']) for coin in outputs):raise InvariantError('decoded replacement anchor output is absent')
        result.append({'actor':action['actor_id'],'refresh_action_id':action['id'],'round_txid':anchor,
            'confirmed_height':height,'expected_output_coin_ids':[coin['coin_id'] for coin in outputs],
            'replacement_outputs':outputs,'pending_movement_id':locked['id'],'input_coin_ids':intent['inputs'],
            'proposal_event_sequence':intent['proposal_sequence'],'input_signed_hashes':[coin['signed_hash'] for coin in intent['input_coins']],'nursery_observed_at':nursery['observed_at'],
            'nursery_digest':hashlib.sha256(nursery['payload'].encode()).hexdigest(),
            'client_owner_verified':False,'traffic_credit':False,'scope':'unique frozen SDK output keys/value and exact decoded direct funding anchor; trusted public nursery confirmation; native signed adoption remains pending'})
    return result


def runtime_parameters(store,actor):
    """Read parameters emitted by an existing native wallet operation, never guess."""
    rows=store.db.execute("""SELECT e.sequence,e.payload,a.id FROM event e JOIN action a
        ON a.id=json_extract(e.payload,'$.action_id') WHERE e.kind='driver_evidence'
        AND json_extract(e.payload,'$.event')='wallet_runtime_parameters'
        AND a.actor_id=? AND a.state='completed' ORDER BY e.sequence DESC""",(actor,)).fetchall()
    if not rows:return None
    data=json.loads(rows[0]['payload'])['data']
    if (data.get('actor')!=actor or data.get('daemon_manual_sync') is not True or data.get('run_daemon') is not False):
        raise InvariantError('native round parameters have different actor or daemon mode')
    return {'round_tx_required_confirmations':integer(data['round_tx_required_confirmations'],'native SDK depth',1),
        'vtxo_exit_margin':integer(data['vtxo_exit_margin'],'native SDK exit margin'),
        'source_action_id':rows[0]['id'],'source_event_sequence':rows[0]['sequence']}


def queue_confirmed(store,config,snapshot,*,now=None,decoder=None,decisions=None):
    """Queue an existing intent's sync as soon as its actual SDK depth is met."""
    now=time.time() if now is None else now
    if not getattr(config,'active',False) or store.get_meta('paused'):return None
    observed=snapshot.get('observed_at')
    if (type(observed) not in (int,float) or not 0<=now-observed<=90 or snapshot.get('stable_tip') is not True
            or snapshot.get('initial_block_download') is not False or snapshot.get('server_status',{}).get('status')!='running'):return None
    height=snapshot.get('height')
    if type(height) is not int or height<0:return None
    retry=integer(getattr(config,'round_sync_retry_seconds',120),'round sync retry interval',1)
    reserve=integer(config.action_fee_reserve_sat,'sync fee reserve')
    if reserve>2000:raise ValueError('round sync reserve exceeds 2000 sats')
    _initialize(store)
    held=[]
    def hold(candidate,reason):
        decision={'actor':candidate['actor'],'rule_id':'round_confirmed_sync','outcome':'held','reason':reason,'inputs':candidate}
        held.append(decision)
        if decisions is not None:decisions.append(decision)
    for candidate in candidate_rounds(store,config,decoder=decoder):
        actor=candidate['actor'];details=store.db.execute('SELECT online,details FROM actor WHERE id=?',(actor,)).fetchone()
        if details is None or not details['online']:continue
        detail=json.loads(details['details'])
        if detail.get('permanent_absence') or not detail.get('created') or not detail.get('ark_address'):continue
        if store.db.execute("SELECT 1 FROM action WHERE actor_id=? AND state IN ('queued','dispatched','outcome_unknown')",(actor,)).fetchone():continue
        parameters=runtime_parameters(store,actor)
        candidate={**candidate,'sdk_parameters':parameters}
        if parameters is None:
            hold(candidate,'sdk_parameters_unknown');continue
        if any(getattr(config,name,actual)!=actual for name,actual in (
                ('round_sync_required_confirmations',parameters['round_tx_required_confirmations']),
                ('round_sync_exit_margin_blocks',parameters['vtxo_exit_margin']))):
            hold(candidate,'sdk_parameters_mismatch');continue
        required=parameters['round_tx_required_confirmations']
        confirmations=height-candidate['confirmed_height']+1
        if confirmations<required:continue
        security=security_window(store,candidate,config,height)
        candidate={**candidate,'security_window':security}
        if security['status']!='ready':
            hold(candidate,'sdk_exitability_window' if security['status']=='held' else 'sdk_input_parameters_unknown');continue
        previous=store.db.execute('SELECT r.*,a.state,a.updated_at FROM round_confirmed_sync r JOIN action a ON a.id=r.sync_action_id WHERE refresh_action_id=? AND round_txid=? ORDER BY attempt DESC LIMIT 1',
            (candidate['refresh_action_id'],candidate['round_txid'])).fetchone()
        if previous and (previous['state']!='completed' or now-previous['updated_at']<retry):continue
        if store.remaining_fee_budget()<reserve:return None
        attempt=previous['attempt']+1 if previous else 0
        digest=hashlib.sha256(canonical([candidate['refresh_action_id'],candidate['round_txid'],attempt]).encode()).hexdigest()
        identity='round-confirmed-sync-'+digest
        args={'round_confirmed_for_action_id':candidate['refresh_action_id'],'round_txid':candidate['round_txid'],
            'expected_output_coin_ids':candidate['expected_output_coin_ids'],'confirmed_height':candidate['confirmed_height'],'required_confirmations':required}
        decision={'actor':actor,'rule_id':'round_confirmed_sync','outcome':'queued','operation':'sync','action_id':identity,
            'inputs':{**candidate,'height':height,'confirmations':confirmations,'required_confirmations':required,'attempt':attempt,'fee_reserve_sat':reserve}}
        public_payload(decision)
        with (nullcontext() if store.db.in_transaction else store.transaction()):
            store.queue(identity,actor,'H01','sync',args,reserve)
            store.db.execute('INSERT INTO round_confirmed_sync VALUES (?,?,?,?,?,?)',(candidate['refresh_action_id'],candidate['round_txid'],attempt,identity,canonical(decision['inputs']),now))
            store._event('round_confirmed_sync_queued',decision)
        if decisions is not None:decisions.append(decision)
        return decision
    return held[0] if held else None


def near_expiry_findings(store,config,snapshot,*,decoder=None):
    """Expose known unclaimed refresh candidates; never infer loss or entitlement."""
    height=snapshot.get('height')
    if type(height) is not int or height<0:return []
    threshold=integer(getattr(config,'round_unclaimed_warning_blocks',6),'unclaimed round warning blocks',1)
    result=[]
    for action in store.db.execute("SELECT * FROM action WHERE operation IN ('refresh','refresh_delegated') AND state IN ('completed','dispatched','outcome_unknown') ORDER BY created_at,id"):
        try:intent=_intent(store,action)
        except InvariantError:raise
        except (EvidenceGap,KeyError,TypeError,ValueError):continue
        for coin in _outputs(store,action,intent,config.expected_server_pubkey,decoder):
            remaining=coin['expiry_height']-height
            if remaining>=threshold:continue
            # A fresh native Spendable observation is positive adoption evidence.
            adopted=store.db.execute("""SELECT 1 FROM coin_observation o JOIN action a ON a.id=o.action_id
                JOIN owned_coin c ON c.id=o.coin_id JOIN owner_key k ON k.pubkey=c.pubkey
                WHERE o.coin_id=? AND k.actor=? AND c.pubkey=? AND c.amount_sat=? AND o.state='Spendable'
                AND a.state='completed' AND a.operation IN ('sync','snapshot') AND a.updated_at>=? LIMIT 1""",
                (coin['coin_id'],action['actor_id'],coin['pubkey'],coin['amount_sat'],action['created_at'])).fetchone()
            if adopted:continue
            result.append({'key':'round_unclaimed_near_expiry:'+coin['coin_id'],'actor':action['actor_id'],'coin_id':coin['coin_id'],
                'refresh_action_id':action['id'],'round_txid':coin['chain_anchor'].split(':')[0],'expiry_height':coin['expiry_height'],
                'height':height,'blocks_remaining':remaining,'warning_threshold_blocks':threshold,'inventory_observed_at':coin['inventory_observed_at'],
                'signed_hash':coin['signed_hash'],'verifier_hash':coin['verifier_hash'],'pubkey':coin['pubkey'],'amount_sat':coin['amount_sat'],'client_owner_verified':False,'traffic_credit':False,
                'scope':'decoder-bound unclaimed output matching a unique frozen SDK refresh; client signed adoption and payout verdict are separate'})
    return result


def record_input_params(store,signed,proof,server_pubkey,verifier_hash):
    """Bind decoder security parameters to the exact existing frozen coin bytes."""
    public_payload(proof)
    _initialize(store)
    hashed=hashlib.sha256(bytes.fromhex(signed)).hexdigest()
    coin=store.db.execute('SELECT * FROM owned_coin WHERE signed_vtxo=? AND signed_hash=?',(signed,hashed)).fetchall()
    if len(coin)!=1:raise EvidenceGap('input parameter decoding lacks a unique recorded signed input')
    coin=coin[0]
    if ((proof.get('id'),proof.get('candidate_user_pubkey'),proof.get('amount_sat'))!=(coin['id'],coin['pubkey'],coin['amount_sat'])
            or proof.get('schema_version')!=1 or proof.get('server_pubkey')!=server_pubkey
            or proof.get('client_owner_verified') is not False or proof.get('chain_contract_verified') is not False):raise InvariantError('decoded input parameters differ from frozen coin or scope')
    integer(proof['exit_delta'],'decoded input exit delta');integer(proof['expiry_height'],'decoded input expiry')
    original=json.loads(coin['proof'])
    if original.get('expiry_height') is not None and original['expiry_height']!=proof['expiry_height']:raise InvariantError('decoded input expiry differs from independent signed proof')
    if re.fullmatch('[0-9a-f]{64}',verifier_hash) is None:raise ValueError('input decoder hash required')
    value={key:proof[key] for key in ('schema_version','id','candidate_user_pubkey','amount_sat','expiry_height','exit_delta','server_pubkey','client_owner_verified','chain_contract_verified')}
    previous=store.db.execute('SELECT proof FROM round_input_params WHERE signed_hash=?',(hashed,)).fetchone()
    if previous and previous['proof']!=canonical(value):raise InvariantError('same frozen input bytes have competing SDK security parameters')
    if previous:return
    with (nullcontext() if store.db.in_transaction else store.transaction()):
        store.db.execute('INSERT INTO round_input_params VALUES (?,?,?)',(hashed,verifier_hash,canonical(value)))
        store._event('round_input_parameters_decoded',{'coin_id':coin['id'],'signed_hash':hashed,'verifier_hash':verifier_hash,
            'expiry_height':value['expiry_height'],'exit_delta':value['exit_delta'],'customer_ownership_credit':False})


async def collect_input_params(store,config,*,limit=8):
    """Pure public SDK decoding only; no client, Core or server operation."""
    command=getattr(config,'server_policy_command',())
    if not command:return
    integer(limit,'input decoder batch',1)
    if limit>32 or len(command)!=1:raise ValueError('bounded input decoder requires one executable')
    executable=Path(command[0])
    if not executable.is_absolute() or executable.is_symlink():raise ValueError('safe declared SDK decoder executable required')
    with executable.open('rb') as stream:verifier_hash=hashlib.file_digest(stream,'sha256').hexdigest()
    _initialize(store);seen=set();count=0
    for action in store.db.execute("SELECT * FROM action WHERE operation IN ('refresh','refresh_delegated') AND state IN ('completed','dispatched','outcome_unknown') AND actual_fee_sat IS NULL ORDER BY created_at DESC,id"):
        try:intent=_intent(store,action)
        except InvariantError:raise
        except (EvidenceGap,KeyError,ValueError,TypeError):continue
        for coin in intent['input_coins']:
            hashed=coin['signed_hash']
            if hashed in seen or store.db.execute('SELECT 1 FROM round_input_params WHERE signed_hash=?',(hashed,)).fetchone():continue
            if count>=limit:return
            seen.add(hashed);count+=1
            request={'signed_vtxo':coin['signed_vtxo'],'server_pubkey':config.expected_server_pubkey}
            try:
                response=await json_command(list(command),request,timeout=30,**public_command_capture(store,'round.input_decode',request))
                record_input_params(store,coin['signed_vtxo'],response,config.expected_server_pubkey,verifier_hash)
            except InvariantError:raise
            except (KeyError,TypeError,ValueError,RuntimeError,TimeoutError) as error:
                store.trace_capture('round.input_decode.gap',{'refresh_action_id':action['id'],'coin_id':coin['id'],'reason':type(error).__name__})


def security_window(store,candidate,config,height):
    """Mirror the SDK's reported policy for visibility; never change its checks."""
    _initialize(store)
    runtime=candidate.get('sdk_parameters') or runtime_parameters(store,candidate['actor'])
    if runtime is None:return {'status':'unknown','reason':'actual native SDK parameters unavailable','sdk_policy_changed':False}
    margin=runtime['vtxo_exit_margin']
    params=[]
    for hashed in candidate['input_signed_hashes']:
        row=store.db.execute('SELECT proof FROM round_input_params WHERE signed_hash=?',(hashed,)).fetchone()
        if row is None:
            return {'status':'unknown','reason':'exact frozen input parameters await public SDK decoding','exit_margin_blocks':margin,
                'all_inputs_expired':None,'minimum_output_expiry_height':None,'sdk_policy_changed':False}
        params.append(json.loads(row['proof']))
    expired=all(value['expiry_height']<=height for value in params)
    delta=max(value['exit_delta'] for value in params)
    minimum=0 if expired else height+2*margin+delta
    observed=min(value['expiry_height'] for value in candidate['replacement_outputs'])
    return {'status':'ready' if expired or observed>=minimum else 'held','exit_margin_blocks':margin,
        'maximum_input_exit_delta_blocks':delta,'input_expiry_heights':[value['expiry_height'] for value in params],
        'all_inputs_expired':expired,'minimum_output_expiry_height':minimum,'minimum_observed_output_expiry_height':observed,
        'reason':'SDK explicitly skips output exitability floor only when all original inputs have expired' if expired else 'SDK requires output expiry >= tip + 2*exit_margin + maximum input exit_delta',
        'sdk_policy_changed':False}


def security_findings(store,config,snapshot,*,decoder=None):
    height=snapshot.get('height')
    if type(height) is not int or height<0:return []
    result=[]
    for candidate in candidate_rounds(store,config,decoder=decoder):
        security=security_window(store,candidate,config,height)
        if security['status']!='held':continue
        result.append({'key':'round_adoption_security_window:'+candidate['refresh_action_id'],'reason':'sdk_exitability_window',
            **candidate,'height':height,'security_window':security,'client_owner_verified':False,'traffic_credit':False})
    return result


def record_sync_diagnostic(store,action_id,diagnostic):
    """Keep a small append-only summary while full SDK stderr remains in trace."""
    public_payload(diagnostic)
    keys={'complete','waiting_funding_txids','confirmed_funding_txids','pending_round_counts','round_error_count','exit_window_rejections'}
    if set(diagnostic)!=keys or len(canonical(diagnostic).encode())>16384:raise ValueError('bounded structured SDK diagnostic required')
    if type(diagnostic['complete']) is not bool:raise ValueError('diagnostic completeness must be explicit')
    for key in ('waiting_funding_txids','confirmed_funding_txids'):
        if not isinstance(diagnostic[key],list) or any(not isinstance(txid,str) or re.fullmatch('[0-9a-f]{64}',txid) is None for txid in diagnostic[key]):raise ValueError('exact diagnostic txids required')
    for count in diagnostic['pending_round_counts']:integer(count,'pending round count')
    integer(diagnostic['round_error_count'],'SDK round error count')
    for rejection in diagnostic['exit_window_rejections']:
        expected={'kind','expiry_height','minimum_expiry_height'} if rejection.get('kind')=='delegated_tree_exitability' else {'kind','coin_id','expiry_height','tip','exit_margin_blocks'}
        if set(rejection)!=expected:raise ValueError('structured SDK exit rejection required')
        if rejection.get('kind') not in {'delegated_tree_exitability','forfeit_exitability'}:raise ValueError('unknown SDK rejection')
        for key,value in rejection.items():
            if key not in {'kind','coin_id'}:integer(value,'SDK rejection height')
        if 'coin_id' in rejection and re.fullmatch('[0-9a-f]{64}:[0-9]+',rejection['coin_id']) is None:raise ValueError('exact rejection coin required')
    _initialize(store)
    action=store.db.execute('SELECT actor_id,operation FROM action WHERE id=?',(action_id,)).fetchone()
    if action is None:raise ValueError('SDK diagnostic lacks its original action')
    if action['operation'] not in {'sync','refresh','refresh_delegated'}:return
    encoded=canonical(diagnostic)
    existing=store.db.execute('SELECT payload FROM round_sync_diagnostic WHERE action_id=?',(action_id,)).fetchone()
    if existing:
        if existing['payload']!=encoded:raise InvariantError('SDK diagnostic changed for the same original action')
        return
    with (nullcontext() if store.db.in_transaction else store.transaction()):
        store.db.execute('INSERT INTO round_sync_diagnostic VALUES (?,?)',(action_id,encoded))
        store._event('round_sync_diagnostic',{'action_id':action_id,'actor':action['actor_id'],'operation':action['operation'],**diagnostic,
            'scope':'public SDK log categories; outer success is not native signed adoption'})


def observation_findings(store,snapshot,config=None):
    """Reports can evaluate captured scheduling facts without live calls."""
    if config is None:
        from types import SimpleNamespace
        target=json.loads(store.get_meta('target_identity') or '{}')
        config=SimpleNamespace(expected_server_pubkey=target.get('server_pubkey'))
    if not config.expected_server_pubkey:return []
    return near_expiry_findings(store,config,snapshot)+security_findings(store,config,snapshot)


def observation_can_clear(store,key,snapshot,config=None):
    """Evidence absence never clears an adoption or security-window warning."""
    row=store.db.execute('SELECT evidence FROM observation WHERE key=?',(key,)).fetchone()
    if row is None:return False
    evidence=json.loads(row['evidence']);action_id=evidence.get('refresh_action_id')
    action=store.db.execute('SELECT actual_fee_sat,actor_id FROM action WHERE id=?',(action_id,)).fetchone()
    if action is None:return False
    if action['actual_fee_sat'] is not None:return True
    if key.startswith('round_unclaimed_near_expiry:'):
        coin=evidence.get('coin_id')
        return store.db.execute("""SELECT 1 FROM coin_observation o JOIN action a ON a.id=o.action_id
            JOIN owned_coin c ON c.id=o.coin_id JOIN owner_key k ON k.pubkey=c.pubkey
            WHERE o.coin_id=? AND k.actor=? AND c.pubkey=? AND c.amount_sat=? AND o.state='Spendable'
            AND a.state='completed' AND a.operation IN ('sync','snapshot') LIMIT 1""",
            (coin,action['actor_id'],evidence.get('pubkey'),evidence.get('amount_sat'))).fetchone() is not None
    return False

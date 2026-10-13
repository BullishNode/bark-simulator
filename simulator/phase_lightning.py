"""Same-hash genuine claim/refund checkpoints; no receipt or outcome shortcuts."""
from __future__ import annotations
import hashlib,json,time
from .model import canonical,integer,InvariantError,public_payload
from .ownership import EvidenceGap
from .phase_trials import hash64

def validate_prepared(intent,legs):
    public_payload(legs);scenario=intent.get('scenario');context=intent.get('context',{})
    if scenario not in {'D33','D34','D36'}:raise InvariantError('Lightning phase differs')
    payment_hash=context.get('payment_hash')
    if not hash64(payment_hash):raise EvidenceGap('exact same-hash payment declaration missing')
    expected={'claim':('ClaimLightningReceive',[v['coin_id'] for v in intent['inputs']])}
    if scenario!='D36':expected['refund']=('RequestLightningPayHtlcRevocation',context.get('sender_htlc_ids',[]))
    if {leg.get('leg_id') for leg in legs}!=set(expected) or len(legs)!=len(expected):raise InvariantError('exact claim/refund leg count differs')
    for leg in legs:
        rpc,ids=expected[leg['leg_id']]
        if not ids or len(ids)>16 or len(ids)!=len(set(ids)) or leg.get('rpc')!=rpc or leg.get('input_coin_ids')!=ids or leg.get('payment_hash')!=payment_hash:raise InvariantError('prepared Lightning request differs from exact same-hash HTLC identity')
        if leg.get('nonce_retention')!='single_process' or leg.get('restart_continuation') is not False:raise InvariantError('Lightning signing nonces require one process and no restart continuation')
        for name in ['wire_sha256','private_checkpoint_sha256','signing_session_sha256']:
            if not hash64(leg.get(name)):raise EvidenceGap('exact protected signing/request checkpoint missing')
        spends=leg.get('input_spends',[])
        if [v.get('coin_id') for v in spends]!=ids or any(not hash64(v.get('txid')) for v in spends):raise EvidenceGap('actual unsigned HTLC spend identities missing')
        outputs=leg.get('outputs',[]);coverage=set()
        if not outputs or len(outputs)>32 or len({v['coin_id'] for v in outputs})!=len(outputs):raise EvidenceGap('exact unsigned claim/refund leaves missing')
        for output in outputs:
            ancestors=output.get('input_coin_ids')
            if not ancestors or not set(ancestors).issubset(ids) or len(set(ancestors))!=len(ancestors):raise InvariantError('Lightning leaf input lineage differs')
            coverage.update(ancestors)
        principal=integer(leg.get('input_principal_sat'),'actual HTLC input value',1)
        if coverage!=set(ids) or sum(integer(v['amount_sat'],'unsigned claim/refund output',1) for v in outputs)!=principal:raise InvariantError('claim/refund package does not conserve actual HTLC inputs')
        if leg['leg_id']=='claim' and principal!=intent['principal_sat']:raise InvariantError('claim package changes frozen receiver principal')
    if len({v['signing_session_sha256'] for v in legs})!=len(legs):raise InvariantError('claim/refund signing sessions cannot reuse public nonces')
    deadline=None
    if scenario=='D36':deadline=integer(context.get('withhold_until_height'),'actual withholding block deadline',1)
    return {'scenario':scenario,'payment_hash':payment_hash,'principal_sat':intent['principal_sat'],'principal_counted_once':True,
        'withhold_until_height':deadline,'claim_dispatched':False,'financial_outcome_verified':False,'customer_traffic_credit':False,
        'required_audit':'signed exact claim/refund paths, current same-hash server arbitration, existing sender/receive fees and SDK movement adoption'}

def refund_authorization(store,intent,refund):
    """D33 resumes the retained claim only after independent saved proof import.

    Claims of verification passed by the driver are not accepted. Read the real
    owned-coin proof rows and fresh original server arbitration instead.
    """
    if store is None:raise EvidenceGap('independently collected proof store unavailable')
    if intent.get('scenario')!='D33' or refund.get('leg_id')!='refund' or refund.get('payment_hash')!=intent['context']['payment_hash']:raise InvariantError('refund authorization differs from same-hash delayed claim')
    now=time.time();proofs=[];states=[];input_total=0;output_total=0
    for spend in refund['input_spends']:
        original=store.db.execute('SELECT * FROM owned_coin WHERE id=?',(spend['coin_id'],)).fetchone()
        row=store.db.execute("SELECT payload,observed_at FROM server_item WHERE kind='coins' AND id=?",(spend['coin_id'],)).fetchone()
        if original is None or row is None or now-row['observed_at']>60:raise EvidenceGap('fresh exact independently verified refund input state unavailable')
        proof=json.loads(original['proof']);state=json.loads(row['payload'])
        if hashlib.sha256(bytes.fromhex(original['signed_vtxo'])).hexdigest()!=original['signed_hash']:raise InvariantError('sender HTLC signed bytes changed')
        if proof.get('signed_path_valid') is not True or proof.get('anchor_confirmations',0)<1 or proof.get('htlc_role')!='send' or proof.get('server_pubkey')!=intent['server_pubkey'] or proof.get('htlc_payment_hash')!=intent['context']['payment_hash']:raise EvidenceGap('independent native HTLC policy/hash proof unavailable')
        if state.get('spend_state')!='spent' or state.get('oor_spent_txid')!=spend['txid']:raise EvidenceGap('sender input does not name exact refund spend')
        if state.get('onchain_spent_txid') or state.get('spent_in_round') or state.get('offboarded_in'):raise InvariantError('refunded sender HTLC also has another financial claim')
        if store.db.execute('SELECT 1 FROM checked_settlement WHERE coin_id=?',(spend['coin_id'],)).fetchone():raise InvariantError('sender HTLC was paid as well as refunded')
        input_total+=original['amount_sat'];states.append(state)
    for expected in refund['outputs']:
        row=store.db.execute('SELECT * FROM owned_coin WHERE id=?',(expected['coin_id'],)).fetchone()
        current=store.db.execute("SELECT payload,observed_at FROM server_item WHERE kind='coins' AND id=?",(expected['coin_id'],)).fetchone()
        if row is None or current is None or now-current['observed_at']>60:raise EvidenceGap('fresh independently signed registered refund leaves unavailable')
        proof=json.loads(row['proof']);state=json.loads(current['payload'])
        if proof.get('signed_path_valid') is not True or proof.get('anchor_confirmations',0)<1 or proof.get('server_pubkey')!=intent['server_pubkey']:raise EvidenceGap('signed refund path/anchor/server proof missing')
        if hashlib.sha256(bytes.fromhex(row['signed_vtxo'])).hexdigest()!=row['signed_hash'] or row['amount_sat']!=expected['amount_sat']:raise InvariantError('refund signed bytes/value differ from prepared leaf')
        if expected.get('pubkey')!=row['pubkey']:raise InvariantError('refund changes exact prepared key')
        key=store.db.execute('SELECT actor FROM owner_key WHERE pubkey=?',(row['pubkey'],)).fetchone()
        if key is None or key[0]!=intent['context']['sender_actor']:raise EvidenceGap('refund recipient signed ownership proof unavailable')
        for spend in refund['input_spends']:
            if spend['coin_id'] not in expected['input_coin_ids']:continue
            if not any(node.get('txid')==spend['txid'] and spend['coin_id'] in node.get('inputs',[]) for node in proof.get('path',[])):raise EvidenceGap('refund leaf lacks exact prepared signed spend')
        if state.get('spend_state')!='spendable' or any(state.get(k) for k in ['oor_spent_txid','onchain_spent_txid','spent_in_round','offboarded_in']):raise EvidenceGap('refund is not yet a sole active registered entitlement')
        if store.db.execute('SELECT 1 FROM checked_settlement WHERE coin_id=?',(expected['coin_id'],)).fetchone():raise InvariantError('active refund leaf also paid')
        output_total+=row['amount_sat'];proofs.append({'id':row['id'],'signed_hash':row['signed_hash'],'proof':proof});states.append(state)
    if input_total!=output_total or output_total!=refund['input_principal_sat']:raise InvariantError('exact refund outputs do not conserve sender HTLC principal')
    return {'payment_hash':intent['context']['payment_hash'],'refund_wire_sha256':refund['wire_sha256'],'refund_output_ids':[v['coin_id'] for v in refund['outputs']],
        'independent_proof_sha256':hashlib.sha256(canonical(proofs).encode()).hexdigest(),'original_spend_sha256':hashlib.sha256(canonical(states).encode()).hexdigest(),
        'actual_refund_attempt_fee_sat':0,'sender_htlc_gross_sat':input_total,'scope':'exact signed registered sender refund through fresh server observation; overall same-hash receiver and existing sender fee arbitration remain separate'}


def registration_allowed(replies):
    """Complete single winner plus known competing refusal; no blind follow-up."""
    return len(replies)==2 and sum(v.get('kind')=='sdk_signed_successors' for v in replies)==1 and all(v.get('kind') in {'sdk_signed_successors','protocol_refusal'} for v in replies)


def sender_refund_terms(checkpoint):
    """Read genuine SDK serde progress; never invoke failure or derive a key."""
    progress=checkpoint.get('progress')
    if not isinstance(progress,dict) or len(progress)!=1:raise EvidenceGap('genuine prepared sender HTLC checkpoint required')
    stage,value=next(iter(progress.items()))
    if stage in {'HtlcReceived','PaymentInitiated'}:
        htlcs=value;key=checkpoint.get('revocation_key')
        if key is None:raise EvidenceGap('pending legacy checkpoint lacks its prederived revocation key')
    elif stage=='RevocableHtlcs':
        htlcs=value.get('htlcs',{});key=value.get('revocation',{}).get('key')
        if checkpoint.get('revocation_key') not in (None,key):raise InvariantError('existing revocation differs from its prederived key')
    else:raise EvidenceGap('sender state has no unused genuine refund preparation')
    import re
    if not isinstance(key,str) or not re.fullmatch('(02|03)[0-9a-f]{64}',key):raise EvidenceGap('exact native prederived revocation key required')
    ids=htlcs.get('vtxo_ids') if isinstance(htlcs,dict) else None
    if not isinstance(ids,list) or not ids or len(ids)>16 or any(not isinstance(v,str) for v in ids) or len(set(ids))!=len(ids):raise EvidenceGap('exact prepared sender HTLC identities required')
    return key,list(ids)


def withheld_refund_ready(evidence,*,proof_lookup=None):
    """After receiver expiry, every granted path must be irrevocably resolved.

    Root supplies independently checked raw-chain proof lookup; a provided hash,
    deadline, server NotFound or driver boolean cannot authorize a refund.
    This is refund readiness only; signed refund/adoption/fees remain separate.
    """
    reasons=[]
    if proof_lookup is None:reasons.append('independent path proof lookup unavailable')
    try:
        height=integer(evidence.get('height'),'current independently observed height')
        deadline=integer(evidence.get('receiver_deadline'),'signed receiver deadline',1)
        depth=integer(evidence.get('sweep_min_confirmations'),'actual configured sweep depth',1)
        if height<=deadline:reasons.append('receiver can still claim at or before its deadline')
        granted=evidence.get('granted_ids');paths=evidence.get('paths',[])
        if not isinstance(granted,list) or not granted or len(granted)!=len(set(granted)):raise EvidenceGap('complete original granted set missing')
        if len(paths)!=len(granted) or {p.get('coin_id') for p in paths}!=set(granted):raise EvidenceGap('complete exact granted path resolutions missing')
        for path in paths:
            if path.get('resolution') not in {'swept','exited_timeout'}:raise EvidenceGap('path remains claimable or resolution is unknown')
            confirmed=integer(path.get('confirmed_height'),'independent resolution confirmation height',1)
            if confirmed+depth>height+1:raise EvidenceGap('path resolution has insufficient required sweep depth')
            checksum=path.get('raw_chain_proof_sha256')
            if not hash64(checksum):raise EvidenceGap('independent exact raw-chain path proof missing')
            if proof_lookup is not None:
                proof=proof_lookup(checksum)
                if (not isinstance(proof,dict) or hashlib.sha256(canonical(proof).encode()).hexdigest()!=checksum or proof.get('coin_id')!=path['coin_id'] or proof.get('payment_hash')!=evidence.get('payment_hash')
                        or proof.get('resolution')!=path['resolution'] or proof.get('confirmed_height')!=confirmed
                        or proof.get('method')!='independent_raw_chain_path_audit'):
                    raise EvidenceGap('independent path proof identity/hash/resolution differs')
        if not hash64(evidence.get('payment_hash')):raise EvidenceGap('exact payment hash missing')
    except (ValueError,TypeError,KeyError,EvidenceGap) as error:reasons.append(str(error))
    return {'ready':not reasons,'reasons':reasons,'payment_hash':evidence.get('payment_hash'),
        'refund_dispatched':False,'financial_outcome_verified':False,'scope':'complete irrevocable granted-path readiness only; refund signed outputs and fee/adoption proof remain required'}

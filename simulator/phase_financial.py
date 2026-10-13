"""Scoped independent financial oracles over saved signed/chain evidence.

Nothing here dispatches, retries, credits traffic or releases a reservation.
Missing positive source evidence is a gap, never an inferred zero liability.
"""
import hashlib,json,time
from .model import canonical,integer,InvariantError,transaction_fee,fee_allocation
from .ownership import EvidenceGap
from .phase_trials import digest,hash64

SCENARIOS=('D18','D19','D20','D26','D27','D28','D33','D34','D36')

def _fee(controller,trial):
    row=controller.store.db.execute('SELECT actual_fee_sat FROM action WHERE id=?',(controller.row(trial)['release_action'],)).fetchone()
    if row is None or row[0] is None:raise EvidenceGap('independently booked complete trial fee unavailable')
    return integer(row[0],'booked trial fee')

def _latest(controller,trial):
    value=controller.store.db.execute('SELECT MAX(observed_at) FROM phase_reply WHERE trial_id=?',(trial,)).fetchone()[0]
    if value is None:raise EvidenceGap('actual retained native reply observation unavailable')
    return value

def _state(controller,identity,since):
    row=controller.store.db.execute("SELECT payload,observed_at FROM server_item WHERE kind='coins' AND id=?",(identity,)).fetchone()
    if row is None or row['observed_at']<since or time.time()-row['observed_at']>60:raise EvidenceGap('fresh exact positive input/output state unavailable')
    value=json.loads(row['payload'])
    if value.get('id',value.get('vtxo_id',identity))!=identity:raise InvariantError('financial observer row names another coin')
    return value

def _coin(controller,identity,expected=None):
    row=controller.store.db.execute('SELECT c.*,k.actor FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey WHERE c.id=?',(identity,)).fetchone()
    if row is None:raise EvidenceGap('independent signed financial coin proof missing')
    proof=json.loads(row['proof'])
    if hashlib.sha256(bytes.fromhex(row['signed_vtxo'])).hexdigest()!=row['signed_hash']:raise InvariantError('signed financial serialization changed')
    if proof.get('signed_path_valid') is not True or proof.get('anchor_confirmations',0)<1:raise EvidenceGap('financial signed path/confirmed anchor proof missing')
    if expected and (row['pubkey'],row['amount_sat'])!=(expected['pubkey'],expected['amount_sat']):raise InvariantError('financial leaf differs from exact prepared key/value')
    return row,proof

def _no_payout(controller,identity):
    if controller.store.db.execute('SELECT 1 FROM checked_settlement WHERE coin_id=?',(identity,)).fetchone():raise InvariantError('active financial entitlement was independently paid as well')

def _active(controller,identity,since):
    state=_state(controller,identity,since)
    if state.get('spend_state')!='spendable' or any(state.get(k) for k in ('oor_spent_txid','onchain_spent_txid','spent_in_round','offboarded_in')):raise EvidenceGap('financial leaf is not a sole current registered entitlement')
    _no_payout(controller,identity);return state

def _payouts(controller,ids,since):
    total=0;fees=0;evidence=[]
    for identity in ids:
        row=controller.store.db.execute('SELECT * FROM checked_settlement WHERE coin_id=?',(identity,)).fetchone()
        if row is None:raise EvidenceGap('complete independent original-owner payout proof missing')
        check=controller.store.db.execute('SELECT state FROM settlement_check WHERE txid=?',(row['txid'],)).fetchone()
        chain=controller.store.db.execute('SELECT payload FROM chain_payout WHERE txid=?',(row['txid'],)).fetchone()
        if check is None or check[0]!='amounts_checked' or chain is None:raise EvidenceGap('complete raw grouped payout amount/fee check missing')
        tx=json.loads(chain[0]);state=_state(controller,identity,since)
        if tx.get('confirmations',0)<1 or tx.get('txid')!=row['txid']:raise EvidenceGap('exact confirmed payout transaction missing')
        if transaction_fee(tx)!=tx.get('fee_sat'):raise InvariantError('raw payout fee identity changed')
        if state.get('spend_state')!='spent' or any(state.get(k) for k in ('oor_spent_txid','spent_in_round','offboarded_in')):raise InvariantError('paid original also has another financial claim')
        group=controller.store.db.execute('SELECT * FROM checked_settlement WHERE txid=?',(row['txid'],)).fetchall()
        gross={};recipient_fees=set()
        for item in group:
            gross[item['script']]=gross.get(item['script'],0)+item['amount_sat'];recipient_fees.add(json.loads(item['evidence']).get('row',{}).get('fee_sat'))
        if len(recipient_fees)!=1 or None in recipient_fees:raise EvidenceGap('exact grouped payout recipient fee missing')
        split=fee_allocation(gross,recipient_fees.pop());outputs=[v for v in tx['outputs'] if v['script']==row['script']]
        if len(outputs)!=1 or outputs[0]['amount_sat']!=gross[row['script']]-split[row['script']]:raise InvariantError('confirmed payout changes owner destination/net amount')
        same={v['coin_id']:v['amount_sat'] for v in group if v['script']==row['script']};shares=fee_allocation(same,split[row['script']]) if split[row['script']] else {v:0 for v in same}
        fee=shares[identity];total+=row['amount_sat']-fee;fees+=fee;evidence.append({'coin_id':identity,'txid':row['txid'],'chain_sha256':digest(tx)})
    return {'confirmed_net_sat':total,'recipient_fee_sat':fees,'evidence':evidence}

def _round(controller,trial,intent,leg,fee):
    since=_latest(controller,trial);ids=[v['coin_id'] for v in intent['inputs']];anchors=set();states=[]
    for identity in ids:
        state=_state(controller,identity,since);txid=state.get('spent_in_round_txid')
        if state.get('spend_state')!='spent' or not hash64(txid):raise EvidenceGap('exact positive original forfeit-to-round identity missing')
        if state.get('oor_spent_txid') or state.get('onchain_spent_txid') or state.get('offboarded_in'):raise InvariantError('round input also carries a cooperative/chain claim')
        _no_payout(controller,identity);anchors.add(txid);states.append(state)
    if len(anchors)!=1:raise InvariantError('one participation maps to multiple funding roots')
    anchor=anchors.pop();outputs=[];total=0
    for expected in leg.get('requested_outputs',[]):
        candidates=controller.store.db.execute('SELECT id FROM owned_coin WHERE pubkey=?',(expected['pubkey'],)).fetchall()
        matches=[]
        for candidate in candidates:
            coin,proof=_coin(controller,candidate['id'])
            if proof.get('chain_anchor','').split(':')[0]==anchor and coin['amount_sat']==expected['amount_sat']:matches.append((coin,proof))
        if len(matches)!=1:raise EvidenceGap('exact unique independently signed confirmed round output unavailable')
        coin,proof=matches[0]
        if coin['actor']!=intent['actor']:raise InvariantError('round output changes original owner')
        _active(controller,coin['id'],since);total+=coin['amount_sat'];outputs.append({'coin_id':coin['id'],'signed_hash':coin['signed_hash']})
    if not outputs:raise EvidenceGap('complete requested round output set missing')
    committed=integer(leg.get('committed_fee_sat'),'exact frozen winning round fee')
    if total+committed!=intent['principal_sat'] or fee!=committed:raise InvariantError('confirmed round principal/fee does not conserve the opening input')
    return {'opening_principal_sat':intent['principal_sat'],'registered_successor_sat':total,'attempt_fee_sat':fee,'identity_residual_sat':0,
        'confirmed_round_txid':anchor,'signed_outputs':outputs,'original_state_sha256':digest(states),'scope':'signed confirmed round outputs and fresh exact input forfeit mapping; cryptographic forfeit-session audit remains a separate gate'}

def _round_or_arkoor(controller,trial,intent,prepared,replies,fee):
    arkoor=next((p for p in prepared if p.get('rpc')=='RequestArkoorCosign'),None)
    winners=[]
    if arkoor:
        matched=[e['coin_id'] for e in arkoor.get('outputs',[]) if controller.linked_coin(e['coin_id'],intent,e)]
        if matched and len(matched)==len(arkoor['outputs']):winners=[{'leg_id':arkoor['leg_id'],'signed_output_ids':matched}]
    if winners:return controller.race_identity(trial,intent,prepared,replies,winners)
    round_leg=next((p for p in prepared if p.get('rpc')=='SubmitPayment'),None)
    if round_leg is None:raise EvidenceGap('actual exact interactive round proposal missing')
    return _round(controller,trial,intent,round_leg,fee)

def _delegated(controller,trial,intent,prepared,replies,fee):
    if len(prepared)!=2:raise EvidenceGap('two actual same-input scheduled proposals missing')
    accepted=[r for r in replies if r.get('kind')=='delegated_submitted']
    if len(accepted)!=2:raise EvidenceGap('actual accepted replacement order/unlock identities missing')
    accepted.sort(key=lambda r:r.get('reply_at_ns',0));winner=next((p for p in prepared if p['leg_id']==accepted[-1]['leg_id']),None)
    if winner is None:raise EvidenceGap('last actual delegated proposal missing')
    result=_round(controller,trial,intent,winner,fee)
    for losing in prepared:
        if losing['leg_id']==winner['leg_id']:continue
        for output in losing['requested_outputs']:
            if controller.store.db.execute('SELECT 1 FROM owned_coin WHERE pubkey=?',(output['pubkey'],)).fetchone():raise EvidenceGap('losing delegated key has a signed liability; exact replacement arbitration required')
    result['scope']='last accepted exact delegated proposal and signed confirmed replacements; complete server acceptance-order/forfeit audit remains a separate gate';return result

def _lightning(controller,trial,intent,prepared,replies,fee):
    from .phase_lightning import refund_authorization
    refund=next((p for p in prepared if p.get('leg_id')=='refund'),None)
    if refund is None:raise EvidenceGap('actual protected sender refund package missing')
    claim_success=any(r.get('leg_id')=='claim' and r.get('kind')=='sdk_signed_successors' for r in replies)
    refund_success=any(r.get('leg_id')=='refund' and r.get('kind')=='sdk_signed_successors' for r in replies)
    if claim_success and refund_success:raise InvariantError('same hash has both signed receiver credit and sender refund')
    if refund_success:
        if fee!=0:raise InvariantError('new refund attempt cannot charge existing send/receive fees again')
        proof=refund_authorization(controller.store,{**intent,'scenario':'D33'},refund)
        if claim_success:raise InvariantError('refunded sender also granted receiver credit')
        raise EvidenceGap('sender refund is independently signed; receiver granted-path destruction and original sender/receive fee adoption remain required')
    if not claim_success:raise EvidenceGap('same-hash signed claim/refund outcome unavailable')
    claim=next((p for p in prepared if p.get('leg_id')=='claim'),None)
    if claim is None:raise EvidenceGap('actual exact receiver package missing')
    since=_latest(controller,trial);total=0
    for expected in claim['outputs']:
        coin,proof=_coin(controller,expected['coin_id'],expected)
        if not controller.exact_path(proof,claim,expected,intent):raise EvidenceGap('receiver lacks exact prepared signed input spend')
        _active(controller,coin['id'],since);total+=coin['amount_sat']
    if total!=intent['principal_sat']:raise InvariantError('same-hash receiver outputs do not conserve actual granted principal')
    raise EvidenceGap('receiver signed credit checked; original sender HTLC terminal payment and original sender/receive fee adoption remain required')

def audit(controller,trial):
    intent=controller.intent(trial);scenario=intent['scenario']
    if scenario not in SCENARIOS:raise ValueError('unknown independent financial phase')
    fee=_fee(controller,trial);prepared=controller.preparations(trial)
    replies=[json.loads(row[0]) for row in controller.store.db.execute('SELECT payload FROM phase_reply WHERE trial_id=?',(trial,))]
    if not replies:raise EvidenceGap('actual post-execution replies missing')
    if any(r.get('kind') in {'transport_unknown','generic_refusal'} for r in replies):raise EvidenceGap('original economic result remains ambiguous')
    if scenario=='D18':return _round_or_arkoor(controller,trial,intent,prepared,replies,fee)
    if scenario=='D19':
        result=_round_or_arkoor(controller,trial,intent,prepared,replies,fee)
        raise EvidenceGap('round financial branch checked; independently measured offboard raw-chain/forfeit alternative must be ruled out')
    if scenario=='D20':raise EvidenceGap('exact original exit/CPFP/CSV/claim or cooperative source arbitration and external fee-source ledger required')
    if scenario=='D26':return _delegated(controller,trial,intent,prepared,replies,fee)
    if scenario=='D27':
        ids=[v['coin_id'] for v in intent['inputs']];payment=_payouts(controller,ids,_latest(controller,trial))
        if payment['confirmed_net_sat']+payment['recipient_fee_sat']!=intent['principal_sat'] or fee!=0:raise InvariantError('cancelled participation payout does not conserve original liability')
        raise EvidenceGap('original payouts checked; exact positive expiry cancellation and no revived replacement financial audit required')
    if scenario=='D28':
        payment=_payouts(controller,[v['coin_id'] for v in intent['inputs']],_latest(controller,trial))
        if fee!=0:raise InvariantError('independent wrong-sweep rejection cannot spend an attempt fee')
        raise EvidenceGap('rightful payout checked; pinned independent actual wrong-branch raw proof rejection witness required')
    if scenario in {'D33','D34'}:return _lightning(controller,trial,intent,prepared,replies,fee)
    if scenario=='D36':raise EvidenceGap('complete independent granted-path sweep/timeout depth, zero-dispatch trace and real sender refund/adoption/fees required; deadline or NotFound is insufficient')

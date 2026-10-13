"""Prerequisites for replaying captured genuine forfeits after cancellation.

The source is an exact positive server cancellation row, not a missing status,
output count, or locally generated marker. Native code separately verifies every
saved partial signature against its original signed input and server nonce.
"""
from __future__ import annotations
import hashlib,json,math
from .model import canonical,InvariantError,integer,public_payload
from .ownership import EvidenceGap
from .phase_trials import hash64

def forfeit_readiness(store,intent):
    public_payload(intent)
    if intent.get('scenario')!='D27':raise InvariantError('cached forfeit scenario differs')
    context=intent.get('context',{});capture=context.get('captured_forfeit',{})
    ids=[v['coin_id'] for v in intent['inputs']];unlock=context.get('unlock_hash')
    if not hash64(unlock) or capture.get('input_coin_ids')!=ids or capture.get('unlock_hash')!=unlock or capture.get('server_pubkey')!=intent['server_pubkey']:
        raise InvariantError('cached forfeit differs from exact original input/hash/server declaration')
    if not all(hash64(capture.get(key)) for key in ['wire_sha256','private_bundle_sha256']) or not isinstance(capture.get('source_action_id'),str) or not capture['source_action_id']:
        raise EvidenceGap('exact prospective protected forfeit source missing')
    captured_at=capture.get('captured_at')
    if type(captured_at) not in {int,float} or not math.isfinite(captured_at) or captured_at<=0:raise EvidenceGap('actual prospective capture time missing')
    source=store.db.execute("SELECT payload,observed_at FROM server_item WHERE kind='expiry_cancelled_participation' AND id=?",(unlock,)).fetchone()
    if source is None:raise EvidenceGap('positive exact expiry cancellation row unavailable; NotFound or paginated absence is insufficient')
    if source['observed_at']<=captured_at:raise EvidenceGap('cancellation does not postdate original genuine forfeit capture')
    row=json.loads(source['payload']);outputs=context.get('cancelled_output_ids',[])
    if not outputs or len(outputs)>16 or len(set(outputs))!=len(outputs):raise EvidenceGap('exact expired replacement branch IDs missing')
    if row.get('id')!=unlock or set(row.get('input_ids',[]))!=set(ids) or set(row.get('output_ids',[]))!=set(outputs):raise InvariantError('cancellation names different original inputs or replacement branch')
    exited=row.get('exited_ids',[])
    if not exited or len(exited)!=len(set(exited)) or not set(exited).issubset(ids):raise InvariantError('positive expiry cancellation must identify actual exited original inputs')
    integer(row.get('round_id'),'cancelled server round',1)
    return {'unlock_hash':unlock,'input_coin_ids':ids,'cancelled_output_ids':outputs,'exited_input_ids':exited,
        'private_bundle_sha256':capture['private_bundle_sha256'],'wire_sha256':capture['wire_sha256'],
        'source_action_id':capture['source_action_id'],'cancellation_sha256':hashlib.sha256(canonical(row).encode()).hexdigest(),'cancellation_observed_at':source['observed_at'],
        'scope':'positive trusted server cancellation; signed branch sweeps/exits, current arbitration and payouts require independent chain proofs',
        'financial_outcome_verified':False,'customer_traffic_credit':False,'automatic_retry':False}

def wrong_sweep_readiness(store,intent,chain):
    """Choose genuine public signed branches and an actual unrelated spender.

    Native code repeats path validation and obtains raw Core transactions itself;
    this selection never substitutes for that native proof gate or pays a claim.
    """
    public_payload(intent)
    if intent.get('scenario')!='D28' or len(intent.get('inputs',[]))!=1:raise InvariantError('wrong sweep requires one exact rightful signed coin')
    context=intent.get('context',{});right=intent['inputs'][0]['coin_id'];other=context.get('other_branch_coin_id')
    if not isinstance(other,str) or other==right:raise InvariantError('actual distinct other branch required')
    def coin(identity):
        row=store.db.execute('SELECT * FROM owned_coin WHERE id=?',(identity,)).fetchone()
        if row is None:raise EvidenceGap('independently signed branch proof unavailable')
        proof=json.loads(row['proof'])
        if proof.get('signed_path_valid') is not True or proof.get('anchor_confirmations',0)<1:raise EvidenceGap('confirmed independently verified signed branch required')
        if proof.get('server_pubkey')!=intent['server_pubkey'] or hashlib.sha256(bytes.fromhex(row['signed_vtxo'])).hexdigest()!=row['signed_hash']:raise InvariantError('branch proof changed or has another server')
        anchor=proof.get('chain_anchor');path=proof.get('path',[])
        if not isinstance(anchor,str) or not path:raise EvidenceGap('complete exact signed transaction output path required')
        points={anchor,identity}
        for node in path:
            if not hash64(node.get('txid')):raise EvidenceGap('signed path transaction identity missing')
            points.add(node['txid']+':'+str(integer(node.get('output_index'),'signed path output index')))
        return row,points
    rightful,right_points=coin(right);foreign,other_points=coin(other)
    txid=context.get('candidate_sweep_txid')
    if not hash64(txid):raise EvidenceGap('actual candidate sweep transaction ID required')
    tx=chain.transaction(txid)
    if tx.get('txid')!=txid:raise InvariantError('Core candidate transaction identity differs')
    if integer(tx.get('confirmations',0),'candidate confirmations')<1:raise EvidenceGap('candidate sweep is not independently confirmed')
    spent={v.get('outpoint') for v in tx.get('inputs',[])}
    if spent.intersection(right_points):raise InvariantError('candidate spends rightful or shared path; cannot represent wrong-branch proof')
    if not spent.intersection(other_points):raise EvidenceGap('candidate does not spend the exact independently signed other branch')
    return {'rightful_signed_vtxo':rightful['signed_vtxo'],'other_signed_vtxo':foreign['signed_vtxo'],
        'rightful_coin_id':right,'other_coin_id':other,'candidate_sweep_txid':txid,'candidate_transaction_sha256':hashlib.sha256(canonical(tx).encode()).hexdigest(),
        'observed_candidate_fee_sat':integer(tx.get('fee_sat'),'actual sweep mining fee'),'server_pubkey':intent['server_pubkey'],
        'rightful_settlement_verified':False,'customer_traffic_credit':False,'native_gate_required':True,
        'scope':'confirmed Core-selected actual other-branch spender; native signed paths and raw serialized transactions must independently repeat selection; no rightful payout or spend arbitration asserted'}

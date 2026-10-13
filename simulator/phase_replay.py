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

"""Validate an actual serialized SDK-prepared offboard before finish/round race."""
from .model import InvariantError,integer
from .ownership import EvidenceGap
from .bundle_audit import decode_transaction
from .phase_trials import hash64

def validate_quote(intent,leg):
    ids=[v['coin_id'] for v in intent['inputs']]
    if leg.get('rpc')!='FinishOffboard' or leg.get('input_coin_ids')!=ids:raise InvariantError('prepared offboard input/RPC differs')
    tx=decode_transaction(leg.get('unsigned_offboard_hex'))
    if tx['txid']!=leg.get('offboard_txid'):raise InvariantError('serialized prepared offboard transaction ID changed')
    script=intent['context'].get('offboard_script')
    if not script or leg.get('destination_script')!=script or not tx['outputs'] or tx['outputs'][0]['script']!=script:raise InvariantError('offboard changes frozen owned destination')
    net=integer(leg.get('net_amount_sat'),'prepared net output',1);fee=integer(leg.get('committed_fee_sat'),'actual SDK offboard quote')
    if tx['outputs'][0]['amount_sat']!=net or net+fee!=intent['principal_sat'] or fee>intent['maximum_fee_sat']:raise InvariantError('offboard gross/net/fee identity differs from whole-trial cap')
    spends=leg.get('input_spends',[])
    if [v.get('coin_id') for v in spends]!=ids or any(not hash64(v.get('txid')) for v in spends):raise EvidenceGap('actual SDK connector-forfeit input identities missing')
    return {'opening_principal_sat':intent['principal_sat'],'prepared_onchain_net_sat':net,'committed_customer_fee_sat':fee,
        'scope':'exact unsigned SDK-validated transaction and connector forfeits; witnesses, chain confirmation and competing round arbitration remain separate'}

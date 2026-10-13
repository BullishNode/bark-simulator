"""Independent matching of genuine SDK exit packages before cooperative race."""
import hashlib,json
from .bundle_audit import decode_transaction
from .model import InvariantError,integer,public_payload
from .ownership import EvidenceGap

def validate_package(store,intent,proposal):
    public_payload(proposal)
    if intent.get('scenario')!='D20':raise InvariantError('unilateral phase differs')
    ids=[v['coin_id'] for v in intent['inputs']];context=intent['context']
    if proposal.get('input_vtxo_ids')!=ids or proposal.get('fee_cap_sat')!=intent['maximum_fee_sat'] or proposal.get('fee_funding_outpoint')!=context.get('fee_funding_outpoint') or proposal.get('fee_rate_kwu')!=integer(context.get('fee_rate_sat_per_vb'),'exit fee rate',1)*250:
        raise InvariantError('exit changes original inputs, lifetime cap, fee rate or owned funding source')
    signed=proposal.get('signed_vtxos',[])
    if len(signed)!=len(ids):raise EvidenceGap('exact original SDK signed input set missing')
    originals={}
    for identity,encoded,expected in zip(ids,signed,intent['inputs']):
        row=store.db.execute('SELECT c.*,k.actor FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey WHERE c.id=?',(identity,)).fetchone()
        if row is None:raise EvidenceGap('independently verified exit original unavailable')
        proof=json.loads(row['proof'])
        if row['actor']!=intent['actor'] or hashlib.sha256(bytes.fromhex(encoded)).hexdigest()!=expected['signed_hash'] or row['signed_vtxo']!=encoded:raise InvariantError('exit original signed bytes or owner changed')
        if proof.get('signed_path_valid') is not True or proof.get('anchor_confirmations',0)<1 or proof.get('server_pubkey')!=intent['server_pubkey']:raise EvidenceGap('exit original signed path/anchor/server proof unavailable')
        originals[identity]=proof
    packages=proposal.get('packages',[])
    if len(packages)!=len(ids) or {v.get('vtxo_id') for v in packages}!=set(ids):raise EvidenceGap('genuine complete SDK exit package inventory missing; no setup-refusal qualification')
    bound=[]
    for package in packages:
        identity=package['vtxo_id'];proof=originals[identity];rows=package.get('transactions',[])
        if not rows:raise EvidenceGap('SDK exit package not initialized; preserve exact intent and hold')
        leaf=False
        for row in rows:
            tx=decode_transaction(row['tx'])
            if tx['txid']!=row.get('txid'):raise InvariantError('raw exit package transaction ID changed')
            known=[v for v in proof.get('path',[]) if v.get('txid')==tx['txid']]
            if not known:raise InvariantError('exit package contains transaction outside independently signed original path')
            for node in known:
                index=integer(node.get('output_index'),'exact exit output index')
                if index>=len(tx['outputs']):raise InvariantError('exit signed output index unavailable')
                out=tx['outputs'][index]
                if (out['amount_sat'],out['script'])!=(node.get('output_amount_sat'),node.get('output_script')):raise InvariantError('exit package changes signed output value/script')
                leaf|=tx['txid']+':'+str(index)==identity
        if not leaf:raise EvidenceGap('genuine exit package lacks exact original leaf transaction')
        bound.append(identity)
    return {'exact_exit_leaf_ids':bound,'package_sha256':hashlib.sha256(json.dumps(proposal,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        'principal_sat':intent['principal_sat'],'financial_outcome_verified':False,'customer_traffic_credit':False,
        'scope':'exact independently signed original SDK exit leaves and immutable fee terms; mempool/confirmation, cooperative spend arbitration, owned fee-source chain proof and actual mining fees remain separate'}

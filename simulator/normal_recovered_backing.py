"""Pure direct-root recovery evidence, preserving customer liabilities.

No RPC, wallet, subprocess, event, policy or balance mutation. The collector must
actually execute its admitted hash-pinned native tools and authenticate raw source
transport before calling these joins. Tool JSON itself is not an authority.
"""
import hashlib
import json
import re
from decimal import Decimal
from .bundle_audit import decode_transaction

MAX = 2_100_000_000_000_000
NATIVE_COMPLETION_SDK = 'cccc3f5747ad11b07b4742df1a25fb7b3ebe29c9'

def _check(condition, message):
    if not condition: raise ValueError(message)

def _int(value):
    _check(type(value) is int and 0 <= value <= MAX, 'invalid recovered monetary integer')
    return value

def _hash(raw): return hashlib.sha256(raw).hexdigest()

def _hex(value):
    _check(isinstance(value,str) and len(value)<=512*1024 and re.fullmatch('[0-9a-f]*',value) is not None,'bounded native hex required')
    return bytes.fromhex(value)

def _point(value):
    _check(isinstance(value,str) and re.fullmatch('[0-9a-f]{64}:(0|[1-9][0-9]{0,9})',value) is not None,'invalid recovery source outpoint')
    txid,index=value.split(':');_check(int(index)<2**32,'recovery source index overflow')
    return txid,int(index)

def _json(raw):
    _check(isinstance(raw,bytes) and len(raw)<=2*1024*1024,'bounded original native proof required')
    def pairs(items):
        result={}
        for key,value in items:
            _check(key not in result,'duplicate native proof field');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs)

def bind_native_claim(expected,row,contract_request,contract_response,binding_request,binding_response,*,genesis,server_pubkey,
                      completed_vtxo=None,source_anchor_raw=None,policy_sdk_commit=None):
    """Join ORIGINAL native tool requests/outputs, after actual pinned execution.

    `expected` is the preserved authenticated owner/coin claim, never a newly
    supplied client flag. Binary/runtime/qualification receipts are independently
    checked by the caller, which retains these private original byte buffers.
    """
    req=_json(contract_request);contract=_json(contract_response)
    breq=_json(binding_request);binding=_json(binding_response)
    _check(isinstance(req,dict) and isinstance(contract,dict) and isinstance(breq,dict)
        and set(breq)=={'user_pubkey','binding','key_link_attestation'},'native proof request differs')
    full=_hex(row['signed_vtxo_hex']);completion={}
    if completed_vtxo is None and source_anchor_raw is None and policy_sdk_commit is None:
        _check(set(req)=={'signed_vtxo','anchor_raw','server_pubkey'},'native proof request differs')
        _check(_hex(req['signed_vtxo'])==full and req['server_pubkey']==server_pubkey,'signed native proof input differs')
    else:
        _check(isinstance(completed_vtxo,str) and isinstance(source_anchor_raw,str)
            and policy_sdk_commit==NATIVE_COMPLETION_SDK,'exact native-completion source/SDK required')
        completed=_hex(completed_vtxo)
        _check(_hash(completed)==expected.get('signed_hash'),'retained completed claim hash differs')
        _check(set(req)=={'signed_vtxo','native_vtxo','anchor_raw','server_pubkey'}
            and req=={'signed_vtxo':completed_vtxo,'native_vtxo':row['signed_vtxo_hex'],
                'anchor_raw':source_anchor_raw,'server_pubkey':server_pubkey},'literal current completed/native request differs')
        relation='exact_full_equality' if full==completed else 'final_hark_leaf_completion'
        wanted={'schema_version':1,'sdk_commit':policy_sdk_commit,'native_vtxo_sha256':_hash(full),
            'completed_vtxo_sha256':_hash(completed),'native_completion_relation':relation,
            'client_owner_verified':False,'native_owner_verified':False,'payment_verified':False}
        _check(all(type(contract.get(key)) is type(value) and contract[key]==value for key,value in wanted.items()),
            'executed current native-completion proof differs')
        completion={'completed_vtxo_sha256':_hash(completed),'native_completion_relation':relation}
    anchor=decode_transaction(req['anchor_raw'])
    root,index=_point(expected['chain_anchor'])
    _check(anchor['txid']==root and index<len(anchor['outputs']),'native proof root differs')
    _check(contract.get('signed_path_valid') is True and contract.get('chain_contract_verified') is True
        and contract.get('tree_padding') is False and contract.get('policy')=='pubkey','genuine ordinary Full contract proof required')
    for key,value in {'id':expected['coin_id'],'amount_sat':expected['amount_sat'],'chain_anchor':expected['chain_anchor'],
        'candidate_user_pubkey':expected['user_pubkey'],'server_pubkey':server_pubkey,
        'expiry_height':expected['expiry_height'],'exit_delta':expected['exit_delta']}.items():
        _check(contract.get(key)==value,'native contract and preserved claim differ')
    _check(row['vtxo_id']==expected['coin_id'] and row['amount']==expected['amount_sat'] and row['anchor_point']==expected['chain_anchor']
        and row['expiry']==expected['expiry_height'] and row['server_pubkey']==server_pubkey,'native source claim differs')
    b=binding['binding'];wanted=expected['binding']
    _check(binding['genesis']==genesis and binding['user_pubkey']==expected['user_pubkey'] and breq['user_pubkey']==expected['user_pubkey']
        and b.get('record_signature_valid') is True and b.get('key_link_signature_valid') is True,'native ownership signatures/network differ')
    _check(all(b[k]==wanted[k]==breq['binding'][k] for k in ('mailbox_pk','spk','seq')),'native rotating per-key binding differs')
    return {**expected,**completion,'signed_vtxo_sha256':_hash(full),'anchor_raw_sha256':_hash(_hex(req['anchor_raw'])),
        'key_link_signature_sha256':_hash(_hex(breq['key_link_attestation'])),
        'record_signature_sha256':_hash(_hex(breq['binding']['record_attestation'])),
        'native_request_sha256':_hash(contract_request),'native_contract_sha256':_hash(contract_response),
        'native_binding_request_sha256':_hash(binding_request),'native_binding_sha256':_hash(binding_response)}

def _transaction(core,txid):
    value=core['transactions'].get(txid)
    _check(isinstance(value,dict),'original Core transaction missing')
    _hex(value['hex']);parsed=decode_transaction(value['hex'])
    _check(parsed['txid']==txid==value['txid'] and parsed['weight']==value['weight'],'Core original raw identity/weight differs')
    _check(len(parsed['inputs'])==len(value['vin']) and len(parsed['outputs'])==len(value['vout']),'Core original geometry differs')
    for raw,rpc in zip(parsed['inputs'],value['vin']):
        _check(raw['outpoint']==rpc.get('txid','')+':'+str(rpc.get('vout','')),'Core original input differs')
    for raw,rpc in zip(parsed['outputs'],value['vout']):
        amount=Decimal(str(rpc['value']))*100000000
        _check(amount==amount.to_integral_value() and raw['vout']==rpc['n'] and raw['amount_sat']==int(amount)
            and raw['script']==rpc['scriptPubKey']['hex'],'Core original output differs')
    return value,parsed

def verify_recovered_backing(claims,tables,core,rounds_inventory,*,identity,source_hashes):
    """Resolve authenticated ordinary claims with directly swept root backing.

    claims MUST come from bind_native_claim after actual admitted native runs.
    The normal adapter enforces that call order plus source transport/qualification
    pins. This result grants no completeness, epoch or qualified-time permission.
    """
    _check(0<len(claims)<=1000,'bounded nonempty retained claim set required')
    _check(set(source_hashes)=={'native_sql','core','rounds_inventory'} and all(re.fullmatch('[0-9a-f]{64}',v or '') for v in source_hashes.values()),'original source hashes required')
    before,after=core['before'],core['after']
    for tip in (before,after):
        _check(tip['chain']=='signet' and tip['initialblockdownload'] is False and tip['blocks']==identity['tip_height']
            and tip['bestblockhash']==identity['tip_hash'],'stable independent Core source required')
    _check(core['genesis']==identity['genesis'],'Core recovery genesis differs')
    rows={r['vtxo_id']:r for r in tables['vtxo']};_check(len(rows)==len(tables['vtxo']),'duplicate native coin row')
    holds={r['id']:r for r in tables['recovery_source_hold']};_check(len(holds)==len(tables['recovery_source_hold']),'duplicate native held source')
    receipts={r['id']:r for r in tables['recovery_receipt']};_check(len(receipts)==len(tables['recovery_receipt']),'duplicate native receipt')
    _check(len(tables['recovery_reserve'])==1 and not tables['recovery_capital_release'] and not tables['expiry_settlement'],
        'initial recovered backing cannot ignore releases or settlements')
    reserve=tables['recovery_reserve'][0];script=reserve['sweep_spk']
    _hex(script)
    _check(reserve['id']=='rounds' and reserve['fee_headroom_sat']==identity['fee_headroom_sat']>0
        and reserve['checkpoint_height']==identity['tip_height'] and reserve['checkpoint_hash']==identity['tip_hash'],'native recovery policy/checkpoint differs')
    roots={};seen=set();liabilities=[]
    for claim in claims:
        identifier=claim['coin_id'];_check(identifier not in seen,'duplicate retained liability');seen.add(identifier)
        row=rows.get(identifier);_check(row is not None and row['policy_type']=='pubkey' and row['spend_state'] in ('spendable','unclaimed'), 'retained ordinary native claim unavailable')
        _check(row['amount']==_int(claim['amount_sat']) and row['anchor_point']==claim['chain_anchor'] and row['server_pubkey']==identity['server_pubkey']
            and row['expiry']==claim['expiry_height'] and row['exit_delta']==claim['exit_delta'] and claim['server_pubkey']==identity['server_pubkey']
            and _hash(_hex(row['signed_vtxo_hex']))==claim['signed_vtxo_sha256'],'authenticated claim/source bytes differ')
        _check(row['onchain_spent_txid'] is None and row['oor_spent_txid'] is None and row['spent_in_round'] is None and row['offboarded_in'] is None,'leaf has another native disposition')
        for key in ('native_request_sha256','native_contract_sha256','native_binding_request_sha256','native_binding_sha256'):
            _check(re.fullmatch('[0-9a-f]{64}',claim[key]) is not None,'native original proof provenance missing')
        links=[v for v in tables['key_link'] if v['user_pubkey']==claim['user_pubkey']]
        _check(len(links)==1 and _hash(_hex(links[0]['sig']))==claim['key_link_signature_sha256'],'native key-link differs')
        records=[v for v in tables['fallback_record'] if v['mailbox_pk']==links[0]['mailbox_pk']]
        _check(len(records)==1 and _hash(_hex(records[0]['sig']))==claim['record_signature_sha256']
            and all(records[0][k]==claim['binding'][k] for k in ('mailbox_pk','spk','seq')),'native per-key recovery record differs')
        point=claim['chain_anchor'];txid,index=_point(point)
        original,parsed=_transaction(core,txid)
        _check(_hash(_hex(original['hex']))==claim['anchor_raw_sha256'],'native signed anchor and Core original differ')
        _check(index<len(parsed['outputs']),'original held root index absent')
        root=rows.get(point);held=holds.get(point)
        _check(root is not None and held is not None and root['anchor_point']==point and root['policy_type']=='expiry','direct held backing root missing')
        _check(root['onchain_spent_txid']==held['receipt_id'] and root['spend_state']=='spent','root consumed by a foreign/unrecorded spend')
        value=parsed['outputs'][index]['amount_sat']
        _check(root['amount']==held['gross_sat']==held['held_sat']==value and held['revision']==0,'original gross reservation released or changed')
        _check(core['utxos'].get(point,'missing') is None,'confirmed swept root unexpectedly unspent or unobserved')
        info=roots.setdefault(point,{'amount_sat':value,'claims_sat':0,'receipt_id':held['receipt_id']})
        info['claims_sat']+=claim['amount_sat'];_check(info['claims_sat']<=value,'retained liabilities exceed original source gross')
        liabilities.append({'coin_id':identifier,'amount_sat':claim['amount_sat'],'root_outpoint':point,'receipt_id':held['receipt_id'],
            'native_contract_sha256':claim['native_contract_sha256'],'native_binding_sha256':claim['native_binding_sha256']})
    active_recovered={r['vtxo_id'] for r in rows.values() if r['policy_type']=='pubkey' and r['spend_state'] in ('spendable','unclaimed') and r['anchor_point'] in holds}
    _check(active_recovered==seen,'omitted or extra ordinary liability against held backing')
    _check(set(roots)==set(holds),'unattributed held source requires its own liability/operator resolver')
    _check({v['receipt_id'] for v in roots.values()}==set(receipts),'unattributed native receipt')
    recovered=0;miner=0;receipt_sources=[]
    for identifier,receipt in receipts.items():
        _check(receipt['proof_state']=='physical_bound' and receipt.get('proof_gap') is None and receipt.get('proof_gap_present',False) is False,'unknown original recovery gross')
        actual,parsed=_transaction(core,identifier)
        native_hex=receipt.get('transaction_bytes_hex',receipt.get('transaction_bytes','').removeprefix('\\x'))
        _check(_hex(native_hex)==_hex(actual['hex']),'SQL/Core receipt full signed bytes differ')
        _check(actual.get('confirmations',0)>0 and receipt['block_height']+actual['confirmations']-1==identity['tip_height']
            and actual['blockhash']==receipt['block_hash'],'original sweep is not active at measured tip')
        points=[i['outpoint'] for i in parsed['inputs']]
        _check(len(points)==len(set(points)) and set(points)=={p for p,r in roots.items() if r['receipt_id']==identifier},'receipt does not consume exact held original roots')
        _check(all(rows[p]['onchain_spent_height']==receipt['block_height'] for p in points),'native root spend height differs')
        _check(all(receipt['block_height']>=rows[p]['expiry'] for p in points)
            and all(receipt['block_height']>=claim['expiry_height'] for claim in claims if claim['chain_anchor'] in points),
            'direct expiry recovery precedes original root or signed claim expiry')
        _check(all(out['script']==script for out in parsed['outputs']),'recovery receipt pays an undeclared destination')
        gross=sum(roots[p]['amount_sat'] for p in points);net=sum(out['amount_sat'] for out in parsed['outputs'])
        _check(0<net<gross,'original recovery fee/conservation differs')
        recovered+=net;miner+=gross-net
        receipt_sources.append({'txid':identifier,'raw_sha256':_hash(_hex(actual['hex'])),'signed_weight_wu':parsed['weight'],
            'gross_sat':gross,'received_sat':net,'mining_fee_sat':gross-net,'height':receipt['block_height'],'block_hash':receipt['block_hash']})
    _check(rounds_inventory['wallet']=='rounds' and rounds_inventory['network']=='signet' and rounds_inventory['tip_height']==identity['tip_height']
        and rounds_inventory['tip_hash']==identity['tip_hash'] and not rounds_inventory['pending_transactions']
        and not rounds_inventory['reserved_outpoints'] and not rounds_inventory['unavailable_parent_txids'],'current owning rounds inventory unresolved')
    cash=0;owned=set()
    for utxo in rounds_inventory['utxos']:
        point=utxo['outpoint'];_point(point);_check(point not in owned,'duplicate recovery wallet asset');owned.add(point)
        live=core['utxos'].get(point)
        value=None if live is None else Decimal(str(live['value']))*100000000
        _check(live is not None and value==value.to_integral_value() and int(value)==utxo['value_sat']
            and live['scriptPubKey']['hex']==utxo['script_pubkey'],'independent owning cash outpoint differs')
        _check(type(live.get('coinbase')) is bool and live['coinbase']==utxo['coinbase']
            and live['bestblock']==identity['tip_hash'] and 1<=live['confirmations']<=identity['tip_height']+1
            and (not live['coinbase'] or live['confirmations']>=100),'independent current coinbase maturity or source tip differs')
        _check(utxo['confirmed_fee_eligible'] is True and utxo['mature'] is True and utxo['trusted'] is True and utxo['reserved'] is False
            and live['confirmations']>=rounds_inventory['min_trusted_confirmations']>=1 and utxo['confirmations']>=rounds_inventory['min_trusted_confirmations'],'cash is not confirmed unreserved owning liquidity')
        cash+=_int(utxo['value_sat'])
    held=sum(_int(row['held_sat']) for row in holds.values());floor=_int(identity['fee_headroom_sat'])
    _check(cash>=held+floor,'confirmed owning cash does not preserve full R plus distinct F')
    principal=sum(item['amount_sat'] for item in liabilities)
    return {'scope':'direct-root confirmed recovery; customer liabilities retained', 'customer_principal_sat':principal,
        'liabilities':liabilities,'source_holds_sat':held,'recovery_received_sat':recovered,'historical_sweep_miner_sat':miner,
        'required_rounds_cash_sat':held+floor,'confirmed_rounds_cash_sat':cash,'rounds_cash_above_R_and_F_sat':cash-held-floor,
        'fee_headroom_sat':floor,'receipts':receipt_sources,'source_hashes':dict(source_hashes),
        'customer_payment_credit_sat':0,'principal_recycled_sat':0}

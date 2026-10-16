"""Confirmed ordinary pool subset; source exports never grant readiness.

Reuse the pinned ordinary-source classifier, actual pure Full verifier and
existing native fee/cost joins. Customer allocation, spent/pruned pools and all
round/conditional transitions remain explicit unresolved obligations.
"""
import hashlib
from pathlib import Path

from . import normal_ordinary_classifier as classifier
from .bundle_audit import decode_transaction
from .model import SIGNET_GENESIS, btc_to_sat, canonical, integer

CLASSIFIER_SHA256='10aa64b21d3725fc9f503d54f2ddd971fa57127cd1eaa6b72ebc9a07372d030e'
POOL_AUX={'owning_pool_inventory':'native-pool.private.json',
          'ordinary_source_classification':'ordinary-source-classification.private.json'}
POOL_TABLES={'vtxo_pool','ephemeral_tweak','nursery_tx','sweep'}
ROUND_TABLES={'round','round_participation','round_part_input','round_part_output'}


def source_configuration(value):
    if (not isinstance(value,dict) or set(value)!={'classifier_sha256','pool_pre_expiry_blocks','maximum_exit_depth','minimum_confirmations'}
            or value['classifier_sha256']!=CLASSIFIER_SHA256
            or hashlib.sha256(Path(classifier.__file__).read_bytes()).hexdigest()!=CLASSIFIER_SHA256):
        raise ValueError('exact installed ordinary classifier configuration required')
    integer(value['pool_pre_expiry_blocks'],'pool expiry margin',1)
    integer(value['maximum_exit_depth'],'pool exit-depth cap',1)
    if value['maximum_exit_depth']>12 or integer(value['minimum_confirmations'],'pool confirmations',3)<3:
        raise ValueError('ordinary pool security margin differs')
    return value


def source_originals(package, configuration):
    """Select manifest-bound originals; a classification is not a proof verdict."""
    from .two_step_normal import digest, strict_json
    source_configuration(configuration)
    manifest=package['manifest'];mapping=manifest.get('auxiliary_originals',{})
    if (any(mapping.get(key)!=name for key,name in POOL_AUX.items())
            or set(mapping)-set(POOL_AUX)-{'target_cln','target_cln_runtime'}
            or manifest.get('classification_program_sha256')!=configuration['classifier_sha256']):
        raise ValueError('admitted ordinary source originals unavailable')
    selected={key:package['auxiliary_originals'][name]for key,name in POOL_AUX.items()}
    for key,raw in selected.items():
        entry=manifest['files'][POOL_AUX[key]]
        maximum=2*1024*1024 if key=='owning_pool_inventory'else 4*1024*1024
        if not isinstance(raw,bytes)or len(raw)>maximum or entry!={'sha256':digest(raw),'size_bytes':len(raw)}:
            raise ValueError('ordinary source original hash/size differs')
        strict_json(raw)
    return selected


def authenticate_pool(tables, raw_sql, originals, raw_core, chain, tool, *,
                      configuration, server_pubkey, height, tip_hash, customer_claims,
                      lineage_context=None):
    """Execute Full/depth proofs and check one unspent, unallocated pool cut.

    Returns no complete flag. Every native pool row must remain selectable in
    this narrow subset; missing, spent, pruned or in-flight rows hold rather
    than disappearing from a global asset/liability inventory.
    """
    from .two_step_normal import digest, strict_json, run_proof
    source_configuration(configuration)
    if (set(originals)!=set(POOL_AUX) or any(not isinstance(raw,bytes)or len(raw)>4*1024*1024 for raw in originals.values())):
        raise ValueError('bounded named ordinary pool originals required')
    if any(tables[name]for name in ROUND_TABLES):
        from .normal_lineage_join import require_round_evidence
        require_round_evidence(lineage_context, tables, digest(raw_sql))
    core=strict_json(raw_core,decimals=True);pool=strict_json(originals['owning_pool_inventory'])
    if (core.get('genesis')!=SIGNET_GENESIS or any(frame.get('chain')!='signet'
            or frame.get('initialblockdownload')is not False
            or (frame.get('blocks'),frame.get('bestblockhash'))!=(height,tip_hash)
            for frame in (core['before'],core['after']))):
        raise ValueError('ordinary captured Core identity/bracket differs')
    framed=strict_json(raw_sql.decode().splitlines()[-2])
    if {name:table['rows']for name,table in framed['tables'].items()}!=tables:
        raise ValueError('ordinary consumer original SQL differs')
    plan=classifier.plan_ordinary(framed['tables'],decode_transaction,server_pubkey,
        strict_json(bytes.fromhex(tables['fee_allowance_policy'][0]['policy_bytes_hex']))['epoch_id'])
    observed=classifier.finish_ordinary(plan,pool,core['transactions'],network='signet',genesis=SIGNET_GENESIS,
        server_pubkey=server_pubkey,height=height,tip_hash=tip_hash,sql_sha256=digest(raw_sql),
        pool_sha256=digest(originals['owning_pool_inventory']))
    if strict_json(originals['ordinary_source_classification'])!=observed:
        raise ValueError('ordinary classification differs from recomputed originals')
    candidates={row['id']:row for row in pool['candidates']}
    if len(candidates)!=len(pool['candidates'])or set(candidates)!=set(plan['pools']):
        raise ValueError('excluded or duplicate durable pool rows remain unresolved')
    def stable():
        info=chain.identity()
        if (chain.call('getblockhash',0)!=SIGNET_GENESIS or info['chain']!='signet'
                or info['initialblockdownload']is not False or (info['blocks'],info['bestblockhash'])!=(height,tip_hash)):
            raise ValueError('ordinary pool independent chain changed')
    stable();claims={row['coin_id']for row in customer_claims};customer_roots={row['chain_anchor']for row in customer_claims}
    roots={};proofs=[];funding={row['txid']:row for row in tables['virtual_transaction']if row['is_funding']is True}
    if len(funding)!=sum(row['is_funding']is True for row in tables['virtual_transaction']):
        raise ValueError('pool original funding identity duplicated')
    ancestry=0
    for identifier,row in candidates.items():
        sql=plan['coins'][identifier];point=sql['anchor_point'];txid,index=point.rsplit(':',1);index=int(index)
        if (identifier in claims or point in customer_roots or sql['policy_type']!='pubkey'
                or row['pool_spent']is not False or row['spend_state']!='pool' or row['has_spend_reference']is not False
                or row['runtime_member']is not True or row['in_flux']is not False
                or row['key_present']is not True or row['key_matches']is not True
                or row['expiry_height']<=height+configuration['pool_pre_expiry_blocks']
                or row['exit_depth']>min(pool['max_exit_depth'],configuration['maximum_exit_depth'])
                or pool['pool_pre_expiry_blocks']!=configuration['pool_pre_expiry_blocks']):
            raise ValueError('pool eligibility, ownership or customer allocation unresolved')
        ancestry+=len(row['signed_vtxo'])//2
        if ancestry>524288 or txid not in funding:
            raise ValueError('pool signed ancestry or original funding unavailable')
        actual=chain.tx(txid);decoded=decode_transaction(actual['hex']);confirmations=actual.get('confirmations',0)
        captured=core['transactions'].get(txid)
        if (decoded['txid']!=txid or actual['hex']!=funding[txid]['signed_transaction_hex']
                or not isinstance(captured,dict) or any(captured.get(key)!=actual.get(key)for key in ('hex','confirmations','blockhash'))
                or type(confirmations)is not int or confirmations<configuration['minimum_confirmations']
                or actual['blockhash']!=chain.call('getblockhash',height-confirmations+1) or index>=len(decoded['outputs'])):
            raise ValueError('pool original funding lacks active confirmed Core body')
        request={'signed_vtxo':row['signed_vtxo'],'anchor_raw':actual['hex'],'server_pubkey':server_pubkey}
        encoded,raw=run_proof(tool,request);proof=strict_json(raw)
        expected={'id':identifier,'amount_sat':row['amount_sat'],'expiry_height':row['expiry_height'],
            'server_pubkey':server_pubkey,'chain_anchor':point,'exit_depth':row['exit_depth'],
            'candidate_user_pubkey':sql['policy_hex'][2:],'exit_delta':12,'policy':'pubkey'}
        if (strict_json(encoded)!=request or any(proof.get(k)!=v for k,v in expected.items())
                or proof.get('signed_path_valid')is not True or proof.get('chain_contract_verified')is not True
                or proof.get('tree_padding')is not False):
            raise ValueError('pool genuine Full/depth contract differs')
        coin=chain.call('gettxout',txid,index,True);out=decoded['outputs'][index]
        if (coin is None or coin.get('bestblock')!=tip_hash or coin.get('confirmations',0)<configuration['minimum_confirmations']
                or coin.get('coinbase')is True and coin['confirmations']<100
                or btc_to_sat(coin['value'])!=out['amount_sat'] or coin['scriptPubKey']['hex']!=out['script']
                or proof.get('anchor_amount_sat')!=out['amount_sat'] or proof.get('anchor_script')!=out['script']):
            raise ValueError('pool current unreserved raw Core backing differs')
        root=roots.setdefault(point,{'amount_sat':out['amount_sat'],'script':out['script'],'claim_sat':0,'funding_txid':txid})
        root['claim_sat']+=row['amount_sat']
        if root['claim_sat']>root['amount_sat']:raise ValueError('pool rights exceed unique physical backing')
        proofs.append({'id':identifier,'amount_sat':row['amount_sat'],'chain_anchor':point,'exit_depth':row['exit_depth'],
            'native_tool_sha256':tool['sha256'],'native_request_sha256':digest(encoded),'native_response_sha256':digest(raw)})
    stable()
    return {'coin_ids':sorted(candidates),'roots':roots,'proofs':proofs,
        'native_sql_sha256':digest(raw_sql),'pool_original_sha256':digest(originals['owning_pool_inventory']),
        'classification_sha256':digest(originals['ordinary_source_classification']),
        'customer_payment_credit_sat':0,'additional_customer_liabilities':[],
        'scope':'Confirmed unspent unallocated ordinary pool subset; no reservation or readiness verdict'}


def join_pool_finance(checked,tables,fee,costs,zero_fee_carriers,assets,*,rounds_member_id,backing_member_id):
    """Require existing actual fee and physical-asset joins; never add assets."""
    from .two_step_normal import strict_json, digest
    permits={};reserved=set()
    for row in tables['fee_allowance_candidate']:
        candidate=strict_json(bytes.fromhex(row['candidate_bytes_hex']))
        reserved.update(item['outpoint']for item in decode_transaction(bytes(candidate['raw']).hex())['inputs'])
        if candidate['path']!='Pool':continue
        raw=bytes(candidate['raw']);txid=decode_transaction(raw.hex())['txid']
        if (row['id']not in fee['candidate_ids']or row['urgent']is not False
                or candidate['epoch_id']!=row['epoch_id']or row['epoch_id']!=fee['epoch_id']):
            raise ValueError('pool exact native fee permit differs')
        if txid in permits:raise ValueError('pool permit variant requires explicit resolution')
        permits[txid]=(row,raw)
    for point,root in checked['roots'].items():
        if point in reserved:raise ValueError('pool physical backing has a durable signed spend reservation')
        txid=root['funding_txid'];permit=permits.get(txid);asset=assets['assets'].get(point)
        if (permit is None or asset is None or asset['member']!=backing_member_id
                or asset['amount_msat']!=root['amount_sat']*1000):
            raise ValueError('pool carrier or unique declared backing asset missing')
        row,raw=permit;native=next(v for v in tables['virtual_transaction']if v['txid']==txid and v['is_funding']is True)
        if raw.hex()!=native['signed_transaction_hex']:raise ValueError('pool funding and signed permit bytes differ')
        if row['fee_sat']==0:
            zero=zero_fee_carriers.get(txid)
            if zero is None or zero['fee_sat']!=0 or zero['raw_sha256']!=digest(raw)or txid in costs:
                raise ValueError('pool zero-fee body not independently authenticated')
        else:
            cost=costs.get(txid)
            if (cost is None or cost['source']!=rounds_member_id or cost['destination']!='miners'
                    or cost['budget']!='ordinary'or cost['amount_msat']!=row['fee_sat']*1000):
                raise ValueError('pool actual miner payer/cost unresolved')
    return {**checked,'funding_carrier_ids':sorted({root['funding_txid']for root in checked['roots'].values()})}

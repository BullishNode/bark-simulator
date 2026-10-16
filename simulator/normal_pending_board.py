"""Resolve retained unsigned Board reservations without inventing paid rights.

The caller must first authenticate every current Full/per-key claim and its
fresh or recovered backing. This module additionally runs the separately
qualified pending/registered Board proof and joins original controller intent.
No wallet, financial action, Store write or readiness verdict is performed.
"""
import json
import re
from .bundle_audit import decode_transaction
from .final_campaign import _source_event
from .model import SIGNET_GENESIS, canonical, integer


def prove_registered_board(item, registered, funding, tool, server_pubkey):
    """Execute the exact qualified unsigned-to-signed relation; no cached verdict."""
    from .two_step_normal import run_proof, strict_json
    if tool is None:
        raise ValueError('pending Board obligation requires qualified native resolver')
    root=item['id'];identifier=item['vtxo_id']
    request={'pending_vtxo':item['signed_vtxo_hex'], 'registered_vtxo':registered['signed_vtxo_hex'],
        'anchor_raw':funding['signed_transaction_hex'],'server_pubkey':server_pubkey}
    encoded,raw=run_proof(tool,request);proof=strict_json(raw)
    if strict_json(encoded)!=request:
        raise ValueError('pending Board native original request differs')
    expected={'schema_version':2,'id':identifier,'chain_anchor':root,'server_pubkey':server_pubkey,
        'amount_sat':registered['amount'],'expiry_height':item['expiry'],'exit_delta':12}
    flags={'pending_unsigned_structure_verified':True,'registered_signed_board_verified':True,
        'same_unsigned_transaction_path':True,'pending_signature_verified':False,
        'current_liability_or_payment_verified':False}
    if (any(proof.get(key)!=value for key,value in expected.items())
            or any(proof.get(key)is not value for key,value in flags.items())
            or type(proof.get('exit_depth'))is not int or proof['exit_depth']<1
            or not isinstance(proof.get('anchor_spender_txid'),str)
            or re.fullmatch('[0-9a-f]{64}',proof['anchor_spender_txid'])is None):
        raise ValueError('pending unsigned/registered signed native proof differs')
    return encoded,raw,proof,request,flags


def verify_pending_boards(store, tables, authenticated, chain, tool, *,
                          server_pubkey, height, tip_hash, fresh_backing, recovered):
    from .two_step_normal import digest
    from .unknown_outcomes import _intent, _coins
    from .financial_transition import _superseded_ark_input
    from .campaign import _receipt_origin
    from .fees import board_fee, _proposal
    pending=tables['pending_board']
    if not isinstance(pending,list) or len(pending)>1000:
        raise ValueError('bounded complete pending Board source required')
    if pending and tool is None:
        raise ValueError('pending Board obligation requires qualified native resolver')
    rows={row['vtxo_id']:row for row in tables['vtxo']}
    if len(rows)!=len(tables['vtxo']):raise ValueError('duplicate registered Board identity')
    virtual={row['txid']:row for row in tables['virtual_transaction']}
    if len(virtual)!=len(tables['virtual_transaction']):raise ValueError('duplicate native funding transaction')
    claims={row['coin_id']:row for row in authenticated}
    if len(claims)!=len(authenticated):raise ValueError('current authenticated claim duplicated')
    start=chain.identity()
    if (chain.call('getblockhash',0)!=SIGNET_GENESIS or start['chain']!='signet'
            or start['initialblockdownload']is not False
            or (start['blocks'],start['bestblockhash'])!=(height,tip_hash)):
        raise ValueError('pending Board independent current chain differs')
    resolved=[];roots=set();identifiers=set();covered_claims=set()
    for item in pending:
        root=item['id'];identifier=item['vtxo_id']
        if root in roots or identifier in identifiers:
            raise ValueError('duplicate pending Board physical root or right')
        roots.add(root);identifiers.add(identifier)
        registered=rows.get(identifier);root_row=rows.get(root)
        if (registered is None or root_row is None or registered['anchor_point']!=root
                or registered['policy_type']!='pubkey' or registered['server_pubkey']!=server_pubkey
                or registered['expiry']!=item['expiry'] or registered['exit_delta']!=12 or root_row['expiry']!=item['expiry']
                or root_row['policy_type']!='expiry'
                or root_row['anchor_point']!=root or root_row['server_pubkey']!=server_pubkey
                or any(registered.get(key)is not None for key in ('onchain_spent_txid','offboarded_in','spent_in_round'))):
            raise ValueError('unregistered/unattributed pending Board remains an obligation')
        txid,index=root.rsplit(':',1);index=integer(int(index),'Board anchor index')
        funding=virtual.get(txid)
        if funding is None or funding['is_funding']is not True:
            raise ValueError('pending Board original funding source missing')
        encoded,raw,proof,request,flags=prove_registered_board(item,registered,funding,tool,server_pubkey)
        actual=chain.tx(txid);decoded=decode_transaction(actual['hex'])
        if (actual.get('confirmations',0)<3
                or actual.get('blockhash')!=chain.call('getblockhash',height-actual['confirmations']+1)
                or actual['hex']!=request['anchor_raw'] or decoded['txid']!=txid or index>=len(decoded['outputs'])
                or decoded['outputs'][index]['amount_sat']!=root_row['amount']):
            raise ValueError('pending Board original anchor is not exact confirmed Core backing')
        matches=[]
        for action in store.db.execute("SELECT * FROM action WHERE operation='board' AND state='completed' ORDER BY id"):
            result=json.loads(action['result'])
            if result.get('data',{}).get('board',{}).get('vtxos')==[identifier]:matches.append(action)
        if len(matches)!=1:raise ValueError('pending Board lacks one original completed intent')
        action=matches[0];_intent(store,action)
        terminal=store.db.execute("SELECT sequence FROM event WHERE kind='action_result' AND json_extract(payload,'$.action_id')=? AND json_extract(payload,'$.state')='completed'",(action['id'],)).fetchall()
        if len(terminal)!=1:raise ValueError('pending Board original terminal missing/ambiguous')
        _,original=_source_event(store,terminal[0][0])
        if canonical(original['result'])!=action['result']:
            raise ValueError('pending Board original terminal result changed')
        coin,owned=_coins(store,[identifier],action['actor_id'])[0]
        if (owned['chain_anchor']!=root or coin['pubkey']!=proof.get('user_pubkey')
                or coin['amount_sat']!=registered['amount'] or owned['expiry_height']!=item['expiry']):
            raise ValueError('pending Board differs from originally authenticated client right')
        proposal=_proposal(store,action,'board_proposal')
        tx=chain.transaction(txid);fee=board_fee(store,action,tx)
        if (proposal['funding_txid']!=txid or fee['coin_id']!=identifier
                or fee['funded_amount_sat']!=root_row['amount']
                or fee['mining_fee_sat']!=proposal['planned_mining_fee_sat']
                or fee['service_charge_sat']!=proposal['estimated_service_fee_sat']):
            raise ValueError('pending Board original funded/miner/service intent differs')
        related={name:claim for name,claim in claims.items()if claim['chain_anchor']==root}
        if (not related or sum(row['amount_sat']for row in related.values())!=registered['amount']
                or covered_claims.intersection(related)):
            raise ValueError('pending Board current liability lineage incomplete/duplicated')
        if registered.get('oor_spent_txid')is None:
            if registered['spend_state']!='spendable' or set(related)!={identifier}:
                raise ValueError('registered pending Board has unknown current spend state')
            lineage='current authenticated registered Board claim'
        else:
            if registered['spend_state']!='spent' or not _superseded_ark_input(store,coin):
                raise ValueError('pending Board spent state lacks positive original Ark supersession')
            for name in related:
                saved=store.db.execute('SELECT proof FROM owned_coin WHERE id=?',(name,)).fetchone()
                origin=None if saved is None else _receipt_origin(json.loads(saved['proof']),[identifier])
                if origin is None or origin['branch_txid']!=registered['oor_spent_txid']:
                    raise ValueError('current pending Board descendant lacks exact signed Ark lineage')
            lineage='authenticated original Ark supersession and signed descendants'
        if root_row.get('onchain_spent_txid')is None:
            coin=chain.call('gettxout',txid,index,True)
            if (root not in fresh_backing or coin is None or coin['bestblock']!=tip_hash
                    or fresh_backing[root]['claim_sat']!=sum(row['amount_sat']for row in related.values())):
                raise ValueError('pending Board fresh physical backing unresolved')
            backing='independently verified current unspent Board root'
        else:
            links=[]if recovered is None else [row for row in recovered['liabilities']if row['root_outpoint']==root]
            if ({row['coin_id']:row['amount_sat']for row in links}!={name:row['amount_sat']for name,row in related.items()}
                    or len(links)!=len(related) or any(row['receipt_id']!=root_row['onchain_spent_txid']for row in links)
                    or chain.call('gettxout',txid,index,True)is not None):
                raise ValueError('pending Board spent root lacks exact retained recovered backing')
            backing='authenticated recovered source hold; customer rights remain unpaid'
        covered_claims.update(related)
        resolved.append({'root_outpoint':root,'registered_coin_id':identifier,'original_board_action':action['id'],
            'amount_sat':registered['amount'],'current_claim_ids':sorted(related),'lineage':lineage,'backing':backing,
            'native_tool_sha256':tool['sha256'],'native_request_sha256':digest(encoded),'native_response_sha256':digest(raw),
            **flags,'customer_payment_credit_sat':0})
    end=chain.identity()
    if (chain.call('getblockhash',0)!=SIGNET_GENESIS or end['chain']!='signet'
            or end['initialblockdownload']is not False or (end['blocks'],end['bestblockhash'])!=(height,tip_hash)):
        raise ValueError('pending Board chain changed during resolution')
    store.verify_event_chain()
    return {'resolved_registered_boards':resolved,'additional_liabilities':[],
        'customer_payment_credit_sat':0,'scope':'Matched retained unsigned registrations only; current rights already counted exactly once. Unregistered, unmatched or paid-settlement-only cases hold.'}

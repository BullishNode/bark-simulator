"""B ordinary miner sources and immutable-opening deltas; no financial writer.

Exact direct groups are derived by the same-capture signed native graph reducer,
never supplied by a target complete flag. New native funding/urgent purposes and
new external flow provenance remain unavailable until their genuine joins exist.
"""
from . import b_native_normal_verifier as native
from .bundle_audit import decode_transaction
from .confirmed_scan import _tip
from .final_campaign import _source_event
from .model import integer
from .ownership import EvidenceGap
from .preserved_treasury_upgrade import recorded
from .treasury import _members


def _need(value, field):
    if not value: raise EvidenceGap('B ordinary money: '+field)


def current_ordinary_miner_costs(store,chain,*,boundary,scripts,groups,tip,
                                 bank_member_id,backing_member_id):
    """Check EVERY actual cost and every positive-fee confirmed direct winner.

    groups are the internally derived current_ordinary_liabilities result from
    the SAME admitted capture, with full original signed group/Core validation.
    This function additionally rejoins each actual body/prevout/fee/owner. No
    unconfirmed transaction, routing fee, internal service charge or failed
    reservation becomes a confirmed miner cost here.
    """
    _tip(chain,tip);members=_members(boundary)
    _need(bank_member_id in members and members[bank_member_id]['kind']=='wallet'
        and backing_member_id in members and members[backing_member_id]['kind']=='ark_backing'
        and members[backing_member_id]['role']=='operator','declared bank/native backing members absent')
    costs=native.original_costs(store,chain)
    _need(len(costs)<=2000 and len(groups)<=2000,'monetary/group source row bound')
    winners={g['transaction']['txid']:g for g in groups}
    _need(len(winners)==len(groups),'duplicate current direct winner')
    by_txid={row['txid']:row for row in costs}
    for txid,group in winners.items():
        fee=integer(group['transaction']['fee_sat'],'current direct miner fee')
        _need(fee==group['result']['accounting']['mining_fee_sat'], 'direct accounting/actual fee differs '+txid)
        _need((fee==0 and txid not in by_txid) or (fee>0 and txid in by_txid),
              'confirmed direct winner lacks exact original cost event '+txid)
    payers={};classes={};transactions={};spent_inputs=set()
    for cost in costs:
        sequence,txid=cost['sequence'],cost['txid']
        _need(cost['budget']=='ordinary','urgent cost requires private publication/input proof '+str(sequence))
        tx,raw=chain.transaction(txid),chain.tx(txid)
        body=decode_transaction(raw['hex'],public_body=True)
        confirmations=integer(tx.get('confirmations'),'current actual cost confirmations',1)
        height=tip[0]-confirmations+1
        actual_fee=integer(tx['fee_sat'],'actual miner fee',1)
        recomputed=sum(integer(v['amount_sat'],'actual input amount')for v in tx['inputs'])-sum(v['amount_sat']for v in body['outputs'])
        _need(0<=height<=tip[0] and chain.call('getblockhash',height)==tx.get('blockhash')
            and body['txid']==txid==tx['txid'] and body['outputs']==tx['outputs']
            and [v['outpoint']for v in body['inputs']]==[v['outpoint']for v in tx['inputs']]
            and raw.get('weight')==body['weight'] and raw.get('vsize')==body['vsize']
            and actual_fee==recomputed and actual_fee*1000==cost['amount_msat'], 'current canonical body/fee differs '+txid)
        points=[v['outpoint']for v in tx['inputs']]
        _need(len(set(points))==len(points) and not spent_inputs.intersection(points),
              'actual cost transactions repeat a physical input '+txid)
        spent_inputs.update(points)
        if txid in winners:
            group=winners[txid]
            _need(tx==group['transaction'] and cost['direct_payment_sequence'] is not None,
                  'ordinary direct cost lacks exact checked source '+txid)
            checked,source=_source_event(store,cost['direct_payment_sequence'])
            _need(checked['kind']=='direct_payment_checked' and checked['sequence']<sequence
                and all(source.get(key)==group['result'].get(key)
                    for key in ('txid','freeze_set','accounting','physical_inputs')),
                'direct cost original payment provenance differs '+txid)
            authorities=[native.direct._proof(store,allocation['id'])
                         for allocation,_ in group['result']['owners']]
            _need(authorities and all(p.get('server_pubkey')==members[backing_member_id]['identity']
                for p in authorities), 'direct economic backing identity differs '+txid)
            if group['fee_inputs']:
                payer=native.physical_cost_payers([cost],chain,scripts,[group])[sequence]
            else:
                # Exact claim_accounts already conserved customer payouts,
                # operator P2A/flat-fee/forfeit value and the whole backing input.
                # With no supplemental input the economic fee owner is the
                # declared operator backing, not an invented watchman UTXO.
                _need(set(group['result']['physical_inputs'])=={v['outpoint']for v in tx['inputs']},
                      'self-funded direct physical inputs differ '+txid)
                payer=backing_member_id
            _need(payer in members and members[payer]['role']=='operator',
                  'direct miner payer is not declared operator '+txid)
            classes[sequence]='native_ordinary_direct'
        else:
            _need(cost['direct_payment_sequence'] is None, 'direct cost missing current whole-group proof '+txid)
            payer=native.physical_cost_payers([cost],chain,scripts,[])[sequence]
            member=members.get(payer)
            _need(member is not None and member['kind']=='wallet'
                and (payer==bank_member_id or member['role']=='customer'),
                'unproved native operator funding/purpose '+txid)
            classes[sequence]='external_ordinary'
        payers[sequence]=payer;transactions[txid]=tx
    _tip(chain,tip)
    return {'costs':costs,'cost_payers':payers,'cost_classes':classes,
        'transactions':transactions,
        'zero_fee_direct_txids':sorted(txid for txid,g in winners.items()if g['transaction']['fee_sat']==0)}


def opening_money_deltas(store,projection):
    """Do not replay an immutable preserved opening as new income or new fees.

    Every existing strict five-field flow is enumerated. A new unsupported flow
    holds with its sequence; it is never replaced by []. New independently
    verified confirmed costs become exact conservation edges once each. This
    does not admit/append a new funding flow or alter the preserved declaration.
    """
    opening=recorded(store)
    _need(opening is not None,'strict preserved opening not recorded')
    references={r['sequence']:r['hash']for r in opening['sources']}
    _need(len(references)==len(opening['sources']),'duplicate preserved source reference')
    old_costs={r['sequence']:r for r in opening['costs']}
    _need(len(old_costs)==len(opening['costs']),'duplicate preserved cost reference')
    costs={r['sequence']:r for r in projection['costs']}
    _need(len(costs)==len(projection['costs']) and set(old_costs)<=set(costs),
          'preserved original cost disappeared')
    expected_costs=[r[0]for r in store.db.execute(
        "SELECT sequence FROM event WHERE kind='financial_cost_verified' ORDER BY sequence")]
    _need(sorted(costs)==expected_costs and set(projection['cost_payers'])==set(costs)
        and set(projection['cost_classes'])==set(costs), 'exhaustive actual cost coverage differs')
    members=_members(opening['boundary'])
    _need('outside-bitcoin-miners' not in members,'outside miner identity collides with member')
    flow_sequences=[];flow_ids=set()
    for row in store.db.execute("SELECT sequence FROM event WHERE kind='treasury_flow_verified' ORDER BY sequence"):
        event,value=_source_event(store,row[0]);sequence=event['sequence']
        _need(set(value)=={'id','kind','source','destination','amount_msat'},
              'strict five-field flow shape differs '+str(sequence))
        integer(value['amount_msat'],'actual flow amount',1)
        _need(value['id'] not in flow_ids,'duplicate original flow id '+str(sequence));flow_ids.add(value['id'])
        _need(references.get(sequence)==event['hash'],
              'new flow needs genuine B provenance join '+str(sequence))
        flow_sequences.append(sequence)
    expected_old_flows=[]
    for sequence,sha in references.items():
        event,_=_source_event(store,sequence)
        _need(event['hash']==sha,'preserved original source hash differs '+str(sequence))
        if event['kind']=='treasury_flow_verified':expected_old_flows.append(sequence)
    _need(sorted(expected_old_flows)==flow_sequences,'preserved original flow disappeared')
    delta=[]
    for sequence,cost in sorted(costs.items()):
        event,value=_source_event(store,sequence)
        _need(event['kind']=='financial_cost_verified' and event['hash']==cost['event_hash'],
              'original actual cost source differs '+str(sequence))
        _need(projection['cost_classes'][sequence] in {'native_ordinary_direct','external_ordinary'},
              'unclassified actual cost domain '+str(sequence))
        payer=projection['cost_payers'][sequence]
        _need(payer in members,'actual cost payer outside preserved boundary '+str(sequence))
        if sequence in old_costs:
            old=old_costs[sequence]
            _need((old['hash'],old['budget'],old['amount_msat'],old['payer'])==
                (event['hash'],cost['budget'],cost['amount_msat'],payer),
                'preserved original cost changed '+str(sequence))
        else:
            _need(value.get('financial_pins')==opening['boundary']['pins'],
                  'new actual cost financial epoch differs '+str(sequence))
            identity='miner:'+cost['txid']
            _need(identity not in flow_ids,'same monetary identity is a flow and cost')
            delta.append({'id':identity,'kind':'miner_cost','source':payer,
                'destination':'outside-bitcoin-miners','amount_msat':cost['amount_msat']})
    return {'flow_sequences':flow_sequences,'cost_sequences':sorted(costs),
        'delta_flows':delta,'cost_payers':dict(projection['cost_payers']),
        'native_ordinary_cost_sequences':sorted(s for s,c in projection['cost_classes'].items()
                                               if c=='native_ordinary_direct'),
        'external_ordinary_cost_sequences':sorted(s for s,c in projection['cost_classes'].items()
                                                 if c=='external_ordinary')}

"""B ordinary current rights from the whole native graph and signed Store paths.

No transport, journal writer, wallet access or readiness authority. This reduces
all retained signed ordinary rights, including frozen/mempool rights. It reuses
the existing confirmed whole-group proof for actual terminal dispositions.
Conditional/round/pool/unregistered paths require separate genuine evidence.
"""
import json

from . import direct_settlements as direct
from . import public_absence as absence
from .architecture import DIRECT, profile
from .bundle_audit import decode_transaction
from .campaign import _signed_coin
from .confirmed_scan import _tip
from .financial_transition import _current_claims
from .model import SIGNET_GENESIS, canonical, integer, btc_to_sat, public_payload
from .negative_checks import record_bytes
from .ownership import EvidenceGap


def _need(value, field):
    if not value:
        raise EvidenceGap('B current ordinary liabilities: '+field)


def _whole_journal(database):
    public_payload(database)
    _need(type(database) is dict and database.get('kind') == 'closed_frontier'
        and database.get('database_tables_complete') is True
        and database.get('inventory_consistent') is True and database.get('read_only') is True,
        'whole same-snapshot native source required')
    rows = database.get('rows')
    _need(type(rows) is dict and set(rows) == absence.TABLES
        and all(type(value) is list for value in rows.values())
        and sum(map(len, rows.values())) <= 2000
        and len(canonical(database).encode()) <= 2*1024*1024, 'whole table/row/byte bounds')
    allowed = {'coins','pending_boards','links','records','nursery'} | {
        'journal_'+name for name in direct.TABLES}
    for name in sorted(set(rows)-allowed):
        _need(not rows[name], 'unsupported native table '+name)
    journal = {'kind':'direct_journal','schema_version':1,'fallback_protocol':3,
        'binding_scope':'owners_referenced_by_allocations','journal_complete':True,
        'inventory_consistent':True,'complete':False,'qualified':False,
        'rows':{name:rows['journal_'+name] for name in direct.TABLES}}
    keys = {r['owner_pubkey'] for r in journal['rows']['allocations'] if r['owner_pubkey'] is not None}
    journal['rows']['links'] = [r for r in journal['rows']['links'] if r['user_pubkey'] in keys]
    mailboxes = {r['mailbox_pk'] for r in journal['rows']['links']}
    journal['rows']['records'] = [r for r in journal['rows']['records'] if r['mailbox_pk'] in mailboxes]
    return rows, direct.frame(journal)


def _signed_graph(store, chain, rows, server_pubkey, tip):
    proofs, points, consumers, anchors, outputs = {}, {}, {}, {}, {}
    size = store.db.execute('SELECT count(*),coalesce(sum(length(proof)),0) FROM owned_coin').fetchone()
    _need(size[0] <= 2000 and size[1] <= 2*1024*1024, 'retained signed source row/byte bounds')
    records = {r['mailbox_pk']:r for r in rows['records']}
    links = {r['user_pubkey']:r for r in rows['links']}
    _need(len(records) == len(rows['records']) and len(links) == len(rows['links']),
          'duplicate native record/link')
    for owned in store.db.execute('SELECT c.id,k.actor FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey ORDER BY c.id'):
        found = _signed_coin(store, owned['id'], owned['actor'])
        _need(found is not None, 'signed owned proof absent '+owned['id'])
        coin, proof = found
        _need(proof.get('proof_encoding') == 'ark-public-authorization-v1'
            and proof.get('authorization_path_valid') is True
            and type(proof.get('conditional_steps')) is int and proof['conditional_steps'] == 0
            and proof.get('genesis') == SIGNET_GENESIS
            and proof.get('server_pubkey') == server_pubkey,
            'unsupported/mismatched signed authority '+owned['id'])
        own = store.db.execute('SELECT * FROM owner_record WHERE actor=? AND mailbox=?',
                              (owned['actor'],coin['mailbox'])).fetchone()
        link, record = links.get(proof['user_pubkey']), records.get(coin['mailbox'])
        _need(own is not None and link is not None and record is not None
            and (link['mailbox_pk'],link['child_index']) ==
                (coin['mailbox'],proof['binding']['child_index'])
            and record['spk'] == own['script']
            and record_bytes(record) == json.loads(own['proof'])['fallback_record'],
            'original signed account/record binding differs '+owned['id'])
        anchor = proof['chain_anchor']
        if anchor not in anchors:
            txid, index = anchor.split(':'); index = int(index)
            tx = chain.transaction(txid)
            _need(tx.get('txid') == txid and tx.get('confirmations',0) >= 1,
                  'current canonical original anchor absent '+anchor)
            height = tip[0]-tx['confirmations']+1
            _need(0 <= height <= tip[0] and chain.call('getblockhash',height) == tx.get('blockhash'),
                  'original anchor is not current canonical '+anchor)
            out = next((o for o in tx['outputs'] if o['vout'] == index),None)
            _need(out is not None, 'original anchor output absent '+anchor)
            anchors[anchor] = {**out, 'creation_height':height}
        path_points = {anchor:(anchors[anchor]['amount_sat'],anchors[anchor]['script'])}
        previous = anchor
        for step in proof['path']:
            # Public projection contains stripped transaction bytes, never a
            # private full HTLC serialization. Native verifier already checked
            # its signatures; replay exact public body/continuity here.
            _need(type(step.get('transaction')) is str, 'original public path body absent '+owned['id'])
            body = decode_transaction(step['transaction'],public_body=True)
            output_index = integer(step['output_index'],'signed output index')
            _need(body['txid'] == step['txid'] and step['inputs'] == [previous]
                and [v['outpoint'] for v in body['inputs']] == [previous],
                'signed path continuity/body differs '+owned['id'])
            selected = next((o for o in body['outputs'] if o['vout'] == output_index),None)
            _need(selected is not None, 'signed selected output absent '+owned['id'])
            for output in body['outputs']:
                output_point = body['txid']+':'+str(output['vout'])
                fact = (output['amount_sat'],output['script'])
                _need(output_point not in outputs or outputs[output_point] == fact,
                      'conflicting signed output '+output_point)
                outputs[output_point] = fact
            consumers.setdefault(previous,set()).add(body['txid'])
            previous = body['txid']+':'+str(output_index)
            path_points[previous] = (selected['amount_sat'],selected['script'])
        _need(previous == coin['id'] and path_points[previous][0] == coin['amount_sat']
            and set(proof['ancestor_ids']) == set(path_points),
            'signed path terminal/ancestors differ '+owned['id'])
        for point, (amount,script) in path_points.items():
            fact = (amount,script,anchor,proof['expiry_height'])
            _need(point not in points or points[point] == fact,
                  'conflicting original signed source '+point)
            points[point] = fact
        proofs[coin['id']] = (coin,proof)
    _need(proofs, 'no retained ordinary signed sources')
    _need(all(len(ids) == 1 for ids in consumers.values()), 'ambiguous signed virtual spend')
    return proofs,points,consumers,anchors,outputs


def _terminal_groups(store,chain,journal,tip,minimum_confirmations):
    transactions, bodies = {}, {}
    for row in journal['rows']['carriers']:
        txid = row['txid']
        # An unavailable replacement is not a fabricated unconfirmed result.
        try:
            tx, raw = chain.transaction(txid), chain.tx(txid)
        except Exception as error:
            raise EvidenceGap('B current ordinary liabilities: independent carrier outcome unavailable '+txid) from error
        body = decode_transaction(raw['hex'],public_body=True)
        _need(tx.get('txid') == txid == body['txid']
            and body['outputs'] == tx['outputs']
            and [v['outpoint'] for v in body['inputs']] == [v['outpoint'] for v in tx['inputs']]
            and raw.get('weight') == body['weight'] and raw.get('vsize') == body['vsize']
            and tx.get('fee_sat') == row['miner_fee_sat'], 'independent carrier body/fee differs '+txid)
        transactions[txid],bodies[txid] = tx,body
    groups = []
    for freeze in sorted({r['freeze_set'] for r in journal['rows']['allocations']}):
        ids = {r['id'] for r in journal['rows']['allocations'] if r['freeze_set'] == freeze}
        versions = {r['txid'] for r in journal['rows']['mappings'] if r['allocation_id'] in ids}
        if not any(transactions[txid].get('confirmations',0) > 0 for txid in versions):
            continue  # frozen/mempool allocations still owe full original gross
        result = direct.check_group(store,journal,freeze,transactions)
        tx = transactions[result['txid']]
        _need(tx['confirmations'] >= minimum_confirmations, 'winner below required confirmation depth')
        height = tip[0]-tx['confirmations']+1
        carrier = next(r for r in journal['rows']['carriers'] if r['txid'] == tx['txid'])
        _need(0 <= height <= tip[0] and carrier['confirmed_height'] == height
            and chain.call('getblockhash',height) == tx['blockhash'], 'winner canonical height differs')
        groups.append({'result':result,'transaction':tx,'height':height,
                       'versions':{txid:transactions[txid] for txid in result['carrier_versions']},
                       'fee_inputs':carrier['fee_inputs'],'signed_weight_wu':bodies[tx['txid']]['weight']})
    return groups


def current_ordinary_liabilities(store,chain,database,*,server_pubkey,borrower,tip,
                                 minimum_confirmations,actor_member_ids):
    """Check the whole ordinary graph and derive every outstanding signed right.

    New ordinary roots/children are admitted from the SAME retained native proof
    contract, not a fixed original leaf list. Every graph row must be covered by
    those paths. Missing new source proofs, conditional/round/unregistered state,
    unknown Core outcomes or unmatched physical retirement refuse the reducer.
    No recorded-state mutation, paid-row filter or caller completion bit.
    """
    _need(profile(store) == DIRECT, 'matching direct_xpub profile required')
    integer(minimum_confirmations,'confirmation depth',1)
    _need(type(borrower) is str and borrower, 'declared backing borrower absent')
    _tip(chain,tip)
    rows,journal = _whole_journal(database)
    proofs,points,consumers,anchors,outputs = _signed_graph(store,chain,rows,server_pubkey,tip)
    coins = {r['vtxo_id']:r for r in rows['coins']}
    _need(len(coins) == len(rows['coins']) and set(coins) == set(points),
          'whole native graph has missing/extra signed source')
    claims = {r['coin_id']:r for r in _current_claims(store)}
    _need(set(claims) <= set(proofs), 'current claim lacks retained signed authority')
    groups = _terminal_groups(store,chain,journal,tip,minimum_confirmations)
    retirement,terminal,used_inputs = {},{},set()
    for group in groups:
        for point in group['result']['physical_inputs']:
            _need(point not in used_inputs, 'confirmed groups reuse physical input '+point)
            used_inputs.add(point)
        for point in group['result']['retirement_ids']:
            _need(point not in retirement, 'duplicated exact retirement '+point)
            retirement[point] = (group['transaction']['txid'],group['height'])
        for allocation,owner in group['result']['owners']:
            _need(allocation['id'] not in terminal, 'duplicate terminal customer right')
            terminal[allocation['id']] = (allocation,owner,group['transaction']['txid'])
    _need(set(retirement) <= set(coins), 'retired source missing from whole graph')
    fields = {'vtxo_id','amount','expiry','spend_state','policy_type','policy','anchor_point',
              'vtxo_txid','oor_spent_txid','spent_in_round','offboarded_in','frontier_at',
              'confirmed_height','onchain_spent_height','onchain_spent_txid'}
    for point,row in coins.items():
        _need(set(row) == fields, 'unknown/missing native coin field '+point)
        integer(row['amount'],'native original amount',1)
        integer(row['expiry'],'native expiry',1)
        amount,script,anchor,expiry = points[point]
        _need((row['amount'],row['anchor_point'],row['expiry'],row['vtxo_txid']) ==
              (amount,anchor,expiry,point.split(':')[0]), 'native signed source/value/anchor differs '+point)
        if point == anchor:
            _need(row['confirmed_height'] == anchors[anchor]['creation_height'],
                  'native root canonical creation height differs '+point)
        _need(row.get('spent_in_round') is None and row.get('offboarded_in') is None,
              'unsupported nonordinary native spend '+point)
        expected_spend = next(iter(consumers[point])) if point in consumers else None
        if point in proofs:
            proof = proofs[point][1]
            _need(row['policy_type'] == 'pubkey' and row['policy'] == '00'+proof['user_pubkey'],
                  'exact ordinary recipient policy differs '+point)
        else:
            _need(row['policy_type'] in ({'expiry'} if point == anchor else {'checkpoint'}),
                  'unsupported intermediate native policy '+point)
        _need(row['oor_spent_txid'] == expected_spend
            and row['spend_state'] == ('spent' if expected_spend else 'spendable'),
              'native virtual spend lacks exact signed path '+point)
        _need((row.get('onchain_spent_txid'),row.get('onchain_spent_height')) ==
              retirement.get(point,(None,None)), 'native physical retirement is not exact checked group '+point)
        if expected_spend is None:
            _need(point in claims, 'unspent ordinary right missing from signed current claims '+point)
        else:
            _need(point not in claims, 'current claim still counts signed superseded input '+point)
    for row in rows['pending_boards']:
        _need(row['vtxo_id'] in coins and row['expiry'] == coins[row['vtxo_id']]['expiry'],
              'pending Board lacks signed current source '+row['vtxo_id'])
    versions = set(transactions_id['txid'] for transactions_id in journal['rows']['carriers'])
    _need(all(row['txid'] in versions for row in rows['nursery']),
          'unclassified nursery publication requires its own proof')
    # Before any terminal credit, require every candidate allocation's actual
    # original owner/value. Its prospective fee/disposition never reduces debt.
    for allocation in journal['rows']['allocations']:
        for field in ('gross_sat','fee_sat','payout_sat','forfeited_sat'):
            integer(allocation[field],'native allocation '+field)
        if allocation['disposition'] == 'operator':
            source = outputs.get(allocation['id'])
            group_sources = set().union(*(set(proofs[r['id']][1]['ancestor_ids'])
                for r in journal['rows']['allocations']
                if r['freeze_set'] == allocation['freeze_set'] and r['id'] in proofs))
            _need(allocation['source'] == 'transition-fee-anchor'
                and source == (allocation['gross_sat'],'51024e73')
                and allocation['owner_pubkey'] is None and allocation['spk'] is None
                and not any(allocation[field] for field in ('fee_sat','payout_sat','forfeited_sat'))
                and type(allocation['retirement_ids']) is list and allocation['retirement_ids']
                and set(allocation['retirement_ids']) <= group_sources,
                'operator allocation lacks exact signed P2A source')
            continue  # no customer debit, including frozen/unconfirmed groups
        _need(allocation['id'] in proofs and allocation['source'] in {'registered','pending-board'},
              'allocation lacks ordinary signed source '+allocation['id'])
        coin,proof = proofs[allocation['id']]
        record = next(r for r in rows['records'] if r['mailbox_pk'] == coin['mailbox'])
        _need((allocation['owner_pubkey'],allocation['gross_sat'],allocation['spk']) ==
              (proof['user_pubkey'],coin['amount_sat'],record['spk']),
              'allocation original owner/value/destination differs '+allocation['id'])
        _need(allocation['gross_sat'] == allocation['fee_sat']+allocation['payout_sat']+allocation['forfeited_sat']
            and type(allocation['retirement_ids']) is list and allocation['retirement_ids']
            and set(allocation['retirement_ids']) <= set(proof['ancestor_ids']),
              'allocation principal/retirement source differs '+allocation['id'])
    liabilities,dispositions = [],[]
    for point,claim in sorted(claims.items()):
        _need(claim['actor'] in actor_member_ids, 'current owner absent from declared customer membership '+point)
        if point in terminal:
            allocation,owner,txid = terminal[point]
            _need((owner['actor'],allocation['gross_sat']) == (claim['actor'],claim['amount_sat']),
                  'terminal original right mismatch '+point)
            dispositions.append({'coin_id':point,'actor':claim['actor'],'amount_sat':claim['amount_sat'],
                'state':'confirmed_'+allocation['disposition'],'txid':txid})
        else:
            anchor = proofs[point][1]['chain_anchor']; txid,index = anchor.split(':')
            actual = chain.call('gettxout',txid,int(index),False)
            expected = anchors[anchor]
            _need(actual is not None and actual.get('confirmations',0) >= 1
                and btc_to_sat(actual['value']) == expected['amount_sat']
                and actual['scriptPubKey']['hex'] == expected['script'],
                  'outstanding right lacks current unspent original backing '+point)
            liabilities.append({'id':'coin:'+point,'borrower':borrower,'amount_msat':claim['amount_sat']*1000})
            dispositions.append({'coin_id':point,'actor':claim['actor'],'amount_sat':claim['amount_sat'],
                                 'state':'unsettled'})
    _need(set(terminal) <= set(claims), 'terminal group has an unclassified retained current right')
    _tip(chain,tip)
    return {'liabilities':liabilities,'dispositions':dispositions,'groups':groups,
            'outstanding_liability_sat':sum(r['amount_msat'] for r in liabilities)//1000,
            'signed_graph_coin_ids':sorted(coins)}

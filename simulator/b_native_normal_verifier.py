"""Read-only direct/xpub normal-source joins. No readiness or journal writer.

The installed common capture owns transports and original-source admission.
These reducers independently check exact ordinary signed groups, confirmed Core
successors, original external costs and whole-input urgent reserve. Unsupported
native domains remain evidence gaps; frozen and mempool are never paid.
"""
from . import direct_settlements as direct
from . import public_absence as absence
from .architecture import DIRECT, profile
from .bundle_audit import decode_transaction
from .final_campaign import _source_event
from .model import InvariantError, btc_to_sat, canonical, integer
from .ownership import EvidenceGap
from .public_treasury import confirmed_frontier, check_current_outputs


def direct_snapshot(store, chain, database, baseline, leaves, scripts, tip,
                    *, minimum_confirmations):
    """Pure counterpart of the existing public-absence terminal joins.

    baseline/leaves come from the original _baseline signed-journey reducer;
    scripts come from admitted complete public-descriptor discovery. Existing
    immutable Store operator scripts must all occur in that derived coverage.
    No direct.record/commit_checked, wallet open, balance debit or SQL write.
    """
    if profile(store) != DIRECT:
        raise EvidenceGap('architecture_profile: B verifier requires direct_xpub')
    integer(minimum_confirmations, 'loaded minimum confirmations', 1)
    journal = absence._journal(database, baseline)
    operators = {script for script, owner in scripts.items()
                 if owner['member_id'] in {'rounds', 'watchman'}}
    known = {row[0] for row in store.db.execute('SELECT script FROM operator_script')}
    if not known <= operators:
        raise EvidenceGap('operator_script: retained script lacks current derived ownership')
    for previous in store.db.execute('SELECT kind,id FROM direct_journal_object'):
        key = direct.TABLES[previous['kind']]
        ids = {row[key] if key else canonical([row['txid'], row['allocation_id']])
               for row in journal['rows'][previous['kind']]}
        if previous['id'] not in ids:
            raise EvidenceGap('journal: retained generation/object missing')
    transactions = {}
    for carrier in journal['rows']['carriers']:
        txid = carrier['txid']
        try:
            tx = chain.transaction(txid)
        except Exception as error:
            raise EvidenceGap('journal.carriers.' + txid + ': Core outcome unavailable') from error
        if tx.get('txid') != txid:
            raise InvariantError('journal.carriers: independent txid differs')
        transactions[txid] = tx
        for coin in carrier['fee_inputs']:
            if scripts.get(coin['script_pubkey'], {}).get('member_id') not in {'rounds', 'watchman'}:
                raise EvidenceGap('journal.fee_inputs: independently derived operator owner missing')
    for row in journal['rows']['allocations']:
        if row['disposition'] != 'operator' and row['id'] not in leaves:
            raise EvidenceGap('journal.allocations.' + row['id'] + ': outside original signed leaves')
    groups = []
    for freeze in sorted({row['freeze_set'] for row in journal['rows']['allocations']}):
        ids = {row['id'] for row in journal['rows']['allocations'] if row['freeze_set'] == freeze}
        versions = {row['txid'] for row in journal['rows']['mappings'] if row['allocation_id'] in ids}
        if not any(transactions[txid].get('confirmations', 0) >= minimum_confirmations for txid in versions):
            raise EvidenceGap('journal.freeze_set.' + freeze + ': no sufficiently confirmed winner')
        result = direct.check_group(store, journal, freeze, transactions)
        tx = transactions[result['txid']]
        if tx.get('confirmations', 0) < minimum_confirmations:
            raise EvidenceGap('journal.winner: below loaded confirmation requirement')
        height = tip[0] - tx['confirmations'] + 1
        winner = next(row for row in journal['rows']['carriers'] if row['txid'] == result['txid'])
        if (not 0 <= height <= tip[0] or winner['confirmed_height'] != height
                or chain.call('getblockhash', height) != tx['blockhash']):
            raise EvidenceGap('journal.winner: current-chain height/block mismatch')
        raw = chain.tx(tx['txid'])
        body = decode_transaction(raw['hex'], public_body=True)
        if (body['txid'] != tx['txid'] or body['outputs'] != tx['outputs']
                or [v['outpoint'] for v in body['inputs']] != [v['outpoint'] for v in tx['inputs']]
                or raw.get('weight') != body['weight'] or raw.get('vsize') != body['vsize']):
            raise EvidenceGap('journal.winner: original signed body/weight differs from Core')
        groups.append({'result': result, 'transaction': tx, 'height': height,
                       'signed_weight_wu': body['weight']})
    absence._current_graph(database, baseline, groups)
    dispositions = {point: {**leaf, 'state': 'unsettled', 'payout_sat': 0,
                           'flat_fee_sat': 0, 'forfeited_sat': 0}
                    for point, leaf in leaves.items()}
    for group in groups:
        for allocation, owner in group['result']['owners']:
            leaf = leaves[allocation['id']]
            if (owner['actor'], allocation['gross_sat']) != (leaf['actor'], leaf['amount_sat']):
                raise InvariantError('journal.disposition: original signed owner/principal differs')
            dispositions[allocation['id']] = {**leaf,
                'state': 'confirmed_pay' if allocation['disposition'] == 'pay' else 'confirmed_forfeit',
                'payout_sat': allocation['payout_sat'], 'flat_fee_sat': allocation['fee_sat'],
                'forfeited_sat': allocation['forfeited_sat'], 'txid': group['transaction']['txid']}
    if groups and any(row['state'] == 'unsettled' for row in dispositions.values()):
        raise EvidenceGap('liabilities: confirmed backing leaves an unclassified original right')
    return {'groups': sorted(groups, key=lambda row: (row['height'], row['transaction']['txid'])),
            'liabilities': list(dispositions.values()),
            'outstanding_liability_sat': sum(row['amount_sat'] for row in dispositions.values()
                                             if row['state'] == 'unsettled')}


def original_costs(store, chain):
    """Original event identity plus actual confirmed fee; no internal service cost.

    Both retained canonical representations are accepted. Two representations
    of one physical transaction remain one duplicate error, never two debits.
    This does not book any new provisioning fee; its importer is separate.
    """
    import re
    costs = []; seen = set()
    for row in store.db.execute("SELECT sequence FROM event WHERE kind='financial_cost_verified' ORDER BY sequence"):
        event, value = _source_event(store, row[0])
        match = re.fullmatch(r'(?:bitcoin-miner|miner):([0-9a-f]{64})', value.get('monetary_id', ''))
        if match is None or value.get('kind', 'miner_cost') != 'miner_cost':
            raise EvidenceGap('costs.' + str(row[0]) + ': unsupported original external-cost identity')
        txid = match[1]
        if txid in seen:
            raise InvariantError('costs: same physical miner transaction counted twice')
        seen.add(txid); tx = chain.transaction(txid)
        if (tx.get('txid') != txid or tx.get('confirmations', 0) < 1
                or value.get('txid', txid) != txid or value.get('budget') not in {'ordinary', 'urgent'}
                or value.get('mining_fee_sat', tx['fee_sat']) != tx['fee_sat']
                or integer(value['amount_msat'], 'original miner amount', 1) !=
                   integer(tx['fee_sat'], 'actual miner fee', 1) * 1000):
            raise EvidenceGap('costs.' + str(row[0]) + ': confirmed independent miner fee differs')
        costs.append({'sequence': event['sequence'], 'event_hash': event['hash'],
                      'txid': txid, 'amount_msat': value['amount_msat'], 'budget': value['budget'],
                      'action_id': value.get('action_id'),
                      'direct_payment_sequence': value.get('direct_payment_sequence')})
    return costs


def add_original_injection(opening, transaction, *, outpoint, amount_sat, scripts):
    """Authenticate an original declared outside output even after internal spend.

    Never require that historical injection still be unspent. Its confirmed
    descendants must subsequently replace it via confirmed_frontier exactly
    once; old receipt and current change are not both closing capital.
    """
    txid, index = outpoint.rsplit(':', 1); index = int(index)
    if transaction.get('txid') != txid or transaction.get('confirmations', 0) < 1:
        raise EvidenceGap('injection: original confirmed transaction required')
    outputs = [row for row in transaction['outputs'] if row['vout'] == index]
    if len(outputs) != 1 or outputs[0]['amount_sat'] != amount_sat:
        raise InvariantError('injection: original output amount/index differs')
    owner = scripts.get(outputs[0]['script'])
    if owner is None or owner['member_id'] != 'bank':
        raise EvidenceGap('injection: original bank script is not independently derived')
    if outpoint in opening:
        raise InvariantError('injection: original outside receipt already counted')
    if any(coin['outpoint'] in opening or coin['script'] in scripts for coin in transaction['inputs']):
        raise EvidenceGap('injection: input may already belong to conserved boundary')
    result = {point: dict(coin) for point, coin in opening.items()}
    result[outpoint] = {**owner, 'amount_sat': amount_sat, 'script': outputs[0]['script']}
    return result


def current_frontier(opening, transactions, scripts, chain, *, started):
    """Replay every declared confirmed successor and recheck all current outputs."""
    frontier = confirmed_frontier(opening, transactions, scripts)
    check_current_outputs(chain, frontier, started)
    return frontier


def urgent_reserve(native, physical, selected_points, chain, *, minimum_sat):
    """Whole selected inputs are encumbered; pending change supplies no reserve."""
    integer(minimum_sat, 'actual urgent reserve')
    if (native.get('wallet') != 'watchman' or native.get('network') != 'signet'
            or native.get('pending_transactions') or native.get('pending_parents')
            or native.get('unavailable_parent_txids')):
        raise EvidenceGap('watchman_inventory: owning wallet/pending source unresolved')
    rows = native.get('utxos'); seen = set(); eligible = {}
    if not isinstance(rows, list):
        raise EvidenceGap('watchman_inventory.utxos: full native rows unavailable')
    for coin in rows:
        point = coin['outpoint']
        integer(coin['value_sat'], 'actual native amount', 1)
        for field in ('reserved', 'confirmed_fee_eligible', 'trusted', 'mature'):
            if type(coin.get(field)) is not bool:
                raise EvidenceGap('watchman_inventory.' + point + '.' + field + ': actual boolean source unavailable')
        if point in seen:
            raise InvariantError('watchman_inventory: duplicate physical coin')
        seen.add(point); observed = physical.get(point)
        if (observed is None or observed['member_id'] != 'watchman'
                or (observed['amount_sat'], observed['script']) !=
                   (coin['value_sat'], coin['script_pubkey'])):
            raise EvidenceGap('watchman_inventory.' + point + ': native/Core ownership differs')
        if (point in selected_points or point in native.get('reserved_outpoints', [])
                or coin.get('reserved') is not False):
            continue
        if not all(coin.get(key) is True for key in ('confirmed_fee_eligible', 'trusted', 'mature')):
            continue
        txid, index = point.rsplit(':', 1)
        for mempool in (False, True):
            actual = chain.call('gettxout', txid, int(index), mempool)
            if (actual is None or actual.get('confirmations', 0) < 1
                    or btc_to_sat(actual['value']) != coin['value_sat']
                    or actual.get('scriptPubKey', {}).get('hex') != coin['script_pubkey']):
                raise EvidenceGap('urgent_reserve.' + point + ': actual confirmed unspent coin differs')
        eligible[point] = coin['value_sat']
    expected = {point for point, coin in physical.items() if coin['member_id'] == 'watchman'}
    if seen != expected:
        raise EvidenceGap('watchman_inventory: native/current full cash set differs')
    if sum(eligible.values()) < minimum_sat:
        raise EvidenceGap('urgent_reserve: confirmed unselected whole-input cash below policy')
    return eligible


def require_native_budget_join(provenance):
    """Disk arithmetic is a candidate, never proof that the daemon owns its ledger.

    The root-owned process/fdinfo/retained-version producer is a separate required
    source. This reducer intentionally has no caller supplied true-flag escape.
    Its exact authenticated original ABI is not yet frozen in this source epoch.
    """
    if provenance is None or provenance.get('disk_budget') is None:
        raise EvidenceGap('native_budget.disk_budget: actual native fee epoch unavailable')
    raise EvidenceGap('native_budget.runtime_lock_and_retained_versions: authenticated producer join not installed')

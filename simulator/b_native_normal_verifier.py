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
from .model import SIGNET_GENESIS, InvariantError, btc_to_sat, canonical, integer
from .ownership import EvidenceGap
from .public_treasury import confirmed_frontier, check_current_outputs



def captured_scan(store, config, chain, current, *, sequence, pins, boundary_id,
                  members, specs, tip):
    """Replay the existing authenticated scan/trace without starting another scan.

    This is the read-only half of confirmed_scan, using its actual identity,
    coverage, raw-RPC and result validators. It never changes the scan pointer.
    Shared owner/descriptor/script limits remain owned by the common module.
    """
    from . import confirmed_scan as scan
    event, receipt = _source_event(store, sequence)
    expected_identity = scan._identity(store, config, chain, current, pins=pins,
        boundary_id=boundary_id, members=members)
    if (event['kind'] != scan.KIND or receipt['identity'] != expected_identity
            or receipt['identity_sha256'] != scan._digest(receipt['identity'])
            or (receipt['height'], receipt['tip_hash']) != tip
            or receipt['result_sha256'] != scan._digest(receipt['result'])):
        raise EvidenceGap('confirmed_scan: original identity/context/height/result differs')
    owner, required = scan._coverage(members, specs)
    retained_specs = {row['desc']: row['range'] for row in receipt['descriptor_ranges']}
    _, coverage = scan._coverage(members, retained_specs)
    if (coverage != receipt['descriptor_ranges'] or set(specs) != set(retained_specs)
            or any(retained_specs[d][1] < interval[1] for d, interval in specs.items())):
        raise EvidenceGap('confirmed_scan: original full derivation frontier is insufficient')
    raw_sha, observed = scan._raw_trace(store, receipt['raw_trace'], coverage, receipt['result'])
    if (raw_sha, observed) != (receipt['raw_response_sha256'], receipt['observed_at']):
        raise EvidenceGap('confirmed_scan: original exact RPC trace differs')
    scan._tip(chain, tip); scripts = {}
    for row in coverage:
        descriptor, interval = row['desc'], row['range']
        info = chain.call('getdescriptorinfo', descriptor)
        if (info.get('descriptor') != descriptor or info.get('hasprivatekeys') is not False
                or info.get('isrange') is not True):
            raise EvidenceGap('confirmed_scan: canonical public descriptor differs')
        addresses = chain.call('deriveaddresses', descriptor, interval)
        if not isinstance(addresses, list) or len(addresses) != interval[1] + 1:
            raise EvidenceGap('confirmed_scan: original public derivation incomplete')
        for child, address in enumerate(addresses):
            actual = chain.call('validateaddress', address); script = actual.get('scriptPubKey')
            if actual.get('isvalid') is not True or not isinstance(script, str) or script in scripts:
                raise EvidenceGap('confirmed_scan: nonunique/unproved public owning script')
            scripts[script] = {**owner[descriptor], 'child_index': child}
    scan._result(receipt['result'], tip, scripts); scan._tip(chain, tip)
    return scripts, receipt['result']


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
    transactions = {}; bodies = {}
    for carrier in journal['rows']['carriers']:
        txid = carrier['txid']
        try:
            tx = chain.transaction(txid)
        except Exception as error:
            raise EvidenceGap('journal.carriers.' + txid + ': Core outcome unavailable') from error
        if tx.get('txid') != txid:
            raise InvariantError('journal.carriers: independent txid differs')
        raw = chain.tx(txid); body = decode_transaction(raw['hex'], public_body=True)
        if (body['txid'] != txid or body['outputs'] != tx['outputs']
                or [v['outpoint'] for v in body['inputs']] != [v['outpoint'] for v in tx['inputs']]
                or raw.get('weight') != body['weight'] or raw.get('vsize') != body['vsize']
                or tx['fee_sat'] != carrier['miner_fee_sat']):
            raise EvidenceGap('journal.carriers.' + txid + ': signed body/weight/fee differs from Core')
        transactions[txid] = tx; bodies[txid] = body
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
        body = bodies[tx['txid']]
        groups.append({'result': result, 'transaction': tx, 'height': height,
                       'versions': {txid: transactions[txid] for txid in result['carrier_versions']},
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


def require_native_budget_join(runtime, *, server_pubkey=None, costs=(), groups=(),
                               accounting_receipt_sha256=None,
                               opening_cost_sequences=(234, 600, 2947)):
    """Independent money/set joins to the admitted peer runtime producer facts.

    The producer proves same process/config/FLOCK and stable original byte hashes.
    We do not accept its disk completeness labels as proofs of retained fees.
    Public history.txids must reproduce the SAME full/prefix hashes, then every
    retained version must match the independently checked direct/Core source.
    """
    import hashlib
    import os
    import re
    if not isinstance(runtime, dict) or not isinstance(runtime.get('native_budget'), dict):
        raise EvidenceGap('native_budget.disk_budget: actual native fee epoch unavailable')
    budget = runtime['native_budget']; disk = budget.get('disk_budget')
    if not isinstance(disk, dict):
        raise EvidenceGap('native_budget.disk_budget: actual native fee epoch unavailable')
    required = ('files', 'lock', 'history', 'accounting_receipt_sha256')
    for key in required:
        if key not in budget:
            raise EvidenceGap('native_budget.' + key + ': original source unavailable')
    if (disk.get('network') != 'signet' or disk.get('genesis') != SIGNET_GENESIS
            or server_pubkey is None or disk.get('server_pubkey') != server_pubkey):
        raise EvidenceGap('native_budget: native chain/server differs')
    for flag in ('runtime_loaded_identity_verified', 'retained_signed_fee_coverage_verified',
                 'urgent_selection_isolation_verified', 'complete', 'qualified'):
        if disk.get(flag) is not False:
            raise EvidenceGap('native_budget.disk_budget.' + flag + ': candidate label cannot grant admission')
    files = budget['files']; lock = budget['lock']
    for name, key in [('ordinary-fee-policy.json', 'policy_sha256'),
                      ('ordinary-fee-opening.json', 'opening_sha256'),
                      ('ordinary-fee-budget', 'budget_file_sha256')]:
        if name not in files or files[name].get('sha256') != disk.get(key):
            raise EvidenceGap('native_budget.files.' + name + ': stable original hash differs')
    actual = files['ordinary-fee-budget']; watch = runtime.get('daemons', {}).get('watchmand', {})
    pattern = r'lock:\s*\d+:\s+FLOCK\s+ADVISORY\s+WRITE\s+(\d+)\s+([0-9a-fA-F]+):([0-9a-fA-F]+):(\d+)\s+0\s+EOF'
    matched = re.fullmatch(pattern, lock.get('lock_line', '').strip())
    if (matched is None or (int(matched[1]), int(matched[2],16), int(matched[3],16), int(matched[4])) !=
            (watch.get('pid'), os.major(actual['device']), os.minor(actual['device']), actual['inode'])
            or (lock.get('pid'), lock.get('device'), lock.get('inode')) !=
               (watch.get('pid'), actual['device'], actual['inode'])):
        raise EvidenceGap('native_budget.lock: same actual watchman whole-file FLOCK unavailable')
    history = budget['history']; ids = history.get('txids')
    if (not isinstance(ids, list) or len(ids) > 2000 or len(set(ids)) != len(ids)
            or any(not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None for value in ids)):
        raise EvidenceGap('native_budget.history.txids: full unique canonical retained set required')
    raw = ''.join(value + '\n' for value in ids).encode()
    prefix = integer(disk['history_prefix_bytes'], 'original signed prefix bytes')
    if (prefix % 65 or prefix > len(raw) or history.get('bytes') != len(raw)
            or history.get('sha256') != hashlib.sha256(raw).hexdigest()
            or history.get('prefix_bytes') != prefix
            or history.get('prefix_sha256') != hashlib.sha256(raw[:prefix]).hexdigest()
            or history['prefix_sha256'] != disk.get('history_prefix_sha256')):
        raise EvidenceGap('native_budget.history: retained IDs do not reproduce actual full/prefix bytes')
    if (not isinstance(accounting_receipt_sha256, str)
            or budget['accounting_receipt_sha256'] != accounting_receipt_sha256
            or disk.get('accounting_receipt_sha256') != accounting_receipt_sha256):
        raise EvidenceGap('native_budget.accounting_receipt_sha256: original admitted accounting source differs')
    versions = {}
    for group in groups:
        for txid, tx in group.get('versions', {}).items():
            if txid in versions and versions[txid] != tx:
                raise InvariantError('native_budget: conflicting retained version')
            versions[txid] = tx
    if set(ids) != set(versions):
        raise EvidenceGap('native_budget.history: extra or missing retained direct/Core version')
    original = ids[:prefix//65]; following = ids[prefix//65:]
    native_opening = sum(versions[txid]['fee_sat'] for txid in original)
    original_costs = {row['txid']: row for row in costs}
    if len(original_costs) != len(costs):
        raise InvariantError('native_budget: duplicate original physical cost')
    for txid in original:
        cost = original_costs.get(txid)
        if (cost is None or cost['direct_payment_sequence'] is None
                or cost['amount_msat'] != versions[txid]['fee_sat']*1000):
            raise EvidenceGap('native_budget.opening: original retained miner cost source differs')
    if disk['opening_native_spent_sat'] != native_opening:
        raise EvidenceGap('native_budget.opening_native_spent_sat: retained original fee coverage differs')
    by_sequence = {row['sequence']: row for row in costs}
    if len(by_sequence) != len(costs) or not set(opening_cost_sequences) <= set(by_sequence):
        raise EvidenceGap('native_budget.opening_cost_sequences: complete original accounting references missing')
    opening_rows = [by_sequence[sequence] for sequence in opening_cost_sequences]
    if ({row['txid'] for row in opening_rows if row['direct_payment_sequence'] is not None} != set(original)
            or any(row['budget'] != 'ordinary' for row in opening_rows)):
        raise EvidenceGap('native_budget.opening: original accounting native identity/budget differs')
    expected_external = sum(row['amount_msat'] for row in opening_rows if row['direct_payment_sequence'] is None)
    if expected_external % 1000 or disk['opening_external_spent_sat'] != expected_external//1000:
        raise EvidenceGap('native_budget.opening_external_spent_sat: original external costs lost or doubled')
    external_opening = integer(disk['opening_external_spent_sat'], 'original external opening')
    future = integer(disk['external_future_reserved_sat'], 'declared external partition')
    ordinary = integer(disk['ordinary_budget_sat'], 'declared ordinary native budget')
    reserved = integer(disk['reserved_ceiling_sum_sat'], 'native full-ceiling reservations')
    attempts = integer(disk['attempt_count'], 'native prepare attempts')
    opening = native_opening + external_opening + future
    if (disk['opening_charge_sat'] != opening or disk['total_charged_sat'] != opening + reserved
            or disk['remaining_ordinary_allowance_sat'] != ordinary-opening-reserved
            or ordinary < opening+reserved):
        raise EvidenceGap('native_budget: opening/full-ceiling lifetime arithmetic differs')
    if len(following) > attempts or sum(versions[txid]['fee_sat'] for txid in following) > reserved:
        raise EvidenceGap('native_budget: complete retained new signed fees exceed durable reservations')
    later_external = sum(row['amount_msat'] for row in costs
        if row['sequence'] not in opening_cost_sequences and row['budget'] == 'ordinary'
        and row['direct_payment_sequence'] is None)
    if later_external % 1000 or later_external//1000 > future:
        raise EvidenceGap('native_budget.external_future_partition: actual later costs exceed original partition')
    return {'ordinary_budget_sat': ordinary, 'urgent_reserve_sat': disk['urgent_reserve_sat'],
            'native_opening_spent_sat': native_opening, 'external_opening_spent_sat': external_opening,
            'external_future_partition_sat': future,
            'external_future_partition_remaining_sat': future-later_external//1000,
            'native_reserved_ceiling_sat': reserved,
            'native_remaining_allowance_sat': ordinary-opening-reserved,
            'original_retained_txids': original, 'new_retained_txids': following}

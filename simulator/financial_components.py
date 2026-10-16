"""Independent chain joins for observed financial components, never readiness.

Source authentication, exhaustive discovery, allocation and effective fee policy
remain separate obligations. This partial result cannot open financial dispatch.
Native CLN originals stay private; only selected monetary fields leave this API.
"""
from .model import SIGNET_GENESIS, btc_to_sat, integer, public_payload


def _hex(value, size):
    if (not isinstance(value, str) or len(value) != size
            or any(c not in '0123456789abcdef' for c in value)):
        raise ValueError('bounded lowercase hexadecimal identity required')
    return value


def inspect(wallets, nodes, costs, chain, *, height, tip_hash, gaps):
    """Check named observed outputs and both sides of owned channels at one tip.

    Inputs carry original-source digests, not completeness assertions. Wallet
    rows need exact native outpoint/value/script; optional public descriptor
    derivation is checked independently. No wallet or transaction is mutated.
    """
    integer(height, 'height', 1); _hex(tip_hash, 64)
    if (not isinstance(gaps, list) or not gaps or any(not isinstance(v, str) or not v for v in gaps)
            or any(not isinstance(v, list) or len(v) > 2000 for v in (wallets, nodes, costs))):
        raise ValueError('bounded sources and explicit remaining coverage gaps required')
    if (len(nodes) > 32 or sum(len(v['utxos']) for v in wallets)
            +sum(len(v['listfunds']['outputs'])+len(v['listfunds']['channels'])
                 +len(v['listpeerchannels']['channels']) for v in nodes) > 20000):
        raise ValueError('aggregate observed rows exceed bound')
    def signet_identity():
        frame = chain.identity()
        if frame.get('chain') != 'signet' or chain.call('getblockhash', 0) != SIGNET_GENESIS:
            raise ValueError('independent signet identity differs')
        return frame
    start = signet_identity()
    if (start.get('initialblockdownload') is not False
            or (start['blocks'], start['bestblockhash']) != (height, tip_hash)):
        raise ValueError('independent source tip differs')
    assets = {}; sources = {}; channels = {}; node_ids = set()

    def original(frame):
        name = frame['id']; digest = _hex(frame['source_sha256'], 64)
        if not isinstance(name, str) or not name or name in sources:
            raise ValueError('unique original source identity required')
        sources[name] = digest

    def output(source, row):
        txid, index = row['outpoint'].rsplit(':', 1); _hex(txid, 64)
        if not index.isdigit() or str(int(index)) != index:
            raise ValueError('canonical outpoint required')
        native = chain.call('gettxout', txid, int(index), False)
        if native is None or integer(native.get('confirmations', 0), 'confirmations') < 1:
            raise ValueError('observed confirmed output absent from independent chain')
        amount = btc_to_sat(native['value']); script = native['scriptPubKey']['hex']
        if amount != integer(row['amount_sat'], 'source amount') or script != row['script']:
            raise ValueError('native source amount or script differs from chain')
        if row['outpoint'] in assets or row['outpoint'] in channels:
            raise ValueError('physical output counted twice')
        if 'descriptor' in row:
            descriptor = row['descriptor']; child = integer(row['child_index'], 'child index')
            if child >= 2**31: raise ValueError('ordinary public derivation required')
            info = chain.call('getdescriptorinfo', descriptor)
            if info.get('hasprivatekeys') is not False or info.get('descriptor') != descriptor:
                raise ValueError('canonical public descriptor required')
            addresses = chain.call('deriveaddresses', descriptor, [child, child])
            if len(addresses) != 1 or chain.call('validateaddress', addresses[0]).get('scriptPubKey') != script:
                raise ValueError('source output does not derive from descriptor')
        assets[row['outpoint']] = {'source': source, 'amount_sat': amount, 'script': script}

    for wallet in wallets:
        original(wallet)
        if not isinstance(wallet['utxos'], list) or len(wallet['utxos']) > 2000:
            raise ValueError('bounded original wallet outputs required')
        for row in wallet['utxos']: output(wallet['id'], row)
    for node in nodes:
        original(node)
        info, funds, peers = node['getinfo'], node['listfunds'], node['listpeerchannels']['channels']
        identity = info['id']; _hex(identity, 66)
        if identity in node_ids or info.get('network') != 'signet' or info.get('blockheight') != height:
            raise ValueError('distinct native node and same signet tip required')
        node_ids.add(identity)
        if any(not isinstance(rows, list) or len(rows) > 2000 for rows in (funds['outputs'], funds['channels'], peers)):
            raise ValueError('bounded native channel and cash originals required')
        if len(funds['channels']) != len(peers):
            raise ValueError('native channel source omits a channel')
        for cash in funds['outputs']:
            if cash['status'] == 'spent': continue
            if cash['status'] != 'confirmed': raise ValueError('pending CLN cash requires a separate projection')
            msat = integer(cash['amount_msat'], 'CLN cash')
            if msat % 1000: raise ValueError('onchain CLN cash has fractional satoshis')
            output(node['id'], {'outpoint': cash['txid']+':'+str(cash['output']),
                               'amount_sat': msat//1000, 'script': cash['scriptpubkey']})
        for peer in peers:
            if peer['state'] != 'CHANNELD_NORMAL' or peer['htlcs']:
                raise ValueError('conditional or non-normal channels require an ownership resolver')
            point = peer['funding_txid']+':'+str(peer['funding_outnum'])
            matches = [v for v in funds['channels'] if v['funding_txid'] == peer['funding_txid']
                       and v['funding_output'] == peer['funding_outnum']]
            owned = integer(peer['to_us_msat'], 'full owned channel balance')
            if (len(matches) != 1 or matches[0]['state'] != 'CHANNELD_NORMAL'
                    or matches[0]['our_amount_msat'] != owned
                    or matches[0]['amount_msat'] != peer['total_msat']):
                raise ValueError('native channel monetary frames disagree')
            if point in assets: raise ValueError('channel cash and backing counted twice')
            group = channels.setdefault(point, [])
            if any(v['identity'] == identity for v in group): raise ValueError('same node channel counted twice')
            group.append({'identity': identity, 'peer': peer['peer_id'], 'owned_msat': owned,
                          'capacity_msat': integer(peer['total_msat'], 'channel capacity'), 'source': node['id']})
    for point, sides in channels.items():
        txid, index = point.rsplit(':', 1); _hex(txid, 64)
        coin = chain.call('gettxout', txid, int(index), False)
        if coin is None or coin.get('confirmations', 0) < 1:
            raise ValueError('confirmed channel funding missing')
        capacity = btc_to_sat(coin['value'])*1000
        if (len(sides) != 2 or sides[0]['peer'] != sides[1]['identity']
                or sides[1]['peer'] != sides[0]['identity']
                or sum(v['owned_msat'] for v in sides) != capacity
                or any(v['capacity_msat'] != capacity for v in sides)):
            raise ValueError('both native channel owners must cover exact funding capacity')
    checked_costs = {}
    for cost in costs:
        txid = _hex(cost['txid'], 64)
        if txid in checked_costs: raise ValueError('same miner cost counted twice')
        _hex(cost['source_sha256'], 64)
        tx = chain.transaction(txid)
        if (tx['txid'] != txid or tx.get('confirmations', 0) < 1
                or tx['fee_sat'] != integer(cost['amount_sat'], 'original miner fee')):
            raise ValueError('original miner cost differs from confirmed independent inputs and outputs')
        checked_costs[txid] = {'amount_sat': tx['fee_sat'], 'source_sha256': cost['source_sha256']}
    end = signet_identity()
    if (end.get('initialblockdownload') is not False
            or (end['blocks'], end['bestblockhash']) != (height, tip_hash)):
        raise ValueError('chain changed during observed-component join')
    result = {'kind': 'financial_component_observation', 'network': 'signet', 'genesis': SIGNET_GENESIS,
              'height': height, 'tip_hash': tip_hash, 'stable_tip': True, 'complete': False, 'qualified': False,
              'wallet_outputs': assets, 'channels': channels, 'chain_checked_miner_costs': checked_costs,
              'observed_physical_msat': sum(v['amount_sat']*1000 for v in assets.values())
                  +sum(sum(v['owned_msat'] for v in sides) for sides in channels.values()),
              'observed_miner_cost_sat': sum(v['amount_sat'] for v in checked_costs.values()),
              'original_sources': sources, 'gaps': gaps}
    public_payload(result)
    return result

"""Readiness evidence for actual bidirectional fixture Lightning traffic."""
def msat(value):
    if isinstance(value, str) and value.endswith('msat'):
        value = value[:-4]
        if not value.isdecimal():
            return None
        value = int(value)
    return value if type(value) is int and value >= 0 else None


def ready(snapshot, minimum_msat=3_000_000):
    if snapshot.get('capabilities', {}).get('lightning_configured') is not True:
        return False
    nodes = snapshot.get('lightning', {})
    operator, peer = nodes.get('operator', {}), nodes.get('fixture_peer', {})
    height = snapshot.get('height')
    if type(height) is not int or not operator.get('node_id') or not peer.get('node_id'):
        return False
    if operator['node_id'] == peer['node_id']:
        return False
    for node in (operator, peer):
        if node.get('fully_synced') is not True or type(node.get('blockheight')) is not int:
            return False
        if node['blockheight'] < height - 1:
            return False
    def eligible(node, other):
        result = set()
        for channel in node.get('channels', []):
            if channel.get('state') != 'CHANNELD_NORMAL' or channel.get('peer_id') != other['node_id']:
                continue
            liquidity = [msat(channel.get(k)) for k in ('spendable_msat', 'receivable_msat')]
            if any(v is None or v < minimum_msat for v in liquidity):
                continue
            identity = tuple(channel.get(k) for k in ('channel_id', 'funding_txid', 'funding_outnum'))
            if identity[0] and identity[1] and type(identity[2]) is int:
                result.add(identity)
        return result
    return bool(eligible(operator, peer) & eligible(peer, operator))

"""Bounded original named-Core-wallet evidence, without wallet actions.

This is a source frame, not a descriptor ownership reducer or a treasury verdict.
Any unsupported/partial observation fails before an event is appended.
"""
import time

from .chain import ChainReader, public_transaction
from .funding import WalletRpc
from .model import SIGNET_GENESIS, btc_to_sat, canonical, integer, public_payload
from .trace import normalized

MAX_BYTES = 2 * 1024 * 1024
MAX_ROWS = 2000
EVENT_KIND = 'treasury_bank_original_source'


def _point(row):
    txid = row.get('txid')
    if not isinstance(txid, str) or len(txid) != 64 or any(c not in '0123456789abcdef' for c in txid):
        raise ValueError('bank outpoint txid missing')
    return txid + ':' + str(integer(row['vout'], 'bank output index'))


def collect_funding_bank_source(store, wallet_rpc, chain, *, timeout_seconds=30):
    """Append the actual original bank frame and return its event sequence.

    Uses separate capture-free clients so unvalidated replies (especially a
    malformed private descriptor) cannot enter diagnostic traces. Credentials
    and signed transaction witnesses never enter this event. No external calls
    occur inside the final event transaction.
    """
    if not 0 < timeout_seconds <= 30:
        raise ValueError('bank observation requires a bounded deadline')
    if chain.expected != SIGNET_GENESIS:
        raise ValueError('bank collector requires the declared signet chain')
    bank = WalletRpc(wallet_rpc.token_file, wallet_rpc.wallet)
    core = ChainReader(chain.url, chain.credential, chain.expected)
    started = time.time()
    deadline = time.monotonic() + timeout_seconds
    remaining = MAX_BYTES
    rows = 0

    def call(client, method, *args, **kwargs):
        nonlocal remaining, rows
        seconds = min(12, deadline - time.monotonic())
        if seconds <= 0 or remaining <= 0:
            raise ValueError('bank observation deadline/byte bound exceeded')
        value = client.call(method, *args, timeout=seconds, max_response_bytes=remaining, **kwargs)
        remaining -= client.last_response_bytes
        def count(item):
            if isinstance(item, list):
                return len(item) + sum(count(v) for v in item)
            if isinstance(item, dict):
                return sum(count(v) for v in item.values())
            return 0
        rows += count(value)
        if remaining < 0 or rows > MAX_ROWS or time.monotonic() > deadline:
            raise ValueError('bank observation exceeds byte/row/time bound')
        return value

    genesis = call(core, 'getblockhash', 0)
    if genesis != SIGNET_GENESIS or call(bank, 'getblockhash', 0, root=True) != genesis:
        raise ValueError('bank and independent Core genesis differ')
    tip = call(core, 'getblockchaininfo')
    height = integer(tip['blocks'], 'bank tip height')
    tip_hash = tip['bestblockhash']
    if tip.get('chain') != 'signet' or tip.get('initialblockdownload') is not False:
        raise ValueError('bank requires an actual synced signet tip')
    position = {'height': height, 'hash': tip_hash}

    def wallet_view():
        info = call(bank, 'getwalletinfo')
        if (info.get('walletname') != bank.wallet or info.get('descriptors') is not True
                or info.get('scanning') is not False or info.get('lastprocessedblock') != position):
            raise ValueError('exact named descriptor wallet must be synced at the observed tip')
        # Core reports signing capability as metadata; it is not public key
        # material and is unnecessary for this strictly public source frame.
        info = {k: info[k] for k in ('walletname', 'walletversion', 'format', 'txcount',
                'descriptors', 'scanning', 'lastprocessedblock') if k in info}
        descriptors = call(bank, 'listdescriptors', False)
        if descriptors.get('wallet_name') != bank.wallet:
            raise ValueError('descriptor reply belongs to another named wallet')
        entries = descriptors.get('descriptors')
        if not isinstance(entries, list) or not entries:
            raise ValueError('complete public descriptor set missing')
        public_payload(entries)
        coins = call(bank, 'listunspent', 0, 9999999, [], True)
        locks = call(bank, 'listlockunspent')
        pending = call(bank, 'listsinceblock', tip_hash, 1, True, True)
        balances = call(bank, 'getbalances')
        if not isinstance(coins, list) or not isinstance(locks, list):
            raise ValueError('complete bank coin/lock arrays required')
        if pending.get('lastblock') != tip_hash or pending.get('removed', []) != []:
            raise ValueError('pending bank frame has changed/reorged tip')
        if not isinstance(pending.get('transactions'), list):
            raise ValueError('complete pending bank transactions missing')
        if any(type(r.get('confirmations')) is not int or r['confirmations'] != 0
                or r.get('abandoned', False) for r in pending['transactions']):
            raise ValueError('conflicted/confirmed pending bank history requires another source slice')
        mine = balances['mine']
        for key in ('trusted', 'untrusted_pending', 'immature'):
            btc_to_sat(mine[key])
        if btc_to_sat(mine['immature']) or 'watchonly' in balances:
            raise ValueError('immature/watch-only bank assets need separate coverage')
        return normalized({'getwalletinfo': info, 'listdescriptors': descriptors,
                'listunspent': coins, 'listlockunspent': locks,
                'listsinceblock': pending, 'getbalances': balances})

    frame = wallet_view()
    descriptors = []
    for entry in frame['listdescriptors']['descriptors']:
        descriptor = entry['desc']
        checked = call(core, 'getdescriptorinfo', descriptor)
        if checked.get('hasprivatekeys') is not False or checked.get('descriptor') != descriptor:
            raise ValueError('canonical public bank descriptor required')
        if descriptor in descriptors:
            raise ValueError('repeated bank descriptor')
        descriptors.append(descriptor)
    coins = {_point(row): row for row in frame['listunspent']}
    locks = {_point(row): row for row in frame['listlockunspent']}
    if len(coins) != len(frame['listunspent']) or len(locks) != len(frame['listlockunspent']) or coins.keys() & locks.keys():
        raise ValueError('duplicate/overlapping bank coin inventory')
    locked = []
    for point, row in {**coins, **locks}.items():
        actual = call(core, 'gettxout', row['txid'], row['vout'], True)
        if actual is None or actual.get('bestblock') != tip_hash:
            raise ValueError('bank coin unavailable at the observed Core tip')
        amount = btc_to_sat(actual['value'])
        if point in coins:
            if (amount != btc_to_sat(row['amount']) or actual['scriptPubKey']['hex'] != row['scriptPubKey']
                    or actual['confirmations'] != row['confirmations']):
                raise ValueError('bank wallet coin differs from independent Core')
        else:
            locked.append({'outpoint': point, 'gettxout': normalized(actual)})
    total = sum(btc_to_sat(r['amount']) for r in coins.values()) + sum(btc_to_sat(r['gettxout']['value']) for r in locked)
    mine = frame['getbalances']['mine']
    if total != btc_to_sat(mine['trusted']) + btc_to_sat(mine['untrusted_pending']):
        raise ValueError('bank balances and complete unlocked/locked inventory differ')
    pending_ids = sorted({r['txid'] for r in frame['listsinceblock']['transactions']})
    if any(r['confirmations'] == 0 and r['txid'] not in pending_ids for r in coins.values()):
        raise ValueError('unconfirmed bank coin absent from pending transaction source')
    transactions = []
    parents = {}
    for txid in pending_ids:
        actual = call(core, 'getrawtransaction', txid, True)
        if actual.get('txid') != txid or actual.get('confirmations', 0) != 0:
            raise ValueError('pending bank transaction not in the observed mempool')
        transactions.append(public_transaction(actual))
        for vin in actual['vin']:
            parent_id = vin['txid']
            if parent_id not in pending_ids and parent_id not in parents:
                parent = call(core, 'getrawtransaction', parent_id, True)
                if parent.get('txid') != parent_id:
                    raise ValueError('bank pending parent source differs')
                parents[parent_id] = public_transaction(parent)
    if frame != wallet_view():
        raise ValueError('bank wallet changed during observation')
    for client, kwargs in ((core, {}), (bank, {'root': True})):
        end = call(client, 'getblockchaininfo', **kwargs)
        if end.get('blocks') != height or end.get('bestblockhash') != tip_hash or end.get('initialblockdownload') is not False:
            raise ValueError('bank/Core tip changed during observation')
    payload = normalized({'schema_version': 1, 'source_identity': {'wallet_name': bank.wallet,
        'endpoint_path': '/wallet/' + bank.wallet, 'descriptors': sorted(descriptors)},
        'network': 'signet', 'genesis': genesis, 'height': height, 'tip_hash': tip_hash,
        'observed_at': started, 'completed_at': time.time(), 'read_only': True,
        'stable_tip': True, 'complete_source_projection': True, **frame,
        'locked_coins': locked, 'pending_transactions': transactions,
        'pending_parents': [parents[k] for k in sorted(parents)],
        'bounds': {'response_bytes': MAX_BYTES - remaining, 'rows': rows, 'timeout_seconds': timeout_seconds},
        'qualification': 'original public Core source only; descriptor ownership reduction and treasury readiness remain separate'})
    public_payload(payload)
    if len(canonical(payload).encode()) > MAX_BYTES or time.monotonic() > deadline:
        raise ValueError('bank source event exceeds byte/time bound')
    with store.transaction():
        store._event(EVENT_KIND, payload)
        sequence = store.db.execute('SELECT MAX(sequence) FROM event').fetchone()[0]
    return sequence

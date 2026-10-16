"""One observed C escrow inflow; no new spending authority or financial epoch.

This fixed allocation was approved and funded externally. The transition keeps
its original pilot, fee budgets, grants, action IDs and namespace, and includes
all three physical bank outputs exactly once in subsequent conservation.
"""
import hashlib
import json
from pathlib import Path
import time

from .final_campaign import _source_event
from .frontier_source import checked_file, _strict_json
from .model import SIGNET_GENESIS, btc_to_sat, canonical, public_payload

KEY = 'direct_per_key_confirmed_escrow_opening'
EVENT = 'direct_per_key_confirmed_escrow_opening_verified'
AUTHORITY_PATH = Path('/etc/track-c/escrow-opening-authority.json')
AUTHORITY_SHA256 = 'f2d0364abc38b77a7816a871d001f8a9bd6673f1154287fcbabd9aea2969cacf'
ALLOCATION_ID = 'COORD-C-ESCROW-20261015-2059'
BANK = 'track-c-bank-9cb02072'
ESCROW_POINT = 'a6aa6afa885edc6eeebd83a1e81849e67fcfffc7f997ffaadb95b541947ee829:2'
ORIGINAL_POINTS = {
    '3e78d8ee5e2b208135f9cac343dce82ddf7ffd42851f2df8867fadf80ef72993:1': 150000,
    '8b64b8cdd173cf4d910136fd5da99fd228f431affed9ea1c4302ddec58b7bc10:0': 750000,
}
ORIGINAL_SAT = 900000
ESCROW_SAT = 17100000
PHYSICAL_SAT = ORIGINAL_SAT + ESCROW_SAT


def _digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def _authority():
    raw, digest = checked_file(AUTHORITY_PATH, maximum=65536)
    if digest != AUTHORITY_SHA256:
        raise ValueError('fixed original coordinator escrow allocation authority differs')
    value = _strict_json(raw)
    if (value.get('decision') != 'ALLOCATED_BANK_ESCROW_ONLY'
            or value.get('no_campaign_dispatch_permission') is not True
            or value.get('no_budget_reset') is not True):
        raise ValueError('escrow is bank capital only, never dispatch or fee authority')
    matches = [row for row in value['allocations'] if row.get('track') == 'C']
    if len(matches) != 1 or matches[0].get('allocation_id') != ALLOCATION_ID or matches[0].get('principal_sat') != ESCROW_SAT:
        raise ValueError('exact original C escrow allocation required')
    return matches[0]


def _pilot(store):
    from .c_pilot import declaration
    value = declaration(store)
    if value['bank_opening_sat'] != ORIGINAL_SAT:
        raise ValueError('escrow transition requires the original 900000-sat C pilot')
    rows = store.db.execute("SELECT sequence FROM event WHERE kind='direct_per_key_bounded_pilot_declared'").fetchall()
    if len(rows) != 1:
        raise ValueError('unique original C pilot event required')
    event, original = _source_event(store, rows[0][0])
    if original != value:
        raise ValueError('original C pilot event differs')
    return value, event


def _bank_frame(store, sequence, allocation):
    event, frame = _source_event(store, sequence)
    if (event['kind'] != 'treasury_bank_original_source' or frame.get('network') != 'signet'
            or frame.get('genesis') != SIGNET_GENESIS or frame.get('read_only') is not True
            or frame.get('stable_tip') is not True or frame.get('complete_source_projection') is not True
            or frame.get('source_identity', {}).get('wallet_name') != BANK
            or frame.get('source_identity', {}).get('endpoint_path') != '/wallet/' + BANK
            or frame.get('getwalletinfo', {}).get('walletname') != BANK
            or any(frame.get(k) != [] for k in ('pending_transactions', 'pending_parents', 'locked_coins', 'listlockunspent'))
            or frame.get('listsinceblock', {}).get('transactions') != []
            or frame.get('listsinceblock', {}).get('removed', []) != []):
        raise ValueError('actual original complete same C bank source required')
    mine = frame['getbalances']['mine']
    if (btc_to_sat(mine['trusted']) != PHYSICAL_SAT or btc_to_sat(mine['untrusted_pending']) != 0
            or btc_to_sat(mine['immature']) != 0):
        raise ValueError('all 18000000 physical bank sats must be confirmed and accounted once')
    expected = {**ORIGINAL_POINTS, ESCROW_POINT: ESCROW_SAT}
    coins = frame['listunspent']
    if not isinstance(coins, list) or len(coins) != len(expected):
        raise ValueError('exact old150k+750k plus new17.1M bank output set required')
    found = {}
    for coin in coins:
        index = coin.get('vout')
        if type(index) is not int or not 0 <= index <= 0xffffffff:
            raise ValueError('canonical bank output index required')
        point = coin['txid'] + ':' + str(index)
        if (point in found or point not in expected or btc_to_sat(coin['amount']) != expected[point]
                or coin.get('scriptPubKey') != allocation['script']
                or type(coin.get('confirmations')) is not int or coin['confirmations'] < 1
                or any(coin.get(k) is not True for k in ('safe', 'spendable', 'solvable'))):
            raise ValueError('escrow bank source changed ownership, value, confirmation or physical output identity')
        found[point] = {'outpoint': point, 'amount_sat': expected[point], 'script': allocation['script']}
    if set(found) != set(expected) or sum(row['amount_sat'] for row in found.values()) != PHYSICAL_SAT:
        raise ValueError('complete bank physical conservation differs')
    return event, frame, [found[point] for point in sorted(found)]


def transition(store):
    """Retained history survives later legitimate spends; never reset to 900k."""
    encoded = store.get_meta(KEY)
    if encoded is None:
        if store.db.execute('SELECT 1 FROM event WHERE kind=? LIMIT 1', (EVENT,)).fetchone():
            raise ValueError('escrow metadata missing over retained transition history')
        return None
    value = json.loads(encoded)
    rows = store.db.execute('SELECT sequence FROM event WHERE kind=?', (EVENT,)).fetchall()
    if len(rows) != 1 or _source_event(store, rows[0][0])[1] != value:
        raise ValueError('escrow opening differs from its once-only immutable event')
    allocation = _authority(); pilot, original = _pilot(store)
    bank_event, bank, coins = _bank_frame(store, value['bank_source_sequence'], allocation)
    fixed = {'allocation_id': ALLOCATION_ID, 'authority_sha256': AUTHORITY_SHA256,
        'original_pilot_source_sequence': original['sequence'], 'original_pilot_event_hash': original['hash'],
        'original_pilot_sha256': _digest(pilot), 'financial_pins': pilot['pins'], 'boundary_id': pilot['boundary_id'],
        'original_pilot_bank_opening_sat': ORIGINAL_SAT, 'escrow_bank_inflow_sat': ESCROW_SAT,
        'effective_physical_bank_opening_sat': PHYSICAL_SAT, 'physical_outputs': coins,
        'bank_source_event_hash': bank_event['hash'], 'bank_source_response_sha256': _digest(bank),
        'height':bank['height'],'tip_hash':bank['tip_hash'],'financial_readiness': False,
        'new_dispatch_authority': False, 'fee_budget_reset': False, 'new_role_allocation_authority': False}
    if (set(value) != set(fixed) | {'bank_source_sequence','independent_confirmations','observed_at'}
            or any(value.get(key) != item or type(item) in (int,bool) and type(value.get(key)) is not type(item)
                   for key, item in fixed.items())):
        raise ValueError('fixed original escrow/pilot financial history differs')
    confirmations=value['independent_confirmations']
    if (not isinstance(confirmations,list) or len(confirmations)!=len(coins)
            or any(not isinstance(actual,dict) or set(actual)!=set(coin)|{'confirmations','bestblock'}
                or any(actual.get(key)!=item for key,item in coin.items())
                or type(actual.get('confirmations')) is not int or actual['confirmations']<1
                or actual.get('bestblock')!=bank['tip_hash'] for actual,coin in zip(confirmations,coins))):
        raise ValueError('retained independent escrow confirmations differ')
    return {**value, 'transition_sequence': rows[0][0]}


def effective_opening_sat(store):
    value = transition(store)
    if value is not None:
        return value['effective_physical_bank_opening_sat']
    from .c_pilot import declaration
    return declaration(store)['bank_opening_sat']


def _before_money(store):
    if any(store.get_meta(key) is not None for key in ('conserved_treasury_boundary',
            'preserved_financial_opening','financial_operating_envelope','final_financial_epoch')):
        raise ValueError('existing treasury/envelope/epoch opening cannot be reset by this transition')
    if (not store.get_meta('paused')
            or store.db.execute("SELECT 1 FROM action WHERE state!='completed' OR operation NOT IN ('create','sync','snapshot','address') OR fee_reservation_sat!=0 OR actual_fee_sat IS NOT 0 LIMIT 1").fetchone()
            or store.db.execute("SELECT 1 FROM event WHERE kind IN ('fixture_funding_intent','fixture_funding_prepared','fixture_funding_broadcast_intent','financial_cost_verified','owner_renewal_allocation_intent') LIMIT 1").fetchone()):
        raise ValueError('pause same C namespace before any monetary, pending or unknown work')
    for table in ('funding_batch', 'seed_recovery'):
        if store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
            if store.db.execute('SELECT 1 FROM ' + table + ' LIMIT 1').fetchone():
                raise ValueError('retained funding/recovery history prohibits an escrow opening transition')


def record_transition(store, chain, *, bank_source_sequence):
    """Root applies this observed allocation once; no wallet/SDK/financial calls."""
    existing = transition(store)
    if existing is not None:
        if existing['bank_source_sequence'] != bank_source_sequence:
            raise ValueError('escrow opening source is immutable; no redeclaration')
        return False
    _before_money(store)
    pilot, original = _pilot(store); allocation = _authority()
    bank_event, bank, coins = _bank_frame(store, bank_source_sequence, allocation)
    if not 0 <= time.time() - bank['completed_at'] <= 90:
        raise ValueError('fresh original bank source required for the one-time transition')
    started = time.monotonic()
    def call(method,*args):
        remaining=min(12,30-(time.monotonic()-started))
        if remaining<=0:raise ValueError('escrow confirmation deadline exceeded')
        return chain.call(method,*args,timeout=remaining)
    before = call('getblockchaininfo')
    if (before.get('chain') != 'signet' or before.get('initialblockdownload') is not False
            or (bank['height'], bank['tip_hash']) != (before['blocks'], before['bestblockhash'])
            or call('getblockhash', 0) != SIGNET_GENESIS):
        raise ValueError('independent synchronized same-tip signet bank evidence required')
    confirmations = []
    for coin in coins:
        txid, index = coin['outpoint'].rsplit(':', 1)
        actual = call('gettxout', txid, int(index), True)
        if (actual is None or type(actual.get('confirmations')) is not int or actual['confirmations'] < 1
                or actual.get('bestblock') != before['bestblockhash']
                or btc_to_sat(actual['value']) != coin['amount_sat']
                or actual['scriptPubKey']['hex'] != coin['script']):
            raise ValueError('escrow/original bank output not independently confirmed and unspent')
        confirmations.append({**coin, 'confirmations': actual['confirmations'], 'bestblock': actual['bestblock']})
    end = call('getblockchaininfo')
    if (end.get('initialblockdownload') is not False
            or (end['blocks'], end['bestblockhash']) != (before['blocks'], before['bestblockhash'])
            or time.monotonic() - started > 30):
        raise ValueError('escrow confirmation changed chain tip or exceeded deadline')
    value = {'allocation_id': ALLOCATION_ID, 'authority_sha256': AUTHORITY_SHA256,
        'original_pilot_source_sequence': original['sequence'], 'original_pilot_event_hash': original['hash'],
        'original_pilot_sha256': _digest(pilot), 'financial_pins': pilot['pins'], 'boundary_id': pilot['boundary_id'],
        'original_pilot_bank_opening_sat': ORIGINAL_SAT, 'escrow_bank_inflow_sat': ESCROW_SAT,
        'effective_physical_bank_opening_sat': PHYSICAL_SAT, 'physical_outputs': coins,
        'bank_source_sequence': bank_source_sequence, 'bank_source_event_hash': bank_event['hash'],
        'bank_source_response_sha256': _digest(bank), 'height': before['blocks'], 'tip_hash': before['bestblockhash'],
        'independent_confirmations': confirmations, 'observed_at': time.time(),
        'financial_readiness': False, 'new_dispatch_authority': False, 'fee_budget_reset': False,
        'new_role_allocation_authority': False}
    public_payload(value)
    with store.transaction():
        _before_money(store)
        if transition(store) is not None:
            raise ValueError('concurrent escrow opening transition already recorded')
        if _pilot(store)[1]['hash'] != original['hash'] or _source_event(store, bank_source_sequence)[0]['hash'] != bank_event['hash']:
            raise ValueError('original source changed during escrow observation')
        store.db.execute('INSERT INTO meta VALUES (?,?)', (KEY, canonical(value)))
        store._event(EVENT, value)
    return True

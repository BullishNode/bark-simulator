"""Once-only five-output funding through the existing Core funding transport.

The caller owns the ordinary Engine lease. This is not a dispatcher. Preparation
uncertainty is parked permanently; only retained signed bytes may be broadcast.
"""
from . import frontier_source
import hashlib
import json
import time
from decimal import Decimal

from .bundle_audit import decode_transaction
from .final_campaign import _pins, _source_event
from .funding import WalletRpc, _check_outputs, _funding_table
from .model import SIGNET_GENESIS, btc_to_sat, canonical, integer, public_payload
from .operating_limits import envelope, preflight
from .treasury import boundary
from .architecture import DIRECT_PER_KEY, profile

KEY = 'finite_initial_funding_plan'
AMOUNTS = {'rounds': 100000, 'watchman': 75000,
           'actor-01': 50000, 'actor-02': 50000, 'actor-04': 50000}


def funding_policy(store):
    if profile(store) == DIRECT_PER_KEY:
        from .c_cohort import cohort_profile, prospective_funding_policy, seal
        if cohort_profile(store) is not None and seal(store).get('opening_kind') == 'unfunded_initial12':
            return prospective_funding_policy(store)
        from .c_pilot import funding_policy as c_policy
        return c_policy(store)
    return {'amounts': AMOUNTS, 'principal_sat': 325000, 'maximum_fee_sat': 10000,
            'maximum_rate_sat_kvb': 20000}


def _digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def _validate(store, value, chain):
    policy = funding_policy(store)
    amounts = policy['amounts']; principal = policy['principal_sat']
    fields = {'id','pins','boundary_id','bank_member_id','bank_wallet_name','bank_source_sequence',
              'finite_initial_source_sequence','recipients','maximum_principal_sat','maximum_miner_fee_sat','fee_rate_sat_kvb'}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('complete finite funding declaration required')
    public_payload(value); _pins(value['pins'])
    if not isinstance(value['id'], str) or not 1 <= len(value['id']) <= 100:
        raise ValueError('bounded unique finite funding identifier required')
    if (value['maximum_principal_sat'] != principal or not 0 < integer(value['maximum_miner_fee_sat'], 'funding fee cap') <= policy['maximum_fee_sat']
            or not 0 < integer(value['fee_rate_sat_kvb'], 'funding fee rate') <= policy['maximum_rate_sat_kvb'] or value['bank_member_id'] != 'bank'):
        raise ValueError('finite principal/miner/rate/bank scope differs')
    treasury = boundary(store)
    if value['pins'] != treasury['pins'] or value['boundary_id'] != treasury['id']:
        raise ValueError('finite funding differs from original treasury')
    members = {m['id']: m for m in treasury['members']}
    bank = members[value['bank_member_id']]
    event, source = _source_event(store, value['finite_initial_source_sequence'])
    bank_event, bank_source = _source_event(store, value['bank_source_sequence'])
    if (event['kind'] != 'finite_initial_funding_sources_verified' or source.get('financial_pins') != value['pins']
            or source.get('boundary_id') != value['boundary_id'] or source.get('bank_member_id') != value['bank_member_id']
            or source.get('bank_source_sequence') != value['bank_source_sequence']
            or source.get('bank_wallet_name') != value['bank_wallet_name']
            or source.get('principal_sat') != principal
            or value['maximum_miner_fee_sat'] > source['maximum_funding_fee_sat']
            or value['fee_rate_sat_kvb'] > source['maximum_fee_rate_sat_kvb']
            or bank_event['kind'] != 'treasury_bank_original_source' or bank['kind'] != 'wallet' or bank['role'] != 'operator'
            or bank_source.get('genesis') != SIGNET_GENESIS or bank_source.get('complete_source_projection') is not True
            or bank_source.get('read_only') is not True or bank_source.get('stable_tip') is not True
            or bank_source['source_identity']['wallet_name'] != value['bank_wallet_name']
            or sorted(bank_source['source_identity']['descriptors']) != sorted(bank['descriptors'])):
        raise ValueError('original independently verified finite bank source differs')
    frontier_source.verify_source(store,None,source,value['pins'])
    from .owned_mempool import verify_source as verify_owned_source
    verify_owned_source(store,source,'finite_initial_funding')
    recipients = value['recipients']
    from .c_fee_geometry import validate_recipients
    geometry = validate_recipients(store, recipients, amounts)
    if recipients != source.get('funding_recipients'):
        raise ValueError('exact original source recipients required')
    if geometry is not None and source.get('watchman_funding_geometry_sequence') != geometry['source_sequence']:
        raise ValueError('original immutable Watch geometry source required')
    for row in recipients:
        if set(row) != {'role','member_id','address','script','amount_sat','descriptor_index','child_index'}:
            raise ValueError('complete derived finite recipient required')
        member = members[row['member_id']]
        role = 'customer' if row['member_id'].startswith('actor-') else 'operator'
        if member['kind'] != 'wallet' or member['role'] != role or row['role'] != role:
            raise ValueError('finite recipient membership/role/principal differs')
        index = integer(row['descriptor_index'], 'funding descriptor index')
        child = integer(row['child_index'], 'funding child index')
        if index >= len(member['descriptors']) or child >= 2**31:
            raise ValueError('finite public derivation out of bound')
        addresses = chain.call('deriveaddresses', member['descriptors'][index], [child, child])
        actual = chain.call('validateaddress', row['address'])
        if addresses != [row['address']] or actual.get('isvalid') is not True or actual.get('scriptPubKey') != row['script']:
            raise ValueError('finite payee does not derive from the original boundary descriptor')
    return bank_source, source


def declare_finite_funding(store, declaration, chain):
    """Freeze this exact source-backed plan while paused, before any preparation."""
    _validate(store, declaration, chain)
    encoded = canonical(declaration)
    with store.transaction():
        previous = store.get_meta(KEY)
        if previous is not None:
            if previous != encoded: raise ValueError('finite funding declaration immutable')
            return False
        if not store.get_meta('paused') or store.get_meta('fixture_funding_plan') is not None:
            raise ValueError('pause before finite funding; legacy funding plan cannot coexist')
        if store.db.execute("SELECT 1 FROM event WHERE kind IN ('fixture_funding_intent','fixture_funding_broadcast_intent') LIMIT 1").fetchone():
            raise ValueError('finite declaration must precede all funding')
        _funding_table(store)
        if store.db.execute('SELECT 1 FROM funding_batch LIMIT 1').fetchone():
            raise ValueError('preserve existing funding batch; no new principal payment')
        store.db.execute('INSERT INTO meta VALUES (?,?)', (KEY, encoded))
        store._event('finite_funding_declared', {'declaration': declaration})
    return True


def _plan(store):
    value = store.get_meta(KEY)
    if value is None: raise ValueError('finite funding declaration missing')
    rows = store.db.execute("SELECT sequence FROM event WHERE kind='finite_funding_declared'").fetchall()
    if len(rows) != 1: raise ValueError('unique original finite declaration required')
    _, original = _source_event(store, rows[0][0])
    if canonical(original['declaration']) != value: raise ValueError('finite declaration changed')
    return original['declaration']


def verify_initial_revalidation(store, value, current_sequence):
    """Bind a new full source observation to the original immutable plan.

    This does not refresh an old event or alter the retained bank/source refs.
    Both independently collected sources must describe the same opening, owning
    member descriptors and exact physical recipient plan. Freshness and current
    chain/assets are separately enforced by the real readiness producer.
    """
    old_event, original=_source_event(store,value['finite_initial_source_sequence'])
    new_event, current=_source_event(store,current_sequence)
    if old_event['kind']!='finite_initial_funding_sources_verified' or new_event['kind']!=old_event['kind']:
        raise ValueError('original and fresh full initial sources required')
    fields=('financial_pins','boundary_id','genesis','bank_member_id','bank_wallet_name',
            'opening_total_sat','opening_liabilities_sat','funding_recipients','funding_plan_sha256',
            'principal_sat','maximum_funding_fee_sat','maximum_fee_rate_sat_kvb','members',
            'descriptor_ranges','operation_scope','architecture_profile','c_pilot_id',
            'client_principal_sat','operator_fee_grants_sat','fee_signer_member',
            'watchman_funding_geometry_sequence','escrow_opening_transition_sequence')
    if (profile(store)!=DIRECT_PER_KEY or any(original.get(k)!=current.get(k) for k in fields)
            or original.get('bank_source_sequence')!=value['bank_source_sequence']
            or original.get('financial_pins')!=value['pins']
            or original.get('boundary_id')!=value['boundary_id']
            or current.get('funding_recipients')!=value['recipients']
            or current.get('funding_plan_sha256')!=_digest(value['recipients'])):
        raise ValueError('fresh initial source changes the immutable financial plan or ownership')
    return current


def _admit(store, config, snapshot, value, chain):
    if store.get_meta('paused'): raise ValueError('campaign paused; no finite funding')
    proof_event, proof = _source_event(store, snapshot['operating_readiness_sequence'])
    if (proof_event['kind']!='financial_operating_readiness' or proof.get('operation_scope') != ['funding']
            or proof.get('funding_plan_sha256') != _digest(value['recipients'])):
        raise ValueError('original funding-only admission differs from immutable finite plan')
    if (proof.get('bank_source_sequence'),proof.get('finite_initial_source_sequence'))!=(value['bank_source_sequence'],value['finite_initial_source_sequence']):
        if (profile(store)!=DIRECT_PER_KEY
                or proof.get('original_finite_initial_source_sequence')!=value['finite_initial_source_sequence']
                or proof.get('original_bank_source_sequence')!=value['bank_source_sequence']):
            raise ValueError('fresh funding observation must retain the original plan source refs')
        fresh=verify_initial_revalidation(store,value,proof.get('finite_initial_source_sequence'))
        if (fresh['bank_source_sequence']!=proof.get('bank_source_sequence')
                or fresh['financial_pins']!=value['pins']
                or (fresh['height'],fresh['tip_hash'])!=(snapshot['height'],snapshot['tip_hash'])):
            raise ValueError('fresh funding source differs from actual admitted tip/bank')
        frontier_source.verify_source(store,config,fresh,value['pins'])
        from .owned_mempool import verify_source as verify_owned_source
        verify_owned_source(store,fresh,'finite_initial_funding',fresh=True)
    _, original_source = _source_event(store,value['finite_initial_source_sequence'])
    frontier_source.verify_source(store,config,original_source,value['pins'])
    tip = chain.identity()
    if (tip.get('initialblockdownload') is not False or tip.get('chain') != 'signet'
            or (tip['blocks'], tip['bestblockhash']) != (snapshot['height'], snapshot['tip_hash'])):
        raise ValueError('actual Core tip differs from funding admission')
    decision = preflight(store, config, snapshot, operation='funding', amount_sat=funding_policy(store)['principal_sat'],
                         maximum_fee_sat=value['maximum_miner_fee_sat'])
    if decision.get('allowed') is not True: raise ValueError('funding preflight held')
    if value['fee_rate_sat_kvb'] > _fee_ceiling(store, config):
        raise ValueError('funding target exceeds original operation path fee ceilings')
    for recipient in value['recipients']:
        if recipient['role'] == 'customer' and not store.ordinary_actor_available(recipient['member_id']):
            raise ValueError('finite customer belongs to another controller/namespace')


def _fee_ceiling(store, config):
    limits = envelope(store, config)
    paths = limits.get('operation_fee_paths', {}).get('funding')
    if not paths: raise ValueError('funding requires explicit existing operation fee paths')
    return min(20000, *(integer(limits['fee_ceilings_sat_kvb'][p], 'funding fee ceiling', 1) for p in paths))


def _needs_sync(store, value):
    for recipient in value['recipients']:
        if recipient['role'] == 'customer':
            row = store.db.execute('SELECT details FROM actor WHERE id=?', (recipient['member_id'],)).fetchone()
            if row is None: raise ValueError('finite customer actor missing')
            details = json.loads(row[0]); details['needs_sync'] = True
            store.db.execute('UPDATE actor SET details=? WHERE id=?', (canonical(details), recipient['member_id']))


def _check(decoded, selected, value, bank, bank_descriptors):
    points = [i['txid']+':'+str(i['vout']) for i in decoded['vin']]
    if len(points) != len(set(points)) or set(points) != set(selected):
        raise ValueError('funding inputs differ from independently confirmed original bank coins')
    changes = _check_outputs(decoded, value['recipients'], bank)
    scripts = {r['address']: r['script'] for r in value['recipients']}
    for output in decoded['vout']:
        address = output['scriptPubKey'].get('address')
        if address in scripts and output['scriptPubKey']['hex'] != scripts[address]:
            raise ValueError('finite recipient script differs')
    for output in changes:
        owner = bank.call('getaddressinfo', output['scriptPubKey']['address'])
        if (owner.get('ismine') is not True or owner.get('parent_desc') not in bank_descriptors
                or owner.get('scriptPubKey') != output['scriptPubKey']['hex']):
            raise ValueError('funding change not owned by the original declared bank')
    fee = sum(selected.values()) - sum(btc_to_sat(o['value']) for o in decoded['vout'])
    if not 0 <= fee <= value['maximum_miner_fee_sat']:
        raise ValueError('actual funding miner fee exceeds declared cap')
    return fee


def _retained(store, row, value):
    """Bind mutable batch state to its original intent and signed-body receipt."""
    parsed = decode_transaction(row['raw_tx'])
    for kind in ('fixture_funding_intent','fixture_funding_prepared'):
        rows = store.db.execute("SELECT sequence FROM event WHERE kind=? AND json_extract(payload,'$.batch')=?", (kind, row['id'])).fetchall()
        if len(rows) != 1: raise ValueError('original finite funding history missing or repeated')
        _, proof = _source_event(store, rows[0][0])
        if kind == 'fixture_funding_intent':
            if proof.get('declaration_sha256') != _digest(value): raise ValueError('finite intent declaration differs')
        elif (proof.get('txid') != parsed['txid'] or row['txid'] != parsed['txid']
                or proof.get('transaction_sha256') != hashlib.sha256(bytes.fromhex(row['raw_tx'])).hexdigest()
                or proof.get('fee_sat') != row['fee_sat'] or proof.get('outputs') != parsed['outputs']
                or [{'outpoint': i['txid']+':'+str(i['vout'])} for i in proof['inputs']] != parsed['inputs']):
            raise ValueError('retained finite signed transaction differs from original history')
    return parsed


def _observe(store, chain, row, value):
    """Observe the retained transaction only; never prepare/sign/send again."""
    if not row['txid']:
        return {'batch': row['id'], 'state': 'outcome_unknown', 'txid': None, 'retry_allowed': False}
    original = _retained(store, row, value)
    intents = store.db.execute("SELECT sequence FROM event WHERE kind='fixture_funding_broadcast_intent' AND json_extract(payload,'$.batch')=?", (row['id'],)).fetchall()
    if len(intents) != 1: raise ValueError('original finite broadcast intent missing or repeated')
    _, intent = _source_event(store, intents[0][0])
    if intent.get('txid') != row['txid']: raise ValueError('original finite broadcast identity differs')
    try:
        before = chain.identity()
        actual = chain.tx(row['txid'])
    except Exception:
        return {'batch': row['id'], 'state': 'outcome_unknown', 'txid': row['txid'], 'retry_allowed': False}
    parsed = decode_transaction(actual['hex'])
    if parsed['txid'] != row['txid'] or parsed['inputs'] != original['inputs'] or parsed['outputs'] != original['outputs']:
        raise ValueError('observed funding differs from retained transaction')
    state = 'confirmed' if actual.get('confirmations', 0) > 0 else 'broadcast'
    checked = chain.transaction(row['txid']) if state == 'confirmed' else None
    ending = chain.identity()
    if (before.get('initialblockdownload') is not False or ending.get('initialblockdownload') is not False
            or (before['blocks'], before['bestblockhash']) != (ending['blocks'], ending['bestblockhash'])):
        raise ValueError('Core tip changed while reconfirming finite funding')
    if checked is not None and (checked['fee_sat'] != row['fee_sat'] or checked.get('confirmations', 0) < 1
            or checked.get('blockhash') != actual.get('blockhash') or checked.get('txid') != row['txid']
            or [{'outpoint': i['outpoint']} for i in checked['inputs']] != parsed['inputs']
            or checked['outputs'] != parsed['outputs']):
        raise ValueError('independently confirmed funding fee differs')
    with store.transaction():
        store.db.execute('UPDATE funding_batch SET state=?,updated_at=? WHERE id=?', (state, time.time(), row['id']))
        prior = store.db.execute("SELECT sequence FROM event WHERE kind='fixture_funding_confirmed' AND json_extract(payload,'$.batch')=?", (row['id'],)).fetchall()
        costs = store.db.execute("SELECT sequence FROM event WHERE kind='financial_cost_verified' AND json_extract(payload,'$.monetary_id')=?", ('bitcoin-miner:'+row['txid'],)).fetchall()
        if len(prior) > 1 or len(costs) > 1 or bool(prior) != bool(costs):
            raise ValueError('original funding confirmation/cost history is missing or repeated')
        if prior:
            _, proof = _source_event(store, prior[0][0]); _, cost = _source_event(store, costs[0][0])
            if (proof.get('txid') != row['txid'] or proof.get('fee_sat') != row['fee_sat']
                    or proof.get('financial_pins') != value['pins'] or cost.get('amount_msat') != row['fee_sat']*1000
                    or cost.get('financial_pins') != value['pins'] or cost.get('budget') != 'ordinary'):
                raise ValueError('original funding confirmation/cost differs')
        if state == 'confirmed' and not prior:
            store._event('fixture_funding_confirmed', {'batch': row['id'], 'txid': row['txid'],
                'principal_sat': funding_policy(store)['principal_sat'], 'fee_sat': row['fee_sat'], 'financial_pins': value['pins'],
                'boundary_id': value['boundary_id'], 'bank_source_sequence': value['bank_source_sequence'],
                'finite_initial_source_sequence': value['finite_initial_source_sequence'],
                'funding_plan_sha256': _digest(value['recipients']), 'recipients': value['recipients'],
                'confirmed_transaction': checked})
            store._event('financial_cost_verified', {'monetary_id': 'bitcoin-miner:'+row['txid'],
                'amount_msat': row['fee_sat']*1000, 'budget': 'ordinary', 'financial_pins': value['pins'],
                'transaction': checked, 'scope': 'once-only independently confirmed finite funding miner fee'})
            _needs_sync(store, value)
    return {'batch': row['id'], 'state': state, 'txid': row['txid'], 'fee_sat': row['fee_sat'], 'retry_allowed': False}


def fund_finite_cohort(store, rpc, chain, config, snapshot):
    """One actual funding payment, after original funding-only preflight."""
    value = _plan(store); batch = 'finite:'+value['id']
    row = store.db.execute('SELECT * FROM funding_batch WHERE id=?', (batch,)).fetchone()
    if row is not None and row['recipients'] != canonical(value): raise ValueError('finite retained batch identity differs')
    if row is not None and row['state'] in {'outcome_unknown','broadcasting','broadcast','confirmed'}:
        return _observe(store, chain, row, value)
    bank_source, source = _validate(store, value, chain)
    if rpc.wallet != value['bank_wallet_name']: raise ValueError('exact declared Core funding wallet required')
    # Signed PSBTs and witness bytes remain private in Core/memory/funding_batch;
    # this client deliberately has no public diagnostic capture callback.
    bank = WalletRpc(rpc.token_file, rpc.wallet)
    _admit(store, config, snapshot, value, chain)
    if (bank.call('getblockhash', 0, root=True) != SIGNET_GENESIS
            or bank.call('getwalletinfo')['walletname'] != value['bank_wallet_name']):
        raise ValueError('funding bank chain/name differs')
    if row is None:
        with store.transaction():
            store.db.execute("INSERT INTO funding_batch VALUES (?,'intent',?,NULL,NULL,NULL,?)", (batch, canonical(value), time.time()))
            store._event('fixture_funding_intent', {'batch': batch, 'declaration_sha256': _digest(value),
                'recipients': value['recipients'], 'maximum_fee_sat': value['maximum_miner_fee_sat']})
        row = store.db.execute('SELECT * FROM funding_batch WHERE id=?', (batch,)).fetchone()
    if row['state'] == 'intent':
        selected = {}; inputs = []
        locked = {i['txid']+':'+str(i['vout']) for i in bank.call('listlockunspent')}
        for coin in sorted(bank_source['listunspent'], key=lambda r: (r['txid'], r['vout'])):
            point = coin['txid']+':'+str(coin['vout'])
            if coin.get('confirmations', 0) < 1 or coin.get('spendable') is not True or point in locked: continue
            actual = chain.call('gettxout', coin['txid'], coin['vout'], True)
            owner = bank.call('getaddressinfo', coin['address'])
            if (actual is None or actual.get('confirmations', 0) < 1 or btc_to_sat(actual['value']) != btc_to_sat(coin['amount'])
                    or actual['scriptPubKey']['hex'] != coin['scriptPubKey'] or owner.get('ismine') is not True
                    or owner.get('scriptPubKey') != coin['scriptPubKey']):
                raise ValueError('original bank input no longer confirmed/owned/available')
            selected[point] = btc_to_sat(coin['amount']); inputs.append({'txid': coin['txid'], 'vout': coin['vout']})
            if sum(selected.values()) >= value['maximum_principal_sat']+value['maximum_miner_fee_sat']: break
            if len(inputs) >= 32: break
        if sum(selected.values()) < value['maximum_principal_sat']+value['maximum_miner_fee_sat']:
            raise ValueError('original confirmed bank inputs do not cover finite principal and fee cap')
        _admit(store, config, snapshot, value, chain)
        # Seal uncertainty BEFORE the first wallet preparation/signing call.
        with store.transaction():
            changed = store.db.execute("UPDATE funding_batch SET state='outcome_unknown',updated_at=? WHERE id=? AND state='intent'", (time.time(), batch))
            if changed.rowcount != 1: raise ValueError('finite preparation already claimed; never retry')
            store._event('fixture_funding_prepare_intent', {'batch': batch, 'inputs': inputs, 'retry_allowed': False})
        try:
            outputs = [{r['address']: str(Decimal(r['amount_sat'])/100000000)} for r in value['recipients']]
            prepared = bank.call('walletcreatefundedpsbt', inputs, outputs, 0, {'fee_rate': str(Decimal(value['fee_rate_sat_kvb'])/1000),
                'minconf': 1, 'lockUnspents': False, 'add_inputs': False})
            unsigned = bank.call('decodepsbt', prepared['psbt'])['tx']
            fee = _check(unsigned, selected, value, bank, bank_source['source_identity']['descriptors'])
            if fee != btc_to_sat(prepared['fee']): raise ValueError('PSBT fee differs from actual original bank inputs')
            signed = bank.call('walletprocesspsbt', prepared['psbt'])
            final = bank.call('finalizepsbt', signed['psbt'])
            if final.get('complete') is not True: raise ValueError('finite funding signing incomplete')
            raw = final['hex']
            if len(raw) > 131072: raise ValueError('finite funding transaction byte bound')
            parsed = decode_transaction(raw); decoded = bank.call('decoderawtransaction', raw, root=True)
            if (decoded['txid'] != parsed['txid'] or parsed['txid'] != unsigned['txid']
                    or _check(decoded, selected, value, bank, bank_source['source_identity']['descriptors']) != fee
                    or parsed['inputs'] != [{'outpoint': i['txid']+':'+str(i['vout'])} for i in decoded['vin']]
                    or parsed['outputs'] != [{'vout': o['n'], 'amount_sat': btc_to_sat(o['value']), 'script': o['scriptPubKey']['hex']} for o in decoded['vout']]
                    or fee*1000 > parsed['vsize']*_fee_ceiling(store, config)):
                raise ValueError('signed finite funding body/fee policy differs')
            with store.transaction():
                store.db.execute("UPDATE funding_batch SET state='prepared',txid=?,raw_tx=?,fee_sat=?,updated_at=? WHERE id=?", (parsed['txid'], raw, fee, time.time(), batch))
                store._event('fixture_funding_prepared', {'batch': batch, 'txid': parsed['txid'],
                    'transaction_sha256': hashlib.sha256(bytes.fromhex(raw)).hexdigest(),
                    'principal_sat': value['maximum_principal_sat'], 'fee_sat': fee, 'inputs': inputs, 'outputs': parsed['outputs']})
        except Exception as error:
            store.event('fixture_funding_prepare_unknown', {'batch': batch, 'error_type': type(error).__name__, 'retry_allowed': False})
            raise
        row = store.db.execute('SELECT * FROM funding_batch WHERE id=?', (batch,)).fetchone()
    if row['state'] != 'prepared': raise ValueError('finite funding preparation parked; no rebuild')
    retained = _retained(store, row, value)
    _admit(store, config, snapshot, value, chain)
    source_coins = {i['txid']+':'+str(i['vout']): i for i in bank_source['listunspent']}
    locked = {i['txid']+':'+str(i['vout']) for i in bank.call('listlockunspent')}
    for item in retained['inputs']:
        txid, index = item['outpoint'].rsplit(':', 1)
        actual = chain.call('gettxout', txid, int(index), True); original = source_coins[item['outpoint']]
        if (actual is None or actual.get('confirmations', 0) < 1 or item['outpoint'] in locked
                or actual.get('bestblock') != snapshot['tip_hash']
                or btc_to_sat(actual['value']) != btc_to_sat(original['amount'])
                or actual['scriptPubKey']['hex'] != original['scriptPubKey']):
            raise ValueError('retained funding input unavailable; no replacement transaction')
    with store.transaction():
        changed = store.db.execute("UPDATE funding_batch SET state='broadcasting',updated_at=? WHERE id=? AND state='prepared'", (time.time(), batch))
        if changed.rowcount != 1: raise ValueError('finite broadcast already claimed; never resend')
        store._event('fixture_funding_broadcast_intent', {'batch': batch, 'txid': row['txid']})
    try:
        if bank.call('sendrawtransaction', row['raw_tx'], root=True) != row['txid']:
            raise ValueError('finite broadcast returned another transaction')
        state = 'broadcast'
    except Exception:
        state = 'outcome_unknown'
    with store.transaction():
        store.db.execute('UPDATE funding_batch SET state=?,updated_at=? WHERE id=?', (state, time.time(), batch))
        store._event('fixture_funding_result', {'batch': batch, 'state': state, 'txid': row['txid'], 'fee_sat': row['fee_sat']})
        if state == 'broadcast': _needs_sync(store, value)
    return {'batch': batch, 'state': state, 'txid': row['txid'], 'fee_sat': row['fee_sat'], 'retry_allowed': False}

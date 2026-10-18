"""One genuine 20k short-exit board; retain the incompatible old refresh.

Uses existing native wallet, funding and failed-send/recovery hooks. The root
owns the one treasury PSBT; this module never loads a funding wallet or retries
an unknown native action. Existing service allocations pay operator fees.
"""
from __future__ import annotations

import io
import hashlib
import json
from pathlib import Path
import re
import tomllib

from .model import canonical, btc_to_sat
from .signet import digest, network_identity
from .signet_phase import _native, _quiescent, _verify_runtime
from .signet_existing_ln import SHORT
from .signet_s02 import _save
from .signet_lightning import _protected, _private_call, _attempt

KIND = 'fresh_short_board'
PROFILE = {'vtxo_refresh_expiry_threshold': 14, 'vtxo_exit_margin': 12,
           'fallback_fee_rate': 750}
RECOVERED = '0e4f2b223e99f27fef775a84811269e307fb053f7a6d8f67d1e58930f88f6fa7:0'
TREASURY_SCRIPT = '0014e401edc4d85cbf4c41231d0414890ff8201282ba'


def _admission(campaign, pins, path):
    allowed = json.loads(Path(path).read_text())
    if (allowed.get('scope') != 'P09-fresh-board-v11c'
            or allowed.get('runtime_manifest_sha256') != pins['runtime_manifest_sha256']
            or allowed.get('recovered_input') != RECOVERED
            or allowed.get('recovered_input_sat') != 58034
            or allowed.get('sender_allocation_sat') != 30000
            or allowed.get('board_amount_sat') != 20000
            or allowed.get('new_treasury_principal_sat') != 0
            or allowed.get('watchman_minimum_confirmed_sat') != 40000
            or allowed.get('watchman_admin') != 'http://127.0.0.1:4596'):
        raise ValueError('explicit recovered-funds/same-runtime fresh20k admission required')
    runtime = json.loads(Path(pins['runtime_manifest']).read_text())
    if runtime.get('server_pubkey') != allowed.get('server_pubkey'):
        raise ValueError('same actual server identity required')
    cfg = tomllib.loads((Path(pins['configuration_directory']) / 'captaind.toml').read_text())
    if ({k: cfg.get(k) for k in SHORT} != SHORT
            or cfg.get('postgres', {}).get('name') != allowed.get('database')
            or cfg.get('vtxopool', {}).get('vtxo_lifetime') != 32
            or cfg.get('vtxopool', {}).get('vtxo_pre_expiry') != 12
            or cfg.get('vtxopool', {}).get('vtxo_targets') != ['10000sat:2']):
        raise ValueError('unchanged explicit short32/12/send18 real-pool profile required')
    return allowed


def prepare(campaign, runtime_pins, admission_path):
    """Actual journaled creation/registration, before any funding or board."""
    if campaign.db.execute('SELECT 1 FROM actor UNION SELECT 1 FROM action UNION SELECT 1 FROM result').fetchone():
        raise ValueError('fresh empty operation required; no automatic partial-setup retry')
    campaign.db.execute("INSERT INTO meta VALUES ('phase_runtime_pins',?)", (canonical(runtime_pins),))
    _verify_runtime(campaign)
    allowed = _admission(campaign, runtime_pins, admission_path)
    chain = network_identity(campaign.core)
    _native(campaign, 'fresh-source-create', 'absent', 'create', {'wallet_profile': PROFILE})
    record = _native(campaign, 'fresh-source-registration', 'absent', 'fallback_record')
    address = _native(campaign, 'fresh-source-funding-address', 'absent', 'onchain_address')['address']
    for value, script in [(address, None), (record['payout_address'], record['record']['spk'])]:
        result = campaign.core.call('validateaddress', value)
        if result.get('isvalid') is not True or (script and result.get('scriptPubKey') != script):
            raise ValueError('genuine native payout/funding addresses required')
    if record.get('network') != 'signet':
        raise ValueError('actual public-Signet registration required')
    # Seed remains private; retain a second durable native-original copy now.
    source = _protected(campaign.actor_path('absent') / 'mnemonic')
    campaign._retain_private('s02-recovery-source-absent', 'source', io.BytesIO(source))
    birth = json.loads(campaign.db.execute("SELECT chain FROM action WHERE id='fresh-source-create'").fetchone()[0])['height']
    request = {'network': 'signet', 'funding_dispatched': False,
        'root_admission_sha256': digest(Path(admission_path)),
        'runtime_manifest_sha256': runtime_pins['runtime_manifest_sha256'],
        'database': allowed['database'], 'server_pubkey': allowed['server_pubkey'],
        'recovered_input': RECOVERED, 'recovered_input_sat': 58034,
        'new_treasury_principal_sat': 0, 'board_amount_sat': 20000,
        'birthday_height': birth, 'sender_directory': str(campaign.actor_path('absent')),
        'sender_config_sha256': digest(campaign.actor_path('absent') / 'config.toml'),
        'registration_sha256': hashlib.sha256(canonical(record).encode()).hexdigest(),
        'outputs': {'sender': {'address': address,
            'script': campaign.core.call('validateaddress', address)['scriptPubKey'], 'amount_sat': 30000}}}
    return _save(campaign, 'fresh-source-request', {'kind': 'fresh_source_request',
        'stage': 'ACTUAL_NEW_WALLET_REGISTERED_NO_FUNDING_NO_BOARD',
        'case_verdict': 'INCOMPLETE', 'chain': chain, 'request': request})


def stage(campaign, request_path, receipt_path, admission_path, recovery_destination):
    """Bind the root's actual batch to the already-created exact actor."""
    _quiescent(campaign)
    if campaign.db.execute("SELECT 1 FROM meta WHERE key='failed_send'").fetchone():
        raise ValueError('already staged; never replace original admission')
    cached = campaign.db.execute("SELECT payload FROM result WHERE json_extract(payload,'$.kind')='fresh_source_request'").fetchone()
    request = json.loads(Path(request_path).read_text())
    if not cached or json.loads(cached[0])['request'] != request:
        raise ValueError('original native funding request required')
    pins = json.loads(campaign.db.execute("SELECT value FROM meta WHERE key='phase_runtime_pins'").fetchone()[0])
    allowed = _admission(campaign, pins, admission_path)
    if digest(Path(admission_path)) != request['root_admission_sha256']:
        raise ValueError('original root admission changed')
    receipt = json.loads(Path(receipt_path).read_text())
    if (receipt.get('request_sha256') != digest(Path(request_path))
            or not re.fullmatch('[0-9a-f]{64}', receipt.get('txid', ''))):
        raise ValueError('actual root funding receipt must bind native request')
    if (recovery_destination != allowed.get('recovery_destination')
            or campaign.core.call('validateaddress', recovery_destination).get('isvalid') is not True):
        raise ValueError('owned declared Signet recovery destination required')
    record = json.loads(campaign.db.execute("SELECT reply FROM action WHERE id='fresh-source-registration' AND state='acknowledged'").fetchone()[0])
    spec = {'source_kind': KIND, 'sender_directory': request['sender_directory'],
        'sender_config_sha256': request['sender_config_sha256'],
        'server_pubkey': allowed['server_pubkey'], 'database': allowed['database'],
        'birthday_height': request['birthday_height'], 'board_amount_sat': 20000,
        'recovery_destination': recovery_destination,
        **{key: str(Path(value).absolute()) for key, value in
           [('financial_admission', admission_path), ('funding_request', request_path), ('funding_receipt', receipt_path)]}}
    spec.update({key + '_sha256': digest(Path(spec[key]))
                 for key in ['financial_admission', 'funding_request', 'funding_receipt']})
    campaign.db.execute('BEGIN IMMEDIATE')
    try:
        campaign.db.execute("INSERT INTO meta VALUES ('failed_send',?)", (canonical(spec),))
        campaign.db.execute("INSERT INTO meta VALUES ('failed_sender_registration',?)", (canonical(record),))
        profile(campaign, spec)
        campaign.db.execute('COMMIT')
    except BaseException:
        campaign.db.execute('ROLLBACK')
        raise
    return _save(campaign, 'fresh-source-stage', {'kind': 'fresh_source_stage',
        'stage': 'ROOT_FUNDING_BOUND_NO_BOARD', 'case_verdict': 'INCOMPLETE'})


def profile(campaign, spec):
    pins = json.loads(campaign.db.execute("SELECT value FROM meta WHERE key='phase_runtime_pins'").fetchone()[0])
    _admission(campaign, pins, spec['financial_admission'])
    for key in ['financial_admission', 'funding_request', 'funding_receipt']:
        if digest(Path(spec[key])) != spec[key + '_sha256']:
            raise ValueError('original fresh-board funding/admission changed')
    path = campaign.actor_path('absent') / 'config.toml'
    wallet = tomllib.loads(path.read_text())
    if (digest(path) != spec['sender_config_sha256']
            or wallet.get('server_address') != campaign.config['ark_url']
            or any(wallet.get(k) != v for k, v in PROFILE.items())):
        raise ValueError('actual new manual-native profile changed')
    return spec


def funding(campaign, spec):
    chain = network_identity(campaign.core)
    request = json.loads(Path(spec['funding_request']).read_text())
    receipt = json.loads(Path(spec['funding_receipt']).read_text())
    tx = campaign.core.call('getrawtransaction', receipt['txid'], True)
    if tx.get('confirmations', 0) < 1:
        return {'kind': 'failed_send_funding', 'stage': 'WAITING_FOR_REAL_FUNDING_CONFIRMATION',
                'case_verdict': 'INCOMPLETE', 'chain': chain}
    from .signet_s02 import _confirmed_transaction
    _confirmed_transaction(campaign, tx['txid'], chain)
    if [v['txid'] + ':' + str(v['vout']) for v in tx['vin']] != [RECOVERED]:
        raise ValueError('exact recovered principal input required; no fresh allocation')
    previous = campaign.core.call('getrawtransaction', RECOVERED.split(':')[0], True)
    _confirmed_transaction(campaign, previous['txid'], chain)
    if (btc_to_sat(previous['vout'][0]['value']) != 58034
            or previous['vout'][0]['scriptPubKey']['hex'] != TREASURY_SCRIPT):
        raise ValueError('actual recovered amount/owned script required')
    expected = request['outputs']['sender']
    matches = [v for v in tx['vout'] if v['scriptPubKey']['hex'] == expected['script']
               and btc_to_sat(v['value']) == 30000]
    if len(matches) != 1:
        raise ValueError('exact native-owned30k funding output required')
    change = [v for v in tx['vout'] if v['n'] != matches[0]['n']]
    if len(change) != 1 or change[0]['scriptPubKey']['hex'] != TREASURY_SCRIPT:
        raise ValueError('one exact owned treasury change output required')
    actual = campaign.core.call('gettxout', tx['txid'], matches[0]['n'], True)
    if not actual and not campaign.db.execute("SELECT 1 FROM action WHERE id='failed-send-board' AND state='acknowledged'").fetchone():
        raise ValueError('funding spent without acknowledged board; reconcile')
    fee = 58034 - sum(btc_to_sat(v['value']) for v in tx['vout'])
    if not 0 < fee <= 10000:
        raise ValueError('actual funding fee outside approved preflight ceiling')
    pins = json.loads(campaign.db.execute("SELECT value FROM meta WHERE key='phase_runtime_pins'").fetchone()[0])
    n = _attempt(campaign, 'fresh-watch')
    wallet = _private_call(campaign, f'fresh-watch-{n}', 'wallet',
        [str(Path(pins['binary_directory']) / 'captaind'), 'rpc', '--addr',
         'http://127.0.0.1:4596', 'wallet'])['watchman']
    # Native ownership plus public current usable confirmed outputs; do not
    # count wallet balance alone or require historically untouched fee coins.
    confirmed = 0
    for point in wallet['confirmed_utxos']:
        txid, index = point.split(':')
        out = campaign.core.call('gettxout', txid, int(index), True)
        if out and out['confirmations'] >= 1:
            confirmed += btc_to_sat(out['value'])
    if min(confirmed, wallet['trusted_balance']) < 40000:
        raise ValueError('actual native-owned confirmed usable40k fee funds required')
    if network_identity(campaign.core) != chain:
        raise ValueError('chain changed during genuine funding admission')
    return _save(campaign, 'failed-send-funding', {'kind': 'failed_send_funding',
        'stage': 'ACTUAL_FUNDING_CONFIRMED', 'case_verdict': 'INCOMPLETE', 'chain': chain,
        'funding_miner_fee_sat': fee, 'sender_allocation_sat': 30000,
        'watchman_confirmed_usable_sat': confirmed})


def board_accounting(campaign, spec, board, tx, coin):
    """Public board funding fee/change, separate from virtual P2A residual."""
    request = json.loads(Path(spec['funding_request']).read_text())
    receipt = json.loads(Path(spec['funding_receipt']).read_text())
    funded = campaign.core.call('getrawtransaction', receipt['txid'], True)
    candidates = [v for v in funded['vout'] if v['scriptPubKey']['hex'] == request['outputs']['sender']['script']
                  and btc_to_sat(v['value']) == 30000]
    if (len(candidates) != 1 or len(tx['vin']) != 1
            or tx['vin'][0].get('txid') != funded['txid']
            or tx['vin'][0].get('vout') != candidates[0]['n']):
        raise ValueError('board must spend only the original owned30k output')
    anchor = int(coin['chain_anchor'].split(':')[1])
    outputs = {v['n']: v for v in tx['vout']}
    if (board['amount_sat'] != coin['amount_sat'] or board['vtxos'] != [coin['id']]
            or btc_to_sat(outputs[anchor]['value']) != 20000
            or not 6000 < coin['amount_sat'] <= 20000):
        raise ValueError('genuine20k board and actual signed customer value required')
    fee = 30000 - sum(btc_to_sat(v['value']) for v in tx['vout'])
    if not 0 < fee < 10000:
        raise ValueError('actual board fee exhausts declared principal/reserve')
    # Decode only the exact body already fully validated by verify_coin. This
    # catches the actual immutable exit delta that invalidated old002's refresh.
    token = hashlib.sha256(('absent:' + coin['id']).encode()).hexdigest()
    artifact = campaign.db.execute("SELECT * FROM native_artifact WHERE intent=? AND kind='stdout'",
                                   ('coin-raw-' + token,)).fetchone()
    if not artifact or artifact['truncated']:
        raise ValueError('complete authentic board body required')
    raw = campaign.root / artifact['relative_path']
    if digest(raw) != artifact['sha256']:
        raise ValueError('authentic board body changed')
    decoded = _private_call(campaign, 'fresh-board-geometry-' + str(_attempt(campaign, 'fresh-geometry')),
        'decode', [campaign.config['binary'], '--quiet', '--no-logfile', 'dev', 'vtxo', 'decode',
                   raw.read_text().strip()])
    if (decoded.get('exit_delta') != 12 or decoded.get('server_pubkey') != spec['server_pubkey']
            or any(decoded.get(k) != coin[k] for k in ['id', 'amount_sat', 'chain_anchor', 'expiry_height'])
            or not 18 < coin['expiry_height'] - network_identity(campaign.core)['height'] <= 32):
        raise ValueError('genuine short-exit12 signed board and18-block send headroom required')
    n = _attempt(campaign, 'fresh-board-change')
    native = _native(campaign, f'fresh-board-change-{n}', 'absent', 'onchain_utxos')
    others = {tx['txid'] + ':' + str(v['n']): v for v in tx['vout'] if v['n'] != anchor}
    owned = {v['outpoint']: v for v in native}
    if not others or set(owned) != set(others):
        raise ValueError('exact board change must be observed in native-owned BDK UTXOs')
    change = []
    for point, v in others.items():
        out = campaign.core.call('gettxout', tx['txid'], v['n'], True)
        amount = btc_to_sat(v['value'])
        if (owned[point]['amount_sat'] != amount or not out or out['confirmations'] < 3
                or btc_to_sat(out['value']) != amount
                or out['scriptPubKey']['hex'] != v['scriptPubKey']['hex']):
            raise ValueError('actual confirmed native-owned board change amount/script required')
        change.append({'outpoint': point, 'amount_sat': amount, 'script': v['scriptPubKey']['hex']})
    actual_anchor = btc_to_sat(outputs[anchor]['value'])
    actual_change = sum(v['amount_sat'] for v in change)
    pins = json.loads(campaign.db.execute("SELECT value FROM meta WHERE key='phase_runtime_pins'").fetchone()[0])
    quote = tomllib.loads((Path(pins['configuration_directory']) / 'captaind.toml').read_text()).get('fees', {}).get('board', {})
    if (set(quote) != {'min_fee_sat', 'base_fee_sat', 'ppm'}
            or any(type(v) is not int or v < 0 for v in quote.values())):
        raise ValueError('actual pinned public board fee components required')
    board_fee = max(quote['min_fee_sat'], quote['base_fee_sat'] +
                    (actual_anchor * quote['ppm'] + 999999) // 1000000)
    if (30000 != actual_anchor + actual_change + fee
            or actual_anchor != coin['amount_sat'] + board_fee):
        raise ValueError('exact gross/net board quote and native-owned change conservation required')
    return {'funded_sat': 30000, 'requested_board_sat': spec['board_amount_sat'],
        'actual_anchor_sat': actual_anchor,
        'actual_signed_exit_delta': 12,
        'signed_customer_sat': coin['amount_sat'],
        'carried_board_residual_sat': board_fee, 'advertised_board_fee_components': quote,
        'board_miner_fee_sat': fee, 'board_fee_above_warning_1000sat': fee > 1000,
        'ordinary_change_sat': actual_change, 'native_owned_change': change}

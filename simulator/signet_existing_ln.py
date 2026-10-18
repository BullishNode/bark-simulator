"""P09 admission of a real cold-copied sender; no funding or board substitute.

The historical c60c funded-board recipe remains separate. Existing-source mode
requires the coordinator's exact current runtime and terminal cohort receipts.
"""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import re
import tomllib

from .model import canonical, public_payload
from .signet import digest, network_identity
from .signet_phase import _native, _quiescent, _verify_runtime
from .signet_checks import confirmed_backing
from .signet_proof import verify_coin
from .signet_s02 import _save
from .signet_lightning import _attempt, _protected, _private_call

KIND = 'existing_native_refresh'
SHORT = {'vtxo_lifetime': 32, 'vtxo_exit_delta': 12, 'htlc_expiry_delta': 6,
         'htlc_send_expiry_delta': 18, 'max_htlc_expiry_delta': 288}


def failed_profile(campaign, spec):
    """Called only after the ordinary paired-runtime verification."""
    if spec.get('source_kind') != KIND:
        raise ValueError('explicit existing native source required')
    admission = Path(spec['financial_admission'])
    if digest(admission) != spec['financial_admission_sha256']:
        raise ValueError('existing-source coordinator admission changed')
    allowed = json.loads(admission.read_text())
    pins = json.loads(campaign.db.execute("SELECT value FROM meta WHERE key='phase_runtime_pins'").fetchone()[0])
    runtime = json.loads(Path(pins['runtime_manifest']).read_text())
    if (allowed.get('scope') != 'P09-existing-v11c'
            or allowed.get('runtime_manifest_sha256') != pins['runtime_manifest_sha256']
            or allowed.get('new_treasury_principal_sat') != 0
            or allowed.get('server_pubkey') != spec['server_pubkey']
            or allowed.get('database') != spec['database']
            or runtime.get('server_pubkey') != spec['server_pubkey']
            or allowed.get('terminal_result_sha256') != spec['terminal_result_sha256']
            or allowed.get('sender_actor') != spec['sender_actor']):
        raise ValueError('explicit same-candidate funded-inventory admission required')
    if digest(Path(spec['terminal_result'])) != spec['terminal_result_sha256']:
        raise ValueError('original terminal financial result changed')
    binding = {'directory': spec['sender_directory'], 'birthday_height': spec['birthday_height'],
               'configuration_sha256': spec['sender_config_sha256'],
               'inventory_sha256': hashlib.sha256(canonical(spec['prior_coins']).encode()).hexdigest(),
               'registration_sha256': spec['sender_registration_sha256'],
               'seed_sha256': spec['sender_seed_sha256']}
    if allowed.get('sender') != binding:
        raise ValueError('coordinator admission must bind exact cold sender inventory and source')
    cfg = tomllib.loads((Path(pins['configuration_directory']) / 'captaind.toml').read_text())
    if ({k: cfg.get(k) for k in SHORT} != SHORT
            or cfg.get('postgres', {}).get('name') != spec['database']
            or cfg.get('vtxopool', {}).get('vtxo_lifetime') != 32
            or cfg.get('vtxopool', {}).get('vtxo_pre_expiry') != 12
            or cfg.get('vtxopool', {}).get('vtxo_targets') != ['10000sat:2']):
        raise ValueError('explicit admitted short profile and real pool required')
    # The inherited144/12 ordinary config is retained unchanged. CLI opens have
    # run_daemon=false; refresh is an explicit one-shot native operation.
    path = campaign.actor_path('absent')
    if digest(path / 'config.toml') != spec['sender_config_sha256']:
        raise ValueError('cold original sender configuration changed')
    wallet = tomllib.loads((path / 'config.toml').read_text())
    if (wallet.get('server_address') != campaign.config['ark_url']
            or wallet.get('vtxo_exit_margin') != 12
            or wallet.get('htlc_recv_claim_delta', 18) != 18):
        raise ValueError('same-server manual sender and unchanged SDK margins required')
    return spec


def stage_failed_sender(campaign, runtime_pins, admission_path, terminal_result_path,
                        sender_directory, sender_actor, registration, original_coins,
                        birthday_height, source_path, recovery_destination):
    """Metadata/source import only; no native open, create, funding or board."""
    if campaign.db.execute('SELECT 1 FROM actor UNION SELECT 1 FROM action UNION SELECT 1 FROM result').fetchone():
        raise ValueError('new empty existing-source operation required')
    if not re.fullmatch(r'load-[0-9]{3}', sender_actor):
        raise ValueError('actual existing cohort actor required')
    terminal = json.loads(Path(terminal_result_path).read_text())
    money = terminal.get('result', {})
    if (terminal.get('status') != 'INCOMPLETE'
            or money.get('stage') != 'LOAD_INCOMPLETE_WINDOW_FINANCIALLY_AUDITED'
            or money.get('failed_or_unknown_transfers') != 0
            or money.get('closing_coin_sat', -1) + money.get('observed_offchain_fee_sat', -1) != money.get('opening_coin_sat')
            or money.get('backing', {}).get('backing') != 'PASS'
            or not money.get('signature_proofs')
            or any(p.get('status') != 'PASS' for p in money['signature_proofs'])):
        raise ValueError('actual terminal financially audited cohort required')
    live = [c for c in original_coins if c['state'] == 'spendable']
    if (not live or len({c['id'] for c in original_coins}) != len(original_coins)
            or any(c['state'] not in {'spent', 'spendable'} for c in original_coins)
            or sum(c['amount_sat'] for c in live) <= 6000):
        raise ValueError('real settled existing sender inventory and headroom required')
    path = Path(sender_directory).absolute()
    if path.is_symlink() or not path.is_dir():
        raise ValueError('actual exclusively cold-copied sender directory required')
    phrase = _protected(source_path)
    chain = network_identity(campaign.core)
    if type(birthday_height) is not int or not 0 <= birthday_height <= chain['height']:
        raise ValueError('original recorded birthday required')
    if registration.get('network') != 'signet':
        raise ValueError('actual authenticated original Signet registration required')
    for address, expected in [(registration['payout_address'], registration['record']['spk']),
                              (recovery_destination, None)]:
        actual = campaign.core.call('validateaddress', address)
        if actual.get('isvalid') is not True or (expected and actual.get('scriptPubKey') != expected):
            raise ValueError('original payout and owned recovery scripts required')
    admission = json.loads(Path(admission_path).read_text())
    spec = {'source_kind': KIND, 'sender_directory': str(path), 'sender_actor': sender_actor,
            'sender_config_sha256': digest(path / 'config.toml'),
            'server_pubkey': admission['server_pubkey'], 'database': admission['database'],
            'birthday_height': birthday_height, 'recovery_destination': recovery_destination,
            'financial_admission': str(Path(admission_path).absolute()),
            'financial_admission_sha256': digest(Path(admission_path)),
            'terminal_result': str(Path(terminal_result_path).absolute()),
            'terminal_result_sha256': digest(Path(terminal_result_path)),
            'sender_registration_sha256': hashlib.sha256(canonical(registration).encode()).hexdigest(),
            'sender_seed_sha256': hashlib.sha256(phrase).hexdigest(),
            'prior_coins': original_coins,
            'prior_spendable_sat': sum(c['amount_sat'] for c in live)}
    public_payload(registration)
    campaign.db.execute('BEGIN IMMEDIATE')
    try:
        campaign.db.execute("INSERT INTO meta VALUES ('failed_send',?)", (canonical(spec),))
        campaign.db.execute("INSERT INTO meta VALUES ('phase_runtime_pins',?)", (canonical(runtime_pins),))
        campaign.db.execute("INSERT INTO meta VALUES ('failed_sender_registration',?)", (canonical(registration),))
        campaign.db.execute("INSERT INTO meta VALUES ('existing_wallet_config:absent',?)", (spec['sender_config_sha256'],))
        campaign.db.execute("INSERT INTO actor VALUES ('absent',0)")
        _verify_runtime(campaign)
        failed_profile(campaign, spec)
        campaign._retain_private('s02-recovery-source-absent', 'source', io.BytesIO(phrase))
        campaign.db.execute('COMMIT')
    except BaseException:
        if campaign.db.in_transaction:
            campaign.db.execute('ROLLBACK')
        raise
    return _save(campaign, 'existing-send-stage', {
        'kind': 'existing_failed_sender', 'stage': 'STAGED_EXISTING_INVENTORY_NO_NATIVE_OPEN',
        'existing_actor': sender_actor, 'original_spendable_sat': spec['prior_spendable_sat'],
        'original_birthday': birthday_height, 'case_verdict': 'INCOMPLETE',
        'new_actor_principal_sat': 0, 'native_create_or_board': False})



def _preflight_refresh_window(campaign, coins, spec):
    """Reject a known incompatible profile before the first refresh intent.

    This necessary window check does not replace the native check against the
    actual signed replacement after confirmation, including elapsed round time.
    """
    chain = network_identity(campaign.core)
    info = _native(campaign, 'existing-refresh-compatibility-info', 'absent', 'ark_info')
    lifetime = info.get('vtxo_lifetime')
    wallet = tomllib.loads((campaign.actor_path('absent') / 'config.toml').read_text())
    margin = wallet.get('vtxo_exit_margin')
    if (info.get('server_pubkey') != spec['server_pubkey']
            or type(lifetime) is not int or lifetime <= 0
            or type(margin) is not int or not 0 <= margin <= 65535):
        raise ValueError('actual server lifetime and unchanged native wallet margin required')
    live = [coin for coin in coins if coin['state'] == 'spendable']
    if not live:
        raise ValueError('actual signed refresh inputs required before first intent')
    deltas = []
    for coin in live:
        proof = verify_coin(campaign, 'absent', coin)
        if proof.get('status') != 'PASS' or not proof.get('path_outpoints'):
            raise ValueError('full signed original input proof required before refresh')
        token = hashlib.sha256(('absent:' + coin['id']).encode()).hexdigest()
        artifact = campaign.db.execute("SELECT * FROM native_artifact WHERE intent=? AND kind='stdout'",
                                      ('coin-raw-' + token,)).fetchone()
        if not artifact or artifact['truncated']:
            raise ValueError('complete verified original input body required before refresh')
        raw = campaign.root / artifact['relative_path']
        if digest(raw) != artifact['sha256']:
            raise ValueError('verified original input body changed before refresh')
        decoded = _private_call(campaign, 'refresh-geometry-' + token, 'decode',
            [campaign.config['binary'], '--quiet', '--no-logfile', 'dev', 'vtxo', 'decode',
             raw.read_text().strip()])
        delta = decoded.get('exit_delta')
        if (decoded.get('server_pubkey') != spec['server_pubkey']
                or any(decoded.get(k) != coin[k] for k in
                       ['id', 'amount_sat', 'user_pubkey', 'chain_anchor', 'expiry_height'])
                or type(delta) is not int or not 0 <= delta <= 65535):
            raise ValueError('actual signed input identity and CSV required before refresh')
        deltas.append(delta)
    maximum = max(deltas)
    required = 2 * margin + maximum
    # Match upstream: if ANY input is unexpired, MAX includes ALL inputs.
    unexpired = any(coin['expiry_height'] > chain['height'] for coin in live)
    compatible = not unexpired or lifetime >= required
    if network_identity(campaign.core) != chain:
        raise ValueError('chain changed during pre-refresh compatibility observation')
    result = _save(campaign, 'existing-refresh-compatibility', {
        'kind': 'existing_refresh_compatibility', 'case_verdict': 'INCOMPLETE',
        'chain': chain, 'compatible': compatible,
        'advertised_lifetime_blocks': lifetime, 'wallet_exit_margin_blocks': margin,
        'maximum_actual_input_csv_blocks': maximum,
        'minimum_output_window_blocks': required, 'any_unexpired_input': unexpired,
        'scope': 'Necessary pre-intent check only; native signed-output/confirmation guard remains authoritative.'})
    if not compatible:
        raise ValueError(f'cannot refresh before intent: advertised lifetime {lifetime} < '
                         f'2 * wallet exit margin {margin} + maximum actual input CSV {maximum} '
                         f'= {required}; no refresh submitted')
    return result


def refresh_existing_sender(campaign):
    """One genuine native refresh; an unconfirmed round only needs observation."""
    from .signet_failed_send import _profile
    spec = _profile(campaign)
    if spec.get('source_kind') != KIND:
        raise ValueError('existing source operation required; never a board substitute')
    _quiescent(campaign)
    before = _native(campaign, 'existing-source-before', 'absent', 'sync_vtxos')
    if sorted(before, key=lambda c: c['id']) != sorted(spec['prior_coins'], key=lambda c: c['id']):
        raise ValueError('real current sender differs from cold terminal inventory')
    record = _native(campaign, 'existing-source-registration', 'absent', 'fallback_record')
    expected = json.loads(campaign.db.execute("SELECT value FROM meta WHERE key='failed_sender_registration'").fetchone()[0])
    if record != expected:
        raise ValueError('original authenticated registration changed')
    if not campaign.db.execute("SELECT 1 FROM action WHERE id='existing-source-refresh'").fetchone():
        _preflight_refresh_window(campaign, before, spec)
    # Campaign never replays any dispatched/unknown native intent, including
    # a refresh whose reply was lost after the actual forfeit was accepted.
    _native(campaign, 'existing-source-refresh', 'absent', 'refresh')
    n = _attempt(campaign, 'existing-source-ready')
    chain = network_identity(campaign.core)
    coins = _native(campaign, f'existing-source-after-{n}', 'absent', 'sync_vtxos')
    live = [c for c in coins if c['state'] == 'spendable']
    old_ids = {c['id'] for c in spec['prior_coins'] if c['state'] == 'spendable'}
    prior = {c['id']: c for c in spec['prior_coins']}
    # The native refresh ACK can precede round completion. Keep observing the
    # original locked inputs; an ACK is neither a new coin nor permission to
    # submit another refresh. Only exact unchanged input bodies may wait here.
    if (len(coins) == len(prior) and {c['id'] for c in coins} == set(prior)
            and any(c['state'] == 'locked' for c in coins)
            and all({k: v for k, v in c.items() if k != 'state'} ==
                    {k: v for k, v in prior[c['id']].items() if k != 'state'}
                    and (c['state'] in {'spendable', 'locked', 'spent'}
                         if c['id'] in old_ids else c['state'] == prior[c['id']]['state'])
                    for c in coins)):
        return _save(campaign, 'existing-source-pending', {
            'kind': 'existing_failed_sender', 'stage': 'WAITING_FOR_NATIVE_REFRESH_COMPLETION',
            'chain': chain, 'locked_input_ids': sorted(c['id'] for c in coins if c['state'] == 'locked'),
            'native_refresh_ack_retained': True, 'case_verdict': 'INCOMPLETE'})
    if (any(c['state'] not in {'spent', 'spendable'} for c in coins)
            or len(live) != 1 or live[0]['id'] in old_ids
            or not old_ids.issubset({c['id'] for c in coins})
            or any(c['id'] in old_ids and c['state'] != 'spent' for c in coins)):
        raise ValueError('actual completed refreshed source required; no synthetic READY')
    coin = live[0]
    if not 18 < coin['expiry_height'] - chain['height'] <= 32:
        raise ValueError('actual new short-tree source and D<E headroom required')
    if not 6000 < coin['amount_sat'] <= spec['prior_spendable_sat']:
        raise ValueError('actual signed refresh value and payment headroom required')
    anchor, vout = coin['chain_anchor'].split(':')
    output = campaign.core.call('gettxout', anchor, int(vout), True)
    if output is None:
        raise ValueError('actual new round backing unavailable')
    if output['confirmations'] < 1:
        return _save(campaign, 'existing-source-wait', {
            'kind': 'existing_failed_sender', 'stage': 'WAITING_FOR_REAL_ROUND_CONFIRMATION',
            'chain': chain, 'coin_id': coin['id'], 'round_anchor': coin['chain_anchor'],
            'actual_tree_expiry': coin['expiry_height'], 'native_refresh_ack_retained': True,
            'case_verdict': 'INCOMPLETE'})
    proof = verify_coin(campaign, 'absent', coin)
    if proof.get('status') != 'PASS' or not proof.get('path_outpoints'):
        raise ValueError('actual new round native full signature proof required')
    backing = confirmed_backing(campaign.core, [coins])
    if network_identity(campaign.core) != chain:
        raise ValueError('chain changed while observing refreshed source; no money replay')
    return _save(campaign, 'failed-send-ready', {
        'kind': 'failed_send_ready', 'stage': 'ACTUAL_NATIVE_SOURCE_READY_NO_INVOICE',
        'source_kind': KIND, 'minimum_confirmations': 1, 'case_verdict': 'INCOMPLETE',
        'chain': chain, 'coin': coin, 'signature_proof': proof, 'backing': backing,
        'actual_tree_expiry': coin['expiry_height'],
        'provisional_send_deadline_if_dispatched_now': chain['height'] + 18,
        'original_spendable_sat': spec['prior_spendable_sat'],
        'observed_refresh_fee_sat': spec['prior_spendable_sat'] - coin['amount_sat'],
        'native_board_ack_fabricated': False})

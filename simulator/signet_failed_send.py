"""Bounded native failed-send campaign, using an already created owned wallet.

This phase stages genuine cached receipts and boards once. It never creates a
wallet, fabricates an initialization ACK, issues an invoice or sends Lightning.
The separately admitted next phase must preserve this journal and source pins.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tomllib

from .model import btc_to_sat, canonical, public_payload
from .signet import Campaign, digest, network_identity
from .signet_phase import _native, _quiescent, _verify_runtime
from .signet_proof import verify_coin
from .signet_s02 import _save
from .signet_lightning import _protected, _private_call, _attempt, _varint


class FailedSendCampaign(Campaign):
    """Bind only this owned original actor; recovery keeps its new empty DB."""

    def actor_path(self, actor):
        default = super().actor_path(actor)
        if actor != 'absent':
            return default
        row = self.db.execute("SELECT value FROM meta WHERE key='failed_send'").fetchone()
        if not row:
            return default
        path = Path(json.loads(row[0])['sender_directory'])
        if not path.is_absolute() or path.is_symlink() or not path.is_dir():
            raise ValueError('original real sender directory required')
        return path


def hold_invoice_frame(payment_hash):
    """Exact existing hold0.3.3 Invoice; stock CLI defaults CLTV80 instead."""
    if not isinstance(payment_hash, str) or not re.fullmatch('[0-9a-f]{64}', payment_hash):
        raise ValueError('original 32-byte payment hash required')
    memo = b'Native failed external send qualification'
    body = (b'\x0a\x20' + bytes.fromhex(payment_hash) + b'\x10' + _varint(5_000_000)
            + b'\x1a' + _varint(len(memo)) + memo
            + b'\x28' + _varint(3600) + b'\x30\x06')
    return b'\0' + len(body).to_bytes(4, 'big') + body


def _profile(campaign):
    row = campaign.db.execute("SELECT value FROM meta WHERE key='failed_send'").fetchone()
    if not row:
        raise ValueError('separate failed-send staging required')
    spec = json.loads(row[0])
    _verify_runtime(campaign)
    for field in ['funding_request', 'funding_receipt', 'financial_admission']:
        if digest(Path(spec[field])) != spec[field + '_sha256']:
            raise ValueError('retained original admission/funding receipt changed')
    pins = json.loads(campaign.db.execute("SELECT value FROM meta WHERE key='phase_runtime_pins'").fetchone()[0])
    request = json.loads(Path(spec['funding_request']).read_text())
    runtime = json.loads(Path(pins['runtime_manifest']).read_text())
    if (digest(Path(pins['runtime_manifest'])) != request['runtime_manifest_sha256']
            or pins['config_hashes'] != request['config_sha256']
            or pins['elf_sha256'] != request['elf_sha256']
            or runtime.get('server_pubkey') != spec['server_pubkey']
            or runtime.get('source_manifest_sha256') != request['source_manifest_sha256']):
        raise ValueError('actual paired runtime must bind original funded profile')
    cfg = tomllib.loads((Path(pins['configuration_directory']) / 'captaind.toml').read_text())
    expected = {'vtxo_lifetime': 32, 'vtxo_exit_delta': 12, 'htlc_send_expiry_delta': 18,
                'max_htlc_expiry_delta': 288, 'htlc_expiry_delta': 6}
    if ({k: cfg.get(k) for k in expected} != expected
            or cfg.get('vtxopool', {}).get('vtxo_targets') != []
            or cfg.get('postgres', {}).get('name') != spec['database']):
        raise ValueError('actual separate18/32 empty-pool configuration required')
    path = campaign.actor_path('absent')
    if digest(path / 'config.toml') != spec['sender_config_sha256']:
        raise ValueError('original sender configuration changed')
    actual = tomllib.loads((path / 'config.toml').read_text())
    if (actual.get('server_address') != campaign.config['ark_url']
            or actual.get('vtxo_refresh_expiry_threshold') != 12
            or actual.get('vtxo_exit_margin') != 12
            or actual.get('htlc_recv_claim_delta') != 18):
        raise ValueError('actual original manual-sync sender profile required')
    return spec


def stage(campaign, request_path, receipt_path, admission_path, runtime_pins,
          registration_path, source_path, recovery_destination):
    """Import actual cached registration/source, without any native wallet open."""
    if campaign.db.execute('SELECT 1 FROM actor UNION SELECT 1 FROM action UNION SELECT 1 FROM result').fetchone():
        raise ValueError('new empty failed-send campaign required')
    request = json.loads(Path(request_path).read_text())
    receipt = json.loads(Path(receipt_path).read_text())
    registration = json.loads(Path(registration_path).read_text())
    source = _protected(source_path)
    if (request.get('allocation_sat') != 100000 or request.get('funding_dispatched') is not False
            or request.get('network') != 'signet' or receipt.get('network') not in {'signet', 'public signet'}
            or request['source_manifest_sha256'] != 'c60c5cd4c9d8cc0fbeaa8f8f6a71ba4102a46075cd2d9515fb505d9ba2dc882b'):
        raise ValueError('original selected funding/source proposal required')
    if (receipt.get('request_sha256') != digest(Path(request_path))
            or not re.fullmatch('[0-9a-f]{64}', receipt.get('txid', ''))):
        raise ValueError('original root funding receipt must bind exact request')
    amounts = {'sender': 60000, 'watchman_fee_0': 20000, 'watchman_fee_1': 20000}
    if (set(request['outputs']) != set(amounts)
            or any(request['outputs'][role]['amount_sat'] != amount for role, amount in amounts.items())
            or len({r['script'] for r in request['outputs'].values()}) != 3):
        raise ValueError('exact distinct100k sender/watchman allocation required')
    sender = request['sender']
    if (digest(Path(registration_path)) != sender['registration_receipt_sha256']
            or hashlib.sha256(canonical(registration).encode()).hexdigest() != sender['registration_canonical_sha256']
            or registration.get('network') != 'signet'
            or registration['record']['spk'] != sender['authenticated_payout_script']):
        raise ValueError('actual authenticated original sender record required')
    chain = network_identity(campaign.core)
    if type(sender['original_birthday_height']) is not int or sender['original_birthday_height'] > chain['height']:
        raise ValueError('original pre-funding birthday required')
    for address, expected in [(registration['payout_address'], registration['record']['spk']),
                              (recovery_destination, None)]:
        result = campaign.core.call('validateaddress', address)
        if result.get('isvalid') is not True or (expected and result.get('scriptPubKey') != expected):
            raise ValueError('actual payout/recovery address required')
    spec = {'sender_directory': sender['wallet_directory'],
            'sender_config_sha256': sender['configuration_sha256'],
            'server_pubkey': request['server_pubkey'], 'birthday_height': sender['original_birthday_height'],
            'database': request['database'], 'recovery_destination': recovery_destination,
            **{key: str(Path(value).absolute()) for key, value in
               [('funding_request', request_path), ('funding_receipt', receipt_path),
                ('financial_admission', admission_path)]}}
    spec.update({key + '_sha256': digest(Path(spec[key]))
                 for key in ['funding_request', 'funding_receipt', 'financial_admission']})
    campaign.db.execute('BEGIN IMMEDIATE')
    try:
        campaign.db.execute("INSERT INTO meta VALUES ('failed_send',?)", (canonical(spec),))
        campaign.db.execute("INSERT INTO meta VALUES ('phase_runtime_pins',?)", (canonical(runtime_pins),))
        campaign.db.execute("INSERT INTO meta VALUES ('failed_sender_registration',?)", (canonical(registration),))
        campaign.db.execute("INSERT INTO meta VALUES ('existing_wallet_config:absent',?)", (spec['sender_config_sha256'],))
        campaign.db.execute("INSERT INTO actor VALUES ('absent',0)")
        _profile(campaign)
        campaign._retain_private('s02-recovery-source-absent', 'source', io.BytesIO(source))
        campaign.db.execute('COMMIT')
    except BaseException:
        if campaign.db.in_transaction:
            campaign.db.execute('ROLLBACK')
        raise
    return _save(campaign, 'failed-send-stage', {
        'kind': 'native_failed_external_send', 'stage': 'STAGED_EXISTING_REAL_SENDER_NO_NATIVE_OPEN',
        'case_verdict': 'INCOMPLETE', 'chain': chain,
        'scope': 'Cached actual registration and original phrase only; no create ACK or Lightning action invented.'})


def funding_admission(campaign):
    spec = _profile(campaign)
    request = json.loads(Path(spec['funding_request']).read_text())
    receipt = json.loads(Path(spec['funding_receipt']).read_text())
    chain = network_identity(campaign.core)
    txid = receipt['txid']
    tx = campaign.core.call('getrawtransaction', txid, True)
    count = tx.get('confirmations', 0)
    if type(count) is not int or count < 1:
        return {'kind': 'failed_send_funding', 'stage': 'WAITING_FOR_REAL_FUNDING_CONFIRMATION',
                'case_verdict': 'INCOMPLETE', 'chain': chain, 'txid': txid, 'confirmations': count}
    height = chain['height'] - count + 1
    if tx.get('txid') != txid or campaign.core.call('getblockhash', height) != tx.get('blockhash'):
        raise ValueError('canonical original funding transaction required')
    targets = request['outputs']
    outputs, watchpoints = {}, []
    for role, expected in targets.items():
        matches = [v for v in tx['vout'] if v['scriptPubKey']['hex'] == expected['script']
                   and btc_to_sat(v['value']) == expected['amount_sat']]
        if len(matches) != 1:
            raise ValueError('funding output differs from original role/script/amount')
        output = matches[0]
        point = txid + ':' + str(output['n'])
        # A recorded board may have spent sender funding. Never treat that as
        # permission to reconstruct its missing/unknown original action.
        unspent = campaign.core.call('gettxout', txid, output['n'], True)
        if role.startswith('watchman_'):
            if not unspent or unspent['confirmations'] < 1:
                raise ValueError('confirmed usable original watchman inputs required')
            watchpoints.append(point)
        elif not unspent and not campaign.db.execute("SELECT 1 FROM action WHERE id='failed-send-board' AND state='acknowledged'").fetchone():
            raise ValueError('sender funding spent without acknowledged original board; reconcile')
        outputs[role] = {'outpoint': point, 'amount_sat': expected['amount_sat'], 'script': expected['script']}
    pins = json.loads(campaign.db.execute("SELECT value FROM meta WHERE key='phase_runtime_pins'").fetchone()[0])
    n = _attempt(campaign, 'failed-funding')
    wallet = _private_call(campaign, f'failed-funding-{n}', 'watch-wallet',
        [str(Path(pins['binary_directory']) / 'captaind'), 'rpc', '--addr',
         'http://127.0.0.1:4586', 'wallet'])['watchman']
    if (wallet['trusted_balance'] < 40000
            or not set(watchpoints).issubset(wallet['confirmed_utxos'])):
        raise ValueError('actual native watchman wallet lacks selected confirmed fee funds')
    if network_identity(campaign.core) != chain:
        raise ValueError('chain changed during actual funding admission')
    return _save(campaign, 'failed-send-funding', {'kind': 'failed_send_funding',
        'stage': 'ACTUAL_FUNDING_CONFIRMED', 'case_verdict': 'INCOMPLETE',
        'chain': chain, 'txid': txid, 'confirmations': count, 'outputs': outputs,
        'native_watchman_trusted_sat': wallet['trusted_balance']})


def board_once(campaign):
    _quiescent(campaign)
    funding = funding_admission(campaign)
    if funding['stage'] != 'ACTUAL_FUNDING_CONFIRMED':
        return funding
    reply = _native(campaign, 'failed-send-board', 'absent', 'board', {'amount_sat': 30000})
    return _save(campaign, 'failed-send-board', {'kind': 'failed_send_board',
        'stage': 'BOARD_ACK_WAITING_FOR_THREE_CONFIRMATIONS', 'case_verdict': 'INCOMPLETE',
        'receipt': reply, 'chain': network_identity(campaign.core)})


def board_ready(campaign):
    spec = _profile(campaign)
    _quiescent(campaign)
    row = campaign.db.execute("SELECT reply FROM action WHERE id='failed-send-board' AND state='acknowledged'").fetchone()
    if not row:
        raise ValueError('original acknowledged board required')
    board = json.loads(row[0])
    chain = network_identity(campaign.core)
    tx = campaign.core.call('getrawtransaction', board['funding_txid'], True)
    confirmations = tx.get('confirmations', 0)
    if type(confirmations) is not int or confirmations < 3:
        return _save(campaign, 'failed-send-ready', {'kind': 'failed_send_ready',
            'stage': 'WAITING_FOR_REAL_THREE_BOARD_CONFIRMATIONS', 'case_verdict': 'INCOMPLETE',
            'chain': chain, 'confirmations': confirmations})
    if (tx.get('txid') != board['funding_txid']
            or campaign.core.call('getblockhash', chain['height'] - confirmations + 1) != tx.get('blockhash')):
        raise ValueError('original board must be canonical before original wallet opens')
    n = _attempt(campaign, 'failed-board-ready')
    info = _native(campaign, f'failed-board-info-{n}', 'absent', 'ark_info')
    if info['server_pubkey'] != spec['server_pubkey'] or info['htlc_send_expiry_delta'] != 18:
        raise ValueError('actual sender SDK handshake differs from new profile')
    coins = _native(campaign, f'failed-board-coins-{n}', 'absent', 'sync_vtxos')
    spendable = [c for c in coins if c['state'] == 'spendable']
    if len(spendable) != 1 or any(c['state'] not in ['spendable', 'spent'] for c in coins):
        raise ValueError('one actual settled source coin required')
    coin = spendable[0]
    if coin['chain_anchor'].split(':')[0] != board['funding_txid'] or coin['expiry_height'] - chain['height'] <= 18:
        raise ValueError('actual board backing and D<E short-profile headroom required')
    proof = verify_coin(campaign, 'absent', coin)
    if proof.get('status') != 'PASS' or not proof.get('path_outpoints'):
        raise ValueError('authentic full board signature/backing proof required')
    if network_identity(campaign.core) != chain:
        raise ValueError('chain changed during actual board readiness')
    result = {'kind': 'failed_send_ready', 'stage': 'ACTUAL_NATIVE_SOURCE_READY_NO_INVOICE',
              'case_verdict': 'INCOMPLETE', 'chain': chain, 'coin': coin, 'signature_proof': proof,
              'actual_tree_expiry': coin['expiry_height'], 'provisional_send_deadline_if_dispatched_now': chain['height'] + 18,
              'scope': 'Actual native admitted board; no Lightning send, held HTLC or failed refund yet.'}
    public_payload(result)
    return _save(campaign, 'failed-send-ready', result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    commands = parser.add_subparsers(dest='operation', required=True)
    start = commands.add_parser('stage')
    for name in ['funding-request', 'funding-receipt', 'financial-admission', 'runtime-pins', 'registration', 'source']:
        start.add_argument('--' + name, type=Path, required=True)
    start.add_argument('--recovery-destination', required=True)
    for name in ['funding', 'board', 'ready']:
        commands.add_parser(name)
    args = parser.parse_args()
    campaign = FailedSendCampaign(args.state, json.loads(args.config.read_text()))
    try:
        with (campaign.root / 'failed-send.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.operation == 'stage':
                result = stage(campaign, args.funding_request, args.funding_receipt, args.financial_admission,
                               json.loads(args.runtime_pins.read_text()), args.registration, args.source,
                               args.recovery_destination)
            elif args.operation == 'board':
                result = board_once(campaign)
            elif args.operation == 'ready':
                result = board_ready(campaign)
            else:
                result = funding_admission(campaign)
            print(canonical(result))
    finally:
        campaign.close()


if __name__ == '__main__':
    main()

"""Bounded native failed-send campaign, using an already created owned wallet.

Native actions use the actual already-created wallet. External mutations are
journaled once; uncertainty never authorizes replay. This is native Lightning
evidence only, not Noah or LNURL compatibility.
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
import sqlite3
import subprocess
import tempfile
import time
import tomllib

from .model import btc_to_sat, canonical, public_payload
from .signet import Campaign, digest, network_identity
from .signet_phase import _native, _quiescent, _verify_runtime
from .signet_proof import verify_coin
from .signet_s02 import _save, _freeze, observe_payout, check_recovery
from .signet_discovery import discover_payouts
from .signet_repair import _fee_child
from .signet_lightning import (_protected, _private_call, _attempt, _varint,
                              _once, _cln, validate_invoice, POINT)


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


def prepare_lightning(campaign, manifest_path, tls_directory):
    """Read/pin existing CLN/hold transport; create no invoice or payment."""
    _profile(campaign)
    path = Path(manifest_path).absolute()
    tls = Path(tls_directory).absolute()
    manifest = json.loads(path.read_text())
    cli = [p for p in manifest['executable_sha256'] if Path(p).name == 'lightning-cli']
    if len(cli) != 1 or set(manifest['nodes']) != {'internal', 'external'}:
        raise ValueError('exact existing two owned CLN peers required')
    if (not tls.is_absolute() or tls.is_symlink()
            or any(not (tls / f).is_file() or (tls / f).is_symlink()
                   for f in ['ca.pem', 'client.pem', 'client-key.pem'])):
        raise ValueError('existing owned external hold mTLS files required')
    spec = {'manifest': str(path), 'manifest_sha256': digest(path),
            'cln_binary': cli[0], 'cln_binary_sha256': manifest['executable_sha256'][cli[0]],
            'directory': str(tls.parent.parent), 'tls_directory': str(tls),
            'tls_sha256': {f: digest(tls / f) for f in ['ca.pem', 'client.pem', 'client-key.pem']},
            'internal_id': manifest['nodes']['internal']['id'],
            'external_id': manifest['nodes']['external']['id'],
            'hold_port': manifest['nodes']['external']['ports'][2]}
    if not 1 <= spec['hold_port'] <= 65535:
        raise ValueError('owned external hold port required')
    old = campaign.db.execute("SELECT value FROM meta WHERE key='failed_send_ln'").fetchone()
    if old:
        if json.loads(old[0]) != spec:
            raise ValueError('original transport pins changed')
        _transport(campaign)
        return {'kind': 'failed_send_transport', 'stage': 'EXISTING_STOCK_TRANSPORT_PINNED_NO_INVOICE',
                'case_verdict': 'INCOMPLETE', 'manifest_sha256': spec['manifest_sha256'],
                'internal_id': spec['internal_id'], 'external_id': spec['external_id'],
                'financial_mutation': False}
    for filename, expected in manifest['executable_sha256'].items():
        if digest(Path(filename)) != expected:
            raise ValueError('actual stock CLN/hold executable changed')
    # Fix the original hash before the invoice DISPATCHED action. The secret
    # stays in one private artifact and is never a public result field.
    preimage = os.urandom(32)
    campaign._retain_private('failed-send-hold', 'preimage', io.BytesIO(preimage))
    campaign.db.execute("INSERT INTO meta VALUES ('failed_send_hash',?)",
                        (hashlib.sha256(preimage).hexdigest(),))
    campaign.db.execute("INSERT INTO meta VALUES ('failed_send_ln',?)", (canonical(spec),))
    return _save(campaign, 'failed-ln-transport', {'kind': 'failed_send_transport',
        'stage': 'EXISTING_STOCK_TRANSPORT_PINNED_NO_INVOICE', 'case_verdict': 'INCOMPLETE',
        'manifest_sha256': spec['manifest_sha256'], 'internal_id': spec['internal_id'],
        'external_id': spec['external_id'], 'financial_mutation': False})


def _transport(campaign):
    row = campaign.db.execute("SELECT value FROM meta WHERE key='failed_send_ln'").fetchone()
    if not row:
        raise ValueError('existing stock transport must be pinned first')
    spec = json.loads(row[0])
    if digest(Path(spec['manifest'])) != spec['manifest_sha256']:
        raise ValueError('original CLN manifest changed')
    manifest = json.loads(Path(spec['manifest']).read_text())
    if any(digest(Path(p)) != h for p, h in manifest['executable_sha256'].items()):
        raise ValueError('actual stock CLN/hold executable changed')
    if any(digest(Path(spec['tls_directory']) / f) != h for f, h in spec['tls_sha256'].items()):
        raise ValueError('original mTLS files changed')
    return spec


def _peer(campaign, spec, role, intent, kind, *args):
    directory = Path(spec['directory']).parent / role
    return _cln(campaign, {**spec, 'cln_directory': str(directory)}, intent, kind, *args)


def _lightning_ready(campaign):
    spec = _transport(campaign)
    chain = network_identity(campaign.core)
    n = _attempt(campaign, 'failed-peer')
    for role in ['internal', 'external']:
        info = _peer(campaign, spec, role, f'failed-peer-{n}-{role}', 'info', 'getinfo')
        if (info.get('id') != spec[role + '_id'] or info.get('network') != 'signet'
                or info.get('version') != 'v26.06.6' or info.get('blockheight') != chain['height']):
            raise ValueError('actual original stock CLN identity/version/sync required')
        channels = _peer(campaign, spec, role, f'failed-peer-{n}-{role}', 'channels', 'listpeerchannels')['channels']
        wanted = spec['external_id' if role == 'internal' else 'internal_id']
        matches = [c for c in channels if c.get('peer_id') == wanted and c.get('state') == 'CHANNELD_NORMAL'
                   and c.get('private') is True]
        amount = 'spendable_msat' if role == 'internal' else 'receivable_msat'
        if len(matches) != 1 or matches[0][amount] < 5_000_000:
            raise ValueError('actual own private channel outbound liquidity required')
    if network_identity(campaign.core) != chain:
        raise ValueError('chain changed during original peer admission')
    return spec


def _ready_source(campaign):
    _profile(campaign)
    row = campaign.db.execute("SELECT payload FROM result WHERE json_extract(payload,'$.kind')='failed_send_ready' "
        "AND json_extract(payload,'$.stage')='ACTUAL_NATIVE_SOURCE_READY_NO_INVOICE' ORDER BY observed DESC LIMIT 1").fetchone()
    if not row:
        raise ValueError('actual native source readiness proof required')
    ready = json.loads(row[0])
    chain = network_identity(campaign.core)
    coin = ready['coin']
    txid, index = coin['chain_anchor'].split(':')
    output = campaign.core.call('gettxout', txid, int(index), True)
    if (not output or output['confirmations'] < 3
            or coin['expiry_height'] - chain['height'] <= 18):
        raise ValueError('real source backing and D<E headroom no longer available')
    return ready


def _capture(campaign, intent, kind, argv, *, input_bytes=None, timeout=150):
    environment = {k: v for k, v in os.environ.items() if not k.startswith('BARK_')}
    try:
        result = subprocess.run(argv, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=environment, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as error:
        campaign._retain_private(intent, kind + '-stdout', io.BytesIO(error.stdout or b''))
        campaign._retain_private(intent, kind + '-stderr', io.BytesIO(error.stderr or b''))
        raise
    campaign._retain_private(intent, kind + '-stdout', io.BytesIO(result.stdout))
    campaign._retain_private(intent, kind + '-stderr', io.BytesIO(result.stderr))
    if result.returncode or len(result.stdout) > 4 * 1024 * 1024:
        raise ValueError('original private subprocess failed; reconcile without replay')
    return result.stdout


def decode_hold_invoice(raw, headers):
    """One successful gRPC response, one complete original BOLT11 field."""
    lines = [line.lower().strip() for line in headers.splitlines()]
    if (b'http/2 200' not in lines or lines.count(b'grpc-status: 0') != 1
            or any(line.startswith(b'grpc-status:') and line != b'grpc-status: 0' for line in lines)
            or len(raw) > 65536 or len(raw) < 7 or raw[0] != 0
            or int.from_bytes(raw[1:5], 'big') != len(raw) - 5 or raw[5] != 10):
        raise ValueError('successful original uncompressed hold Invoice response required')
    pos, length = 6, 0
    for shift in range(0, 35, 7):
        if pos >= len(raw):
            raise ValueError('truncated original invoice length')
        byte = raw[pos]
        pos += 1
        length |= (byte & 127) << shift
        if byte < 128:
            break
    else:
        raise ValueError('oversized original invoice length')
    if not 1 <= length <= 20000 or len(raw) - pos != length:
        raise ValueError('exact original invoice bytes required')
    invoice = raw[pos:].decode('ascii')
    if not invoice.startswith('lntbs'):
        raise ValueError('original public Signet BOLT11 required')
    return invoice


def issue_hold_invoice(campaign):
    _quiescent(campaign)
    _ready_source(campaign)
    spec = _lightning_ready(campaign)
    payment_hash = campaign.db.execute("SELECT value FROM meta WHERE key='failed_send_hash'").fetchone()[0]
    def dispatch():
        prior = _peer(campaign, spec, 'external', 'failed-send-hold-invoice', 'prior',
                      'listholdinvoices', 'payment_hash=' + payment_hash)
        if prior.get('holdinvoices') != []:
            raise ValueError('original hold hash already exists; reconcile without replacement')
        frame = hold_invoice_frame(payment_hash)
        campaign._retain_private('failed-send-hold-invoice', 'request-frame', io.BytesIO(frame))
        tls = Path(spec['tls_directory'])
        with tempfile.TemporaryDirectory(dir=campaign.root) as directory:
            headers = Path(directory) / 'headers'
            argv = ['curl', '--silent', '--show-error', '--http2', '--noproxy', '*',
                    '--max-redirs', '0', '--max-time', '30', '--cacert', str(tls / 'ca.pem'),
                    '--cert', str(tls / 'client.pem'), '--key', str(tls / 'client-key.pem'),
                    '-H', 'content-type: application/grpc', '-H', 'te: trailers',
                    '--data-binary', '@-', '--dump-header', str(headers), '--output', '-',
                    f'https://localhost:{spec["hold_port"]}/hold.Hold/Invoice']
            try:
                raw = _capture(campaign, 'failed-send-hold-invoice', 'grpc', argv, input_bytes=frame)
            finally:
                if headers.exists():
                    campaign._retain_private('failed-send-hold-invoice', 'grpc-headers', io.BytesIO(headers.read_bytes()))
            invoice = decode_hold_invoice(raw, headers.read_bytes())
        campaign._retain_private('failed-send-hold-invoice', 'invoice', io.BytesIO(invoice.encode()))
        decoded = _peer(campaign, spec, 'internal', 'failed-send-hold-invoice', 'decode', 'decode', invoice)
        public = validate_invoice(decoded, {'amount_sat': 5000, 'invoice_payee': spec['external_id']}, int(time.time()))
        if public['payment_hash'] != payment_hash or public['min_final_cltv_expiry'] != 6:
            raise ValueError('actual original hash and explicit final CLTV6 required')
        return {**public, 'invoice_sha256': hashlib.sha256(invoice.encode()).hexdigest(),
                'scope': 'One native external hold invoice; no payment, acceptance or refund credit.'}
    return _once(campaign, 'failed-send-hold-invoice', 'external-hold', 'hold_invoice',
                 {'payment_hash': payment_hash, 'amount_msat': 5000000, 'min_final_cltv_expiry': 6}, dispatch)


def _invoice(campaign):
    action = campaign.db.execute("SELECT reply FROM action WHERE id='failed-send-hold-invoice' AND state='acknowledged'").fetchone()
    artifact = campaign.db.execute("SELECT * FROM native_artifact WHERE intent='failed-send-hold-invoice' AND kind='invoice'").fetchone()
    if not action or not artifact or artifact['truncated']:
        raise ValueError('original acknowledged hold invoice required')
    public = json.loads(action[0])
    raw = (campaign.root / artifact['relative_path']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != artifact['sha256'] or artifact['sha256'] != public['invoice_sha256']:
        raise ValueError('original hold invoice bytes changed')
    return raw.decode(), public


def send_once(campaign):
    _quiescent(campaign)
    _ready_source(campaign)
    spec = _lightning_ready(campaign)
    invoice, public = _invoice(campaign)
    def dispatch():
        if campaign.db.execute("SELECT absent FROM actor WHERE id='absent'").fetchone()[0]:
            raise ValueError('original sender is fenced absent')
        decoded = _peer(campaign, spec, 'internal', 'failed-send-native-pay', 'decode', 'decode', invoice)
        checked = validate_invoice(decoded, {'amount_sat': 5000, 'invoice_payee': spec['external_id']}, int(time.time()))
        if checked != {k: public[k] for k in checked} or checked['min_final_cltv_expiry'] != 6:
            raise ValueError('original hold invoice identity changed')
        # A zero exit is only initiation ACK. The subsequent owned hold and
        # persisted SDK checkpoint must prove the intended crash boundary.
        raw = _capture(campaign, 'failed-send-native-pay', 'native',
            [campaign.config['binary'], '--quiet', '--no-logfile', '--datadir',
             str(campaign.actor_path('absent')), 'lightning', 'pay', 'invoice', invoice,
             '--no-sync', '--retry-for', '120'])
        if raw.strip():
            raise ValueError('unexpected native send output; reconcile original checkpoint')
        return {'native_exit_zero': True, 'payment_hash': public['payment_hash'],
                'completion': 'Requires actualAccepted hold and original sender checkpoint; not paid.'}
    return _once(campaign, 'failed-send-native-pay', 'absent', 'native_lightning_send',
                 {'payment_hash': public['payment_hash'], 'amount_sat': 5000, 'retry_for_seconds': 120}, dispatch)


def observe_hold(campaign):
    """Observe only the original held invoice; raw secret-bearing fields stay private."""
    _profile(campaign)
    spec = _transport(campaign)
    invoice, public = _invoice(campaign)
    n = _attempt(campaign, 'failed-hold')
    raw = _peer(campaign, spec, 'external', f'failed-hold-{n}', 'list',
                'listholdinvoices', 'payment_hash=' + public['payment_hash'])
    rows = raw.get('holdinvoices')
    if not isinstance(rows, list) or len(rows) != 1:
        raise ValueError('exact original hold invoice required')
    row = rows[0]
    state = row.get('state')
    if (row.get('payment_hash') != public['payment_hash'] or row.get('invoice') != invoice
            or row.get('preimage') is not None or state not in {'unpaid', 'accepted', 'cancelled'}):
        raise ValueError('original hold hash/invoice or unpaid outcome changed')
    htlcs = row.get('htlcs')
    if not isinstance(htlcs, list) or len(htlcs) > 16:
        raise ValueError('bounded genuine held HTLC observation required')
    projection = []
    for h in htlcs:
        if type(h.get('msat')) is not int or h['msat'] <= 0 or not isinstance(h.get('state'), str):
            raise ValueError('actual held HTLC amount/state required')
        expiry = h.get('cltv_expiry')
        if expiry is not None and (type(expiry) is not int or expiry < 1):
            raise ValueError('actual held HTLC deadline required')
        projection.append({k: h[k] for k in ['state', 'msat', 'cltv_expiry']})
    if state == 'accepted' and (not htlcs or sum(h['msat'] for h in htlcs if h['state'] == 'accepted') != 5000000):
        raise ValueError('actual accepted original five-million-msat HTLC required')
    return _save(campaign, 'failed-hold', {'kind': 'failed_send_external_hold',
        'payment_hash': public['payment_hash'], 'state': state, 'htlcs': projection,
        'chain': network_identity(campaign.core), 'case_verdict': 'INCOMPLETE',
        'scope': 'Owned external hold observation, not sender refund or fallback payment.'})


def _sender_checkpoint(campaign, payment_hash):
    # This is a read-only projection of the original native SDK checkpoint.
    # Opening this SQLite connection does not instantiate a wallet or drive it.
    path = campaign.actor_path('absent') / 'db.sqlite'
    with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as db:
        row = db.execute('SELECT payload FROM bark_wallet_action_checkpoint WHERE id=?',
                         ('ln_pay.' + payment_hash,)).fetchone()
    if not row:
        raise ValueError('original native Lightning send checkpoint required')
    raw = json.loads(row[0])
    if not isinstance(raw, dict) or set(raw) != {'LightningSend'}:
        raise ValueError('actual LightningSend native checkpoint required')
    send = raw['LightningSend']
    progress = send.get('progress')
    if not isinstance(progress, dict) or set(progress) != {'PaymentInitiated'}:
        raise ValueError('original native send must be parked at PaymentInitiated')
    ids = progress['PaymentInitiated'].get('vtxo_ids')
    if (not isinstance(ids, list) or not 1 <= len(ids) <= 4 or len(set(ids)) != len(ids)
            or any(not isinstance(point, str) or not POINT.fullmatch(point) for point in ids)
            or type(send.get('htlc_expiry')) is not int or send['htlc_expiry'] < 1):
        raise ValueError('actual signed grant IDs/deadline required')
    return {'grant_ids': ids, 'htlc_expiry': send['htlc_expiry'],
            'checkpoint_sha256': hashlib.sha256(canonical(raw).encode()).hexdigest(),
            'progress': 'PaymentInitiated'}


def _sender_idle(campaign):
    actor_path = str(campaign.actor_path('absent'))
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            argv = (proc / 'cmdline').read_bytes().decode(errors='replace').split('\0')
        except (OSError, ProcessLookupError):
            continue
        if argv and Path(argv[0]).name in {'bark', 'barkd'} and actor_path in argv:
            raise ValueError('original native sender process still active')


def fence_sender(campaign):
    spec = _profile(campaign)
    _quiescent(campaign)
    old = campaign.db.execute("SELECT value FROM meta WHERE key='s02_absent:absent'").fetchone()
    if old:
        return json.loads(old[0])
    action = campaign.db.execute("SELECT reply FROM action WHERE id='failed-send-native-pay' AND state='acknowledged'").fetchone()
    if not action:
        raise ValueError('actual original native send initiation ACK required')
    payment_hash = json.loads(action[0])['payment_hash']
    held = observe_hold(campaign)
    if held['state'] != 'accepted' or held['payment_hash'] != payment_hash:
        raise ValueError('original genuine Accepted state required before absence')
    checkpoint = _sender_checkpoint(campaign, payment_hash)
    ready = _ready_source(campaign)
    n = _attempt(campaign, 'failed-freeze')
    snapshot = _native(campaign, f'failed-freeze-{n}', 'absent', 'vtxos')
    coins = [c for c in snapshot if c['state'] in {'spendable', 'locked'}]
    grants = set(checkpoint['grant_ids'])
    htlc_amount = sum(c['amount_sat'] for c in coins if c['id'] in grants)
    if (any(c['state'] not in {'spendable', 'locked', 'spent'} for c in snapshot)
            or not grants.issubset({c['id'] for c in coins if c['state'] == 'locked'})
            or sum(c['amount_sat'] for c in coins) != ready['coin']['amount_sat']
            or any(c['chain_anchor'] != ready['coin']['chain_anchor'] for c in coins)
            or any(c['expiry_height'] != ready['actual_tree_expiry'] for c in coins)
            or not 5000 <= htlc_amount <= 6000
            or not held['chain']['height'] < checkpoint['htlc_expiry'] < ready['actual_tree_expiry']):
        raise ValueError('actual conditional source/change conservation and D<E required')
    proofs = [verify_coin(campaign, 'absent', c) for c in coins]
    if any(p.get('status') != 'PASS' or not p.get('path_outpoints') for p in proofs):
        raise ValueError('full signed grant/change paths required before sender absence')
    quoted = ','.join("'" + point + "'" for point in sorted(grants))
    query = ("BEGIN READ ONLY; SELECT coalesce(json_agg(json_build_object("
        "'grant_id',v.vtxo_id,'payment_hash',h.payment_hash,'direction',h.direction,"
        "'htlc_expiry',h.htlc_expiry)), '[]'::json) FROM htlc_vtxo h "
        "JOIN vtxo v ON v.id=h.id WHERE v.vtxo_id IN (" + quoted + "); COMMIT;")
    terms = _private_call(campaign, f'failed-freeze-{n}', 'grant-deadlines',
        ['sudo', '-u', 'postgres', 'psql', '-X', '-qAt', '-d', spec['database'], '-c', query])
    if (not isinstance(terms, list) or len(terms) != len(grants)
            or {r.get('grant_id') for r in terms} != grants
            or any(set(r) != {'grant_id', 'payment_hash', 'direction', 'htlc_expiry'}
                   or r['payment_hash'] != payment_hash or r['direction'] != 'incoming'
                   or r['htlc_expiry'] != checkpoint['htlc_expiry'] for r in terms)):
        raise ValueError('actual registered grant/hash/direction/deadline must bind signed native IDs')
    _sender_idle(campaign)
    if checkpoint != _sender_checkpoint(campaign, payment_hash):
        raise ValueError('original native action changed while freezing sender')
    held = observe_hold(campaign)
    if held['state'] != 'accepted':
        raise ValueError('hold stopped being Accepted before sender absence')
    registration = json.loads(campaign.db.execute("SELECT value FROM meta WHERE key='failed_sender_registration'").fetchone()[0])
    frozen = {'kind': 'S02_absent_cohort', 'actor': 'absent', 'registration': registration,
              'coins': coins, 'signature_proofs': proofs, 'chain': held['chain'],
              'case_verdict': 'INCOMPLETE', 'stage': 'SENDER_OFFLINE_WITH_REAL_ACCEPTED_HTLC',
              'payment_hash': payment_hash, **checkpoint,
              'actual_htlc_amount_sat': htlc_amount, 'reserved_send_fee_sat': htlc_amount - 5000,
              'grant_terms': terms,
              'ownership_evidence': 'Actual locked native grant plus spendable change, signed paths and parked native checkpoint. HTLC remains conditional until original source failure/deadline.'}
    public_payload(frozen)
    campaign.db.execute('BEGIN IMMEDIATE')
    try:
        _quiescent(campaign)
        if campaign.db.execute("SELECT absent FROM actor WHERE id='absent'").fetchone()[0]:
            raise ValueError('sender already absent without original frozen cohort')
        campaign.db.execute("UPDATE actor SET absent=1 WHERE id='absent'")
        campaign.db.execute("INSERT INTO meta VALUES ('s02_absent:absent',?)", (canonical(frozen),))
        campaign.db.execute('COMMIT')
    except BaseException:
        if campaign.db.in_transaction:
            campaign.db.execute('ROLLBACK')
        raise
    return _save(campaign, 'failed-send-absence', frozen)


def cancel_hold_once(campaign):
    _profile(campaign)
    _quiescent(campaign)
    spec = _transport(campaign)
    frozen = _freeze(campaign, 'absent')
    if not campaign.db.execute("SELECT 1 FROM actor WHERE id='absent' AND absent=1").fetchone():
        raise ValueError('original sender must be fenced before external cancellation')
    def dispatch():
        held = observe_hold(campaign)
        if held['state'] != 'accepted' or held['payment_hash'] != frozen['payment_hash']:
            raise ValueError('original external hold must still be Accepted before cancellation')
        raw = _peer(campaign, spec, 'external', 'failed-send-cancel', 'cancel',
                    'cancelholdinvoice', 'payment_hash=' + frozen['payment_hash'])
        if raw != {}:
            raise ValueError('unexpected original hold cancellation reply; reconcile by hash')
        return {'payment_hash': frozen['payment_hash'], 'native_exit_zero': True,
                'completion': 'Cancellation ACK only; observe original hold and actual backend source failure.'}
    return _once(campaign, 'failed-send-cancel', 'external-hold', 'cancel_hold_invoice',
                 {'payment_hash': frozen['payment_hash']}, dispatch)


def observe_failure(campaign):
    """Corroborate the exact attempted source, never coarse Failed or hash alone."""
    spec = _profile(campaign)
    transport = _transport(campaign)
    frozen = _freeze(campaign, 'absent')
    held = observe_hold(campaign)
    payment_hash = frozen['payment_hash']
    if held['state'] != 'cancelled':
        return _save(campaign, 'failed-source', {'kind': 'failed_send_source',
            'stage': 'WAITING_FOR_ORIGINAL_HOLD_CANCELLATION', 'case_verdict': 'INCOMPLETE'})
    if not campaign.db.execute("SELECT 1 FROM action WHERE id='failed-send-cancel' AND state='acknowledged'").fetchone():
        raise ValueError('original journaled cancellation acknowledgement required')
    if not re.fullmatch('[0-9a-f]{64}', payment_hash):
        raise ValueError('exact original public hash required')
    # An explicit public-field allowlist; no preimage/body/credential column.
    columns = {
        'attempt_id': 'a.id', 'payment_hash': 'a.payment_hash', 'status': 'a.status::text',
        'lightning_node_id': 'a.lightning_node_id', 'subscription_id': 'a.lightning_htlc_subscription_id',
        'label': 'd.label', 'failure_created_index': 'f.created_index',
        'failure_updated_index': 'f.updated_index', 'jsonrpc_error_code': 'f.jsonrpc_error_code',
        'success_created_index': 's.created_index', 'grant_id': 'l.vtxo_id',
        'direction': 'h.direction::text', 'htlc_expiry': 'h.htlc_expiry',
        'offchain_resolution': 'h.offchain_resolution::text', 'chain_resolution': 'h.chain_resolution::text',
        'chain_resolution_height': 'h.chain_resolution_height',
        'onchain_spent_txid': 'v.onchain_spent_txid', 'onchain_spent_height': 'v.onchain_spent_height'}
    projection = ','.join("'" + name + "'," + value for name, value in columns.items())
    query = ("BEGIN READ ONLY; SELECT coalesce(json_agg(json_build_object(" + projection +
        ")), '[]'::json) FROM lightning_payment_attempt a "
        "JOIN lightning_payment_attempt_htlc_vtxo l ON l.lightning_payment_attempt_id=a.id "
        "JOIN vtxo v ON v.vtxo_id=l.vtxo_id JOIN htlc_vtxo h ON h.id=v.id "
        "LEFT JOIN expiry_lightning_dispatch d ON d.id=a.id "
        "LEFT JOIN expiry_lightning_terminal_failure f ON f.id=a.id "
        "LEFT JOIN expiry_lightning_external_success s ON s.id=a.id "
        "WHERE a.payment_hash='" + payment_hash + "'; COMMIT;")
    n = _attempt(campaign, 'failed-source')
    rows = _private_call(campaign, f'failed-source-{n}', 'source-public-fields',
        ['sudo', '-u', 'postgres', 'psql', '-X', '-qAt', '-d', spec['database'], '-c', query])
    if not isinstance(rows, list) or any(not isinstance(r, dict) or set(r) != set(columns) for r in rows):
        raise ValueError('actual source-specific administrative projection required')
    pays = _peer(campaign, transport, 'internal', f'failed-source-{n}', 'pays',
                 'listpays', 'payment_hash=' + payment_hash).get('pays')
    if not isinstance(pays, list):
        raise ValueError('actual own-node payment groups required')
    if (any(p.get('payment_hash') != payment_hash or p.get('status') == 'complete'
            or p.get('preimage') is not None or p.get('payment_preimage') is not None for p in pays)
            or any(r['success_created_index'] is not None or r['offchain_resolution'] == 'fulfilled'
                   or r['chain_resolution'] == 'fulfilled' for r in rows)):
        raise ValueError('source indicates possible discharge; do not credit refundable principal')
    proven = (len(rows) == len(frozen['grant_ids'])
        and {r['grant_id'] for r in rows} == set(frozen['grant_ids'])
        and len({r['attempt_id'] for r in rows}) == 1
        and all(r['payment_hash'] == payment_hash and r['status'] == 'failed'
                and r['subscription_id'] is None and r['direction'] == 'incoming'
                and r['htlc_expiry'] == frozen['htlc_expiry'] and isinstance(r['label'], str)
                and type(r['failure_created_index']) is int and r['failure_created_index'] > 0
                and r['jsonrpc_error_code'] is None for r in rows)
        and bool(pays) and all(p.get('status') == 'failed' for p in pays)
        and all(any(p.get('label') == r['label'] and p.get('created_index') == r['failure_created_index']
                    for p in pays) for r in rows))
    # The node's listpays may include unknown future fields. Public evidence
    # retains only the actual source/group fields needed for this conclusion.
    groups = [{k: p.get(k) for k in ['payment_hash', 'label', 'status', 'created_index', 'updated_index']}
              for p in pays]
    return _save(campaign, 'failed-source', {'kind': 'failed_send_source',
        'stage': 'ACTUAL_SOURCE_SPECIFIC_EXTERNAL_FAILURE' if proven else 'WAITING_FOR_SOURCE_SPECIFIC_FAILURE',
        'case_verdict': 'INCOMPLETE', 'source_check': 'PASS' if proven else 'INCOMPLETE',
        'payment_hash': payment_hash, 'sources': rows, 'payer_groups': groups,
        'chain': network_identity(campaign.core),
        'scope': 'Observed-group failure only; no typed no-attempt substitute and no fallback completion yet.'})


def advance_recovery(campaign):
    spec = _profile(campaign)
    _quiescent(campaign)
    frozen = _freeze(campaign, 'absent')
    failure = observe_failure(campaign)
    result = {'kind': 'native_failed_external_send_fallback', 'case_verdict': 'INCOMPLETE',
              'stage': 'WAITING_FOR_RIGHTFUL_FALLBACK',
              'scope': 'Native attempted external hold failure; no Noah/LNURL or typed no-attempt credit.'}
    chain = network_identity(campaign.core)
    if failure.get('source_check') != 'PASS':
        return _save(campaign, 'failed-recovery', {**result, 'stage': failure['stage']})
    if chain['height'] < max(frozen['htlc_expiry'], max(c['expiry_height'] for c in frozen['coins'])):
        return _save(campaign, 'failed-recovery', {**result, 'stage': 'WAITING_FOR_ACTUAL_HTLC_AND_TREE_HEIGHTS',
            'chain': chain, 'actual_htlc_deadline': frozen['htlc_expiry'],
            'actual_tree_expiry': max(c['expiry_height'] for c in frozen['coins'])})
    discover_payouts(campaign, 'absent')
    payouts = {}
    for row in campaign.db.execute("SELECT id,payload FROM result WHERE json_extract(payload,'$.kind')='S02_payout_observation' AND json_extract(payload,'$.payout_check')='PASS' ORDER BY observed").fetchall():
        old = json.loads(row['payload'])
        if old['outpoint'] in payouts:
            continue
        txid, index = old['outpoint'].split(':')
        current = observe_payout(campaign, 'absent', txid, int(index), old['coin_ids'])
        if current['payout_check'] == 'PASS':
            payouts[old['outpoint']] = (row['id'], current)
    # This declared same-tree source/change case requires one actual payout.
    # Partial discharge or different grouping stays an unmet expectation.
    if (len(payouts) != 1 or sorted(cid for _, p in payouts.values() for cid in p['coin_ids'])
            != sorted(c['id'] for c in frozen['coins'])):
        return _save(campaign, 'failed-recovery', result)
    chain = network_identity(campaign.core)
    fees = [_fee_child(campaign, p, chain) for _, p in payouts.values()]
    if network_identity(campaign.core) != chain:
        raise ValueError('chain changed during actual payout/child proof')
    if (any(f is None for f in fees) or any(p['confirmations'] < 6 for _, p in payouts.values())
            or any(f['confirmations'] < 6 for f in fees)):
        return _save(campaign, 'failed-recovery', {**result, 'stage': 'WAITING_FOR_SIX_CONFIRMED_PARENT_AND_CHILD',
                                                'fee_children': fees})
    _native(campaign, 'failed-send-seed-restore', 'restored', 'restore',
            {'source_actor': 'absent', 'birthday_height': spec['birthday_height']})
    if not campaign.db.execute("SELECT 1 FROM action WHERE id='failed-send-drain'").fetchone():
        n = _attempt(campaign, 'failed-recovery-utxos')
        utxos = _native(campaign, f'failed-recovery-utxos-{n}', 'restored', 'onchain_utxos')
        found = {u['outpoint']: u for u in utxos if u['confirmation_height'] is not None}
        if any(point not in found or found[point]['amount_sat'] != p['amount_sat']
               for point, (_, p) in payouts.items()):
            return _save(campaign, 'failed-recovery', {**result, 'stage': 'WAITING_FOR_ORIGINAL_SEED_ONLY_DISCOVERY'})
        if network_identity(campaign.core) != chain:
            raise ValueError('chain changed before single recovery drain')
    _native(campaign, 'failed-send-drain', 'restored', 'onchain_drain',
            {'destination': spec['recovery_destination']})
    recovery = [check_recovery(campaign, 'absent', 'restored', 'failed-send-drain', row,
                              spec['recovery_destination']) for row, _ in payouts.values()]
    current = network_identity(campaign.core)
    complete = all(r['recovery_check'] == 'PASS' and r['chain'] == current for r in recovery)
    return _save(campaign, 'failed-recovery', {**result,
        'stage': 'RECOVERY_CONFIRMED' if complete else 'WAITING_FOR_CONFIRMED_RECOVERY',
        'case_verdict': 'PASS' if complete else 'INCOMPLETE',
        'payouts': [p for _, p in payouts.values()], 'fee_children': fees, 'recovery': recovery,
        'physical_recovery_spend': recovery[0].get('spend_txid'),
        'physical_recovery_fee_sat': recovery[0].get('miner_fee_sat'),
        'accounting_note': 'One physical seed-only drain; ordinary onchain change remains separately accounted.'})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    commands = parser.add_subparsers(dest='operation', required=True)
    start = commands.add_parser('stage')
    for name in ['funding-request', 'funding-receipt', 'financial-admission', 'runtime-pins', 'registration', 'source']:
        start.add_argument('--' + name, type=Path, required=True)
    start.add_argument('--recovery-destination', required=True)
    for name in ['funding', 'board', 'ready', 'invoice', 'send', 'observe-hold', 'fence', 'cancel', 'observe-failure', 'recover']:
        commands.add_parser(name)
    transport = commands.add_parser('transport')
    transport.add_argument('--manifest', type=Path, required=True)
    transport.add_argument('--tls-directory', type=Path, required=True)
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
            elif args.operation == 'transport':
                result = prepare_lightning(campaign, args.manifest, args.tls_directory)
            elif args.operation == 'invoice':
                result = issue_hold_invoice(campaign)
            elif args.operation == 'send':
                result = send_once(campaign)
            elif args.operation == 'observe-hold':
                result = observe_hold(campaign)
            elif args.operation == 'fence':
                result = fence_sender(campaign)
            elif args.operation == 'cancel':
                result = cancel_hold_once(campaign)
            elif args.operation == 'observe-failure':
                result = observe_failure(campaign)
            elif args.operation == 'recover':
                result = advance_recovery(campaign)
            else:
                result = funding_admission(campaign)
            print(canonical(result))
    finally:
        campaign.close()


if __name__ == '__main__':
    main()

"""Failed-send staging/board safety tests; no funded Lightning proof."""
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import subprocess
import time
import unittest
from unittest.mock import patch

from simulator.model import canonical
from simulator.signet_failed_send import (FailedSendCampaign, stage, funding_admission,
    board_once, board_ready, hold_invoice_frame)
from tests import test_signet, test_signet_phase, test_signet_s02

TXID = '6' * 64
PUB = '02' + '3' * 64
SCRIPTS = ['0014' + str(n) * 40 for n in (1, 2, 3)]


class FundingCore(test_signet_s02.LifecycleCore):
    def __init__(self):
        super().__init__()
        self.unconfirmed_watch = False
        self.transactions[TXID] = {'txid': TXID, 'confirmations': 1, 'blockhash': '3' * 64,
            'vout': [test_signet_s02.output(amount, script, n)
                     for n, (amount, script) in enumerate(zip([60000, 20000, 20000], SCRIPTS))]}

    def call(self, method, *args):
        if method == 'gettxout' and args[0] == TXID:
            return {'confirmations': 0 if self.unconfirmed_watch and args[1] else 1}
        return super().call(method, *args)


class FailedSendTests(unittest.TestCase):
    setUp = test_signet.SignetTests.setUp
    tearDown = test_signet.SignetTests.tearDown

    def prepare(self, *, execute_stage=True):
        test_signet_phase.PhaseTests.fixture(self)
        self.campaign.close()
        cfg = self.root / 'service-config/captaind.toml'
        cfg.write_text('''vtxo_lifetime=32
vtxo_exit_delta=12
htlc_send_expiry_delta=18
max_htlc_expiry_delta=288
htlc_expiry_delta=6
[vtxopool]
vtxo_targets=[]
[postgres]
name='fresh_owned_failed_send'
''')
        self.runtime_pins['config_hashes']['captaind'] = hashlib.sha256(cfg.read_bytes()).hexdigest()
        self.new_config['product_config_sha256'] = hashlib.sha256(canonical(self.runtime_pins['config_hashes']).encode()).hexdigest()
        self.campaign = FailedSendCampaign(self.new_directory, self.new_config)
        self.campaign.core = FundingCore()
        manifest = Path(self.runtime_pins['runtime_manifest'])
        manifest.write_text(canonical({'server_pubkey': PUB,
            'source_manifest_sha256': 'c60c5cd4c9d8cc0fbeaa8f8f6a71ba4102a46075cd2d9515fb505d9ba2dc882b'}))
        self.runtime_pins['runtime_manifest_sha256'] = hashlib.sha256(manifest.read_bytes()).hexdigest()
        self.sender = self.root / 'real-owned-native-sender'
        self.sender.mkdir(mode=0o700)
        config = self.sender / 'config.toml'
        config.write_text('server_address=' + json.dumps(self.new_config['ark_url']) + '\n'
                          'vtxo_refresh_expiry_threshold=12\nvtxo_exit_margin=12\nhtlc_recv_claim_delta=18\n')
        config.chmod(0o600)
        (self.sender / 'actual-wallet.sqlite').write_bytes(b'original DB must stay in place')
        self.source = self.root / 'original-phrase'
        self.source.write_text('abandon ' * 11 + 'about')
        self.source.chmod(0o600)
        self.registration = {'network': 'signet', 'payout_address': 'tb1qpayout', 'record': {'spk': SCRIPTS[0]}}
        self.registration_path = self.root / 'actual-registration.json'
        self.registration_path.write_text(canonical(self.registration))
        self.request = {'allocation_sat': 100000, 'funding_dispatched': False, 'network': 'signet',
            'source_manifest_sha256': 'c60c5cd4c9d8cc0fbeaa8f8f6a71ba4102a46075cd2d9515fb505d9ba2dc882b',
            'outputs': {role: {'amount_sat': amount, 'script': script}
                for role, amount, script in zip(['sender', 'watchman_fee_0', 'watchman_fee_1'],
                                               [60000, 20000, 20000], SCRIPTS)},
            'sender': {'wallet_directory': str(self.sender), 'original_birthday_height': 100,
                'configuration_sha256': hashlib.sha256(config.read_bytes()).hexdigest(),
                'registration_receipt_sha256': hashlib.sha256(self.registration_path.read_bytes()).hexdigest(),
                'registration_canonical_sha256': hashlib.sha256(canonical(self.registration).encode()).hexdigest(),
                'authenticated_payout_script': SCRIPTS[0]},
            'database': 'fresh_owned_failed_send', 'server_pubkey': PUB,
            'runtime_manifest_sha256': self.runtime_pins['runtime_manifest_sha256'],
            'config_sha256': self.runtime_pins['config_hashes'], 'elf_sha256': self.runtime_pins['elf_sha256']}
        self.request_path = self.root / 'root-request.json'
        self.request_path.write_text(canonical(self.request))
        self.receipt_path = self.root / 'root-receipt.json'
        self.receipt_path.write_text(canonical({'network': 'signet', 'txid': TXID,
            'request_sha256': hashlib.sha256(self.request_path.read_bytes()).hexdigest()}))
        self.admission_path = self.root / 'root-admission.json'
        self.admission_path.write_text(canonical({'network': 'signet', 'server_pubkey': PUB}))
        if execute_stage:
            return self.stage()

    def stage(self):
        return stage(self.campaign, self.request_path, self.receipt_path, self.admission_path,
                     self.runtime_pins, self.registration_path, self.source, 'tb1qrecovered')

    def wallet(self, *args):
        return {'watchman': {'trusted_balance': 40000,
            'confirmed_utxos': [TXID + ':1', TXID + ':2']}}

    def receipt(self, reply):
        self.campaign.db.execute('INSERT INTO action VALUES (?,?,?,?,?,?,?,?,?,?)',
            ('failed-send-board', 'absent', 'board', canonical({'amount_sat': 30000}),
             'acknowledged', time.time(), time.time(), canonical({'height': 200}), canonical(reply), None))

    def test_cached_stage_opens_no_wallet_and_fabricates_no_create_ack(self):
        with patch('simulator.signet.subprocess.run') as native:
            result = self.prepare()
        native.assert_not_called()
        self.assertEqual(result['stage'], 'STAGED_EXISTING_REAL_SENDER_NO_NATIVE_OPEN')
        self.assertEqual(self.campaign.actor_path('absent'), self.sender)
        self.assertNotEqual(self.campaign.actor_path('restored'), self.sender)
        self.assertEqual(self.campaign.db.execute('SELECT count(*) FROM action').fetchone()[0], 0)
        self.assertFalse((self.campaign.root / 'wallets/absent').exists())
        from simulator.signet_s02 import recovery_source
        self.assertEqual(recovery_source(self.campaign, 'absent').read_bytes(), self.source.read_bytes())

    def test_staging_rejects_changed_authentic_registration(self):
        self.prepare(execute_stage=False)
        self.registration_path.write_text('{}')
        with self.assertRaisesRegex(ValueError, 'authenticated original'):
            self.stage()
        self.assertEqual(self.campaign.db.execute('SELECT count(*) FROM actor').fetchone()[0], 0)

    def test_original_funding_request_binding_is_required(self):
        self.prepare(execute_stage=False)
        value = json.loads(self.receipt_path.read_text())
        value['request_sha256'] = 'a' * 64
        self.receipt_path.write_text(canonical(value))
        with self.assertRaisesRegex(ValueError, 'bind exact request'):
            self.stage()

    def test_actual_root_receipt_public_signet_label_and_other_network_refusal(self):
        self.prepare(execute_stage=False)
        value = json.loads(self.receipt_path.read_text())
        value['network'] = 'regtest'
        self.receipt_path.write_text(canonical(value))
        with self.assertRaisesRegex(ValueError, 'selected funding/source'):
            self.stage()
        self.assertEqual(self.campaign.db.execute('SELECT count(*) FROM actor').fetchone()[0], 0)
        value['network'] = 'public signet'
        self.receipt_path.write_text(canonical(value))
        with patch('simulator.signet.subprocess.run') as native:
            result = self.stage()
        native.assert_not_called()
        self.assertEqual(result['stage'], 'STAGED_EXISTING_REAL_SENDER_NO_NATIVE_OPEN')

    def test_no_native_board_before_actual_funding_confirmation(self):
        self.prepare()
        self.campaign.core.transactions[TXID]['confirmations'] = 0
        with patch('simulator.signet_failed_send._native') as native:
            result = board_once(self.campaign)
        native.assert_not_called()
        self.assertEqual(result['stage'], 'WAITING_FOR_REAL_FUNDING_CONFIRMATION')

    def test_unconfirmed_watch_inputs_block_board_even_with_nominal_balance(self):
        self.prepare()
        self.campaign.core.unconfirmed_watch = True
        with patch('simulator.signet_failed_send._native') as native:
            with self.assertRaisesRegex(ValueError, 'confirmed usable'):
                board_once(self.campaign)
        native.assert_not_called()

    def test_canonical_funding_and_exact_scripts_values_are_required(self):
        self.prepare()
        for mutation in ['block', 'amount', 'script']:
            tx = self.campaign.core.transactions[TXID]
            original = dict(tx)
            original['vout'] = [dict(v) | {'scriptPubKey': dict(v['scriptPubKey'])} for v in tx['vout']]
            if mutation == 'block':
                tx['blockhash'] = '0' * 64
            elif mutation == 'amount':
                tx['vout'][0]['value'] = Decimal('0.00059999')
            else:
                tx['vout'][0]['scriptPubKey']['hex'] = '0014' + '9' * 40
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                funding_admission(self.campaign)
            self.campaign.core.transactions[TXID] = original

    def test_native_wallet_must_contain_the_confirmed_sponsor_prevouts(self):
        self.prepare()
        with patch('simulator.signet_failed_send._private_call', return_value={
                'watchman': {'trusted_balance': 40000, 'confirmed_utxos': []}}):
            with self.assertRaisesRegex(ValueError, 'native watchman wallet'):
                funding_admission(self.campaign)

    def test_unknown_board_is_not_replayed_and_keeps_existing_actor(self):
        self.prepare()
        with patch('simulator.signet_failed_send._private_call', side_effect=self.wallet), \
             patch('simulator.signet.subprocess.run', side_effect=subprocess.TimeoutExpired('board', 1)):
            with self.assertRaisesRegex(ValueError, 'requires reconciliation'):
                board_once(self.campaign)
        with patch('simulator.signet.subprocess.run') as replay:
            with self.assertRaisesRegex(ValueError, 'unknown action'):
                board_once(self.campaign)
        replay.assert_not_called()
        row = self.campaign.db.execute("SELECT state FROM action WHERE id='failed-send-board'").fetchone()
        self.assertEqual(row[0], 'unknown')
        self.assertTrue((self.sender / 'actual-wallet.sqlite').exists())

    def test_board_depth_wait_performs_no_native_wallet_open(self):
        self.prepare()
        self.receipt({'funding_txid': TXID})
        self.campaign.core.transactions[TXID]['confirmations'] = 2
        with patch('simulator.signet_failed_send._native') as native:
            result = board_ready(self.campaign)
        native.assert_not_called()
        self.assertEqual(result['stage'], 'WAITING_FOR_REAL_THREE_BOARD_CONFIRMATIONS')

    def test_actual_source_gate_requires_correct_server_and_signature_headroom(self):
        self.prepare()
        self.receipt({'funding_txid': TXID})
        self.campaign.core.transactions[TXID]['confirmations'] = 3
        self.campaign.core.transactions[TXID]['blockhash'] = 'f' * 64
        coin = {'id': '7' * 64 + ':0', 'amount_sat': 29670, 'state': 'spendable',
                'chain_anchor': TXID + ':0', 'expiry_height': 230}
        def native(campaign, intent, actor, operation, *args):
            if operation == 'ark_info':
                return {'server_pubkey': PUB, 'htlc_send_expiry_delta': 18}
            return [coin]
        proof = {'status': 'PASS', 'path_outpoints': [TXID + ':0', coin['id']]}
        with patch('simulator.signet_failed_send._native', side_effect=native), \
             patch('simulator.signet_failed_send.verify_coin', return_value=proof):
            result = board_ready(self.campaign)
            self.assertEqual(result['coin']['amount_sat'], 29670)
            self.assertEqual(result['actual_tree_expiry'], 230)
            self.assertEqual(result['provisional_send_deadline_if_dispatched_now'], 218)
            coin['expiry_height'] = 218
            with self.assertRaisesRegex(ValueError, 'headroom'):
                board_ready(self.campaign)

    def test_absence_fence_blocks_every_future_original_wallet_open(self):
        self.prepare()
        self.campaign.db.execute("UPDATE actor SET absent=1 WHERE id='absent'")
        with patch('simulator.signet.subprocess.run') as native:
            with self.assertRaisesRegex(ValueError, 'absent actor'):
                self.campaign.execute('forbidden-after-fence', 'absent', 'vtxos', {})
        native.assert_not_called()

    def test_exact_existing_hold_wire_overrides_default_cltv_without_effect(self):
        frame = hold_invoice_frame('12' * 32)
        self.assertEqual(frame[0], 0)
        self.assertEqual(int.from_bytes(frame[1:5], 'big'), len(frame) - 5)
        self.assertEqual(frame[5:39], b'\x0a\x20' + bytes.fromhex('12' * 32))
        self.assertTrue(frame.endswith(b'\x28\x90\x1c\x30\x06'))
        with self.assertRaises(ValueError):
            hold_invoice_frame('not-a-payment-hash')


class FailedSendLightningTests(unittest.TestCase):
    setUp = test_signet.SignetTests.setUp
    tearDown = test_signet.SignetTests.tearDown
    prepare = FailedSendTests.prepare
    stage = FailedSendTests.stage

    def transport(self):
        from simulator.signet_failed_send import prepare_lightning
        self.invoice_created_at = int(time.time())
        self.prepare()
        self.cli = self.root / 'lightning-cli'
        self.cli.write_bytes(b'original cli')
        self.tls = self.root / 'ln/external/signet/hold'
        self.tls.mkdir(parents=True)
        for name in ['ca.pem', 'client.pem', 'client-key.pem']:
            (self.tls / name).write_bytes(b'owned fixture ' + name.encode())
            (self.tls / name).chmod(0o600)
        self.ln_manifest = self.root / 'ln/runtime-manifest.json'
        self.ln_manifest.write_text(canonical({'executable_sha256': {str(self.cli): hashlib.sha256(self.cli.read_bytes()).hexdigest()},
            'nodes': {'internal': {'id': PUB, 'ports': [1, 2, 3]},
                      'external': {'id': '03' + '4' * 64, 'ports': [4, 5, 39838]}}}))
        return prepare_lightning(self.campaign, self.ln_manifest, self.tls)

    def decoded(self):
        return {'type': 'bolt11 invoice', 'valid': True, 'currency': 'tbs', 'amount_msat': 5000000,
            'payment_hash': self.campaign.db.execute("SELECT value FROM meta WHERE key='failed_send_hash'").fetchone()[0],
            'payee': '03' + '4' * 64, 'created_at': self.invoice_created_at, 'expiry': 3600,
            'min_final_cltv_expiry': 6}

    def peer(self, campaign, spec, role, intent, kind, *args):
        if args[0] == 'getinfo':
            return {'id': spec[role + '_id'], 'network': 'signet', 'version': 'v26.06.6', 'blockheight': 200}
        if args[0] == 'listpeerchannels':
            return {'channels': [{'peer_id': spec['external_id' if role == 'internal' else 'internal_id'],
                'state': 'CHANNELD_NORMAL', 'private': True, 'spendable_msat': 6000000, 'receivable_msat': 6000000}]}
        if args[0] == 'listholdinvoices':
            return {'holdinvoices': []}
        if args[0] == 'decode':
            return self.decoded()
        raise AssertionError(args)

    def invoice(self, *, capture=None):
        from simulator.signet_failed_send import issue_hold_invoice
        def response(campaign, intent, kind, argv, **kwargs):
            self.assertIn('--noproxy', argv)
            self.assertNotIn('--insecure', argv)
            Path(argv[argv.index('--dump-header') + 1]).write_bytes(b'HTTP/2 200\r\ngrpc-status: 0\r\n')
            invoice = b'lntbs50000fixture'
            return b'\0' + (len(invoice) + 2).to_bytes(4, 'big') + b'\x0a' + bytes([len(invoice)]) + invoice
        with patch('simulator.signet_failed_send._ready_source', return_value={}), \
             patch('simulator.signet_failed_send._peer', side_effect=self.peer), \
             patch('simulator.signet_failed_send._capture', side_effect=capture or response):
            return issue_hold_invoice(self.campaign)

    def acknowledged(self, intent, actor, operation, reply):
        now = time.time()
        self.campaign.db.execute('INSERT INTO action VALUES (?,?,?,?,?,?,?,?,?,?)',
            (intent, actor, operation, '{}', 'acknowledged', now, now,
             canonical({'height': 200}), canonical(reply), None))

    def held(self, state='accepted'):
        return {'payment_hash': self.decoded()['payment_hash'], 'state': state,
            'chain': {'height': 200}, 'kind': 'failed_send_external_hold'}

    def test_transport_reopen_preserves_hash_and_private_files(self):
        from simulator.signet_failed_send import prepare_lightning
        first = self.transport()
        payment_hash = self.decoded()['payment_hash']
        again = prepare_lightning(self.campaign, self.ln_manifest, self.tls)
        self.assertEqual(first, again)
        self.assertEqual(payment_hash, self.decoded()['payment_hash'])
        self.assertNotIn('tls_directory', again)
        self.assertEqual(self.campaign.db.execute("SELECT count(*) FROM native_artifact WHERE kind='preimage'").fetchone()[0], 1)
        self.cli.write_bytes(b'replaced cli')
        with self.assertRaisesRegex(ValueError, 'executable changed'):
            prepare_lightning(self.campaign, self.ln_manifest, self.tls)

    def test_actual_stock_peer_identity_and_channel_gate(self):
        from simulator.signet_failed_send import _lightning_ready
        self.transport()
        with patch('simulator.signet_failed_send._peer', side_effect=self.peer):
            self.assertEqual(_lightning_ready(self.campaign)['hold_port'], 39838)
        def wrong(*args):
            value = self.peer(*args)
            if args[5] == 'getinfo': value['id'] = '03' + '9' * 64
            return value
        with patch('simulator.signet_failed_send._peer', side_effect=wrong):
            with self.assertRaisesRegex(ValueError, 'identity/version/sync'):
                _lightning_ready(self.campaign)

    def test_hold_wire_rejects_nonzero_status_compression_and_truncation(self):
        from simulator.signet_failed_send import decode_hold_invoice
        invoice = b'lntbsfixture'
        body = b'\x0a' + bytes([len(invoice)]) + invoice
        raw = b'\0' + len(body).to_bytes(4, 'big') + body
        headers = b'HTTP/2 200\r\ngrpc-status: 0\r\n'
        self.assertEqual(decode_hold_invoice(raw, headers), invoice.decode())
        for bad_raw, bad_headers in [(b'\1' + raw[1:], headers), (raw[:-1], headers),
            (raw, headers.replace(b'status: 0', b'status: 2')), (raw + b'junk', headers)]:
            with self.assertRaises(ValueError):
                decode_hold_invoice(bad_raw, bad_headers)

    def test_invoice_once_uses_original_hash_and_six_block_override(self):
        self.transport()
        first = self.invoice()
        self.assertEqual(first['min_final_cltv_expiry'], 6)
        self.assertEqual(first['payment_hash'], self.decoded()['payment_hash'])
        with patch('simulator.signet_failed_send._capture') as duplicate:
            again = self.invoice(capture=duplicate)
        duplicate.assert_not_called()
        self.assertEqual(first, again)
        replies = ' '.join(r[0] or '' for r in self.campaign.db.execute('SELECT reply FROM action'))
        self.assertNotIn('preimage', replies)
        self.assertNotIn('lntbs50000fixture', replies)

    def test_lost_invoice_response_holds_without_second_effect(self):
        self.transport()
        def lost(*args, **kwargs):
            state = self.campaign.db.execute("SELECT state FROM action WHERE id='failed-send-hold-invoice'").fetchone()[0]
            self.assertEqual(state, 'dispatched')
            raise subprocess.TimeoutExpired('curl', 30)
        with self.assertRaises(subprocess.TimeoutExpired):
            self.invoice(capture=lost)
        with patch('simulator.signet_failed_send._capture') as duplicate:
            with self.assertRaisesRegex(ValueError, 'requires reconciliation'):
                self.invoice(capture=duplicate)
        duplicate.assert_not_called()

    def test_native_nonwaiting_send_once_and_sender_fence(self):
        from simulator.signet_failed_send import send_once
        self.transport(); self.invoice()
        with patch('simulator.signet_failed_send._ready_source', return_value={}), \
             patch('simulator.signet_failed_send._peer', side_effect=self.peer), \
             patch('simulator.signet_failed_send._capture', return_value=b'') as capture:
            first = send_once(self.campaign); again = send_once(self.campaign)
        self.assertEqual(first, again); self.assertEqual(capture.call_count, 1)
        argv = capture.call_args.args[3]
        self.assertIn('--no-sync', argv); self.assertNotIn('--wait', argv)
        self.assertEqual(argv[-2:], ['--retry-for', '120'])
        self.assertIn('not paid', first['completion'])

    def test_hold_observer_does_not_publish_preimage_or_accept_wrong_invoice(self):
        from simulator.signet_failed_send import observe_hold
        self.transport(); self.invoice()
        row = {'payment_hash': self.decoded()['payment_hash'], 'invoice': 'lntbs50000fixture',
            'state': 'accepted', 'htlcs': [{'state': 'accepted', 'msat': 5000000, 'cltv_expiry': 206}]}
        with patch('simulator.signet_failed_send._peer', return_value={'holdinvoices': [row]}):
            observed = observe_hold(self.campaign)
            self.assertNotIn('invoice', observed)
            row['preimage'] = '12' * 32
            with self.assertRaisesRegex(ValueError, 'unpaid outcome'):
                observe_hold(self.campaign)

    def test_read_only_native_checkpoint_and_atomic_absence_fence(self):
        import sqlite3
        from simulator.signet_failed_send import fence_sender, _sender_checkpoint
        self.transport(); self.invoice()
        payment_hash = self.decoded()['payment_hash']; grant = '8' * 64 + ':0'; change = '9' * 64 + ':0'
        self.acknowledged('failed-send-native-pay', 'absent', 'native_lightning_send', {'payment_hash': payment_hash})
        with sqlite3.connect(self.sender / 'db.sqlite') as db:
            db.execute('CREATE TABLE bark_wallet_action_checkpoint(id TEXT PRIMARY KEY,payload BLOB)')
            db.execute('INSERT INTO bark_wallet_action_checkpoint VALUES (?,?)', ('ln_pay.' + payment_hash,
                canonical({'LightningSend': {'htlc_expiry': 218, 'progress': {'PaymentInitiated': {'vtxo_ids': [grant]}}}}).encode()))
        coins = [{'id': point, 'amount_sat': value, 'state': state, 'expiry_height': 230,
                  'chain_anchor': TXID + ':0', 'user_pubkey': PUB}
                 for point, value, state in [(grant, 5075, 'locked'), (change, 24595, 'spendable')]]
        ready = {'coin': {'amount_sat': 29670, 'chain_anchor': TXID + ':0'}, 'actual_tree_expiry': 230}
        terms = [{'grant_id': grant, 'payment_hash': payment_hash, 'direction': 'incoming', 'htlc_expiry': 217}]
        def proof(campaign, actor, coin):
            return {'coin_id': coin['id'], 'status': 'PASS', 'path_outpoints': [coin['chain_anchor'], coin['id']]}
        with patch('simulator.signet_failed_send.observe_hold', return_value=self.held()), \
             patch('simulator.signet_failed_send._ready_source', return_value=ready), \
             patch('simulator.signet_failed_send._native', return_value=coins), \
             patch('simulator.signet_failed_send._private_call', return_value=terms), \
             patch('simulator.signet_failed_send.verify_coin', side_effect=proof):
            with self.assertRaisesRegex(ValueError, 'registered grant/hash/direction/deadline'):
                fence_sender(self.campaign)
            self.assertEqual(self.campaign.db.execute("SELECT absent FROM actor WHERE id='absent'").fetchone()[0], 0)
            terms[0]['htlc_expiry'] = 218
            frozen = fence_sender(self.campaign)
        self.assertEqual(frozen['htlc_expiry'], 218)
        self.assertEqual(sum(c['amount_sat'] for c in frozen['coins']), 29670)
        self.assertEqual(_sender_checkpoint(self.campaign, payment_hash)['grant_ids'], [grant])
        with patch('simulator.signet.subprocess.run') as forbidden:
            with self.assertRaisesRegex(ValueError, 'absent actor'):
                self.campaign.execute('forbidden-reopen', 'absent', 'vtxos', {})
        forbidden.assert_not_called()

    def failed_source(self):
        self.transport(); self.invoice()
        payment_hash = self.decoded()['payment_hash']
        grant = '8' * 64 + ':0'
        frozen = {'payment_hash': payment_hash, 'grant_ids': [grant], 'htlc_expiry': 180,
            'registration': self.registration,
            'coins': [{'id': point, 'amount_sat': 5000, 'expiry_height': 190,
                       'chain_anchor': test_signet_s02.ANCHOR + ':0'}
                      for point in [grant, '9' * 64 + ':0']],
            'signature_proofs': [{'coin_id': point,
                 'path_outpoints': [test_signet_s02.ANCHOR + ':0', point]}
                for point in [grant, '9' * 64 + ':0']]}
        self.campaign.db.execute("INSERT INTO meta VALUES ('s02_absent:absent',?)", (canonical(frozen),))
        self.campaign.db.execute("UPDATE actor SET absent=1 WHERE id='absent'")
        self.acknowledged('failed-send-cancel', 'external-hold', 'cancel_hold_invoice', {'payment_hash': payment_hash})
        row = {'attempt_id': 1, 'payment_hash': payment_hash, 'status': 'failed', 'lightning_node_id': 1,
            'subscription_id': None, 'label': 'original-own-dispatch', 'failure_created_index': 8,
            'failure_updated_index': 9, 'jsonrpc_error_code': None, 'success_created_index': None,
            'grant_id': grant, 'direction': 'incoming', 'htlc_expiry': 180,
            'offchain_resolution': None, 'chain_resolution': None, 'chain_resolution_height': None,
            'onchain_spent_txid': None, 'onchain_spent_height': None}
        group = {'payment_hash': payment_hash, 'label': row['label'], 'created_index': 8,
                 'updated_index': 9, 'status': 'failed'}
        return frozen, row, group

    def test_coarse_failed_zero_index_wrong_label_or_preimage_cannot_prove_refund(self):
        from simulator.signet_failed_send import observe_failure
        frozen, row, group = self.failed_source()
        with patch('simulator.signet_failed_send.observe_hold', return_value=self.held('cancelled')), \
             patch('simulator.signet_failed_send._private_call', return_value=[row]) as diagnostic, \
             patch('simulator.signet_failed_send._peer', return_value={'pays': [group]}):
            self.assertEqual(observe_failure(self.campaign)['source_check'], 'PASS')
            query = diagnostic.call_args.args[-1][-1]
            self.assertNotIn('preimage', query)
            self.assertIn('BEGIN READ ONLY;', query)
            for field, value in [('failure_created_index', 0), ('label', 'unrelated'), ('jsonrpc_error_code', 205)]:
                original = row[field]; row[field] = value
                with self.subTest(field=field):
                    self.assertEqual(observe_failure(self.campaign)['source_check'], 'INCOMPLETE')
                row[field] = original
            group['payment_preimage'] = '12' * 32
            with self.assertRaisesRegex(ValueError, 'possible discharge'):
                observe_failure(self.campaign)

    def test_recovery_cannot_open_wallet_before_actual_parent_child_six_depth(self):
        from simulator.signet_failed_send import advance_recovery
        from simulator.signet_s02 import observe_payout
        frozen, row, group = self.failed_source()
        coins = [c['id'] for c in frozen['coins']]
        observation = observe_payout(self.campaign, 'absent', test_signet_s02.PAYOUT, 0, coins)
        self.assertEqual(observation['payout_check'], 'PASS')
        with patch('simulator.signet_failed_send.observe_failure', return_value={'source_check': 'PASS'}), \
             patch('simulator.signet_failed_send.discover_payouts'), \
             patch('simulator.signet_failed_send._fee_child', return_value={'confirmations': 5}), \
             patch('simulator.signet_failed_send._native') as native:
            result = advance_recovery(self.campaign)
        self.assertEqual(result['stage'], 'WAITING_FOR_SIX_CONFIRMED_PARENT_AND_CHILD')
        native.assert_not_called()
        with patch('simulator.signet_failed_send.observe_failure', return_value={'stage': 'WAITING_FOR_SOURCE_SPECIFIC_FAILURE'}), \
             patch('simulator.signet_failed_send._native') as native:
            result = advance_recovery(self.campaign)
        self.assertEqual(result['stage'], 'WAITING_FOR_SOURCE_SPECIFIC_FAILURE')
        native.assert_not_called()

    def test_cancellation_requires_fence_and_never_retries_lost_reply(self):
        from simulator.signet_failed_send import cancel_hold_once
        self.transport(); self.invoice()
        frozen = {'payment_hash': self.decoded()['payment_hash']}
        self.campaign.db.execute("INSERT INTO meta VALUES ('s02_absent:absent',?)", (canonical(frozen),))
        with self.assertRaisesRegex(ValueError, 'fenced'):
            cancel_hold_once(self.campaign)
        self.campaign.db.execute("UPDATE actor SET absent=1 WHERE id='absent'")
        with patch('simulator.signet_failed_send.observe_hold', return_value=self.held()), \
             patch('simulator.signet_failed_send._peer', side_effect=subprocess.TimeoutExpired('cancel', 1)) as cancel:
            with self.assertRaises(subprocess.TimeoutExpired):
                cancel_hold_once(self.campaign)
            self.assertEqual(cancel.call_count, 1)
        with patch('simulator.signet_failed_send._peer') as replay:
            with self.assertRaisesRegex(ValueError, 'requires reconciliation'):
                cancel_hold_once(self.campaign)
        replay.assert_not_called()


if __name__ == '__main__':
    unittest.main()

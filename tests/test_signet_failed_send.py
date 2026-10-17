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


if __name__ == '__main__':
    unittest.main()

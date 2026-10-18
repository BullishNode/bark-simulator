"""Fresh-short-source unit faults; native/Core are explicit stubs, not Signet proof."""
import hashlib
import json
import time
import unittest
from unittest.mock import patch

from simulator.model import canonical
from simulator.signet import digest
from simulator.signet_fresh_ln import (prepare, stage, funding, board_accounting,
    PROFILE, RECOVERED, TREASURY_SCRIPT)
from simulator.signet_failed_send import board_once, board_ready
from tests import test_signet_failed_send as old
from tests.test_signet_s02 import output


class FreshBoardTests(unittest.TestCase):
    setUp = old.FailedSendTests.setUp
    tearDown = old.FailedSendTests.tearDown

    def setup_source(self, run=True):
        old.FailedSendTests.prepare(self, execute_stage=False)
        cfg = self.root / 'service-config/captaind.toml'
        cfg.write_text(cfg.read_text().replace('vtxo_targets=[]',
            'vtxo_targets=["10000sat:2"]\nvtxo_lifetime=32\nvtxo_pre_expiry=12') +
            '\n[fees.board]\nmin_fee_sat=330\nbase_fee_sat=100\nppm=1000\n')
        self.runtime_pins['config_hashes']['captaind'] = digest(cfg)
        self.campaign.config['product_config_sha256'] = hashlib.sha256(
            canonical(self.runtime_pins['config_hashes']).encode()).hexdigest()
        self.sender = self.campaign.actor_path('absent')
        self.sender.mkdir(parents=True)
        (self.sender / 'config.toml').write_text('server_address=' + json.dumps(self.new_config['ark_url']) + '\n' +
            '\n'.join(k+'='+str(v) for k, v in PROFILE.items()))
        (self.sender / 'config.toml').chmod(0o600)
        (self.sender / 'mnemonic').write_bytes(self.source.read_bytes())
        (self.sender / 'mnemonic').chmod(0o600)
        self.admission = {'scope': 'P09-fresh-board-v11c',
            'runtime_manifest_sha256': self.runtime_pins['runtime_manifest_sha256'],
            'recovered_input': RECOVERED, 'recovered_input_sat': 58034,
            'sender_allocation_sat': 30000, 'board_amount_sat': 20000,
            'new_treasury_principal_sat': 0, 'watchman_minimum_confirmed_sat': 40000,
            'watchman_admin': 'http://127.0.0.1:4596',
            'recovery_destination': 'tb1qrecovered',
            'server_pubkey': old.PUB, 'database': 'fresh_owned_failed_send'}
        self.admission_path.write_text(canonical(self.admission))
        if run:
            with patch('simulator.signet_fresh_ln._native', side_effect=self.native):
                self.request = prepare(self.campaign, self.runtime_pins, self.admission_path)['request']
            self.request_path.write_text(canonical(self.request))
            self.receipt_path.write_text(canonical({'txid': old.TXID,
                'request_sha256': digest(self.request_path)}))
            stage(self.campaign, self.request_path, self.receipt_path, self.admission_path, 'tb1qrecovered')
            core = self.campaign.core
            core.transactions[old.TXID].update(vin=[{'txid': RECOVERED.split(':')[0], 'vout': 0}],
                vout=[output(30000, old.SCRIPTS[0]), output(27534, TREASURY_SCRIPT, 1)])
            core.transactions[RECOVERED.split(':')[0]] = {'txid': RECOVERED.split(':')[0],
                'confirmations': 51, 'blockhash': '4'*64, 'vout': [output(58034, TREASURY_SCRIPT)]}
            self.spec = json.loads(self.campaign.db.execute("SELECT value FROM meta WHERE key='failed_send'").fetchone()[0])

    def native(self, campaign, intent, actor, operation, args=None):
        reply = self.registration if operation == 'fallback_record' else (
            {'address': 'tb1qfunding'} if operation == 'onchain_address' else {'actual_native_ack': True})
        if operation == 'create':
            self.assertEqual(args, {'wallet_profile': PROFILE})
        campaign.db.execute("INSERT OR IGNORE INTO actor VALUES ('absent',0)")
        campaign.db.execute('INSERT INTO action VALUES (?,?,?,?,?,?,?,?,?,?)',
            (intent, actor, operation, canonical(args or {}), 'acknowledged', time.time(), time.time(),
             canonical({'height': 100}), canonical(reply), None))
        return reply

    def watch(self, *args):
        return {'watchman': {'trusted_balance': 100000,
            'confirmed_utxos': ['9'*64+':0', '8'*64+':0']}}

    def test_real_create_receipts_and_original_seed_preserved_no_synthetic_refresh(self):
        self.setup_source()
        self.assertEqual(self.request['birthday_height'], 100)
        self.assertEqual(self.request['outputs']['sender']['amount_sat'], 30000)
        self.assertEqual(self.request['board_amount_sat'], 20000)
        self.assertEqual(self.campaign.db.execute("SELECT count(*) FROM action WHERE operation IN ('refresh','board')").fetchone()[0], 0)
        from simulator.signet_s02 import recovery_source
        self.assertEqual(recovery_source(self.campaign, 'absent').read_bytes(), self.source.read_bytes())
        with self.assertRaisesRegex(ValueError, 'empty operation'):
            prepare(self.campaign, self.runtime_pins, self.admission_path)

    def test_wrong_runtime_or_new_principal_rejected_before_create(self):
        self.setup_source(run=False)
        self.admission['new_treasury_principal_sat'] = 30000
        self.admission_path.write_text(canonical(self.admission))
        with patch('simulator.signet_fresh_ln._native') as native:
            with self.assertRaisesRegex(ValueError, 'recovered-funds'):
                prepare(self.campaign, self.runtime_pins, self.admission_path)
        native.assert_not_called()

    def test_funding_confirmation_gates_board_and_exact20k_amount(self):
        self.setup_source()
        self.campaign.core.transactions[old.TXID]['confirmations'] = 0
        with patch('simulator.signet_failed_send._native') as native:
            self.assertEqual(board_once(self.campaign)['stage'], 'WAITING_FOR_REAL_FUNDING_CONFIRMATION')
        native.assert_not_called()
        self.campaign.core.transactions[old.TXID]['confirmations'] = 1
        with patch('simulator.signet_fresh_ln._private_call', side_effect=self.watch), \
             patch('simulator.signet_failed_send._native', return_value={}) as native:
            board_once(self.campaign)
        self.assertEqual(native.call_args.args[-1], {'amount_sat': 20000})

    def test_wrong_funding_input_or_change_and_spent_watch_funds_fail(self):
        self.setup_source()
        tx = self.campaign.core.transactions[old.TXID]
        tx['vin'][0]['txid'] = '7'*64
        with self.assertRaisesRegex(ValueError, 'recovered principal'):
            funding(self.campaign, self.spec)
        tx['vin'][0]['txid'] = RECOVERED.split(':')[0]
        tx['vout'][1]['scriptPubKey']['hex'] = old.SCRIPTS[2]
        with self.assertRaisesRegex(ValueError, 'treasury change'):
            funding(self.campaign, self.spec)
        tx['vout'][1]['scriptPubKey']['hex'] = TREASURY_SCRIPT
        with patch('simulator.signet_fresh_ln._private_call', return_value={
                'watchman': {'trusted_balance': 100000, 'confirmed_utxos': []}}):
            with self.assertRaisesRegex(ValueError, 'usable40k'):
                funding(self.campaign, self.spec)

    def test_board_three_confirmations_before_any_native_open(self):
        self.setup_source()
        self.campaign.db.execute('INSERT INTO action VALUES (?,?,?,?,?,?,?,?,?,?)',
            ('failed-send-board', 'absent', 'board', '{}', 'acknowledged', 1, 1, '{}',
             canonical({'funding_txid': old.TXID}), None))
        with patch('simulator.signet_failed_send._native') as native:
            self.assertEqual(board_ready(self.campaign)['stage'], 'WAITING_FOR_REAL_THREE_BOARD_CONFIRMATIONS')
        native.assert_not_called()

    def test_actual_exit_geometry_and_board_fee_residual_are_separate(self):
        self.setup_source()
        coin = {'id': 'a'*64+':0', 'amount_sat': 19670, 'expiry_height': 232,
            'chain_anchor': 'b'*64+':0'}
        token = hashlib.sha256(('absent:' + coin['id']).encode()).hexdigest()
        import io
        self.campaign._retain_private('coin-raw-'+token, 'stdout', io.BytesIO(b'cafe\n'))
        board = {'amount_sat': 19670, 'vtxos': [coin['id']]}
        tx = {'txid': 'b'*64, 'vin': [{'txid': old.TXID, 'vout': 0}],
            'vout': [output(20000), output(9800, old.SCRIPTS[1], 1)]}
        decoded = {**coin, 'server_pubkey': old.PUB, 'exit_delta': 12}
        original = self.campaign.core.call
        self.campaign.core.call = lambda method,*args: ({'confirmations': 3,
            'value': tx['vout'][1]['value'], 'scriptPubKey': tx['vout'][1]['scriptPubKey']}
            if method == 'gettxout' and args[0] == tx['txid'] else original(method,*args))
        with patch('simulator.signet_fresh_ln._private_call', return_value=decoded), \
             patch('simulator.signet_fresh_ln._native', return_value=[{'outpoint':tx['txid']+':1','amount_sat':9800}]):
            result = board_accounting(self.campaign, self.spec, board, tx, coin)
        self.assertEqual((result['board_miner_fee_sat'], result['carried_board_residual_sat'],
                          result['ordinary_change_sat']), (200, 330, 9800))
        self.assertEqual((result['requested_board_sat'], result['actual_anchor_sat'],
                          result['signed_customer_sat']), (20000, 20000, 19670))
        with patch('simulator.signet_fresh_ln._private_call', return_value=decoded), \
             patch('simulator.signet_fresh_ln._native', return_value=[]):
            with self.assertRaisesRegex(ValueError, 'native-owned BDK'):
                board_accounting(self.campaign, self.spec, board, tx, coin)
        decoded['exit_delta'] = 144
        with patch('simulator.signet_fresh_ln._private_call', return_value=decoded):
            with self.assertRaisesRegex(ValueError, 'short-exit12'):
                board_accounting(self.campaign, self.spec, board, tx, coin)


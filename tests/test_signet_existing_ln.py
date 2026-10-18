"""Existing-funded actor fault tests; native signatures/Core are explicit stubs."""
import hashlib
import json
import time
import unittest
from unittest.mock import patch

from simulator.model import canonical
from simulator.signet import digest
from simulator.signet_existing_ln import (stage_failed_sender, refresh_existing_sender,
    _preflight_refresh_window)
from simulator.signet_failed_send import _ready_source, board_once, funding_admission
from tests import test_signet_failed_send as funded
PUB = funded.PUB


class ExistingSenderTests(unittest.TestCase):
    def setUp(self):
        funded.FailedSendTests.setUp(self)
        # These existing flow tests isolate round completion/replay behavior.
        # The real new preflight is exercised separately below with explicit
        # native/Core/signature stubs, not counted as native financial proof.
        self.compatibility = patch('simulator.signet_existing_ln._preflight_refresh_window')
        self.compatibility_mock = self.compatibility.start()
        self.addCleanup(self.compatibility.stop)

    tearDown = funded.FailedSendTests.tearDown

    def prepare(self, stage=True):
        funded.FailedSendTests.prepare(self, execute_stage=False)
        cfg = self.root / 'service-config/captaind.toml'
        cfg.write_text(cfg.read_text().replace('vtxo_targets=[]',
            'vtxo_targets=["10000sat:2"]\nvtxo_lifetime=32\nvtxo_pre_expiry=12'))
        self.runtime_pins['config_hashes']['captaind'] = digest(cfg)
        self.campaign.config['product_config_sha256'] = hashlib.sha256(
            canonical(self.runtime_pins['config_hashes']).encode()).hexdigest()
        self.coins = [{'id': 'a' * 64 + ':0', 'state': 'spendable', 'amount_sat': 28670,
            'expiry_height': 4500, 'chain_anchor': 'b' * 64 + ':0', 'user_pubkey': PUB}]
        self.terminal = self.root / 'terminal-result.json'
        self.terminal.write_text(canonical({'status': 'INCOMPLETE', 'result': {
            'stage': 'LOAD_INCOMPLETE_WINDOW_FINANCIALLY_AUDITED',
            'failed_or_unknown_transfers': 0, 'opening_coin_sat': 28670,
            'closing_coin_sat': 28670, 'observed_offchain_fee_sat': 0,
            'backing': {'backing': 'PASS'}, 'signature_proofs': [{'status': 'PASS'}]}}))
        self.admission = {'scope': 'P09-existing-v11c', 'new_treasury_principal_sat': 0,
            'runtime_manifest_sha256': self.runtime_pins['runtime_manifest_sha256'],
            'server_pubkey': PUB, 'database': 'fresh_owned_failed_send',
            'terminal_result_sha256': digest(self.terminal), 'sender_actor': 'load-002',
            'sender': {'directory': str(self.sender), 'birthday_height': 100,
                'configuration_sha256': digest(self.sender / 'config.toml'),
                'inventory_sha256': hashlib.sha256(canonical(self.coins).encode()).hexdigest(),
                'registration_sha256': hashlib.sha256(canonical(self.registration).encode()).hexdigest(),
                'seed_sha256': digest(self.source)}}
        self.admission_path.write_text(canonical(self.admission))
        if stage:
            return self.stage_existing()

    def stage_existing(self):
        return stage_failed_sender(self.campaign, self.runtime_pins, self.admission_path,
            self.terminal, self.sender, 'load-002', self.registration, self.coins,
            100, self.source, 'tb1qrecovered')

    def native(self, campaign, intent, actor, operation, args=None):
        previous = self.campaign.db.execute('SELECT * FROM action WHERE id=?', (intent,)).fetchone()
        if previous:
            if previous['state'] != 'acknowledged':
                raise ValueError('requires reconciliation')
            return json.loads(previous['reply'])
        if operation == 'fallback_record':
            reply = self.registration
        elif intent == 'existing-source-before':
            reply = self.coins
        elif operation == 'refresh':
            reply = {'actual_native_ack': True}
        else:
            reply = [{**self.coins[0], 'state': 'spent'}, self.refreshed]
        self.campaign.db.execute('INSERT INTO action VALUES (?,?,?,?,?,?,?,?,?,?)',
            (intent, actor, operation, '{}', 'acknowledged', time.time(), time.time(),
             '{}', canonical(reply), None))
        return reply

    def refresh(self):
        with patch('simulator.signet_existing_ln._native', side_effect=self.native), \
             patch('simulator.signet_existing_ln.verify_coin', return_value={
                 'status': 'PASS', 'path_outpoints': ['c' * 64 + ':0']}), \
             patch('simulator.signet_existing_ln.confirmed_backing', return_value={'backing': 'PASS'}):
            return refresh_existing_sender(self.campaign)

    def new_coin(self):
        self.refreshed = {**self.coins[0], 'id': 'd' * 64 + ':0',
            'chain_anchor': 'c' * 64 + ':0', 'amount_sat': 28291, 'expiry_height': 232}

    def test_stage_binds_real_inventory_without_any_create_board_or_native_open(self):
        with patch('simulator.signet.subprocess.run') as native:
            result = self.prepare()
        native.assert_not_called()
        self.assertFalse(result['native_create_or_board'])
        self.assertEqual(result['original_spendable_sat'], 28670)
        self.assertEqual(self.campaign.db.execute('SELECT count(*) FROM action').fetchone()[0], 0)
        self.assertEqual(self.campaign.actor_path('absent'), self.sender)

    def test_unbound_inventory_or_original_seed_is_refused_before_open(self):
        self.prepare(stage=False)
        for field in ['inventory_sha256', 'registration_sha256', 'seed_sha256', 'configuration_sha256', 'birthday_height']:
            with self.subTest(field=field):
                original = self.admission['sender'][field]
                self.admission['sender'][field] = 'tampered'
                self.admission_path.write_text(canonical(self.admission))
                with patch('simulator.signet.subprocess.run') as native:
                    with self.assertRaisesRegex(ValueError, 'exact cold sender'):
                        self.stage_existing()
                native.assert_not_called()
                self.assertEqual(self.campaign.db.execute('SELECT count(*) FROM actor').fetchone()[0], 0)
                self.admission['sender'][field] = original

    def test_refresh_waits_zero_then_one_confirmation_without_second_refresh(self):
        self.prepare()
        self.new_coin()
        original = self.campaign.core.call
        self.depth = 0
        def core(method, *args):
            return {'confirmations': self.depth} if method == 'gettxout' else original(method, *args)
        self.campaign.core.call = core
        self.assertEqual(self.refresh()['stage'], 'WAITING_FOR_REAL_ROUND_CONFIRMATION')
        self.depth = 1
        result = self.refresh()
        self.assertEqual(result['observed_refresh_fee_sat'], 379)
        self.assertEqual(result['minimum_confirmations'], 1)
        self.assertEqual(self.campaign.db.execute("SELECT count(*) FROM action WHERE operation='refresh'").fetchone()[0], 1)
        self.assertEqual(_ready_source(self.campaign)['coin'], self.refreshed)
        self.campaign.core.info['blocks'] = 214
        with self.assertRaisesRegex(ValueError, 'D<E'):
            _ready_source(self.campaign)

    def test_unknown_refresh_is_never_replayed(self):
        self.prepare()
        self.campaign.db.execute('INSERT INTO action VALUES (?,?,?,?,?,?,?,?,?,?)',
            ('existing-source-refresh', 'absent', 'refresh', '{}', 'unknown', 1, 1, '{}', None, 'lost reply'))
        with patch('simulator.signet_existing_ln._native') as native:
            with self.assertRaisesRegex(ValueError, 'reconciliation'):
                refresh_existing_sender(self.campaign)
        native.assert_not_called()

    def test_locked_original_inputs_wait_then_complete_without_another_refresh(self):
        self.prepare()
        self.new_coin()
        observed = [{**self.coins[0], 'state': 'locked'}]
        def pending(campaign, intent, actor, operation, args=None):
            reply = self.native(campaign, intent, actor, operation, args)
            return observed if intent.startswith('existing-source-after-') else reply
        with patch('simulator.signet_existing_ln._native', side_effect=pending):
            result = refresh_existing_sender(self.campaign)
        self.assertEqual(result['stage'], 'WAITING_FOR_NATIVE_REFRESH_COMPLETION')
        self.assertEqual(result['case_verdict'], 'INCOMPLETE')
        self.assertEqual(result['locked_input_ids'], [self.coins[0]['id']])
        self.assertFalse(self.campaign.db.execute("SELECT 1 FROM result WHERE json_extract(payload,'$.kind')='failed_send_ready'").fetchone())
        self.assertEqual(self.refresh()['stage'], 'ACTUAL_NATIVE_SOURCE_READY_NO_INVOICE')
        self.assertEqual(self.campaign.db.execute("SELECT count(*) FROM action WHERE operation='refresh'").fetchone()[0], 1)

    def test_locked_inputs_with_changed_value_or_unrecognized_state_do_not_wait(self):
        self.prepare()
        self.new_coin()
        for changed in [{'state': 'locked', 'amount_sat': 1}, {'state': 'unrecognized'},
                        {'state': 'locked', 'id': 'f' * 64 + ':0'}]:
            with self.subTest(changed=changed):
                def invalid(campaign, intent, actor, operation, args=None):
                    reply = self.native(campaign, intent, actor, operation, args)
                    return [{**self.coins[0], **changed}] if intent.startswith('existing-source-after-') else reply
                with patch('simulator.signet_existing_ln._native', side_effect=invalid):
                    with self.assertRaisesRegex(ValueError, 'completed refreshed'):
                        refresh_existing_sender(self.campaign)

    def test_long_or_missing_original_coin_never_becomes_short_source(self):
        self.prepare()
        self.new_coin()
        self.refreshed['expiry_height'] = 4500
        with self.assertRaisesRegex(ValueError, 'short-tree'):
            self.refresh()

    def test_changed_terminal_result_blocks_even_cached_native_actions(self):
        self.prepare()
        self.terminal.write_text('{}')
        with patch('simulator.signet_existing_ln._native') as native:
            with self.assertRaisesRegex(ValueError, 'terminal financial'):
                refresh_existing_sender(self.campaign)
        native.assert_not_called()

    def test_existing_source_cannot_enter_new_funding_or_board_recipe(self):
        self.prepare()
        with patch('simulator.signet_failed_send._native') as native:
            for operation in [funding_admission, board_once]:
                with self.assertRaisesRegex(ValueError, 'no new funding or board'):
                    operation(self.campaign)
        native.assert_not_called()

    def test_all_original_inputs_must_be_present_and_spent_after_refresh(self):
        self.prepare()
        self.new_coin()
        def missing(campaign, intent, actor, operation, args=None):
            reply = self.native(campaign, intent, actor, operation, args)
            return [self.refreshed] if intent.startswith('existing-source-after-') else reply
        with patch('simulator.signet_existing_ln._native', side_effect=missing):
            with self.assertRaisesRegex(ValueError, 'completed refreshed'):
                refresh_existing_sender(self.campaign)


class RefreshCompatibilityTests(unittest.TestCase):
    setUp = funded.FailedSendTests.setUp
    tearDown = funded.FailedSendTests.tearDown
    prepare = ExistingSenderTests.prepare
    stage_existing = ExistingSenderTests.stage_existing
    native = ExistingSenderTests.native
    new_coin = ExistingSenderTests.new_coin

    def geometry(self, delta=144, lifetime=32):
        self.prepare()
        self.new_coin()
        self.delta, self.lifetime = delta, lifetime
        self.info = {'server_pubkey': PUB, 'vtxo_lifetime': lifetime}
        self.spec = json.loads(self.campaign.db.execute(
            "SELECT value FROM meta WHERE key='failed_send'").fetchone()[0])
        self.add_body(self.coins[0])

    def add_body(self, coin):
        import io
        token = hashlib.sha256(('absent:' + coin['id']).encode()).hexdigest()
        self.campaign._retain_private('coin-raw-' + token, 'stdout', io.BytesIO(b'cafe\n'))

    def io(self, campaign, intent, actor, operation, args=None):
        if operation == 'ark_info':
            return self.info
        if intent.startswith('existing-source-after-'):
            return [{**self.coins[0], 'state': 'locked'}]
        return self.native(campaign, intent, actor, operation, args)

    def decode(self, *args):
        return {**self.coins[0], 'server_pubkey': PUB, 'exit_delta': self.delta}

    def proof(self, *args):
        return {'status': 'PASS', 'path_outpoints': [self.coins[0]['chain_anchor'], self.coins[0]['id']]}

    def test_actual144_csv_cannot_refresh_into32_before_any_refresh_intent(self):
        self.geometry()
        with patch('simulator.signet_existing_ln._native', side_effect=self.io), \
             patch('simulator.signet_existing_ln.verify_coin', side_effect=self.proof), \
             patch('simulator.signet_existing_ln._private_call', side_effect=self.decode):
            with self.assertRaisesRegex(ValueError, 'lifetime 32.*CSV 144.*168; no refresh submitted'):
                refresh_existing_sender(self.campaign)
        self.assertEqual(self.campaign.db.execute(
            "SELECT count(*) FROM action WHERE operation='refresh'").fetchone()[0], 0)
        result = json.loads(self.campaign.db.execute(
            "SELECT payload FROM result WHERE json_extract(payload,'$.kind')='existing_refresh_compatibility'").fetchone()[0])
        self.assertFalse(result['compatible'])
        self.assertEqual(result['maximum_actual_input_csv_blocks'], 144)
        self.assertEqual(result['wallet_exit_margin_blocks'], 12)
        self.assertEqual(result['minimum_output_window_blocks'], 168)

    def test_compatible_window_is_only_a_necessary_preflight_not_ready(self):
        # The mathematical control uses an explicitly advertised64-block
        # window; the existing strict32-block campaign profile is unchanged.
        self.geometry(delta=12, lifetime=64)
        with patch('simulator.signet_existing_ln._native', side_effect=self.io), \
             patch('simulator.signet_existing_ln.verify_coin', side_effect=self.proof), \
             patch('simulator.signet_existing_ln._private_call', side_effect=self.decode):
            result = _preflight_refresh_window(self.campaign, self.coins, self.spec)
        self.assertTrue(result['compatible'])
        self.assertEqual(result['minimum_output_window_blocks'], 36)
        self.assertEqual(result['case_verdict'], 'INCOMPLETE')
        self.assertEqual(self.campaign.db.execute("SELECT count(*) FROM action WHERE operation='refresh'").fetchone()[0], 0)
        self.assertFalse(self.campaign.db.execute("SELECT 1 FROM result WHERE json_extract(payload,'$.kind')='failed_send_ready'").fetchone())

    def test_failed_signature_or_changed_decoded_input_cannot_authorize_refresh(self):
        self.geometry()
        with patch('simulator.signet_existing_ln._native', side_effect=self.io), \
             patch('simulator.signet_existing_ln.verify_coin', return_value={'status': 'FAILED'}), \
             patch('simulator.signet_existing_ln._private_call') as decoder:
            with self.assertRaisesRegex(ValueError, 'full signed original'):
                refresh_existing_sender(self.campaign)
            decoder.assert_not_called()
        decoded = self.decode()
        decoded['amount_sat'] -= 1
        with patch('simulator.signet_existing_ln._native', side_effect=self.io), \
             patch('simulator.signet_existing_ln.verify_coin', side_effect=self.proof), \
             patch('simulator.signet_existing_ln._private_call', return_value=decoded):
            with self.assertRaisesRegex(ValueError, 'signed input identity'):
                refresh_existing_sender(self.campaign)
        self.assertEqual(self.campaign.db.execute("SELECT count(*) FROM action WHERE operation='refresh'").fetchone()[0], 0)

    def test_existing_ack_observes_pending_without_a_new_compatibility_open(self):
        self.geometry()
        self.campaign.db.execute('INSERT INTO action VALUES (?,?,?,?,?,?,?,?,?,?)',
            ('existing-source-refresh', 'absent', 'refresh', '{}', 'acknowledged', 1, 1, '{}', '{}', None))
        with patch('simulator.signet_existing_ln._native', side_effect=self.io) as native, \
             patch('simulator.signet_existing_ln.verify_coin') as proof, \
             patch('simulator.signet_existing_ln._private_call') as decoder:
            result = refresh_existing_sender(self.campaign)
        self.assertEqual(result['stage'], 'WAITING_FOR_NATIVE_REFRESH_COMPLETION')
        self.assertFalse(any(call.args[3] == 'ark_info' for call in native.call_args_list))
        proof.assert_not_called()
        decoder.assert_not_called()
        self.assertEqual(self.campaign.db.execute("SELECT count(*) FROM action WHERE operation='refresh'").fetchone()[0], 1)

    def test_all_expired_inputs_keep_upstream_window_exception(self):
        self.geometry()
        coins = [{**self.coins[0], 'expiry_height': 1}]
        decoded = {**coins[0], 'server_pubkey': PUB, 'exit_delta': 144}
        with patch('simulator.signet_existing_ln._native', side_effect=self.io), \
             patch('simulator.signet_existing_ln.verify_coin', side_effect=self.proof), \
             patch('simulator.signet_existing_ln._private_call', return_value=decoded):
            result = _preflight_refresh_window(self.campaign, coins, self.spec)
        self.assertTrue(result['compatible'])
        self.assertFalse(result['any_unexpired_input'])

    def test_one_unexpired_input_uses_maximum_csv_of_all_inputs(self):
        self.geometry(lifetime=64)
        old = {**self.coins[0], 'expiry_height': 1}
        current = {**self.coins[0], 'id': 'e' * 64 + ':0'}
        self.add_body(current)
        decoded = [{**old, 'server_pubkey': PUB, 'exit_delta': 144},
                   {**current, 'server_pubkey': PUB, 'exit_delta': 12}]
        with patch('simulator.signet_existing_ln._native', side_effect=self.io), \
             patch('simulator.signet_existing_ln.verify_coin', side_effect=self.proof), \
             patch('simulator.signet_existing_ln._private_call', side_effect=decoded):
            with self.assertRaisesRegex(ValueError, 'maximum actual input CSV 144'):
                _preflight_refresh_window(self.campaign, [old, current], self.spec)
        self.assertEqual(self.campaign.db.execute("SELECT count(*) FROM action WHERE operation='refresh'").fetchone()[0], 0)

"""Synthetic scoped-admission controls; no native inventory or money credit."""
import copy
import asyncio
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from simulator.engine import Engine
from simulator.operating_limits import declare_envelope, preflight, validate
from tests.test_final_campaign import PINS
from tests.test_treasury import TreasuryFixture


class ScopedOperatingTests(TreasuryFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.config = SimpleNamespace(board_amount_sat=800, action_fee_reserve_sat=200)
        self.limits = {
            'id': 'scoped-fixture', 'pins': PINS, 'boundary_id': 'fixture',
            'capital_exposure_msat': 3000000,
            'fee_budgets_msat': {'ordinary': 500000, 'urgent': 500000},
            'fee_ceilings_sat_kvb': {'round': None, 'pool': None, 'sweep': 2000,
                                   'payout': 2000, 'claim': None, 'progression': None},
            'per_action_fee_sat': 200, 'grant_sat': 1000, 'board_sat': 800,
            'board_fee_reserve_sat': 200, 'minimum_pool_sat': 100,
            'minimum_channel_msat': 100000, 'fee_assets': ['a' * 64 + ':0'],
            'operation_fee_paths': {operation: ['sweep', 'payout'] for operation in
                ('ordinary', 'create', 'address', 'snapshot', 'sync', 'board', 'send_arkoor')},
        }
        self.inventories = {'rounds': self.inventory(self.wallet), 'peer': self.inventory(self.peer)}
        self.store.add_snapshot({'observed_at': time.time(), 'financial_pins': PINS})

    def declare(self):
        declare_envelope(self.store, self.limits, self.config, self.inventories, self.chain)

    def readiness(self, **changes):
        proof = {'financial_pins': PINS, 'boundary_id': 'fixture', 'tip_hash': 'tip',
                 'height': 100, 'complete': True, 'observed_at': time.time(),
                 'effective_fee_ceilings_sat_kvb': self.limits['fee_ceilings_sat_kvb'],
                 'capital_exposure_msat': 2000000, 'available_fee_funding_msat': 1000000,
                 'estimated_fee_rate_sat_kvb': 1000}
        proof.update(changes)
        self.event('financial_operating_readiness', proof)
        return {'financial_pins': PINS, 'tip_hash': 'tip', 'height': 100,
                'operating_readiness_sequence': self.sequence(), 'observed_at': time.time(),
                'stable_tip': True, 'initial_block_download': False,
                'server_status': {'status': 'running'}}

    def test_scoped_ordinary_uses_only_supported_paths(self):
        self.declare()
        snapshot = self.readiness()
        for operation in self.limits['operation_fee_paths']:
            with self.subTest(operation=operation):
                self.assertTrue(preflight(self.store, self.config, snapshot,
                                          operation=operation)['allowed'])
        self.assertFalse(preflight(self.store, self.config,
            self.readiness(estimated_fee_rate_sat_kvb=2001), operation='board')['allowed'])

    def test_unlisted_operations_refuse_even_before_readiness(self):
        self.declare()
        for operation in ('invoice', 'pay_invoice', 'claim', 'progression', 'refresh',
                          'exit', 'offboard_all', 'raw_protocol_d13', 'typo'):
            with self.subTest(operation=operation), self.assertRaisesRegex(ValueError, 'not declared'):
                preflight(self.store, self.config, {}, operation=operation)

    def test_null_active_or_positive_unavailable_or_missing_path_refused(self):
        for path, ceiling in [('sweep', None), ('claim', 2000), ('pool', 0)]:
            value = copy.deepcopy(self.limits)
            value['fee_ceilings_sat_kvb'][path] = ceiling
            with self.subTest(path=path), self.assertRaises(ValueError):
                validate(value, self.config)
        value = copy.deepcopy(self.limits)
        del value['fee_ceilings_sat_kvb']['pool']
        with self.assertRaises(ValueError): validate(value, self.config)

    def test_invalid_or_empty_scopes_refused(self):
        for scope in ({}, {'ordinary': []}, {'ordinary': ['invented']},
                      {'ordinary': 'sweep'}, {'ordinary': ['sweep', 'sweep']}, []):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                validate({**self.limits, 'operation_fee_paths': scope}, self.config)

    def test_actual_ceilings_must_match_including_unavailable_paths(self):
        self.declare()
        actual = {**self.limits['fee_ceilings_sat_kvb'], 'pool': 2000}
        with self.assertRaisesRegex(ValueError, 'ceilings differ'):
            preflight(self.store, self.config,
                      self.readiness(effective_fee_ceilings_sat_kvb=actual))

    def test_scoped_declaration_and_paths_are_immutable(self):
        self.declare()
        value = copy.deepcopy(self.limits)
        del value['operation_fee_paths']['board']
        with self.assertRaisesRegex(ValueError, 'immutable'):
            declare_envelope(self.store, value, self.config, self.inventories, self.chain)

    def test_engine_can_admit_scoped_ordinary_without_claim_or_progression(self):
        self.declare()
        self.store.db.execute("INSERT INTO meta VALUES ('financial_qualification_required','true')")
        engine = Engine.__new__(Engine)
        engine.store, engine.config = self.store, self.config
        self.assertTrue(engine.ready_for_actions(self.readiness()))
        self.assertFalse(engine.ready_for_actions(self.readiness(estimated_fee_rate_sat_kvb=2001)))

    def test_engine_checks_separately_declared_urgent_path_after_ordinary_hold(self):
        self.limits['operation_fee_paths']['claim'] = ['claim']
        self.limits['fee_ceilings_sat_kvb']['claim'] = 3000
        self.declare()
        self.store.db.execute("INSERT INTO meta VALUES ('financial_qualification_required','true')")
        engine = Engine.__new__(Engine)
        engine.store, engine.config = self.store, self.config
        self.assertTrue(engine.ready_for_actions(self.readiness(estimated_fee_rate_sat_kvb=2500)))
        self.assertTrue(engine.ready_for_actions(self.readiness(estimated_fee_rate_sat_kvb=2500,
            operation_scope=['claim'])))
        self.assertFalse(engine.ready_for_actions(self.readiness(estimated_fee_rate_sat_kvb=3001)))

    def test_scoped_sync_is_checked_as_sync_without_a_native_call_when_held(self):
        self.declare()
        self.store.db.execute("INSERT INTO meta VALUES ('financial_qualification_required','true')")
        self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        self.config.active = True
        self.config.wallet_root = Path(self.tmp.name) / 'wallets'
        self.config.expected_server_pubkey = '02' + '2' * 64
        scenario = self.store.db.execute('SELECT id FROM scenario LIMIT 1').fetchone()[0]
        self.store.queue('scoped-sync', 'actor-01', scenario, 'sync', {}, 200)
        engine = Engine.__new__(Engine)
        engine.store, engine.config = self.store, self.config
        with patch('simulator.operating_limits.preflight',
                   return_value={'allowed':False, 'reason':'control hold'}) as check, \
             patch('simulator.engine.json_command', AsyncMock()) as native:
            asyncio.run(engine.dispatch_one())
        self.assertEqual('sync', check.call_args.kwargs['operation'])
        native.assert_not_awaited()
        self.assertEqual('blocked', self.store.db.execute(
            "SELECT state FROM action WHERE id='scoped-sync'").fetchone()[0])

    def test_unlisted_payment_does_not_even_request_pool_or_call_driver(self):
        self.declare()
        self.store.db.execute("INSERT INTO meta VALUES ('financial_qualification_required','true')")
        self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        self.config.active = True
        self.config.wallet_root = Path(self.tmp.name) / 'wallets'
        self.config.expected_server_pubkey = '02' + '2' * 64
        scenario = self.store.db.execute('SELECT id FROM scenario LIMIT 1').fetchone()[0]
        self.store.queue('scoped-ln-denied', 'actor-01', scenario, 'pay_invoice', {}, 200)
        engine = Engine.__new__(Engine)
        engine.store, engine.config = self.store, self.config
        with patch('simulator.engine.json_command', AsyncMock()) as native:
            asyncio.run(engine.dispatch_one())
        native.assert_not_awaited()
        row = self.store.db.execute("SELECT state,result FROM action WHERE id='scoped-ln-denied'").fetchone()
        self.assertEqual('blocked', row['state'])
        self.assertIn('not declared', row['result'])

    def test_zero_principal_create_never_bootstraps_from_health_alone(self):
        engine = Engine.__new__(Engine)
        engine.store, engine.config = self.store, self.config
        self.store.db.execute("INSERT INTO meta VALUES ('financial_qualification_required','true')")
        self.assertFalse(engine.ready_for_actions({'observed_at':time.time(), 'stable_tip':True,
            'initial_block_download':False, 'server_status':{'status':'running'}}))
        self.declare()
        with self.assertRaisesRegex(ValueError, 'missing'):
            preflight(self.store, self.config, {'financial_pins':PINS}, operation='create')

"""Pause races and preparation polling with temporary state and synthetic Core."""
import asyncio
import sqlite3
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import tests.test_recovery as recovery_fixture
from simulator.engine import Engine


class MaintenancePauseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.fixture = recovery_fixture.RecoveryTests('test_long_seed_scan_is_polled_without_blocking_customer_ticks')
        await self.fixture.asyncSetUp()
        self.future = asyncio.Future()
        async def blocked(*args): return await self.future
        self.fixture.prepare = AsyncMock(side_effect=blocked)
        self.controller = self.fixture.controller_for()
        await self.controller.tick()
        await asyncio.sleep(0)
        self.store = self.fixture.store
        fields = {**vars(self.fixture.config), 'active': True, 'workload': 'continuous',
            'trace_enabled': False, 'funding_wallet': None, 'recovery_command': (),
            'interval_seconds': 30, 'dispatch_per_tick': 1, 'server_policy_command': (),
            'proof_command': ('unused', 'http://127.0.0.1:1', 'unused', 'signet'),
            'driver_command': (), 'inventory_command': (), 'expected_server_pubkey': '03' + '1' * 64,
            'log_target_enabled': False, 'log_local_sources': ()}
        self.engine = Engine(SimpleNamespace(**fields), self.store)
        self.engine.recovery = self.controller
        self.snapshot = {'observed_at': 0, 'height': 100, 'timings': {'payout_enabled': True}}
        async def observed():
            self.store.add_snapshot(self.snapshot)
            return self.snapshot
        self.engine.observe = AsyncMock(side_effect=observed)
        self.engine.ready_for_actions = Mock(return_value=True)
        self.engine.collect_inventory = AsyncMock()
        self.patches = ExitStack()
        for name in ('collect_public_proofs', 'collect_payments', 'collect_negative_checks',
                     'retry_public_candidates', 'collect_operator_scripts', 'collect_direct_settlements',
                     'collect_fees', 'collect_recycling'):
            self.patches.enter_context(patch('simulator.engine.' + name, AsyncMock()))
        for name in ('collect_renewal', 'collect_delegated', 'collect_ark_receipts', 'observe', 'generate'):
            self.patches.enter_context(patch('simulator.engine.' + name, Mock()))
        self.patches.enter_context(patch('simulator.engine.ChainReader', Mock()))
        self.patches.enter_context(patch('simulator.round_adoption.collect_input_params', AsyncMock()))

    async def asyncTearDown(self):
        self.patches.close()
        await self.fixture.asyncTearDown()

    def pause(self, reason):
        # Reproduce the real external writer between a scheduler guard and queue.
        db = sqlite3.connect(self.store.root / 'state.sqlite', isolation_level=None)
        try: db.execute("INSERT OR REPLACE INTO meta VALUES ('paused',?)", (reason,))
        finally: db.close()

    async def racing_pause(self, reason):
        original = self.store.queue
        def race(*args, **kwargs):
            self.pause(reason)
            return original(*args, **kwargs)
        with patch.object(self.store, 'queue', side_effect=race):
            await self.engine.run(once=True)
        self.assertEqual(reason, self.store.get_meta('paused'))
        self.assertEqual('preparing', self.fixture.recoveries()[0]['state'])
        self.assertEqual(1, self.fixture.prepare.await_count)
        self.assertFalse(next(iter(self.controller.jobs.values())).cancelled())
        self.assertEqual(0, self.fixture.sends())
        self.assertEqual(1, self.store.db.execute('SELECT count(*) FROM action').fetchone()[0])
        self.assertIsNone(self.store.claim({'create'}))

    async def test_legitimate_lease_acquired_during_schedule_keeps_preparation_alive(self):
        from simulator.store import Store
        second = Store(self.store.root, 'synthetic')
        original = self.store.queue
        def lease_after_guard(*args, **kwargs):
            self.assertTrue(second.acquire_actor_lease(args[1], 'private-controller-race', 'synthetic review'))
            return original(*args, **kwargs)
        try:
            with patch.object(self.store, 'queue', side_effect=lease_after_guard):
                await self.engine.run(once=True)
            self.assertTrue(self.store.actor_held('actor-01'))
            self.assertEqual('preparing', self.fixture.recoveries()[0]['state'])
            self.assertFalse(next(iter(self.controller.jobs.values())).cancelled())
            self.assertEqual(1, self.store.db.execute('SELECT count(*) FROM action').fetchone()[0])
            self.assertEqual(0, self.fixture.sends())
        finally:
            second.close()

    async def test_external_maintenance_pause_does_not_exit_or_cancel_preparation(self):
        await self.racing_pause('declared target upgrade')

    async def test_incident_pause_race_remains_fenced_without_restart(self):
        await self.racing_pause('incident')

    async def test_finished_preparation_is_observed_during_paused_inventory_failure(self):
        self.pause('declared target upgrade')
        self.future.set_result(self.fixture.prepared)
        await asyncio.sleep(0)
        self.engine.collect_inventory = AsyncMock(side_effect=ValueError('inventory unavailable'))
        await self.engine.run(once=True)
        self.assertEqual('prepared', self.fixture.recoveries()[0]['state'])
        self.assertEqual({}, self.controller.jobs)
        self.assertEqual(0, self.fixture.sends())
        self.assertEqual(1, self.fixture.prepare.await_count)

    async def test_finished_preparation_during_incident_never_broadcasts(self):
        self.pause('incident')
        self.future.set_result(self.fixture.prepared)
        await asyncio.sleep(0)
        await self.engine.run(once=True)
        self.assertEqual('prepared', self.fixture.recoveries()[0]['state'])
        self.assertEqual('incident', self.store.get_meta('paused'))
        self.assertEqual(0, self.fixture.sends())

    async def test_unrelated_queue_error_is_not_hidden_as_a_pause(self):
        with patch.object(self.store, 'queue', side_effect=ValueError('unrelated queue invariant')):
            with self.assertRaisesRegex(ValueError, 'unrelated queue invariant'):
                await self.engine.run(once=True)

    async def test_independent_recovery_invariant_remains_an_incident(self):
        self.pause('declared target upgrade')
        self.engine.collect_inventory = AsyncMock(side_effect=ValueError('inventory unavailable'))
        original = self.fixture.rpc.call
        def wrong_chain(method, *args, **kwargs):
            return 'wrong-genesis' if method == 'getblockhash' else original(method, *args, **kwargs)
        with patch.object(self.fixture.rpc, 'call', side_effect=wrong_chain):
            await self.engine.run(once=True)
        self.assertEqual('ownership contradiction', self.store.get_meta('paused'))
        self.assertTrue(self.store.db.execute("SELECT 1 FROM event WHERE kind='ownership_incident'").fetchone())
        self.assertEqual('preparing', self.fixture.recoveries()[0]['state'])
        self.assertEqual(0, self.fixture.sends())

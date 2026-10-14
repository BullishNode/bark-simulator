"""Supervisor ordering controls; synthetic sources earn no payment credit."""
import tempfile
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from simulator.config import Config
from simulator.engine import Engine, initialize
from simulator.model import SIGNET_GENESIS
from simulator.store import Store


class FinancialAdmissionOrderTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.store = Store(root, 'synthetic', 10000)
        initialize(self.store)
        self.store.db.execute("INSERT INTO meta VALUES ('financial_qualification_required','true')")
        config = Config(root, ('observer',), (), root / 'wallets', SIGNET_GENESIS,
                        'abandon-signet-fallback', 'sha256:' + '1' * 64,
                        '02' + '2' * 64, 10000, 1, 10, False,
                        proof_command=('proof', 'http://127.0.0.1:18443', str(root / 'cookie'), 'server'),
                        inventory_command=('bridge',), trace_enabled=False)
        self.engine = Engine(config, self.store)
        self.order = []
        self.snapshot = {'observed_at': time.time(), 'stable_tip': True,
                         'initial_block_download': False, 'server_status': {'status': 'running'}}

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    async def run_once(self, error=None, *, same_tip=True, actual_preflight=False):
        async def source(*args):
            self.order.append('source')
            if error:
                raise error
            return {'qualified': False, 'complete': False, 'independent_same_tip': same_tip,
                    'gaps': ['control source only']}

        def admission(snapshot):
            self.order.append('admission')
            return False

        with ExitStack() as stack:
            stack.enter_context(patch.object(self.engine, 'observe', AsyncMock(return_value=self.snapshot)))
            if not actual_preflight:
                stack.enter_context(patch.object(self.engine, 'ready_for_actions', side_effect=admission))
            dispatch = stack.enter_context(patch.object(self.engine, 'dispatch_batch', AsyncMock()))
            stack.enter_context(patch.object(self.engine, 'collect_inventory', AsyncMock()))
            stack.enter_context(patch('simulator.engine.ChainReader', return_value=SimpleNamespace()))
            stack.enter_context(patch('simulator.financial_observer.collect_partial', side_effect=source))
            for name in ('collect_negative_checks', 'collect_protocol_checks', 'retry_public_candidates',
                         'collect_operator_scripts', 'collect_fees', 'collect_recycling'):
                stack.enter_context(patch('simulator.engine.' + name, AsyncMock()))
            stack.enter_context(patch.object(self.engine, 'collect_settlement_evidence', AsyncMock()))
            stack.enter_context(patch('simulator.entitlements.collect'))
            stack.enter_context(patch('simulator.engine.observe'))
            stack.enter_context(patch('simulator.engine.generate'))
            await self.engine.run(once=True)
            dispatch.assert_not_awaited()

    async def test_collects_sources_before_the_first_admission_check(self):
        await self.run_once()
        self.assertEqual(['source', 'admission'], self.order)
        self.assertEqual(0, self.store.db.execute(
            "SELECT count(*) FROM event WHERE kind='financial_operating_readiness'").fetchone()[0])

    async def test_source_refresh_interval_is_shorter_than_readiness_lifetime(self):
        self.store.db.execute("INSERT INTO meta VALUES ('financial_partial_observed_at',?)",
                              (str(time.time() - 91),))
        await self.run_once()
        self.assertEqual(['source', 'admission'], self.order)

    async def test_unavailable_source_holds_admission_without_advancing_refresh_time(self):
        await self.run_once(ValueError('source unavailable'))
        self.assertEqual(['source'], self.order)
        self.assertIsNone(self.store.get_meta('financial_partial_observed_at'))
        self.assertEqual(1, self.store.db.execute(
            "SELECT count(*) FROM event WHERE kind='financial_source_gap'").fetchone()[0])

    async def test_inconsistent_tip_does_not_reuse_an_existing_readiness_claim(self):
        await self.run_once(same_tip=False)
        self.assertEqual(['source'], self.order)
        self.assertIsNone(self.store.get_meta('financial_partial_observed_at'))

    async def test_successful_partial_collection_never_opens_actual_preflight(self):
        await self.run_once(actual_preflight=True)
        self.assertEqual(['source'], self.order)
        self.assertIsNotNone(self.store.get_meta('financial_partial_observed_at'))
        self.assertEqual(0, self.store.db.execute(
            "SELECT count(*) FROM event WHERE kind='financial_operating_readiness'").fetchone()[0])


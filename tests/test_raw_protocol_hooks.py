"""Supervisor integration gates for explicitly frozen protocol probes."""
import tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock,patch
from simulator.engine import Engine,initialize
from simulator.store import Store

class ProtocolHookTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp=tempfile.TemporaryDirectory();root=Path(self.temp.name)
        self.store=Store(root,'synthetic',10000);initialize(self.store)
        self.config=SimpleNamespace(active=True,wallet_root=root/'wallets',trace_enabled=False,
            workload='manual',recovery_command=(),driver_command=('driver',),action_timeout_seconds=30,
            expected_server_pubkey='02'+'33'*32,proof_command=())
    async def asyncTearDown(self):self.store.close();self.temp.cleanup()
    async def test_new_adapters_available_without_entering_automatic_rotation(self):
        from simulator.raw_cases import RAW_CASES,next_case
        from simulator.raw_protocol import OPERATIONS
        self.assertTrue(set(OPERATIONS).issubset(RAW_CASES))
        for count in range(100):self.assertNotIn(next_case(self.store,'actor-11',count)[1],OPERATIONS)
    async def test_protocol_incident_remains_unknown_and_reserves_fee(self):
        self.store.queue('probe','actor-11','D02','raw_record_tamper',{},2000)
        with patch('simulator.engine.json_command',AsyncMock(return_value={'action_id':'probe','status':'incident'})):
            await Engine(self.config,self.store).dispatch_one()
        row=self.store.db.execute('SELECT * FROM action WHERE id="probe"').fetchone()
        self.assertEqual('outcome_unknown',row['state']);self.assertIsNone(row['actual_fee_sat'])
        self.assertEqual('incident',self.store.get_meta('paused'));self.assertEqual(8000,self.store.remaining_fee_budget())
    async def test_absent_original_is_blocked_without_calling_driver(self):
        self.store.queue('probe','actor-03','D13','raw_protocol_d13',{},2000)
        action=self.store.claim({'raw_protocol_d13'})
        with patch('simulator.engine.json_command',AsyncMock(return_value={'action_id':'probe','status':'error'})) as driver:
            await Engine(self.config,self.store).dispatch_one(action)
        self.assertEqual(0,driver.await_count)
        self.assertEqual('blocked',self.store.db.execute('SELECT state FROM action WHERE id="probe"').fetchone()[0])

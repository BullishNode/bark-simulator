import asyncio,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock,patch
from simulator.engine import Engine,initialize
from simulator.store import Store

class ExitHoldTests(unittest.TestCase):
    def test_native_exit_acknowledgement_keeps_original_reservation_and_actor_hold(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);store=Store(root/'state','synthetic',10000);initialize(store)
            cfg=SimpleNamespace(workload='none',trace_enabled=True,trace_retention_days=30,recovery_command=(),active=True,wallet_root=root/'wallets',driver_command=('native',),
                expected_server_pubkey='server',action_timeout_seconds=10,proof_command=())
            store.queue('exit','actor-01','H34','exit',{'input_vtxo_ids':['coin']},2000)
            response={'action_id':'exit','status':'ok','actual_fee_sat':0,'data':{'started':True,'finished':True}}
            native=AsyncMock(return_value=response)
            with patch('simulator.engine.json_command',native),patch('simulator.engine.record_actor_result') as record:
                self.assertTrue(asyncio.run(Engine(cfg,store).dispatch_one()))
                row=store.db.execute("SELECT * FROM action WHERE id='exit'").fetchone()
                self.assertEqual('outcome_unknown',row['state']);self.assertIsNone(row['actual_fee_sat'])
                self.assertEqual(2000,row['fee_reservation_sat']);record.assert_not_called()
                store.queue('next','actor-01','H01','snapshot',{},0)
                self.assertFalse(asyncio.run(Engine(cfg,store).dispatch_one()))
                self.assertEqual(1,native.await_count)
            self.assertTrue(store.verify_event_chain());store.close()

if __name__=='__main__':unittest.main()

import json,time,unittest,tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from tests import test_continuous
from simulator.continuous import schedule

class TrafficLiquidityTests(unittest.TestCase):
    setUp=test_continuous.ContinuousTests.setUp
    tearDown=test_continuous.ContinuousTests.tearDown
    detail=test_continuous.ContinuousTests.detail
    def test_use_existing_affordable_payer_without_replenishing_a_named_wallet(self):
        from simulator.continuous import lightning_payer
        self.detail('actor-05',registered_spendable_sat=2850)
        self.detail('actor-08',registered_spendable_sat=12948)
        self.assertEqual('actor-08',lightning_payer(self.s,self.c)[0])
        self.assertEqual(0,self.s.db.execute('SELECT COUNT(*) FROM action').fetchone()[0])
    def test_closed_originals_and_private_phones_are_never_payers(self):
        from simulator.continuous import lightning_payer
        for actor in ['actor-03','actor-09','actor-10']:
            self.detail(actor,registered_spendable_sat=50000)
        self.s.actor('actor-41','noah');self.detail('actor-41',registered_spendable_sat=50000)
        self.assertIsNone(lightning_payer(self.s,self.c)[0])
    def test_stale_or_unsynchronized_capital_does_not_authorize_payment(self):
        from simulator.continuous import lightning_payer
        for extra in [{'snapshot_at':0},{'snapshot_at':time.time()-181},{'needs_sync':True}]:
            self.detail('actor-12',registered_spendable_sat=12000,**extra)
            self.assertIsNone(lightning_payer(self.s,self.c)[0])

class LiquidityDispatchFenceTests(unittest.IsolatedAsyncioTestCase):
    async def test_recipient_hold_after_claim_prevents_native_wallet_call(self):
        from simulator.engine import Engine,initialize
        from simulator.store import Store
        with tempfile.TemporaryDirectory() as directory:
            store=Store(Path(directory)/'state','synthetic',10000);initialize(store)
            try:
                store.queue('capital-send','actor-08','H07','send_arkoor',{'recipient_actor':'actor-05','purpose':'replenish_lightning_payer'},2000)
                action=store.claim({'send_arkoor'})
                store.acquire_actor_lease('actor-05','private-trial','trial')
                config=SimpleNamespace(active=True,trace_enabled=False,workload='pilot',recovery_command=(),wallet_root=Path(directory)/'wallets')
                with patch('simulator.engine.json_command',side_effect=AssertionError('unsafe native call')):
                    self.assertTrue(await Engine(config,store).dispatch_one(action))
                row=store.db.execute("SELECT state,actual_fee_sat FROM action WHERE id='capital-send'").fetchone()
                self.assertEqual(('blocked',0),tuple(row))
            finally:store.close()

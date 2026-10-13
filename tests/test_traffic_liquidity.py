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
    action=test_continuous.ContinuousTests.action
    def prepare(self):
        self.c.active=True
        self.snapshot['capabilities']['lightning_configured']=True
        self.detail('actor-05',registered_spendable_sat=2850)
        self.detail('actor-08',registered_spendable_sat=12948)
    def test_live_payer_shortfall_circulates_existing_client_principal(self):
        self.prepare();schedule(self.s,self.c,self.snapshot);a=self.action()
        self.assertEqual(('actor-08','send_arkoor'),(a['actor_id'],a['operation']))
        args=json.loads(a['args']);self.assertEqual('actor-05',args['recipient_actor'])
        self.assertEqual(3150,args['amount_sat'])
        self.assertEqual('replenish_lightning_payer',args['purpose'])
        self.assertEqual(2000,a['fee_reservation_sat'])
        self.assertEqual(2850,json.loads(self.s.db.execute("SELECT details FROM actor WHERE id='actor-05'").fetchone()[0])['registered_spendable_sat'])
        event=json.loads(self.s.db.execute("SELECT payload FROM event WHERE kind='client_liquidity_transfer_intent'").fetchone()[0]);self.assertEqual(0,event['external_injection_sat']);self.assertEqual(0,event['recycling_credit_sat'])
    def test_lost_transfer_does_not_create_a_second_payment(self):
        self.prepare();schedule(self.s,self.c,self.snapshot);a=self.action();self.s.db.execute("UPDATE action SET state='outcome_unknown' WHERE id=?",(a['id'],))
        self.detail('actor-12',registered_spendable_sat=12000)
        schedule(self.s,self.c,self.snapshot)
        self.assertEqual(1,self.s.db.execute("SELECT COUNT(*) FROM action WHERE json_extract(args,'$.purpose')='replenish_lightning_payer'").fetchone()[0])
        self.assertFalse(self.s.get_meta('paused'))
    def test_stale_or_unsynchronized_donor_is_not_spent(self):
        for state in [{'snapshot_at':0},{'snapshot_at':time.time()-181},{'needs_sync':True}]:
            with self.subTest(state=state):
                self.prepare();self.detail('actor-08',registered_spendable_sat=12948,**state);schedule(self.s,self.c,self.snapshot)
                self.assertFalse(self.s.db.execute("SELECT 1 FROM action WHERE json_extract(args,'$.purpose')='replenish_lightning_payer'").fetchone())
                self.s.db.execute("DELETE FROM action WHERE state='queued'")
    def test_payer_hold_or_offline_state_keeps_capital_in_place(self):
        self.prepare();self.s.acquire_actor_lease('actor-05','private','trial');schedule(self.s,self.c,self.snapshot)
        self.assertFalse(self.s.db.execute("SELECT 1 FROM action WHERE json_extract(args,'$.purpose')='replenish_lightning_payer'").fetchone())
    def test_noah_and_absent_originals_are_never_donors(self):
        self.prepare();self.detail('actor-08',registered_spendable_sat=0)
        self.detail('actor-03',registered_spendable_sat=50000);self.s.set_online('actor-03',False)
        self.s.actor('noah-phone-01','noah');self.detail('noah-phone-01',registered_spendable_sat=50000)
        schedule(self.s,self.c,self.snapshot)
        self.assertFalse(self.s.db.execute("SELECT 1 FROM action WHERE json_extract(args,'$.purpose')='replenish_lightning_payer'").fetchone())
        self.assertFalse(self.s.online('actor-03'))
    def test_known_success_waits_for_receive_sync_and_fresh_balance(self):
        self.prepare();schedule(self.s,self.c,self.snapshot);a=self.action();self.s.db.execute("UPDATE action SET state='completed' WHERE id=?",(a['id'],))
        self.detail('actor-12',registered_spendable_sat=12000)
        schedule(self.s,self.c,self.snapshot)
        self.assertEqual(1,self.s.db.execute("SELECT COUNT(*) FROM action WHERE json_extract(args,'$.purpose')='replenish_lightning_payer'").fetchone()[0])
    def test_fee_reservation_and_retained_donor_balance_are_not_spent(self):
        self.prepare();self.detail('actor-08',registered_spendable_sat=8149)
        schedule(self.s,self.c,self.snapshot)
        self.assertFalse(self.s.db.execute("SELECT 1 FROM action WHERE json_extract(args,'$.purpose')='replenish_lightning_payer'").fetchone())
    def test_old_success_without_independent_receipt_stays_held(self):
        self.prepare();schedule(self.s,self.c,self.snapshot);a=self.action()
        self.s.db.execute("UPDATE action SET state='completed',actual_fee_sat=0 WHERE id=?",(a['id'],))
        self.detail('actor-05',registered_spendable_sat=2850)
        schedule(self.s,self.c,self.snapshot)
        self.assertEqual(1,self.s.db.execute("SELECT COUNT(*) FROM action WHERE json_extract(args,'$.purpose')='replenish_lightning_payer'").fetchone()[0])
    def test_fresh_receipt_and_fee_proof_allow_a_later_genuine_shortfall(self):
        self.prepare();schedule(self.s,self.c,self.snapshot);a=self.action()
        self.s.db.execute("UPDATE action SET state='completed',actual_fee_sat=0 WHERE id=?",(a['id'],))
        self.s.event('ark_transfer_verified',{'action_id':a['id'],'recipient_actor':'actor-05'})
        self.detail('actor-05',registered_spendable_sat=2850)
        schedule(self.s,self.c,self.snapshot)
        self.assertEqual(2,self.s.db.execute("SELECT COUNT(*) FROM action WHERE json_extract(args,'$.purpose')='replenish_lightning_payer'").fetchone()[0])
    def test_payer_with_a_stale_balance_does_not_receive_another_transfer(self):
        self.prepare();self.detail('actor-05',registered_spendable_sat=2850,snapshot_at=0)
        schedule(self.s,self.c,self.snapshot)
        self.assertFalse(self.s.db.execute("SELECT 1 FROM action WHERE json_extract(args,'$.purpose')='replenish_lightning_payer'").fetchone())

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

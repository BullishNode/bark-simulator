import json,time,unittest
from tests import test_continuous
from simulator.continuous import lightning_payer,queue_lightning_pair,lightning_recipient
from simulator.receive_sync import queue_payment_receiver
from simulator.pool_readiness import ready

class LightningPairTests(unittest.TestCase):
    setUp=test_continuous.ContinuousTests.setUp
    tearDown=test_continuous.ContinuousTests.tearDown
    detail=test_continuous.ContinuousTests.detail
    action=test_continuous.ContinuousTests.action
    def pool(self):
        self.snapshot.update(identity={'genesis':'g','server_pubkey':'s'},tip_hash='tip',pool_status={
            'schema_version':1,'observed_at':time.time(),'height':100,'tip_hash':'tip','genesis':'g','server_pubkey':'s',
            'stable_tip':True,'complete':True,'pool_pre_expiry_blocks':10,
            'pool':{'confirmed_eligible_count':8,'confirmed_eligible_amount_sat':80000,'minimum_eligible_expiry_height':148}})
        self.snapshot['capabilities']['lightning_configured']=True
    def test_pool_requires_positive_fresh_same_identity_evidence(self):
        self.pool();self.assertTrue(ready(self.snapshot,2000))
        for field,value in [('complete',False),('observed_at',time.time()-91),('server_pubkey','other'),('height',99),('tip_hash','other')]:
            self.pool();self.snapshot['pool_status'][field]=value;self.assertFalse(ready(self.snapshot,2000))
        for field,value in [('confirmed_eligible_count',0),('confirmed_eligible_amount_sat',1999),('minimum_eligible_expiry_height',110)]:
            self.pool();self.snapshot['pool_status']['pool'][field]=value;self.assertFalse(ready(self.snapshot,2000))
        self.snapshot['pool_status']={};self.assertFalse(ready(self.snapshot,2000))
    def test_highest_fresh_payer_without_unknowns_is_chosen(self):
        self.detail('actor-05',registered_spendable_sat=2823)
        self.detail('actor-12',registered_spendable_sat=10718)
        self.assertEqual('actor-12',lightning_payer(self.s,self.c)[0])
        self.s.queue('unknown','actor-12','H01','sync',{},2000)
        self.s.db.execute("UPDATE action SET state='outcome_unknown' WHERE id='unknown'")
        self.assertIsNone(lightning_payer(self.s,self.c)[0])
    def test_invoice_not_created_until_both_pool_and_payer_are_ready(self):
        self.pool();self.assertFalse(queue_lightning_pair(self.s,self.c,self.snapshot,{}))
        self.detail('actor-12',registered_spendable_sat=10718)
        self.snapshot['pool_status']['complete']=False
        self.assertFalse(queue_lightning_pair(self.s,self.c,self.snapshot,{}))
        self.pool();self.assertTrue(queue_lightning_pair(self.s,self.c,self.snapshot,{}))
        self.assertEqual('actor-12',json.loads(self.action()['args'])['planned_payer_actor'])
        self.assertFalse(queue_lightning_pair(self.s,self.c,self.snapshot,{}))
    def test_unknown_receiver_is_not_accepted_as_a_fallback(self):
        self.s.queue('unknown','actor-06','H01','sync',{},2000)
        self.s.db.execute("UPDATE action SET state='outcome_unknown' WHERE id='unknown'")
        self.assertEqual('actor-08',lightning_recipient(self.s)[0])
    def test_exact_frozen_receiver_hash_is_claimed_once_without_replaying_payer(self):
        h='a'*64
        self.s.queue('invoice','actor-08','H40','invoice',{'amount_sat':2000},2000)
        self.s.db.execute("UPDATE action SET state='completed',result=? WHERE id='invoice'",(json.dumps({'data':{'payment_hash':h}}),))
        payer={'id':'payer','args':{'recipient_actor':'actor-08','recipient_invoice_action':'invoice'}}
        claimed=queue_payment_receiver(self.s,self.c,payer,h)
        self.assertEqual(h,claimed['args']['receive_payment_hash'])
        self.assertEqual(2000,claimed['fee_reservation_sat'])
        self.assertIsNone(queue_payment_receiver(self.s,self.c,payer,h))
        self.assertEqual(2,self.s.db.execute('SELECT COUNT(*) FROM action').fetchone()[0])
        self.s.verify_event_chain()

class ExactReceiverDispatchTests(unittest.IsolatedAsyncioTestCase):
    async def test_receiver_runs_before_payer_reply_and_preserves_unknown_fee(self):
        import asyncio,tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import patch,AsyncMock
        from simulator.store import Store
        from simulator.engine import Engine,initialize
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);wallets=root/'wallets';wallets.mkdir()
            store=Store(root/'state','synthetic',20000);initialize(store)
            try:
                h='a'*64
                store.queue('invoice','actor-08','H40','invoice',{'amount_sat':2000},2000)
                store.db.execute("UPDATE action SET state='completed',result=? WHERE id='invoice'",(json.dumps({'data':{'payment_hash':h}}),))
                store.queue('payer','actor-12','H40','pay_invoice',{'amount_sat':2000,'recipient_actor':'actor-08','recipient_invoice_action':'invoice'},2000)
                test=LightningPairTests();test.snapshot={'height':100};test.snapshot['capabilities']={};test.pool()
                snapshot={**test.snapshot,'observed_at':time.time(),'stable_tip':True,'initial_block_download':False}
                store.add_snapshot(snapshot)
                config=SimpleNamespace(active=True,trace_enabled=False,workload='pilot',recovery_command=(),
                    wallet_root=wallets.resolve(),inventory_command=('observer',),driver_command=('driver',),
                    expected_server_pubkey='s',proof_command=(),action_timeout_seconds=5,action_fee_reserve_sat=2000)
                receiver_started=asyncio.Event()
                async def native(command,request,**kwargs):
                    if request.get('kind')=='pool_status':return snapshot['pool_status']
                    if request['operation']=='pay_invoice':
                        kwargs['on_event']({'action_id':'payer','event':'lightning_proposal','data':{'payment_hash':h}})
                        await asyncio.wait_for(receiver_started.wait(),2)
                        return {'action_id':'payer','status':'ok','actual_fee_sat':None,'data':{'initiated':True,'payment_hash':h}}
                    self.assertEqual('sync',request['operation']);self.assertEqual(h,request['args']['receive_payment_hash'])
                    receiver_started.set()
                    return {'action_id':request['action_id'],'status':'ok','actual_fee_sat':None,'data':{'bounded_receive_sync':True}}
                with patch('simulator.engine.json_command',side_effect=native),patch('simulator.engine.verify_client_evidence',AsyncMock(return_value=None)):
                    await Engine(config,store).dispatch_one()
                row=store.db.execute("SELECT state,actual_fee_sat FROM action WHERE id='receive-drive:payer'").fetchone()
                self.assertEqual(('completed',None),tuple(row))
                self.assertEqual(1,store.db.execute("SELECT COUNT(*) FROM action WHERE operation='pay_invoice'").fetchone()[0])
                store.verify_event_chain()
            finally:store.close()

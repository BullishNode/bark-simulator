"""Actual callback wiring and durable financial holds; native calls are mocked."""
import copy,hashlib,json,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock,patch

import test_noah_adapter as fixtures
import test_noah_controller as controllers
from simulator.engine import Engine

class NoahNativeJobs(unittest.IsolatedAsyncioTestCase):
    setUp=fixtures.NoahAdapterTests.setUp
    tearDown=fixtures.NoahAdapterTests.tearDown
    adapter=fixtures.NoahAdapterTests.adapter
    controller=controllers.NoahPrivateControllerTests.controller

    async def test_original_invoice_push_invokes_native_invoice_then_submits_without_claim(self):
        controller,adapter,_=self.controller();adapter._sessions['actor-41']=('private-session',2000)
        async def submit(*args):return {'success':True}
        adapter.transport=submit
        calls=[]
        async def native(*args):
            calls.append(args);return {'invoice':'private-native-invoice','payment_hash':fixtures.HASH}
        engine=SimpleNamespace(store=self.store,noah_action=native,config=SimpleNamespace(wallet_root=self.root/'phones'))
        inbox=SimpleNamespace(adapter=adapter,original=lambda actor,cursor:{'payload':{
            'to':['ExpoPushToken[phone]'],'data':fixtures.canonical({'notification_type':'lightning_invoice_request',
             'transaction_id':'00000000-0000-4000-8000-000000000001','amount':5000000})}},_token=lambda actor:'ExpoPushToken[phone]')
        result=await controller.consume(inbox,'actor-41',7,engine)
        self.assertEqual('invoice_submitted',result['state']);self.assertFalse(result['outcome_verified'])
        self.assertEqual(('actor-41','noah-job-actor-41-7','invoice',{'amount_sat':5000},1000),calls[0][1:])
        await controller.consume(inbox,'actor-41',7,engine);self.assertEqual(1,len(calls))

    def engine(self):
        self.store.actor('actor-41','noah-phone')
        self.store.db.execute("UPDATE meta SET value='live' WHERE key='mode'")
        command=self.root/'native';command.write_bytes(b'unit-stub-only')
        self.manifest['source']['driver_binary_sha256']=hashlib.sha256(command.read_bytes()).hexdigest()
        self.manifest['evidence']['source']=self.store.trace_capture('noah.readiness.source',{'observed':copy.deepcopy(self.manifest['source']),'verified':True,'method':'independent_observation'})
        wallets=self.root/'wallets';(wallets/'actor-41').mkdir(parents=True)
        self.store.add_snapshot({'observed_at':time.time(),'complete':True,'stable_tip':True,'initial_block_download':False,'server_status':{'status':'running'}})
        cfg=SimpleNamespace(active=True,trace_enabled=True,trace_retention_days=30,workload='none',recovery_command=(),wallet_root=wallets,
            driver_command=(str(command),),inventory_command=('unit-bridge',),expected_server_pubkey=fixtures.PUB,
            action_timeout_seconds=10,validate_identity=lambda snapshot:None)
        adapter=self.adapter();adapter._ready=lambda **kwargs:None # Mock independently qualified live admission, not transport.
        return Engine(cfg,self.store),adapter

    async def test_claim_ack_stays_unknown_fee_reserved_and_secret_wire_private(self):
        engine,adapter=self.engine()
        response={'action_id':'claim-1','status':'ok','actual_fee_sat':None,'data':{'raw_wire':'private-preimage-material','payment_hash':fixtures.HASH}}
        with patch('simulator.engine.json_command',AsyncMock(return_value=response)) as native:
            data=await engine.noah_action(adapter,'actor-41','claim-1','claim_lightning',{'receive_payment_hash':fixtures.HASH},1000)
            self.assertEqual(response['data'],data)
            with self.assertRaises(ValueError):await engine.noah_action(adapter,'actor-41','claim-1','claim_lightning',{'receive_payment_hash':fixtures.HASH},1000)
            self.assertEqual(1,native.await_count)
        row=self.store.db.execute('SELECT state,actual_fee_sat FROM action WHERE id="claim-1"').fetchone()
        self.assertEqual(('outcome_unknown',None),tuple(row))
        text=' '.join(r[0] for r in self.store.db.execute('SELECT payload FROM event'))
        self.assertNotIn('private-preimage-material',text)

    async def test_frozen_payer_dispatch_after_state_transition_is_once_only_and_unknown(self):
        engine,adapter=self.engine();(engine.config.wallet_root/'actor-241').mkdir()
        self.binding=self.store.trace_capture('noah.recipient.invoice',{'actor':'actor-41','auth_pubkey':fixtures.PUB,
            'ark_address':self.phone['ark_address'],'payment_hash':fixtures.HASH,'invoice_sha256':self.proof['invoice_sha256'],
            'amount_msat':5000000,'source':'device','registered_destination_checked':True},actor='actor-41')
        await adapter.negotiate('pay-1','actor-241','actor-41',5000000,binding=self.binding)
        calls=[]
        async def native(argv,request,**kwargs):
            if request.get('kind')=='pool_status':return {'unit-only':True}
            calls.append(request)
            return {'action_id':'pay-1','status':'ok','actual_fee_sat':None,'data':{'payment_hash':fixtures.HASH,'paid':True}}
        async def submit(request):return await engine.noah_action(adapter,request['actor'],'pay-1',request['operation'],request['args'],request['maximum_fee_sat'])
        with patch('simulator.engine.json_command',native),patch('simulator.pool_readiness.ready',return_value=True):
            await adapter.dispatch('pay-1',submit);await adapter.dispatch('pay-1',submit)
        self.assertEqual(1,len(calls));self.assertEqual(fixtures.HASH,calls[0]['args']['payment_hash'])
        self.assertEqual('outcome_unknown',adapter.intent('pay-1')['state'])
        self.assertEqual('outcome_unknown',self.store.db.execute('SELECT state FROM action WHERE id="pay-1"').fetchone()[0])

    async def test_absent_phone_wrong_driver_and_fee_drift_never_launch_native(self):
        engine,adapter=self.engine()
        with patch('simulator.engine.json_command',side_effect=AssertionError('native launch')):
            self.store.set_online('actor-41',False)
            with self.assertRaises(ValueError):await engine.noah_action(adapter,'actor-41','absent','claim_lightning',{'receive_payment_hash':fixtures.HASH},1000)
            self.store.set_online('actor-41',True)
            with self.assertRaises(ValueError):await engine.noah_action(adapter,'actor-41','fee','claim_lightning',{'receive_payment_hash':fixtures.HASH},1001)
            engine.config.driver_command=(str(self.root/'foreign-driver'),)
            (self.root/'foreign-driver').write_bytes(b'not-qualified')
            with self.assertRaises(ValueError):await engine.noah_action(adapter,'actor-41','wrong-driver','claim_lightning',{'receive_payment_hash':fixtures.HASH},1000)

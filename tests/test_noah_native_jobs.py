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
        engine=SimpleNamespace(store=self.store,noah_action=native)
        inbox=SimpleNamespace(adapter=adapter,original=lambda actor,cursor:{'payload':{
            'to':['ExpoPushToken[phone]'],'data':fixtures.canonical({'notification_type':'lightning_invoice_request',
             'transaction_id':'00000000-0000-4000-8000-000000000001','amount':5000000})}},_token=lambda actor:'ExpoPushToken[phone]')
        result=await controller.consume(inbox,'actor-41',7,engine)
        self.assertEqual('invoice_submitted',result['state']);self.assertFalse(result['outcome_verified'])
        self.assertEqual(('actor-41','noah-job-actor-41-7','invoice',{'amount_sat':5000},1000),calls[0][1:])
        await controller.consume(inbox,'actor-41',7,engine);self.assertEqual(1,len(calls))

    def engine(self):
        self.store.actor('actor-41','noah-phone')
        command=self.root/'native';command.write_bytes(b'unit-stub-only')
        self.manifest['source']['driver_binary_sha256']=hashlib.sha256(command.read_bytes()).hexdigest()
        self.manifest['evidence']['source']=self.store.trace_capture('noah.readiness.source',{'observed':copy.deepcopy(self.manifest['source']),'verified':True,'method':'independent_observation'})
        wallets=self.root/'wallets';(wallets/'actor-41').mkdir(parents=True)
        self.store.add_snapshot({'observed_at':time.time(),'complete':True,'stable_tip':True,'initial_block_download':False,'server_status':{'status':'running'}})
        cfg=SimpleNamespace(active=True,trace_enabled=True,workload='none',recovery_command=(),wallet_root=wallets,
            driver_command=(str(command),),inventory_command=('unit-bridge',),expected_server_pubkey=fixtures.PUB,
            action_timeout_seconds=10,validate_identity=lambda snapshot:None)
        return Engine(cfg,self.store),self.adapter()

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

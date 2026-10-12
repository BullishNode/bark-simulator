"""Client operations must overlap without sharing an actor."""
import asyncio,json,tempfile,time,unittest
from pathlib import Path
from unittest.mock import AsyncMock,patch
from simulator.config import Config
from simulator.engine import Engine,initialize
from simulator.model import SIGNET_GENESIS
from simulator.store import Store

class DispatchOverlapTests(unittest.IsolatedAsyncioTestCase):
    async def batch(self,slots):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);store=Store(root,'synthetic',1000000);initialize(store)
            config=Config(root,('observer',),('driver',),root/'wallets',SIGNET_GENESIS,
                'test','test','test',1000000,1,1,True,dispatch_per_tick=slots)
            for i in range(1,slots+1):store.queue('first-'+str(i),'actor-'+str(i).zfill(2),'H01','snapshot',{},0)
            store.queue('same-actor','actor-01','H01','snapshot',{},0)
            entered=[];active=set();max_active=0;barrier=asyncio.Event()
            async def command(argv,request=None,**kwargs):
                nonlocal max_active
                name=Path(request['actor_dir']).name
                self.assertNotIn(name,active,'same actor commands overlap')
                active.add(name);entered.append(request['action_id']);max_active=max(max_active,len(active))
                if len(active)==slots:barrier.set()
                try:await asyncio.wait_for(barrier.wait(),2)
                finally:active.remove(name)
                return {'action_id':request['action_id'],'status':'ok','actual_fee_sat':0,'data':{}}
            engine=Engine(config,store)
            snapshot={'observed_at':time.time(),'stable_tip':True,'initial_block_download':False,'server_status':{'status':'running'}}
            try:
                with patch.object(engine,'observe',AsyncMock(return_value=snapshot)),patch('simulator.engine.json_command',command):
                    await engine.run(once=True)
                self.assertEqual(slots,max_active,'client operations never overlapped')
                self.assertEqual(slots,len(entered));self.assertEqual('queued',store.db.execute("SELECT state FROM action WHERE id='same-actor'").fetchone()[0])
                requests=[r[0] for r in store.db.execute("SELECT sequence FROM event WHERE kind='driver_request'")]
                responses=[r[0] for r in store.db.execute("SELECT sequence FROM event WHERE kind='driver_response'")]
                self.assertEqual(slots,len(requests));self.assertEqual(slots,len(responses))
                self.assertLess(max(requests),min(responses),'all batch requests precede the first response')
                self.assertTrue(store.verify_event_chain())
            finally:store.close()
    async def test_two_actors_dispatched_per_tick(self):await self.batch(2)
    async def test_three_actors_dispatched_per_tick(self):await self.batch(3)

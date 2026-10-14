import asyncio,json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock,patch
from simulator.engine import initialize,Engine
from simulator.model import canonical
from simulator.store import Store


def coin_id(number):return f'{number:064x}:0'
def coin(number):return {'vtxo_id':coin_id(number),'signed_vtxo':'ab','expiry':999,'policy_type':'pubkey','spend_state':'unclaimed'}
def page(kind,rows,next=None):return {'kind':kind,'rows':rows,'next':next,'inventory_consistent':False}

class PriorityInventoryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name),'synthetic',100000);initialize(self.store)
        self.config=SimpleNamespace(inventory_command=('public-inventory',),server_policy_command=('public-decoder',),expected_server_pubkey='02'+'11'*32)
        self.requests=[];self.decoded=[];self.rows=[coin(n) for n in range(1,951)]
        self.pending('actor-02','movement-02')
    async def asyncTearDown(self):self.store.close();self.tmp.cleanup()
    def pending(self,actor,movement):
        self.store.db.execute('INSERT OR REPLACE INTO movement_evidence VALUES (?,?,?)',(actor,movement,canonical({'id':movement,'subsystem':'bark.round','status':'pending','input_vtxos':['public-input:0']})))
    async def fetch(self,argv,request,**kwargs):
        self.requests.append(request)
        if request['kind']=='nursery':return page('nursery',[])
        rows=[row for row in self.rows if row['vtxo_id']>request['after']]
        return page('coins',rows[:100],rows[99]['vtxo_id'] if len(rows)>100 else None)
    async def decode(self,store,command,server,*,limit):
        self.decoded.append({'rows':store.db.execute("SELECT count(*) FROM server_item WHERE kind='coins'").fetchone()[0],'limit':limit})
    async def collect(self,**kwargs):
        from simulator.priority_inventory import collect
        return await collect(self.store,self.config,fetch=self.fetch,decode=self.decode,**kwargs)
    async def test_late_lexicographic_replacement_discovered_in_four_bounded_ticks(self):
        self.store.db.execute("INSERT OR REPLACE INTO meta VALUES ('inventory_kind_index','3')");self.store.db.execute("INSERT OR REPLACE INTO meta VALUES ('inventory_cursor_coins','normal-cursor')")
        for _ in range(4):
            before=len(self.requests);result=await self.collect();self.assertLessEqual(len(self.requests)-before,4)
            self.assertTrue(result['read_only']);self.assertFalse(result['traffic_credit'])
        self.assertIsNotNone(self.store.db.execute("SELECT id FROM server_item WHERE kind='coins' AND id=?",(coin_id(950),)).fetchone())
        self.assertEqual('3',self.store.get_meta('inventory_kind_index'));self.assertEqual('normal-cursor',self.store.get_meta('inventory_cursor_coins'))
        self.assertEqual(4,len(self.decoded));self.assertEqual(950,self.decoded[-1]['rows']);self.store.verify_event_chain()
    async def test_offline_permanent_absence_and_nonpending_movements_make_no_extra_calls(self):
        self.store.set_online('actor-02',False);await self.collect();self.assertEqual([],self.requests)
        self.store.set_online('actor-02',True);self.store.db.execute('UPDATE actor SET details=? WHERE id=?',(canonical({'permanent_absence':{'original_wallet_must_stay_closed':True}}),'actor-02'))
        await self.collect();self.assertEqual([],self.requests)
        self.store.db.execute("UPDATE actor SET details='{}' WHERE id='actor-02'")
        self.store.db.execute('UPDATE movement_evidence SET payload=?',(canonical({'id':'movement-02','subsystem':'bark.round','status':'successful','input_vtxos':['public-input:0']}),))
        await self.collect();self.assertEqual([],self.requests);self.assertEqual([],self.decoded)
    async def test_cursor_survives_restart_and_changed_online_interest_without_rewind(self):
        await self.collect();self.assertEqual(coin_id(300),json.loads(self.store.get_meta('round_priority_cursor_coins'))['after'])
        root=Path(self.tmp.name);self.store.close();self.store=Store(root,'synthetic',100000)
        self.pending('actor-05','movement-05');self.requests=[]
        await self.collect();self.assertEqual({'kind':'coins','after':coin_id(300)},self.requests[1])
    async def test_finished_scan_wrap_is_journaled_and_not_repeated_in_same_tick(self):
        self.rows=self.rows[:5];await self.collect()
        self.assertEqual(2,len(self.requests));self.assertEqual(['nursery','coins'],[r['kind'] for r in self.requests])
        events=[json.loads(r[0]) for r in self.store.db.execute("SELECT payload FROM event WHERE kind='round_priority_inventory_page'")]
        self.assertTrue(all(e['scan_finished'] and e['next_cursor']=='' and e['generation']==1 for e in events))
        await self.collect();self.assertEqual(4,len(self.requests));self.assertEqual(5,self.store.db.execute("SELECT count(*) FROM server_item_version WHERE kind='coins'").fetchone()[0])
    async def test_normal_page_is_reused_without_duplicate_request(self):
        from simulator.ownership import record_server_page
        response=page('coins',self.rows[:100],coin_id(100));record_server_page(self.store,response)
        await self.collect(normal_page={'request':{'kind':'coins','after':''},'response':response})
        self.assertEqual(['nursery','coins','coins'],[r['kind'] for r in self.requests]);self.assertEqual(coin_id(100),self.requests[1]['after'])
        reused=[json.loads(r[0]) for r in self.store.db.execute("SELECT payload FROM event WHERE kind='round_priority_inventory_page'")]
        self.assertEqual(1,sum(p['reused_normal_page'] for p in reused))
    async def test_bad_cursor_cannot_advance_checkpoint_or_ingest_rows(self):
        async def bad(argv,request,**kwargs):
            self.requests.append(request)
            return page(request['kind'],[]) if request['kind']=='nursery' else page('coins',[coin(1)],coin_id(0))
        from simulator.priority_inventory import collect
        result=await collect(self.store,self.config,fetch=bad,decode=self.decode)
        self.assertEqual('held',result['status']);self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM server_item WHERE kind='coins'").fetchone()[0])
        self.assertIsNone(self.store.get_meta('round_priority_cursor_coins'));self.assertEqual(1,self.store.db.execute("SELECT count(*) FROM event WHERE kind='round_priority_inventory_gap'").fetchone()[0])
    async def test_timeout_keeps_committed_cursor_and_bounds_extra_work(self):
        async def slow(argv,request,**kwargs):
            self.requests.append(request)
            if request['kind']=='coins' and request['after']:await asyncio.sleep(4)
            return await self.fetch(argv,request,**kwargs)
        from simulator.priority_inventory import collect
        result=await collect(self.store,self.config,fetch=slow,decode=self.decode,time_budget=2)
        self.assertEqual('held',result['status']);self.assertEqual(coin_id(100),json.loads(self.store.get_meta('round_priority_cursor_coins'))['after'])
        self.assertLessEqual(result['requests'],4)
    async def test_invalid_secret_page_is_never_written(self):
        async def secret(argv,request,**kwargs):return page(request['kind'],[]) if request['kind']=='nursery' else page('coins',[{**coin(1),'private_key':'forbidden'}])
        from simulator.priority_inventory import collect
        result=await collect(self.store,self.config,fetch=secret,decode=self.decode)
        self.assertEqual('held',result['status']);self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM server_item WHERE kind='coins'").fetchone()[0])
        self.assertNotIn('forbidden',''.join(r[0] for r in self.store.db.execute('SELECT payload FROM event')))
    async def test_priority_page_and_cursor_commit_atomically_on_event_failure(self):
        original=self.store._event
        def fail(kind,payload):
            if kind=='round_priority_inventory_page' and payload['kind']=='coins':raise RuntimeError('simulated journal failure')
            return original(kind,payload)
        with patch.object(self.store,'_event',side_effect=fail):await self.collect()
        self.assertIsNone(self.store.get_meta('round_priority_cursor_coins'))
        self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM server_item WHERE kind='coins'").fetchone()[0]);self.store.verify_event_chain()

    async def test_engine_preserves_four_source_kinds_while_priority_finds_late_coin(self):
        self.config.trace_enabled=False;self.config.workload='none';self.config.recovery_command=()
        normal=[]
        async def normal_fetch(argv,request,**kwargs):
            normal.append(request)
            if request['kind'] in {'coins','nursery'}:return await self.fetch(argv,request,**kwargs)
            return page(request['kind'],[])
        with patch('simulator.engine.json_command',side_effect=normal_fetch),patch('simulator.engine.collect_padding',new=AsyncMock()), \
                patch('simulator.priority_inventory.json_command',side_effect=self.fetch),patch('simulator.priority_inventory.collect_decoder',side_effect=self.decode):
            engine=Engine(self.config,self.store)
            for _ in range(4):await engine.collect_inventory()
        self.assertEqual(['coins','pending','links','records'],[r['kind'] for r in normal])
        self.assertEqual('0',self.store.get_meta('inventory_kind_index'))
        self.assertEqual(coin_id(100),self.store.get_meta('inventory_cursor_coins'))
        self.assertIsNotNone(self.store.db.execute("SELECT id FROM server_item WHERE kind='coins' AND id=?",(coin_id(950),)).fetchone())
        self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM action').fetchone()[0]);self.store.verify_event_chain()
    async def test_disappearance_during_read_stops_further_priority_requests(self):
        async def disappearance(argv,request,**kwargs):
            self.requests.append(request);self.store.set_online('actor-02',False)
            return page(request['kind'],[])
        from simulator.priority_inventory import collect
        result=await collect(self.store,self.config,fetch=disappearance,decode=self.decode)
        self.assertEqual(1,result['requests']);self.assertEqual([],self.decoded)
    async def test_corrupt_saved_cursor_is_held_without_reinitialization(self):
        saved=canonical({'schema_version':1,'after':'unsafe cursor','generation':4})
        self.store.db.execute('INSERT INTO meta VALUES (?,?)',('round_priority_cursor_nursery',saved))
        result=await self.collect()
        self.assertEqual('held',result['status']);self.assertEqual([],self.requests)
        self.assertEqual(saved,self.store.get_meta('round_priority_cursor_nursery'))

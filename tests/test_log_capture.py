import json,tempfile,unittest
from pathlib import Path
from simulator.store import Store

class LogCollectorTests(unittest.IsolatedAsyncioTestCase):
    async def test_unavailable_target_endpoint_records_gap_and_preserves_cursor(self):
        from simulator.log_capture import collect_source,LogSource
        with tempfile.TemporaryDirectory() as tmp:
            store=Store(Path(tmp),'synthetic',1000);store.attach_trace()
            source=LogSource('target-captaind','target','captaind',('fixture-command',),1000000)
            async def unavailable(command,request):raise RuntimeError('unsupported bridge operation')
            try:
                await collect_source(store,source,command=unavailable)
                value=json.loads(store.get_meta('log_capture_gap:target-captaind'))
                self.assertEqual('producer_unavailable',value['kind']);self.assertIsNone(store.get_meta('log_capture_cursor:target-captaind'))
            finally:store.close()
    async def test_response_identity_or_cursor_mismatch_never_commits_rows_or_advances(self):
        from simulator.log_capture import collect_source,LogSource
        with tempfile.TemporaryDirectory() as tmp:
            store=Store(Path(tmp),'synthetic',1000);store.attach_trace()
            source=LogSource('target-captaind','target','captaind',('fixture-command',),1000000)
            async def wrong(command,request):return {'schema_version':1,'kind':'logs','component':'watchmand','rows':[],'next_cursor':None,'more':False,'gap':None}
            try:
                await collect_source(store,source,command=wrong)
                self.assertIsNone(store.get_meta('log_capture_cursor:target-captaind'))
                self.assertEqual('invalid_producer_response',json.loads(store.get_meta('log_capture_gap:target-captaind'))['kind'])
            finally:store.close()
    async def test_real_public_pages_and_redactions_capture_once_with_no_money_or_actor_actions(self):
        from simulator.log_capture import collect_source,LogSource
        from simulator.log_producer import page_records
        with tempfile.TemporaryDirectory() as tmp:
            store=Store(Path(tmp),'synthetic',1000);store.attach_trace()
            source=LogSource('target-captaind','target','captaind',('fixture-command',),1000000)
            records=[{'utc_us':1000000,'stream':'stdout','text':'public payout tick'},
             {'utc_us':1000001,'stream':'stderr','text':'seed: '+'ab'*32}]
            async def producer(command,request):return page_records(request,records,source_id='instance1')
            try:
                first=await collect_source(store,source,command=producer);self.assertEqual(2,first['rows'])
                second=await collect_source(store,source,command=producer);self.assertEqual(0,second['rows'])
                logs=[r for r in store.trace.records() if r['kind']=='target.log'];self.assertEqual(2,len(logs))
                self.assertTrue(logs[1]['payload']['redacted']);self.assertIsNone(logs[1]['raw'])
                self.assertEqual(0,store.db.execute('SELECT count(*) FROM action').fetchone()[0])
                self.assertEqual(0,store.db.execute('SELECT count(*) FROM owned_coin').fetchone()[0])
            finally:store.close()
    async def test_continuity_gap_remains_in_report_after_producer_resumes(self):
        from simulator.log_capture import collect_source,LogSource,report
        from simulator.log_producer import page_records
        with tempfile.TemporaryDirectory() as tmp:
            store=Store(Path(tmp),'synthetic',1000);store.attach_trace()
            source=LogSource('target-captaind','target','captaind',('fixture-command',),1000000)
            generation=['instance1']
            async def producer(command,request):return page_records(request,[{'utc_us':1000000,'stream':'stdout','text':'tick'}],source_id=generation[0])
            try:
                await collect_source(store,source,command=producer);generation[0]='instance2'
                await collect_source(store,source,command=producer);await collect_source(store,source,command=producer)
                value=report(store);self.assertIsNone(value['sources'][0]['current_gap'])
                self.assertEqual('source_replaced',value['sources'][0]['continuity_gap']['kind']);self.assertFalse(value['complete'])
            finally:store.close()
    async def test_new_timestamp_bucket_cannot_start_with_invented_ordinal(self):
        from simulator.log_capture import collect_source,LogSource
        with tempfile.TemporaryDirectory() as tmp:
            store=Store(Path(tmp),'synthetic',1000);store.attach_trace();source=LogSource('target-captaind','target','captaind',('fixture-command',),1000000)
            async def invented(command,request):
                cursor={'source_id':'instance1','utc_us':1000000,'ordinal':9}
                return {'schema_version':1,'kind':'logs','component':'captaind','source_id':'instance1','rows':[{'utc_us':1000000,'ordinal':9,'cursor':cursor,'stream':'stdout','text':'tick','raw_line':'tick','redacted':False}], 'next_cursor':cursor,'more':False,'gap':None}
            try:
                result=await collect_source(store,source,command=invented)
                self.assertEqual('invalid_producer_response',result['gap']['kind']);self.assertIsNone(store.get_meta('log_capture_cursor:target-captaind'))
            finally:store.close()

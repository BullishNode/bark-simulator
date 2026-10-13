import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from simulator.store import Store


class TargetLogWindowTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.store=Store(Path(self.temp.name),'synthetic',10000)
        self.store.attach_trace()
        self.source=SimpleNamespace(name='target-captaind',kind='target_window',component='captaind',command=('readonly-bridge',),since_us=0)
        self.ending=dt.datetime.now(dt.timezone.utc)
        self.requests=[]

    async def asyncTearDown(self):
        self.store.close();self.temp.cleanup()

    def response(self,request,lines=None,**extra):
        return {'kind':'logs','service':'captaind','from_utc':(self.ending-dt.timedelta(seconds=request['seconds'])).isoformat(),
            'until_utc':self.ending.isoformat(),'tail':request['tail'],'max_bytes':request['max_bytes'],
            'source_bytes':100,'truncated':False,'timed_out':False,'lines':['public tick'] if lines is None else lines,
            'complete':False,'validation_scope':'bounded returned log tail',**extra}

    async def capture(self,lines=None,**extra):
        from simulator.target_log_window import collect_window
        async def command(argv,request):
            self.requests.append(request)
            return self.response(request,lines,**extra)
        return await collect_window(self.store,self.source,command=command,maximum_bytes=65536)

    def traces(self,kind):
        return [row for row in self.store.trace.records() if row['kind']==kind]

    async def test_exact_bridge_contract_preserves_repeated_occurrences_and_full_windows(self):
        await self.capture(['same','same']);self.ending+=dt.timedelta(seconds=60)
        await self.capture(['same','same'])
        self.assertEqual({'kind','service','seconds','tail','max_bytes'},set(self.requests[0]))
        self.assertEqual(1000,self.requests[0]['tail'])
        self.assertEqual(2,len(self.traces('target.log.window')))
        self.assertEqual(4,len(self.traces('target.log')))
        self.assertEqual(2,self.store.db.execute('SELECT count(*) FROM target_log_window').fetchone()[0])
        self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM action').fetchone()[0])
        self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM event').fetchone()[0])

    async def test_private_line_is_replaced_without_its_bytes_or_hash(self):
        await self.capture(['{"seed":"'+'ab'*32+'"}','public'])
        serialized=json.dumps(list(self.store.trace.records()))
        self.assertNotIn('ab'*32,serialized)
        lines=self.traces('target.log')
        self.assertTrue(lines[0]['payload']['redacted'])
        self.assertNotIn('line_sha256',lines[0]['payload'])
        self.assertEqual('public',lines[1]['payload']['returned_line'])

    async def test_bad_echo_or_completeness_cannot_advance_capture_metadata(self):
        for extra in ({'service':'watchmand'},{'complete':True},{'max_bytes':999999},
                      {'source_bytes':65537},{'truncated':'false'},{'lines':[{}]}):
            with self.subTest(extra=extra):
                result=await self.capture(**extra)
                self.assertEqual('invalid_producer_response',result['gap']['kind'])
                self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM target_log_window').fetchone()[0])

    async def test_partial_and_disjoint_windows_keep_gaps_after_later_success(self):
        first=await self.capture(truncated=True,timed_out=True)
        self.assertIn('byte_truncated',first['gaps']);self.assertIn('producer_timeout',first['gaps'])
        self.ending+=dt.timedelta(seconds=1800)
        second=await self.capture()
        self.assertIn('window_bound_gap',second['gaps'])
        self.ending+=dt.timedelta(seconds=60)
        await self.capture()
        self.assertIsNotNone(self.store.get_meta('log_capture_continuity_gap:'+self.source.name))
        self.assertIsNone(self.store.get_meta('log_capture_cursor:'+self.source.name))

    async def test_unavailable_trace_and_invalid_resource_bound_never_call_bridge(self):
        from simulator.target_log_window import collect_window
        async def command(*args):raise AssertionError('must not call producer')
        self.store.trace.close();self.store.trace=None
        result=await collect_window(self.store,self.source,command=command)
        self.assertEqual('trace_capture_disabled',result['gap']['kind'])
        self.store.attach_trace()
        result=await collect_window(self.store,self.source,command=command,maximum_bytes=1024)
        self.assertEqual('unsupported_window_bound',result['gap']['kind'])

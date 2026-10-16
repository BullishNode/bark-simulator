"""Real owned processes and actual TraceStore; synthetic authority only.

No SSH/PG, financial admission, private wallet or original actor is exercised.
"""
import asyncio
import ctypes
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from simulator import frontier_source as source
from simulator.process import CommandError
from simulator.trace import TraceStore, partition_paths, iter_records


@unittest.skipUnless(sys.platform == 'linux', 'owned Linux process lifecycle')
class WorkerLifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.trace=TraceStore(self.root/'trace');self.addCleanup(self.trace.close)
        self.trace.append('before',{'original':True})
        self.store=SimpleNamespace(trace=self.trace)
        self.config=SimpleNamespace(closed_frontier_schema=2,architecture_profile='direct_per_key',
            trace_enabled=True,network='signet',expected_genesis='g',expected_server_pubkey='p')
        self.pins={'product_commit':'a'*40,'sdk_commit':'b'*40,'driver_sha256':'c'*64,
            'configuration_sha256':'d'*64,'schema_sha256':'e'*64}
        self.repo=str(Path(source.__file__).resolve().parent.parent)

    def fixture(self,phase):
        supervisor=self.root/'supervisor.py';worker=self.root/'worker.py'
        supervisor.write_text(f'''import sys,subprocess,os
from pathlib import Path
sys.path.insert(0,{self.repo!r})
from simulator import frontier_process as p
Path({str(self.root/'supervisor.pid')!r}).write_text(str(os.getpid()))
original=p.subprocess.Popen
p.subprocess.Popen=lambda argv,**kw:original([sys.executable,'-I',{str(worker)!r},'--work'],**kw)
p.main()
''')
        worker.write_text(f'''import sys,os,time,subprocess
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,{self.repo!r})
from simulator import frontier_process as p,frontier_source as s
root=Path({str(self.root)!r})
(root/'worker.pid').write_text(str(os.getpid()))
def bootstrap():
    if {phase!r}=='bootstrap':
        (root/'blocked_phase').write_text('bootstrap')
        time.sleep(2);(root/'late').write_text('late')
    expected={{'financial_pins':{self.pins!r},'source_binding':{{'network':'signet','genesis':'g','server_pubkey':'p'}},'resource_declaration':{{'deadline_ms':1000}}}}
    def collect(trace,*,inherited_session):
        assert inherited_session is True
        if {phase!r}=='sqlite':
            (root/'blocked_phase').write_text('actual SQLite append next')
            trace.append('after_block',{{'late':True}});(root/'late').write_text('late')
        elif {phase!r}=='descendants':
            code="import subprocess,sys,time,os;from pathlib import Path;root=Path("+repr(str(root))+");(root/'producer.pid').write_text(str(os.getpid()));grand=subprocess.Popen([sys.executable,'-c',\\\"import os,time;from pathlib import Path;Path(\\\\\\\""+str(root/'grandchild.pid')+"\\\\\\\").write_text(str(os.getpid()));time.sleep(60)\\\"]);time.sleep(60)"
            subprocess.Popen([sys.executable,'-c',code]);time.sleep(60)
        else:trace.append('worker_prefix',{{'original':True}})
        return {{'schema_version':2,'qualified':False,'complete':False}}
    def verify(frame,trace):
        if {phase!r}=='replay':
            (root/'blocked_phase').write_text('replay');time.sleep(2);(root/'late').write_text('late')
        list(__import__('simulator.trace',fromlist=['iter_records']).iter_records(trace.root))
        return frame
    controller=SimpleNamespace(protected_binding=lambda:expected,collect=collect,verify=verify)
    return controller,{{'expected_contract':expected}},'synthetic-authority'
s._bootstrap=bootstrap;s._same_binding=lambda digest:None
p.main()
''')
        return [sys.executable,'-I',str(supervisor),'--supervise']

    def assert_reaped(self,required=()):
        for name in ('supervisor','worker',*required):
            path=self.root/(name+'.pid')
            self.assertTrue(path.is_file(),name+' actually started')
            self.assertFalse(Path('/proc',path.read_text().strip()).exists(),name+' fully reaped')

    def collect(self,phase,timeout=1.8):
        with mock.patch.object(source,'_worker_command',return_value=self.fixture(phase)):
            return asyncio.run(source.collect(self.store,self.config,self.pins,timeout=timeout))

    def test_success_reopens_actual_trace_and_does_not_claim_readiness(self):
        frame=self.collect('success',timeout=2.5)
        self.assertEqual({'schema_version':2,'qualified':False,'complete':False},frame)
        self.assertEqual(['before','worker_prefix'],[row['kind'] for row in iter_records(self.trace.root)])
        self.assert_reaped()

    def test_actual_authenticated_packet_collect_and_original_replay_in_fresh_worker(self):
        packet=os.environ.get('TRACK_C_FRONTIER_TEST_PACKET')
        if not packet:self.skipTest('explicit protected packet fixture required')
        packet=Path(packet).resolve()
        command=self.fixture('success')
        worker=self.root/'worker.py'
        worker.write_text(f'''import sys,os,json,hashlib,copy,base64,subprocess
from pathlib import Path
sys.path.insert(0,{self.repo!r});sys.path.insert(0,{str(packet)!r})
from simulator import frontier_process as p,frontier_source as s
from test_frontier_v2_contract import EXPECTED,lines
Path({str(self.root/'worker.pid')!r}).write_text(str(os.getpid()))
expected=copy.deepcopy(EXPECTED)
expected['resource_declaration'].update(deadline_ms=1000,statement_timeout_ms=250)
packet=Path({str(packet)!r});wrapper=b'synthetic fixed public wrapper'
binding={{'expected_contract':expected,'observer_wrapper_sha256':hashlib.sha256(wrapper).hexdigest(),
'source_files':{{name:hashlib.sha256((packet/name).read_bytes()).hexdigest() for name in s.SOURCE_FILES}}}}
def read(path,**kw):
    raw=json.dumps(binding).encode() if path==s.BINDING else wrapper if path==s.WRAPPER else Path(path).read_bytes()
    return raw,hashlib.sha256(raw).hexdigest()
s.SOURCE_ROOT=packet;s.checked_file=read
bootstrap=s._bootstrap
def checked_bootstrap():
    controller,binding,digest=bootstrap();controller.checked_file=read
    return controller,binding,digest
s._bootstrap=checked_bootstrap
original=subprocess.Popen
payload=base64.b64encode(b''.join(lines(expected))).decode()
code='import sys,base64,os;sys.stdin.buffer.read();sys.stdout.buffer.write(base64.b64decode(%r))'%payload
def launch(argv,**kw):
    assert kw['start_new_session'] is False
    return original([sys.executable,'-I','-c',code],**kw)
subprocess.Popen=launch
p.main()
''')
        import importlib.util,copy
        sys.path.insert(0,str(packet))
        try:
            spec=importlib.util.spec_from_file_location('actual_packet_fixture',packet/'test_frontier_v2_contract.py')
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        finally:sys.path.pop(0)
        expected=copy.deepcopy(module.EXPECTED)
        config=SimpleNamespace(**vars(self.config))
        config.expected_genesis=expected['source_binding']['genesis']
        config.expected_server_pubkey=expected['source_binding']['server_pubkey']
        with mock.patch.object(source,'_worker_command',return_value=command):
            frame=asyncio.run(source.collect(self.store,config,expected['financial_pins'],timeout=2.5))
        self.assertEqual(2,frame['schema_version'])
        self.assertFalse(frame['complete']);self.assertFalse(frame['qualified'])
        records=list(iter_records(self.trace.root))
        originals=[row for row in records if row['kind']=='frontier_v2.original_line']
        expected['resource_declaration'].update(deadline_ms=1000,statement_timeout_ms=250)
        self.assertEqual(b''.join(module.lines(expected)),b''.join(row['raw'] for row in originals))
        self.assertGreater(len(originals),1)
        self.assert_reaped()

    def test_blocked_sqlite_is_killed_reaped_and_cannot_write_after_unlock(self):
        connection=sqlite3.connect(partition_paths(self.trace.root)[0],isolation_level=None)
        self.addCleanup(connection.close);connection.execute('BEGIN IMMEDIATE')
        started=time.monotonic()
        with self.assertRaises((CommandError,ValueError)):
            self.collect('sqlite')
        self.assertLess(time.monotonic()-started,2.4)
        self.assert_reaped();self.assertTrue((self.root/'blocked_phase').is_file())
        connection.execute('ROLLBACK');time.sleep(0.2)
        self.assertFalse((self.root/'late').exists())
        self.assertEqual(['before'],[row['kind'] for row in iter_records(self.trace.root)])

    def test_bootstrap_and_replay_are_inside_same_hard_process_bound(self):
        for phase in ('bootstrap','replay'):
            with self.subTest(phase=phase),self.assertRaises((CommandError,ValueError)):
                self.collect(phase)
            self.assert_reaped();time.sleep(0.1)
            self.assertFalse((self.root/'late').exists())
        self.assertEqual(['before','worker_prefix'],[row['kind'] for row in iter_records(self.trace.root)])

    def test_nested_producer_and_grandchild_reaped_without_engine_subreaper(self):
        before=ctypes.c_int();libc=ctypes.CDLL(None)
        self.assertEqual(0,libc.prctl(37,ctypes.byref(before),0,0,0))
        unrelated=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],start_new_session=True)
        self.addCleanup(lambda:(unrelated.kill(),unrelated.wait()) if unrelated.poll() is None else None)
        with self.assertRaises((CommandError,ValueError)):
            self.collect('descendants',timeout=2.5)
        self.assert_reaped(('producer','grandchild'))
        self.assertIsNone(unrelated.poll())
        after=ctypes.c_int();self.assertEqual(0,libc.prctl(37,ctypes.byref(after),0,0,0))
        self.assertEqual(before.value,after.value)

    def test_async_cancellation_waits_owned_deadline_cleanup_no_thread_left(self):
        async def run():
            task=asyncio.create_task(source.collect(self.store,self.config,self.pins,timeout=1.8))
            while not (self.root/'worker.pid').exists():await asyncio.sleep(0.01)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):await task
        with mock.patch.object(source,'_worker_command',return_value=self.fixture('bootstrap')):
            asyncio.run(asyncio.wait_for(run(),2.5))
        self.assert_reaped();self.assertFalse((self.root/'late').exists())

    def test_already_cancelled_command_task_does_not_spin_on_global_shutdown(self):
        # Run this actual asyncio cancellation state in a separate bounded
        # process: a spinning loop would prevent asyncio.wait_for from firing.
        script=self.root/'inner_cancel.py'
        script.write_text(f'''import sys,asyncio
from types import SimpleNamespace
from unittest import mock
sys.path.insert(0,{self.repo!r})
from simulator import frontier_source as s
from simulator.trace import TraceStore
async def cancelled(*args,**kw):raise asyncio.CancelledError
async def run(store,config,pins):
    try:await s.collect(store,config,pins,timeout=1)
    except asyncio.CancelledError:return
    raise AssertionError('cancellation not retained')
trace=TraceStore({str(self.root/'inner-trace')!r})
try:
    config=SimpleNamespace(closed_frontier_schema=2,architecture_profile='direct_per_key',trace_enabled=True,network='signet',expected_genesis='g',expected_server_pubkey='p')
    with mock.patch('simulator.process.json_command',side_effect=cancelled):
        asyncio.run(run(SimpleNamespace(trace=trace),config,{self.pins!r}))
finally:trace.close()
''')
        result=subprocess.run([sys.executable,'-I',str(script)],timeout=2,
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.assertEqual(0,result.returncode)

    def test_sync_re_admission_uses_same_owned_worker_under_active_event_loop(self):
        async def run():
            request=source._request(self.store,self.config,self.pins,'verify',
                frame={'schema_version':2,'qualified':False,'complete':False},timeout=1.8)
            with self.assertRaises(ValueError):source._run_sync(request)
        with mock.patch.object(source,'_worker_command',return_value=self.fixture('replay')):
            asyncio.run(run())
        self.assert_reaped();self.assertFalse((self.root/'late').exists())


if __name__=='__main__':unittest.main()

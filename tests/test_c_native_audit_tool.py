"""Real archive/Store/closure hashing; SYNTHETIC native replies/qualifications.

Actual subprocess controls use a tiny local hash probe, never the product/native
checker. These tests provide protocol/lifecycle credit only, no financial proof.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from simulator import c_native_audit_tool as c
from simulator import two_step_normal as runner
from simulator.store import Store
from tests import test_c_native_audit_request as fixture


class AuditTool(unittest.TestCase):
    def setUp(self):
        self.f=fixture.CapturedRequest();self.f.setUp();self.addCleanup(self.f.doCleanups);self.f.load()
        self.prepared=self.f.prepare();self.observation=self.f.observation;self.calls=[]
        self.checked={'kind':'c-checked-native-target-source','source_observation':copy.deepcopy(self.observation),
            'loaded':self.f.loaded,'original_private_source_references':copy.deepcopy(self.f.refs)}
        self.root=self.f.base.root;self.runtime=self.root/'audit-runtime';self.runtime.mkdir(mode=0o700);(self.runtime/'lib').mkdir(mode=0o700)
        source='9'*40;components={}
        for name,mode in {'launch':0o500,'native-fee-audit':0o500,'source-identity.json':0o600,
                'lib/libc.so.6':0o400,'lib/ld-linux-x86-64.so.2':0o500,'lib/libgcc_s.so.1':0o400}.items():
            raw=(json.dumps({'source':source,'SDK_actual_source':source,'actual_GIT_HASH':source,
                'SDK_component':self.observation['financial_pins']['sdk_commit']}).encode()if name=='source-identity.json'else('SYNTHETIC-NEVER-EXECUTED-'+name).encode())
            p=self.runtime/name;p.write_bytes(raw);p.chmod(mode)
            components[name]={'bytes':len(raw),'sha256':c.digest(raw),'mode':oct(mode)}
        tool={'command':[str(self.runtime/'launch')],'sha256':components['launch']['sha256'],'evidence_directory':str(self.root)}
        identity={'source_commit':source,'sdk_actual_GIT_HASH':source,'sdk_component_commit':self.observation['financial_pins']['sdk_commit'],
            'binary_sha256':components['native-fee-audit']['sha256'],'launcher_sha256':components['launch']['sha256'],
            'runtime_manifest_sha256':'d'*64,'component_inventory':components,'python_sha256':c.digest(Path('/usr/bin/python3').resolve().read_bytes())}
        self.store=Store(self.root/'store','synthetic',60000,architecture_profile='direct_per_key');self.addCleanup(self.store.close)
        self.binding=c.AuditBinding(tool,identity,self.f.expected,1)
        self.store.event(c.QUALIFIED_KIND,c.requirement(self.binding,self.observation['financial_pins']))
        self.binding=c.AuditBinding(tool,identity,self.f.expected,self.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0])
        self.reply={'format':c.request.FORMAT,'request_sha256':self.prepared['safe']['request_sha256'],
            'charged_sat':20000,'carrier_charged_sat':20000,**{k:0 for k in c.COUNTS},
            'complete':False,'qualified':False,'financial_readiness':False,'scope':c.SCOPE}
    def encoded(self):return json.dumps(self.reply,sort_keys=True,separators=(',',':')).encode()+b'\n'
    def bind(self):return c.bind_summary(self.prepared,self.prepared['private_request'],self.encoded(),loaded=self.f.loaded)
    def collect(self,effect=None):
        outer=self
        class Core:
            def identity(self):return {'chain':'signet','blocks':outer.observation['height'],
                'bestblockhash':outer.observation['tip_hash'],'initialblockdownload':False}
            def call(self,method,*args):
                if method=='getblockhash'and args==(0,):return c.request.fee.SIGNET_GENESIS
                raise AssertionError('unexpected RPC')
        def execute(command,*,input,**kwargs):
            self.calls.append(input)
            if effect:effect(self.binding.tool,input)
            return SimpleNamespace(stdout=self.encoded(),stderr=b'',returncode=0)
        # Retain the ACTUAL request preparer/runner/closure codehashes. Only the
        # OS child is synthetic in this protocol test; no native proof credit.
        with patch.object(c,'_context'),patch.object(runner.subprocess,'run',side_effect=execute)as run:
            result=c.collect(self.store,SimpleNamespace(expected_server_pubkey=self.f.expected['server_pubkey']),Core(),
                self.observation,checked=self.checked,binding=self.binding)
            return result,run
    def test_original_request_hash_closed_false_result_and_row_cardinality(self):
        self.assertEqual(self.reply,self.bind())
        for key,value in [('request_sha256','a'*64),('complete',True),('qualified',0),('financial_readiness',True),
                ('coin_rows',1),('urgent_signed',True),('round_rights',-1),('scope','financial-ready')]:
            original=copy.deepcopy(self.reply);self.reply[key]=value
            with self.subTest(key=key),self.assertRaises(c.EvidenceGap):self.bind()
            self.reply=original
        self.reply['raw_witness']='DO-NOT-EXPORT'
        with self.assertRaises(c.EvidenceGap):self.bind()
    def test_raw_byte_identity_duplicate_reply_and_missing_native_field_refuse(self):
        with self.assertRaises(c.EvidenceGap):c.bind_summary(self.prepared,self.prepared['private_request']+b' ',self.encoded(),loaded=self.f.loaded)
        raw=self.encoded().rstrip()[:-1]+b',"complete":false}'
        with self.assertRaises(ValueError):c.bind_summary(self.prepared,self.prepared['private_request'],raw,loaded=self.f.loaded)
        del self.reply['coin_rows']
        with self.assertRaises(c.EvidenceGap):self.bind()
    def test_fixed_tool_and_exact_components_never_old_fullproof_alias(self):
        c._tool(self.binding,self.observation['financial_pins'])
        for name in self.binding.tool_identity['component_inventory']:
            p=self.runtime/name;raw=p.read_bytes();mode=p.stat().st_mode&0o777;p.chmod(0o600);p.write_bytes(b'changed');p.chmod(mode)
            with self.subTest(name=name),self.assertRaises(ValueError):c._tool(self.binding,self.observation['financial_pins'])
            p.chmod(0o600);p.write_bytes(raw);p.chmod(mode)
        self.binding.tool['command'].append('--invented')
        with self.assertRaises(c.EvidenceGap):self.binding.check()
    def test_actual_prepare_qualified_constructor_runner_and_private_aux_event(self):
        result,run=self.collect();run.assert_called_once()
        self.assertEqual(self.prepared['private_request'],run.call_args.kwargs['input'])
        self.assertEqual(self.prepared['private_request'],result['private_request'])
        safe=result['safe'];self.assertEqual(self.f.refs,safe['original_private_source_references'])
        for key in ('complete','qualified','financial_readiness'):self.assertIs(safe[key],False)
        payload=self.store.db.execute('SELECT payload FROM event WHERE kind=?',(c.KIND,)).fetchone()[0]
        self.assertNotIn('policy_utf8',payload);self.assertNotIn('body_hex',payload)
        self.assertEqual(0,self.store.db.execute("SELECT count(*)FROM event WHERE kind='financial_operating_readiness'").fetchone()[0])
        with self.assertRaisesRegex(c.EvidenceGap,'already consumed'):self.collect()
    def test_missing_or_changed_qualification_refuses_before_process(self):
        self.binding.expected['opening_sha256']='a'*64
        with self.assertRaisesRegex(c.EvidenceGap,'qualification'):self.collect()
        self.assertEqual([],self.calls)
    def test_mutated_constructor_during_process_is_unknown_not_success(self):
        with self.assertRaises(c.EvidenceGap):self.collect(lambda tool,raw:self.binding.expected.update(opening_sha256='a'*64))
        self.assertIsNone(self.store.db.execute('SELECT 1 FROM event WHERE kind=?',(c.KIND,)).fetchone())
    def test_missing_original_source_refuses_without_child(self):
        self.checked['original_private_source_references']['archive_sha256']='b'*64
        with self.assertRaises(c.EvidenceGap):self.collect()
        self.assertEqual([],self.calls)
    def test_existing_expired_aggregate_deadline_does_not_start_fresh(self):
        deadline=c.Deadline(self.observation['started_at']);deadline.monotonic_end=0;token=c.ACTIVE.set(deadline)
        try:
            with self.assertRaises(TimeoutError):self.collect()
            self.assertEqual([],self.calls)
        finally:c.ACTIVE.reset(token)


class ExistingRunnerRawBytes(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.binary=self.root/'synthetic-probe'
        self.binary.write_text('#!/usr/bin/python3\nimport sys,json,hashlib\nraw=sys.stdin.buffer.read()\nprint(json.dumps({"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}))\n');self.binary.chmod(0o700)
        self.tool={'command':[str(self.binary)],'sha256':c.digest(self.binary.read_bytes()),'evidence_directory':str(self.root)}
    def test_C_raw_bytes_over_old2MiB_preserved_without_json_reencoding(self):
        raw=b'{"private-original":"'+b'x'*(2*1024*1024)+b'\\u00e9"}\n'
        actual,reply=runner.run_c_captured_audit(self.tool,raw)
        self.assertEqual(raw,actual);self.assertEqual({'bytes':len(raw),'sha256':c.digest(raw)},json.loads(reply))
        directories=[p for p in self.root.iterdir()if p.is_dir()];self.assertEqual(1,len(directories))
        self.assertEqual(raw,(directories[0]/'request.json').read_bytes())
        self.assertEqual(0o600,(directories[0]/'request.json').stat().st_mode&0o777)
    def test_default_A_B_input2MiB_unchanged_and_fixedC32MiB_bound(self):
        with self.assertRaisesRegex(ValueError,'input exceeds'):runner.run_proof(self.tool,{'large':'x'*(2*1024*1024)})
        with self.assertRaisesRegex(ValueError,'input exceeds'):runner.run_c_captured_audit(self.tool,b'x'*(32*1024*1024+1))
        with self.assertRaisesRegex(ValueError,'exact private'):runner.run_c_captured_audit(self.tool,{'request':'wrong-type'})
    def test_existing_timeout_retains_private_terminal_and_reaps_pure_child(self):
        self.binary.write_text('#!/usr/bin/python3\nimport os,time\nprint(os.getpid(),flush=True)\ntime.sleep(5)\n');self.binary.chmod(0o700)
        self.tool['sha256']=c.digest(self.binary.read_bytes())
        with patch.object(runner,'source_timeout',return_value=.1),self.assertRaisesRegex(ValueError,'timed out'):
            runner.run_c_captured_audit(self.tool,b'private-synthetic')
        directory=next(p for p in self.root.iterdir()if p.is_dir());terminal=json.loads((directory/'terminal.json').read_bytes())
        self.assertIs(terminal['timed_out'],True);pid=int((directory/'stdout').read_bytes())
        with self.assertRaises(ProcessLookupError):os.kill(pid,0)
    def test_changed_executable_and_nonzero_exit_never_return_success(self):
        self.binary.write_text('#!/usr/bin/python3\nraise SystemExit(1)\n');self.binary.chmod(0o700)
        with self.assertRaisesRegex(ValueError,'executable identity'):runner.run_c_captured_audit(self.tool,b'private')
        self.tool['sha256']=c.digest(self.binary.read_bytes())
        with self.assertRaisesRegex(ValueError,'refused'):runner.run_c_captured_audit(self.tool,b'private')


if __name__=='__main__':unittest.main()

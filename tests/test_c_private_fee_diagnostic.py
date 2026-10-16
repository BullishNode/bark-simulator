"""Actual raw TraceStore/reducer/41ce join; synthetic host/PG/Core/transport."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import runpy
import shutil
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from simulator import c_private_fee_diagnostic as d
from simulator import c_private_fee_cut as capture
from simulator import c_private_fee_package as package
from simulator import frontier_source
from simulator.store import Store
from tests import test_c_private_fee_cut as fixture
from tests import test_c_native_fee_sources as fees


class Diagnostic(unittest.TestCase):
    def setUp(self):
        self.x=fixture.PrivateFeeCapture();self.x.setUp();self.addCleanup(self.x.doCleanups)
        value=self.x.capture(self.x.pg());path=self.x.root/'zero.tar';safe=capture.write_private_package(value,path)
        self.target={'source_files':{'c-private-fee-worker.py':'a'*64},'history_identity':self.x.expected,'policy_sha256':capture.digest(self.x.fixture.policy)}
        self.loaded=package.load_target_tar(path,expected_package_sha256=safe['sha256'],expected_source_sha256=capture.digest(Path(capture.__file__).read_bytes()),
              expected_financial_pins=self.x.observation['financial_pins'],expected_observation=self.x.observation,expected_history_identity=self.x.expected,
              expected_policy_sha256=self.target['policy_sha256'],expected_server_pubkey=fees.KEY,adapter=self.x.fixed,limits=self.x.limits,binding=self.x.binding,producer_exit=lambda:0)
        packet=fixture.PACKET
        spec=importlib.util.spec_from_file_location('actual_frozen_diagnostic_adapter',packet/'adapter_v3.py')
        adapter=importlib.util.module_from_spec(spec);spec.loader.exec_module(adapter);self.adapter=adapter
        self.contract=adapter.contract();self.controller=SimpleNamespace(adapter=lambda:adapter)
        self.expected={'resource_declaration':self.x.limits,'source_binding':self.x.binding,'financial_pins':self.x.observation['financial_pins'],'deployment_id':'synthetic-C-old-zero'}
        self.config=SimpleNamespace(closed_frontier_schema=2,architecture_profile='direct_per_key',trace_enabled=True,network='signet',expected_genesis=capture.SIGNET_GENESIS,expected_server_pubkey=fees.KEY)
        self.store=Store(self.x.root/'diagnostic-store','synthetic-diagnostic',architecture_profile='direct_per_key');self.store.attach_trace();self.addCleanup(self.store.close)
        def replay(request):
            # Real original raw trace verification. Only installed host authority
            # and process launch are synthetic here; never return request.frame.
            return self.contract.verify_snapshot(request['frame'],self.expected,lambda ref:self.adapter._load(self.store.trace,ref,self.x.limits))
        patcher=patch.object(frontier_source,'_run_sync',side_effect=replay);patcher.start();self.addCleanup(patcher.stop)
    def reduce(self,loaded=None):
        if fees.JOIN is None:raise unittest.SkipTest('explicit corrected shared helper required')
        self.assertEqual(d.JOIN_SHA,capture.digest(fees.JOIN.read_bytes()))
        spec=importlib.util.spec_from_file_location('simulator.normal_money_join',fees.JOIN);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with patch.dict(sys.modules,{'simulator.normal_money_join':module}):
            return d.reduce_in_diagnostic_store(self.store,loaded or self.loaded,controller=self.controller,expected=self.expected,config=self.config,
                chain=self.x.fixture.chain,observation=self.x.observation,target_binding=self.target,actual_exit=lambda:0)
    def test_zero_actual_trace_replay_and_existing_reducer_join_never_ready(self):
        result=self.reduce();self.assertFalse(result['qualified']);self.assertFalse(result['complete']);self.assertFalse(result['financial_readiness']);self.assertFalse(result['normal_activation'])
        self.assertEqual(0,result['cost_records']);self.assertEqual(0,result['native_fee']['ordinary_booked_sat']);self.assertEqual(58000,result['native_fee']['ordinary_remaining_sat'])
        self.assertIsNone(result['actual_operator_fee_liquidity_sat']);self.assertIsNone(result['urgent_liquidity_deficit_sat'])
        self.assertEqual(19,len(result['public_table_counts']));self.assertGreaterEqual(result['trace_original_lines'],2)
        self.assertEqual(0,self.store.db.execute('SELECT count(*)FROM action').fetchone()[0]);self.store.verify_event_chain()
    def test_trace_loss_refuses_on_immutable_fee_source_reuse(self):
        self.reduce();row=self.store.db.execute("SELECT payload FROM event WHERE kind='closed_cohort_original_source'").fetchone();frame=json.loads(row[0])['response']
        ref=frame['frontier_stream_source']['line_references'][0]
        from simulator.trace import partition_paths
        trace=next(p for p in partition_paths(self.store.trace.root)if p.name==ref['partition'])
        c=sqlite3.connect(trace)
        try:
            with self.assertRaises(sqlite3.IntegrityError):c.execute('UPDATE trace SET raw=?WHERE seq=?',(b'{}\n',ref['seq']))
        finally:c.close()
        missing=trace.with_suffix('.unavailable');trace.rename(missing)
        try:
            with self.assertRaises(ValueError):self.contract.verify_snapshot(frame,self.expected,lambda r:self.adapter._load(self.store.trace,r,self.x.limits))
        finally:missing.rename(trace)
    def test_corrupt_original_stream_fails_before_source_event(self):
        loaded=copy.deepcopy(self.loaded);loaded['public_lines'][0]=loaded['public_lines'][0].replace(b'"snapshot"',b'"changed_snapshot"')
        with self.assertRaises(ValueError):self.reduce(loaded)
        self.assertEqual(0,self.store.db.execute("SELECT count(*)FROM event WHERE kind='normal_financial_source'").fetchone()[0])
    def test_actual_root_terminal_ABI_binds_flags_nonce_worker_and_archive(self):
        observation=self.x.observation;archive={'path':'/synthetic/private/zero.tar','sha256':'c'*64}
        terminal={'schema_version':1,'kind':'c-native-fee-diagnostic-transport','nonce':'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','observation_id':observation['id'],
          'started_utc':'2026-10-16T07:50:00+00:00','ended_utc':'2026-10-16T07:50:01+00:00','argv':['/synthetic/fixed/ssh'],
          'executed_worker_sha256':'a'*64,'source_binding_sha256':'b'*64,'returncode':0,'timed_out':False,'reaped':True,
          'stdout_bytes':10240,'stdout_sha256':'c'*64,'archive_path':archive['path'],'receiver_exit':0}
        kwargs={'archive_bytes':10240,'expected_binding_sha256':'b'*64}
        d.validate_terminal(terminal,observation,self.target,archive,**kwargs)
        for name,value in [('returncode',1),('returncode',False),('reaped',False),('timed_out',True),('receiver_exit',1),
                           ('stdout_sha256','d'*64),('executed_worker_sha256','d'*64),('observation_id','b'*32),('source_binding_sha256','d'*64)]:
            with self.subTest(field=name),self.assertRaises(ValueError):d.validate_terminal({**terminal,name:value},observation,self.target,archive,**kwargs)
    def test_CoreCLI_only_two_identity_methods_no_wallet_or_transaction(self):
        core=d.DiagnosticCore()
        with patch.object(d.subprocess,'run',side_effect=AssertionError('no subprocess for forbidden method')):
            for name,args in [('sendrawtransaction',('bad',)),('getrawtransaction',('a'*64,)),('getblockhash',(100,)),('getnewaddress',())]:
                with self.subTest(name=name),self.assertRaises(ValueError):core.call(name,*args)
            with self.assertRaises(ValueError):core.tx('a'*64)

    def test_explicit_isolated_file_entry_authenticates_sources_before_bootstrap(self):
        frozen=self.x.root/'readonly-source';(frozen/'simulator').mkdir(parents=True,mode=0o700)
        for path in(d.ROOT/'simulator').rglob('*.py'):
            destination=frozen/path.relative_to(d.ROOT);destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(path,destination);destination.chmod(0o644)
        shutil.copyfile(d.ROOT/'simulator/bip39-english.txt',frozen/'simulator/bip39-english.txt');(frozen/'simulator/bip39-english.txt').chmod(0o644)
        runtime={str(p.relative_to(frozen)):d.digest(p.read_bytes())for p in(frozen/'simulator').rglob('*.py')}
        runtime['simulator/bip39-english.txt']=d.digest((frozen/'simulator/bip39-english.txt').read_bytes())
        admission={'schema_version':1,'kind':'c-native-fee-zero-diagnostic','source_files':runtime,
          'archive':None,'transport':None,'observation':None,'target_binding':None,'controller_binding_sha256':'f'*64,
          'shared_join':None,'core_cli_sha256':'f'*64,'output_root':'/synthetic/not-opened'}
        class BootstrapReached(Exception):pass
        with patch.object(sys,'path',list(sys.path)),patch.object(frontier_source,'_bootstrap',side_effect=BootstrapReached):
            entry=runpy.run_path(str(frozen/'simulator/c_private_fee_diagnostic.py'),run_name='diagnostic_entry_probe')
            self.assertFalse(entry['__package__'])
            with self.assertRaises(BootstrapReached):entry['run'](admission)

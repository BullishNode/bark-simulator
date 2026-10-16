"""Protected bootstrap and consumer provenance; synthetic authority, no PG/SSH."""
import asyncio
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from simulator import frontier_source as f
from simulator.config import Config
from simulator.model import canonical
from simulator.store import Store


class SourceControls(unittest.TestCase):
    def config(self, schema=2):
        return SimpleNamespace(closed_frontier_schema=schema, architecture_profile='direct_per_key',
                               trace_enabled=True, network='signet', expected_genesis='g',
                               expected_server_pubkey='p')

    def test_selection_requires_exact_integer_C_and_trace(self):
        self.assertEqual(1, f.schema(SimpleNamespace()))
        for value in (False, True, '2', 0, 3):
            with self.subTest(value=value), self.assertRaises(ValueError):
                f.schema(self.config(value))
        for key, value in [('architecture_profile', 'direct'), ('trace_enabled', False)]:
            config=self.config();setattr(config,key,value)
            with self.assertRaises(ValueError):f.schema(config)

    def test_default_schema_never_admits_v2_or_runs_installed_code(self):
        with mock.patch.object(f,'_bootstrap') as bootstrap:
            with self.assertRaises(ValueError):
                f.verify_frame(None,self.config(1),{'schema_version':2},{})
            with self.assertRaises(ValueError):
                asyncio.run(f.collect(None,self.config(1),{}))
            bootstrap.assert_not_called()

    def test_missing_protected_binding_refuses_before_import(self):
        with mock.patch.object(f,'checked_file',side_effect=FileNotFoundError), \
                mock.patch('builtins.compile') as compile_code:
            with self.assertRaises(FileNotFoundError):f._bootstrap()
            compile_code.assert_not_called()

    def test_real_mutable_or_symlinked_path_refuses(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'binding';path.write_text('{}');path.chmod(0o666)
            with self.assertRaises(ValueError):f.checked_file(path)
            link=Path(root)/'link';link.symlink_to(path)
            with self.assertRaises((ValueError,OSError)):f.checked_file(link)

    def binding(self):
        sources={name:b'raise RuntimeError("must not execute")\n' for name in f.SOURCE_FILES}
        wrapper=b'fixed own test wrapper'
        binding={'source_files':{name:hashlib.sha256(raw).hexdigest() for name,raw in sources.items()},
                 'observer_wrapper_sha256':hashlib.sha256(wrapper).hexdigest(),'expected_contract':{}}
        raw=json.dumps(binding).encode()
        def read(path,**kwargs):
            payload=(raw if path==f.BINDING else wrapper if path==f.WRAPPER else sources[path.name])
            return payload,hashlib.sha256(payload).hexdigest()
        return sources,binding,read

    def test_each_nine_tampered_source_refuses_before_any_import(self):
        for name in sorted(f.SOURCE_FILES):
            sources,binding,read=self.binding();sources[name]+=b'# altered\n'
            with self.subTest(name=name),mock.patch.object(f,'checked_file',side_effect=read), \
                    mock.patch('builtins.compile') as compile_code:
                with self.assertRaisesRegex(ValueError,'differs before import'):f._bootstrap()
                compile_code.assert_not_called()

    def test_wrapper_tamper_and_duplicate_or_incomplete_binding_refuse_before_import(self):
        sources,binding,read=self.binding()
        for raw in (b'{"source_files":{},"source_files":{}}',json.dumps({**binding,'extra':True}).encode(),
                    json.dumps({**binding,'source_files':{}}).encode(),
                    json.dumps({**binding,'observer_wrapper_sha256':'0'*64}).encode()):
            def changed(path,**kwargs):
                if path==f.BINDING:return raw,hashlib.sha256(raw).hexdigest()
                return read(path,**kwargs)
            with self.subTest(raw=raw[:40]),mock.patch.object(f,'checked_file',side_effect=changed), \
                    mock.patch('builtins.compile') as compile_code:
                with self.assertRaises(ValueError):f._bootstrap()
                compile_code.assert_not_called()

    def test_caller_deadline_and_financial_or_chain_mismatch_refuse_before_collection(self):
        pins={'product_commit':'a'*40,'sdk_commit':'b'*40,'driver_sha256':'c'*64,
              'configuration_sha256':'d'*64,'schema_sha256':'e'*64}
        expected={'financial_pins':pins,'source_binding':{'network':'signet','genesis':'g','server_pubkey':'p'},
                  'resource_declaration':{'deadline_ms':25000}}
        controller=SimpleNamespace(protected_binding=lambda:expected,collect=mock.Mock())
        binding={'expected_contract':expected}
        self.assertEqual(expected,f._context(controller,binding,self.config(),pins,timeout=25))
        for changed_pins,config,timeout in (({**pins,'driver_sha256':'f'*64},self.config(),25),
                                         (pins,self.config(),24)):
            with self.assertRaises(ValueError):f._context(controller,binding,config,changed_pins,timeout=timeout)
        config=self.config();config.expected_server_pubkey='other'
        with self.assertRaises(ValueError):f._context(controller,binding,config,pins,timeout=25)
        controller.collect.assert_not_called()


class OriginalTraceConsumerControls(unittest.TestCase):
    """Actual frozen stream -> actual common TraceStore -> immutable event replay.

    Only installed-filesystem authority and the harmless producer command are
    synthetic. Raw rows and event hashes are real; no owner/financial readiness.
    """
    @classmethod
    def setUpClass(cls):
        cls.packet=Path(__file__).with_name('fixtures')/'track_c_frontier_v2'
        manifest=json.loads((cls.packet/'manifest.json').read_text())
        expected=set(f.SOURCE_FILES)|{'test_frontier_stream.py','test_frontier_v2_contract.py'}
        if (manifest.get('schema_version')!=1 or set(manifest.get('files',{}))!=expected):
            raise ValueError('complete frozen frontier test packet required')
        for name,digest in manifest['files'].items():
            if hashlib.sha256((cls.packet/name).read_bytes()).hexdigest()!=digest:
                raise ValueError('frozen frontier test packet differs: '+name)
        spec=importlib.util.spec_from_file_location('frontier_fixture',cls.packet/'test_frontier_v2_contract.py')
        sys.path.insert(0,str(cls.packet))
        try:
            helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
        finally:sys.path.pop(0)
        cls.expected=copy.deepcopy(helper.EXPECTED)
        cls.expected['resource_declaration'].update(deadline_ms=25000,statement_timeout_ms=1000)
        cls.lines=staticmethod(helper.lines)

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=Store(Path(self.tmp.name)/'campaign','live');self.store.attach_trace();self.addCleanup(self.store.close)
        self.pins=self.expected['financial_pins']
        self.config=SimpleNamespace(closed_frontier_schema=2,architecture_profile='direct_per_key',trace_enabled=True,
            network='signet',expected_genesis=self.expected['source_binding']['genesis'],
            expected_server_pubkey=self.expected['source_binding']['server_pubkey'])
        files={name:hashlib.sha256((self.packet/name).read_bytes()).hexdigest() for name in f.SOURCE_FILES}
        self.wrapper=b'fixed synthetic own wrapper'
        self.binding={'expected_contract':self.expected,'source_files':files,
            'observer_wrapper_sha256':hashlib.sha256(self.wrapper).hexdigest()}
        def read(path,**kwargs):
            raw=(json.dumps(self.binding).encode() if path==f.BINDING else self.wrapper if path==f.WRAPPER else Path(path).read_bytes())
            return raw,hashlib.sha256(raw).hexdigest()
        with mock.patch.object(f,'SOURCE_ROOT',self.packet),mock.patch.object(f,'checked_file',side_effect=read):
            self.controller,_,_=f._bootstrap()
        self.controller.checked_file=read
        # Use the actual fixed adapter and actual trace. Launch a harmless local
        # child in place of the unavailable root-installed SSH wrapper only.
        self.adapter=self.controller.adapter()
        original=subprocess.Popen
        payload=b''.join(self.lines(self.expected))
        import base64
        code='import sys,base64;sys.stdin.buffer.read();sys.stdout.buffer.write(base64.b64decode(%r))'%base64.b64encode(payload).decode()
        with mock.patch.object(subprocess,'Popen',side_effect=lambda command,**kw:original([sys.executable,'-I','-c',code],**kw)):
            self.frame=self.adapter._run(['synthetic-fixed-wrapper'],self.adapter.contract().request(self.expected),self.expected,self.store.trace)
        self.controller.adapter=lambda:self.adapter
        self.bootstrap=mock.patch.object(f,'_bootstrap',return_value=(self.controller,self.binding,'synthetic-binding'))
        self.bootstrap.start();self.addCleanup(self.bootstrap.stop)
        same=mock.patch.object(f,'_same_binding');same.start();self.addCleanup(same.stop)
        # These provenance tests deliberately exercise the existing real replay
        # primitive in-process. Separate lifecycle controls execute actual fresh
        # workers, blocking SQLite and descendant cleanup.
        def replay(request):
            f._context(self.controller,self.binding,self.config,self.pins)
            return self.controller.verify(request['frame'],self.store.trace)
        boundary=mock.patch.object(f,'_run_sync',side_effect=replay)
        boundary.start();self.addCleanup(boundary.stop)
        self.event_source={'source_kind':'closed_frontier','response':self.frame,
            'response_sha256':hashlib.sha256(canonical(self.frame).encode()).hexdigest(),
            'financial_pins':self.pins,'observed_at':1}
        self.sequence=self.event('closed_cohort_original_source',self.event_source)

    def event(self,kind,source):
        self.store.event(kind,source)
        return self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]

    def test_real_original_trace_replays_but_never_asserts_readiness(self):
        self.assertEqual(self.frame,f.verify_event(self.store,self.config,self.sequence,self.pins))
        self.assertEqual(2,self.frame['schema_version']);self.assertFalse(self.frame['complete']);self.assertFalse(self.frame['qualified'])
        with self.assertRaises(ValueError):f.verify_event(self.store,SimpleNamespace(closed_frontier_schema=1),self.sequence,self.pins)

    def test_event_kind_outer_pins_digest_and_inline_frame_are_independent_checks(self):
        for kind,source in [('wrong',self.event_source),('closed_cohort_original_source',{**self.event_source,'financial_pins':{}}),
                            ('closed_cohort_original_source',{**self.event_source,'response_sha256':'0'*64})]:
            sequence=self.event(kind,source)
            with self.subTest(kind=kind),self.assertRaises(ValueError):f.verify_event(self.store,self.config,sequence,self.pins)
        source={'financial_pins':self.pins,'database_source_sequence':self.sequence,'database':{**self.frame,'qualified':True}}
        with self.assertRaises(ValueError):f.verify_source(self.store,self.config,source,self.pins)

    def test_immutable_event_tamper_and_original_raw_trace_loss_refuse_on_reuse(self):
        self.store.db.execute('UPDATE event SET payload=? WHERE sequence=?',(canonical({**self.event_source,'observed_at':2}),self.sequence))
        with self.assertRaises(ValueError):f.verify_event(self.store,self.config,self.sequence,self.pins)
        # Separate original trace loss after a formerly valid receipt: no fresh
        # caller JSON can substitute for the original whole captured stream.
        sequence=self.event('closed_cohort_original_source',self.event_source)
        from simulator.trace import partition_paths
        import sqlite3
        path=partition_paths(self.store.trace.root)[0]
        connection=sqlite3.connect(path)
        with self.assertRaises(sqlite3.IntegrityError):connection.execute('UPDATE trace SET raw=NULL')
        connection.close()
        path.rename(path.with_suffix('.unavailable'))
        with self.assertRaises(ValueError):f.verify_event(self.store,self.config,sequence,self.pins)

    def test_funding_cash_backing_ancestors_replay_and_cannot_be_relabelled(self):
        initial={'financial_pins':self.pins,'database_source_sequence':self.sequence}
        initial_seq=self.event('finite_initial_funding_sources_verified',initial)
        cash={**initial,'finite_initial_source_sequence':initial_seq}
        cash_seq=self.event('finite_fresh_cash_sources_verified',cash)
        backing={**initial,'database':self.frame,'cash_source_sequence':cash_seq}
        f.verify_source(self.store,self.config,backing,self.pins)
        wrong_seq=self.event('wrong_parent_kind',cash)
        with self.assertRaises(ValueError):f.verify_source(self.store,self.config,{**backing,'cash_source_sequence':wrong_seq},self.pins)
        with self.assertRaises(ValueError):f.verify_source(self.store,self.config,{'financial_pins':self.pins,'database':self.frame},self.pins)
        with self.assertRaises(ValueError):f.verify_source(self.store,self.config,{**cash,'database_response_sha256':'f'*64},self.pins)

    def operating_proof(self,kind='finite_initial_funding'):
        import time
        from tests.owned_activity_fixture import receipt
        source={'financial_pins':self.pins,'database_source_sequence':self.sequence,
            'boundary_id':'own-boundary','height':100,'tip_hash':'a'*64,'descriptor_ranges':[],
            'observed_at':time.time()}
        if kind=='board_backing':
            source['origin']={'anchor':'a'*64+':0','anchor_output':{'script':'0014'+'ab'*20}}
            source['database']=self.frame
        activity=receipt(self.store,source,kind)
        source['mempool_activity' if kind=='finite_initial_funding' else 'mempool']=activity
        if kind=='finite_initial_funding':
            source['owned_mempool_activity_source_sequence']=self.event('finite_initial_funding_owned_mempool_activity',
                {'height':100,'tip_hash':'a'*64,'financial_pins':self.pins,'activity_source':activity})
        event_kind={'finite_initial_funding':'finite_initial_funding_sources_verified',
                    'finite_fresh_cash':'finite_fresh_cash_sources_verified',
                    'board_backing':'original_board_adoption_sources_verified'}[kind]
        sequence=self.event(event_kind,source)
        proof={key:source[key] for key in ('financial_pins','boundary_id','height','tip_hash')}
        key={'finite_initial_funding':'finite_initial_source_sequence','finite_fresh_cash':'finite_fresh_cash_source_sequence',
             'board_backing':'board_adoption_scope'}[kind]
        proof[key]={'source_sequence':sequence} if kind=='board_backing' else sequence
        return proof,source

    def test_effective_admission_replays_all_four_exact_source_routes(self):
        for kind in ('finite_initial_funding','finite_fresh_cash','board_backing'):
            proof,source=self.operating_proof(kind)
            f.verify_readiness(self.store,self.config,proof,self.pins)
            if kind=='board_backing':
                sequence=self.event('ordinary_arkoor_sources_verified',source)
                proof.pop('board_adoption_scope');proof['ordinary_arkoor_scope']={'source_sequence':sequence}
                f.verify_readiness(self.store,self.config,proof,self.pins)

    def test_effective_admission_missing_context_old_schema_or_lost_trace_holds(self):
        proof,source=self.operating_proof()
        with self.assertRaisesRegex(ValueError,'lacks original'):
            f.verify_readiness(self.store,self.config,{'financial_pins':self.pins},self.pins)
        with self.assertRaisesRegex(ValueError,'context differs'):
            f.verify_readiness(self.store,self.config,{**proof,'boundary_id':'foreign'},self.pins)
        old={**self.event_source,'response':{'schema_version':1}}
        old['response_sha256']=hashlib.sha256(canonical(old['response']).encode()).hexdigest()
        old_seq=self.event('closed_cohort_original_source',old)
        source_seq=self.event('finite_initial_funding_sources_verified',{**source,'database_source_sequence':old_seq})
        with self.assertRaisesRegex(ValueError,'schema differs'):
            f.verify_readiness(self.store,self.config,{**proof,'finite_initial_source_sequence':source_seq},self.pins)
        from simulator.trace import partition_paths
        path=partition_paths(self.store.trace.root)[0];path.rename(path.with_suffix('.missing'))
        with self.assertRaises(ValueError):f.verify_readiness(self.store,self.config,proof,self.pins)

    def test_effective_admission_refuses_copied_owning_activity_context(self):
        proof,source=self.operating_proof('finite_fresh_cash')
        changed=self.event('finite_fresh_cash_sources_verified',
            {**source,'descriptor_ranges':[{'desc':'foreign-public-descriptor','range':[0,19]}]})
        with self.assertRaisesRegex(ValueError,'collector context'):
            f.verify_readiness(self.store,self.config,{**proof,'finite_fresh_cash_source_sequence':changed},self.pins)


class EffectiveCallsiteControls(unittest.TestCase):
    def test_actual_preflight_legacy_positive_cannot_be_reused_as_schema2(self):
        from tests.test_operating_limits import OperatingLimitsTests
        from simulator.operating_limits import preflight
        fixture=OperatingLimitsTests();fixture.setUp();self.addCleanup(fixture.tearDown)
        snapshot=fixture.readiness()
        self.assertTrue(preflight(fixture.store,fixture.config,snapshot)['allowed'])
        fixture.config.closed_frontier_schema=2
        fixture.config.architecture_profile='direct_per_key';fixture.config.trace_enabled=True
        with self.assertRaisesRegex(ValueError,'lacks original source'):
            preflight(fixture.store,fixture.config,snapshot)

    def test_schema2_never_falls_back_to_legacy_exploratory_dispatch(self):
        from tests.test_operating_limits import OperatingLimitsTests
        from simulator.operating_limits import preflight
        fixture=OperatingLimitsTests();fixture.setUp();self.addCleanup(fixture.tearDown)
        fixture.config.closed_frontier_schema=2
        fixture.config.architecture_profile='direct_per_key';fixture.config.trace_enabled=True
        with mock.patch('simulator.exploratory.scope',return_value={'legacy':'unqualified'}), \
                mock.patch('simulator.exploratory.preflight') as legacy:
            with self.assertRaisesRegex(ValueError,'legacy exploratory'):
                preflight(fixture.store,fixture.config,fixture.snapshot)
            legacy.assert_not_called()


if __name__=='__main__':unittest.main()

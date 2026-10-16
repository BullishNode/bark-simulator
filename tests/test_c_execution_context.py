"""Actual source/TraceStore/context controls, entirely synthetic qualification.

No actual native stored load, deployed runtime or financial readiness credit.
"""
import copy
import hashlib
import json
import sqlite3
import time
import unittest
from pathlib import Path

from simulator import c_execution_context as c, c_client_transition as signatures
from tests import test_c_client_transition,test_c_pilot
from simulator.model import canonical,SIGNET_GENESIS


class ExecutionContextControls(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fixture=test_c_client_transition.ClientSignatureControls();self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups);self.store=self.fixture.store;self.config=self.fixture.config
        self.root=self.fixture.root;self.number=0
    def write(self,name,value):
        p=self.root/name;p.write_text(json.dumps(value,separators=(',',':')));p.chmod(0o600)
        return {'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
    def change(self,name,value):
        self.admission[name]=self.write(name+'.json',value)
        return self.write('admission.json',self.admission)
    async def prepare(self):
        self.sig=await self.fixture.collect()
        db=self.fixture.fixture.wallet/'actor-01'/'db.sqlite'
        conn=sqlite3.connect(db);conn.execute('CREATE TABLE bark_properties(id INTEGER,fingerprint TEXT)')
        conn.execute("INSERT INTO bark_properties VALUES(1,'cafebabe')");conn.commit();conn.close()
        dbsha=hashlib.sha256(db.read_bytes()).hexdigest();old=self.fixture.fixture.pins['sdk_commit']
        self.result={'schema_version':1,'actor':'c_create_01','result':'PASS','old_sdk_source':old,
            'new_sdk_source':'c'*40,'new_sdk_baseline':'f'*40,'old_database_sha256':dbsha,
            'all_tables_sha256':'5'*64,'sqlite_schema_before':43,'sqlite_schema_after':43,
            'retained_key_count':51,'two_existing_opens':True,'assets_sat':0,'recovery_or_sync_called':False,
            'new_wallet_created':False,'monetary_RPC_or_dispatch':False,'network':'signet','genesis':SIGNET_GENESIS,
            'core_tip_unchanged':True,'original_file_immutability_requires_independent_runner_recheck':True,
            'identity':{'fingerprint':'cafebabe',**c._public_identity(signatures._origin(self.store)[3])}}
        files={'db.sqlite':{'sha256':dbsha},**{'public-'+str(i):{'sha256':str(i)*64} for i in range(1,5)}}
        source=self.write('source.json',{'source_files':files})
        self.inputs={'schema_version':1,'actor':'c_create_01','old_sdk_source':old,'new_sdk_source':'c'*40,
            'new_sdk_baseline':'f'*40,'original_source_manifest_sha256':source['sha256'],
            'qualified_copy_seal_sha256':'2'*64,'projection_contract_sha256':'3'*64,'network':'signet',
            'genesis':SIGNET_GENESIS,'all_tables_sha256':'5'*64,'copies_independently_verified':True,
            'original_snapshots_unchanged':True,'copy_is_not_original':True,**self.result['identity']}
        inputs=self.write('inputs.json',self.inputs)
        self.result.update(inputs_sha256=inputs['sha256'],original_source_manifest_sha256=source['sha256'],qualified_copy_seal_sha256='2'*64)
        result=self.write('result.json',self.result)
        self.contract={'contract_revision':3,'frozen_source':'a'*40,'tree':'b'*40,'source_archive_sha256':'a'*64,
            'SDK_component':'c'*40,'SDK_baseline':'f'*40,'selector':{'name':'stored_upgrade::synthetic_existing_open'},
            'INPUTS_exact_required_fields':copy.deepcopy(self.inputs),
            'RESULT_fixed_values':{k:self.result[k] for k in ('result','old_database_sha256','sqlite_schema_before','sqlite_schema_after',
                'retained_key_count','two_existing_opens','assets_sat','recovery_or_sync_called','new_wallet_created',
                'monetary_RPC_or_dispatch','network','core_tip_unchanged','original_file_immutability_requires_independent_runner_recheck')}}
        binary=self.root/'synthetic-native-ELF';binary.write_bytes(b'synthetic test artifact; never executed');binary.chmod(0o700)
        binarysha=hashlib.sha256(binary.read_bytes()).hexdigest()
        self.build={'actual_source':'a'*40,'actual_tree':'b'*40,'source_archive_sha256':'a'*64,'SDK_component':'c'*40,'SDK_baseline':'f'*40,
            'artifacts':{'per-key':{'sha256':binarysha,'bytes':binary.stat().st_size}}}
        self.runner={'source_commit':'a'*40,'source_tree':'b'*40,'source_archive_sha256':'a'*64,
            'binary_sha256':binarysha,'selector':self.contract['selector']['name'],'inputs_sha256':inputs['sha256'],'result_sha256':result['sha256'],
            'exit_code':0,'listed_tests':1,'passed_tests':1,'argv':[str(binary),self.contract['selector']['name'],'--exact'],
            'readonly_core_genesis':SIGNET_GENESIS,'original_locks_held':True,'copy_lock_held':False,
            'original_files_before':{hashlib.sha256(n.encode()).hexdigest():r['sha256'] for n,r in files.items()}}
        self.runner['original_files_after']=copy.deepcopy(self.runner['original_files_before'])
        self.admission={'schema_version':1,'contract':self.write('contract.json',self.contract),'build':self.write('build.json',self.build),
            'binary':{'path':str(binary),'sha256':binarysha},'inputs':inputs,'result':result,'runner':self.write('runner.json',self.runner),
            'original_manifest':source,'original_database':{'path':str(db),'sha256':dbsha},
            'projection':self.write('projection.json',{'all_tables_sha256':'5'*64,'original_DB_sha256':dbsha,'schema_version':43,
                'table_count':33,'retained_key_count':51,'key_indices':list(range(51)),'issued_indices':[0]})}
        self.runner.update(contract_sha256=self.admission['contract']['sha256'],build_manifest_sha256=self.admission['build']['sha256'],
            projection_sha256=self.admission['projection']['sha256'],original_source_manifest_sha256=source['sha256'],
            qualified_copy_seal_sha256=self.inputs['qualified_copy_seal_sha256'])
        self.admission['runner']=self.write('runner.json',self.runner)
        return self.write('admission.json',self.admission)
    def record(self,item):return c.record_stored_load_source(self.store,signature_sequence=self.sig,admission_path=item['path'],admission_sha256=item['sha256'])

    async def test_native_import_authenticates_original_identity_and_refuses_wrong_result_runner_and_files(self):
        item=await self.prepare()
        for name,change in [('identity',{**self.result['identity'],'fingerprint':'wrong'}),('assets_sat',1),('two_existing_opens',False)]:
            bad={**self.result,name:change};item=self.change('result',bad)
            self.runner['result_sha256']=self.admission['result']['sha256'];item=self.change('runner',self.runner)
            with self.subTest(name=name),self.assertRaises(ValueError):self.record(item)
        item=self.change('result',self.result);self.runner['result_sha256']=self.admission['result']['sha256']
        for name,value in [('passed_tests',0),('listed_tests',2),('exit_code',1),('original_files_after',{}),('source_commit','d'*40)]:
            with self.subTest(name=name),self.assertRaises(ValueError):self.record(self.change('runner',{**self.runner,name:value}))
        item=self.change('runner',self.runner);sequence=self.record(item)
        verified=c.verified_stored_load(self.store,sequence)
        self.assertTrue(verified['wallet_load_qualified']);self.assertFalse(verified['financial_readiness'])
        with self.assertRaisesRegex(ValueError,'retain original'):self.record(item)
        # Physical source mutation refuses at independent hash before importing.
        Path(self.admission['binary']['path']).write_bytes(b'changed')
        with self.assertRaises(ValueError):
            self.record(self.write('second-admission.json',{**self.admission,'schema_version':2}))

    async def test_real_runtime_verifier_activation_keeps_origin_and_new_financial_pins_separate(self):
        item=await self.prepare();native=self.record(item)
        expected,startup,current=test_c_pilot.NativeStartupControls.frames(object())
        product='d'*40;schema='e'*64
        expected.update(product_commit=product,schema_sha256=schema)
        for frame in (startup,current):
            frame.update(product_commit=product,schema_sha256=schema)
            for name,row in frame['daemons'].items():row['version']=name+' '+product
        startup_file=self.write('startup.json',startup);current_file=self.write('current.json',current)
        config_file=self.root/'synthetic-financial.toml'
        cfg=self.config
        sections={'target':{'network':cfg.network,'genesis':cfg.expected_genesis,'architecture_profile':'direct_per_key',
            'sdk_commit':cfg.expected_sdk_commit,'runtime_transport':'systemd','container':cfg.expected_container,
            'image_digest':cfg.expected_image,'server_pubkey':cfg.expected_server_pubkey},
            'runtime':{'state_dir':str(cfg.state_dir),'wallet_root':str(cfg.wallet_root),
            'driver_command':list(cfg.driver_command),'observer_command':list(cfg.observer_command),
            'fee_budget_sat':cfg.fee_budget_sat,'interval_seconds':cfg.interval_seconds,
            'action_timeout_seconds':cfg.action_timeout_seconds,'active':cfg.active,
            'board_amount_sat':cfg.board_amount_sat,'action_fee_reserve_sat':cfg.action_fee_reserve_sat},
            'trace':{'enabled':cfg.trace_enabled},
            'executables':{cfg.driver_command[0]:hashlib.sha256(Path(cfg.driver_command[0]).read_bytes()).hexdigest()}}
        config_file.write_text('\n'.join('['+section+']\n'+'\n'.join(json.dumps(k)+' = '+json.dumps(v) for k,v in rows.items())
            for section,rows in sections.items()))
        signed=signatures.verified_original_bindings(self.store,self.sig)
        newpins={'product_commit':'9'*40,'sdk_commit':'f'*40,'driver_sha256':signed['execution_client']['driver_sha256'],
            'configuration_sha256':hashlib.sha256(config_file.read_bytes()).hexdigest(),'schema_sha256':schema}
        build=self.write('release.json',{'actual_GIT_HASH':product,'financial_product_component':'9'*40,'SDK_component':'c'*40,
            'bins':{name:{'sha256':'a'*64} for name in ('captaind','watchmand')}})
        before=self.store.get_meta('zero_principal_identity_bootstrap')
        kwargs={'identifier':'actual-source-shaped-transition','signature_sequence':self.sig,'stored_load_sequence':native,
            'new_financial_pins':newpins,'build_manifest_path':build['path'],'build_manifest_sha256':build['sha256'],
            'configuration_path':str(config_file),'expected_runtime':expected,'startup_path':startup_file['path'],'current_path':current_file['path']}
        import dataclasses
        with self.assertRaisesRegex(ValueError,'actual loaded financial configuration'):
            c.activate(self.store,dataclasses.replace(self.config,active=False),self.fixture.fixture.chain,**kwargs)
        value=c.activate(self.store,self.config,self.fixture.fixture.chain,**kwargs)
        self.assertEqual(self.fixture.fixture.pins,value['origin_financial_pins']);self.assertEqual(newpins,value['financial_pins'])
        self.assertFalse(value['financial_readiness']);self.assertEqual(before,self.store.get_meta('zero_principal_identity_bootstrap'))
        self.assertEqual(newpins,c.effective_pins(self.store,self.fixture.fixture.pins))
        from simulator.identity_bootstrap import _context
        context=_context(self.config,json.loads(before),store=self.store)
        self.assertEqual(newpins['driver_sha256'],context['driver_sha256'])
        with self.assertRaisesRegex(ValueError,'immutable'):c.activate(self.store,self.config,self.fixture.fixture.chain,**kwargs)
        self.assertEqual(1,self.store.db.execute('SELECT count(*) FROM action').fetchone()[0])
        # The actual original02 admission keeps its once-only ID and old
        # declaration, while NEW source events use the activated financial pins.
        case=self.fixture.fixture
        snapshot={**case.fixture.snapshot,'financial_pins':newpins,
            'origin_financial_pins':value['origin_financial_pins'],'execution_release':value['execution_release'],
            'deployment_epoch_id':value['id'],'financial_pins_scope':'active_execution_with_preserved_origin',
            'runtime_source_sequence':value['runtime_source_sequence'],'observed_at':time.time()}
        self.store.add_snapshot(snapshot)
        from simulator import identity_bootstrap as bootstrap,c_cohort
        self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        self.assertTrue(bootstrap.eligible(self.store,self.config,snapshot))
        case.config=self.config;case.fixture.config=self.config;case.fixture.snapshot=snapshot
        old_pins=case.pins;case.pins=newpins
        case.complete_new_identity('actor-02');case.pins=old_pins
        self.assertFalse(bootstrap.pending(self.store))
        proofs={json.loads(row['payload'])['actor']:json.loads(row['payload']) for row in self.store.db.execute(
            "SELECT payload FROM event WHERE kind='identity_bootstrap_zero_assets_verified'")}
        self.assertEqual(old_pins,proofs['actor-01']['financial_pins'])
        self.assertEqual(newpins,proofs['actor-02']['financial_pins'])
        self.assertEqual(before,self.store.get_meta('zero_principal_identity_bootstrap'))
        c_cohort.declare_profile(self.store,case.profile())
        self.assertEqual(newpins,c_cohort.prospective_funding_policy(self.store)['pins'])
        c_cohort.declare_enrollment(self.store,self.config,'initial',identifier='new-sdk-extra10',
            actions={actor:'c_create_'+actor[-2:] for actor in c_cohort.INITIAL[2:]})
        self.assertEqual(newpins,c_cohort.enrollment(self.store,'initial')['declaration']['pins'])
        with self.assertRaisesRegex(ValueError,'all original12'):c_cohort.initial_identity_sources(self.store)
        case.pins=newpins
        for actor in c_cohort.INITIAL[2:]:case.complete_new_identity(actor)
        case.pins=old_pins
        complete=c_cohort.initial_identity_sources(self.store)
        self.assertEqual(newpins,complete['financial_pins']);self.assertEqual(old_pins,complete['origin_financial_pins'])
        self.assertEqual(old_pins,complete['sources']['actor-01']['financial_pins'])
        self.assertTrue(all(complete['sources'][actor]['financial_pins']==newpins for actor in c_cohort.INITIAL[1:]))
        bootstrap.require_only_verified_creates(self.store,newpins)
        self.assertEqual(12,self.store.db.execute('SELECT count(*) FROM action').fetchone()[0])
        self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM event WHERE kind='financial_operating_readiness'").fetchone()[0])

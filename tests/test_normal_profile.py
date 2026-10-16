"""Installed source wiring controls; fake tools never receive native credit."""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from simulator.architecture import TWO_STEP
from simulator.engine import Engine, initialize
from simulator.model import SIGNET_GENESIS, canonical
from simulator.normal_profile import collector_from_profile
from simulator.normal_funding_reader import FundingReader
from simulator.store import Store
from simulator.two_step_normal import digest, module_hash
from tests.test_final_campaign import PINS


class FundingReadTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.wallet=self.root/'wallets';self.wallet.mkdir()
        self.store=Store(self.root/'state','source-contract',10000)
        self.files=self.root/'originals';self.files.mkdir(mode=0o700)
        self.declaration=b'{"source":"synthetic original contract only"}';self.sha=digest(self.declaration)
        self.file=self.files/'original.json';self.file.write_bytes(b'{"raw":"synthetic"}');self.file.chmod(0o600)
        self.manifest={'files':{'original.json':{'sha256':digest(self.file.read_bytes()),'size_bytes':self.file.stat().st_size}}}
        self.manifest_path=self.root/'manifest.json';self.manifest_path.write_text(canonical(self.manifest));self.manifest_path.chmod(0o600)
        self.declaration_path=self.root/'declaration.json';self.declaration_path.write_bytes(self.declaration);self.declaration_path.chmod(0o600)
        self.boundary={'pins':PINS,'id':'fixture-members'}
        from simulator.normal_funding_ownership import verify_funding_ownership
        self.qualified={'financial_pins':PINS,'boundary_sha256':digest(canonical(self.boundary).encode()),
            'module_sha256':module_hash(verify_funding_ownership),'declarations':[{'declaration_sha256':self.sha,
                'bank_manifest_sha256':digest(self.manifest_path.read_bytes())}]}
        self.store.event('normal_funding_ownership_sources_qualified',self.qualified)
        self.sequence=self.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
        self.configuration={'qualification_sequence':self.sequence,'packages':{self.sha:{'declaration_path':str(self.declaration_path),
            'manifest_path':str(self.manifest_path),'files_root':str(self.files)}}}
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def read(self):return FundingReader(self.configuration,self.wallet).read(self.store,self.boundary)
    def test_exact_private_original_bytes_are_reloaded_without_events_or_ownership_verdict(self):
        before=self.store.db.execute('SELECT count(*)FROM event').fetchone()[0];value=self.read()
        self.assertEqual(self.declaration,value['packages'][self.sha]['declaration_bytes'])
        self.assertEqual(self.file.read_bytes(),value['packages'][self.sha]['files']['original.json'])
        self.assertEqual(before,self.store.db.execute('SELECT count(*)FROM event').fetchone()[0])
        self.assertNotIn('ready',value)
        self.file.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'hash'):self.read()
    def test_missing_original_membership_module_or_manifest_never_means_zero(self):
        self.configuration['packages']={}
        with self.assertRaises(ValueError):self.read()
        self.configuration['packages']={self.sha:{'declaration_path':str(self.declaration_path),'manifest_path':str(self.manifest_path),'files_root':str(self.files)}}
        self.qualified['module_sha256']='f'*64;self.store.event('normal_funding_ownership_sources_qualified',self.qualified)
        self.configuration['qualification_sequence']=self.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
        with self.assertRaisesRegex(ValueError,'admission'):self.read()
    def test_wallet_paths_symlinks_and_public_original_permissions_hold(self):
        config=self.configuration['packages'][self.sha];original=config['declaration_path']
        config['declaration_path']=str(self.wallet/'source.json')
        with self.assertRaisesRegex(ValueError,'outside wallet'):self.read()
        link=self.root/'aliased.json';link.symlink_to(self.declaration_path);config['declaration_path']=str(link)
        with self.assertRaisesRegex(ValueError,'unaliased'):self.read()
        config['declaration_path']=original;self.file.chmod(0o644)
        with self.assertRaisesRegex(ValueError,'private source'):self.read()


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.wallet=self.root/'wallets';self.wallet.mkdir()
        self.pins=copy.deepcopy(PINS);driver=self.root/'actual-driver';driver.write_bytes(b'synthetic source identity only');driver.chmod(0o700);self.pins['driver_sha256']=digest(driver.read_bytes())
        self.store=Store(self.root/'state','source-contract',10000,architecture_profile=TWO_STEP);initialize(self.store)
        self.config=SimpleNamespace(driver_command=(str(driver),),wallet_root=self.wallet,architecture_profile=TWO_STEP,expected_sdk_commit=self.pins['sdk_commit'],
            network='signet',expected_genesis=SIGNET_GENESIS,expected_container='container',expected_image='sha256:'+'a'*64,
            expected_server_pubkey='02'+'b'*64)
        self.members=[];mapping={}
        for n in range(1,25):
            name='customer-'+str(n);member={'id':name,'kind':'wallet','role':'customer','identity':'descriptor-'+str(n),'descriptors':['public-'+str(n)]}
            self.store.event('treasury_member_verified',{'member':member,'financial_pins':self.pins,'genesis':SIGNET_GENESIS})
            self.members.append({**member,'verification_sequence':self.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]});mapping[f'actor-{n:02}']=name
        self.boundary={'id':'actual-declaration-fixture','genesis':SIGNET_GENESIS,'pins':self.pins,'members':self.members,'excluded':[]}
        self.envelope={'pins':self.pins,'boundary_id':self.boundary['id'],'unchosen_fixture_limits':True,'grant_sat':15000}
        self.funding={'initial_clients':12,'ramp_clients':12,'grant_sat':15000,'maximum_total_principal_sat':360000,'batch_maximum_fee_sat':1000,'maximum_total_fee_sat':2000}
        self.opening={'declaration':{'target_epoch_id':'deployed-fixture'}}
        self.final={'pins':self.pins};identity={key:getattr(self.config,name)for key,name in [('network','network'),('genesis','expected_genesis'),
            ('container','expected_container'),('image_digest','expected_image'),('server_pubkey','expected_server_pubkey')]}
        self.store.event('target_epoch_declared',{'id':'deployed-fixture','identity':identity,'sdk_commit':self.pins['sdk_commit'],
            'native_hashes':{'bark-sim-driver':self.pins['driver_sha256']}})
        self.admission={'financial_pins':self.pins,'proof_schema_versions':{'pending':2}}
        self.store.event('normal_financial_collector_qualified',self.admission);self.sequence=self.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
        tools={}
        for name in ['policy','binding','pending']:
            binary=self.root/name;binary.write_bytes(('synthetic not executable '+name).encode());binary.chmod(0o700);evidence=self.root/(name+'-evidence');evidence.mkdir(mode=0o700)
            tools[name]={'command':[str(binary)],'sha256':digest(binary.read_bytes()),'evidence_directory':str(evidence)}
        directories={name:self.root/name for name in ['target-source','member-source','helper-source']}
        for directory in directories.values():directory.mkdir(mode=0o700)
        self.value={'schema_version':1,'architecture_profile':TWO_STEP,'financial_pins':self.pins,'admission_sequence':self.sequence,
            'boundary_sha256':digest(canonical(self.boundary).encode()),'envelope_sha256':digest(canonical(self.envelope).encode()),
            'opening_sha256':digest(canonical(self.opening).encode()),'funding_plan_sha256':digest(canonical(self.funding).encode()),'target_epoch_id':'deployed-fixture',
            'capture_configuration':{'actor_member_ids':mapping},'target_configuration':{'evidence_directory':str(directories['target-source'])},
            'member_configuration':{'actor_member_ids':mapping,'wallet_root':str(self.wallet),'evidence_root':str(directories['member-source']),'helper_evidence_root':str(directories['helper-source'])},
            'tools':tools,'funding_configuration':{'synthetic_reader_contract_only':True}}
        self.path=self.root/'installed-profile.json';self.config.normal_source_profile=self.path;self.save()
        outer=self
        class Capture:
            def collect(inner,*args):raise AssertionError('no source collection in wiring test')
            def admission(inner,*args):pass
        class Reader:
            configuration=outer.value['funding_configuration']
            def read(inner,*args):return {'synthetic_read_only_contract':True}
        self.collector=SimpleNamespace(admission=lambda *args:None,capture=Capture().collect,funding_reader=Reader())
        self.patches=[patch('simulator.normal_profile.boundary',side_effect=lambda store:self.boundary),
            patch('simulator.normal_profile.envelope',side_effect=lambda store,config:self.envelope),
            patch('simulator.normal_profile.recorded',side_effect=lambda store:self.opening),
            patch('simulator.normal_profile.epoch',side_effect=lambda store:self.final),
            patch('simulator.normal_profile.plan',side_effect=lambda store:self.funding),
            patch('simulator.normal_profile.active_identity',return_value=identity),
            patch('simulator.two_step_normal_factory.build_collector',return_value=self.collector)]
        for p in self.patches:p.start();self.addCleanup(p.stop)
    def save(self):self.path.write_text(canonical(self.value));self.path.chmod(0o600);self.config.normal_source_profile_sha256=digest(self.path.read_bytes())
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def load(self):return collector_from_profile(self.config,self.store)
    def test_explicit_profile_wires_only_static_factory_without_events_or_native_calls(self):
        count=self.store.db.execute('SELECT count(*)FROM event').fetchone()[0]
        self.assertIs(self.collector,self.load());self.assertEqual(count,self.store.db.execute('SELECT count(*)FROM event').fetchone()[0])
    def test_missing_opening_epoch_or_changed_budget_hash_remains_hold(self):
        old=self.opening;self.opening=None
        with self.assertRaisesRegex(ValueError,'admitted opening'):self.load()
        self.opening=old;self.final=None
        with self.assertRaisesRegex(ValueError,'admitted opening'):self.load()
        self.final={'pins':self.pins};self.envelope['budget_changed']=True
        with self.assertRaisesRegex(ValueError,'admitted opening'):self.load()
    def test_funding_plan_missing_or_different_grant_is_not_selected_by_builder(self):
        self.funding['grant_sat']=20000
        with self.assertRaisesRegex(ValueError,'funding plan'):self.load()
        self.funding['grant_sat']=15000;self.funding['maximum_total_principal_sat']=1
        self.value['funding_plan_sha256']=digest(canonical(self.funding).encode());self.save()
        with self.assertRaisesRegex(ValueError,'funding plan'):self.load()
    def test_profile_tampering_dynamic_module_and_sdk_mismatch_refuse(self):
        self.path.write_text('{}')
        with self.assertRaisesRegex(ValueError,'profile hash'):self.load()
        self.value['module']='os';self.save()
        with self.assertRaisesRegex(ValueError,'explicit A'):self.load()
        del self.value['module'];self.save();self.config.expected_sdk_commit='e'*40
        with self.assertRaisesRegex(ValueError,'SDK differs'):self.load()
    def test_schema1_unadmitted_tools_missing_absent_or_future_member_refuse(self):
        self.admission['proof_schema_versions']['pending']=1;self.store.event('normal_financial_collector_qualified',self.admission)
        self.value['admission_sequence']=self.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0];self.save()
        with self.assertRaisesRegex(ValueError,'schema2'):self.load()
        self.admission['proof_schema_versions']['pending']=2;self.store.event('normal_financial_collector_qualified',self.admission)
        self.value['admission_sequence']=self.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
        del self.value['member_configuration']['actor_member_ids']['actor-09'];self.save()
        with self.assertRaisesRegex(ValueError,'member identities'):self.load()
    def test_changed_tool_file_or_substituted_member_event_refuses(self):
        binary=Path(self.value['tools']['pending']['command'][0]);binary.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'executable hash'):self.load()
        binary.write_bytes(b'synthetic not executable pending')
        self.store.event('unqualified_member',{'member':self.members[0]});self.members[0]['verification_sequence']=self.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
        self.value['boundary_sha256']=digest(canonical(self.boundary).encode());self.save()
        with self.assertRaisesRegex(ValueError,'member registration'):self.load()


class CliWiringTests(unittest.TestCase):
    def test_actual_observe_cli_installs_explicit_profile_collector(self):
        import sys
        from simulator.cli import main
        from tests.test_architecture_wiring import ProfileConfigurationTests,SDK
        fixture=ProfileConfigurationTests();fixture.setUp();self.addCleanup(fixture.tearDown);fixture.write(TWO_STEP,SDK)
        with fixture.path.open('a')as output:output.write('\n[trace]\nenabled=false\n[normal_financial_source]\nprofile="'+str(fixture.root/'profile.json')+'"\nsha256="'+'a'*64+'"\n')
        sentinel=object();called=[]
        async def run(engine,once):called.append((engine.financial_source_collector,once))
        with patch.object(sys,'argv',['bark-simulator','observe','--config',str(fixture.path),'--once']),\
                patch('simulator.normal_profile.collector_from_profile',return_value=sentinel)as build,patch.object(Engine,'run',run):
            main()
        self.assertEqual([(sentinel,True)],called);self.assertEqual(1,build.call_count)
    def test_config_requires_a_profile_hash_and_rejects_dynamic_module_fields(self):
        from simulator.config import Config
        from tests.test_architecture_wiring import ProfileConfigurationTests,SDK
        fixture=ProfileConfigurationTests();fixture.setUp();self.addCleanup(fixture.tearDown)
        for profile,section in [(TWO_STEP,'profile="/fixed/profile.json"'),
                (TWO_STEP,'profile="/fixed/profile.json"\nsha256="bad"'),
                ('direct_xpub','profile="/fixed/profile.json"\nsha256="'+'a'*64+'"'),
                (TWO_STEP,'profile="/fixed/profile.json"\nsha256="'+'a'*64+'"\nmodule="os"')]:
            fixture.write(profile,SDK)
            with fixture.path.open('a')as output:output.write('\n[normal_financial_source]\n'+section+'\n')
            with self.subTest(profile=profile,section=section),self.assertRaises(ValueError):Config.load(fixture.path)

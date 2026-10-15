"""Synthetic source/Store controls only; these do not qualify a live deployment."""
import copy,hashlib,json,tempfile,time,unittest
from pathlib import Path
from simulator.model import canonical
from simulator.store import CampaignPaused
from simulator.target_epochs import (SERVER_COMMIT,DEPLOY_COMMIT,SERVER_IMAGE,ORIGIN_COMMIT,
    runtime_declaration_hashes,declare,active_runtime_manifest,verified_execution_context,verified_runtime_source)
from simulator.runtime_startup import verify_owned_startup_sources
from tests import test_target_epochs as target_fixture
from tests import test_runtime_startup as runtime_fixture

class FiniteRuntimeEpochTests(unittest.TestCase):
    def setUp(self):
        driver_sha256=getattr(self,'driver_sha256','5'*64)
        self.target=target_fixture.TargetEpochTests();self.target.setUp();self.store=self.target.store
        self.store.db.execute("INSERT INTO meta VALUES('financial_qualification_required','true')")
        self.runtime=runtime_fixture.RuntimeStartupTests();self.runtime.setUp();self.runtime.store=self.store
        self.root=self.runtime.root
        for service in ('captaind','watchmand'):
            self.runtime.original['daemons'][service]['image_sha256']=self.target.old['image_digest']
        self.runtime.original['daemons']['captaind']['container']=self.target.old['container']
        self.runtime.current=copy.deepcopy(self.runtime.original)
        self.runtime.expected['image_sha256']=self.target.old['image_digest']
        self.runtime.expected['containers']['captaind']=self.target.old['container']
        self.runtime.current['canonical_schema']={'protocol':'pg-dump-restrict-lines-v1','sha256':'f'*64,
            'repeat_sha256':'f'*64,'removed_line_kinds':['restrict','unrestrict']}
        self.runtime.original=copy.deepcopy(self.runtime.current)
        self.prior=self.runtime.verify()
        self.prior_sequence=self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
        self.pins={'product_commit':ORIGIN_COMMIT,'sdk_commit':ORIGIN_COMMIT,'driver_sha256':driver_sha256,
            'configuration_sha256':hashlib.sha256(canonical(self.runtime.expected['config_sha256']).encode()).hexdigest(),'schema_sha256':'b'*64}
        bootstrap={'pins':self.pins,'identity':self.target.old,'wallet_root':self.store.get_meta('wallet_root')}
        self.store.db.execute("INSERT INTO meta VALUES('zero_principal_identity_bootstrap',?)",(canonical(bootstrap),))
        bootstrap_source=getattr(self,'bootstrap_source',None)
        source=bootstrap_source(bootstrap) if bootstrap_source else {'declaration':bootstrap}
        self.store.db.execute("UPDATE meta SET value=? WHERE key='zero_principal_identity_bootstrap'",(canonical(bootstrap),))
        self.store.event('identity_bootstrap_declared',source)
        for key in ('conserved_treasury_boundary','financial_operating_envelope','finite_initial_funding_plan','finite_first_board_plan'):
            self.store.db.execute('INSERT INTO meta VALUES(?,?)',(key,'original-'+key))
        self.expected=copy.deepcopy(self.runtime.expected)
        self.expected.update(product_commit=SERVER_COMMIT,image_sha256=SERVER_IMAGE,schema_sha256='e'*64)
        self.expected['binary_sha256']={service:'9'*64 for service in ('captaind','watchmand')}
        self.new=copy.deepcopy(self.runtime.original);self.new.update(product_commit=SERVER_COMMIT,schema_sha256='e'*64)
        for service,daemon in self.new['daemons'].items():
            daemon.update(image_sha256=SERVER_IMAGE,binary_sha256='9'*64,process_exe_sha256='9'*64,
                pid=daemon['pid']+1000,version=service+' '+SERVER_COMMIT)
        self.startup=self.root/'new-startup';self.current=self.root/'new-current'
        self.startup.write_text(json.dumps(self.new));self.current.write_text(json.dumps(self.new))
        self.value=self.target.declaration();self.value.update(sdk_commit=ORIGIN_COMMIT)
        self.value['native_hashes']['bark-sim-driver']=driver_sha256
        self.value['identity']['image_digest']=SERVER_IMAGE
        self.release={'product_commit':SERVER_COMMIT,'deploy_commit':DEPLOY_COMMIT,'image_sha256':SERVER_IMAGE,
            'sdk_commit':ORIGIN_COMMIT,'driver_sha256':driver_sha256,'configuration_sha256':self.pins['configuration_sha256'],'schema_sha256':'e'*64}
        self.store.add_snapshot({'observed_at':time.time(),'financial_pins':self.pins})
        self.unpause();self.store.queue('original-send','actor-01','H01','send_arkoor',{'amount_sat':2000},0)
        self.store.claim({'send_arkoor'});self.store.finish('original-send','completed',{'status':'ok'},0)
        self.store.db.execute("INSERT INTO meta VALUES('paused','cutover')")
        self.store.event('ark_transfer_verified',{'action_id':'original-send'})
        transfer=self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
        self.store.event('ordinary_arkoor_journey_verified',{'financial_pins':self.pins,'sender_actor':'actor-01',
            'recipient_actor':'actor-02','amount_sat':2000,'miner_fee_sat':0,'internal_service_fee_sat':0,
            'action_id':'original-send','ark_transfer_sequence':transfer})
        journey=self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
        last=self.store.db.execute('SELECT sequence,hash FROM event ORDER BY sequence DESC LIMIT 1').fetchone()
        self.value['runtime_manifest']={'scope':'finite_exploratory','origin_financial_pins':self.pins,
            'execution_release':self.release,'expected':self.expected,'startup_source_sha256':hashlib.sha256(self.startup.read_bytes()).hexdigest(),
            'previous_runtime_source_sequence':self.prior_sequence,'precutover_source_sequence':journey,'checkpoint':dict(last),
            'preserved_declaration_hashes':runtime_declaration_hashes(self.store)}
    def tearDown(self):self.runtime.tearDown();self.target.tearDown()
    def install(self):
        declare(self.store,self.value)
        result=verify_owned_startup_sources(self.store,self.startup,self.current,expected=self.expected)
        sequence=self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
        return sequence,result
    def snapshot(self,sequence,**changes):
        snapshot={'observed_at':time.time(),'financial_pins':self.pins,'financial_pins_scope':'preserved_origin_and_budget_lineage',
            'execution_release':self.release,'deployment_epoch_id':self.value['id'],'runtime_source_sequence':sequence,
            'identity':self.value['identity'],**changes}
        self.store.add_snapshot(snapshot);return snapshot
    def unpause(self):self.store.db.execute("DELETE FROM meta WHERE key='paused'")
    def test_new_baseline_accepts_new_pids_keeps_original_prefix_and_requires_actual_context(self):
        before=[tuple(row) for row in self.store.db.execute('SELECT * FROM event ORDER BY sequence')]
        old_baseline=(self.root/'original').read_bytes()
        sequence,runtime=self.install();snapshot=self.snapshot(sequence)
        self.assertEqual(SERVER_COMMIT,runtime['product_commit']);self.assertFalse(runtime['qualified'])
        self.assertEqual(before,[tuple(row) for row in self.store.db.execute('SELECT * FROM event ORDER BY sequence')][:len(before)])
        self.assertEqual(old_baseline,(self.root/'original').read_bytes())
        self.assertEqual(sequence,verified_execution_context(self.store)['runtime_source_sequence'])
        self.unpause();self.store.queue('post-cutover','actor-01','H01','sync',{},0)
        self.assertEqual('post-cutover',self.store.claim({'sync'})['id'])
        for kind in ('action_intent','action_dispatched'):
            payload=json.loads(self.store.db.execute("SELECT payload FROM event WHERE kind=? AND json_extract(payload,'$.action_id')='post-cutover'",(kind,)).fetchone()[0])
            self.assertEqual(self.pins,payload['financial_pins']);self.assertEqual(self.release,payload['execution_release'])
        self.assertEqual(self.release,verified_runtime_source(self.store,sequence,origin_pins=self.pins,
            current_source_sha256=runtime['current_source_sha256'])['execution_release'])
        self.assertIsNone(self.store.get_meta('final_financial_epoch'));self.store.verify_event_chain()
    def test_unqualified_release_sdk_driver_config_database_or_account_change_refuses(self):
        mutations=[('execution_release','deploy_commit','c59a9907373c1dcae8bed96d4cfabcd31148e88b'),
            ('execution_release','product_commit','a'*40),('execution_release','sdk_commit','a'*40),
            ('execution_release','driver_sha256','a'*64),('expected','database','another-database'),
            ('expected','config_sha256',{'captaind':'a'*64,'watchmand':'d'*64})]
        for section,key,value in mutations:
            with self.subTest(section=section,key=key):
                declaration=copy.deepcopy(self.value);declaration['runtime_manifest'][section][key]=value
                with self.assertRaises(ValueError):declare(self.store,declaration)
        self.store.db.execute("UPDATE meta SET value='changed account declaration' WHERE key='conserved_treasury_boundary'")
        with self.assertRaises(ValueError):declare(self.store,self.value)
    def test_new_baseline_hash_pid_restart_or_schema_change_refuses(self):
        declare(self.store,self.value)
        for key,value in [('pid',999),('restart_count',1)]:
            current=copy.deepcopy(self.new);current['daemons']['captaind'][key]=value;self.current.write_text(json.dumps(current))
            with self.assertRaises(ValueError):verify_owned_startup_sources(self.store,self.startup,self.current,expected=self.expected)
        current=copy.deepcopy(self.new);current['canonical_schema']['sha256']='a'*64;current['canonical_schema']['repeat_sha256']='a'*64
        self.current.write_text(json.dumps(current))
        with self.assertRaisesRegex(ValueError,'canonical schema'):verify_owned_startup_sources(self.store,self.startup,self.current,expected=self.expected)
        self.current.write_text(json.dumps(self.new));self.startup.write_text(json.dumps({**self.new,'observed_at':'2000-01-01T00:00:00Z'}))
        with self.assertRaisesRegex(ValueError,'baseline'):verify_owned_startup_sources(self.store,self.startup,self.current,expected=self.expected)
    def test_missing_stale_execution_or_runtime_context_rolls_back_new_queue(self):
        sequence,_=self.install();self.unpause()
        for changes in ({'execution_release':{}},{'observed_at':time.time()-91},{'runtime_source_sequence':self.prior_sequence},
                        {'financial_pins_scope':'actual current product'}):
            self.snapshot(sequence,**changes)
            with self.assertRaises((ValueError,CampaignPaused)):self.store.queue('held','actor-01','H01','sync',{},0)
            self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM action WHERE id='held'").fetchone()[0])
    def test_late_evidence_uses_original_authenticated_intent_not_latest_snapshot(self):
        sequence,_=self.install();self.snapshot(sequence);self.unpause()
        self.store.queue('original','actor-01','H01','sync',{},0);self.store.claim({'sync'})
        self.snapshot(sequence,observed_at=time.time()-120,execution_release={})
        self.store.event('driver_evidence',{'action_id':'original','event':'late_progress'})
        payload=json.loads(self.store.db.execute("SELECT payload FROM event WHERE kind='driver_evidence'").fetchone()[0])
        self.assertEqual(self.release,payload['execution_release']);self.assertEqual(sequence,payload['runtime_source_sequence'])
    def test_queued_before_cutover_refuses_declaration_and_old_intent_cannot_be_replayed(self):
        self.store.add_snapshot({'observed_at':time.time(),'financial_pins':self.pins})
        self.unpause();self.store.queue('old','actor-01','H01','sync',{},0)
        self.store.db.execute("INSERT INTO meta VALUES('paused','cutover')")
        with self.assertRaises(ValueError):declare(self.store,self.value)
        self.store.db.execute("UPDATE action SET state='completed',actual_fee_sat=0 WHERE id='old'")
        row=self.store.db.execute('SELECT sequence,hash FROM event ORDER BY sequence DESC LIMIT 1').fetchone()
        self.value['runtime_manifest']['checkpoint']=dict(row)
        sequence,_=self.install();self.snapshot(sequence);self.unpause()
        self.store.db.execute("UPDATE action SET state='queued' WHERE id='old'")
        with self.assertRaisesRegex(CampaignPaused,'pre-cutover'):self.store.claim({'sync'})
        self.assertEqual('queued',self.store.db.execute("SELECT state FROM action WHERE id='old'").fetchone()[0])
    def test_later_telemetry_keeps_prefix_valid_but_original_prefix_edit_refuses(self):
        self.install();self.store.event('telemetry_only',{'qualified':False})
        self.assertIsNotNone(active_runtime_manifest(self.store))
        self.store.db.execute("UPDATE event SET payload='{}' WHERE sequence=?",(self.prior_sequence,))
        with self.assertRaises(ValueError):active_runtime_manifest(self.store)
    def test_final_campaign_cannot_use_finite_transition(self):
        self.store.db.execute("INSERT INTO meta VALUES('final_financial_epoch','{}')")
        with self.assertRaisesRegex(ValueError,'final campaign'):declare(self.store,self.value)

    def test_missing_or_unverified_original_journey_cannot_cut_over(self):
        value=copy.deepcopy(self.value);value['runtime_manifest']['precutover_source_sequence']=self.prior_sequence
        with self.assertRaisesRegex(ValueError,'finite2k journey'):declare(self.store,value)

    def test_stale_at_claim_keeps_original_queued_and_writes_no_dispatch(self):
        sequence,_=self.install();self.snapshot(sequence);self.unpause()
        self.store.queue('new-held','actor-01','H01','sync',{},0)
        self.snapshot(sequence,observed_at=time.time()-91)
        with self.assertRaises((ValueError,CampaignPaused)):self.store.claim({'sync'})
        self.assertEqual('queued',self.store.db.execute("SELECT state FROM action WHERE id='new-held'").fetchone()[0])
        self.assertIsNone(self.store.db.execute("SELECT 1 FROM event WHERE kind='action_dispatched' AND json_extract(payload,'$.action_id')='new-held'").fetchone())

    def test_changed_original_intent_hash_cannot_supply_late_execution_context(self):
        sequence,_=self.install();self.snapshot(sequence);self.unpause()
        self.store.queue('original','actor-01','H01','sync',{},0);self.store.claim({'sync'})
        self.store.db.execute("UPDATE event SET payload='{}' WHERE kind='action_intent' AND json_extract(payload,'$.action_id')='original'")
        with self.assertRaises((ValueError,CampaignPaused)):self.store.event('driver_evidence',{'action_id':'original','event':'late'})

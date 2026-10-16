"""Synthetic typed-delegation controls; no actual normal activation credit."""
import asyncio
import hashlib
import json
import unittest
from unittest.mock import patch
from simulator import b_normal_profile_adapter as adapter
from simulator import confirmed_scan
from simulator import two_step_normal_factory as factory
from simulator.two_step_capture import SourceCapture
from simulator.two_step_normal import Collector
from simulator.final_campaign import _source_event
from simulator.model import SIGNET_GENESIS,canonical
from simulator.ownership import EvidenceGap
from tests import test_b_native_normal_verifier as fixtures
from tests import test_public_absence as source_fixtures


class FixedProfileControls(unittest.TestCase):
    def test_only_explicit_B_architecture_is_registered(self):
        with patch.object(adapter,'profile',return_value='direct_xpub'):
            self.assertIs(type(adapter.initial_profile(object(),'direct_xpub')),adapter.InitialDirectProfile)
            for other in ('two_step_per_key','direct_per_key',None,{},True):
                with self.subTest(other=other),self.assertRaises(EvidenceGap):adapter.initial_profile(object(),other)
        with patch.object(adapter,'profile',return_value='two_step_per_key'):
            with self.assertRaisesRegex(EvidenceGap,'matching'):adapter.initial_profile(object(),'direct_xpub')
    def test_arbitrary_profile_object_cannot_select_a_reducer(self):
        for constructor,args in [(Collector,(None,1,{})),(SourceCapture,(None,None,1,{},{}))]:
            with self.assertRaisesRegex(EvidenceGap,'arbitrary reducers'):
                constructor(*args,native_profile=object())
    def test_default_A_constructor_has_no_B_profile_or_changed_required_args(self):
        self.assertIsNone(Collector(None,1,{}).native_profile)
        self.assertIsNone(SourceCapture(None,None,1,{},{}).native_profile)
    def test_factory_wrong_profile_refuses_before_any_reader_is_built(self):
        with patch.object(adapter,'profile',return_value='direct_xpub'),patch.object(factory,'TargetTarReader')as target:
            with self.assertRaisesRegex(EvidenceGap,'matching'):
                factory.build_collector(object(),admission_sequence=1,boundary={},capture_configuration={},
                    target_configuration={},member_configuration={},tools={},architecture_profile='direct_per_key')
            target.assert_not_called()
    def test_legacy_runtime_or_caller_complete_cannot_substitute_protected_originals(self):
        for value in ({'complete':True},{'identity':{}},{'expected_raw':'{}'}):
            with self.subTest(value=value),self.assertRaisesRegex(EvidenceGap,'raw runtime'):
                adapter.runtime_from_target({'raw_runtime':canonical(value).encode()},{})
    def test_B_cannot_use_A_first_opening_validation(self):
        async def run():
            return await Collector(None,1,{},native_profile=adapter.InitialDirectProfile()).prepare_opening(
                object(),None,None,{}, {},{}, {},{})
        with self.assertRaisesRegex(ValueError,'strict preserved treasury upgrade'):asyncio.run(run())


class PolicyAdmissionControls(unittest.TestCase):
    def setUp(self):
        from tests.test_two_step_normal import AdmissionTests
        self.fixture=AdmissionTests();self.fixture.setUp()
        self.fixture.collector.native_profile=adapter.InitialDirectProfile()
        self.fixture.value['component_sha256'].update(
            self.fixture.collector.native_profile.component_hashes())

    def tearDown(self):self.fixture.tearDown()

    def test_changed_policy_module_invalidates_existing_source_admission(self):
        f=self.fixture;f.admit()
        self.assertEqual(f.value,f.collector.admission(f.store,f.value['financial_pins']))
        original=adapter.module_hash
        def changed(component):
            return '0'*64 if component is adapter.loaded_native_fee_policy else original(component)
        with patch.object(adapter,'module_hash',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'qualification'):
                f.collector.admission(f.store,f.value['financial_pins'])

    def test_original_admission_without_policy_dependency_is_insufficient(self):
        f=self.fixture
        del f.value['component_sha256']['b_native_fee_policy']
        f.admit()
        with self.assertRaisesRegex(ValueError,'qualification'):
            f.collector.admission(f.store,f.value['financial_pins'])


class SignedBProjectionControls(unittest.TestCase):
    def setUp(self):
        self.h=fixtures.DirectControls();self.h.setUp();self.f=self.h.f;self.store=self.h.store
        self.txid=self.f.confirmed()
        for row in self.store.db.execute('SELECT id,proof FROM owned_coin').fetchall():
            value=json.loads(row['proof']);value['server_pubkey']='02'+'a'*64
            self.store.db.execute('UPDATE owned_coin SET proof=? WHERE id=?',(json.dumps(value),row['id']))
        member={'id':'original-board-backing','kind':'ark_backing','role':'operator',
                'identity':'02'+'a'*64,'descriptors':[]}
        self.store.event('treasury_member_verified',{'member':member,'genesis':SIGNET_GENESIS,
            'financial_pins':source_fixtures.PINS})
        seq=self.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
        self.member={**member,'verification_sequence':seq}
        self.boundary={'id':'finite','pins':source_fixtures.PINS,'genesis':SIGNET_GENESIS,
                      'members':self.f.members+[self.member],'excluded':[]}
        self.frame=asyncio.run(self.f.collect())
        self.scanseq=self.frame['confirmed_scan']['original_scan_sequence']
        _,self.scan=_source_event(self.store,self.scanseq)
        self.context={'current_startup':self.f.current,'metadata':{},
            'descriptor_ranges':self.frame['descriptor_ranges'],'confirmed_scan_sequence':self.scanseq,
            'confirmed_scan_event_hash':self.frame['confirmed_scan']['original_scan_event_hash']}
        raw=json.dumps(self.f.database).encode()
        self.target={'raw_sql':raw,'raw_runtime':b'{}','manifest':{'original_sha256':{'native_sql':hashlib.sha256(raw).hexdigest()}}}
        self.additional={'b_public_context':self.context,
            'manifest':{'b_public_context_sha256':hashlib.sha256(canonical(self.context).encode()).hexdigest()}}
        self.admitted={'binary_sha256':{'captaind':'1'*64,'watchmand':'2'*64},'b_sweep_min_confs':1}
        self.runtime={'execution_release':source_fixtures.PINS,
            'daemons':{name:{'binary_sha256':sha}for name,sha in self.admitted['binary_sha256'].items()}}
        self.observation={'financial_pins':source_fixtures.PINS,'height':self.f.height,'tip_hash':self.f.tip}
        self.profile=adapter.InitialDirectProfile()
        self.initial_profile=adapter.initial.InitialTerminalProfile(journey_sequence=self.f.journey)
    def tearDown(self):self.h.tearDown()
    def project(self):
        before=self.store.db.total_changes
        with self.f.dependencies(),patch.object(adapter,'runtime_from_target',return_value=self.runtime), \
             patch.object(adapter.initial,'InitialTerminalProfile',return_value=self.initial_profile), \
             patch.object(confirmed_scan,'_identity',return_value=self.scan['identity']):
            result=self.profile.decode(self.store,self.f.config,self.f.chain,
                {'identity':{'server_pubkey':'02'+'a'*64}},self.observation,self.boundary,
                self.target,self.additional,self.admitted)
        self.assertEqual(before,self.store.db.total_changes)
        return result
    def test_actual_B_journal_fixture_uses_per_group_confirmed_disposition_not_A_rows(self):
        runtime,database,context=self.project()
        self.assertIn('rows',database);self.assertNotIn('vtxo',database)
        self.assertEqual([],context['pending_liabilities'])
        self.assertEqual(3,len(context['direct']['liabilities']))
        self.assertEqual(19670,sum(v['amount_sat']for v in context['direct']['liabilities']))
        self.assertEqual(({},[]),self.profile.backing(self.member,context))
    def test_unconfirmed_winner_cannot_remove_original_liability(self):
        self.f.transactions[self.txid]['confirmations']=0
        with self.assertRaisesRegex(EvidenceGap,'no sufficiently confirmed'):self.project()
    def test_missing_literal_metadata_source_is_not_a_zero_wallet_proof(self):
        del self.additional['b_public_context']
        with self.assertRaisesRegex(EvidenceGap,'metadata/scan context missing'):self.project()
    def test_mismatched_loaded_configuration_pin_refuses_before_native_reduction(self):
        self.runtime['execution_release']={**source_fixtures.PINS,'configuration_sha256':'0'*64}
        with self.assertRaisesRegex(EvidenceGap,'exact new financial pins'):self.project()
    def test_changed_public_metadata_scan_context_refuses(self):
        self.additional['b_public_context']['metadata']={'fabricated':True}
        with self.assertRaisesRegex(EvidenceGap,'context changed'):self.project()
    def test_changed_native_frontier_original_hash_refuses(self):
        self.target['manifest']['original_sha256']['native_sql']='0'*64
        with self.assertRaisesRegex(EvidenceGap,'frontier hash'):self.project()
    def test_other_backing_member_cannot_claim_original_retirement(self):
        _,_,context=self.project()
        with self.assertRaisesRegex(EvidenceGap,'original terminal'):
            self.profile.backing({**self.member,'id':'another-backing'},context)
    def test_raw_runtime_and_watchman_originals_are_retained_for_independent_reducer(self):
        self.target['raw_watchman_inventory']=b'{"actual":"private watch source"}'
        result=self.profile.originals(self.target,self.additional)
        self.assertIs(result['raw_runtime'],self.target['raw_runtime'])
        self.assertIs(result['raw_watchman_inventory'],self.target['raw_watchman_inventory'])
        self.assertIs(result['b_public_context'],self.context)


if __name__=='__main__':unittest.main()

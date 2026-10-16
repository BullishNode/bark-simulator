"""Real Store/TraceStore/private archive; synthetic native and transport inputs.

No live C source, native signatures, operating readiness or financial credit.
"""
import copy
import hashlib
import time
import unittest
from unittest.mock import patch

from simulator import c_normal_profile_adapter as c
from simulator import c_cohort
from simulator import c_normal_target_source as target_module
from simulator.model import canonical
from simulator.two_step_capture import SourceCapture
from simulator.two_step_normal import Collector
from tests import test_c_normal_target_source as target_fixture
from tests import test_c_premoney


class TargetBoundary(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.x=target_fixture.CheckedTarget();self.x.setUp()
        for function,args,kwargs in self.x._cleanups:self.addCleanup(function,*args,**kwargs)
        self.x._cleanups.clear()
        self.x.store.attach_trace();self.profile=c.DirectPerKeyProfile(self.x.target)
        self.transport_calls=[]

    async def checked(self,mutate=None):
        outer=self
        async def transport(reader,observation):
            outer.transport_calls.append(observation)
            if mutate:mutate()
            return target_module.native.decode_transport(outer.x.path,producer_exit=lambda:0)
        with patch.object(target_module.TargetTarReader,'read',transport),patch.object(target_module,'_context'):
            expected=self.x.target.admission_requirement(self.x.f.observation)
            self.x.store.event('c_normal_target_source_qualified',expected)
            self.x.target.qualification_sequence=self.x.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
            capture=SourceCapture(self.x.reader.read,None,1,{}, {},native_profile=self.profile)
            return await capture.checked_target(self.x.store,self.x.chain,self.x.f.observation)

    async def test_shared_early_hook_checks_one_original_C_cut_without_A_or_B_shape(self):
        before=self.x.store.db.execute("SELECT count(*) FROM event WHERE kind='financial_operating_readiness'").fetchone()[0]
        checked=await self.checked()
        self.assertEqual(1,len(self.transport_calls))
        self.assertEqual('c-native-normal-private-cut',checked['loaded']['manifest']['kind'])
        self.assertNotIn('raw_sql',checked)
        self.assertEqual(before,self.x.store.db.execute("SELECT count(*) FROM event WHERE kind='financial_operating_readiness'").fetchone()[0])
        self.assertFalse(checked['financial_readiness'])

    async def test_policy_constructor_change_during_transport_holds_before_member_use(self):
        with self.assertRaisesRegex(ValueError,'qualification'):
            await self.checked(lambda:self.x.target.configuration.update(policy_sha256='e'*64))
        self.assertEqual(1,len(self.transport_calls))

    async def test_C_checker_cannot_wrap_another_shared_reader(self):
        other=target_module.TargetTarReader(['/other'],self.x.f.root,timeout=25,request_stdin=True,loader=target_module.native.decode_transport)
        with self.assertRaisesRegex(ValueError,'SAME'):
            SourceCapture(other.read,None,1,{}, {},native_profile=self.profile)

    async def test_component_admission_hash_binds_target_static_state(self):
        before=self.profile.component_hashes()
        self.x.target.qualification_sequence+=1
        after=self.profile.component_hashes()
        self.assertNotEqual(before['c_target_configuration_sha256'],after['c_target_configuration_sha256'])
        self.assertEqual(before['c_profile'],after['c_profile'])

    async def test_B_public_context_filename_and_source_kind_remain_exact(self):
        from simulator.b_normal_profile_adapter import InitialDirectProfile
        self.assertEqual('b_public_context',InitialDirectProfile.public_context_key)
        self.assertEqual('b-public-metadata-context.json',InitialDirectProfile.public_context_filename)
        self.assertEqual('b_original_direct_backing',InitialDirectProfile.backing_source_kind)

    async def test_incomplete_C_context_cannot_register_as_normal_money_collector(self):
        with self.assertRaisesRegex(c.EvidenceGap,'arbitrary reducers'):
            Collector(None,1,{},native_profile=self.profile)

    async def test_public_context_replays_actual_original_trace_not_saved_hash_flag(self):
        checked=await self.checked();store=self.x.store;observation=self.x.f.observation
        coverage=[{'desc':'synthetic-public','range':[0,19]}]
        result={'success':True,'height':observation['height'],'bestblock':observation['tip_hash'],'unspents':[],'total_amount':'0'}
        raw=canonical({'result':result,'error':None}).encode()
        reference=store.trace_capture('chain.rpc',{'method':'scantxoutset','params':['start',coverage],'error':None,'result':result},raw=raw)
        from simulator.trace import partition_paths,readonly
        path=next(p for p in partition_paths(store.trace.root)if p.name==reference['partition'])
        db=readonly(path)
        try:original_at=db.execute('SELECT utc FROM trace WHERE seq=?',(reference['seq'],)).fetchone()[0]
        finally:db.close()
        scan={'identity':{'financial_pins':observation['financial_pins'],'boundary_id':observation.get('boundary_id')},
            'height':observation['height'],'tip_hash':observation['tip_hash'],'descriptor_ranges':coverage,
            'result':result,'raw_trace':reference,'raw_response_sha256':hashlib.sha256(raw).hexdigest(),'observed_at':original_at}
        store.event('confirmed_descriptor_scan_verified',scan)
        event=dict(store.db.execute('SELECT * FROM event ORDER BY sequence DESC LIMIT 1').fetchone())
        context={'metadata':{},'descriptor_ranges':coverage,'confirmed_scan_sequence':event['sequence'],
            'confirmed_scan_event_hash':event['hash'],'observed_at':time.time()}
        from simulator.final_campaign import _source_event
        _,original_admission=_source_event(store,self.x.target.qualification_sequence)
        with patch.object(c,'_context'),patch.object(self.x.target,'admission',return_value=original_admission):
            bound=self.profile.bind_member_context(store,observation,checked,context)
            self.assertEqual(checked['original_private_source_references'],bound['target_original_private_source_references'])
            for key,value in [('confirmed_scan_event_hash','0'*64),('descriptor_ranges',[]),('observed_at',observation['started_at']-1)]:
                bad={**context,key:value}
                with self.subTest(key=key),self.assertRaises(c.EvidenceGap):self.profile.bind_member_context(store,observation,checked,bad)
            # A complete bit/result hash is no substitute for the original raw
            # TraceStore entry. The append-only lookup must find the exact seq.
            scan['raw_trace']={**reference,'seq':reference['seq']+100}
            store.event('confirmed_descriptor_scan_verified',scan)
            event=dict(store.db.execute('SELECT * FROM event ORDER BY sequence DESC LIMIT 1').fetchone())
            bad={**context,'confirmed_scan_sequence':event['sequence'],'confirmed_scan_event_hash':event['hash']}
            with self.assertRaisesRegex(ValueError,'raw trace'):self.profile.bind_member_context(store,observation,checked,bad)


class PremoneyOpening(unittest.TestCase):
    def setUp(self):
        case=test_c_premoney.PremoneyControls();case.setUp();self.addCleanup(case.doCleanups)
        self.case=case;self.store=case.store
        case.verify();c_cohort.seal_unfunded(case.store,case.config,case.chain)
        c_cohort.declare_profile(case.store,case.profile());case.complete_new_identity('actor-02')
        c_cohort.declare_enrollment(case.store,case.config,'initial',identifier='extra10',
            actions={actor:'c_create_'+actor[-2:]for actor in c_cohort.INITIAL[2:]})
        for actor in c_cohort.INITIAL[2:]:case.complete_new_identity(actor)
        self.boundary={'id':'c-treasury','pins':case.pins}

    def test_true_first_opening_needs_no_pilot_Board_Ark_or_closed_A_exploratory_work(self):
        before=[tuple(row)for row in self.store.db.execute('SELECT * FROM action ORDER BY id')]
        events=self.store.db.execute('SELECT count(*) FROM event').fetchone()[0]
        value=c.initial_history(self.store,self.boundary)
        self.assertEqual([f'c_create_{i:02}'for i in range(1,13)],value['action_ids'])
        self.assertEqual(int(self.store.get_meta('fee_budget_sat')),value['original_fee_budget_sat'])
        self.assertEqual(10000,value['original_fee_budget_sat']) # preserve original fixture budget, never reset to declared60k
        self.assertEqual(900000,value['opening_physical_sat'])
        self.assertEqual(60000,value['ordinary_budget_sat']);self.assertEqual(40000,value['urgent_reserve_sat'])
        self.assertEqual(before,[tuple(row)for row in self.store.db.execute('SELECT * FROM action ORDER BY id')])
        self.assertEqual(events,self.store.db.execute('SELECT count(*) FROM event').fetchone()[0])
        self.assertIsNone(self.store.get_meta('preserved_financial_opening'))

    def test_NULL_fee_reservation_or_wrong_boundary_cannot_enter_first_opening(self):
        for column,value in (('actual_fee_sat',None),('fee_reservation_sat',1)):
            self.store.db.execute('UPDATE action SET '+column+'=? WHERE id=?',(value,'c_create_12'))
            with self.subTest(column=column),self.assertRaises(ValueError):c.initial_history(self.store,self.boundary)
            self.store.db.execute('UPDATE action SET '+column+'=0 WHERE id=?',('c_create_12',))
        for changed in ({**self.boundary,'id':'other'},{**self.boundary,'pins':{**self.case.pins,'sdk_commit':'f'*40}}):
            with self.assertRaises(c.EvidenceGap):c.initial_history(self.store,changed)

    def test_missing_real_dispatch_or_extra_action_cannot_become_initial12_opening(self):
        row=self.store.db.execute("SELECT * FROM event WHERE kind='action_dispatched' AND json_extract(payload,'$.action_id')='c_create_12'").fetchone()
        self.store.db.execute('DELETE FROM event WHERE sequence=?',(row['sequence'],))
        with self.assertRaises(ValueError):c.initial_history(self.store,self.boundary)

    def test_even_confirmed_funding_or_prior_cost_requires_preserved_funded_path(self):
        self.store.db.execute('CREATE TABLE funding_batch(state TEXT)')
        self.store.db.execute("INSERT INTO funding_batch VALUES ('confirmed')")
        with self.assertRaisesRegex(ValueError,'funded path'):c.initial_history(self.store,self.boundary)
        self.store.db.execute('DELETE FROM funding_batch')
        self.store.event('financial_cost_verified',{'amount_msat':1})
        with self.assertRaisesRegex(ValueError,'financial history'):c.initial_history(self.store,self.boundary)


if __name__=='__main__':unittest.main()

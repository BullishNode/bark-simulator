"""Real strict private cut/member/current reducers; synthetic tool authority.

The empty native-body positive executes no native decoder. No native/current
economic qualification, creates or financial readiness follows from these tests.
"""
import copy
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from simulator import c_normal_current_join as c
from simulator.model import SIGNET_GENESIS
from tests import test_c_normal_member_join as members_fixture
from tests import test_c_private_normal_cut as cut_fixture
from tests import test_c_native_body_proof as tool_fixture
from tests.test_c_native_fee_sources import KEY


class CurrentJoin(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.f=members_fixture.Members();self.f.setUp()
        for function,args,kwargs in self.f._cleanups:self.addCleanup(function,*args,**kwargs)
        self.f._cleanups.clear();self.store=self.f.store;self.observation=self.f.observation
        self.cut=cut_fixture.CombinedNativeCut();self.cut.setUp();self.addCleanup(self.cut.doCleanups)
        self.cut.fixture.observation=copy.deepcopy(self.observation)
        self.cut.fixture.chain={'genesis':SIGNET_GENESIS,'height':self.observation['height'],
            'tip_hash':self.observation['tip_hash'],'ibd':False}
        raw=self.cut.capture(self.cut.pg());path=self.cut.fixture.root/'current-empty.tar'
        loaded=self.cut.load(raw,path)
        self.checked={'kind':'c-checked-native-target-source','source_observation':copy.deepcopy(self.observation),
            'loaded':loaded,'original_private_source_references':loaded['original_private_source_references']}
        self.f.f.f.checked=self.checked
        self.tool=tool_fixture.NativeBodyProof();self.tool.setUp();self.addCleanup(self.tool.doCleanups)
        self.binding=c.CurrentBinding(self.tool.tool,self.tool.identity,1)
        self.store.event('c_normal_current_source_qualified',c.requirement(self.binding,self.observation['financial_pins']))
        self.binding=c.CurrentBinding(self.tool.tool,self.tool.identity,self.sequence())

    def sequence(self):return self.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
    def count(self,kind):return self.store.db.execute('SELECT count(*)FROM event WHERE kind=?',(kind,)).fetchone()[0]
    async def collect(self,members=None):
        members=await self.f.collect() if members is None else members
        with patch.object(c,'_context'),patch('simulator.c_normal_source._context'):
            return c.collect(self.store,SimpleNamespace(expected_server_pubkey=KEY),self.f.core,self.observation,
                boundary=self.f.boundary,checked=self.checked,members=members,binding=self.binding)

    async def test_actual_empty_private_cut_and_member_sources_still_no_readiness(self):
        result=await self.collect();safe=result['safe']
        self.assertEqual([],result['supported_retained_customer_rights'])
        self.assertEqual([],safe['current_source_audit']['unresolved'])
        self.assertFalse(safe['complete']);self.assertFalse(safe['financial_readiness'])
        self.assertEqual(1,self.count(c.KIND));self.assertEqual(0,self.count('financial_operating_readiness'))
        self.assertEqual([],result['private_current_audit']['private_path_originals']['paths'])

    async def test_wrong_SDK_binding_refuses_even_for_empty_native_body_set(self):
        members=await self.f.collect();self.binding.tool_identity['sdk_component_commit']='e'*40
        self.store.event('c_normal_current_source_qualified',c.requirement(self.binding,self.observation['financial_pins']))
        self.binding=c.CurrentBinding(self.binding.tool,self.binding.tool_identity,self.sequence())
        with self.assertRaisesRegex(ValueError,'proof source/component/runtime'):
            await self.collect(members)
        self.assertEqual(0,self.count(c.KIND))

    async def test_changed_qualified_runtime_component_refuses_before_native_audit(self):
        members=await self.f.collect();component=self.tool.runtime/'native-full-proof'
        component.chmod(0o600);component.write_bytes(b'changed');component.chmod(0o500)
        with self.assertRaisesRegex(ValueError,'runtime component differs'):
            await self.collect(members)
        self.assertEqual(0,self.count(c.KIND))

    async def test_wrong_member_observation_cannot_relabel_original_target(self):
        members=await self.f.collect();members['safe']['source_observation']['id']='f'*32
        with self.assertRaises(c.EvidenceGap):await self.collect(members)
        self.assertEqual(0,self.count(c.KIND))

    async def test_unobserved_retained_right_is_diagnostic_then_hold_never_zero(self):
        members=await self.f.collect();key='02'+'9'*64
        self.store.actor('actor-01','customer')
        self.store.db.execute('INSERT INTO owner_key VALUES(?,?,?,?)',(key,'actor-01','synthetic-mailbox','{}'))
        self.store.db.execute('INSERT INTO owned_coin VALUES(?,?,?,?,?,?)',('f'*64+':0',key,1000,'e'*64,'aa','{}'))
        with self.assertRaisesRegex(c.EvidenceGap,'complete current'):
            await self.collect(members)
        self.assertEqual(1,self.count(c.KIND))
        event,audit=c._source_event(self.store,self.sequence())
        self.assertEqual(c.KIND,event['kind'])
        self.assertTrue(audit['current_source_audit']['unresolved'])
        self.assertFalse(audit['financial_readiness'])
        self.assertEqual(0,self.count('financial_operating_readiness'))

    async def test_new_joint_source_cannot_reuse_old_empty_current_audit(self):
        members=await self.f.collect()
        self.checked['loaded']['manifest']['schema_version']=2
        self.checked['loaded']['manifest']['kind']='c-native-joint-normal-private-cut'
        with self.assertRaisesRegex(c.EvidenceGap,'actual native fee/opening/urgent'):
            await self.collect(members)
        self.assertEqual(0,self.count(c.KIND))

    async def test_V4_actual_current_caller_runs_byte_subgate_then_explicit_financial_hold(self):
        from simulator import c_native_audit_tool as audit
        members=await self.f.collect();self.checked['loaded']['manifest']['schema_version']=4
        audit_binding=audit.AuditBinding({}, {}, {}, 1)
        with patch.object(audit,'collect',return_value={'safe':{'complete':False,'qualified':False,'financial_readiness':False}})as execute:
            with patch.object(c,'_context'),self.assertRaisesRegex(c.EvidenceGap,'legacy DirectRecord/allocation, Board-root'):
                c.collect(self.store,SimpleNamespace(expected_server_pubkey=KEY),self.f.core,self.observation,
                    boundary=self.f.boundary,checked=self.checked,members=members,binding=self.binding,audit_binding=audit_binding)
            execute.assert_called_once()
            self.assertIs(self.checked,execute.call_args.kwargs['checked'])
        self.assertEqual(0,self.count('financial_operating_readiness'))
        self.assertEqual(0,self.count(c.KIND))

    async def test_missing_tool_binding_is_specific_hold_in_actual_profile_caller(self):
        from simulator.c_normal_profile_adapter import DirectPerKeyProfile
        profile=DirectPerKeyProfile.__new__(DirectPerKeyProfile);profile.current=None
        with self.assertRaisesRegex(c.EvidenceGap,'not installed'):
            profile.collect_current(None,None,None,None,None,None,None)


if __name__=='__main__':unittest.main()

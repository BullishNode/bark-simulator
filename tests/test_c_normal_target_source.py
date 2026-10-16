"""Actual private archive/context loader; synthetic transport exit/Core/admission."""
import copy
import unittest
from pathlib import Path
from unittest.mock import patch
from simulator import c_normal_target_source as c
from simulator.store import Store
from simulator.model import SIGNET_GENESIS
from tests import test_c_private_normal_cut as fixture

class CheckedTarget(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.x=fixture.CombinedNativeCut();self.x.setUp();self.addCleanup(self.x.doCleanups)
        self.f=self.x.fixture;self.cut=self.x.capture(self.x.pg());self.path=self.f.root/'target-source.tar'
        self.safe=c.native.write_private_package(self.cut,self.path)
        self.store=Store(self.f.root/'journal','synthetic-C',architecture_profile='direct_per_key');self.addCleanup(self.store.close)
        self.reader=c.TargetTarReader(['/synthetic/fixed-target'],self.f.root,timeout=25,request_stdin=True,loader=c.native.decode_transport)
        self.configuration={'source_sha256':self.cut['source_sha256'],'body_source_sha256':self.cut['body_source_sha256'],
          'history_identity':self.f.expected,'policy_sha256':self.cut['policy_sha256'],'limits':self.f.limits,'binding':self.f.binding}
        self.target=c.CheckedTargetReader(self.reader,self.f.fixed,self.configuration,1);self.calls=[];self.exit=0;outer=self
        class Chain:
            def identity(self):return {'chain':'signet','blocks':outer.f.chain['height'],'bestblockhash':outer.f.chain['tip_hash'],'initialblockdownload':False}
            def call(self,method,*args):
                if method=='getblockhash'and args==(0,):return SIGNET_GENESIS
                raise AssertionError('no wallet/financial calls')
        self.chain=Chain()
        self.requirement=self.target.admission_requirement(self.f.observation)
        self.store.event('c_normal_target_source_qualified',self.requirement)
    async def collect(self):
        outer=self
        async def transport(actual_reader,observation):
            outer.calls.append(observation)
            return c.native.decode_transport(outer.path,producer_exit=lambda:outer.exit)
        with patch.object(c.TargetTarReader,'read',transport),patch.object(c,'_context'):
            # Class-code hash changes in this synthetic transport test; bind the
            # literal test transport file hash explicitly, no production credit.
            expected=self.target.admission_requirement(self.f.observation)
            self.store.event('c_normal_target_source_qualified',expected);self.target.qualification_sequence=self.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
            if self.mutate:self.mutate()
            return await self.target.read(self.store,self.chain,self.f.observation)
    mutate=None
    async def test_actual_C_manifest_stays_C_after_whole_context_verification(self):
        result=await self.collect();loaded=result['loaded']
        self.assertEqual('c-native-normal-private-cut',loaded['manifest']['kind']);self.assertEqual(self.f.observation,loaded['manifest']['source_observation'])
        self.assertFalse(result['financial_readiness']);self.assertEqual(1,len(self.calls));self.assertNotIn('raw_sql',result)
        self.assertEqual(loaded['private_pg']['snapshot'],loaded['fee_cut']['database_snapshot'])
    async def test_missing_wrong_qualification_or_mutated_constructor_refuses_before_transport(self):
        self.mutate=lambda:self.target.configuration.update(policy_sha256='a'*64)
        with self.assertRaisesRegex(ValueError,'qualification'):await self.collect()
        self.assertEqual([],self.calls)
    async def test_original_source_observation_or_history_mismatch_cannot_be_relabelled(self):
        self.f.observation={**self.f.observation,'id':'f'*32}
        with self.assertRaises(ValueError):await self.collect()
        self.assertEqual(1,len(self.calls))
    async def test_failed_actual_producer_exit_never_becomes_source(self):
        self.exit=1
        with self.assertRaises(ValueError):await self.collect()
    async def test_reply_manifest_cannot_select_policy_or_source_program(self):
        self.configuration['source_sha256']='d'*64
        self.target.configuration=copy.deepcopy(self.configuration)
        with self.assertRaises(ValueError):await self.collect()
    async def test_changed_binding_schema_and_unadmitted_reader_override_hold(self):
        self.mutate=lambda:self.target.configuration['binding'].update(schema_sha256='b'*64)
        with self.assertRaises(ValueError):await self.collect()
        self.assertEqual([],self.calls)
        self.mutate=None;self.reader.extra_unknown_state='refuse'
        with self.assertRaisesRegex(ValueError,'override'):await self.collect()
    async def test_only_shared_stateless_original_transport_loader_accepted(self):
        reader=c.TargetTarReader(['/synthetic/fixed'],self.f.root,timeout=25)
        with self.assertRaises(ValueError):c.CheckedTargetReader(reader,self.f.fixed,self.configuration,1)

    async def test_mutated_loader_cannot_execute_before_full_expected_context_checks(self):
        self.mutate=lambda:setattr(self.reader,'loader',lambda *args,**kwargs:None)
        with self.assertRaisesRegex(ValueError,'loader changed'):await self.collect()
        self.assertEqual([],self.calls)

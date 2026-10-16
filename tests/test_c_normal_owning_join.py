"""Actual owning reducer/TraceStore; synthetic RPC/runtime/TARGET authority.

No live source, native process, complete normal treasury or readiness credit.
"""
import copy
import unittest
from types import SimpleNamespace
from unittest.mock import patch,AsyncMock

from simulator import c_normal_owning_join as c
from simulator import c_normal_runtime_source as runtime_source
from simulator.model import canonical,SIGNET_GENESIS
from tests import test_c_owning_wallet_source as fixture


class OwningJoin(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.f=fixture.OwningSources();self.f.setUp()
        # A manually instantiated IsolatedAsyncioTestCase has no runner. Its
        # doCleanups silently records cleanup errors instead of stopping mocks.
        # Run the registered callbacks on THIS actual running test instead.
        for function,args,kwargs in self.f._cleanups:self.addCleanup(function,*args,**kwargs)
        self.f._cleanups.clear()
        self.store=self.f.store;self.observation=self.f.observation
        self.source={'kind':'owned_native_startup_source','architecture_profile':'direct_per_key',
            'runtime_transport':'systemd','product_commit':self.observation['financial_pins']['product_commit'],
            'schema_sha256':self.observation['financial_pins']['schema_sha256'],
            'daemons':copy.deepcopy(self.f.runtime['daemons']),
            **{o+'_inventory':copy.deepcopy(self.f.responses[o])for o in c.owning.OWNERS}}
        path=self.f.root/'private-current-runtime.json';raw=(canonical(self.source)+'\n').encode();path.write_bytes(raw);path.chmod(0o600)
        self.f.runtime['current_source_sha256']=runtime_source.digest(raw)
        self.store.event('owned_runtime_configuration_verified',self.f.runtime);seq=self.f.sequence()
        from simulator.final_campaign import _source_event
        event,_=_source_event(self.store,seq)
        owners={o:{'available':True,'source':copy.deepcopy(self.f.responses[o])}for o in c.owning.OWNERS}
        literal={'native_runtime':self.source['daemons'],'runtime_wallet_inventory':{'frames':owners}}
        original=canonical(literal).encode()
        ref=self.store.trace_capture(runtime_source.RAW_KIND,{'request':{'kind':'financial_readiness'},
            'source_observation':self.observation,'exit_code':0,'truncated':False,'bytes':len(original)},raw=original)
        safe={'source_observation':copy.deepcopy(self.observation),'financial_pins':self.observation['financial_pins'],
            'runtime_source_sequence':seq,'runtime_source_event_hash':event['hash'],
            'current_startup_path':str(path),'current_source_sha256':runtime_source.digest(raw),
            'qualification_sequence':1,'original_trace':ref,'original_response_sha256':runtime_source.digest(original),
            'complete':False,'qualified':False,'financial_readiness':False}
        self.store.event(runtime_source.KIND,safe);safe['source_sequence']=self.f.sequence()
        self.runtime={'safe':safe,'private_runtime_source':self.source,'private_owning_frames':owners}
        self.checked={'kind':'c-checked-native-target-source','source_observation':copy.deepcopy(self.observation),
            'loaded':{'manifest':{'source_observation':copy.deepcopy(self.observation),'financial_pins':self.observation['financial_pins']}},
            'original_private_source_references':{'archive_sha256':'1'*64,'manifest_sha256':'2'*64}}
        self.binding=c.OwningBinding(self.f.reader,self.f.qualification_sequence)
        self.f.runtime_sequence=seq
        self.handle=patch('simulator.runtime_startup._read',return_value=(self.source,safe['current_source_sha256']))
        self.handle.start();self.addCleanup(self.handle.stop)

    async def collect(self):
        with patch.object(c,'_context'),patch.object(c.owning,'text_command',side_effect=self.f.command):
            return await c.collect(self.store,SimpleNamespace(network='signet',expected_genesis=SIGNET_GENESIS),
                self.f.chain,self.observation,boundary=self.f.boundary,checked=self.checked,runtime=self.runtime,binding=self.binding)

    def count(self,kind):return self.store.db.execute('SELECT count(*)FROM event WHERE kind=?',(kind,)).fetchone()[0]

    async def test_actual_owning_source_reducers_join_new_events_to_original_runtime_and_target(self):
        result=await self.collect();safe=result['safe']
        self.assertEqual(4,len(self.f.calls));self.assertEqual(1,self.count(c.KIND))
        self.assertEqual(self.checked['original_private_source_references'],safe['target_original_private_source_references'])
        self.assertEqual(self.runtime['safe']['runtime_source_sequence'],safe['runtime_source_sequence'])
        self.assertEqual({'rounds','watchman'},set(safe['inventory_sequences']))
        self.assertFalse(safe['financial_readiness']);self.assertFalse(safe['complete'])
        self.assertEqual(0,self.count('financial_operating_readiness'))
        self.assertEqual(100000000,result['private_owning_component']['actual_owning_wallet_assets']['total_msat'])

    async def test_missing_or_boolean_original_sequence_is_never_an_actual_component(self):
        for value in (None,True,0):
            self.runtime['safe']['source_sequence']=value
            with self.subTest(value=value),self.assertRaises(c.EvidenceGap):await self.collect()
        self.assertEqual([],self.f.calls)

    async def test_runtime_or_target_wrong_observation_refuses_before_owning_rpc(self):
        self.runtime['safe']['source_observation']['id']='f'*32
        with self.assertRaises(c.EvidenceGap):await self.collect()
        self.assertEqual([],self.f.calls)
        self.runtime['safe']['source_observation']=copy.deepcopy(self.observation)
        self.checked['loaded']['manifest']['financial_pins']={**self.observation['financial_pins'],'sdk_commit':'f'*40}
        with self.assertRaises(c.EvidenceGap):await self.collect()
        self.assertEqual([],self.f.calls)

    async def test_changed_wallet_between_runtime_and_stable_independent_scan_is_not_relabelled(self):
        self.f.responses['watchman']['watchman']['last_revealed_index']=2
        with self.assertRaisesRegex(c.EvidenceGap,'between actual runtime'):await self.collect()
        self.assertEqual(1,self.count(c.owning.KIND));self.assertEqual(0,self.count(c.KIND))
        self.assertEqual(0,self.count('financial_operating_readiness'))

    async def test_changed_private_runtime_or_supplied_owning_copy_refuses_before_rpc(self):
        self.runtime['private_owning_frames']['rounds']['source']['rounds']['last_revealed_index']=10
        with self.assertRaisesRegex(c.EvidenceGap,'originals differ'):await self.collect()
        self.assertEqual([],self.f.calls)

    async def test_missing_descriptor_output_is_still_an_effective_source_hold(self):
        self.f.extra_scan=True
        with self.assertRaisesRegex(ValueError,'exhaustive confirmed'):await self.collect()
        self.assertEqual(0,self.count(c.KIND))

    async def test_owning_reader_subclass_or_instance_override_cannot_change_qualified_source(self):
        self.f.reader.read=lambda *args,**kwargs:None
        with self.assertRaisesRegex(c.EvidenceGap,'fixed C owning'):await self.collect()
        self.assertEqual([],self.f.calls)

    async def test_cached_component_sequence_cannot_satisfy_new_collection(self):
        first=await self.collect();cached=first['private_owning_component']
        with patch.object(c.owning,'collect',new=AsyncMock(return_value=cached)):
            with self.assertRaisesRegex(c.EvidenceGap,'this invocation'):await self.collect()
        self.assertEqual(1,self.count(c.KIND))

    async def test_original_trace_from_another_owner_or_phase_cannot_be_swapped(self):
        first=await self.collect();component=copy.deepcopy(first['private_owning_component'])
        # Preserve original event verification; direct replay of a mismatched
        # reference has to refuse independently of a saved source hash.
        with self.assertRaisesRegex(ValueError,'scope'):
            c.owning.replay_original(self.store,component['original_traces']['before:rounds'],
                owner='watchman',phase='before',observation=self.observation)


if __name__=='__main__':unittest.main()

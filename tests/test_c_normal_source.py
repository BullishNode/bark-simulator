"""Actual Store/event binding controls; native financial producers are doubles."""
import copy
import time
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from simulator import c_normal_source as c, c_cohort, c_pilot
from simulator.architecture import DIRECT_PER_KEY
from simulator.model import canonical
from simulator.store import Store
from tests.test_c_pilot import pilot


class BindingControls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=Store(Path(self.tmp.name),'synthetic',60000,architecture_profile=DIRECT_PER_KEY)
        self.addCleanup(self.store.close)
        self.store.db.execute("INSERT OR REPLACE INTO meta VALUES('paused','test')")
        self.pilot=pilot();c_pilot.declare(self.store,self.pilot)
        self.observation={'id':'a'*32,'started_at':time.time(),'architecture_profile':DIRECT_PER_KEY,
            'financial_pins':self.pilot['pins'],'boundary_id':self.pilot['boundary_id'],'height':100,'tip_hash':'b'*64}
        self.source={key:copy.deepcopy(self.observation[key]) for key in ('financial_pins','boundary_id','height','tip_hash')}
        self.source['observed_at']=time.time()
        self.receipt={**copy.deepcopy(self.source),'complete':True,'pool_ready':False,'channel_route_ready':False}

    def test_exact_binding_and_none_preserves_legacy(self):
        old=copy.deepcopy(self.receipt)
        c.bind_source_observation(self.store,self.receipt,self.source,None)
        self.assertEqual(old,self.receipt)
        c.bind_source_observation(self.store,self.receipt,self.source,self.observation)
        self.observation['financial_pins']['sdk_commit']='c'*40
        self.assertEqual(old['financial_pins'],self.receipt['source_observation']['financial_pins'])

    def test_changed_source_context_predating_observation_or_broader_scope_refuses(self):
        for field,value in [('financial_pins',{}),('boundary_id','foreign'),('height',101),('tip_hash','c'*64),
                            ('observed_at',self.observation['started_at']-1)]:
            with self.subTest(field=field),self.assertRaises(ValueError):
                c.bind_source_observation(self.store,copy.deepcopy(self.receipt),{**self.source,field:value},self.observation)
        for changed in ({'complete':False},{'pool_ready':True},{'channel_route_ready':True}):
            with self.subTest(changed=changed),self.assertRaises(ValueError):
                c.bind_source_observation(self.store,{**self.receipt,**changed},self.source,self.observation)

    def test_reuse_invalid_id_bool_stale_and_foreign_profile_refuse(self):
        c.bind_source_observation(self.store,self.receipt,self.source,self.observation)
        self.store.event('financial_operating_readiness',self.receipt)
        with self.assertRaisesRegex(ValueError,'already emitted'):
            c.bind_source_observation(self.store,copy.deepcopy(self.receipt),self.source,self.observation)
        for change in ({'id':'wrong'},{'id':'c'*32,'started_at':time.time()-91},
                       {'id':'c'*32,'height':True},{'architecture_profile':'direct_xpub'},{'extra':True}):
            with self.subTest(change=change),self.assertRaises(ValueError):
                c.bind_source_observation(self.store,copy.deepcopy(self.receipt),self.source,{**self.observation,**change})

    def test_missing_runtime_dependency_unsupported_phase_and_relative_paths_hold(self):
        rpc=SimpleNamespace(call=lambda *a:None)
        for binding in (c.Initial12SourceBinding('ordinary','/private/runtime'),c.Initial12SourceBinding('cash','relative')):
            with self.assertRaises(ValueError):c.collector(binding,rpc,runtime_source_collector=lambda *a:1)
        with self.assertRaises(ValueError):
            c.collector(c.Initial12SourceBinding('cash','/private/runtime'),rpc,runtime_source_collector=None)


class AdapterControls(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.base=BindingControls();self.base.setUp();self.addCleanup(self.base.doCleanups)
        self.store=self.base.store;self.store.attach_trace();self.observation=self.base.observation
        self.pins=self.base.pilot['pins'];self.config=SimpleNamespace(architecture_profile=DIRECT_PER_KEY,validate_identity=lambda value:None)
        self.snapshot={key:copy.deepcopy(self.observation[key]) for key in ('financial_pins','height','tip_hash')}
        self.runtime_sha='c'*64
        policy={'opening_kind':'unfunded_initial12','customers':set(c_cohort.INITIAL)}
        for target,value in [('simulator.identity_bootstrap.declaration',{'declaration':{'actors':['actor-01','actor-02']}}),
            ('simulator.identity_bootstrap._context',{}),('simulator.c_cohort.prospective_funding_policy',policy),
            ('simulator.c_cohort.initial_identity_sources',{'actors':list(c_cohort.INITIAL)}),
            ('simulator.c_cohort.historical_initial_identity_sources',{'actors':list(c_cohort.INITIAL)}),
            ('simulator.runtime_startup._read',({},self.runtime_sha))]:
            handle=patch(target,return_value=value);handle.start();self.addCleanup(handle.stop)
        self.old_source=None;self.omit_member=False

    def sequence(self):return self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
    async def runtime(self,*args):
        self.store.event('owned_runtime_configuration_verified',{'loaded_configuration_identity_verified':True,
            'current_source_sha256':self.runtime_sha,'product_commit':self.pins['product_commit'],
            'schema_sha256':self.pins['schema_sha256'],'observed_at':time.time()})
        return self.sequence()
    async def source(self,*args,**kwargs):
        if self.old_source is not None:return self.old_source
        frame={**self.base.source,'observed_at':time.time(),'members':[{'id':str(i)} for i in range(14 if self.omit_member else 15)],
            'actors':list(c_cohort.INITIAL),'customer_source_sequences':{a:i+1 for i,a in enumerate(c_cohort.INITIAL)}}
        self.store.event(self.kind,frame)
        return {'source_sequence':self.sequence(),'source':frame}
    def reduce(self,*args,**kwargs):
        sequence=kwargs.get('source_sequence',args[3] if len(args)>3 else None)
        _,source=c._source_event(self.store,sequence)
        receipt={**source,'observed_at':time.time(),'complete':True,'pool_ready':False,'channel_route_ready':False}
        c.bind_source_observation(self.store,receipt,source,kwargs['source_observation'])
        self.store.event('financial_operating_readiness',receipt)
        return {'operating_readiness_sequence':self.sequence(),**receipt}
    async def invoke(self,phase='initial_funding',runtime=None):
        module='finite_funding_readiness' if phase=='initial_funding' else 'fresh_cash_readiness'
        self.kind='finite_initial_funding_sources_verified' if phase=='initial_funding' else 'finite_fresh_cash_sources_verified'
        collect_name='collect_initial_funding_sources' if phase=='initial_funding' else 'collect_fresh_cash_sources'
        reduce_name='record_initial_funding_readiness' if phase=='initial_funding' else 'record_fresh_cash_readiness'
        adapter=c.collector(c.Initial12SourceBinding(phase,'/private/current-runtime'),SimpleNamespace(call=lambda *a:None),
                            runtime_source_collector=self.runtime if runtime is None else runtime)
        with patch('simulator.'+module+'.'+collect_name,side_effect=self.source) as collect, \
             patch('simulator.'+module+'.'+reduce_name,side_effect=self.reduce) as reduce:
            result=await adapter(self.store,self.config,object(),self.snapshot,self.observation)
            self.assertEqual(1,collect.call_count);self.assertEqual(1,reduce.call_count)
            return result

    async def test_new_full_initial12_source_and_readiness_bound_to_each_invocation(self):
        first=await self.invoke()
        _,proof=c._source_event(self.store,first)
        self.assertEqual(self.observation,proof['source_observation'])
        with self.assertRaisesRegex(ValueError,'already emitted'):await self.invoke()
        self.observation={**self.observation,'id':'d'*32,'started_at':time.time()}
        self.assertGreater(await self.invoke(),first)
        self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM action').fetchone()[0])

    async def test_cash_uses_same_new_source_and_original_invocation_contract(self):
        sequence=await self.invoke('cash');_,proof=c._source_event(self.store,sequence)
        self.assertEqual(self.observation,proof['source_observation'])

    async def test_old_source_newly_wrapped_missing_member_and_wrong_snapshot_refuse(self):
        self.kind='finite_initial_funding_sources_verified';self.old_source=await self.source()
        self.observation={**self.observation,'started_at':time.time()}
        with self.assertRaisesRegex(ValueError,'new original source'):await self.invoke()
        self.old_source=None;self.omit_member=True
        with self.assertRaisesRegex(ValueError,'omitted a member'):await self.invoke()
        self.omit_member=False;self.snapshot['height']=101
        with self.assertRaisesRegex(ValueError,'snapshot context'):await self.invoke()
        self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM event WHERE kind='financial_operating_readiness'").fetchone()[0])

    async def test_old_runtime_and_mutated_invocation_refuse_before_financial_source(self):
        old=await self.runtime()
        self.observation={**self.observation,'started_at':time.time()}
        with self.assertRaisesRegex(ValueError,'new actual loaded'):await self.invoke(runtime=lambda *args:old)
        async def changing(*args):
            args[-1]['height']=101
            return await self.runtime()
        with self.assertRaisesRegex(ValueError,'changed original observation'):await self.invoke(runtime=changing)
        self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM event WHERE kind='financial_operating_readiness'").fetchone()[0])

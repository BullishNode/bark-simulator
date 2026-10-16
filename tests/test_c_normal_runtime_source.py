"""Actual bounded subprocess + Store/TraceStore/C verifier, synthetic systemd.

No SSH, SDK open, real services, actual host identity or financial qualification.
"""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from simulator import c_normal_runtime_source as c,c_pilot
from simulator.architecture import DIRECT_PER_KEY
from simulator.model import SIGNET_GENESIS,canonical
from simulator.store import Store
from tests import test_c_pilot


class RuntimeProducer(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.wallets=self.root/'wallets';self.wallets.mkdir(mode=0o700)
        self.directory=self.root/'sources';self.directory.mkdir(mode=0o700)
        schema=self.root/'schema.sql';schema.write_bytes(b'-- synthetic source-bound schema only\n');schema.chmod(0o600)
        self.pins={**test_c_pilot.PINS,'schema_sha256':self.sha(schema)}
        self.store=Store(self.root/'state','synthetic-C',60000,architecture_profile=DIRECT_PER_KEY)
        self.store.attach_trace();self.addCleanup(self.store.close)
        self.store.db.execute("INSERT OR REPLACE INTO meta VALUES('paused','runtime source tests')")
        c_pilot.declare(self.store,{**test_c_pilot.pilot(),'pins':self.pins})
        expected,startup,current=test_c_pilot.NativeStartupControls.frames(object())
        for obj in (expected,startup,current):obj['schema_sha256']=self.pins['schema_sha256']
        self.startup=self.root/'startup.json';self.expected=self.root/'expected.json'
        self.write(self.startup,startup);self.write(self.expected,expected)
        self.frame={'kind':'financial_readiness','network':'signet','genesis':SIGNET_GENESIS,
            'runtime_transport':'systemd','stable_tip':True,'initial_block_download':False,
            'observed_at':time.time(),'height':1000,'tip_hash':'c'*64,'native_runtime':current['daemons'],
            'runtime_wallet_inventory':{'frames':{o:{'available':True,'source':{'synthetic_owner':o}}
                for o in ('rounds','watchman')}}}
        self.frame_path=self.root/'synthetic-live-frame.json';self.write(self.frame_path,self.frame)
        self.helper=self.root/'synthetic-existing-inventory.py'
        self.helper.write_text("""import json,sys,time
from pathlib import Path
request=json.loads(sys.stdin.readline())
if request!={'kind':'financial_readiness'}:raise SystemExit(2)
value=json.loads(Path(sys.argv[1]).read_text())
if value.pop('synthetic_child_failure',False):raise SystemExit(3)
if not value.pop('synthetic_stale',False):value['observed_at']=time.time()
print(json.dumps(value))
""");self.helper.chmod(0o500)
        # The producer requires a protected installed executable. The runner's
        # toolcache interpreter can have different ownership/mode/link metadata.
        python=str(Path('/usr/bin/python3').resolve())
        command=[python,str(self.helper),str(self.frame_path)]
        self.configuration={'command':command,'command_files':{p:self.sha(Path(p))for p in (python,str(self.helper))},
            'startup_path':str(self.startup),'startup_sha256':self.sha(self.startup),
            'expected_path':str(self.expected),'expected_sha256':self.sha(self.expected),
            'schema_artifact_path':str(schema),'source_dir':str(self.directory)}
        self.config=SimpleNamespace(inventory_command=command,expected_sdk_commit=self.pins['sdk_commit'],wallet_root=self.wallets)
        self.producer=c.RuntimeSource(self.configuration,1)
        self.store.event('c_normal_runtime_source_qualified',self.producer.requirement(self.pins))
        self.producer.qualification_sequence=self.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
        self.observation={'id':'a'*32,'started_at':time.time(),'architecture_profile':DIRECT_PER_KEY,
            'financial_pins':self.pins,'boundary_id':'c-treasury','height':1000,'tip_hash':'c'*64}
        outer=self
        class Core:
            reads=0
            def identity(inner):
                inner.reads+=1
                return {'chain':'signet','blocks':1000,'bestblockhash':outer.tip,'initialblockdownload':False}
            def call(inner,method,*args):
                if(method,args)==('getblockhash',(0,)):return SIGNET_GENESIS
                raise AssertionError('runtime source must not use wallets/financial RPC')
        self.tip='c'*64;self.chain=Core()

    @staticmethod
    def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
    @staticmethod
    def write(path,value):path.write_text(canonical(value));path.chmod(0o600)
    def events(self,kind):return self.store.db.execute('SELECT count(*)FROM event WHERE kind=?',(kind,)).fetchone()[0]
    async def collect(self):return await self.producer.collect(self.store,self.config,self.chain,self.observation)

    async def test_actual_child_and_native_startup_verifier_emit_only_new_runtime_component(self):
        before=self.startup.read_bytes();result=await self.collect();safe=result['safe']
        self.assertEqual(1,self.events(c.KIND));self.assertEqual(1,self.events('owned_runtime_configuration_verified'))
        self.assertEqual(0,self.events('financial_operating_readiness'))
        self.assertEqual(before,self.startup.read_bytes());self.assertFalse(safe['complete']);self.assertFalse(safe['qualified'])
        self.assertEqual(self.observation,safe['source_observation'])
        frame,raw=c.replay_original(self.store,safe['original_trace'],self.observation)
        self.assertEqual(self.frame['native_runtime'],frame['native_runtime'])
        self.assertEqual(hashlib.sha256(raw).hexdigest(),safe['original_response_sha256'])
        self.assertEqual(0o600,Path(safe['current_startup_path']).stat().st_mode&0o777)
        self.assertEqual(1,len(list(self.directory.iterdir())))
        self.assertEqual('financial_readiness',frame['kind'])

    async def test_same_observation_never_reuses_source_or_repeats_helper(self):
        first=await self.collect();files=list(self.directory.iterdir())
        with self.assertRaisesRegex(ValueError,'already collected'):await self.collect()
        self.assertEqual(files,list(self.directory.iterdir()));self.assertEqual(1,self.events(c.KIND))
        self.assertEqual(first['safe']['source_sequence'],self.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0])

    async def test_missing_original_startup_cannot_auto_initialize_from_current(self):
        self.startup.unlink()
        with self.assertRaises(FileNotFoundError):await self.collect()
        self.assertFalse(self.startup.exists());self.assertEqual([],list(self.directory.iterdir()));self.assertEqual(0,self.events(c.KIND))

    async def test_wrong_command_or_code_hash_refuses_before_child(self):
        self.helper.chmod(0o700);self.helper.write_text('raise SystemExit(99)\n');self.helper.chmod(0o500)
        with self.assertRaisesRegex(ValueError,'component changed'):await self.collect()
        self.assertEqual([],list(self.directory.iterdir()));self.assertEqual(0,self.events(c.KIND))

    async def test_changed_operating_policy_helper_invalidates_original_source_admission(self):
        from simulator import c_runtime_profile
        original=c.module_hash
        def changed(component):
            return '0'*64 if component is c_runtime_profile.verify_loaded else original(component)
        with patch.object(c,'module_hash',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'qualification'):
                await self.collect()
        self.assertEqual([],list(self.directory.iterdir()))
        self.assertEqual(0,self.events(c.KIND))

    async def test_unsuccessful_actual_child_cannot_publish_source(self):
        self.frame['synthetic_child_failure']=True;self.write(self.frame_path,self.frame)
        with self.assertRaises(ValueError):await self.collect()
        self.assertEqual([],list(self.directory.iterdir()));self.assertEqual(0,self.events('owned_runtime_configuration_verified'))

    async def test_foreign_network_wrong_tip_stale_or_missing_owning_source_holds(self):
        for mutation in ('network','tip_hash','stale','owner'):
            bad=copy.deepcopy(self.frame)
            if mutation=='network':bad['network']='regtest'
            if mutation=='tip_hash':bad['tip_hash']='f'*64
            if mutation=='stale':bad.update(synthetic_stale=True,observed_at=self.observation['started_at']-1)
            if mutation=='owner':bad['runtime_wallet_inventory']['frames']['watchman']['available']=False
            self.write(self.frame_path,bad)
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):await self.collect()
        self.assertEqual([],list(self.directory.iterdir()));self.assertEqual(0,self.events(c.KIND))

    async def test_real_verifier_refuses_changed_process_preserving_failed_private_current(self):
        self.frame['native_runtime']['captaind']['pid']+=1;self.write(self.frame_path,self.frame)
        with self.assertRaisesRegex(ValueError,'same native daemon'):await self.collect()
        self.assertEqual(0,self.events('owned_runtime_configuration_verified'));self.assertEqual(0,self.events(c.KIND))
        self.assertEqual(1,len(list(self.directory.iterdir())))

    async def test_current_source_directory_cannot_be_wallet_root(self):
        self.producer.configuration['source_dir']=str(self.wallets)
        with self.assertRaisesRegex(ValueError,'qualification'):await self.collect()
        self.assertEqual([],list(self.wallets.iterdir()))

    async def test_trace_replay_refuses_other_invocation_and_missing_original(self):
        result=await self.collect();ref=result['safe']['original_trace']
        for changed_ref,obs in [(ref,{**self.observation,'id':'d'*32}),({**ref,'seq':ref['seq']+100},self.observation)]:
            with self.assertRaises(ValueError):c.replay_original(self.store,changed_ref,obs)

    async def test_independent_chain_change_holds_before_runtime_verifier_admission(self):
        original=self.chain.identity
        def changed():
            value=original()
            if self.chain.reads>1:value['bestblockhash']='e'*64
            return value
        self.chain.identity=changed
        with self.assertRaisesRegex(ValueError,'chain changed'):await self.collect()
        self.assertEqual(0,self.events('owned_runtime_configuration_verified'))
        self.assertEqual(0,self.events(c.KIND))
        self.assertEqual(1,len(list(self.directory.iterdir()))) # retain failed private cut

    async def test_shared_aggregate_deadline_can_refuse_before_helper_or_file_creation(self):
        from simulator.normal_source_deadline import ACTIVE
        class Expired:
            def remaining(self):raise TimeoutError('synthetic owned outer deadline expired')
        token=ACTIVE.set(Expired())
        try:
            with self.assertRaises(TimeoutError):await self.collect()
        finally:ACTIVE.reset(token)
        self.assertEqual([],list(self.directory.iterdir()));self.assertEqual(0,self.events(c.KIND))

    async def test_new_invocation_produces_new_current_and_new_original_verifier_event(self):
        one=await self.collect();self.observation={**self.observation,'id':'b'*32,'started_at':time.time()}
        two=await self.collect()
        self.assertNotEqual(one['safe']['current_startup_path'],two['safe']['current_startup_path'])
        self.assertLess(one['safe']['runtime_source_sequence'],two['safe']['runtime_source_sequence'])
        self.assertEqual(2,self.events(c.KIND));self.assertEqual(0,self.events('financial_operating_readiness'))


if __name__=='__main__':unittest.main()

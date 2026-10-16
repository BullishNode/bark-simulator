import ast
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('fixture_runtime',ROOT/'integration/fixture_runtime.py')
runtime=importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class FixtureProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir='/dev/shm')
        self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'driver.json'
        self.manifest={'driver_config':str(self.path)}
        self.path.write_text('{}')

    def pair(self,declared,driver):
        self.manifest.update(architecture_profile=declared,sdk_commit='1'*40)
        self.path.write_text(json.dumps({'architecture_profile':driver,'sdk_commit':'1'*40}))
        return runtime.fixture_profile(self.manifest)

    def test_historical_unprofiled_B_unchanged(self):
        self.assertIsNone(runtime.fixture_profile(self.manifest))

    def test_explicit_A_native_name(self):
        self.assertEqual(self.pair('two_step_per_key','two_step_per_key'),'two_step_per_key')

    def test_explicit_B_native_name(self):
        self.assertEqual(self.pair('direct_xpub','direct_xpub'),'direct_xpub')

    def test_explicit_C_native_name(self):
        self.assertEqual(self.pair('direct_per_key','direct_per_key'),'direct_per_key')

    def test_missing_driver_profile_cannot_select_A(self):
        self.manifest['architecture_profile']='two_step_per_key'
        with self.assertRaises(ValueError):runtime.fixture_profile(self.manifest)

    def test_driver_B_cannot_impersonate_A(self):
        with self.assertRaises(ValueError):self.pair('two_step_per_key','direct_xpub')

    def test_driver_A_cannot_impersonate_B(self):
        with self.assertRaises(ValueError):self.pair('direct_xpub','two_step_per_key')

    def test_omitted_manifest_cannot_select_profiled_driver(self):
        self.path.write_text(json.dumps({'architecture_profile':'two_step_per_key'}))
        with self.assertRaises(ValueError):runtime.fixture_profile(self.manifest)

    def test_unknown_profile_is_refused(self):
        with self.assertRaises(ValueError):self.pair('arbitrary','arbitrary')

    def test_explicit_null_is_not_legacy(self):
        with self.assertRaises(ValueError):self.pair(None,None)

    def test_boolean_is_not_a_profile(self):
        with self.assertRaises(ValueError):self.pair(True,True)

    def test_config_nonobject_is_refused(self):
        self.path.write_text('[]')
        with self.assertRaises(ValueError):runtime.fixture_profile(self.manifest)

    def test_config_size_is_bounded(self):
        self.path.write_bytes(b' '*65537)
        with self.assertRaises(ValueError):runtime.fixture_profile(self.manifest)

    def test_reads_leave_config_unchanged(self):
        self.pair('two_step_per_key','two_step_per_key');before=self.path.read_bytes()
        runtime.fixture_profile(self.manifest)
        self.assertEqual(self.path.read_bytes(),before)

    def test_profiled_config_requires_same_actual_sdk_pin(self):
        self.pair('two_step_per_key','two_step_per_key')
        for value in (None, 'short', 'G'*40, '2'*40):
            with self.subTest(value=value):
                self.manifest['sdk_commit']=value
                with self.assertRaises(ValueError):runtime.fixture_profile(self.manifest)

    def test_actual_fixture_config_constructor_receives_qualified_sdk(self):
        # Execute the actual constructor definition without its script CLI or RPCs.
        import sys
        from simulator.config import Config
        self.pair('two_step_per_key','two_step_per_key')
        source=ROOT/'integration/regtest-client.py'
        tree=ast.parse(source.read_text())
        definition=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='config')
        manifest={**self.manifest,'state_dir':str(Path(self.tmp.name)/'state'),
            'wallet_root':str(Path(self.tmp.name)/'wallets'),'driver':'driver','proof':'proof',
            'core_url':'http://127.0.0.1:1234','core_cookie':'cookie',
            'genesis':'0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206',
            'server_pubkey':'02'+'b'*64,'server_binary_sha256':'a'*64}
        namespace={'Config':Config,'Path':Path,'sys':sys,'m':manifest,
                   'profile':runtime.fixture_profile(manifest),'manifest':self.path,'__file__':str(source)}
        exec(compile(ast.Module(body=[definition],type_ignores=[]),str(source),'exec'),namespace)
        actual=namespace['config']()
        self.assertEqual('two_step_per_key',actual.architecture_profile)
        self.assertEqual('1'*40,actual.expected_sdk_commit)

    def test_observation_metadata_satisfies_real_config_identity_gate(self):
        from simulator.config import Config
        self.pair('two_step_per_key','two_step_per_key')
        cfg=Config(Path(self.tmp.name)/'state',('observer',),(),Path(self.tmp.name)/'wallets',
                   '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206',
                   'regtest-local-captaind','sha256:'+'a'*64,'02'+'b'*64,
                   10000,1,10,False,network='regtest',architecture_profile='two_step_per_key',expected_sdk_commit='1'*40)
        snapshot={'identity':{'network':'regtest','genesis':cfg.expected_genesis,'container':cfg.expected_container,
                             'image_digest':cfg.expected_image,'server_pubkey':cfg.expected_server_pubkey},
                  **runtime.fixture_observation_fields(self.manifest),'complete':False}
        cfg.validate_identity(snapshot)
        self.assertFalse(snapshot['complete'])
        snapshot['financial_pins']['sdk_commit']='2'*40
        with self.assertRaises(ValueError):cfg.validate_identity(snapshot)

    def test_legacy_observation_does_not_invent_sdk_or_financial_readiness(self):
        self.assertEqual({},runtime.fixture_observation_fields(self.manifest))

    def test_all_actual_client_stores_receive_bound_profile(self):
        total=0
        for name in ['regtest-client.py','round-adoption-client.py','unilateral-exit-client.py',
                     'round-padding-client.py']:
            tree=ast.parse((ROOT/'integration'/name).read_text())
            calls=[node for node in ast.walk(tree) if isinstance(node,ast.Call)
                   and isinstance(node.func,ast.Name) and node.func.id=='Store']
            self.assertTrue(calls,name)
            for call in calls:
                values=[kw.value for kw in call.keywords if kw.arg=='architecture_profile']
                self.assertEqual(len(values),1,name)
                self.assertIsInstance(values[0],ast.Name)
                self.assertEqual(values[0].id,'profile')
            total+=len(calls)
        self.assertGreater(total,10)

    def test_actual_engine_configs_receive_bound_profile(self):
        for name in ['regtest-client.py','round-adoption-client.py']:
            calls=[node for node in ast.walk(ast.parse((ROOT/'integration'/name).read_text()))
                   if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='Config']
            self.assertTrue(calls,name)
            for call in calls:
                values=[kw.value for kw in call.keywords if kw.arg=='architecture_profile']
                self.assertEqual(len(values),1,name)
                self.assertIsInstance(values[0],ast.Name)
                self.assertEqual(values[0].id,'profile')


if __name__=='__main__':unittest.main()

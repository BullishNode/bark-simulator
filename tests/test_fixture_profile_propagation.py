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
        self.manifest['architecture_profile']=declared
        self.path.write_text(json.dumps({'architecture_profile':driver}))
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

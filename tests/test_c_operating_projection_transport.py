"""Source controls only: package/certificate authority is synthetic here."""
from pathlib import Path
import hashlib
import importlib.util
import json
import sys
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / 'deploy' / 'track-c'
INSTALLED = Path('/opt/track-c/observer/operating-projection')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProjectionControls(unittest.TestCase):
    def setUp(self):
        self.ops = load('c_projection_source_ops', DEPLOY / 'native-ops.py')
        self.raw = {name: (ROOT / 'simulator' / name).read_bytes() for name in ('c_runtime_profile.py', 'model.py', 'bip39-english.txt')}
        self.binding = {name: hashlib.sha256(raw).hexdigest() for name, raw in self.raw.items()}
        self.manifest = {'operating_projection': self.binding}
        self.calls = []
        self.cert = b'-----BEGIN CERTIFICATE-----\nSYNTHETIC-PUBLIC-ONLY\n-----END CERTIFICATE-----\n'
        def read(path, maximum):
            path = Path(path)
            self.calls.append((path, maximum))
            if path.parent == INSTALLED:
                raw = self.raw[path.name]
            elif path.name.endswith('.cert'):
                raw = self.cert
            else:
                self.fail('unapproved source or private key read')
            self.assertLessEqual(len(raw), maximum)
            return raw, {'sha256': hashlib.sha256(raw).hexdigest(),
                         'device': 1, 'inode': 2, 'mtime_ns': 3, 'ctime_ns': 4}
        self.reader = mock.patch.object(self.ops, 'public_file', side_effect=read)
        self.reader.start()
        self.addCleanup(self.reader.stop)
        original_read_text = Path.read_text
        def read_text(path, *args, **kwargs):
            if path == INSTALLED / 'bip39-english.txt':
                return self.raw['bip39-english.txt'].decode()
            return original_read_text(path, *args, **kwargs)
        self.dictionary = mock.patch.object(Path, 'read_text', read_text)
        self.dictionary.start()
        self.addCleanup(self.dictionary.stop)

    def cap(self):
        connection = {'uri': 'https://owned.invalid:1234',
                      'server_cert_path': '/public/server.cert',
                      'client_cert_path': '/public/client.cert',
                      'client_key_path': '/never-read/private.key'}
        return {**{name: '100000 sat' for name in (
            'max_vtxo_amount', 'max_board_amount', 'max_offboard_amount',
            'max_arkoor_amount', 'max_ln_send_amount', 'max_ln_receive_amount',
            'max_round_amount')}, 'min_board_amount': '10000 sat',
            'vtxopool': {'vtxo_targets': ['25000 sat:2'], 'vtxo_pre_expiry': 100},
            'cln_array': [{**connection, 'priority': 1, 'hold_invoice': connection}]}

    def test_existing_projector_exports_only_public_operating_facts(self):
        result = self.ops.operating_projection(self.cap(), 'captaind', self.manifest)
        self.assertEqual(result['amount_caps_sat']['max_board_amount'], 100000)
        self.assertEqual(result['pool_targets'], [{'amount_sat': 25000, 'count': 2}])
        raw = json.dumps(result)
        for private in ('owned.invalid', 'https://', '/public/', '/never-read/', 'client_key_path'):
            self.assertNotIn(private, raw)
        self.assertEqual(len([p for p, _ in self.calls if p.name.endswith('.cert')]), 4)

    def test_watchman_keeps_original_58000_40000_and_full_20000(self):
        cfg = {'watchman': {'direct_expiry': {'max_miner_fee': '20000 sat',
            'ordinary_fee_policy': {'ordinary_budget_sat': 58000, 'urgent_reserve_sat': 40000}}}}
        result = self.ops.operating_projection(cfg, 'watchmand', self.manifest)
        self.assertEqual(result, {'direct_max_miner_fee_sat': 20000,
            'ordinary_fee_policy': {'ordinary_budget_sat': 58000, 'urgent_reserve_sat': 40000}})

    def test_changed_dependency_refuses_before_executing_projector(self):
        self.raw['model.py'] += b'\nraise AssertionError("must not execute")\n'
        with self.assertRaisesRegex(ValueError, 'source differs'):
            self.ops.operating_projection(self.cap(), 'captaind', self.manifest)

    def test_foreign_path_or_missing_dependency_is_not_a_package(self):
        for extra in (None, {'../model.py': 'a' * 64}, {}, {k: v for k, v in self.binding.items() if k != 'model.py'}):
            with self.subTest(extra=extra):
                with self.assertRaisesRegex(ValueError, 'package required'):
                    self.ops.operating_projection(self.cap(), 'captaind', {'operating_projection': extra})

    def test_missing_declaration_supplies_no_fullmode_claim(self):
        self.assertIsNone(self.ops.operating_projection(self.cap(), 'captaind', {}))
        self.assertEqual(self.calls, [])

    def test_package_changed_after_projection_cannot_return_facts(self):
        original_reader = self.ops.public_file.side_effect
        counts = {}
        def changed(path, maximum):
            raw, facts = original_reader(path, maximum)
            name = Path(path).name
            counts[name] = counts.get(name, 0) + 1
            if name == 'model.py' and counts[name] == 2:
                raw += b'\n'
                facts['sha256'] = hashlib.sha256(raw).hexdigest()
            return raw, facts
        self.ops.public_file.side_effect = changed
        with self.assertRaisesRegex(ValueError, 'changed during read'):
            self.ops.operating_projection(self.cap(), 'captaind', self.manifest)

    def test_projection_declaration_cannot_bypass_original_manifest_guards(self):
        from tests.test_c_native_observer import manifest, observer
        value = {**manifest(), 'operating_projection': self.binding}
        self.assertEqual(observer.validate_manifest(value), value)
        for bad in (None, {}, {**self.binding, '../extra.py': 'a' * 64}):
            with self.subTest(binding=bad), self.assertRaises(ValueError):
                observer.validate_manifest({**value, 'operating_projection': bad})
        with self.assertRaises(ValueError):
            observer.validate_manifest({**value, 'active': False})

    def test_private_certificate_or_plaintext_endpoint_is_rejected(self):
        cfg = self.cap()
        cfg['cln_array'][0]['uri'] = 'http://owned.invalid:1234'
        with self.assertRaisesRegex(ValueError, 'HTTPS'):
            self.ops.operating_projection(cfg, 'captaind', self.manifest)
        self.cert += b'PRIVATE KEY'
        with self.assertRaisesRegex(ValueError, 'public TLS'):
            self.ops.operating_projection(self.cap(), 'captaind', self.manifest)

    def test_temporary_package_cannot_replace_cached_module_and_is_restored(self):
        key = '_track_c_operating_projection.model'
        marker = types.ModuleType(key)
        with mock.patch.dict(sys.modules, {key: marker}):
            self.ops.operating_projection(self.cap(), 'captaind', self.manifest)
            self.assertIs(sys.modules[key], marker)

    def test_observer_allowlists_projection_but_rejects_private_nested_fields(self):
        public = types.ModuleType('public_observer')
        public.public_hash = lambda value: self.assertRegex(value, '^[0-9a-f]{64}$')
        value = {'sha256': 'a' * 64, 'operating_source': {'ordinary_budget_sat': 58000}}
        public.ops = lambda *args: json.dumps(value)
        with mock.patch.dict(sys.modules, {'public_observer': public}):
            observer = load('c_projection_source_observer', DEPLOY / 'server-observer.py')
        self.assertEqual(observer.config('watchmand'), value)
        value['operating_source']['private_key'] = 'never-public'
        with self.assertRaisesRegex(ValueError, 'private nested'):
            observer.config('watchmand')


if __name__ == '__main__':
    unittest.main(verbosity=2)

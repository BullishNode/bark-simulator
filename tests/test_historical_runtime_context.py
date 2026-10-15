"""Synthetic historical-context hooks; no runtime or wallet creation credit."""
from dataclasses import replace
import unittest
from unittest.mock import patch
from simulator import identity_bootstrap as bootstrap
from simulator.target_epochs import SERVER_IMAGE
from simulator.engine import Lease
from tests import test_identity_bootstrap as bootstrap_fixture

class HistoricalRuntimeContextTests(unittest.TestCase):
    def setUp(self):
        self.fixture=bootstrap_fixture.IdentityBootstrapTests();self.fixture.setUp();self.fixture.declare()
        self.store=self.fixture.store;self.current={**self.fixture.identity,'image_digest':SERVER_IMAGE}
        self.config=replace(self.fixture.config,expected_image=SERVER_IMAGE)
        self.manifest={'previous_identity':self.fixture.identity}
    def tearDown(self):self.fixture.tearDown()
    def test_declared4d_historical_context_keeps_original_sources_and_refuses_wrong_context(self):
        before=[tuple(row) for row in self.store.db.execute('SELECT * FROM event ORDER BY sequence')]
        with patch('simulator.target_epochs.active_runtime_manifest',return_value=self.manifest),patch('simulator.target_epochs.active_identity',return_value=self.current):
            checked=bootstrap._context(self.config,self.fixture.value,store=self.store)
            self.assertEqual(self.fixture.pins['driver_sha256'],checked['driver_sha256'])
            for changes in ({'expected_image':'sha256:'+'9'*64},{'expected_server_pubkey':'02'+'9'*64},
                            {'expected_sdk_commit':'9'*40},{'wallet_root':self.fixture.root/'other-wallets'}):
                with self.subTest(changes=changes),self.assertRaises(ValueError):
                    bootstrap._context(replace(self.config,**changes),self.fixture.value,store=self.store)
            for path in (self.fixture.driver,self.fixture.native_config,self.fixture.wallet_config):
                original=path.read_bytes();path.write_bytes(original+b' changed')
                with self.subTest(path=path.name),self.assertRaises(ValueError):
                    bootstrap._context(self.config,self.fixture.value,store=self.store)
                path.write_bytes(original)
            with patch('simulator.target_epochs.active_runtime_manifest',return_value={'previous_identity':self.current}):
                with self.assertRaises(ValueError):bootstrap._context(self.config,self.fixture.value,store=self.store)
        self.assertEqual(before,[tuple(row) for row in self.store.db.execute('SELECT * FROM event ORDER BY sequence')])
    def test_new_create_cannot_use_historical_bootstrap_on_new_deployment(self):
        action=self.fixture.action();before=[tuple(row) for row in self.store.db.execute('SELECT * FROM event ORDER BY sequence')]
        with Lease(self.fixture.wallets),patch('simulator.target_epochs.active_runtime_manifest',return_value=self.manifest),patch('simulator.target_epochs.active_identity',return_value=self.current):
            with self.assertRaisesRegex(ValueError,'bootstrap target identity differs'):
                bootstrap.eligible(self.store,self.config,{**self.fixture.snapshot,'identity':self.current},action)
        self.assertEqual(before,[tuple(row) for row in self.store.db.execute('SELECT * FROM event ORDER BY sequence')])

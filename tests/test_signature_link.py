"""Current-profile isolation and proof consumption; no synthetic live credit."""
import asyncio
import tempfile
import unittest
from pathlib import Path
from simulator.store import Store
from simulator.workload import record_actor_result
from simulator.engine import initialize, Engine
from simulator.config import Config
from simulator.signature_link import SDK_COMMIT
from dataclasses import replace
from unittest.mock import AsyncMock, patch
from simulator.signature_link import proof_matches, binding_matches


class SignatureLinkTests(unittest.TestCase):
    def test_ten_fresh_actors_and_profile_cannot_adopt_legacy_campaign(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with_store = Store(root, 'synthetic', 10000, architecture_profile='signature_link')
            try:
                initialize(with_store)
                self.assertEqual(10, with_store.db.execute('SELECT count(*) FROM actor').fetchone()[0])
                binding = {'mailbox_pk':'02'+'11'*32,'spk':'0014'+'22'*20,
                    'fallback_record':'04'+'33'*86,'server_mailbox_pubkey':'02'+'44'*32}
                record_actor_result(with_store, 'actor-01', 'create', {
                    'funding_address':'public-address','fallback_script':binding['spk'],'binding':binding})
                self.assertIn('"created": true', with_store.db.execute("SELECT details FROM actor WHERE id='actor-01'").fetchone()[0])
                self.assertEqual('record_version', with_store.db.execute('PRAGMA table_info(owner_record)').fetchall()[2]['name'])
            finally:
                with_store.close()
            with self.assertRaises(ValueError):
                Store(root, 'synthetic', 10000, architecture_profile='direct_per_key')

    def test_only_current_native_signature_claims_match_the_requested_recipient(self):
        bound = {'mailbox_pk':'mailbox','spk':'script','fallback_record':'record',
                 'server_mailbox_pubkey':'server','record_signature_valid':True,
                 'owner_link_signature_valid':True,'record_version':4,
                 'owner_link':'link','policy_pubkey_full':'recipient'}
        proof = {'user_pubkey':'recipient','binding':bound}
        self.assertTrue(proof_matches(proof, {'user_pubkey':'recipient','owner_link':'link'}))
        for source in ({'user_pubkey':'other'}, {'user_pubkey':'recipient','owner_link':'other'}):
            self.assertFalse(proof_matches(proof, source))
        for field in ('record_signature_valid','owner_link_signature_valid'):
            changed = {**proof,'binding':{**bound,field:False}}
            self.assertFalse(proof_matches(changed, {'user_pubkey':'recipient'}))
        self.assertFalse(binding_matches(bound, {**bound,'server_mailbox_pubkey':'other'}))
        self.assertFalse(binding_matches(bound, {**bound,'account_xpub':'legacy'}))

    def test_current_client_budget_is_immutable_without_legacy_accounting_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = Config(state_dir=root, observer_command=(), driver_command=(), wallet_root=root / 'wallets',
                expected_genesis='genesis', expected_container='container', expected_image='image',
                expected_server_pubkey='pubkey', fee_budget_sat=10000, interval_seconds=30,
                action_timeout_seconds=120, active=False, trace_enabled=False,
                architecture_profile='signature_link', expected_sdk_commit=SDK_COMMIT, principal_budget_sat=40000)
            store = Store(root, 'synthetic', 10000, architecture_profile='signature_link')
            try:
                initialize(store)
                engine = Engine(config, store)
                self.assertFalse(engine._requires_financial_qualification())
                self.assertIsNone(store.get_meta('financial_qualification_required'))
                store.queue('create-1', 'actor-01', 'H01', 'create', {}, 0)
                store.claim({'create'})
                store.finish('create-1', 'blocked', {}, 0)
                (root / 'wallets').mkdir()
                active = replace(config, active=True, driver_command=('/bin/false',),
                    proof_command=('verifier','core','cookie','server','mailbox'))
                engine = Engine(active, store)
                store.queue('oversize-board', 'actor-01', 'H01', 'board', {'amount_sat':40001}, 2000)
                with patch('simulator.engine.json_command', new_callable=AsyncMock) as native:
                    asyncio.run(engine.dispatch_one())
                    native.assert_not_called()
                self.assertEqual('blocked', store.db.execute("SELECT state FROM action WHERE id='oversize-board'").fetchone()[0])
                with self.assertRaises(ValueError):
                    Engine(replace(config, principal_budget_sat=40001), store)
            finally:
                store.close()

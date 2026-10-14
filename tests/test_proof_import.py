from tests import account_fixtures
"""Public import boundaries: synthetic native replies never claim live proof."""
import asyncio
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from simulator.config import Config
from simulator.engine import initialize
from simulator.model import SIGNET_GENESIS, InvariantError, canonical
from simulator.ownership import EvidenceGap, expiry_owner
from simulator.store import Store


class ProofImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = Store(self.root / 'journal', 'synthetic', 10000)
        initialize(self.store)
        self.path = self.root / 'public.json'
        self.mailbox = '02' + 'a' * 64
        self.key = '02' + 'b' * 64
        self.server = '03' + 'c' * 64
        self.coin = account_fixtures.coin({'id': 'd' * 64 + ':0', 'amount_sat': 500, 'user_pubkey': self.key,
            'expiry_height': 1000, 'signed_vtxo': 'ab' * 32,
            'binding': account_fixtures.binding({'mailbox_pk': self.mailbox, 'seq': 7,
                'spk': '0014' + 'e' * 40, 'record_attestation': 'ef' * 64})})
        self.bundle = {'schema_version': 1, 'actor': 'actor-09',
            'identity': {'network': 'signet', 'genesis': SIGNET_GENESIS, 'server_pubkey': self.server},
            'coins': [self.coin]}
        self.set_binding('actor-09', self.mailbox)
        self.store.set_online('actor-09', False)
        self.write()
        self.config = Config(self.root / 'journal', (), (), self.root / 'wallets',
            SIGNET_GENESIS, 'unused-container', 'unused-image', self.server, 10000, 30, 120,
            True, proof_command=('public-verifier', 'rpc', 'credential-path', self.server))
        self.reply = account_fixtures.proof({'id': self.coin['id'], 'amount_sat': 500, 'user_pubkey': self.key,
            'expiry_height': 1000, 'server_pubkey': self.server, 'genesis': SIGNET_GENESIS,
            'signed_path_valid': True, 'anchor_confirmations': 1,
            'binding': {**{k: v for k, v in self.coin['binding'].items() if k != 'record_attestation'},
                'account_child_verified': True, 'record_signature_valid': True}, 'path': []})

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def set_binding(self, actor, mailbox):
        self.store.db.execute('UPDATE actor SET details=? WHERE id=?',
            (canonical({'binding': {'mailbox_pk': mailbox}}), actor))

    def write(self, bundle=None):
        self.path.write_text(json.dumps(self.bundle if bundle is None else bundle))

    def collect(self, reply=None, paths=None, error=None):
        from simulator.proof_import import collect
        native = AsyncMock(return_value=self.reply if reply is None else reply, side_effect=error)
        with patch('simulator.proof_import.json_command', native):
            result = asyncio.run(collect(self.store, self.config,
                paths=(self.path,) if paths is None else paths))
        return result, native

    def assert_no_import(self):
        self.assertEqual(0, self.store.db.execute('SELECT COUNT(*) FROM owned_coin').fetchone()[0])
        self.assertEqual(0, self.store.db.execute('SELECT COUNT(*) FROM action').fetchone()[0])
        self.assertFalse(self.store.online('actor-09'))

    def test_native_rerun_resolves_missing_owner_without_original_wallet_or_traffic(self):
        with self.assertRaises(EvidenceGap): expiry_owner(self.store, self.coin['id'], 'spendable')
        budget = self.store.remaining_fee_budget()
        _, native = self.collect()
        self.assertEqual(1, native.await_count)
        request = native.call_args.args[1]
        self.assertEqual(self.coin['signed_vtxo'], request['signed_vtxo'])
        self.assertEqual(self.coin['binding'], request['binding'])
        self.assertEqual(self.coin['child_index'], request['child_index'])
        self.assertNotIn('actor_dir', request)
        self.assertEqual('actor-09', expiry_owner(self.store, self.coin['id'], 'spendable')['actor'])
        action = self.store.db.execute('SELECT * FROM action').fetchone()
        self.assertTrue(action['id'].startswith('public-proof-import-'))
        self.assertEqual('public_proof_import', action['operation'])
        self.assertIsNone(action['scenario_id'])
        self.assertEqual('completed', action['state'])
        self.assertEqual(0, action['actual_fee_sat'])
        self.assertEqual(budget, self.store.remaining_fee_budget())
        self.assertFalse(self.store.online('actor-09'))
        self.assertEqual(0, self.store.db.execute('SELECT COUNT(*) FROM movement_evidence').fetchone()[0])
        self.assertEqual('PublicProof', self.store.db.execute('SELECT state FROM coin_observation').fetchone()[0])
        self.assertEqual(0, self.store.db.execute("SELECT COUNT(*) FROM event WHERE kind IN ('driver_request','ark_transfer_verified')").fetchone()[0])
        self.store.verify_event_chain()

    def test_confirmed_payout_owner_gap_resolves_after_import_without_wallet_call(self):
        from simulator.ownership import record_server_page
        from simulator.settlements import collect_settlements
        from types import SimpleNamespace
        txid = 'f' * 64
        script = self.coin['binding']['spk']
        row = {'id': self.coin['id'], 'txid': txid, 'spk': script, 'fee_sat': 9,
            'tx_settlement_count': 1, 'pre_commit_rows': [{'spend_state': 'spendable'}]}
        record_server_page(self.store, {'kind': 'settlements', 'rows': [row],
            'next': None, 'inventory_consistent': False})
        self.store.db.execute('INSERT INTO operator_script VALUES (?,?)', ('operator-change', '{}'))
        tx = {'txid': txid, 'confirmations': 1, 'fee_sat': 14,
            'outputs': [{'script': script, 'amount_sat': 491},
                        {'script': 'operator-change', 'amount_sat': 100}]}
        chain = SimpleNamespace(identity=lambda: None, transaction=lambda identity: tx)
        asyncio.run(collect_settlements(self.store, chain))
        self.assertEqual('pending', self.store.db.execute('SELECT state FROM settlement_check').fetchone()[0])
        self.collect()
        asyncio.run(collect_settlements(self.store, chain))
        self.assertEqual('amounts_checked', self.store.db.execute('SELECT state FROM settlement_check').fetchone()[0])
        self.assertEqual('actor-09', self.store.db.execute('SELECT actor FROM checked_settlement').fetchone()[0])
        self.assertFalse(self.store.online('actor-09'))
        self.assertEqual(0, self.store.db.execute("SELECT COUNT(*) FROM event WHERE kind='driver_request'").fetchone()[0])
        self.store.verify_event_chain()

    def test_content_hash_is_idempotent_across_whitespace_paths_and_restart(self):
        self.collect()
        self.path.write_text(canonical(self.bundle))
        _, native = self.collect()
        self.assertEqual(0, native.await_count)
        other = self.root / 'same.json'; other.write_text(canonical(self.bundle))
        _, native = self.collect(paths=(other,))
        self.assertEqual(0, native.await_count)
        self.assertEqual(1, self.store.db.execute('SELECT COUNT(*) FROM action').fetchone()[0])
        self.assertEqual(1, self.store.db.execute("SELECT COUNT(*) FROM event WHERE kind='public_proof_imported'").fetchone()[0])
        self.store.verify_event_chain()

    def test_wrong_actor_cannot_adopt_another_actors_signed_mailbox(self):
        wrong = copy.deepcopy(self.bundle); wrong['actor'] = 'actor-10'; self.write(wrong)
        self.set_binding('actor-10', '02' + 'f' * 64)
        _, native = self.collect()
        self.assertEqual(0, native.await_count)
        self.assert_no_import()

    def test_signed_bytes_link_and_destination_tampering_remain_unverified(self):
        for field in ('signed_vtxo', 'blinded_mailbox_id', 'destination'):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.bundle)
                if field == 'destination': changed['coins'][0]['binding']['spk'] = '0014' + '0' * 40
                else: changed['coins'][0][field] = '00' * 64
                self.write(changed)
                self.collect(error=ValueError('native signature rejected'))
                self.assert_no_import()

    def test_native_identity_key_value_or_signature_flags_must_match(self):
        for field, value in [('id', 'a' * 64 + ':0'), ('user_pubkey', self.server),
                             ('amount_sat', 501), ('server_pubkey', self.key),
                             ('genesis', '0' * 64), ('signed_path_valid', False),
                             ('anchor_confirmations', 0)]:
            with self.subTest(field=field):
                reply = copy.deepcopy(self.reply); reply[field] = value
                self.collect(reply=reply)
                self.assert_no_import()
        reply = copy.deepcopy(self.reply); reply['binding']['spk'] = '0014' + '0' * 40
        self.collect(reply=reply); self.assert_no_import()

    def test_competing_verified_owner_is_an_incident_and_rolls_back(self):
        self.store.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',
            (self.key, 'actor-10', self.mailbox, canonical(self.reply)))
        with self.assertRaises(InvariantError): self.collect()
        self.assert_no_import()

    def test_audit_only_and_incomplete_bundles_are_pending_and_not_trusted(self):
        audit = {'actor': 'actor-09', 'result': 'PUBLIC_SIGNATURE_BACKING_PASS', 'public_coin': self.reply}
        self.write(audit); _, native = self.collect(); self.assertEqual(0, native.await_count)
        self.assert_no_import()
        partial = copy.deepcopy(self.bundle); del partial['coins'][0]['binding']['fallback_record']
        self.write(partial); _, native = self.collect(); self.assertEqual(0, native.await_count)
        self.assert_no_import()
        partial = copy.deepcopy(self.bundle); partial['coins'].append({'id': 'a' * 64 + ':0'})
        self.write(partial); _, native = self.collect(); self.assertEqual(0, native.await_count)
        self.assert_no_import()

    def test_unverified_cache_cannot_substitute_for_a_native_verifier_run(self):
        self.collect(error=TimeoutError)
        self.assert_no_import()
        self.collect()
        self.assertEqual(1, self.store.db.execute('SELECT COUNT(*) FROM owned_coin').fetchone()[0])

    def test_missing_source_and_symlink_or_wallet_paths_do_not_follow_files(self):
        link = self.root / 'link.json'; link.symlink_to(self.path)
        for path in (self.root / 'missing.json', link, Path('../public.json'), self.root / 'wallets' / 'actor-09' / 'proof.json'):
            with self.subTest(path=str(path)):
                _, native = self.collect(paths=(path,)); self.assertEqual(0, native.await_count)
                self.assert_no_import()
        directory = self.root / 'redirect'; directory.symlink_to(self.root, target_is_directory=True)
        _, native = self.collect(paths=(directory / 'public.json',))
        self.assertEqual(0, native.await_count); self.assert_no_import()

    def test_secret_fields_and_secret_values_never_enter_public_journal(self):
        for field, value in [('mnemonic', 'private recovery words'), ('comment', 'xprv-secret'),
                             ('seed', 'abandon ' * 12), ('comment', '__cookie__:secret')]:
            secret = copy.deepcopy(self.bundle); secret[field] = value
            self.write(secret); _, native = self.collect(); self.assertEqual(0, native.await_count)
            self.assert_no_import()
            events = ' '.join(r[0] for r in self.store.db.execute('SELECT payload FROM event'))
            self.assertNotIn(value, events)
            self.assertNotIn(self.coin['signed_vtxo'], events)

    def test_secret_shaped_native_reply_is_not_written_to_public_records(self):
        for value in ('xprv-secret', '__cookie__:secret', 'abandon ' * 12):
            reply = copy.deepcopy(self.reply); reply['validation_scope'] = value
            self.collect(reply=reply)
            self.assert_no_import()
            events = ' '.join(r[0] for r in self.store.db.execute('SELECT payload FROM event'))
            self.assertNotIn(value, events)

    def test_bound_target_must_match_declared_config_and_bundle(self):
        bundle = copy.deepcopy(self.bundle); bundle['identity']['server_pubkey'] = self.key
        self.write(bundle); _, native = self.collect(); self.assertEqual(0, native.await_count)
        self.assert_no_import()


class ProofConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.path = self.root / 'config.toml'
        self.base = f'''[target]
network="signet"
genesis="{SIGNET_GENESIS}"
container="abandon-signet-fallback-test"
image_digest="sha256:{'a' * 64}"
server_pubkey="02{'b' * 64}"
[runtime]
state_dir="{self.root / 'state'}"
wallet_root="{self.root / 'wallets'}"
fee_budget_sat=10000
active=false
observer_command=[]
'''
    def tearDown(self): self.temp.cleanup()
    def test_declared_local_bundle_paths_load_without_glob_or_shell(self):
        bundle = self.root / 'public.json'
        self.path.write_text(self.base + f'\n[proofs]\nbundles=["{bundle}"]\n')
        self.assertEqual((bundle,), Config.load(self.path).proof_bundles)
    def test_remote_relative_and_wallet_paths_are_rejected(self):
        for value in ('https://example.com/proof.json', '../public.json', str(self.root / 'wallets' / 'actor-09.json')):
            self.path.write_text(self.base + f'\n[proofs]\nbundles=["{value}"]\n')
            with self.assertRaises(ValueError): Config.load(self.path)

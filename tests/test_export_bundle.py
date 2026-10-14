from tests import account_fixtures
"""Self-contained public evidence export, with explicit signature-proof limits."""
import json
import tempfile
import unittest
from pathlib import Path

from simulator.engine import initialize
from simulator.model import canonical, InvariantError, SIGNET_GENESIS
from simulator.ownership import record_verified
from simulator.store import Store


class ExportBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.store = Store(self.root / 'campaign', 'synthetic', 10000); initialize(self.store)
        self.out = self.root / 'bundle'
        self.txid = 'a' * 64; self.coin_id = 'b' * 64 + ':0'; self.pub = '02' + 'c' * 64
        self.script = '0014' + 'd' * 40
        self.store.queue('observe-09', 'actor-09', 'H01', 'snapshot', {}, 0)
        self.store.db.execute("UPDATE action SET state='completed',updated_at=100 WHERE id='observe-09'")
        binding = account_fixtures.binding({'mailbox_pk': '02' + 'e' * 64, 'seq': 7, 'spk': self.script,
            'record_signature_valid': True, 'account_child_verified': True})
        coin = account_fixtures.coin({'id': self.coin_id, 'user_pubkey': self.pub, 'amount_sat': 5000,
                'signed_vtxo': 'ab' * 32, 'state': 'Spendable'})
        proof = account_fixtures.proof({'id': self.coin_id, 'user_pubkey': self.pub, 'amount_sat': 5000,
            'signed_path_valid': True, 'anchor_confirmations': 1, 'binding': binding,
            'chain_anchor': 'f' * 64 + ':0', 'genesis': SIGNET_GENESIS, 'server_pubkey': '03' + '1' * 64,
            'path': []})
        record_verified(self.store, 'actor-09', 'observe-09', {'objects': [{'kind': 'coin',
            'coin': coin, 'proof': proof, 'signed_hash': '2' * 64, 'request_binding': binding}], 'movements': []})
        row = {'id': self.coin_id, 'txid': self.txid, 'spk': self.script, 'fee_sat': 339,
            'tx_settlement_count': 1, 'pre_commit_rows': [{'spend_state': 'spendable'}]}
        self.store.db.execute('INSERT INTO server_item VALUES (?,?,?,100)', ('settlements', self.coin_id, canonical(row)))
        tx = {'txid': self.txid, 'confirmations': 1, 'fee_sat': 339,
              'inputs': [{'outpoint': 'f' * 64 + ':0', 'amount_sat': 10000, 'script': 'anchor'}],
              'outputs': [{'vout': 0, 'script': self.script, 'amount_sat': 4661},
                          {'vout': 1, 'script': 'operator-change', 'amount_sat': 5000}]}
        self.store.db.execute('INSERT INTO chain_payout VALUES (?,?)', (self.txid, canonical(tx)))
        self.store.db.execute('INSERT INTO operator_script VALUES (?,?)', ('operator-change', canonical({'verified': True})))
        self.store.db.execute('INSERT INTO checked_settlement VALUES (?,?,?,?,?,?)',
            (self.coin_id, self.txid, 'actor-09', self.script, 5000, canonical({'row': row})))
        self.store.event('confirmed_payout_amounts_checked', {'txid': self.txid, 'coins': [self.coin_id]})
        self.store.set_online('actor-09', False)
    def tearDown(self): self.store.close(); self.temp.cleanup()
    def export(self, **kwargs):
        from simulator.export_bundle import export_bundle
        return export_bundle(self.store, self.out, **kwargs)
    def test_actor_bundle_replays_4661_sat_payout_from_exported_evidence_alone(self):
        from simulator.export_bundle import audit_bundle
        manifest = self.export(actor='actor-09')
        for name in ('manifest.json', 'events.jsonl', 'trace.jsonl', 'actor.json', 'timeline.jsonl', 'README.md'):
            self.assertTrue((self.out / name).is_file(), name)
        self.assertTrue((self.out / 'proofs').is_dir()); self.assertTrue((self.out / 'raw-rpc').is_dir())
        self.assertEqual('actor-09', manifest['selection']['actor'])
        result = audit_bundle(self.out)
        self.assertEqual(4661, result['payouts'][0]['recipient_net_sat']['actor-09'])
        self.assertEqual('amounts_checked', result['payouts'][0]['state'])
        self.assertFalse(result['native_protocol_reverified'])
        self.assertTrue(result['gaps'], 'missing raw native requests/backing must remain explicit')
        self.assertFalse(self.store.online('actor-09'))
    def test_changed_proof_or_missing_file_invalidates_manifest(self):
        from simulator.export_bundle import audit_bundle
        self.export(actor='actor-09')
        proof = next((self.out / 'proofs').glob('*.json')); proof.write_text('{}')
        with self.assertRaises(InvariantError): audit_bundle(self.out)
    def test_export_never_overwrites_destination_or_modifies_financial_journal(self):
        first = self.store.verify_event_chain(); self.export(actor='actor-09')
        self.assertEqual(first, self.store.verify_event_chain())
        with self.assertRaises(FileExistsError): self.export(actor='actor-09')
    def test_payout_selection_includes_whole_group_and_related_actor_without_claiming_other_scenarios(self):
        from simulator.export_bundle import audit_bundle
        manifest = self.export(payout=self.txid)
        self.assertEqual(self.txid, manifest['selection']['payout'])
        self.assertEqual(4661, audit_bundle(self.out)['payouts'][0]['recipient_net_sat']['actor-09'])
    def test_secret_database_fields_are_redacted_before_export(self):
        self.store.db.execute('UPDATE actor SET details=? WHERE id=?',
            (canonical({'mnemonic': 'do not export'}), 'actor-09'))
        self.export(actor='actor-09')
        text = ' '.join(p.read_text() for p in self.out.rglob('*') if p.is_file())
        self.assertNotIn('do not export', text)
        self.assertTrue(json.loads((self.out / 'actor.json').read_text())[0]['details']['redacted'])
    def test_actor_timeline_contains_actions_coin_observations_and_checked_payouts(self):
        self.export(actor='actor-09')
        timeline = [json.loads(line) for line in (self.out / 'timeline.jsonl').read_text().splitlines()]
        self.assertTrue({'action', 'coin_observation', 'checked_settlement'} <= {r['kind'] for r in timeline})

    def test_unlisted_proof_file_is_rejected_before_replay(self):
        from simulator.export_bundle import audit_bundle
        self.export(actor='actor-09')
        (self.out/'proofs/extra.json').write_text('{}')
        with self.assertRaises(InvariantError):audit_bundle(self.out)
    def test_replayed_actor_net_uses_rechecked_owner_not_cached_settlement_actor(self):
        from simulator.export_bundle import audit_bundle
        self.store.db.execute('UPDATE checked_settlement SET actor=?',('actor-08',))
        self.export(payout=self.txid)
        self.assertEqual({'actor-09':4661},audit_bundle(self.out)['payouts'][0]['recipient_net_sat'])

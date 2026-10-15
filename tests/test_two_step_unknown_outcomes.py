"""Synthetic controller routing controls; these award no native/live credit."""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from simulator import unknown_outcomes
from simulator.engine import initialize
from simulator.model import canonical
from simulator.store import Store
from tests import test_unknown_outcomes as existing_controls


class PerKeyUnknownOutcomeTests(unittest.TestCase):
    movement = existing_controls.UnknownOutcomeTests.movement
    row = existing_controls.UnknownOutcomeTests.row
    tearDown = existing_controls.UnknownOutcomeTests.tearDown

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.s = Store(Path(self.tmp.name), 'synthetic', 1000000,
                       architecture_profile='two_step_per_key')
        initialize(self.s)
        self.actor = 'actor-08'
        self.key = '02' + '11' * 32
        self.output_key = '02' + '22' * 32
        self.binding = {'mailbox_pk': 'mailbox', 'seq': 7, 'spk': 'owner-script',
                        'record_signature_valid': True, 'key_link_signature_valid': True}
        self.s.db.execute('INSERT INTO owner_record VALUES (?,?,?,?,?)',
                         (self.actor, 'mailbox', 7, 'owner-script', canonical(self.binding)))
        for name, key, amount, signed in [('original', self.key, 10000, 'aa'),
                                           ('replacement', self.output_key, 9900, 'bb')]:
            proof = {'id': name, 'user_pubkey': key, 'amount_sat': amount,
                     'signed_path_valid': True, 'anchor_confirmations': 1,
                     'binding': copy.deepcopy(self.binding)}
            self.s.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',
                              (key, self.actor, 'mailbox', canonical(proof)))
            self.s.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',
                              (name, key, amount, hashlib.sha256(bytes.fromhex(signed)).hexdigest(),
                               signed, canonical(proof)))
        self.s.queue('lost', self.actor, 'H17', 'refresh', {}, 2000)
        self.s.db.execute("UPDATE action SET state='outcome_unknown',result=? WHERE id='lost'",
                          (canonical({'reason': 'TimeoutError'}),))
        self.original_time = self.row()['updated_at']
        self.s.event('driver_evidence', {'action_id': 'lost', 'event': 'refresh_proposal',
            'data': {'committed_fee_sat': 100,
                     'participation': {'inputs': ['aa'],
                       'outputs': [{'amount': 9900, 'policy': '00' + self.output_key}]}}})

    def read_action(self, operation='snapshot', data=None, binding=None):
        self.s.db.execute('DELETE FROM action')
        self.s.db.execute("DELETE FROM event WHERE kind!='architecture_profile_declared'")
        self.s.queue('lost', self.actor, 'H01', operation, {}, 0)
        self.s.db.execute("UPDATE action SET state='outcome_unknown',result='{}' WHERE id='lost'")
        frame = {'coins': [], 'movements': [], 'binding': binding or self.binding}
        for phase in ('before', 'after'):
            self.s.event('driver_evidence', {'action_id': 'lost', 'event': 'client_evidence_' + phase,
                                           'data': {'fresh': True, 'evidence': frame}})
        self.s.event('driver_response', {'action_id': 'lost', 'response': {
            'action_id': 'lost', 'status': 'ok', 'actual_fee_sat': 0, 'data': data or {}}})

    def test_per_key_signed_refresh_reconciles_once_without_account_flags_or_replay(self):
        self.movement()
        self.s.set_online(self.actor, False)
        self.assertTrue(unknown_outcomes.resolve(self.s, 'lost'))
        self.assertEqual(100, self.row()['actual_fee_sat'])
        self.assertEqual(self.original_time, self.row()['updated_at'])
        self.assertFalse(self.s.online(self.actor))
        self.assertFalse(unknown_outcomes.resolve(self.s, 'lost'))
        self.assertEqual(1, self.s.db.execute('SELECT count(*) FROM action').fetchone()[0])
        for row in self.s.db.execute('SELECT proof FROM owned_coin'):
            self.assertNotIn('account_child_verified', json.loads(row[0])['binding'])
        self.assertTrue(self.s.verify_event_chain())

    def test_per_key_empty_read_uses_exact_checked_sequence_and_script(self):
        self.read_action()
        self.assertTrue(unknown_outcomes.resolve(self.s, 'lost'))
        self.assertEqual(0, self.row()['actual_fee_sat'])

    def test_incomplete_or_cross_profile_coin_proof_keeps_unknown_and_original_budget(self):
        self.movement()
        original = self.s.db.execute("SELECT proof FROM owned_coin WHERE id='replacement'").fetchone()[0]
        for update in ({'key_link_signature_valid': False}, {'seq': True},
                       {'account_xpub': 'foreign'}, {'account_child_verified': True}):
            with self.subTest(update=update):
                proof = json.loads(original)
                proof['binding'].update(update)
                self.s.db.execute("UPDATE owned_coin SET proof=? WHERE id='replacement'", (canonical(proof),))
                before = dict(self.row())
                self.assertFalse(unknown_outcomes.resolve(self.s, 'lost'))
                self.assertEqual(before, dict(self.row()))
        self.s.db.execute("UPDATE owned_coin SET proof=? WHERE id='replacement'", (original,))

    def test_other_sequence_script_or_mailbox_read_stays_unknown_without_sql_error(self):
        for update in ({'seq': 8}, {'seq': True}, {'spk': 'other'}, {'mailbox_pk': 'other'}):
            with self.subTest(update=update):
                self.read_action(binding={**self.binding, **update})
                before = dict(self.row())
                self.assertFalse(unknown_outcomes.resolve(self.s, 'lost'))
                self.assertEqual(before, dict(self.row()))

    def test_create_recovery_preserves_per_key_binding_without_adopting_account_metadata(self):
        self.read_action('create', {'funding_address': 'funding', 'fallback_script': 'owner-script',
                                  'binding': self.binding, 'account_xpub': 'must-not-adopt'})
        self.assertTrue(unknown_outcomes.resolve(self.s, 'lost'))
        details = json.loads(self.s.db.execute('SELECT details FROM actor WHERE id=?', (self.actor,)).fetchone()[0])
        self.assertEqual(self.binding, details['binding'])
        self.assertNotIn('account_xpub', details)
        self.assertTrue(details['needs_sync'])
        self.assertTrue(details['created'])

    def test_create_reply_cannot_replace_the_checked_per_key_binding_or_script(self):
        updates = [{'binding': {**self.binding, 'seq': 8}},
                   {'binding': {**self.binding, 'mailbox_pk': 'other'}},
                   {'fallback_script': 'other'}]
        for update in updates:
            with self.subTest(update=update):
                self.read_action('create', {'funding_address': 'funding',
                    'fallback_script': 'owner-script', 'binding': self.binding, **update})
                before = dict(self.row())
                actor_before = dict(self.s.db.execute('SELECT * FROM actor WHERE id=?', (self.actor,)).fetchone())
                events_before = [tuple(r) for r in self.s.db.execute('SELECT * FROM event ORDER BY sequence')]
                self.assertFalse(unknown_outcomes.resolve(self.s, 'lost'))
                self.assertEqual(before, dict(self.row()))
                self.assertEqual(actor_before, dict(self.s.db.execute('SELECT * FROM actor WHERE id=?', (self.actor,)).fetchone()))
                self.assertEqual(events_before, [tuple(r) for r in self.s.db.execute('SELECT * FROM event ORDER BY sequence')])

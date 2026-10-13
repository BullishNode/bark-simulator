"""Accounting fixtures for one targeted claim among unrelated pending invoices.

Synthetic signed-inventory rows model already independently verified evidence;
these tests perform no native verification, wallet or financial operation.
"""
import asyncio
import copy
import json
import tempfile
import unittest
from pathlib import Path

from simulator.engine import initialize
from simulator.fees import collect, receive_fee
from simulator.model import InvariantError, canonical
from simulator.ownership import EvidenceGap
from simulator.store import Store


class TargetedReceiveFeeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name), 'synthetic', 100000)
        initialize(self.store)
        self.actor = 'actor-06'
        self.target, self.old_a, self.old_b = ('a' * 64, 'b' * 64, 'c' * 64)
        self.key = '02' + '11' * 32
        self.store.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',
            (self.key, self.actor, 'fixture-mailbox', '{}'))
        self.store.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',
            ('received', self.key, 1896, 'fixture-digest', 'fixture-signed', '{}'))
        for name, payment_hash in [('old-a', self.old_a), ('old-b', self.old_b), ('selected', self.target)]:
            self.action(name, self.actor, 'invoice', {'amount_sat': 2000},
                {'payment_hash': payment_hash, 'estimated_claim_fee_sat': 104})
        self.action('payer', 'actor-02', 'pay_invoice', {}, {'payment_hash': self.target}, state='outcome_unknown')
        self.movement = {'id': '57', 'subsystem': 'bark.lightning_receive',
            'status': 'successful', 'payment_hash': self.target, 'input_vtxos': [],
            'output_vtxos': ['received'], 'offchain_fee_sat': 104, 'effective_balance_sat': 1896}
        self.store.db.execute('INSERT INTO movement_evidence VALUES (?,?,?)',
            (self.actor, '57', canonical(self.movement)))
        self.before = {'movements': [], 'coins': []}
        self.data = {'bounded_receive_sync': True, 'receive_count_before': 3, 'receive_count_after': 2,
            'receive_payment_hashes_before': [self.old_a, self.old_b, self.target],
            'receive_payment_hashes_after': [self.old_a, self.old_b],
            'selected_receive_payment_hashes': [self.target], 'selected_receive_fee_ceiling_sat': 104,
            'all_pending_receive_fee_ceiling_sat': 312,
            'before_evidence': copy.deepcopy(self.before),
            'evidence': {'movements': [copy.deepcopy(self.movement)], 'coins': []}}
        unchanged = {**self.data, 'receive_count_after': 3,
            'receive_payment_hashes_after': [self.old_a, self.old_b, self.target],
            'evidence': copy.deepcopy(self.before)}
        self.action('earlier-sync', self.actor, 'sync', {}, unchanged)
        self.args = {'receive_payment_hash': self.target, 'recipient_invoice_action': 'selected',
            'payer_action_id': 'payer'}
        self.action('target-sync', self.actor, 'sync', self.args, self.data)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def action(self, name, actor, operation, args, data, state='completed'):
        self.store.queue(name, actor, 'H06', operation, args, 2000)
        self.store.db.execute("UPDATE action SET state='dispatched' WHERE id=?", (name,))
        self.store.finish(name, state, {'data': copy.deepcopy(data)})

    def row(self, name='target-sync'):
        return self.store.db.execute('SELECT * FROM action WHERE id=?', (name,)).fetchone()

    def update(self, **changes):
        data = copy.deepcopy(self.data)
        data.update(changes)
        self.store.db.execute("UPDATE action SET result=? WHERE id='target-sync'",
            (canonical({'data': data}),))

    def test_selected_3_to_2_claim_reconciles_104_once_and_preserves_other_reserves(self):
        untouched = [(name, self.row(name)['result'], self.row(name)['state'])
            for name in ['old-a', 'old-b', 'selected', 'payer', 'earlier-sync']]
        before = self.store.remaining_fee_budget()
        asyncio.run(collect(self.store, None, limit=100))
        self.assertEqual(104, self.row()['actual_fee_sat'])
        self.assertEqual(1896, self.store.remaining_fee_budget() - before)
        for name, result, state in untouched:
            self.assertIsNone(self.row(name)['actual_fee_sat'])
            self.assertEqual((result, state), (self.row(name)['result'], self.row(name)['state']))
        asyncio.run(collect(self.store, None, limit=100))
        self.assertEqual(1, self.store.db.execute("SELECT COUNT(*) FROM event WHERE kind='client_fee_reconciled'").fetchone()[0])
        self.assertEqual(0, self.store.db.execute("SELECT COUNT(*) FROM event WHERE kind='fee_reservation_released'").fetchone()[0])
        self.store.verify_event_chain()

    def test_incomplete_or_changed_selected_boundary_keeps_reservation(self):
        variants = [
            {'selected_receive_payment_hashes': []},
            {'selected_receive_payment_hashes': [self.old_a]},
            {'selected_receive_payment_hashes': [self.target, self.target]},
            {'bounded_receive_sync': False},
            {'receive_count_after': 3, 'receive_payment_hashes_after': [self.old_a, self.old_b, self.target]},
            {'receive_count_after': 1, 'receive_payment_hashes_after': [self.old_a]},
            {'receive_payment_hashes_after': [self.old_a, 'd' * 64]},
            {'receive_payment_hashes_before': [self.target, self.target, self.old_a]},
            {'receive_payment_hashes_before': None, 'receive_payment_hashes_after': None},
            {'receive_count_after': 1},
        ]
        for changes in variants:
            with self.subTest(changes=changes):
                self.update(**changes)
                with self.assertRaises(EvidenceGap): receive_fee(self.store, self.row())
                self.assertIsNone(self.row()['actual_fee_sat'])

    def test_untargeted_partial_sync_keeps_legacy_whole_reservation(self):
        self.store.db.execute("UPDATE action SET args='{}' WHERE id='target-sync'")
        with self.assertRaises(EvidenceGap): receive_fee(self.store, self.row())

    def test_missing_success_cancelled_or_preexisting_claim_is_not_free(self):
        variants = [[], [{**self.movement, 'status': 'pending'}],
            [{**self.movement, 'status': 'failed'}]]
        for movements in variants:
            with self.subTest(movements=movements):
                self.update(evidence={'movements': movements, 'coins': []})
                with self.assertRaises(EvidenceGap): receive_fee(self.store, self.row())
        self.update(before_evidence={'movements': [self.movement], 'coins': []})
        with self.assertRaises(EvidenceGap): receive_fee(self.store, self.row())

    def test_changed_unrelated_movement_is_held(self):
        pending = {**self.movement, 'id': 'old', 'payment_hash': self.old_a,
            'status': 'pending', 'output_vtxos': [], 'offchain_fee_sat': 0, 'effective_balance_sat': 0}
        self.data['before_evidence'] = {'movements': [pending], 'coins': []}
        self.update(evidence={'movements': [self.movement, {**pending, 'status': 'failed'}], 'coins': []})
        with self.assertRaises(EvidenceGap): receive_fee(self.store, self.row())

    def test_additional_unselected_success_is_held(self):
        extra = {**self.movement, 'id': '58', 'payment_hash': self.old_a}
        self.update(evidence={'movements': [self.movement, extra], 'coins': []})
        with self.assertRaises(EvidenceGap): receive_fee(self.store, self.row())

    def test_selected_success_must_equal_independently_recorded_boundary(self):
        self.store.db.execute("UPDATE movement_evidence SET payload=? WHERE movement_id='57'",
            (canonical({**self.movement, 'output_vtxos': ['foreign']}),))
        with self.assertRaises(EvidenceGap): receive_fee(self.store, self.row())

    def test_wrong_owner_signed_value_missing_proof_and_reserve_overflow_are_held(self):
        self.store.db.execute("UPDATE owner_key SET actor='actor-02'")
        with self.assertRaises(InvariantError): receive_fee(self.store, self.row())
        self.store.db.execute('UPDATE owner_key SET actor=?', (self.actor,))
        self.store.db.execute('UPDATE owned_coin SET amount_sat=1895')
        with self.assertRaises(InvariantError): receive_fee(self.store, self.row())
        self.store.db.execute('UPDATE owned_coin SET amount_sat=1896')
        self.store.db.execute("UPDATE action SET fee_reservation_sat=103 WHERE id='target-sync'")
        with self.assertRaises(InvariantError): receive_fee(self.store, self.row())
        self.store.db.execute('DELETE FROM owned_coin')
        with self.assertRaises(EvidenceGap): receive_fee(self.store, self.row())

    def test_changed_frozen_target_or_invoice_binding_is_an_incident(self):
        self.store.db.execute("UPDATE action SET args=? WHERE id='target-sync'",
            (canonical({**self.args, 'receive_payment_hash': self.old_a}),))
        with self.assertRaises(InvariantError): receive_fee(self.store, self.row())
        self.action('wrong-invoice-binding', self.actor, 'sync',
            {**self.args, 'recipient_invoice_action': 'old-a'}, self.data)
        with self.assertRaises(InvariantError): receive_fee(self.store, self.row('wrong-invoice-binding'))

    def test_original_invoice_principal_cannot_be_changed(self):
        self.store.db.execute("UPDATE action SET args=? WHERE id='selected'", (canonical({'amount_sat': 2001}),))
        with self.assertRaises(InvariantError): receive_fee(self.store, self.row())

    def test_claim_cannot_be_assigned_again_under_another_movement_id(self):
        for claimed in [{'payment_hash': self.target}, {'invoice_action_id': 'selected'}, {'output_coin_ids': ['received']}]:
            with self.subTest(claimed=claimed):
                self.store.db.execute("DELETE FROM event WHERE kind='client_fee_reconciled'")
                self.store.event('client_fee_reconciled', {'actor': self.actor, 'action_id': 'other-sync',
                    'receive_movement_ids': ['different'], 'claims': [claimed]})
                with self.assertRaises(InvariantError): receive_fee(self.store, self.row())

    def test_duplicate_history_and_customer_inputs_do_not_qualify(self):
        self.update(evidence={'movements': [self.movement, self.movement], 'coins': []})
        with self.assertRaises(EvidenceGap): receive_fee(self.store, self.row())
        self.update(evidence={'movements': [{**self.movement, 'input_vtxos': ['customer-input']}], 'coins': []})
        self.store.db.execute("UPDATE movement_evidence SET payload=? WHERE movement_id='57'",
            (canonical({**self.movement, 'input_vtxos': ['customer-input']}),))
        with self.assertRaises(InvariantError): receive_fee(self.store, self.row())

    def test_declared_cancellation_or_unresolved_target_is_not_charged_as_success(self):
        for changes in [{'target_receive_terminal': flag} for flag in [False, None, 'true', 1]] + [
                {'receive_canceled_payment_hashes': [self.target]}, {'receive_canceled_payment_hashes': None}]:
            with self.subTest(changes=changes):
                self.update(**changes)
                with self.assertRaises(EvidenceGap): receive_fee(self.store, self.row())

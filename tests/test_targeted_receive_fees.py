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

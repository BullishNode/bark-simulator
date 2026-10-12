"""Reservation tests using native coin_evidence shape (no pending-receive IDs).

The empty-invoice fixture records b=1,a=1 with movements=[]; the pending
invoice is known only through its earlier frozen invoice action. Successful
claim cost must remain on the later sync that independently proves its outputs.
"""
import asyncio
import copy
import json
import tempfile
import unittest
from pathlib import Path

from simulator.engine import initialize
from simulator.fees import collect
from simulator.model import canonical
from simulator.store import Store


class PendingSyncReclaimTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.s = Store(Path(self.tmp.name), 'synthetic', 100000)
        initialize(self.s)
        self.actor = 'actor-06'
        self.key = '02' + '11' * 32
        self.hash = 'a' * 64
        self.s.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',
                          (self.key, self.actor, 'mailbox', '{}'))
        self.s.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',
                          ('received', self.key, 1900, 'digest', 'signed', '{}'))
        self.movement = {'id': '1', 'subsystem': 'bark.lightning_receive',
                         'status': 'successful', 'payment_hash': self.hash,
                         'input_vtxos': [], 'output_vtxos': ['received'],
                         'offchain_fee_sat': 100, 'effective_balance_sat': 1900}
        self.s.db.execute('INSERT INTO movement_evidence VALUES (?,?,?)',
                          (self.actor, '1', canonical(self.movement)))
        self.invoice('invoice', self.hash)
        self.sync('early', self.boundary(1, 1))
        self.sync('proof', self.boundary(1, 0, after=[self.movement]))

    def tearDown(self):
        self.s.close()
        self.tmp.cleanup()

    def evidence(self, movements):
        # Native evidence includes coins, movements and binding. Pending invoices
        # are absent from history until the SDK creates a claim movement.
        return {'coins': [], 'movements': copy.deepcopy(movements),
                'binding': {'mailbox_pk': self.key, 'spk': '0014' + '22' * 20,
                            'seq': 1, 'record_attestation': 'public',
                            'onchain_ownership_checked': True}}

    def boundary(self, before_count, after_count, before=(), after=()):
        return {'requested': 'sync', 'actual_fee_sat': None,
                'receive_count_before': before_count,
                'receive_count_after': after_count,
                'before_evidence': self.evidence(before),
                'evidence': self.evidence(after)}

    def action(self, name, operation, args, data, actor=None):
        self.s.queue(name, actor or self.actor, 'H06', operation, args, 2000)
        self.s.db.execute("UPDATE action SET state='dispatched' WHERE id=?", (name,))
        self.s.finish(name, 'completed', {'data': data})

    def invoice(self, name, payment_hash):
        self.action(name, 'invoice', {'amount_sat': 2000},
                    {'payment_hash': payment_hash, 'estimated_claim_fee_sat': 100})

    def sync(self, name, data):
        self.action(name, 'sync', {}, data)

    def change_data(self, name, **values):
        row = self.s.db.execute('SELECT result FROM action WHERE id=?', (name,)).fetchone()
        result = json.loads(row[0])
        result['data'].update(values)
        self.s.db.execute('UPDATE action SET result=? WHERE id=?', (canonical(result), name))

    def fee(self, name):
        return self.s.db.execute('SELECT actual_fee_sat FROM action WHERE id=?', (name,)).fetchone()[0]

    def collect(self):
        asyncio.run(collect(self.s, None, limit=100))

    def test_native_pending_empty_history_releases_only_after_later_proven_claim(self):
        # Independent receive proof is deliberately withheld on the first pass.
        self.s.db.execute('DELETE FROM owned_coin')
        self.collect()
        self.assertIsNone(self.fee('early'))
        self.assertIsNone(self.fee('proof'))
        self.s.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',
                          ('received', self.key, 1900, 'digest', 'signed', '{}'))
        before_budget = self.s.remaining_fee_budget()
        self.collect()
        self.assertEqual(0, self.fee('early'))
        self.assertEqual(100, self.fee('proof'))
        self.assertEqual(3900, self.s.remaining_fee_budget() - before_budget)
        releases = self.s.db.execute("SELECT payload FROM event WHERE kind='fee_reservation_released'").fetchall()
        self.assertEqual(1, len(releases))
        release = json.loads(releases[0][0])
        self.assertEqual('early', release['action_id'])
        self.assertEqual('proof', release['proving_action_id'])
        self.assertEqual(['1'], release['receive_movement_ids'])
        self.assertEqual(2000, release['released_reservation_sat'])
        self.s.verify_event_chain()


if __name__ == '__main__':
    unittest.main()

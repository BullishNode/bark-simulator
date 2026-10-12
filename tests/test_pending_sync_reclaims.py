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

    def test_repeated_collection_closes_claim_and_earlier_reserve_exactly_once(self):
        original_results = list(self.s.db.execute('SELECT id,result FROM action ORDER BY id'))
        self.collect()
        budget = self.s.remaining_fee_budget()
        self.collect()
        self.collect()
        self.assertEqual(budget, self.s.remaining_fee_budget())
        self.assertEqual(original_results, list(self.s.db.execute('SELECT id,result FROM action ORDER BY id')))
        self.assertEqual(1, self.s.db.execute("SELECT count(*) FROM event WHERE kind='fee_reservation_released'").fetchone()[0])
        self.assertEqual(1, self.s.db.execute("SELECT count(*) FROM event WHERE kind='client_fee_reconciled'").fetchone()[0])
        self.assertEqual(100, self.fee('proof'))
        self.s.verify_event_chain()

    def test_previously_reconciled_claim_reclaims_legacy_reserve_on_first_collection(self):
        from simulator.fees import receive_fee
        action = self.s.db.execute("SELECT * FROM action WHERE id='proof'").fetchone()
        evidence = receive_fee(self.s, action)
        self.s.db.execute("UPDATE action SET actual_fee_sat=100 WHERE id='proof'")
        self.s.event('client_fee_reconciled', {'action_id': 'proof', **evidence})
        self.collect()
        self.assertEqual(0, self.fee('early'))
        self.assertEqual(100, self.fee('proof'))

    def assert_reserved(self):
        self.collect()
        self.assertIsNone(self.fee('early'))
        self.assertEqual(0, self.s.db.execute("SELECT count(*) FROM event WHERE kind='fee_reservation_released'").fetchone()[0])

    def test_partial_claim_completion_stays_reserved(self):
        self.change_data('proof', receive_count_after=1)
        self.assert_reserved()

    def test_changed_pending_count_stays_reserved(self):
        self.change_data('early', receive_count_after=2)
        self.assert_reserved()

    def test_changed_movement_history_stays_reserved(self):
        self.change_data('early', evidence=self.evidence([self.movement]))
        self.assert_reserved()

    def test_changed_legacy_coin_inventory_stays_reserved(self):
        evidence = self.evidence([])
        evidence['coins'] = [{'id': 'unexplained', 'amount_sat': 10}]
        self.change_data('early', evidence=evidence)
        self.assert_reserved()

    def test_missing_legacy_coin_inventory_stays_reserved(self):
        self.change_data('early', before_evidence={'movements': []})
        self.assert_reserved()

    def test_missing_before_or_after_history_stays_reserved(self):
        self.change_data('early', evidence={'coins': []})
        self.assert_reserved()

    def test_ambiguous_prior_invoice_count_stays_reserved(self):
        self.invoice('unpaid', 'b' * 64)
        self.s.db.execute("UPDATE action SET created_at=0,updated_at=0 WHERE id='unpaid'")
        self.assert_reserved()

    def test_missing_prior_invoice_stays_reserved(self):
        self.s.db.execute("DELETE FROM action WHERE id='invoice'")
        self.assert_reserved()

    def test_unknown_prior_invoice_call_stays_reserved(self):
        self.s.db.execute("UPDATE action SET state='outcome_unknown' WHERE id='invoice'")
        self.assert_reserved()

    def test_dispatched_prior_invoice_call_stays_reserved(self):
        self.s.db.execute("UPDATE action SET state='dispatched' WHERE id='invoice'")
        self.assert_reserved()

    def test_invoice_completed_after_earlier_boundary_stays_reserved(self):
        self.s.db.execute("UPDATE action SET updated_at=updated_at+3600 WHERE id='invoice'")
        self.assert_reserved()

    def test_new_invoice_between_legacy_boundaries_stays_reserved(self):
        self.invoice('new', 'b' * 64)
        early = self.s.db.execute("SELECT updated_at FROM action WHERE id='early'").fetchone()[0]
        proof = self.s.db.execute("SELECT created_at FROM action WHERE id='proof'").fetchone()[0]
        self.s.db.execute("UPDATE action SET created_at=? WHERE id='new'", ((early + proof)/2,))
        self.assert_reserved()

    def test_foreign_actor_proof_stays_reserved(self):
        self.s.db.execute("UPDATE action SET actor_id='actor-02' WHERE id='early'")
        self.assert_reserved()

    def test_dispatched_or_unknown_earlier_sync_stays_reserved(self):
        for state in ['dispatched', 'outcome_unknown']:
            with self.subTest(state=state):
                self.s.db.execute("UPDATE action SET state=? WHERE id='early'", (state,))
                self.assert_reserved()

    def test_later_unknown_or_dispatched_sync_stays_reserved(self):
        for state in ['dispatched', 'outcome_unknown']:
            with self.subTest(state=state):
                self.s.db.execute("UPDATE action SET state=? WHERE id='proof'", (state,))
                self.assert_reserved()

    def test_count_without_matching_identity_cannot_release_another_invoice(self):
        self.s.db.execute("UPDATE action SET created_at=created_at+3600 WHERE id='invoice'")
        self.assert_reserved()

    def test_fee_number_without_reconciliation_event_is_insufficient(self):
        self.s.db.execute("UPDATE action SET actual_fee_sat=100 WHERE id='proof'")
        self.assert_reserved()

    def test_missing_independently_recorded_movement_stays_reserved(self):
        self.s.db.execute('DELETE FROM movement_evidence')
        self.assert_reserved()

    def test_missing_signed_output_proof_stays_reserved(self):
        self.s.db.execute('DELETE FROM owned_coin')
        self.assert_reserved()

    def test_explicit_native_pending_identities_release(self):
        self.change_data('early', receive_payment_hashes_before=[self.hash],
                         receive_payment_hashes_after=[self.hash])
        self.change_data('proof', receive_payment_hashes_before=[self.hash],
                         receive_payment_hashes_after=[])
        self.collect()
        self.assertEqual(0, self.fee('early'))
        self.assertEqual(100, self.fee('proof'))

    def test_changed_native_hash_with_same_count_stays_reserved(self):
        self.change_data('early', receive_payment_hashes_before=[self.hash],
                         receive_payment_hashes_after=['b' * 64])
        self.assert_reserved()

    def test_missing_half_of_native_hash_boundary_stays_reserved(self):
        self.change_data('early', receive_payment_hashes_before=[self.hash])
        self.assert_reserved()

    def test_native_hash_count_mismatch_stays_reserved(self):
        self.change_data('early', receive_payment_hashes_before=[self.hash, self.hash],
                         receive_payment_hashes_after=[self.hash, self.hash])
        self.assert_reserved()

    def test_unrelated_native_pending_identity_stays_reserved(self):
        self.change_data('early', receive_payment_hashes_before=['b' * 64],
                         receive_payment_hashes_after=['b' * 64])
        self.assert_reserved()

    def test_changed_proving_native_hash_keeps_both_reserves(self):
        self.change_data('proof', receive_payment_hashes_before=['b' * 64],
                         receive_payment_hashes_after=[])
        self.assert_reserved()
        self.assertIsNone(self.fee('proof'))

    def test_proving_only_one_of_two_pending_invoices_stays_reserved(self):
        self.invoice('other', 'b' * 64)
        self.s.db.execute("UPDATE action SET created_at=0,updated_at=0 WHERE id='other'")
        self.change_data('early', receive_count_before=2, receive_count_after=2)
        self.assert_reserved()
        self.assertEqual(100, self.fee('proof'))

    def test_all_pending_claims_must_be_proved_and_charged_once(self):
        self.invoice('other', 'b' * 64)
        self.s.db.execute("UPDATE action SET created_at=0,updated_at=0 WHERE id='other'")
        self.s.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',
                          ('received2', self.key, 1900, 'digest2', 'signed2', '{}'))
        other = {**self.movement, 'id': '2', 'payment_hash': 'b' * 64,
                 'output_vtxos': ['received2']}
        self.s.db.execute('INSERT INTO movement_evidence VALUES (?,?,?)',
                          (self.actor, '2', canonical(other)))
        self.change_data('early', receive_count_before=2, receive_count_after=2)
        self.change_data('proof', receive_count_before=2,
                         evidence=self.evidence([self.movement, other]))
        self.collect()
        self.assertEqual(0, self.fee('early'))
        self.assertEqual(200, self.fee('proof'))
        self.collect()
        self.assertEqual(1, self.s.db.execute("SELECT count(*) FROM event WHERE kind='client_fee_reconciled'").fetchone()[0])

    def test_old_successful_claim_is_excluded_from_inferred_pending_invoices(self):
        self.invoice('old', 'b' * 64)
        self.s.db.execute("UPDATE action SET created_at=0,updated_at=0 WHERE id='old'")
        old = {**self.movement, 'id': '0', 'payment_hash': 'b' * 64,
               'output_vtxos': ['oldcoin']}
        self.change_data('early', before_evidence=self.evidence([old]), evidence=self.evidence([old]))
        self.change_data('proof', before_evidence=self.evidence([old]),
                         evidence=self.evidence([old, self.movement]))
        self.collect()
        self.assertEqual(0, self.fee('early'))
        self.assertEqual(100, self.fee('proof'))

    def test_multiple_unchanged_syncs_release_against_same_once_only_claim(self):
        self.sync('early2', self.boundary(1, 1))
        self.s.db.execute("UPDATE action SET created_at=created_at+3600,updated_at=updated_at+3600 WHERE id='proof'")
        self.collect()
        self.assertEqual(0, self.fee('early'))
        self.assertEqual(0, self.fee('early2'))
        self.assertEqual(100, self.fee('proof'))
        self.collect()
        self.assertEqual(2, self.s.db.execute("SELECT count(*) FROM event WHERE kind='fee_reservation_released'").fetchone()[0])

    def test_earlier_pending_native_movement_must_match_proven_claim_identity(self):
        pending = {**self.movement, 'status': 'pending', 'input_vtxos': [],
                   'output_vtxos': [], 'effective_balance_sat': 0, 'offchain_fee_sat': 0}
        self.change_data('early', before_evidence=self.evidence([pending]), evidence=self.evidence([pending]))
        self.change_data('proof', before_evidence=self.evidence([pending]))
        self.collect()
        self.assertEqual(0, self.fee('early'))
        self.assertEqual(100, self.fee('proof'))

    def test_duplicate_history_id_is_ambiguous_and_stays_reserved(self):
        self.change_data('early', before_evidence=self.evidence([self.movement, self.movement]),
                         evidence=self.evidence([self.movement, self.movement]))
        self.assert_reserved()

    def test_changed_explicit_coin_inventory_stays_reserved(self):
        self.change_data('early', receive_payment_hashes_before=[self.hash],
                         receive_payment_hashes_after=[self.hash])
        evidence = self.evidence([])
        evidence['coins'] = [{'id': 'unexplained', 'amount_sat': 10}]
        self.change_data('early', evidence=evidence)
        self.assert_reserved()

    def test_zero_count_does_not_fabricate_pending_claim_release(self):
        self.change_data('early', receive_count_before=0, receive_count_after=0)
        self.assert_reserved()

    def test_duplicate_reconciliation_is_ambiguous_and_stays_reserved(self):
        from simulator.fees import receive_fee
        action = self.s.db.execute("SELECT * FROM action WHERE id='proof'").fetchone()
        evidence = receive_fee(self.s, action)
        self.s.db.execute("UPDATE action SET actual_fee_sat=100 WHERE id='proof'")
        for _ in range(2):
            self.s.event('client_fee_reconciled', {'action_id': 'proof', **evidence})
        self.assert_reserved()

    def test_changed_reconciliation_payload_stays_reserved(self):
        from simulator.fees import receive_fee
        action = self.s.db.execute("SELECT * FROM action WHERE id='proof'").fetchone()
        evidence = receive_fee(self.s, action)
        self.s.db.execute("UPDATE action SET actual_fee_sat=100 WHERE id='proof'")
        self.s.event('client_fee_reconciled', {'action_id': 'proof', **evidence, 'claims': []})
        self.assert_reserved()

    def test_proving_action_must_follow_earlier_completed_sync(self):
        self.s.db.execute("UPDATE action SET updated_at=updated_at+3600 WHERE id='early'")
        self.assert_reserved()


if __name__ == '__main__':
    unittest.main()

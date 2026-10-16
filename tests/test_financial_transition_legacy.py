"""Synthetic integration controls, never native or live money qualification."""
import unittest
from unittest.mock import patch
from simulator import financial_transition as transition
from simulator.store import Store
from tests import test_financial_transition as fixtures


class LegacyTransitionProposal(unittest.TestCase):
    def setUp(self):
        original = Store.event
        def retained_legacy(store, kind, payload):
            if kind == 'financial_cost_verified' and payload.get('monetary_id', '').startswith('miner:'):
                payload = {k: v for k, v in payload.items() if k not in ('kind', 'txid')}
                payload['monetary_id'] = 'bitcoin-' + payload['monetary_id']
            return original(store, kind, payload)
        self.case = fixtures.FinancialTransitionTests()
        with patch.object(Store, 'event', retained_legacy):
            self.case.setUp()
        self.store = self.case.store

    def tearDown(self): self.case.tearDown()

    def test_original_legacy_opening_validates_without_rewriting(self):
        before = self.store.db.execute('SELECT * FROM event WHERE sequence=?', (self.case.cost_seq,)).fetchone()
        before = tuple(before)
        result = self.case.validate()
        self.assertEqual(result['historical_miner_cost_msat'], 1000)
        self.assertEqual(tuple(self.store.db.execute('SELECT * FROM event WHERE sequence=?', (self.case.cost_seq,)).fetchone()), before)
        self.store.verify_event_chain()

    def test_existing_one_msat_cost_mismatch_still_refuses(self):
        self.case.chain.transaction = lambda txid: {'txid': txid, 'confirmations': 1, 'fee_sat': 2}
        with self.assertRaises(ValueError): self.case.validate()

    def test_unconfirmed_original_still_refuses(self):
        self.case.chain.transaction = lambda txid: {'txid': txid, 'confirmations': 0, 'fee_sat': 1}
        with self.assertRaises(ValueError): self.case.validate()

    def test_two_aliases_same_actual_fee_refused(self):
        self.store.event('financial_cost_verified', {'kind': 'miner_cost', 'txid': 'b' * 64,
                         'monetary_id': 'miner:' + 'b' * 64, 'amount_msat': 1000, 'budget': 'ordinary'})
        self.case.readiness['preserved_history_opening']['historical_cost_sequences'].append(self.case.seq())
        self.case.source()
        with self.assertRaises(ValueError): self.case.validate()

    def test_explicit_conflicting_legacy_identity_refuses(self):
        self.store.event('financial_cost_verified', {'monetary_id': 'bitcoin-miner:' + 'c' * 64,
                         'kind': 'miner_cost', 'txid': 'd' * 64, 'amount_msat': 1000, 'budget': 'ordinary'})
        with self.assertRaises(ValueError): transition._original_miner_cost(self.store, self.case.seq())


if __name__ == '__main__': unittest.main(verbosity=2)

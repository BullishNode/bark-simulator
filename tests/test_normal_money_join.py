"""Append-only journal controls with isolated synthetic Stores; no money proof."""
import copy
from pathlib import Path
import tempfile
import unittest

from simulator.final_campaign import _source_event
from simulator.normal_money_join import journal_money_sources
from simulator.store import Store
from tests.test_final_campaign import PINS


class MoneyJournalJoinTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        self.store = Store(Path(directory.name), 'synthetic-money-join', 60000)
        self.addCleanup(self.store.close); self.store.attach_trace()
        self.source = {'financial_pins': copy.deepcopy(PINS)}
        self.store.event('normal_financial_source', self.source)
        self.parent, _ = _source_event(self.store, 1)
        self.txid = 'b'*64
        self.cost = {'monetary_id': 'miner:'+self.txid, 'kind': 'miner_cost',
            'txid': self.txid, 'amount_msat': 1000, 'budget': 'ordinary',
            'source': 'operator', 'destination': 'miners', 'financial_pins': copy.deepcopy(PINS)}
        self.flow = {'monetary_id': 'injection:synthetic', 'kind': 'injection',
            'amount_msat': 1000, 'source': 'bank', 'destination': 'operator',
            'financial_pins': copy.deepcopy(PINS)}

    def result(self, costs=(), flows=()):
        return {'cost_records': list(costs), 'flow_records': list(flows),
            'reused_cost_ids': [], 'reused_flow_ids': [], 'evidence_hashes': {},
            'zero_fee_carriers': {}, 'pending_carriers': {}, 'client_service_charges': []}

    def join(self, result):
        return journal_money_sources(self.store, result, self.parent, self.source,
            helper_sha256='a'*64)

    def rows(self):
        return self.store.db.execute('SELECT sequence,kind,payload,hash FROM event ORDER BY sequence').fetchall()

    def test_once_only_cost_flow_and_original_source_join(self):
        event, joined = self.join(self.result([self.cost], [self.flow]))
        self.assertEqual('normal_financial_source_cost_join', event['kind'])
        self.assertEqual(self.parent['hash'], joined['original_source_hash'])
        self.assertEqual([2], joined['cost_sequences']); self.assertEqual([3], joined['flow_sequences'])
        self.join(self.result([self.cost], [self.flow]))
        self.assertEqual(1, self.store.db.execute("SELECT count(*) FROM event WHERE kind='financial_cost_verified'").fetchone()[0])
        self.assertEqual(1, self.store.db.execute("SELECT count(*) FROM event WHERE kind='treasury_flow_verified'").fetchone()[0])
        self.assertEqual(0, self.store.db.execute("SELECT count(*) FROM event WHERE kind='financial_operating_readiness'").fetchone()[0])
        self.store.verify_event_chain()

    def test_new_cost_cannot_reuse_existing_flow_id(self):
        flow = {**self.flow, 'monetary_id': self.cost['monetary_id']}
        self.store.event('treasury_flow_verified', flow); before = self.rows()
        with self.assertRaises(ValueError): self.join(self.result([self.cost]))
        self.assertEqual(before, self.rows())

    def test_new_flow_cannot_reuse_existing_cost_id(self):
        self.store.event('financial_cost_verified', self.cost); before = self.rows()
        flow = {**self.flow, 'monetary_id': self.cost['monetary_id']}
        with self.assertRaises(ValueError): self.join(self.result(flows=[flow]))
        self.assertEqual(before, self.rows())

    def test_original_cost_cannot_be_rewritten(self):
        self.store.event('financial_cost_verified', self.cost); before = self.rows()
        with self.assertRaisesRegex(ValueError, 'cannot be rewritten'):
            self.join(self.result([{**self.cost, 'amount_msat': 2000}]))
        self.assertEqual(before, self.rows())

    def test_duplicate_new_record_across_kinds_refuses_atomically(self):
        flow = {**self.flow, 'monetary_id': self.cost['monetary_id']}; before = self.rows()
        with self.assertRaisesRegex(ValueError, 'supplied twice'):
            self.join(self.result([self.cost], [flow]))
        self.assertEqual(before, self.rows())

    def test_missing_original_reused_record_refuses(self):
        value = self.result(); value['reused_cost_ids'] = ['miner:'+self.txid]; before = self.rows()
        with self.assertRaisesRegex(ValueError, 'existing immutable'):
            self.join(value)
        self.assertEqual(before, self.rows())

    def test_changed_source_hash_cannot_append_money(self):
        self.parent = {**self.parent, 'hash': 'c'*64}; before = self.rows()
        with self.assertRaisesRegex(ValueError, 'original financial source'):
            self.join(self.result([self.cost]))
        self.assertEqual(before, self.rows())

    def test_wrong_pins_do_not_append_partial_costs(self):
        changed = {**self.flow, 'financial_pins': {}}; before = self.rows()
        with self.assertRaisesRegex(ValueError, 'identity/pins'):
            self.join(self.result([self.cost], [changed]))
        self.assertEqual(before, self.rows())

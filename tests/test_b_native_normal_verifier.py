"""Synthetic source controls only. No actual signatures/native/Core qualification."""
import copy
import sqlite3
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from simulator import b_native_normal_verifier as native
from simulator import direct_settlements as direct
from simulator.final_campaign import _source_event
from simulator.model import InvariantError
from simulator.ownership import EvidenceGap
from tests import test_public_absence as fixtures


class DirectControls(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.PublicAbsenceControls(); self.f.setUp(); self.store = self.f.store
        _, journey = _source_event(self.store, self.f.journey)
        _, original = _source_event(self.store, journey['source_sequence'])
        self.baseline = original['database']
        ids = original['server']['recipient_coins'] + original['server']['change_coins']
        self.leaves = {}
        for point in ids:
            row = self.store.db.execute('SELECT * FROM owned_coin WHERE id=?', (point,)).fetchone()
            actor = 'actor-02' if point in original['server']['recipient_coins'] else 'actor-01'
            self.leaves[point] = {'actor': actor, 'pubkey': row['pubkey'], 'amount_sat': row['amount_sat'],
                                  'script': self.f.records[actor]['spk']}
        self.scripts = {self.f.script(member['id'] + ':' + str(i)):
                        {'member_id': member['id'], 'descriptor_index': 0, 'child_index': i}
                        for member in self.f.members for i in range(20)}
        direct.initialize(self.store)
        for script, owner in self.scripts.items():
            if owner['member_id'] in {'rounds', 'watchman'}:
                self.store.db.execute('INSERT INTO operator_script VALUES (?,?)', (script, '{}'))
    def tearDown(self): self.f.tearDown()
    def run_snapshot(self):
        return native.direct_snapshot(self.store, self.f.chain, self.f.database, self.baseline,
            self.leaves, self.scripts, (self.f.height, self.f.tip), minimum_confirmations=1)
    def test_full_original_signed_group_confirms_without_any_store_write(self):
        txid = self.f.confirmed(); before = self.store.db.total_changes
        result = self.run_snapshot()
        self.assertEqual(before, self.store.db.total_changes)
        self.assertEqual(txid, result['groups'][0]['transaction']['txid'])
        self.assertEqual(0, result['outstanding_liability_sat'])
        self.assertEqual(19670, sum(row['amount_sat'] for row in result['liabilities']))
    def test_other_architecture_is_not_implicitly_admitted(self):
        with patch.object(native, 'profile', return_value='direct_per_key'):
            with self.assertRaisesRegex(EvidenceGap, 'requires direct_xpub'): self.run_snapshot()
    def test_frozen_or_mempool_never_retires_liability(self):
        txid = self.f.confirmed(); self.f.transactions[txid]['confirmations'] = 0
        with self.assertRaisesRegex(EvidenceGap, 'no sufficiently confirmed winner'): self.run_snapshot()
    def test_wrong_mapped_original_owner_and_changed_signed_body_hold(self):
        txid = self.f.confirmed(); self.f.database['rows']['journal_allocations'][0]['owner_pubkey'] = '02' + '7'*64
        with self.assertRaises(InvariantError): self.run_snapshot()
        self.f.database['rows']['journal_allocations'][0]['owner_pubkey'] = self.f.f.recipient_pk
        self.f.raw_transactions[txid]['weight'] += 1
        with self.assertRaisesRegex(EvidenceGap, 'signed body/weight'): self.run_snapshot()
    def test_unsupported_pool_receive_rows_and_unaccounted_graph_hold(self):
        self.f.database['rows']['pool'] = [{'id': 'unsupported'}]
        with self.assertRaisesRegex(EvidenceGap, 'unsupported LN/pool/round'): self.run_snapshot()
        self.f.database['rows']['pool'] = []; self.f.database['rows']['coins'].pop()
        with self.assertRaisesRegex(EvidenceGap, 'extra or missing'): self.run_snapshot()
    def test_urgent_whole_selected_input_cannot_credit_change(self):
        wallet = self.f.current['watchman_inventory']['watchman']
        point = wallet['utxos'][0]['outpoint']
        with self.assertRaisesRegex(EvidenceGap, 'whole-input'): native.urgent_reserve(
            wallet, self.f.physical, {point}, self.f.chain, minimum_sat=15000)
        result = native.urgent_reserve(wallet, self.f.physical, set(), self.f.chain, minimum_sat=15000)
        self.assertEqual({point: 75000}, result)
    def test_urgent_current_native_set_or_confirmed_eligibility_gap_holds(self):
        wallet = copy.deepcopy(self.f.current['watchman_inventory']['watchman'])
        wallet['utxos'][0]['trusted'] = False
        with self.assertRaisesRegex(EvidenceGap, 'whole-input'): native.urgent_reserve(
            wallet, self.f.physical, set(), self.f.chain, minimum_sat=15000)
        wallet['utxos'] = []
        with self.assertRaisesRegex(EvidenceGap, 'full cash set'): native.urgent_reserve(
            wallet, self.f.physical, set(), self.f.chain, minimum_sat=15000)


class MonetaryControls(unittest.TestCase):
    def test_historical_injection_spent_internally_replaces_original_once(self):
        initial = {'outside:0': {'amount_sat': 10, 'script': 'old', 'member_id': 'bank'}}
        tx = {'txid': 'a'*64, 'confirmations': 3, 'inputs': [{'outpoint': 'neutral:0', 'script': 'neutral'}],
              'outputs': [{'vout': 0, 'amount_sat': 100, 'script': 'bank'}]}
        scripts = {'bank': {'member_id': 'bank'}, 'watch': {'member_id': 'watchman'}}
        opening = native.add_original_injection(initial, tx, outpoint='a'*64+':0', amount_sat=100, scripts=scripts)
        spend = {'txid': 'b'*64, 'confirmations': 2,
            'inputs': [{'outpoint': 'a'*64+':0', 'amount_sat': 100, 'script': 'bank'}],
            'outputs': [{'vout': 0, 'amount_sat': 80, 'script': 'bank'}, {'vout': 1, 'amount_sat': 17, 'script': 'watch'}], 'fee_sat': 3}
        frontier = native.confirmed_frontier(opening, [spend], scripts)
        self.assertNotIn('a'*64+':0', frontier); self.assertEqual(107, sum(v['amount_sat'] for v in frontier.values()))
        with self.assertRaisesRegex(InvariantError, 'already counted'):
            native.add_original_injection(opening, tx, outpoint='a'*64+':0', amount_sat=100, scripts=scripts)
        with self.assertRaises(InvariantError): native.confirmed_frontier(opening, [spend, spend], scripts)
    def test_unconfirmed_or_unknown_injection_is_not_income(self):
        tx = {'txid': 'a'*64, 'confirmations': 0, 'inputs': [], 'outputs': []}
        with self.assertRaisesRegex(EvidenceGap, 'confirmed'): native.add_original_injection(
            {}, tx, outpoint='a'*64+':0', amount_sat=100, scripts={})
    def test_original_cost_alias_duplicate_and_internal_service_mismatch_refuse(self):
        db = sqlite3.connect(':memory:'); db.execute('CREATE TABLE event(sequence INTEGER,kind TEXT)')
        db.executemany('INSERT INTO event VALUES (?,?)', [(1,'financial_cost_verified'),(2,'financial_cost_verified')])
        txid = 'a'*64
        def event(store, sequence): return ({'sequence': sequence, 'hash': str(sequence)},
            {'monetary_id': ('bitcoin-miner:' if sequence == 1 else 'miner:') + txid,
             'amount_msat': 171000, 'budget': 'ordinary'})
        chain = SimpleNamespace(transaction=lambda value: {'txid': value, 'confirmations': 2, 'fee_sat': 171})
        with patch.object(native, '_source_event', side_effect=event):
            with self.assertRaisesRegex(InvariantError, 'physical miner transaction counted twice'):
                native.original_costs(SimpleNamespace(db=db), chain)
            db.execute('DELETE FROM event WHERE sequence=2')
            self.assertEqual(171000, native.original_costs(SimpleNamespace(db=db), chain)[0]['amount_msat'])
            chain.transaction = lambda value: {'txid': value, 'confirmations': 2, 'fee_sat': 501}
            with self.assertRaisesRegex(EvidenceGap, 'independent miner fee differs'):
                native.original_costs(SimpleNamespace(db=db), chain)
        db.close()
    def test_disk_false_or_caller_true_flags_never_prove_loaded_budget(self):
        for value in [None, {'disk_budget': {'complete': True, 'qualified': True}, 'runtime_loaded_identity_verified': True}]:
            with self.assertRaises(EvidenceGap): native.require_native_budget_join(value)

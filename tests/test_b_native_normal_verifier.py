"""Synthetic source controls only. No actual signatures/native/Core qualification."""
import copy
import asyncio
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
    def test_captured_descriptor_scan_replays_original_raw_trace_without_write(self):
        from simulator import confirmed_scan
        frame = asyncio.run(self.f.collect())
        provenance = frame['confirmed_scan']; specs = {row['desc']: row['range'] for row in frame['descriptor_ranges']}
        context = {'owners': self.f.members, 'scope': 'synthetic immutable actual epoch'}
        before = self.store.db.total_changes
        with patch.object(confirmed_scan, '_identity', return_value=context):
            scripts, result = native.captured_scan(self.store, self.f.config, self.f.chain, self.f.current,
                sequence=provenance['original_scan_sequence'], pins=frame['financial_pins'],
                boundary_id=frame['boundary_id'], members=self.f.members, specs=specs,
                tip=(self.f.height, self.f.tip))
        self.assertEqual(before, self.store.db.total_changes)
        self.assertEqual(124, len(scripts)); self.assertEqual(6, len(result['unspents']))
        self.assertIn(self.f.script('watchman:21'), scripts)
        with patch.object(confirmed_scan, '_identity', return_value={**context, 'scope': 'changed'}):
            with self.assertRaisesRegex(EvidenceGap, 'identity/context'):
                native.captured_scan(self.store, self.f.config, self.f.chain, self.f.current,
                    sequence=provenance['original_scan_sequence'], pins=frame['financial_pins'],
                    boundary_id=frame['boundary_id'], members=self.f.members, specs=specs,
                    tip=(self.f.height, self.f.tip))
    def test_b_capture_hook_keeps_paid_original_leaf_rows_out_of_liabilities(self):
        import json, hashlib
        from simulator.model import SIGNET_GENESIS
        self.f.confirmed()
        # Existing old synthetic fixture omits native verifier server identity.
        # Supply that public field explicitly; this remains a synthetic control.
        for row in self.store.db.execute('SELECT id,proof FROM owned_coin').fetchall():
            value = json.loads(row['proof']); value['server_pubkey'] = '02'+'a'*64
            self.store.db.execute('UPDATE owned_coin SET proof=? WHERE id=?',(json.dumps(value),row['id']))
        proof = json.loads(self.store.db.execute('SELECT proof FROM owned_coin LIMIT 1').fetchone()['proof'])
        member = {'id':'original-board-backing','kind':'ark_backing','role':'operator',
                  'identity':proof['server_pubkey'],'descriptors':[]}
        self.store.event('treasury_member_verified',{'member':member,'genesis':SIGNET_GENESIS,'financial_pins':fixtures.PINS})
        sequence = self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
        boundary = {'id':'finite','pins':fixtures.PINS,'genesis':SIGNET_GENESIS,
                    'members':[{**member,'verification_sequence':sequence}],'excluded':[]}
        raw = json.dumps(self.f.database).encode(); sha = hashlib.sha256(raw).hexdigest()
        before = self.store.db.total_changes
        with self.f.dependencies():
            result = native.captured_direct_source(self.store,self.f.chain,raw,sha,
                journey_sequence=self.f.journey,scripts=self.scripts,tip=(self.f.height,self.f.tip),
                minimum_confirmations=1,boundary=boundary)
        self.assertEqual(before,self.store.db.total_changes)
        self.assertEqual([],result['pending_liabilities'])
        self.assertEqual(3,len(result['direct']['liabilities']))
        self.assertEqual(19670,sum(v['amount_sat'] for v in result['direct']['liabilities']))
        with self.assertRaisesRegex(EvidenceGap,'original frontier hash'):
            native.captured_direct_source(self.store,self.f.chain,raw,'0'*64,
                journey_sequence=self.f.journey,scripts=self.scripts,tip=(self.f.height,self.f.tip),
                minimum_confirmations=1,boundary=boundary)

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
    def test_physical_fee_payers_ignore_action_labels_and_internal_outputs(self):
        txid = 'a'*64
        tx = {'txid':txid,'confirmations':2,'fee_sat':3,
              'inputs':[{'outpoint':'old:0','amount_sat':100,'script':'bank'}],
              'outputs':[{'amount_sat':80,'script':'rounds'},{'amount_sat':17,'script':'bank'}]}
        cost = {'sequence':4447,'txid':txid,'amount_msat':3000,
                'action_id':'misleading-actor-label','direct_payment_sequence':None}
        chain = SimpleNamespace(transaction=lambda value:copy.deepcopy(tx))
        scripts = {'bank':{'member_id':'bank'},'rounds':{'member_id':'rounds'}}
        self.assertEqual({4447:'bank'},native.physical_cost_payers([cost],chain,scripts,[]))
        tx['inputs'].append({'outpoint':'other:0','amount_sat':1,'script':'rounds'})
        with self.assertRaisesRegex(EvidenceGap,'mixed or absent'):
            native.physical_cost_payers([cost],chain,scripts,[])
    def test_direct_cost_uses_exact_supplemental_prevout_not_backing_owner(self):
        txid = 'b'*64
        tx = {'txid':txid,'confirmations':2,'fee_sat':5,
              'inputs':[{'outpoint':'anchor:0','amount_sat':20,'script':'ark'},
                        {'outpoint':'watch:0','amount_sat':50,'script':'watch'}], 'outputs':[]}
        cost = {'sequence':2947,'txid':txid,'amount_msat':5000,'direct_payment_sequence':2946}
        chain = SimpleNamespace(transaction=lambda value:copy.deepcopy(tx))
        scripts = {'ark':{'member_id':'backing'},'watch':{'member_id':'watchman'}}
        group = {'transaction':copy.deepcopy(tx),'fee_inputs':[
            {'outpoint':'watch:0','value_sat':50,'script_pubkey':'watch'}]}
        self.assertEqual({2947:'watchman'},native.physical_cost_payers([cost],chain,scripts,[group]))
        with self.assertRaisesRegex(EvidenceGap,'no validated current winner'):
            native.physical_cost_payers([cost],chain,scripts,[])
        group['fee_inputs'][0]['value_sat'] = 49
        with self.assertRaisesRegex(EvidenceGap,'actual prevout differs'):
            native.physical_cost_payers([cost],chain,scripts,[group])

    def budget(self):
        import hashlib, os
        from simulator.model import SIGNET_GENESIS
        txid = 'a'*64; raw = (txid+'\n').encode(); sha = hashlib.sha256(raw).hexdigest()
        disk = {'network':'signet','genesis':SIGNET_GENESIS,'server_pubkey':'02'+'1'*64,
            'policy_sha256':'b'*64,'opening_sha256':'c'*64,'budget_file_sha256':'d'*64,
            'history_prefix_bytes':65,'history_prefix_sha256':sha,'accounting_receipt_sha256':'e'*64,
            'opening_native_spent_sat':4985,'opening_external_spent_sat':879,
            'external_future_reserved_sat':20000,'ordinary_budget_sat':60000,'urgent_reserve_sat':15000,
            'opening_charge_sat':25864,'reserved_ceiling_sum_sat':0,'attempt_count':0,
            'total_charged_sat':25864,'remaining_ordinary_allowance_sat':34136,
            **{key:False for key in ('runtime_loaded_identity_verified','retained_signed_fee_coverage_verified',
                'urgent_selection_isolation_verified','complete','qualified')}}
        files = {name:{'device':os.makedev(0,44),'inode':1234+i,'sha256':digest} for i,(name,digest) in enumerate([
            ('ordinary-fee-budget','d'*64),('ordinary-fee-opening.json','c'*64),('ordinary-fee-policy.json','b'*64)])}
        runtime = {'daemons':{'watchmand':{'pid':321}},'native_budget':{'disk_budget':disk,'files':files,
            'lock':{'pid':321,'device':os.makedev(0,44),'inode':1234,
                'lock_line':'lock:\t1: FLOCK  ADVISORY  WRITE 321 00:2c:1234 0 EOF'},
            'history':{'txids':[txid],'bytes':65,'sha256':sha,'prefix_bytes':65,'prefix_sha256':sha},
            'accounting_receipt_sha256':'e'*64}}
        costs = [{'sequence':seq,'txid':tid,'amount_msat':fee*1000,'budget':'ordinary',
            'direct_payment_sequence':2946 if seq==2947 else None} for seq,tid,fee in [
            (234,'1'*64,708),(600,'2'*64,171),(2947,txid,4985),(4117,'3'*64,2378)]]
        groups = [{'versions':{txid:{'txid':txid,'fee_sat':4985}}}]
        return runtime,costs,groups
    def test_loaded_lock_retained_history_and_original_costs_join_without_reset(self):
        runtime,costs,groups = self.budget()
        result = native.require_native_budget_join(runtime,server_pubkey='02'+'1'*64,
            costs=costs,groups=groups,accounting_receipt_sha256='e'*64)
        self.assertEqual(34136,result['native_remaining_allowance_sat'])
        self.assertEqual(17622,result['external_future_partition_remaining_sat'])
        self.assertEqual(60000,result['ordinary_budget_sat'])
    def test_current_adoption_opening_carries_import4447_without_partition_refill(self):
        runtime,costs,groups = self.budget(); costs[-1]['sequence'] = 4447
        disk = runtime['native_budget']['disk_budget']
        disk['opening_external_spent_sat'] = 3257
        disk['external_future_reserved_sat'] = 17622
        args = dict(server_pubkey='02'+'1'*64,costs=costs,groups=groups,
                    accounting_receipt_sha256='e'*64,opening_cost_sequences=(234,600,2947,4447))
        result = native.require_native_budget_join(runtime,**args)
        self.assertEqual(4985,result['native_opening_spent_sat'])
        self.assertEqual(3257,result['external_opening_spent_sat'])
        self.assertEqual(17622,result['external_future_partition_remaining_sat'])
        self.assertEqual(34136,result['native_remaining_allowance_sat'])
        disk['external_future_reserved_sat'] = 20000
        with self.assertRaisesRegex(EvidenceGap,'lifetime arithmetic'):
            native.require_native_budget_join(runtime,**args)

    def test_wrong_lock_missing_version_or_undercharged_opening_hold(self):
        runtime,costs,groups = self.budget(); runtime['native_budget']['lock']['pid']=322
        with self.assertRaisesRegex(EvidenceGap,'FLOCK'):native.require_native_budget_join(runtime,
            server_pubkey='02'+'1'*64,costs=costs,groups=groups,accounting_receipt_sha256='e'*64)
        runtime,costs,groups = self.budget();groups[0]['versions']={}
        with self.assertRaisesRegex(EvidenceGap,'extra or missing'):native.require_native_budget_join(runtime,
            server_pubkey='02'+'1'*64,costs=costs,groups=groups,accounting_receipt_sha256='e'*64)
        runtime,costs,groups = self.budget();runtime['native_budget']['disk_budget']['opening_external_spent_sat']=0
        with self.assertRaisesRegex(EvidenceGap,'external costs lost'):native.require_native_budget_join(runtime,
            server_pubkey='02'+'1'*64,costs=costs,groups=groups,accounting_receipt_sha256='e'*64)
    def test_disk_false_or_caller_true_flags_never_prove_loaded_budget(self):
        for value in [None, {'disk_budget': {'complete': True, 'qualified': True}, 'runtime_loaded_identity_verified': True}]:
            with self.assertRaises(EvidenceGap): native.require_native_budget_join(value)

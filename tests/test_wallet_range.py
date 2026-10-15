"""Replay actual A native/Core range captures; no new live or native test credit."""
import copy
import json
import unittest
from datetime import datetime
from pathlib import Path

from simulator.model import InvariantError
from simulator.ownership import EvidenceGap
from simulator.wallet_range import reduce_declared_wallet_range

FIXTURE = Path(__file__).with_name('fixtures')/'a-wallet-range-core-326474-20261015.json'


class RecordedCore:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def call(self, method, *args):
        self.calls.append((method, args))
        for row in self.rows:
            if row['method'] == method and row['params'] == list(args):
                return copy.deepcopy(row['result'])
        if method == 'deriveaddresses':
            for row in self.rows:
                if row['method'] == method and row['params'][0] == args[0]:
                    low, high = args[1]; recorded_low, recorded_high = row['params'][1]
                    if recorded_low <= low <= high <= recorded_high:
                        # Exact subset of an original larger derivation reply.
                        return copy.deepcopy(row['result'][low-recorded_low:high-recorded_low+1])
        raise AssertionError('No original captured Core response for '+repr((method,args)))


class DeclaredWalletRangeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads(FIXTURE.read_text())
        self.capture = self.fixture['capture']
        self.pins = self.fixture['financial_pins']
        self.core = RecordedCore(self.fixture['original_core_observations'])
        self.now = datetime.fromisoformat(self.capture['completed_at']).timestamp()+1

    def facts(self, owner):
        packet = self.capture['native_before']
        field = 'rounds_inventory' if owner == 'rounds' else 'watchman_inventory'
        native = packet[field]['data'][owner]
        member = {'id':owner,'kind':'wallet','role':'operator',
            'identity':owner+'-captured-source','descriptors':[native['public_descriptor']]}
        facts = {'schema_version':1,'kind':'financial_facts','architecture_profile':'two_step_per_key',
            'network':'signet','genesis':packet['genesis'],
            'height':packet['core_before']['blocks'],'tip_hash':packet['core_before']['bestblockhash'],
            'observed_at':datetime.fromisoformat(self.capture['observed_at']).timestamp(),
            'completed_at':datetime.fromisoformat(self.capture['completed_at']).timestamp(),
            'financial_pins':self.pins,
            'source_identity':{'product_commit':self.pins['product_commit'],
                'schema_sha256':self.pins['schema_sha256'],
                'bridge_sha256':'0a5a5ee3b0ea36f6fbe91e9cb99314b70fd81270f11aa3f89228cb4f9a5e84b4',
                'daemon_binary_hashes':{n:packet['binary_sha256'][n] for n in ['captaind','watchmand']}},
            'sources':{owner+'_wallet':{'owner':owner,
                'observed_at':datetime.fromisoformat(packet['observed_at']).timestamp(),
                'completed_at':datetime.fromisoformat(packet['completed_at']).timestamp(),
                'source':copy.deepcopy(packet[field]['data'])}},
            'source_gaps':['global economic/signing/urgent readiness unqualified']}
        return member, facts

    def reduce(self, owner='rounds'):
        member, facts = self.facts(owner)
        return reduce_declared_wallet_range(member,facts,self.capture,self.core,self.pins,
            owner=owner,now=self.now)

    def test_original_populated_rounds_range_matches_actual_core_and_keeps_gaps(self):
        result = self.reduce()
        self.assertEqual(result['discovered_confirmed_sat'],90000)
        self.assertEqual(result['derivation_range'],[0,32])
        self.assertTrue(result['declared_range_matches'])
        self.assertFalse(result['global_complete'])
        self.assertFalse(result['operating_readiness'])
        self.assertIn('fee_cost_budgets_and_urgent_reserve_unqualified',result['remaining_gaps'])

    def test_original_empty_watch_wallet_requires_actual_chain_range_evidence(self):
        result = self.reduce('watchman')
        self.assertEqual(result['discovered_confirmed_sat'],0)
        self.assertEqual(result['confirmed_outpoints'],[])
        self.assertTrue(result['declared_range_matches'])
        self.assertFalse(result['global_complete'])

    def test_omitted_real_native_output_fails_even_with_complete_flag(self):
        for packet in [self.capture['native_before'],self.capture['native_after']]:
            packet['rounds_inventory']['data']['rounds']['utxos']=[]
            packet['rounds_inventory']['data']['rounds']['complete']=True
        with self.assertRaisesRegex(EvidenceGap,'omits or adds'):
            self.reduce()

    def test_omitted_original_scan_output_fails(self):
        self.capture['scan']['unspents']=[]
        self.capture['scan']['total_amount']='0'
        with self.assertRaisesRegex(EvidenceGap,'omits or adds'):
            self.reduce()

    def test_changed_native_cut_is_a_hold(self):
        self.capture['native_after']['rounds_inventory']['data']['rounds']['reserved_outpoints']=['aa'*32+':0']
        with self.assertRaisesRegex(EvidenceGap,'changed across'):
            self.reduce()

    def test_issued_address_beyond_measured_horizon_is_unqualified(self):
        for packet in [self.capture['native_before'],self.capture['native_after']]:
            packet['rounds_inventory']['data']['rounds']['last_revealed_index']=33
        with self.assertRaisesRegex(EvidenceGap,'issuance exceeds'):
            self.reduce()

    def test_scan_cannot_substitute_a_different_range_or_wallet(self):
        self.capture['requests'] = copy.deepcopy(self.capture['requests'])
        for row in self.capture['requests']:
            if row['method']=='scantxoutset' and row['params'][0]=='start':
                row['params'][1][0]['range']=[0,31]
        with self.assertRaisesRegex(InvariantError,'exact one declared'):
            self.reduce()

    def test_duplicate_scan_output_is_a_hard_failure(self):
        self.capture['scan']['unspents']*=2
        self.capture['scan']['total_amount']='0.0018'
        with self.assertRaisesRegex(InvariantError,'repeats'):
            self.reduce()

    def test_stale_source_or_changed_tip_never_qualifies(self):
        self.now+=91
        with self.assertRaisesRegex(EvidenceGap,'stale'):
            self.reduce()
        self.now-=91
        self.capture['core_after']['bestblockhash']='aa'*32
        with self.assertRaisesRegex(EvidenceGap,'cuts differ'):
            self.reduce()

    def test_changed_actual_daemon_bytes_fail_before_projection(self):
        self.capture['native_after']['binary_sha256']['watchmand']='ab'*32
        with self.assertRaisesRegex(InvariantError,'daemon bytes'):
            self.reduce()


if __name__ == '__main__':
    unittest.main()

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from simulator.bundle_audit import decode_transaction
from simulator.engine import initialize
from simulator.model import SIGNET_GENESIS, canonical
from simulator.store import Store


class FeeWatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name), 'synthetic', 10000)
        initialize(self.store)
        self.parent_raw = '02000000' + '01' + '11' * 32 + '00000000' + '00' + 'ffffffff' + '01' + (10000).to_bytes(8, 'little').hex() + '02' + '0014' + '00000000'
        self.parent = decode_transaction(self.parent_raw)
        self.raw = '02000000' + '01' + bytes.fromhex(self.parent['txid'])[::-1].hex() + '00000000' + '00' + 'ffffffff' + '01' + (9900).to_bytes(8, 'little').hex() + '02' + '0014' + '00000000'
        self.tx = decode_transaction(self.raw)
        self.store.db.execute('INSERT INTO server_item VALUES (?,?,?,?)',
            ('nursery', self.tx['txid'], canonical({'txid': self.tx['txid'], 'kind': 'expiry-payout'}), 100))
        owner = self
        class Core:
            expected = SIGNET_GENESIS
            def __init__(inner): inner.calls = []; inner.estimate = {'feerate': '0.00001001', 'blocks': 6}; inner.vsize = len(bytes.fromhex(owner.raw))
            def identity(inner): return {'chain': 'signet', 'blocks': 100, 'bestblockhash': 'a' * 64, 'initialblockdownload': False}
            def call(inner, method, *args):
                inner.calls.append((method, args))
                if method == 'estimatesmartfee': return inner.estimate
                raise AssertionError(method)
            def tx(inner, txid):
                inner.calls.append(('getrawtransaction', (txid,)))
                raw = owner.raw if txid == owner.tx['txid'] else owner.parent_raw
                return {'txid': txid, 'hex': raw, 'confirmations': 1,
                        **({'vsize': inner.vsize} if txid == owner.tx['txid'] else {})}
        self.core = Core()

    def tearDown(self): self.store.close(); self.tmp.cleanup()

    def collect(self, tick='snapshot:1'):
        from simulator.fee_watch import collect
        return asyncio.run(collect(self.store, self.core, tick, target_blocks=6, mode='economical', transaction_limit=2))

    def test_raw_fee_and_fractional_reference_do_not_invent_policy_or_operator_share(self):
        value = self.collect()
        self.assertEqual('1.001', value['estimate']['sat_per_vbyte'])
        row = value['transactions'][0]
        self.assertEqual(100, row['mining_fee_sat'])
        self.assertEqual(len(bytes.fromhex(self.raw)), row['vsize'])
        self.assertTrue(row['above_current_reference'])
        self.assertIsNone(row['operator_fee_sat'])
        self.assertEqual('undeclared', row['policy_verdict'])

    def test_same_simulator_tick_is_idempotent_but_new_tick_samples_reference_again(self):
        first = self.collect(); calls = len(self.core.calls)
        self.assertEqual(first, self.collect())
        self.assertEqual(calls, len(self.core.calls))
        second = self.collect('snapshot:2')
        self.assertEqual(2, sum(method == 'estimatesmartfee' for method, _ in self.core.calls))
        self.assertEqual(first['transactions'][0]['mining_fee_sat'], second['transactions'][0]['mining_fee_sat'])

    def test_missing_estimate_leaves_comparison_unknown_without_zero_fee_or_ceiling(self):
        self.core.estimate = {'errors': ['Insufficient data'], 'blocks': 6}
        value = self.collect()
        self.assertIsNone(value['estimate']['sat_per_vbyte'])
        self.assertIsNone(value['transactions'][0]['above_current_reference'])
        self.assertEqual(100, value['transactions'][0]['mining_fee_sat'])

    def test_parent_identity_and_core_size_mismatch_are_evidence_gaps(self):
        self.core.vsize += 1
        value = self.collect()
        self.assertEqual([], value['transactions'])
        self.assertTrue(value['unknowns'])
        self.assertEqual(0, self.store.db.execute('SELECT count(*) FROM fee_watch_transaction').fetchone()[0])

    def test_unconfirmed_raw_transaction_does_not_become_realized_operator_cost(self):
        original = self.core.tx
        self.core.tx = lambda txid: {**original(txid), 'confirmations': 0}
        row = self.collect()['transactions'][0]
        self.assertEqual('unconfirmed', row['chain_state'])
        self.assertIsNone(row['operator_fee_sat'])

    def test_only_exact_checked_settlement_event_can_attribute_fee_shares(self):
        from simulator.settlements import initialize as settlements_initialize
        settlements_initialize(self.store)
        self.store.db.execute('INSERT INTO settlement_check VALUES (?,?,?,?)', (self.tx['txid'], 'amounts_checked', None, 1))
        self.store.event('confirmed_payout_amounts_checked', {'txid': self.tx['txid'], 'recipient_fee_sat': 60, 'operator_fee_sat': 40})
        row = self.collect()['transactions'][0]
        self.assertEqual(60, row['recipient_fee_sat']); self.assertEqual(40, row['operator_fee_sat'])

    def window(self, duplicate=False):
        summary = {'target': 'server::expiry_payout', 'timestamp': '2026-10-12T23:01:19.831Z',
            'message': 'expiry payout tick summary', 'tip': 326111, 'candidates': 5,
            'waiting': 5, 'paid': 0, 'success': True, 'duration_ms': '134'}
        warning = {'target': 'server::expiry_payout', 'timestamp': '2026-10-12T23:01:19.810Z',
                   'message': 'expiry batch deferred: payout funding/fee deferred: payout does not cover its fee'}
        lines = [warning, summary] + ([summary] if duplicate else [])
        return {'component': 'captaind', 'gaps': ['source_identity_unavailable', 'tail_coverage_unknown'],
                'response': {'complete': False, 'lines': [{'line_index': i, 'redacted': False, 'returned_line': json.dumps(row)} for i, row in enumerate(lines)]}}

    def test_repeated_windows_preserve_occurrences_without_counting_unique_daemon_ticks(self):
        from simulator.fee_watch import record_window, report
        record_window(self.store, 'captaind', 1, self.window(True), {'partition': 'trace-2026-10-12.sqlite', 'seq': 1, 'hash': 'a' * 64})
        record_window(self.store, 'captaind', 2, self.window(), {'partition': 'trace-2026-10-12.sqlite', 'seq': 2, 'hash': 'b' * 64})
        value = report(self.store)
        self.assertEqual(3, value['server_diagnostics']['summary_occurrences'])
        self.assertEqual(1, value['server_diagnostics']['distinct_summary_payloads'])
        self.assertIsNone(value['server_diagnostics']['unique_daemon_ticks'])
        self.assertEqual(2, value['server_diagnostics']['warning_occurrences'])

    def test_aggregate_warning_cannot_be_assigned_to_pending_payout_or_age(self):
        from simulator.fee_watch import record_window, report
        from simulator.settlements import initialize as settlements_initialize
        settlements_initialize(self.store)
        self.store.db.execute('INSERT INTO settlement_check VALUES (?,?,?,?)', (self.tx['txid'], 'pending', 'missing signed owner', 1))
        record_window(self.store, 'captaind', 1, self.window(), {'partition': 'trace-2026-10-12.sqlite', 'seq': 1, 'hash': 'a' * 64})
        row = report(self.store)['pending_payouts'][0]
        self.assertIsNone(row['server_waiting_reason']); self.assertIsNone(row['same_reason_age_ticks'])
        self.assertEqual('missing signed owner', row['local_verification_reason'])

    def test_redacted_and_malformed_summaries_remain_gaps_not_timestamps_or_ticks(self):
        from simulator.fee_watch import record_window, report
        window = self.window(); window['response']['lines'] += [{'line_index': 2, 'redacted': True, 'bytes': 100},
            {'line_index': 3, 'redacted': False, 'returned_line': json.dumps({'message': 'expiry payout tick summary', 'waiting': 5})}]
        record_window(self.store, 'captaind', 1, window, {'partition': 'trace-2026-10-12.sqlite', 'seq': 1, 'hash': 'a' * 64})
        self.assertGreater(report(self.store)['server_diagnostics']['unparsed_occurrences'], 0)

    def test_non_signet_chain_is_refused_without_any_estimate_or_transaction_calls(self):
        self.core.expected = 'other-genesis'
        with self.assertRaises(ValueError): self.collect()
        self.assertEqual([], self.core.calls)

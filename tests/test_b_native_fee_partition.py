"""Synthetic-only accounting controls; no native/runtime/chain qualification."""
import copy
import hashlib
import unittest

from simulator.b_native_fee_partition import partition_native_fee_authorizations, MAX_MONEY
from simulator.ownership import EvidenceGap


def fixture():
    # Fictional complete public projection: ordinary, u1, p1, ordinary, u2.
    # The source producer, not this pure reducer, authenticates actual raw bytes.
    raw = b'1000\nu:1:4000\np:1:' + b'a'*64 + b':[[]]\n2000\nu:2:1000\n'
    digest = hashlib.sha256(raw).hexdigest()
    ledger = {'budget_file_sha256': digest, 'ordinary_reservations': [
        {'line': 1, 'ceiling_sat': 1000}, {'line': 4, 'ceiling_sat': 2000}],
        'urgent_reservations': [{'line': 2, 'attempt_index': 1, 'ceiling_sat': 4000},
                                {'line': 5, 'attempt_index': 2, 'ceiling_sat': 1000}],
        'urgent_bindings': [{'line': 3, 'attempt_index': 1, 'binding_sha256': 'a'*64}],
        'record_count': 5}
    disk = {'schema_version': 2, 'budget_file_sha256': digest, 'budget_file_bytes': len(raw),
        'ordinary_attempt_count': 2, 'urgent_attempt_count': 2, 'urgent_binding_count': 1,
        'attempt_count': 4, 'urgent_reserved_ceiling_sum_sat': 5000,
        'reserved_ceiling_sum_sat': 8000, 'opening_native_spent_sat': 4985,
        'opening_external_spent_sat': 3257, 'external_future_reserved_sat': 17622,
        'ordinary_budget_sat': 60000, 'urgent_reserve_sat': 15000,
        'opening_charge_sat': 25864, 'total_charged_sat': 33864,
        'remaining_ordinary_allowance_sat': 26136}
    return {'native_budget': {'public_ledger': ledger, 'disk_budget': disk,
        'files': {'ordinary-fee-budget': {'sha256': digest, 'bytes': len(raw)}}}}


class PartitionTests(unittest.TestCase):
    def setUp(self):
        self.runtime = fixture()
        self.budget = self.runtime['native_budget']
        self.disk = self.budget['disk_budget']
        self.ledger = self.budget['public_ledger']

    def reject(self, expected):
        with self.assertRaisesRegex(EvidenceGap, expected):
            partition_native_fee_authorizations(self.runtime)

    def test_interleaved_full_ceilings_not_actual_fees_or_bindings(self):
        result = partition_native_fee_authorizations(self.runtime)
        self.assertEqual([r['attempt_index'] for r in result['ordinary_attempts']], [1, 2])
        self.assertEqual([r['line'] for r in result['ordinary_attempts']], [1, 4])
        self.assertEqual(result['ordinary_reserved_sat'], 3000)
        self.assertEqual(result['urgent_reserved_sat'], 5000)
        self.assertEqual(result['total_charged_sat'], 33864)
        self.assertEqual(result['remaining_urgent_sat'], 10000)
        self.assertEqual(result['remaining_discretionary_sat'], 16136)
        self.assertEqual(result['unbound_urgent_attempts'], [2])
        self.assertFalse({'complete', 'qualified', 'confirmed', 'paid', 'spent'} & set(result))

    def test_no_mutation_of_original_runtime(self):
        before = copy.deepcopy(self.runtime)
        partition_native_fee_authorizations(self.runtime)
        self.assertEqual(before, self.runtime)

    def test_empty_fresh_epoch_keeps_entire_urgent_partition(self):
        digest = hashlib.sha256(b'').hexdigest()
        self.ledger.update(budget_file_sha256=digest, ordinary_reservations=[],
            urgent_reservations=[], urgent_bindings=[], record_count=0)
        self.budget['files']['ordinary-fee-budget'].update(sha256=digest, bytes=0)
        self.disk.update(budget_file_sha256=digest, budget_file_bytes=0,
            ordinary_attempt_count=0, urgent_attempt_count=0, urgent_binding_count=0,
            attempt_count=0, urgent_reserved_ceiling_sum_sat=0, reserved_ceiling_sum_sat=0,
            opening_native_spent_sat=0, opening_external_spent_sat=0,
            external_future_reserved_sat=20000, opening_charge_sat=20000,
            total_charged_sat=20000, remaining_ordinary_allowance_sat=40000)
        result = partition_native_fee_authorizations(self.runtime)
        self.assertEqual(result['remaining_urgent_sat'], 15000)
        self.assertEqual(result['remaining_discretionary_sat'], 25000)

    def test_urgent_binding_does_not_create_another_attempt_or_charge(self):
        self.disk['attempt_count'] = 5
        self.reject('attempt_count differs')

    def test_aggregate_attempts_cannot_be_used_as_ordinary_attempts(self):
        self.disk['ordinary_attempt_count'] = 4
        self.reject('ordinary_attempt_count differs')

    def test_missing_schema2_aggregate_refuses(self):
        del self.disk['urgent_reserved_ceiling_sum_sat']
        self.reject('urgent_reserved_ceiling_sum_sat differs')

    def test_file_identity_changes_refuse(self):
        self.budget['files']['ordinary-fee-budget']['sha256'] = 'f'*64
        self.reject('hash differs')

    def test_file_length_changes_refuse(self):
        self.disk['budget_file_bytes'] += 1
        self.reject('bytes differ')

    def test_bound_record_and_byte_capacity(self):
        self.ledger['record_count'] = 10001
        self.reject('record count')
        self.ledger['record_count'] = 5
        self.budget['files']['ordinary-fee-budget']['bytes'] = 2*1024*1024+1
        self.reject('held-file bytes')

    def test_extra_projection_fields_refuse(self):
        self.ledger['complete'] = True
        self.reject('exact public ledger fields')

    def test_hidden_or_missing_line_refuses(self):
        self.ledger['urgent_reservations'][1]['line'] = 6
        self.reject('missing ledger line')

    def test_duplicate_cross_category_line_refuses(self):
        self.ledger['urgent_reservations'][0]['line'] = 1
        self.reject('duplicate/unordered')

    def test_reordered_ordinary_rows_refuse(self):
        self.ledger['ordinary_reservations'].reverse()
        self.reject('duplicate/unordered')

    def test_sequential_urgent_ids_required(self):
        self.ledger['urgent_reservations'][1]['attempt_index'] = 3
        self.reject('not sequential')

    def test_binding_without_prior_reservation_refuses(self):
        self.ledger['urgent_bindings'][0]['attempt_index'] = 2
        self.reject('unique prior urgent')

    def test_binding_cannot_precede_reservation(self):
        self.ledger['urgent_bindings'][0]['line'] = 2
        self.ledger['urgent_reservations'][0]['line'] = 3
        self.reject('unique prior urgent')

    def test_duplicate_binding_refuses(self):
        self.ledger['urgent_reservations'].pop()
        self.ledger['urgent_bindings'].append(
            {'line': 5, 'attempt_index': 1, 'binding_sha256': 'b'*64})
        self.reject('unique prior urgent')

    def test_zero_or_malformed_binding_hash_refuses(self):
        for value in ['0'*64, 'A'*64, 'a'*63, None]:
            with self.subTest(value=value):
                self.ledger['urgent_bindings'][0]['binding_sha256'] = value
                self.reject('binding hash')

    def test_bool_and_zero_ceilings_refuse(self):
        for value in [True, 0, -1, MAX_MONEY+1]:
            with self.subTest(value=value):
                self.ledger['ordinary_reservations'][0]['ceiling_sat'] = value
                self.reject('ordinary ceiling')

    def test_boolean_counter_and_version_refuse(self):
        self.disk['schema_version'] = True
        self.reject('schema2')
        self.disk['schema_version'] = 2
        self.disk['urgent_binding_count'] = True
        self.reject('urgent_binding_count differs')

    def test_lifetime_and_urgent_sublimit_are_not_independent_allowances(self):
        self.disk['urgent_reserve_sat'] = 4999
        self.reject('sublimit exhausted')
        self.disk['urgent_reserve_sat'] = 15000
        self.disk['ordinary_budget_sat'] = 33863
        self.reject('sublimit exhausted')

    def test_ordinary_attempts_cannot_consume_unused_urgent_headroom(self):
        self.disk['ordinary_budget_sat'] = 43863
        self.reject('protected urgent headroom')

    def test_success_or_confirmation_cannot_replenish_failed_attempt_ceiling(self):
        # Retained auth rows remain, even if an external observer says fee was
        # smaller or transaction confirmed: a reduced total is contradictory.
        self.disk['total_charged_sat'] -= 1000
        self.disk['remaining_ordinary_allowance_sat'] += 1000
        self.reject('full-ceiling arithmetic differs')

    def test_original_external_partition_cannot_be_added_twice(self):
        self.disk['external_future_reserved_sat'] = 20000
        self.reject('opening/full-ceiling arithmetic differs')

    def test_unknown_schema_refuses(self):
        self.disk['schema_version'] = 3
        self.reject('schema2')

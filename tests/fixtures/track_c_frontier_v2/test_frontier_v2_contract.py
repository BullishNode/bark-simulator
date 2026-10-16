"""Pure fixed-command/provenance controls; no DB, ops, SDK or financial action."""
import copy
import hashlib
import unittest
import frontier_stream as f
import frontier_v2_contract as c
from test_frontier_stream import FakeConnection, LIMITS, SOURCE, dataset

EXPECTED = {'resource_declaration': LIMITS,
            'source_binding': {**SOURCE, 'network': 'signet', 'genesis': c.SIGNET_GENESIS},
            'financial_pins': {'product_commit': 'a' * 40, 'sdk_commit': 'b' * 40,
                               'driver_sha256': 'c' * 64, 'configuration_sha256': 'd' * 64,
                               'schema_sha256': SOURCE['schema_sha256']},
            'deployment_id': 'synthetic-unfunded-c'}


def lines(expected=None, rows=None):
    expected = expected or EXPECTED
    result = []
    f.produce(FakeConnection(dataset(1) if rows is None else rows),
              expected['resource_declaration'], expected['source_binding'], result.append)
    return result


class SyntheticTrace:
    def __init__(self):
        self.records = {}

    def capture(self, metadata, raw):
        seq = len(self.records) + 1
        digest = hashlib.sha256(f.canonical(metadata) + raw).hexdigest()
        reference = {'partition': 'synthetic.sqlite', 'seq': seq, 'hash': digest}
        self.records[seq] = (copy.deepcopy(metadata), raw, reference)
        return reference

    def load(self, reference):
        metadata, raw, stored = self.records[reference['seq']]
        if reference != stored or hashlib.sha256(f.canonical(metadata) + raw).hexdigest() != stored['hash']:
            raise ValueError('synthetic original trace bytes/hash differ')
        return copy.deepcopy(metadata), raw


class FixedV2IntegrationControls(unittest.TestCase):
    def test_exact_new_command_does_not_accept_old_alias_sql_host_or_extra_fields(self):
        good = c.request(EXPECTED)
        self.assertEqual(c.COMMAND, c.validate_request(f.canonical(good), EXPECTED)['kind'])
        for bad in [{**good, 'kind': 'closed_frontier'}, {**good, 'kind': 'raw_query'},
                    {**good, 'sql': 'SELECT * FROM secrets'}, {**good, 'host': 'other'},
                    {**good, 'cursor': 'prefix'}]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                c.validate_request(f.canonical(bad), EXPECTED)

    def test_bool_resource_value_cannot_alias_declared_integer(self):
        expected = copy.deepcopy(EXPECTED)
        expected['resource_declaration']['max_pages'] = 1
        bad = c.request(expected)
        bad['resource_declaration']['max_pages'] = True
        with self.assertRaises(ValueError):
            c.validate_request(f.canonical(bad), expected)

    def test_wrong_genesis_network_schema_or_missing_financial_pin_refuses(self):
        for key, value in [('genesis', '0' * 64), ('network', 'regtest'), ('schema_sha256', '9' * 64)]:
            bad = copy.deepcopy(EXPECTED)
            bad['source_binding'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                c.expected_contract(bad)
        bad = copy.deepcopy(EXPECTED)
        bad['financial_pins'].pop('sdk_commit')
        with self.assertRaises(ValueError):
            c.expected_contract(bad)

    def test_original_raw_capture_and_replay_preserve_schema2_without_readiness(self):
        trace = SyntheticTrace()
        original = lines()
        frame = c.consume_original(original, lambda: 0, EXPECTED, lambda _: None, trace.capture, trace.load)
        self.assertEqual(original, [v[1] for v in trace.records.values()])
        self.assertEqual(frame, c.verify_snapshot(frame, EXPECTED, trace.load))
        self.assertEqual(2, frame['schema_version'])
        self.assertEqual('direct_per_key', frame['architecture_profile'])
        self.assertEqual(4, frame['fallback_protocol'])
        self.assertEqual(EXPECTED['financial_pins'], frame['declared_financial_pins'])
        self.assertFalse(frame['complete'])
        self.assertFalse(frame['qualified'])
        self.assertNotIn('available_fee_funding_sat', frame)
        self.assertNotIn('ownership_verified', frame)

    def test_nonzero_or_unknown_exit_never_captures_or_admits(self):
        for status in [1, -9, None, False]:
            trace = SyntheticTrace()
            with self.subTest(status=status), self.assertRaises(ValueError):
                c.consume_original(lines(), lambda: status, EXPECTED, lambda _: None, trace.capture, trace.load)
            self.assertFalse(trace.records)

    def test_truncated_or_mixed_source_never_captures_or_admits(self):
        foreign = copy.deepcopy(EXPECTED)
        foreign['source_binding']['deployment_sha256'] = '8' * 64
        for source in [lines()[:-1], lines(foreign)]:
            trace = SyntheticTrace()
            with self.assertRaises(ValueError):
                c.consume_original(source, lambda: 0, EXPECTED, lambda _: None, trace.capture, trace.load)
            self.assertFalse(trace.records)

    def test_failed_public_value_validation_captures_no_raw_secret_shaped_values(self):
        rows = dataset(1)
        rows['coins'][0]['vtxo_id'] = 'synthetic-forbidden-private-value'
        def public(value):
            if 'synthetic-forbidden-private-value' in f.canonical(value).decode():
                raise ValueError('synthetic public policy refusal')
        trace = SyntheticTrace()
        with self.assertRaisesRegex(ValueError, 'public policy'):
            c.consume_original(lines(rows=rows), lambda: 0, EXPECTED, public, trace.capture, trace.load)
        self.assertFalse(trace.records)

    def test_changed_pin_contract_cannot_reuse_valid_original_stream(self):
        trace = SyntheticTrace()
        frame = c.consume_original(lines(), lambda: 0, EXPECTED, lambda _: None, trace.capture, trace.load)
        for key in EXPECTED['financial_pins']:
            changed = copy.deepcopy(EXPECTED)
            changed['financial_pins'][key] = '9' * len(changed['financial_pins'][key])
            with self.subTest(key=key), self.assertRaises(ValueError):
                c.verify_snapshot(frame, changed, trace.load)

    def test_changed_row_or_false_qualification_cannot_survive_original_replay(self):
        trace = SyntheticTrace()
        frame = c.consume_original(lines(), lambda: 0, EXPECTED, lambda _: None, trace.capture, trace.load)
        for mutate in [lambda v: v['rows']['coins'].clear(),
                       lambda v: v.__setitem__('qualified', True),
                       lambda v: v.__setitem__('schema_version', 1)]:
            changed = copy.deepcopy(frame)
            mutate(changed)
            with self.assertRaises(ValueError):
                c.verify_snapshot(changed, EXPECTED, trace.load)

    def test_missing_reordered_or_tampered_original_trace_refuses(self):
        trace = SyntheticTrace()
        frame = c.consume_original(lines(), lambda: 0, EXPECTED, lambda _: None, trace.capture, trace.load)
        for mutate in [lambda v: v['frontier_stream_source']['line_references'].pop(1),
                       lambda v: v['frontier_stream_source']['line_references'].reverse(),
                       lambda v: v['frontier_stream_source']['line_references'][0].__setitem__('hash', '9' * 64)]:
            changed = copy.deepcopy(frame)
            mutate(changed)
            with self.assertRaises(ValueError):
                c.verify_snapshot(changed, EXPECTED, trace.load)

    def test_valid_trace_reference_to_redaction_marker_does_not_admit(self):
        trace = SyntheticTrace()
        def redacted(metadata, raw):
            return trace.capture({'redacted': True, 'reason': 'rejected'}, b'')
        with self.assertRaisesRegex(ValueError, 'trace/context'):
            c.consume_original(lines(), lambda: 0, EXPECTED, lambda _: None, redacted, trace.load)

    def test_no_raw_trace_reference_means_no_schema2_admission(self):
        trace = SyntheticTrace()
        frame = c.consume_original(lines(), lambda: 0, EXPECTED, lambda _: None, trace.capture, trace.load)
        frame.pop('frontier_stream_source')
        with self.assertRaises(ValueError):
            c.verify_snapshot(frame, EXPECTED, trace.load)


if __name__ == '__main__':
    unittest.main(verbosity=2)

"""Trace partitions are public evidence, separate from the financial journal."""
import datetime as dt
import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from pathlib import Path

from simulator.model import InvariantError


class TraceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc).timestamp()
        self.trace = None
    def tearDown(self):
        if self.trace is not None: self.trace.close()
        self.temp.cleanup()
    def open(self, **kwargs):
        from simulator.trace import TraceStore
        self.trace = TraceStore(self.root, clock=lambda: self.now, **kwargs)
        return self.trace
    def rows(self): return list(self.trace.records())
    def test_raw_bytes_payload_metadata_and_hashes_round_trip(self):
        trace = self.open()
        reference = trace.append('driver.call', {'request': {'operation': 'sync'}, 'duration_ms': 12},
            actor='actor-09', action_id='sync-09', raw=b'{"status":"ok"}\n')
        record = self.rows()[0]
        self.assertEqual('trace-2026-01-01.sqlite', reference['partition'])
        self.assertEqual((1, 1, 'driver.call', 'actor-09', 'sync-09'),
            (record['seq'], record['schema_version'], record['kind'], record['actor'], record['action_id']))
        self.assertEqual({'request': {'operation': 'sync'}, 'duration_ms': 12}, record['payload'])
        self.assertEqual(b'{"status":"ok"}\n', record['raw'])
        self.assertEqual(reference['hash'], record['hash'])
        self.assertEqual(1, trace.verify()['records'])
    def test_rollover_closes_previous_connection_and_preserves_old_partition(self):
        trace = self.open(); trace.append('scheduler.tick', {'actors': []})
        previous = trace.connection
        self.now += 86400; trace.append('observer.sample.raw', {'height': 10})
        with self.assertRaises(sqlite3.ProgrammingError): previous.execute('SELECT 1')
        self.assertEqual('trace-2026-01-02.sqlite', trace.current_path.name)
        self.assertEqual(2, len(list(self.root.glob('trace-*.sqlite'))))
        self.assertEqual(2, trace.verify()['records'])
        self.assertEqual(2, len(self.rows()))
    def test_restart_continues_current_day_sequence_without_new_chain(self):
        trace = self.open(); trace.append('chain.rpc', {'method': 'getblockhash'})
        tip = trace.verify()['partitions'][0]['tip']; trace.close()
        trace = self.open(); trace.append('chain.rpc', {'method': 'gettxout'})
        self.assertEqual([1, 2], [r['seq'] for r in self.rows()])
        self.assertEqual(tip, self.rows()[1]['previous_hash'])
        self.assertEqual(2, trace.verify()['records'])
    def test_sql_mutation_and_delete_are_rejected_and_raw_tampering_is_detected(self):
        trace = self.open(); trace.append('chain.rpc', {'height': 1}, raw=b'public')
        for sql in ('UPDATE trace SET raw=\'changed\'', 'DELETE FROM trace'):
            with self.assertRaises(sqlite3.DatabaseError): trace.connection.execute(sql)
        trace.connection.execute('DROP TRIGGER trace_no_update')
        trace.connection.execute("UPDATE trace SET raw='changed'")
        with self.assertRaises(InvariantError): trace.verify()
    def test_secret_fields_values_and_raw_are_rejected_or_redacted_by_every_capture_kind(self):
        trace = self.open()
        private = [' '.join(['abandon'] * 11 + ['about']), ' '.join(['abandon'] * 23 + ['art']),
                   'xprv' + 'a' * 110, '__cookie__:private', 'seed=' + 'ab' * 32]
        kinds = ['driver.call', 'driver.stdout', 'driver.stderr', 'scheduler.tick',
                 'observer.sample.raw', 'chain.rpc', 'target.log', 'inventory.page', 'test.run']
        for kind in kinds:
            for secret in private:
                with self.subTest(kind=kind):
                    with self.assertRaises(ValueError): trace.append(kind, {'text': secret})
                    trace.capture(kind, {'text': secret}, raw=secret.encode(), actor='actor-09')
                    record = self.rows()[-1]
                    self.assertTrue(record['payload']['redacted']); self.assertIsNone(record['raw'])
                    self.assertNotIn(secret, json.dumps(record, default=str))
        with self.assertRaises(ValueError): trace.append('driver.call', {'nested': {'mnemonic': 'hidden'}})
        self.assertEqual(len(kinds) * len(private), trace.verify()['records'])
    def test_json_raw_is_checked_structurally_and_invalid_utf8_never_bypasses_privacy(self):
        trace = self.open()
        for raw in (b'{"private_key":"hidden"}', b'\xff\xfe'):
            trace.capture('driver.stdout', {'status': 'ok'}, raw=raw)
            self.assertTrue(self.rows()[-1]['payload']['redacted'])
            self.assertIsNone(self.rows()[-1]['raw'])
    def test_decimal_rpc_values_are_exact_strings_and_original_json_stays_exact(self):
        trace = self.open()
        trace.append('chain.rpc', {'result': {'value': Decimal('0.00004661')}}, raw=b'{"value":0.00004661}')
        self.assertEqual('0.00004661', self.rows()[0]['payload']['result']['value'])
        self.assertEqual(b'{"value":0.00004661}', self.rows()[0]['raw'])
    def test_threaded_core_callbacks_are_serialized(self):
        trace = self.open()
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda i: trace.capture('chain.rpc', {'height': i}), range(40)))
        self.assertEqual(list(range(1, 41)), [r['seq'] for r in self.rows()])
        self.assertEqual(40, trace.verify()['records'])
    def test_retention_archives_closed_partitions_without_erasing_event_history(self):
        journal = self.root / 'state.sqlite'; journal.write_bytes(b'financial journal remains untouched')
        trace = self.open(retention_days=2)
        for day in range(4):
            trace.append('scheduler.tick', {'day': day}); self.now += 86400
        trace.archive()
        self.assertTrue(list((self.root / 'trace-archive').glob('trace-*.sqlite')))
        self.assertEqual(4, len(self.rows()))
        self.assertEqual(b'financial journal remains untouched', journal.read_bytes())
        self.assertEqual(4, trace.verify()['records'])
    def test_older_capture_day_cannot_reopen_and_append_to_closed_history(self):
        trace = self.open(); trace.append('scheduler.tick', {})
        self.now += 86400; trace.append('scheduler.tick', {})
        self.now -= 86400
        with self.assertRaises(ValueError): trace.append('scheduler.tick', {})
    def test_record_bounds_retain_a_marker_without_partial_secret_output(self):
        trace = self.open(max_record_bytes=128)
        trace.capture('driver.stderr', {'text': 'x' * 256}, raw=b'x' * 256)
        self.assertTrue(self.rows()[0]['payload']['redacted'])
        self.assertIsNone(self.rows()[0]['raw'])
    def test_readers_filter_actor_action_and_time_without_rewriting_files(self):
        trace = self.open(); trace.append('driver.call', {}, actor='actor-09', action_id='one')
        first = self.now; self.now += 10
        trace.append('driver.call', {}, actor='actor-03', action_id='two')
        self.assertEqual(['one'], [r['action_id'] for r in trace.records(actor='actor-09')])
        self.assertEqual(['two'], [r['action_id'] for r in trace.records(after=first + 1)])
        self.assertEqual(['one'], [r['action_id'] for r in trace.records(before=first)])
        self.assertEqual(2, trace.verify()['records'])

    def test_symlink_archive_is_rejected_without_following_external_partitions(self):
        from simulator.trace import partition_paths
        external=self.root/'external';external.mkdir()
        (self.root/'trace-archive').symlink_to(external,target_is_directory=True)
        with self.assertRaises(ValueError):partition_paths(self.root)

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from simulator import process


class ProcessRawCaptureTests(unittest.TestCase):
    def test_complete_public_stdout_and_stderr_are_captured_without_stdin(self):
        import sys
        stdout = []; stderr = []
        result = asyncio.run(process.json_command([sys.executable, '-c',
            'import sys; sys.stdin.read(); sys.stderr.write("public diagnostic\\n"); print("{\\"status\\":\\"ok\\"}")'],
            {'public': True}, on_stdout_raw=stdout.append, on_stderr_raw=stderr.append))
        self.assertEqual('ok', result['status'])
        self.assertEqual(b'{"status":"ok"}\n', stdout[0]['raw'])
        self.assertEqual(b'public diagnostic\n', stderr[0]['raw'])
        self.assertNotIn(b'public', stdout[0]['raw'])
    def test_failed_commands_preserve_bounded_stdout_and_raw_diagnostics(self):
        import sys
        stdout = []; stderr = []
        with self.assertRaises(process.CommandError):
            asyncio.run(process.json_command([sys.executable, '-c',
                'import sys; print("partial public output"); sys.stderr.write("failure\\n"); sys.exit(1)'],
                on_stdout_raw=stdout.append, on_stderr_raw=stderr.append))
        self.assertEqual(b'partial public output\n', stdout[0]['raw'])
        self.assertEqual(b'failure\n', stderr[0]['raw'])


class ObserverRawCaptureTests(unittest.TestCase):
    def test_lightning_full_public_rpc_is_preserved_before_summary_projection(self):
        from simulator.remote_observer import lightning
        responses = {'getinfo': {'id': 'node', 'network': 'signet', 'blockheight': 10, 'extra_public': 'keep'},
            'listfunds': {'outputs': [{'txid': 'a' * 64, 'amount_msat': 1000, 'extra_public': 'keep'}]},
            'listpeerchannels': {'channels': [{'state': 'CHANNELD_NORMAL', 'extra_public': 'keep'}]}}
        async def command(argv, **kwargs): return responses[argv[-1]]
        samples = []
        with patch('simulator.remote_observer.json_command', AsyncMock(side_effect=command)):
            result = asyncio.run(lightning('fixture-node', capture=samples.append))
        self.assertEqual(3, len(samples))
        self.assertEqual('keep', next(s for s in samples if s['payload']['method'] == 'getinfo')['payload']['result']['extra_public'])
        self.assertNotIn('extra_public', result)
    def test_secret_node_output_becomes_a_marker_without_rejecting_healthy_public_summary(self):
        from simulator.remote_observer import sample
        record = sample('lightning', 'getinfo', [], {'id': 'node', 'mnemonic': 'never publish'}, raw=b'{"mnemonic":"never publish"}')
        self.assertTrue(record['payload']['redacted'])
        self.assertIsNone(record['raw'])
        self.assertNotIn('never publish', json.dumps(record))


class ChainRawCaptureTests(unittest.TestCase):
    def test_exact_rpc_bytes_and_consumer_are_recorded_without_http_authorization(self):
        from simulator.chain import ChainReader
        class Reply:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, bound=-1): return b'{"result":{"txid":"public","value":0.00004661},"error":null}'
        with tempfile.TemporaryDirectory() as tmp:
            credential = Path(tmp) / 'private-auth'; credential.write_text('local-user:local-token')
            samples = []; reader = ChainReader('http://127.0.0.1:1234', credential, 'genesis', capture=samples.append, consumer='payout-check')
            with patch('simulator.chain.urllib.request.urlopen', return_value=Reply()): result = reader.call('getrawtransaction', 'a' * 64, True)
            self.assertEqual('0.00004661', str(result['value']))
            self.assertEqual('payout-check', samples[0]['payload']['consumer'])
            self.assertIn(b'0.00004661', samples[0]['raw'])
            self.assertNotIn('local-token', json.dumps(samples, default=str))


class FixtureLogCaptureTests(unittest.TestCase):
    def test_only_daemon_logs_are_copied_and_secret_logs_are_redacted_in_trace(self):
        from simulator.fixture_logs import collect_daemon_logs
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root / 'test-data' / 'fixture' / 'captaind'; source.mkdir(parents=True)
            (source / 'stdout.log').write_text('public round event\n')
            (source / 'stderr.log').write_text('mnemonic: never publish\n')
            (source / 'mnemonic').write_text('never read this file')
            manifest = collect_daemon_logs(root)
            self.assertEqual(2, len(manifest['files']))
            self.assertTrue((root / 'daemon-logs' / 'fixture' / 'captaind' / 'stdout.log').is_file())
            self.assertFalse((root / 'daemon-logs' / 'fixture' / 'captaind' / 'mnemonic').exists())
            from simulator.trace import iter_records
            rows = list(iter_records(root))
            self.assertEqual(2, len(rows))
            self.assertTrue(any(row['payload'].get('redacted') for row in rows))

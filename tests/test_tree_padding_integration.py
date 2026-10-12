import asyncio
import csv
import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, patch

from simulator.config import Config, verify_executables
from simulator.engine import Engine, initialize
from simulator.model import SIGNET_GENESIS
from simulator.padding import PADDING_AMOUNT_SAT, PADDING_PUBKEY, PADDING_UNLOCK_HASH, capture_snapshot, record_decoded
from simulator.ownership import record_server_page
from simulator.report import generate
from simulator.store import Store


class PaddingIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = Store(self.root, 'synthetic', 10000)
        initialize(self.store)
        self.config = Config(self.root, (), (), self.root / 'wallets', SIGNET_GENESIS,
                             'container', 'sha256:' + 'a' * 64, 'server', 10000, 30, 30, False)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_read_only_padding_decoder_still_requires_declared_executable_hash(self):
        executable = self.root / 'decoder'
        executable.write_bytes(b'public decoder')
        runtime = {'active': False, 'server_policy_command': [str(executable)]}
        with self.assertRaises(ValueError): verify_executables(runtime, {})
        verify_executables(runtime, {str(executable): hashlib.sha256(executable.read_bytes()).hexdigest()})

    def test_inventory_ingestion_decodes_without_changing_original_observation(self):
        config = replace(self.config, inventory_command=('inventory',), server_policy_command=('decoder',))
        page = {'kind': 'coins', 'rows': [], 'next': None, 'inventory_consistent': False}
        with patch('simulator.engine.json_command', AsyncMock(return_value=page)), \
                patch('simulator.engine.collect_padding', AsyncMock()) as collector:
            asyncio.run(Engine(config, self.store).collect_inventory())
        collector.assert_awaited_once_with(self.store, ('decoder',), 'server', limit=16)

    def test_json_markdown_html_and_historical_csv_separate_padding(self):
        raw = {'vtxo_id': 'b' * 64 + ':0', 'signed_vtxo': 'ab', 'expiry': 99,
               'policy_type': 'pubkey', 'spend_state': 'unclaimed'}
        record_server_page(self.store, {'kind': 'coins', 'rows': [raw], 'next': None, 'inventory_consistent': False})
        record_decoded(self.store, raw, {'schema_version': 1, 'id': raw['vtxo_id'], 'chain_anchor': 'a' * 64 + ':0',
            'amount_sat': 330, 'policy': 'pubkey', 'server_pubkey': 'server', 'expiry_height': 99,
            'candidate_user_pubkey': PADDING_PUBKEY, 'unlock_hash': PADDING_UNLOCK_HASH, 'arkoor_transition_count': 0,
            'tree_padding': True, 'chain_contract_verified': False, 'client_owner_verified': False}, 'server', 'c' * 64)
        sample = {'observed_at': 100, 'height': 100, 'complete': False, 'stable_tip': True, 'initial_block_download': False}
        snapshot_id = self.store.add_snapshot(sample)
        # add_snapshot returns no ID; the journal is the authoritative source.
        snapshot_id = self.store.db.execute('SELECT id FROM snapshot ORDER BY id DESC LIMIT 1').fetchone()[0]
        capture_snapshot(self.store, snapshot_id, sample)
        result = generate(self.store)
        self.assertEqual(1, result['tree_padding']['tree_padding_unclaimed'])
        self.assertEqual(0, result['expired_unclaimed_outputs']['expired_unclaimed_public_key_rows'])
        self.assertIsNone(result['tree_padding']['tree_padding_locked_sat'])
        self.assertIn('Operator padding locked within existing backing: unknown', (self.root / 'report.md').read_text())
        self.assertIn('Protocol padding: 1 unclaimed', (self.root / 'index.html').read_text())
        with (self.root / 'capital.csv').open() as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual('1', rows[0]['tree_padding_unclaimed'])
        self.assertEqual('', rows[0]['tree_padding_locked_sat'])

    def test_protocol_constants_cannot_be_repinned_as_spending_policy(self):
        for field, value in [('expected_padding_pubkey', '02' + '11' * 32),
                             ('expected_padding_unlock_hash', '00' * 32),
                             ('expected_padding_amount_sat', 331)]:
            with self.subTest(field=field):
                with self.assertRaises(ValueError): replace(self.config, **{field: value})

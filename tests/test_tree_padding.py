"""Padding is protocol inventory, not an owner entitlement or a new asset."""
import asyncio
import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from simulator.engine import initialize
from simulator.model import InvariantError, canonical
from simulator.ownership import record_server_page
from simulator.store import Store


class TreePaddingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name), 'synthetic', 10000)
        initialize(self.store)
        self.anchor = 'a' * 64 + ':0'
        self.coin = 'b' * 64 + ':0'
        self.server = '03' + '11' * 32
        self.raw = {'vtxo_id': self.coin, 'signed_vtxo': 'ab', 'expiry': 99,
                    'policy_type': 'pubkey', 'spend_state': 'unclaimed'}
        record_server_page(self.store, {'kind': 'coins', 'rows': [self.raw],
                                     'next': None, 'inventory_consistent': False})

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def decoded(self, **changes):
        from simulator.padding import PADDING_PUBKEY, PADDING_UNLOCK_HASH
        return {'schema_version': 1, 'id': self.coin, 'chain_anchor': self.anchor,
                'amount_sat': 330, 'policy': 'pubkey', 'server_pubkey': self.server,
                'expiry_height': 99, 'candidate_user_pubkey': PADDING_PUBKEY,
                'unlock_hash': PADDING_UNLOCK_HASH, 'arkoor_transition_count': 0,
                'tree_padding': True, 'chain_contract_verified': False,
                'client_owner_verified': False, **changes}

    def classify(self, **changes):
        from simulator.padding import record_decoded
        record_decoded(self.store, self.raw, self.decoded(**changes),
                       self.server, 'c' * 64)

    def test_decoded_padding_is_excluded_without_deleting_raw_versions_or_events(self):
        from simulator.entitlements import unclaimed_expired_report
        from simulator.padding import report
        self.classify()
        result = unclaimed_expired_report(self.store, 100)
        self.assertEqual(0, result['expired_unclaimed_public_key_rows'])
        self.assertEqual([], result['rows'])
        self.assertEqual(1, report(self.store)['tree_padding_unclaimed'])
        self.assertEqual(1, report(self.store, height=100)['tree_padding_expired_unclaimed'])
        self.assertEqual(self.raw, json.loads(self.store.db.execute(
            "SELECT payload FROM server_item WHERE kind='coins'").fetchone()[0]))
        self.assertEqual(1, self.store.db.execute('SELECT count(*) FROM server_item_version').fetchone()[0])
        self.store.verify_event_chain()

    def test_unsigned_server_padding_flag_and_unknown_decode_remain_user_candidates(self):
        from simulator.entitlements import unclaimed_expired_report
        self.raw['tree_padding'] = True
        record_server_page(self.store, {'kind': 'coins', 'rows': [self.raw],
                                     'next': None, 'inventory_consistent': False})
        result = unclaimed_expired_report(self.store, 100)
        self.assertEqual(1, result['expired_unclaimed_public_key_rows'])
        self.assertFalse(result['rows'][0]['independent_ownership_verified'])

    def test_partial_marker_amount_policy_or_transition_does_not_hide_customer_candidate(self):
        from simulator.entitlements import unclaimed_expired_report
        for field, value in [('amount_sat', 331), ('candidate_user_pubkey', self.server),
                             ('unlock_hash', '00' * 32), ('policy', 'expiry'),
                             ('arkoor_transition_count', 1)]:
            with self.subTest(field=field):
                self.classify(**{field: value, 'tree_padding': False})
                self.assertEqual(1, unclaimed_expired_report(self.store, 100)['expired_unclaimed_public_key_rows'])

    def test_decoder_identity_or_false_positive_marker_is_rejected(self):
        for fields in [{'id': 'd' * 64 + ':0'}, {'server_pubkey': 'other'},
                       {'expiry_height': 98}, {'amount_sat': 331},
                       {'client_owner_verified': True}, {'arkoor_transition_count': True}]:
            with self.subTest(fields=fields):
                with self.assertRaises((InvariantError, ValueError)):
                    self.classify(**fields)

    def test_changed_serialized_coin_invalidates_classification(self):
        from simulator.entitlements import unclaimed_expired_report
        self.classify()
        self.raw['signed_vtxo'] = 'ac'
        record_server_page(self.store, {'kind': 'coins', 'rows': [self.raw],
                                     'next': None, 'inventory_consistent': False})
        self.assertEqual(1, unclaimed_expired_report(self.store, 100)['expired_unclaimed_public_key_rows'])

    def backing(self, amount=1000):
        proof = {**self.decoded(), 'chain_contract_verified': False, 'padding_backing_structure_verified': True, 'signed_path_valid': False,
                 'signed_hash': hashlib.sha256(bytes.fromhex('ab')).hexdigest(),
                 'anchor_amount_sat': amount, 'anchor_script': '5120' + '22' * 32}
        self.store.db.execute('INSERT OR REPLACE INTO tree_padding_contract VALUES (?,?,?,?,?)',
                             (self.coin, proof['signed_hash'], 'c' * 64, self.anchor, canonical(proof)))
        self.store.db.execute('INSERT OR REPLACE INTO tree_padding_backing VALUES (?,?,?,?)',
                             (self.anchor, amount, proof['anchor_script'], canonical(proof)))
        return proof

    def test_locked_padding_needs_positive_current_core_backing_and_is_only_a_subset(self):
        from simulator.padding import record_anchor_observation, report
        self.classify()
        self.assertIsNone(report(self.store)['tree_padding_locked_sat'])
        proof = self.backing()
        tip = {'blocks': 100, 'bestblockhash': 'd' * 64, 'initialblockdownload': False}
        utxo = {'bestblock': 'd' * 64, 'confirmations': 1, 'value': '0.00001000',
                'scriptPubKey': {'hex': proof['anchor_script']}}
        record_anchor_observation(self.store, self.anchor, tip, utxo)
        result = report(self.store, height=100)
        self.assertEqual(330, result['tree_padding_locked_sat'])
        self.assertEqual(1000, result['padding_backing_confirmed_sat'])
        self.assertFalse(result['additive_asset'])
        self.assertIsNone(report(self.store, height=101)['tree_padding_locked_sat'])

    def test_null_utxo_and_server_spent_are_not_confirmed_sweep_or_zero_capital(self):
        from simulator.padding import record_anchor_observation, report
        self.classify()
        self.backing()
        record_anchor_observation(self.store, self.anchor,
            {'blocks': 100, 'bestblockhash': 'd' * 64, 'initialblockdownload': False}, None)
        self.raw['spend_state'] = 'spent'
        record_server_page(self.store, {'kind': 'coins', 'rows': [self.raw],
                                     'next': None, 'inventory_consistent': False})
        result = report(self.store, height=100)
        self.assertEqual(1, result['tree_padding_server_spent'])
        self.assertEqual(0, result['tree_padding_swept'])
        self.assertIsNone(result['tree_padding_locked_sat'])
        self.assertTrue(result['unknowns'])

    def test_raw_confirmed_operator_sweep_releases_attribution_once(self):
        from simulator.padding import report
        self.classify()
        proof = self.backing()
        self.raw['spend_state'] = 'spent'
        record_server_page(self.store, {'kind': 'coins', 'rows': [self.raw],
                                     'next': None, 'inventory_consistent': False})
        tx = 'e' * 64
        evidence = {'raw_chain_verified': True, 'block_hash': 'f' * 64,
                    'transaction': {'txid': tx, 'inputs': [{'outpoint': self.anchor,
                    'amount_sat': 1000, 'script': proof['anchor_script']}],
                    'outputs': [{'vout': 0, 'amount_sat': 900, 'script': 'rounds'}]}}
        self.store.db.execute('INSERT INTO tree_padding_sweep VALUES (?,?,?)',
                             (tx, 100, canonical(evidence)))
        result = report(self.store, height=100)
        self.assertEqual(1, result['tree_padding_swept'])
        self.assertEqual(0, result['tree_padding_locked_sat'])
        self.assertEqual(result, report(self.store, height=100))

    def test_missing_inventory_cannot_report_zero_locked_padding(self):
        from simulator.padding import report
        self.store.db.execute('DELETE FROM server_item')
        self.assertIsNone(report(self.store)['tree_padding_locked_sat'])

    def test_bounded_classifier_uses_no_wallet_or_chain_call_and_is_idempotent(self):
        from simulator.padding import collect
        executable = Path(self.tmp.name) / 'decoder'
        executable.write_bytes(b'pinned public decoder')
        calls = []
        async def decoder(command, request, **kwargs):
            calls.append(request)
            return self.decoded()
        with patch('simulator.padding.json_command', decoder):
            asyncio.run(collect(self.store, [str(executable)], self.server, limit=1))
            tip = self.store.verify_event_chain()
            asyncio.run(collect(self.store, [str(executable)], self.server, limit=1))
        self.assertEqual([{'signed_vtxo': 'ab', 'server_pubkey': self.server}], calls)
        self.assertEqual(tip, self.store.verify_event_chain())
        self.assertEqual(0, self.store.db.execute('SELECT count(*) FROM owned_coin').fetchone()[0])

    def test_decoded_accessor_requires_current_bytes_and_optional_exact_server_pin(self):
        from simulator.padding import decoded_coin
        self.classify()
        value = decoded_coin(self.store, self.raw, server_pubkey=self.server)
        self.assertEqual(self.anchor, value['chain_anchor'])
        self.assertEqual(hashlib.sha256(bytes.fromhex('ab')).hexdigest(), value['signed_hash'])
        self.assertFalse(value['client_owner_verified'])
        self.assertIsNone(decoded_coin(self.store, self.raw, server_pubkey='other'))
        self.assertIsNone(decoded_coin(self.store, {**self.raw, 'signed_vtxo': 'ac'}))

    def test_historical_csv_cannot_be_backfilled_from_a_later_padding_observation(self):
        from simulator.padding import capture_snapshot, csv_values
        self.classify()
        result = capture_snapshot(self.store, 1, {'height': 100, 'stable_tip': True, 'initial_block_download': False})
        self.assertIsNone(csv_values(self.store, 1)['tree_padding_locked_sat'])
        self.assertEqual(1, csv_values(self.store, 1)['tree_padding_unclaimed'])
        self.assertIsNone(csv_values(self.store, 99)['tree_padding_unclaimed'])
        self.backing()
        self.assertEqual(result, capture_snapshot(self.store, 1, {'height': 100}))

    def test_two_padding_leaves_cannot_exceed_one_backing_output(self):
        from simulator.padding import report
        self.classify()
        self.backing(amount=500)
        second = {**self.raw, 'vtxo_id': 'f' * 64 + ':0'}
        record_server_page(self.store, {'kind': 'coins', 'rows': [second], 'next': None, 'inventory_consistent': False})
        from simulator.padding import record_decoded
        record_decoded(self.store, second, {**self.decoded(), 'id': second['vtxo_id']}, self.server, 'c' * 64)
        proof = {**self.decoded(), 'id': second['vtxo_id'], 'chain_contract_verified': False, 'padding_backing_structure_verified': True, 'signed_path_valid': False,
                 'signed_hash': hashlib.sha256(bytes.fromhex('ab')).hexdigest(),
                 'anchor_amount_sat': 500, 'anchor_script': '5120' + '22' * 32}
        self.store.db.execute('INSERT INTO tree_padding_contract VALUES (?,?,?,?,?)',
            (second['vtxo_id'], proof['signed_hash'], 'c' * 64, self.anchor, canonical(proof)))
        with self.assertRaises(InvariantError): report(self.store, height=100)

    def test_raw_sweep_requires_declared_return_script_and_matching_serialized_parents(self):
        from simulator.padding import record_sweep
        from simulator.bundle_audit import decode_transaction
        from simulator.ownership import EvidenceGap
        self.classify()
        raw_parent = '02000000' + '01' + '11' * 32 + '00000000' + '00' + 'ffffffff' + '01' + (1000).to_bytes(8, 'little').hex() + '02' + '5120' + '00000000'
        parent = decode_transaction(raw_parent); point = parent['txid'] + ':0'
        self.store.db.execute('INSERT INTO tree_padding_backing VALUES (?,?,?,?)', (point, 1000, '5120', '{}'))
        raw = '02000000' + '01' + bytes.fromhex(parent['txid'])[::-1].hex() + '00000000' + '00' + 'ffffffff' + '01' + (900).to_bytes(8, 'little').hex() + '02' + '0014' + '00000000'
        tx = decode_transaction(raw); evidence = {'txid': tx['txid'], 'height': 100, 'confirmations': 1, 'blockhash': 'f' * 64}
        wires = {parent['txid']: raw_parent, tx['txid']: raw}
        with self.assertRaises(EvidenceGap): record_sweep(self.store, evidence, wires)
        self.store.db.execute('INSERT INTO operator_script VALUES (?,?)', ('0014', '{}'))
        record_sweep(self.store, evidence, wires)
        before = self.store.verify_event_chain(); record_sweep(self.store, evidence, wires)
        self.assertEqual(before, self.store.verify_event_chain())
        with self.assertRaises(InvariantError): record_sweep(self.store, evidence, {**wires, parent['txid']: raw})
        with self.assertRaises(EvidenceGap): record_sweep(self.store, {**evidence, 'confirmations': 0}, wires)

    def test_classification_does_not_commit_an_enclosing_entitlement_transaction(self):
        from simulator.padding import classification
        with self.assertRaisesRegex(ValueError, 'rollback'):
            with self.store.transaction():
                classification(self.store, self.raw)
                self.store.db.execute("INSERT INTO meta VALUES ('padding-rollback','must disappear')")
                raise ValueError('rollback')
        self.assertIsNone(self.store.get_meta('padding-rollback'))

    def test_new_unclaimed_outputs_precede_history_and_failed_decodes_rotate(self):
        from simulator.padding import collect
        executable = Path(self.tmp.name) / 'decoder'
        executable.write_bytes(b'pinned public decoder')
        older = {**self.raw, 'vtxo_id': 'a' * 64 + ':0', 'signed_vtxo': 'ac'}
        history = {**self.raw, 'vtxo_id': '0' * 64 + ':0', 'signed_vtxo': 'ad', 'spend_state': 'spent'}
        record_server_page(self.store, {'kind': 'coins', 'rows': [older, history], 'next': None, 'inventory_consistent': False})
        self.store.db.execute("UPDATE server_item SET observed_at=1 WHERE id=?", (older['vtxo_id'],))
        self.store.db.execute("UPDATE server_item SET observed_at=2 WHERE id=?", (self.coin,))
        calls = []
        async def unavailable(command, request, **kwargs):
            calls.append(request['signed_vtxo'])
            raise ValueError('unavailable')
        with patch('simulator.padding.json_command', unavailable):
            asyncio.run(collect(self.store, [str(executable)], self.server, limit=1))
            asyncio.run(collect(self.store, [str(executable)], self.server, limit=1))
        self.assertEqual(['ab', 'ac'], calls)
        self.assertEqual(2, self.store.db.execute('SELECT observed_at FROM server_item WHERE id=?', (self.coin,)).fetchone()[0])

    def test_cookbook_sql_keeps_unknown_and_changed_serialized_rows(self):
        self.classify()
        text = (Path(__file__).resolve().parents[1] / 'docs/cookbook.md').read_text()
        query = text.split('```sql\n', 1)[1].split('```', 1)[0]
        self.assertEqual([], self.store.db.execute(query, {'tip': 100}).fetchall())
        self.raw['signed_vtxo'] = 'ac'
        record_server_page(self.store, {'kind': 'coins', 'rows': [self.raw], 'next': None, 'inventory_consistent': False})
        self.assertEqual(1, len(self.store.db.execute(query, {'tip': 100}).fetchall()))

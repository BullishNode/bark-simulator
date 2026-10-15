"""Synthetic controller privacy regressions; no native money qualification."""
import hashlib
import json
import unittest

from simulator.bundle_audit import decode_transaction
from simulator.chain import public_transaction
from simulator.model import canonical
from tests import test_fee_watch as fixture


TARGET_MARKER = bytes([0x5a]) * 32
PARENT_MARKER = bytes([0x6b]) * 32


def wire(parent, amount, *, script=b'', witness=b''):
    raw = bytearray((2).to_bytes(4, 'little'))
    if witness:
        raw.extend(b'\x00\x01')
    raw.extend(b'\x01' + bytes.fromhex(parent)[::-1] + bytes(4))
    raw.extend(bytes([len(script)]) + script + b'\xff' * 4)
    raw.extend(b'\x01' + amount.to_bytes(8, 'little') + b'\x02\x00\x14')
    if witness:
        raw.extend(b'\x01' + bytes([len(witness)]) + witness)
    raw.extend(bytes(4))
    return raw.hex()


class FeeWatchTracePrivacyTests(unittest.TestCase):
    # Reuse existing synthetic Core/store setup, without inheriting its tests.
    setUp = fixture.FeeWatchTests.setUp
    tearDown = fixture.FeeWatchTests.tearDown
    collect = fixture.FeeWatchTests.collect

    def configure(self, *, target_script=b'', target_witness=b'',
                  parent_script=b'', parent_witness=b''):
        self.parent_raw = wire('11' * 32, 10000, script=parent_script,
                               witness=parent_witness)
        self.parent = decode_transaction(self.parent_raw)
        self.raw = wire(self.parent['txid'], 9900, script=target_script,
                        witness=target_witness)
        self.tx = decode_transaction(self.raw)
        self.core.vsize = self.tx['vsize']
        self.store.db.execute('DELETE FROM server_item')
        self.store.db.execute('INSERT INTO server_item VALUES (?,?,?,?)',
            ('nursery', self.tx['txid'], canonical({'txid': self.tx['txid'],
              'kind': 'expiry-payout'}), 100))
        self.store.attach_trace()

    def records(self):
        return list(self.store.trace.records())

    def assert_not_exported(self, marker):
        self.assertNotIn(marker.hex(), json.dumps(self.records(), default=str),
                         'Public fee-watch trace contains opaque authorization bytes')

    def assert_private_facts(self, result):
        row = result['transactions'][0]
        self.assertEqual(100, row['mining_fee_sat'])
        self.assertEqual(hashlib.sha256(bytes.fromhex(self.raw)).hexdigest(),
                         row['raw_sha256'])
        self.assertEqual(self.tx['weight'], row['weight'])
        self.assertEqual(self.tx['vsize'], row['vsize'])

    def test_target_witness_does_not_escape_through_fee_trace(self):
        self.configure(target_witness=TARGET_MARKER)
        self.assert_private_facts(self.collect())
        self.assert_not_exported(TARGET_MARKER)

    def test_parent_witness_does_not_escape_through_fee_trace(self):
        self.configure(parent_witness=PARENT_MARKER)
        self.assert_private_facts(self.collect())
        self.assert_not_exported(PARENT_MARKER)

    def test_public_bodies_are_explicitly_stripped_and_preserve_both_txids(self):
        self.configure(target_witness=TARGET_MARKER, parent_witness=PARENT_MARKER)
        result = self.collect()
        self.assert_private_facts(result)
        payload = next(row['payload'] for row in self.records()
                       if row['kind'] == 'fee.watch.transaction')
        self.assertNotIn('raw_transactions', payload)
        for txid, original in ((self.tx['txid'], self.raw),
                               (self.parent['txid'], self.parent_raw)):
            body = payload['transaction_bodies'][txid]
            self.assertEqual('bitcoin-stripped-body-v1', body['encoding'])
            decoded = decode_transaction(body['transaction_body'])
            self.assertEqual(txid, decoded['txid'])
            self.assertLess(decoded['weight'], body['observed_original_weight_wu'])
            self.assertEqual(decode_transaction(original)['size'], body['observed_original_size'])
        self.assertIn('not authorization', payload['facts']['public_replay_scope'])

    def test_target_script_sig_is_a_public_gap_not_an_opaque_replay(self):
        self.configure(target_script=b'\x20' + TARGET_MARKER)
        with self.assertRaises(ValueError):
            public_transaction(self.raw)
        result = self.collect()
        self.assert_not_exported(TARGET_MARKER)
        self.assertTrue(result['unknowns'], 'Unprojectable wire must remain an evidence gap')

    def test_parent_script_sig_is_a_public_gap_not_an_opaque_replay(self):
        self.configure(parent_script=b'\x20' + PARENT_MARKER)
        with self.assertRaises(ValueError):
            public_transaction(self.parent_raw)
        result = self.collect()
        self.assert_not_exported(PARENT_MARKER)
        self.assertTrue(result['unknowns'], 'Unprojectable parent must remain an evidence gap')

    def test_unsafe_public_replay_gap_survives_cached_observation(self):
        self.configure(parent_script=b'\x20' + PARENT_MARKER)
        for tick in ('snapshot:1', 'snapshot:2'):
            result = self.collect(tick)
            self.assert_private_facts(result)
            self.assertIsNone(result['transactions'][0]['raw_evidence_reference'])
            self.assertTrue(any(item['bucket'] == 'transaction_public_projection'
                                for item in result['unknowns']))
            self.assert_not_exported(PARENT_MARKER)
        cached = json.loads(self.store.db.execute(
            'SELECT payload FROM fee_watch_transaction').fetchone()[0])
        self.assertTrue(cached['public_projection_gap'])
        self.assertIsNotNone(cached['public_projection_gap_reference'])
        self.assertIsNone(cached['trace_reference'])

    def test_private_measurement_keeps_original_wires_hash_and_signed_weight(self):
        from simulator.fee_watch import _measure
        self.configure(target_witness=TARGET_MARKER, parent_witness=PARENT_MARKER)
        facts, row, originals = _measure(self.core, self.tx['txid'])
        self.assertEqual(self.raw, originals[self.tx['txid']])
        self.assertEqual(self.parent_raw, originals[self.parent['txid']])
        self.assert_private_facts({'transactions': [row]})
        projected = public_transaction(self.raw)
        self.assertEqual(self.tx['txid'], decode_transaction(projected)['txid'])
        self.assertNotEqual(facts['raw_sha256'],
                            hashlib.sha256(bytes.fromhex(projected)).hexdigest())
        self.assertLess(decode_transaction(projected)['weight'], facts['weight'])
        self.assertEqual([], self.records())

    def test_opaque_core_error_body_is_not_exported_as_a_fee_gap_reason(self):
        self.configure()
        def fail(_txid):
            raise RuntimeError('Core error body ' + TARGET_MARKER.hex())
        self.core.tx = fail
        result = self.collect()
        self.assertEqual([], result['transactions'])
        self.assertTrue(any(item.get('reason') == 'RuntimeError'
                            for item in result['unknowns']))
        self.assert_not_exported(TARGET_MARKER)


if __name__ == '__main__':
    unittest.main()

"""Public observation privacy; synthetic wire bytes, never native money proof."""
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from simulator.bundle_audit import decode_transaction
from simulator.chain import ChainReader, public_transaction
from simulator.model import SIGNET_GENESIS


SENTINEL = bytes([0x5a]) * 32


def transaction(script=b'', witness=b''):
    raw = bytearray((2).to_bytes(4, 'little'))
    if witness:
        raw.extend(b'\x00\x01')
    raw.extend(b'\x01' + bytes([3])*32 + bytes(4))
    raw.extend(bytes([len(script)]) + script + b'\xff'*4)
    raw.extend(b'\x01' + (1000).to_bytes(8, 'little') + b'\x01\x51')
    if witness:
        raw.extend(b'\x01' + bytes([len(witness)]) + witness)
    raw.extend(bytes(4))
    return raw.hex()


def verbose(raw, script=b'', witness=b''):
    value = {'txid': decode_transaction(raw)['txid'], 'hex': raw,
             'vin': [{'txid': '03'*32, 'vout': 0, 'sequence': 4294967295,
                      'scriptSig': {'hex': script.hex(), 'asm': script.hex()}}], 'vout': []}
    if witness:
        value['vin'][0]['txinwitness'] = [witness.hex()]
    return value


class PublicTransactionPrivacyTests(unittest.TestCase):
    def capture_call(self, reply):
        captured = []
        with tempfile.TemporaryDirectory() as directory:
            credential = Path(directory) / 'credential'
            credential.write_text('synthetic:fixture')
            reader = ChainReader('http://127.0.0.1:31337', credential, SIGNET_GENESIS,
                                 capture=captured.append)
            with patch('urllib.request.urlopen', return_value=io.BytesIO(reply)):
                try:
                    result = reader.call('getrawtransaction', '03'*32, True)
                except ValueError:
                    result = None
        return result, captured

    def test_safe_raw_preserves_txid_and_omits_witness(self):
        raw = transaction(witness=SENTINEL)
        projected = public_transaction(raw)
        self.assertEqual(decode_transaction(projected)['txid'], decode_transaction(raw)['txid'])
        self.assertEqual(projected, transaction())
        self.assertNotIn(SENTINEL.hex(), projected)

    def test_safe_verbose_preserves_weight_without_witness(self):
        raw = transaction(witness=SENTINEL)
        value = verbose(raw, witness=SENTINEL)
        before = copy.deepcopy(value)
        projected = public_transaction(value)
        self.assertEqual(projected['hex'], transaction())
        self.assertEqual(projected['original_weight'], decode_transaction(raw)['weight'])
        self.assertEqual(projected['vin'][0]['witness_item_sizes'], [32])
        self.assertNotIn('txinwitness', projected['vin'][0])
        self.assertEqual(value, before)
        self.assertNotIn(SENTINEL.hex(), json.dumps(projected))

    def test_nonempty_script_sig_raw_is_refused(self):
        with self.assertRaises(ValueError):
            public_transaction(transaction(b'\x20' + SENTINEL))

    def test_nonempty_script_sig_verbose_is_refused(self):
        script = b'\x20' + SENTINEL
        with self.assertRaises(ValueError):
            public_transaction(verbose(transaction(script), script))

    def test_contradictory_script_sig_json_cannot_export_opaque_data(self):
        value = verbose(transaction())
        value['vin'][0]['scriptSig']['asm'] = SENTINEL.hex()
        with self.assertRaises(ValueError):
            public_transaction(value)

    def test_unsafe_capture_has_gap_but_private_result_is_unchanged(self):
        script = b'\x20' + SENTINEL
        value = verbose(transaction(script), script)
        result, captured = self.capture_call(json.dumps({'result': value, 'error': None}).encode())
        self.assertEqual(result, value)
        self.assertTrue(captured[0]['payload']['result'].get('public_projection_gap'))
        self.assertIsNone(captured[0]['raw'])
        self.assertNotIn(SENTINEL.hex(), json.dumps(captured))

    def test_malformed_transaction_reply_never_becomes_public_raw(self):
        result, captured = self.capture_call(b'{"result":{"hex":"' + SENTINEL.hex().encode() + b'","txid":')
        self.assertIsNone(result)
        self.assertEqual(captured[0]['payload']['error'], 'JSONDecodeError')
        self.assertIsNone(captured[0]['raw'])

    def test_failed_transaction_capture_omits_any_result_body(self):
        reader = object.__new__(ChainReader)
        captured = []
        reader.capture, reader.consumer = captured.append, 'synthetic-privacy'
        reader._capture('getrawtransaction', [], SENTINEL.hex(), 'ValueError', SENTINEL.hex().encode())
        self.assertIsNone(captured[0]['raw'])
        self.assertNotIn(SENTINEL.hex(), json.dumps(captured))

    def test_rpc_error_message_and_data_are_not_public_transaction_evidence(self):
        _, captured = self.capture_call(json.dumps({'error': {
            'code': -5, 'message': SENTINEL.hex(), 'data': {'opaque': SENTINEL.hex()}}}).encode())
        self.assertEqual(captured[0]['payload']['error'], {'code': -5})
        self.assertNotIn(SENTINEL.hex(), json.dumps(captured))

    def test_unclassified_rpc_error_string_is_not_exported(self):
        _, captured = self.capture_call(json.dumps({'error': SENTINEL.hex()}).encode())
        self.assertEqual(captured[0]['payload']['error'], 'ObservationError')
        self.assertNotIn(SENTINEL.hex(), json.dumps(captured))

    def test_bad_verbose_metadata_cannot_interrupt_the_private_response(self):
        for vin in (None, [42], [{'txinwitness': [23]}]):
            with self.subTest(vin=vin):
                value = verbose(transaction())
                value['vin'] = vin
                try:
                    result, captured = self.capture_call(json.dumps({'result': value}).encode())
                except (TypeError, AttributeError):
                    self.fail('Public metadata projection interrupted the private Core response')
                self.assertEqual(result, value)
                self.assertTrue(captured[0]['payload']['result'].get('public_projection_gap'))

    def test_other_public_rpc_raw_capture_is_retained(self):
        reader = object.__new__(ChainReader)
        captured = []
        reader.capture, reader.consumer = captured.append, 'synthetic-privacy'
        raw = b'{"result":1000}'
        reader._capture('getblockcount', [], 1000, None, raw)
        self.assertEqual(captured[0]['raw'], raw)


if __name__ == '__main__':
    unittest.main()

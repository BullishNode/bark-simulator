"""Synthetic privacy/parser controls only; no financial qualification credit."""
import hashlib
import json
import unittest

from simulator.bundle_audit import decode_transaction
from simulator.model import InvariantError
from simulator.private_transaction_projection import project_private_transaction,MAX_PRIVATE_TRANSACTION_BYTES
from tests.test_wallet_projection import transaction


class PrivateTransactionProjectionTests(unittest.TestCase):
    def setUp(self):
        self.raw=bytes.fromhex(transaction(['12'*32+':0'],[(99500,'5120'+'22'*32)]))
        self.txid=decode_transaction(self.raw.hex())['txid']

    def test_original_weight_hash_and_txid_are_retained_without_witness(self):
        d=project_private_transaction(self.txid,self.raw)
        expected=decode_transaction(self.raw.hex(),public_body=True)
        self.assertEqual(d['transaction_body'],expected['stripped_hex'])
        self.assertEqual(d['original_signed_weight_wu'],expected['weight'])
        self.assertEqual(d['original_signed_sha256'],hashlib.sha256(self.raw).hexdigest())
        self.assertNotIn('b1'*64,json.dumps(d))
        self.assertNotIn('complete',d)
        self.assertNotIn('terminal_payment_verified',d)

    def test_witness_preimage_never_crosses_public_boundary(self):
        # Replace this fixture's sole64byte witness with two stack items, adding a32byte preimage.
        raw=self.raw[:-70]+b'\x02\x40'+b'\xb1'*64+b'\x20'+b'\xc3'*32+self.raw[-4:]
        decoded=decode_transaction(raw.hex())
        self.assertEqual(decoded['txid'],self.txid)
        d=project_private_transaction(self.txid,raw)
        self.assertNotIn('c3'*32,json.dumps(d))
        self.assertNotIn('b1'*64,json.dumps(d))
        self.assertEqual(d['original_signed_weight_wu'],decoded['weight'])

    def test_script_sig_is_refused_rather_than_exported(self):
        raw=bytes.fromhex(transaction(['12'*32+':0'],[(99500,'5120'+'22'*32)],script_sig=b'sensitive-buffer'))
        txid=decode_transaction(raw.hex())['txid']
        with self.assertRaisesRegex(ValueError,'scriptSig'):
            project_private_transaction(txid,raw)

    def test_wrong_native_row_identity_cannot_relabel_bytes(self):
        with self.assertRaisesRegex(InvariantError,'differs'):
            project_private_transaction('aa'*32,self.raw)

    def test_truncation_or_trailing_bytes_are_refused(self):
        for raw in (self.raw[:-1],self.raw+b'\x00'):
            with self.assertRaises(ValueError):project_private_transaction(self.txid,raw)

    def test_bounds_types_and_id_are_checked_before_decoding(self):
        for raw in (b'',b'x'*(MAX_PRIVATE_TRANSACTION_BYTES+1),self.raw.hex(),list(self.raw)):
            with self.assertRaises(ValueError):project_private_transaction(self.txid,raw)
        for txid in (None,True,'AA'*32,self.txid+'.json'):
            with self.assertRaises(ValueError):project_private_transaction(txid,self.raw)


if __name__=='__main__':unittest.main()

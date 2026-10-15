"""Synthetic parser/privacy controls only; never a native money qualification."""
import json
import unittest

from simulator.bundle_audit import decode_transaction
from simulator.model import InvariantError
from simulator.ownership import EvidenceGap
from simulator.two_step_witness import project_private_witness
from tests.test_wallet_projection import transaction


class PrivateWitnessProjectionTests(unittest.TestCase):
    def setUp(self):
        self.identity={'version':1,'genesis':'11'*32,'server_pubkey':'02'+'33'*32}
        self.raw=transaction(['12'*32+':0'],[(99500,'5120'+'22'*32)],nonce=7)
        self.txid=decode_transaction(self.raw)['txid']
        self.point='44'*32+':0'
        self.witness={'tx':list(bytes.fromhex(self.raw)),
            'settlements':[{'id':self.point,'spk':list(bytes.fromhex('5120'+'22'*32)),'fee_sat':500}],
            'capital_releases':[{'id':self.point,'source':'55'*32+':0','receipt':'66'*32,
                'gross_sat':100000,'source_gross_sat':100100,'source_revision':0,'receipt_block_hash':'77'*32}]}
        self.history=(self.txid+'\n').encode()

    def project(self):
        return project_private_witness(json.dumps(self.identity).encode(),self.history,self.txid+'.json',
            json.dumps(self.witness).encode(),self.identity)

    def test_private_signature_bytes_are_stripped_and_never_terminal_proof(self):
        result=self.project()
        self.assertEqual(result['payout_txid'],self.txid)
        self.assertEqual(result['original_signed_weight_wu'],decode_transaction(self.raw)['weight'])
        self.assertEqual(result['transaction_body'],decode_transaction(self.raw,public_body=True)['stripped_hex'])
        self.assertNotIn('b1'*64,json.dumps(result))
        self.assertFalse(result['complete'])
        self.assertFalse(result['terminal_payment_verified'])
        self.assertIn('independent_confirmed_backing_and_payout_not_checked',result['gaps'])

    def test_torn_or_duplicate_history_is_rejected(self):
        self.history=self.txid.encode()
        with self.assertRaisesRegex(InvariantError,'torn'):self.project()
        self.history=((self.txid+'\n')*2).encode()
        with self.assertRaisesRegex(InvariantError,'duplicate'):self.project()

    def test_filename_is_bound_to_actual_private_transaction_id(self):
        self.txid='aa'*32;self.history=(self.txid+'\n').encode()
        with self.assertRaisesRegex(InvariantError,'txid differ'):self.project()

    def test_missing_or_legacy_fields_are_explicit_gaps(self):
        self.witness.pop('capital_releases');self.witness['settlements'][0]['spk']=None
        result=self.project()
        self.assertIn('native_capital_release_witness_unavailable',result['gaps'])
        self.assertIn('original_settlement_destination_unavailable:'+self.point,result['gaps'])
        self.assertEqual(result['capital_releases'],[])
        self.assertFalse(result['terminal_payment_verified'])

    def test_release_cannot_change_or_repeat_selected_settlement(self):
        self.witness['capital_releases'][0]['id']='ab'*32+':0'
        with self.assertRaisesRegex(InvariantError,'identity differs'):self.project()

    def test_duplicate_settlement_or_json_field_is_rejected(self):
        self.witness['settlements']*=2
        with self.assertRaisesRegex(InvariantError,'settlement appears twice'):self.project()
        with self.assertRaisesRegex(InvariantError,'duplicate native JSON'):
            project_private_witness(b'{"version":1,"version":1}',self.history,self.txid+'.json',b'{}',self.identity)

    def test_script_sig_never_crosses_public_boundary(self):
        self.raw=transaction(['12'*32+':0'],[(99500,'5120'+'22'*32)],script_sig=b'sensitive-buffer')
        self.txid=decode_transaction(self.raw)['txid'];self.history=(self.txid+'\n').encode()
        self.witness['tx']=list(bytes.fromhex(self.raw))
        with self.assertRaisesRegex(EvidenceGap,'scriptSig'):self.project()

    def test_bounds_and_unknown_fields_fail_closed(self):
        self.history=b'a'*4097
        with self.assertRaisesRegex(EvidenceGap,'bounded original history'):self.project()
        self.history=(self.txid+'\n').encode();self.witness['unrecognized']='payload'
        with self.assertRaisesRegex(ValueError,'schema'):self.project()

    def test_mismatched_network_or_server_never_projects(self):
        expected=dict(self.identity);expected['genesis']='99'*32
        with self.assertRaisesRegex(InvariantError,'identity differs'):
            project_private_witness(json.dumps(self.identity).encode(),self.history,self.txid+'.json',
                json.dumps(self.witness).encode(),expected)

    def test_impossible_release_does_not_become_a_zero_hold(self):
        self.witness['capital_releases'][0]['gross_sat']=100101
        with self.assertRaisesRegex(InvariantError,'exceeds'):self.project()

    def test_boolean_version_is_not_native_integer_version(self):
        self.identity['version']=True
        with self.assertRaisesRegex(InvariantError,'identity differs'):self.project()

    def test_two_releases_cannot_overallocate_the_same_physical_source(self):
        second=dict(self.witness['settlements'][0]);second['id']='45'*32+':0'
        self.witness['settlements'].append(second)
        second_release=dict(self.witness['capital_releases'][0]);second_release['id']=second['id']
        self.witness['capital_releases'].append(second_release)
        with self.assertRaisesRegex(InvariantError,'same source physical bound'):self.project()


if __name__=='__main__':unittest.main()

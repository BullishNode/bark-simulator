"""Public raw-chain replay rejects internally inconsistent exported evidence."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path


def transaction():
    raw = ('02000000'+'01'+'11'*32+'00000000'+'00'+'ffffffff'+'01'+
           (4661).to_bytes(8,'little').hex()+'02'+'0014'+'00000000')
    txid=hashlib.sha256(hashlib.sha256(bytes.fromhex(raw)).digest()).digest()[::-1].hex()
    return raw,txid


class BundleRawAuditTests(unittest.TestCase):
    def test_decode_recomputes_identity_and_exact_satoshis(self):
        from simulator.bundle_audit import decode_transaction
        raw,txid=transaction();decoded=decode_transaction(raw)
        self.assertEqual(txid,decoded['txid'])
        self.assertEqual(4661,decoded['outputs'][0]['amount_sat'])
        self.assertEqual('11'*32+':0',decoded['inputs'][0]['outpoint'])
        with self.assertRaises(ValueError):decode_transaction(raw+'00')
    def test_rpc_archive_rejects_mismatched_rpc_identity_and_raw_bytes(self):
        from simulator.bundle_audit import archived_transactions
        from simulator.model import InvariantError
        raw,txid=transaction()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);metadata={'method':'getrawtransaction','params':[txid,True],
                'result':{'txid':txid,'hex':raw,'confirmations':1}}
            (root/'sample.json').write_text(json.dumps(metadata))
            self.assertEqual(4661,archived_transactions(root)[txid]['decoded']['outputs'][0]['amount_sat'])
            metadata['result']['hex']=raw[:-8]+'01000000'
            (root/'sample.json').write_text(json.dumps(metadata))
            with self.assertRaises(InvariantError):archived_transactions(root)
    def test_partial_native_request_is_pending_without_invoking_binary(self):
        from simulator.bundle_audit import verify_native_proofs
        proof={'id':'coin','signed_vtxo':'aa','requests':[{'signed_vtxo':'aa','binding':{'seq':1}}],
            'proof':{'genesis':'genesis','server_pubkey':'server'}}
        result=verify_native_proofs([proof],{},'/nonexistent-public-verifier')
        self.assertFalse(result['native_protocol_reverified'])
        self.assertEqual('missing_raw_signature_request',result['gaps'][0]['kind'])
    def test_replay_core_refuses_nonpublic_rpc_and_unarchived_anchor(self):
        from simulator.bundle_audit import ReplayCore
        with ReplayCore('genesis',{}) as core:
            self.assertEqual('genesis',core.call('getblockhash',[0]))
            with self.assertRaises(ValueError):core.call('sendrawtransaction',['00'])
            with self.assertRaises(ValueError):core.call('getrawtransaction',['a'*64,False])
    def test_native_result_must_match_top_level_coin_value_and_identity(self):
        from simulator.bundle_audit import verify_native_proofs
        from simulator.model import InvariantError
        from unittest.mock import patch
        from types import SimpleNamespace
        raw,txid=transaction()
        bound={'mailbox_pk':'mailbox','seq':1,'spk':'0014','record_signature_valid':True,'key_link_signature_valid':True}
        validated={'id':'coin','user_pubkey':'public-key','amount_sat':5000,'chain_anchor':txid+':0',
            'genesis':'genesis','server_pubkey':'server','path':[],'binding':bound,
            'signed_path_valid':True,'anchor_confirmations':1}
        request={'signed_vtxo':'aa','key_link_attestation':'link',
                 'binding':{**bound,'record_attestation':'record'}}
        coin={'id':'coin','pubkey':'public-key','amount_sat':6000,'signed_vtxo':'aa',
              'proof':validated,'requests':[request]}
        with patch('simulator.bundle_audit.subprocess.run',return_value=SimpleNamespace(returncode=0,stdout=json.dumps(validated).encode())):
            with self.assertRaises(InvariantError):verify_native_proofs([coin],{txid:{'hex':raw,'info':{'confirmations':1}}},'public-verifier')

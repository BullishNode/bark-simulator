"""Private request boundaries only; no native identity is qualified here."""
import copy
import tempfile
import unittest
from pathlib import Path

class NoahNativeRequestTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.wallet=Path(self.tmp.name)/'actor-41';self.wallet.mkdir()
        self.phone={'actor':'actor-41','ark_address':'tark-public-fixture','fallback_script':'0014'+'22'*20,
            'auth_pubkey':'02'+'11'*32,'mailbox_id':'03'+'33'*32}
        self.chain={'network':'signet','phone_sdk_commit':'8f2286ee7e1631b0ceccd1631ec3b728a1bb0a52','server_pubkey':'02'+'44'*32}
    def tearDown(self):self.tmp.cleanup()
    def request(self,**changes):
        from simulator.noah_native_request import enrollment_request
        args=dict(identifier='setup-1',actor='actor-41',wallet=self.wallet,phone=self.phone,
            chain=self.chain,k1='aa'*32+'_1000',expiry=1500)
        args.update(changes);return enrollment_request(**args)
    def test_request_binds_all_frozen_public_phone_identities_without_payment_gate(self):
        request=self.request()
        self.assertEqual(self.phone['ark_address'],request['expected_ark_address'])
        self.assertEqual(self.phone['fallback_script'],request['expected_fallback_script'])
        self.assertEqual(self.phone['auth_pubkey'],request['expected_auth_pubkey'])
        self.assertEqual(self.phone['mailbox_id'],request['expected_mailbox_id'])
        self.assertEqual(self.chain['phone_sdk_commit'],request['expected_sdk_commit'])
        self.assertEqual('enrollment_material',request['operation'])
    def test_ordinary_original_wallet_paths_and_actor_drift_are_rejected(self):
        with self.assertRaises(ValueError):self.request(actor='actor-09')
        with self.assertRaises(ValueError):self.request(wallet=self.wallet.parent)
        phone=copy.deepcopy(self.phone);phone['actor']='actor-42'
        with self.assertRaises(ValueError):self.request(phone=phone)
        alias=self.wallet.parent/'actor-42';alias.symlink_to(self.wallet,target_is_directory=True)
        phone['actor']='actor-42'
        with self.assertRaises(ValueError):self.request(actor='actor-42',phone=phone,wallet=alias)
    def test_no_assumed_sdk_or_wrong_chain_is_accepted(self):
        for field,value in [('network','regtest'),('phone_sdk_commit','d47c6a4d115b30bf56219d69251fa9238d13f32d')]:
            chain=copy.deepcopy(self.chain);chain[field]=value
            with self.assertRaises(ValueError):self.request(chain=chain)
    def test_invalid_auth_mailbox_challenge_and_bounds_are_rejected(self):
        for field,value in [('auth_pubkey','11'*32),('mailbox_id','04'+'33'*32),('fallback_script','deadbeef')]:
            phone=copy.deepcopy(self.phone);phone[field]=value
            with self.assertRaises(ValueError):self.request(phone=phone)
        for value in ['aa'*32,'AA'*32+'_1000','aa'*32+'_NaN']:
            with self.assertRaises(ValueError):self.request(k1=value)
        with self.assertRaises(ValueError):self.request(expiry=True)
        with self.assertRaises(ValueError):self.request(identifier='../../outside')

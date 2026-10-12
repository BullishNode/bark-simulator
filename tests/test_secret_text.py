import unittest
from simulator.model import public_payload

class SecretTextTests(unittest.TestCase):
    def test_bare_public_test_mnemonic_is_rejected_without_field_label(self):
        # Well-known BIP39 test vector, never a funded wallet seed.
        phrase=' '.join(['abandon']*11+['about'])
        with self.assertRaises(ValueError):public_payload({'text':phrase})

    def test_native_preimage_debug_line_is_rejected(self):
        with self.assertRaises(ValueError):public_payload({'text':'payment_preimage: '+ 'ab'*32})

    def test_public_signed_coin_and_hashes_remain_allowed(self):
        public_payload({'signed_vtxo':'ab'*2048,'payment_hash':'cd'*32,
                        'success_preimage_hash_valid':True})

    def test_embedded_mnemonic_and_preimage_assignment_are_rejected(self):
        phrase=' '.join(['abandon']*11+['about'])
        for text in ('DEBUG wallet: '+phrase+'\nfinished', 'preimage = '+ 'ab'*32):
            with self.subTest(text=text),self.assertRaises(ValueError):public_payload({'text':text})

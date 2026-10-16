"""Strict64KiB matching activity replaces global verbose-body resource controls."""
import io,time,unittest
from unittest.mock import patch
from simulator.fresh_cash_readiness import _empty_mempool
from simulator.owned_mempool import MAX_RESPONSE_BYTES
from tests.test_owned_mempool import OwnedMempoolTests

class CashActivityCapacityControls(unittest.TestCase):
    def setUp(self):self.f=OwnedMempoolTests();self.f.setUp()
    def tearDown(self):self.f.tearDown()
    def collect(self,raw):
        with patch('urllib.request.urlopen',return_value=io.BytesIO(raw)):
            return _empty_mempool(self.f.chain,self.f.scripts,time.monotonic(),store=self.f.store,context={'collector':'synthetic-control'})
    def test_exact64k_reply_is_complete_with_truthful_source_metrics(self):
        raw=self.f.raw+b' '*(MAX_RESPONSE_BYTES-len(self.f.raw));receipt=self.collect(raw)
        self.assertEqual(MAX_RESPONSE_BYTES,receipt['response_bytes']);self.assertNotIn('bytes_checked',receipt)
    def test_one_byte_over64k_refuses_not_empty(self):
        raw=self.f.raw+b' '*(MAX_RESPONSE_BYTES+1-len(self.f.raw))
        with self.assertRaisesRegex(ValueError,'capture bound'):self.collect(raw)
    def test_nonempty_reply_refuses_even_below_response_limit(self):
        raw=b'{"id":1,"result":{"activity":[{"type":"spend"}]}}'
        with self.assertRaisesRegex(ValueError,'unconfirmed assets or spends'):self.collect(raw)

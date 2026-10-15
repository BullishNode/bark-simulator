"""Synthetic complete verbose-transport bounds; no Core or financial credit."""
import time
import unittest
from types import SimpleNamespace
from simulator.fresh_cash_readiness import _empty_mempool
from simulator.model import canonical


class CashMempoolCapacityTests(unittest.TestCase):
    def chain(self,size,outputs=1):
        txid='d'*64
        transaction={'txid':txid,'vout':[{'n':index,'scriptPubKey':{'hex':'unrelated'}} for index in range(outputs)],'verbose_padding':''}
        overhead=len(canonical(transaction).encode());transaction['verbose_padding']='x'*(size-overhead)
        self.assertEqual(size,len(canonical(transaction).encode()))
        return SimpleNamespace(call=lambda *args:[txid],tx=lambda point:transaction)
    def test_exact_sixteen_mib_complete_reply_is_accepted_with_declared_limits(self):
        result=_empty_mempool(self.chain(16*1024*1024),{'owned'},time.monotonic())
        self.assertEqual(16*1024*1024,result['bytes']);self.assertEqual(16*1024*1024,result['maximum_bytes'])
        self.assertEqual(1,result['unique_checked']);self.assertEqual(1,result['current_count'])
        self.assertEqual(50000,result['maximum_outputs']);self.assertEqual(2500,result['maximum_unique_transactions'])
        self.assertEqual(180,result['maximum_seconds'])
    def test_one_byte_over_sixteen_mib_refuses_with_exact_observed_counts(self):
        size=16*1024*1024+1
        with self.assertRaisesRegex(ValueError,f'observed_bytes={size}; maximum_bytes=16777216; observed_outputs=1; maximum_outputs=50000'):
            _empty_mempool(self.chain(size),{'owned'},time.monotonic())
    def test_output_limit_remains_complete_and_refuses_even_below_byte_limit(self):
        count=50001;rows=[{'n':index,'scriptPubKey':{'hex':'unrelated'}} for index in range(count)]
        size=len(canonical({'txid':'d'*64,'vout':rows,'verbose_padding':''}).encode())
        with self.assertRaisesRegex(ValueError,f'observed_bytes={size}; maximum_bytes=16777216; observed_outputs=50001; maximum_outputs=50000'):
            _empty_mempool(self.chain(size,outputs=count),{'owned'},time.monotonic())

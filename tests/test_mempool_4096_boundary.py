"""Synthetic full-parser capacity controls; no Core or financial qualification."""
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from simulator.fresh_cash_readiness import _empty_mempool
from tests import test_closed_cohort_sources, test_finite_funding_readiness


class MempoolBoundaryControls(unittest.TestCase):
    def collector(self, kind, count):
        ids = [f'{index:064x}' for index in range(count)]
        if kind == 'bootstrap':
            fixture = test_closed_cohort_sources.BootstrapSourceTests()
            fixture.setUp(); self.addCleanup(fixture.tearDown)
            fixture.chain.mempool = ids
            return fixture.chain, fixture.verify, 'scriptaddress0'
        if kind == 'initial':
            fixture = test_finite_funding_readiness.InitialFundingReadinessTests()
            fixture.setUp(); self.addCleanup(fixture.tearDown)
            fixture.chain.mempool = ids
            return fixture.chain, fixture.collect, fixture.chain.coin['scriptPubKey']
        chain = SimpleNamespace(call=lambda *args: ids,
            tx=lambda txid: {'txid': txid, 'vout': [{'n': 0, 'scriptPubKey': {'hex': 'unrelated'}}]})
        return chain, lambda: _empty_mempool(chain, {'owned'}, time.monotonic()), 'owned'

    def test_exact_4096_checks_every_transaction_in_all_three_collectors(self):
        for kind in ('bootstrap', 'initial', 'cash'):
            with self.subTest(kind=kind):
                chain, collect, _ = self.collector(kind, 4096)
                with patch.object(chain, 'tx', wraps=chain.tx) as reads:
                    result = collect()
                self.assertEqual(4096, reads.call_count)
                self.assertEqual({f'{index:064x}' for index in range(4096)},
                    {call.args[0] for call in reads.call_args_list})
                source = result.get('source', result)
                checked = source.get('mempool_transactions_checked', source.get('unique_checked'))
                self.assertEqual(4096, checked)

    def test_4097_refuses_before_any_transaction_body_in_all_three_collectors(self):
        for kind in ('bootstrap', 'initial', 'cash'):
            with self.subTest(kind=kind):
                chain, collect, _ = self.collector(kind, 4097)
                with patch.object(chain, 'tx', wraps=chain.tx) as reads:
                    with self.assertRaisesRegex(ValueError, 'bound'):
                        collect()
                self.assertEqual(0, reads.call_count)

    def test_owned_output_in_last_of_4096_is_never_truncated_or_accepted(self):
        for kind in ('bootstrap', 'initial', 'cash'):
            with self.subTest(kind=kind):
                chain, collect, owned = self.collector(kind, 4096)
                original = chain.tx
                def transaction(txid):
                    result = original(txid)
                    if txid == f'{4095:064x}':
                        result['vout'][0]['scriptPubKey']['hex'] = owned
                    return result
                with patch.object(chain, 'tx', side_effect=transaction) as reads:
                    with self.assertRaisesRegex(ValueError, 'unconfirmed'):
                        collect()
                self.assertEqual(4096, reads.call_count)


if __name__ == '__main__':
    unittest.main()

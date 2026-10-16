"""Replacement source controls for the former global4096 scanner; no live credit."""
import time
import unittest
from unittest.mock import patch
from simulator.fresh_cash_readiness import _empty_mempool
from tests import test_closed_cohort_sources,test_finite_funding_readiness
from tests.test_owned_mempool import OwnedMempoolTests
from tests.owned_activity_fixture import capture


class OwnedSourceCollectorControls(unittest.TestCase):
    def collector(self,kind):
        if kind=='bootstrap':
            f=test_closed_cohort_sources.BootstrapSourceTests();f.setUp();self.addCleanup(f.tearDown)
            return f.store,f.chain,f.verify
        if kind=='initial':
            f=test_finite_funding_readiness.InitialFundingReadinessTests();f.setUp();self.addCleanup(f.tearDown)
            return f.store,f.chain,f.collect
        f=OwnedMempoolTests();f.setUp();self.addCleanup(f.tearDown)
        def call(method,*args,**kwargs):
            return capture(f.chain,f.store,args,getattr(f.chain,'activity',{'activity':[]}))
        f.chain.call=call
        return f.store,f.chain,lambda:_empty_mempool(f.chain,f.scripts,time.monotonic(),store=f.store,context={'collector':'synthetic-control'})
    def test_all_three_collectors_use_complete_owned_activity_without_global_bodies(self):
        for kind in ('bootstrap','initial','cash'):
            with self.subTest(kind=kind):
                store,chain,collect=self.collector(kind);chain.mempool=[f'{i:064x}' for i in range(10000)]
                with patch.object(chain,'call',wraps=chain.call) as rpc:result=collect()
                calls=[call for call in rpc.call_args_list if call.args[0]=='getdescriptoractivity']
                self.assertEqual(1,len(calls));self.assertEqual([],calls[0].args[1]);self.assertIs(True,calls[0].args[3])
                self.assertEqual(65536,calls[0].kwargs['max_response_bytes'])
                self.assertFalse(any(call.args[0] in ('getrawmempool','getrawtransaction') for call in rpc.call_args_list))
                source=result.get('source',result);receipt=source.get('mempool_activity',source)
                self.assertEqual('core31-owned-script-activity-v1',receipt['source_schema'])
                self.assertNotIn('mempool_transactions_checked',source)
    def test_owned_receive_and_spend_refuse_in_every_production_collector(self):
        for kind in ('bootstrap','initial','cash'):
            for activity in ([{'type':'receive'}],[{'type':'spend'}]):
                with self.subTest(kind=kind,activity=activity):
                    _,chain,collect=self.collector(kind);chain.activity={'activity':activity}
                    with self.assertRaisesRegex(ValueError,'unconfirmed assets or spends'):collect()
    def test_missing_activity_and_timeout_refuse_in_every_production_collector(self):
        for kind in ('bootstrap','initial','cash'):
            with self.subTest(kind=kind):
                _,chain,collect=self.collector(kind);chain.activity={}
                with self.assertRaisesRegex(ValueError,'activity reply'):collect()
                original=chain.call
                def fail(method,*args,**kwargs):
                    if method=='getdescriptoractivity':raise TimeoutError('synthetic')
                    return original(method,*args,**kwargs)
                with patch.object(chain,'call',side_effect=fail),self.assertRaises(TimeoutError):collect()

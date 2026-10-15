"""Synthetic transport controls for fixed read-only public descriptor scans."""
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from simulator.chain import ChainReader


class CoreScanBoundsTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.token=Path(self.tmp.name)/'rpc'
        self.token.write_text('synthetic:fixture');self.token.chmod(0o600)
        self.chain=ChainReader('http://127.0.0.1:1',self.token,'synthetic-genesis')
    def tearDown(self):self.tmp.cleanup()
    def test_original_fresh_range_and_actual_operator_range_are_bounded(self):
        for last in (19,97,1999):
            reply=io.BytesIO(json.dumps({'result':{'success':True},'error':None}).encode())
            with self.subTest(last=last),patch('simulator.chain.urllib.request.urlopen',return_value=reply) as transport:
                self.assertTrue(self.chain.call('scantxoutset','start',[{'desc':'wpkh(public)#checksum','range':[0,last]}])['success'])
                request=transport.call_args.args[0]
                self.assertEqual([0,last],json.loads(request.data)['params'][1][0]['range'])
    def test_out_of_bound_or_untyped_ranges_and_nonstart_calls_never_reach_core(self):
        ranges=([0,18],[0,2000],[1,97],[-1,97],[0,True],[False,97],[0,97.0],[0],None)
        with patch('simulator.chain.urllib.request.urlopen') as transport:
            for interval in ranges:
                with self.subTest(interval=interval),self.assertRaisesRegex(ValueError,'bounded public'):
                    self.chain.call('scantxoutset','start',[{'desc':'wpkh(public)#checksum','range':interval}])
            for operation in ('abort','status-with-args'):
                with self.subTest(operation=operation),self.assertRaisesRegex(ValueError,'bounded public'):
                    self.chain.call('scantxoutset',operation,[])
            transport.assert_not_called()
    def test_only_scan_start_accepts_extended_timeout_and_status_is_read_only(self):
        for method,args,timeout,result in (
                ('scantxoutset',('start',[{'desc':'wpkh(public)#checksum','range':[0,97]}]),120,{'success':True}),
                ('scantxoutset',('status',),12,None)):
            reply=io.BytesIO(json.dumps({'result':result,'error':None}).encode())
            with patch('simulator.chain.urllib.request.urlopen',return_value=reply) as transport:
                self.assertEqual(result,self.chain.call(method,*args,timeout=timeout))
                self.assertEqual(timeout,transport.call_args.kwargs['timeout'])
        with patch('simulator.chain.urllib.request.urlopen') as transport:
            for method,args,timeout in (('getblockchaininfo',(),120),('scantxoutset',('status',),120),
                    ('scantxoutset',('start',[{'desc':'wpkh(public)#checksum','range':[0,97]}]),121)):
                with self.subTest(method=method,args=args),self.assertRaisesRegex(ValueError,'response bounds'):
                    self.chain.call(method,*args,timeout=timeout)
            transport.assert_not_called()

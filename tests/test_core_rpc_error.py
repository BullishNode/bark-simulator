"""Real ChainReader parsing/trace with synthetic HTTP replies, no Core money."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from simulator.chain import ChainReader, CoreRpcError
from simulator.model import SIGNET_GENESIS
from simulator.store import Store


class Response:
    def __init__(self,value):self.raw=json.dumps(value).encode()
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def read(self,maximum):return self.raw[:maximum]


class CoreErrorTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();root=Path(self.tmp.name)
        self.credential=root/'reader';self.credential.write_text('synthetic:credential')
        self.store=Store(root/'state','synthetic',1000);self.store.attach_trace()
        self.chain=ChainReader('http://127.0.0.1:1',self.credential,SIGNET_GENESIS,capture=self.store.trace_sample)
        self.txid='a'*64
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def reply(self,**changes):
        value={'jsonrpc':'2.0','id':1,'error':{'code':-5,'message':'opaque diagnostic','data':'00ff'},'result':None}
        value.update(changes);return value
    def test_matched_error_is_additive_valueerror_with_exact_method_params_and_capture(self):
        with patch('simulator.chain.urllib.request.urlopen',return_value=Response(self.reply())):
            with self.assertRaises(CoreRpcError) as caught:self.chain.tx(self.txid)
        error=caught.exception
        self.assertIsInstance(error,ValueError);self.assertEqual(-5,error.code)
        self.assertEqual('getrawtransaction',error.method);self.assertEqual((self.txid,True),error.params)
        self.assertEqual(self.chain.last_capture,error.capture)
        self.assertNotIn('opaque',str(error));self.assertNotIn('00ff',str(error))
    def test_wrong_id_missing_envelope_noninteger_code_and_ambiguous_result_are_not_typed(self):
        replies=[self.reply(id=2),self.reply(id=True),self.reply(jsonrpc='1.0'),self.reply(jsonrpc=None),
            self.reply(error={'code':'-5'}),self.reply(error={'code':True}),self.reply(result={'txid':self.txid})]
        for reply in replies:
            with self.subTest(reply=reply),patch('simulator.chain.urllib.request.urlopen',return_value=Response(reply)):
                with self.assertRaises(ValueError) as caught:self.chain.tx(self.txid)
                self.assertNotIsInstance(caught.exception,CoreRpcError)
    def test_other_rpc_error_codes_remain_identifiable_and_never_claim_absence(self):
        with patch('simulator.chain.urllib.request.urlopen',return_value=Response(self.reply(error={'code':-28}))):
            with self.assertRaises(CoreRpcError) as caught:self.chain.tx(self.txid)
        self.assertEqual(-28,caught.exception.code)
    def test_http_or_transport_failure_is_never_typed_rpc_absence(self):
        with patch('simulator.chain.urllib.request.urlopen',side_effect=TimeoutError('synthetic timeout')):
            with self.assertRaises(TimeoutError):self.chain.tx(self.txid)
    def test_error_trace_preserves_only_code_and_omits_raw_opaque_error_bytes(self):
        with patch('simulator.chain.urllib.request.urlopen',return_value=Response(self.reply())):
            with self.assertRaises(CoreRpcError):self.chain.tx(self.txid)
        from simulator.trace import readonly,partition_paths
        connection=readonly(partition_paths(self.store.trace.root)[0])
        try:row=connection.execute('SELECT payload,raw FROM trace ORDER BY seq DESC LIMIT 1').fetchone()
        finally:connection.close()
        self.assertIsNone(row['raw']);self.assertEqual({'code':-5},json.loads(row['payload'])['error'])
        self.assertNotIn('opaque',row['payload']);self.assertNotIn('00ff',row['payload'])

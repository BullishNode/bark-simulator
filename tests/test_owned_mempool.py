"""Pure strict transport/provenance controls, never live Core evidence."""
import io
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from simulator.chain import ChainReader
from simulator.engine import initialize
from simulator.model import SIGNET_GENESIS,canonical
from simulator.owned_mempool import (arguments,validate_arguments,decode_reply,collect,verify,
    MAX_RESPONSE_BYTES,MAX_SCRIPTS)
from simulator.store import Store


class OwnedMempoolTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.store=Store(self.root/'state','source-control',10000);initialize(self.store);self.store.attach_trace()
        credential=self.root/'fake-cookie';credential.write_text('synthetic:credential')
        self.chain=ChainReader('http://127.0.0.1:18443',credential,SIGNET_GENESIS,capture=self.store.trace_sample)
        self.context={'collector':'synthetic-control','height':100,'tip_hash':'a'*64}
        self.scripts={'0014'+'ab'*20};self.raw=canonical({'jsonrpc':'2.0','id':1,'result':{'activity':[]}}).encode()
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def run_source(self,raw=None):
        with patch('urllib.request.urlopen',return_value=io.BytesIO(self.raw if raw is None else raw)) as rpc:
            receipt=collect(self.store,self.chain,self.scripts,time.monotonic(),context=self.context)
        request=rpc.call_args.args[0]
        self.assertEqual({'method':'getdescriptoractivity','params':[[],['raw('+next(iter(self.scripts))+')'],True]},
            {key:json.loads(request.data)[key] for key in ('method','params')})
        return receipt
    def test_complete_empty_activity_has_authenticated_distinct_schema(self):
        receipt=self.run_source();self.assertEqual(receipt,verify(self.store,receipt,expected_context=self.context))
        self.assertEqual('core31-owned-script-activity-v1',receipt['source_schema'])
        self.assertEqual(1,receipt['script_count']);self.assertEqual(65536,receipt['maximum_response_bytes'])
        for old in ('transactions','current_txids','unique_checked','current_count','passes','mempool_transactions_checked'):
            self.assertNotIn(old,receipt)
    def test_owned_receive_spend_and_parent_child_net_zero_always_hold(self):
        for activity in ([{'type':'receive'}],[{'type':'spend'}],[{'type':'receive'},{'type':'spend'}]):
            raw=canonical({'jsonrpc':'2.0','id':1,'result':{'activity':activity}}).encode()
            with self.subTest(activity=activity),self.assertRaisesRegex(ValueError,'unconfirmed assets or spends'):
                self.run_source(raw)
    def test_missing_malformed_duplicate_and_error_replies_fail_closed(self):
        replies=[b'{}',b'{"id":1,"result":{}}',b'{"id":1,"result":{"activity":null}}',
            b'{"id":1,"result":{"activity":[],"truncated":true}}',
            b'{"id":1,"result":{"activity":[{"type":"receive"}],"activity":[]}}',
            b'{"id":1,"result":{"activity":[]},"result":{"activity":[]}}',
            b'{"id":1,"error":{"code":-1,"message":"unknown RPC"}}',
            b'{"id":true,"result":{"activity":[]}}',b'not json']
        for raw in replies:
            with self.subTest(raw=raw),self.assertRaises(ValueError):self.run_source(raw)
    def test_exact_64k_response_and_one_byte_over_boundary(self):
        raw=self.raw+b' '*(MAX_RESPONSE_BYTES-len(self.raw))
        self.assertEqual(MAX_RESPONSE_BYTES,self.run_source(raw)['response_bytes'])
        with self.assertRaisesRegex(ValueError,'capture bound'):self.run_source(raw+b' ')
    def test_timeout_and_source_deadline_hold_without_an_absence_receipt(self):
        with patch('urllib.request.urlopen',side_effect=TimeoutError),self.assertRaises(TimeoutError):
            collect(self.store,self.chain,self.scripts,time.monotonic(),context=self.context)
        with patch('urllib.request.urlopen') as rpc,self.assertRaisesRegex(ValueError,'deadline'):
            collect(self.store,self.chain,self.scripts,time.monotonic()-181,context=self.context)
        rpc.assert_not_called()
    def test_exact_2000_owning_scripts_are_requested_and_2001_holds(self):
        scripts={f'{index:064x}' for index in range(MAX_SCRIPTS)}
        args=arguments(scripts);self.assertEqual(MAX_SCRIPTS,len(validate_arguments(args)))
        with self.assertRaisesRegex(ValueError,'bounded'):arguments(scripts|{'ff'*32})
    def test_fixed_rpc_arguments_and_bounds_reject_before_http(self):
        valid=arguments(self.scripts)
        bad=[([],valid[1],False),([],valid[1]),(['a'*64],valid[1],True),([],[],True),
            ([],[valid[1][0],valid[1][0]],True),([],['raw(not-hex)'],True),
            ([],[{'desc':'ranged','range':[0,2000]}],True)]
        for args in bad:
            with self.subTest(args=args),patch('urllib.request.urlopen') as rpc,self.assertRaises(ValueError):
                self.chain.call('getdescriptoractivity',*args,max_response_bytes=65536)
            rpc.assert_not_called()
        with patch('urllib.request.urlopen') as rpc,self.assertRaisesRegex(ValueError,'response bound'):
            self.chain.call('getdescriptoractivity',*valid,max_response_bytes=65537)
        rpc.assert_not_called()
    def test_original_trace_wrong_script_digest_or_reference_cannot_be_rebound(self):
        receipt=self.run_source()
        for field,value in [('scripts',['0014'+'cd'*20]),('script_set_sha256','0'*64),
                ('raw_trace',None),('response_bytes',1),('raw_response_sha256','0'*64),('include_mempool',False)]:
            with self.subTest(field=field),self.assertRaises(ValueError):verify(self.store,{**receipt,field:value},expected_context=self.context)
    def test_valid_receipt_for_different_owning_source_context_is_rejected(self):
        receipt=self.run_source()
        with self.assertRaisesRegex(ValueError,'collector context'):
            verify(self.store,receipt,expected_context={'collector':'another-wallet'})
        forged={**receipt,'collector_context':{'collector':'another-wallet'}}
        with self.assertRaisesRegex(ValueError,'collector context'):
            verify(self.store,forged,expected_context={'collector':'another-wallet'})
    def test_oldtip_wrongheight_and_two_valid_foreign_receipts_cannot_be_transplanted(self):
        first=self.run_source()
        for changes in ({'height':101},{'tip_hash':'b'*64}):
            with self.subTest(changes=changes),self.assertRaisesRegex(ValueError,'collector context'):
                verify(self.store,first,expected_context={**self.context,**changes})
        other_context={**self.context,'height':101,'tip_hash':'b'*64}
        with patch('urllib.request.urlopen',return_value=io.BytesIO(self.raw)):
            second=collect(self.store,self.chain,{'0014'+'cd'*20},time.monotonic(),context=other_context)
        self.assertEqual(second,verify(self.store,second,expected_context=other_context))
        transplant={**first,**{key:second[key] for key in ('raw_trace','scripts','script_count','script_set_sha256',
            'raw_response_sha256','response_bytes','observed_at')}}
        with self.assertRaisesRegex(ValueError,'collector context'):
            verify(self.store,transplant,expected_context=self.context)
    def test_actual_request_contains_all2000_scripts_and_no_subset(self):
        self.scripts={f'{index:064x}' for index in range(2000)}
        with patch('urllib.request.urlopen',return_value=io.BytesIO(self.raw)) as rpc:
            receipt=collect(self.store,self.chain,self.scripts,time.monotonic(),context={'collector':'wide-control'})
        params=json.loads(rpc.call_args.args[0].data)['params']
        self.assertEqual(set(self.scripts),{item[4:-1] for item in params[1]})
        self.assertEqual(2000,len(params[1]));self.assertEqual(2000,receipt['script_count'])
        self.assertEqual(sorted(self.scripts),receipt['scripts'])
    def test_malformed_nonpublic_fields_never_enter_public_trace(self):
        raw=b'{"id":1,"result":{"activity":[],"txinwitness":["private-marker"]}}'
        with self.assertRaises(ValueError):self.run_source(raw)
        from simulator.trace import partition_paths,readonly
        for path in partition_paths(self.store.trace.root):
            conn=readonly(path)
            try:rows=conn.execute('SELECT payload,raw FROM trace').fetchall()
            finally:conn.close()
            for row in rows:
                self.assertNotIn('private-marker',row['payload']);self.assertIsNone(row['raw'])


if __name__=='__main__':unittest.main()

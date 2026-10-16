"""Checkpoint+current delta controls; synthetic sources, no readiness verdict."""
import copy,hashlib,json,tempfile,unittest
from pathlib import Path
from decimal import Decimal
from unittest.mock import patch
from simulator.descriptor_checkpoint import apply_delta,current_from_checkpoint
from simulator.model import SIGNET_GENESIS
from simulator.two_step_normal import digest

class DeltaTests(unittest.TestCase):
    def test_exact_baseline_spend_and_new_receipt_preserve_amounts(self):
        point='a'*64+':0';coins={point:{'script':'51','amount_sat':1000,'height':80}}
        rows=[{'type':'spend','height':91,'blockhash':'b'*64,'prevout_txid':'a'*64,'prevout_vout':0,'prevout_spk':{'hex':'51'},'amount':Decimal('.00001')},
            {'type':'receive','height':91,'blockhash':'b'*64,'txid':'c'*64,'vout':1,'output_spk':{'hex':'51'},'amount':Decimal('.000009')}]
        result=apply_delta(coins,rows,{91:'b'*64},{'51':{}},minimum_height=90)
        self.assertEqual({'c'*64+':1':{'script':'51','amount_sat':900,'height':91}},result);self.assertIn(point,coins)
        for change in ('amount','block','missing'):
            value=copy.deepcopy(rows)
            if change=='amount':value[0]['amount']=Decimal('.00002')
            elif change=='block':value[0]['blockhash']='other'
            else:value[0]['prevout_txid']='d'*64
            with self.subTest(change=change),self.assertRaises(ValueError):apply_delta(coins,value,{91:'b'*64},{'51':{}},minimum_height=90)

class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.files={};self.scripts={};self.windows=[];self.members={};self.mapping={};self.meta={};self.prepared={'actors':[]}
        self.tip='f'*64;self.height=100;self.base='e'*64;self.path=self.root/'manifest.json'
        for n in range(1,25):
            actor=f'actor-{n:02d}';desc='public-'+actor;member='wallet-'+actor;self.mapping[actor]=member
            self.members[member]={'kind':'wallet','role':'customer','descriptors':[desc]}
            self.prepared['actors'].append({'actor':actor,'public_descriptor':desc})
            self.windows.append({'actor':actor,'desc':desc,'range':[0,19]})
            for child in range(20):self.scripts[(actor+str(child)).encode().hex()]={'actor':actor,'child_index':child}
            self.meta[actor]={'wallet':{'descriptor':desc,'network':'signet'},'issued_frontier':1,'locked_outpoints':[],
                'last_revealed':[{'last_revealed':1,'descriptor_id':hashlib.sha256((actor+'0').encode()).hexdigest()}]}
        self.batches=[]
        for index,offset in enumerate((0,16)):
            windows=self.windows[offset:offset+16];name=f'rpc-{index:04d}.response.json';request=name.replace('.response.','.request.')
            self.files[request]=json.dumps({'jsonrpc':'2.0','id':index,'method':'scantxoutset','params':['start',[{'desc':r['desc'],'range':r['range']} for r in windows]]}).encode()
            self.files[name]=json.dumps({'jsonrpc':'2.0','id':index,'result':{'success':True,'height':90,'bestblock':self.base,'unspents':[],'total_amount':0}}).encode()
            self.batches.append({'windows':windows,'response':name,'request_id':index,'height':90,'tip_hash':self.base})
        self.files['scripts.json']=json.dumps(self.scripts).encode()
        self.manifest={'schema':'actual-public-descriptor-checkpoint-v1','genesis':SIGNET_GENESIS,'prepared_sha256':'p'*64,'windows':self.windows,'batches':self.batches}
        outer=self
        class Chain:
            def identity(inner):return {'chain':'signet','blocks':outer.height,'bestblockhash':outer.tip,'initialblockdownload':False}
            def call(inner,method,*args,**kwargs):
                if method=='getblockhash':return outer.base if args[0]==90 else (str(args[0])*64)[:64]
                if method=='getdescriptoractivity':return {'activity':[]}
                raise AssertionError(method)
        self.chain=Chain()
    def tearDown(self):self.tmp.cleanup()
    def freeze(self):
        self.manifest['files']={n:{'sha256':digest(raw),'size_bytes':len(raw)} for n,raw in self.files.items()}
        for n,raw in self.files.items():p=self.root/n;p.write_bytes(raw);p.chmod(0o600)
        raw=json.dumps(self.manifest).encode();self.path.write_bytes(raw);self.path.chmod(0o600);return digest(raw)
    def collect(self):
        return current_from_checkpoint(self.chain,self.members,self.mapping,self.prepared,self.meta,['a'*64],path=self.path,expected_sha256=self.freeze(),prepared_sha256='p'*64)
    def test_all24_actual_scan_windows_are_advanced_through_every_block_without_rescan(self):
        with patch('simulator.descriptor_checkpoint.confirmed_activity',return_value={'activity':[]}) as activity:
            result=self.collect();self.assertEqual(24,len(result));self.assertEqual(2,activity.call_count)
            self.assertEqual(10,len(activity.call_args.args[1]));self.assertTrue(all(v['utxos']==[] for v in result.values()))
    def test_reorg_staleness_omittedmember_and_frontier_beyond_real_window_refuse(self):
        self.base='d'*64
        with self.assertRaisesRegex(ValueError,'reorged'):self.collect()
        self.base='e'*64;self.height=235
        with self.assertRaisesRegex(ValueError,'stale'):self.collect()
        self.height=100;self.meta['actor-01']['issued_frontier']=20
        with self.assertRaisesRegex(ValueError,'frontier'):self.collect()
    def test_actual_original_hash_scan_request_or_private_mode_substitution_refuses(self):
        self.freeze();(self.root/'scripts.json').write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError,'content'):current_from_checkpoint(self.chain,self.members,self.mapping,self.prepared,self.meta,['a'*64],path=self.path,expected_sha256=digest(self.path.read_bytes()),prepared_sha256='p'*64)
        name=self.batches[0]['response'];value=json.loads(self.files[name]);value['id']=999;self.files[name]=json.dumps(value).encode()
        with self.assertRaisesRegex(ValueError,'request/reply'):self.collect()
    def test_nonempty_current_mempool_or_chain_change_refuses(self):
        original=self.chain.call
        def call(method,*args,**kwargs):
            if method=='getdescriptoractivity':return {'activity':[{'type':'receive'}]}
            return original(method,*args,**kwargs)
        self.chain.call=call
        with patch('simulator.descriptor_checkpoint.confirmed_activity',return_value={'activity':[]}):
            with self.assertRaisesRegex(ValueError,'mempool'):self.collect()

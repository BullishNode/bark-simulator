"""Bounded synthetic Core controls; these do not qualify live discovery."""
import copy
import hashlib
import unittest
from decimal import Decimal
from simulator.model import SIGNET_GENESIS
from simulator.scanned_public_wallets import scan_current

class ScanTests(unittest.TestCase):
    def setUp(self):
        self.members={};self.mapping={};self.prepared={'genesis':SIGNET_GENESIS,'wallets_opened':0,'financial_dispatches':0,'actors':[]};self.meta={};self.calls=[]
        for n in range(1,25):
            actor=f'actor-{n:02d}';member='wallet-'+actor;desc=f'descriptor{n}'
            self.members[member]={'role':'customer','kind':'wallet','descriptors':[desc]};self.mapping[actor]=member
            self.prepared['actors'].append({'actor':actor,'public_descriptor':desc,'fresh_seed_birth_Core':None,'created_utc':None,'native_wallet_opened':False})
            self.meta[actor]={'wallet':{'descriptor':desc,'network':'signet'},'issued_frontier':2 if n<3 else 1,'locked_outpoints':[],'last_revealed':[{'descriptor_id':hashlib.sha256((desc+'_0').encode()).hexdigest(),'last_revealed':2 if n<3 else 1}]}
        outer=self
        class Chain:
            def identity(inner):return {'chain':'signet','initialblockdownload':False,'blocks':100,'bestblockhash':'tip'}
            def call(inner,method,*args,**kwargs):
                outer.calls.append((method,args,kwargs))
                if method=='getdescriptorinfo':return {'descriptor':args[0],'hasprivatekeys':False}
                if method=='deriveaddresses':return [args[0]+'_'+str(n) for n in range(args[1][1]+1)]
                if method=='validateaddress':return {'address':args[0],'isvalid':True,'scriptPubKey':args[0].encode().hex()}
                if method=='scantxoutset':return copy.deepcopy(outer.scan)
                if method=='getdescriptoractivity':return copy.deepcopy(outer.mempool)
                if method=='gettxout':return copy.deepcopy(outer.coin)
                raise AssertionError(method)
        self.chain=Chain();self.scan={'success':True,'height':100,'bestblock':'tip','unspents':[],'total_amount':Decimal(0)};self.mempool={'activity':[]}
        self.coin={'bestblock':'tip','scriptPubKey':{'hex':b'descriptor1_2'.hex()},'value':Decimal('.0001'),'confirmations':2}
    def run_scan(self):return scan_current(self.chain,self.members,self.mapping,self.prepared,self.meta,['a'*64])
    def test_all_twentyfour_current_wallets_scan_in_two_guarded_batches(self):
        result=self.run_scan();self.assertEqual(24,len(result));self.assertTrue(all(v['utxos']==[] for v in result.values()))
        batches=[v[1][1] for v in self.calls if v[0]=='scantxoutset'];self.assertEqual([16,8],list(map(len,batches)))
        self.assertTrue(all(row['range']==[0,19] for batch in batches for row in batch))
    def test_dormant_only_with_actual_fresh_generation_and_no_existing_database(self):
        self.meta['actor-24']={'wallet_database_exists':False}
        with self.assertRaises(ValueError):self.run_scan()
        self.prepared['actors'][-1].update(created_utc='dated',fresh_seed_birth_Core=self.chain.identity())
        self.assertEqual(-1,self.run_scan()['wallet-actor-24']['issued_frontier'])
    def test_wrong_descriptor_private_descriptor_frontier_or_missing_member_refuses(self):
        saved=copy.deepcopy(self.meta)
        for field,value in [('issued_frontier',2000),('wallet',{'descriptor':'foreign','network':'signet'})]:
            self.meta=copy.deepcopy(saved);self.meta['actor-01'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.run_scan()
        self.meta=saved;self.members['wallet-actor-01']['descriptors']=['foreign']
        with self.assertRaises(ValueError):self.run_scan()
    def test_scan_tip_truncation_total_or_current_coin_mismatch_refuses(self):
        saved=copy.deepcopy(self.scan)
        for field,value in [('success',False),('bestblock','other'),('height',101),('total_amount',Decimal('.1'))]:
            self.scan=copy.deepcopy(saved);self.scan[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.run_scan()
    def test_pending_activity_or_final_chain_change_refuses(self):
        self.mempool={'activity':[{'type':'spend'}]}
        with self.assertRaisesRegex(ValueError,'pending'):self.run_scan()
        self.mempool={'activity':[]};original=self.chain.identity;calls=0
        def identity():
            nonlocal calls
            calls+=1;return {**original(),'bestblockhash':'tip' if calls==1 else 'next'}
        self.chain.identity=identity
        with self.assertRaisesRegex(ValueError,'chain changed'):self.run_scan()
    def test_current_scan_output_is_rechecked_and_not_historical_asset_sum(self):
        # Return the one owned output only in the first descriptor batch.
        original=self.chain.call;scans=0
        def call(method,*args,**kwargs):
            nonlocal scans
            if method=='scantxoutset':
                scans+=1
                if scans==1:return {**self.scan,'unspents':[{'txid':'b'*64,'vout':1,'scriptPubKey':b'descriptor1_2'.hex(),'amount':Decimal('.0001'),'height':99}],'total_amount':Decimal('.0001')}
            return original(method,*args,**kwargs)
        self.chain.call=call;result=self.run_scan()
        self.assertEqual(10000,result['wallet-actor-01']['utxos'][0]['amount_sat'])
        self.assertEqual(1,sum(len(v['utxos']) for v in result.values()))
        self.coin['value']=Decimal('.00011');scans=0
        with self.assertRaisesRegex(ValueError,'current confirmed'):self.run_scan()

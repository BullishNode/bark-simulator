"""Synthetic chain joins; component checks never establish source completeness."""
import copy
import unittest
from simulator.financial_components import inspect
from simulator.model import SIGNET_GENESIS


class Chain:
    def __init__(self): self.changed=False;self.genesis=SIGNET_GENESIS;self.network='signet'
    def identity(self):return {'chain':self.network,'blocks':100,'bestblockhash':('c' if self.changed else 'a')*64,'initialblockdownload':False}
    def call(self,method,*args):
        if method=='getblockhash':return self.genesis
        if method=='gettxout':return {'value':'0.00002000' if args[0]=='b'*64 else '0.00001000','confirmations':3,'scriptPubKey':{'hex':'0014'+'d'*40}}
        if method=='getdescriptorinfo':return {'descriptor':args[0],'hasprivatekeys':False}
        if method=='deriveaddresses':return ['test-address']
        if method=='validateaddress':return {'scriptPubKey':'0014'+'d'*40}
        raise AssertionError(method)
    def transaction(self,txid):return {'txid':txid,'confirmations':3,'fee_sat':100}


class FinancialComponentsTests(unittest.TestCase):
    def setUp(self):
        self.chain=Chain();self.wallets=[{'id':'bank','source_sha256':'1'*64,'utxos':[{'outpoint':'d'*64+':0','amount_sat':1000,'script':'0014'+'d'*40,'descriptor':'fixture','child_index':0}]}]
        self.nodes=[]
        for identity,peer,owned in [('02'+'1'*64,'03'+'2'*64,1500000),('03'+'2'*64,'02'+'1'*64,500000)]:
            self.nodes.append({'id':identity,'source_sha256':'2'*64,'getinfo':{'id':identity,'network':'signet','blockheight':100},'listfunds':{'outputs':[],'channels':[{'funding_txid':'b'*64,'funding_output':1,'state':'CHANNELD_NORMAL','our_amount_msat':owned,'amount_msat':2000000}]},'listpeerchannels':{'channels':[{'funding_txid':'b'*64,'funding_outnum':1,'state':'CHANNELD_NORMAL','peer_id':peer,'to_us_msat':owned,'spendable_msat':0,'total_msat':2000000,'htlcs':[]}]}})
        self.costs=[{'txid':'c'*64,'amount_sat':100,'source_sha256':'3'*64}]
    def run_join(self):return inspect(self.wallets,self.nodes,self.costs,self.chain,height=100,tip_hash='a'*64,gaps=['source authentication and exhaustive discovery remain unqualified'])
    def test_exact_channel_ownership_includes_reserves_without_double_counting_funding(self):
        r=self.run_join();self.assertEqual(3000000,r['observed_physical_msat']);self.assertEqual(100,r['observed_miner_cost_sat']);self.assertFalse(r['complete']);self.assertFalse(r['qualified'])
    def test_native_amount_or_script_mismatch_refused(self):
        for field,value in [('amount_sat',1001),('script','bad')]:
            old=copy.deepcopy(self.wallets);self.wallets[0]['utxos'][0][field]=value
            with self.assertRaisesRegex(ValueError,'differs from chain'):self.run_join()
            self.wallets=old
    def test_duplicate_wallet_or_channel_backing_refused(self):
        self.wallets[0]['utxos'].append(copy.deepcopy(self.wallets[0]['utxos'][0]))
        with self.assertRaisesRegex(ValueError,'counted twice'):self.run_join()
        self.wallets[0]['utxos']=[{'outpoint':'b'*64+':1','amount_sat':2000,'script':'0014'+'d'*40}]
        with self.assertRaisesRegex(ValueError,'counted twice'):self.run_join()
    def test_channel_spendable_cannot_replace_full_owned_balance(self):
        self.nodes[0]['listpeerchannels']['channels'][0]['to_us_msat']=0
        with self.assertRaisesRegex(ValueError,'frames disagree'):self.run_join()
    def test_missing_peer_or_unresolved_htlc_refused(self):
        old=self.nodes.pop()
        with self.assertRaisesRegex(ValueError,'both native'):self.run_join()
        self.nodes.append(old);self.nodes[0]['listpeerchannels']['channels'][0]['htlcs']=[{'amount_msat':1}]
        with self.assertRaisesRegex(ValueError,'ownership resolver'):self.run_join()
    def test_miner_cost_cannot_include_internal_service_fee_or_duplicate(self):
        self.costs[0]['amount_sat']=430
        with self.assertRaisesRegex(ValueError,'miner cost differs'):self.run_join()
        self.costs[0]['amount_sat']=100;self.costs.append(copy.deepcopy(self.costs[0]))
        with self.assertRaisesRegex(ValueError,'cost counted twice'):self.run_join()
    def test_missing_gap_list_never_claims_complete(self):
        with self.assertRaisesRegex(ValueError,'coverage gaps'):inspect([],[],[],self.chain,height=100,tip_hash='a'*64,gaps=[])
    def test_changed_tip_refused_after_chain_checks(self):
        original=self.chain.transaction
        def tx(txid):self.chain.changed=True;return original(txid)
        self.chain.transaction=tx
        with self.assertRaisesRegex(ValueError,'chain changed'):self.run_join()
    def test_native_funds_channel_cannot_be_omitted_from_peer_frame(self):
        self.nodes[0]['listpeerchannels']['channels']=[]
        with self.assertRaisesRegex(ValueError,'omits a channel'):self.run_join()
    def test_source_identity_reuse_and_unbounded_aggregate_refused(self):
        self.wallets.append(copy.deepcopy(self.wallets[0]))
        with self.assertRaisesRegex(ValueError,'unique original'):self.run_join()
        self.wallets=[];self.nodes=self.nodes*17
        with self.assertRaisesRegex(ValueError,'aggregate observed'):self.run_join()
    def test_wrong_genesis_or_network_cannot_be_stamped_signet(self):
        self.chain.genesis='f'*64
        with self.assertRaisesRegex(ValueError,'signet identity'):self.run_join()
        self.chain.genesis=SIGNET_GENESIS;self.chain.network='regtest'
        with self.assertRaisesRegex(ValueError,'signet identity'):self.run_join()
    def test_self_peering_frames_cannot_cover_owned_channel(self):
        for n in self.nodes:n['listpeerchannels']['channels'][0]['peer_id']=n['getinfo']['id']
        with self.assertRaisesRegex(ValueError,'both native'):self.run_join()

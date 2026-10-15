"""Synthetic RPC/ledger fixtures exercise independent inventory checks, not signet qualification."""
import copy
import json
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path
from simulator.engine import initialize
from simulator.model import SIGNET_GENESIS, InvariantError
from simulator.store import Store
from simulator.treasury import declare_boundary,capture_assets,reconcile_edge
from tests.test_final_campaign import PINS

class Chain:
    def __init__(self):
        self.tip='tip';self.calls=[]
        self.coins={('a'*64,0):{'confirmations':1,'value':Decimal('.00001000'),'scriptPubKey':{'hex':'wallet-script'}},
                    ('b'*64,0):{'confirmations':1,'value':Decimal('.00002000'),'scriptPubKey':{'hex':'channel-script'}}}
    def identity(self):return {'bestblockhash':self.tip,'blocks':100,'initialblockdownload':False}
    def call(self,method,*args):
        self.calls.append((method,args))
        if method=='getdescriptorinfo':return {'hasprivatekeys':False,'descriptor':args[0]}
        if method=='gettxout':
            assert args[2] is False
            return self.coins.get(args[:2])
        if method=='deriveaddresses':return ['fixture-address']
        if method=='validateaddress':return {'scriptPubKey':'wallet-script'}
        raise AssertionError(method)

class TreasuryFixture:
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name),'synthetic',100000)
        initialize(self.store);self.store.db.execute("INSERT INTO meta VALUES ('paused','declare')")
        self.chain=Chain()
        self.wallet={'id':'rounds','kind':'wallet','role':'operator','identity':'actual-wallet-fingerprint',
                     'descriptors':['wpkh(public-fixture)#checksum']}
        self.peer={'id':'peer','kind':'lightning_peer','role':'fixture_peer','identity':'actual-peer-pubkey','descriptors':[]}
        members=[]
        for member in (self.wallet,self.peer):
            self.event('treasury_member_verified',{'member':member,'genesis':SIGNET_GENESIS,'financial_pins':PINS})
            members.append({**member,'verification_sequence':self.sequence()})
        self.declaration={'id':'fixture','genesis':SIGNET_GENESIS,'pins':PINS,'members':members,'excluded':['outside-payer','bitcoin-miners']}
        declare_boundary(self.store,self.declaration,self.chain)
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def event(self,kind,payload):self.store.event(kind,payload)
    def sequence(self):return self.store.db.execute('SELECT MAX(sequence) FROM event').fetchone()[0]
    def inventory(self,member,**changes):
        value={'member_id':member['id'],'identity':member['identity'],'financial_pins':PINS,'tip_hash':'tip','height':100,'complete':True}
        if member['kind']=='wallet':value['utxos']=[{'outpoint':'a'*64+':0','amount_sat':1000,'script':'wallet-script','descriptor_index':0,'child_index':0}]
        else:
            value['utxos']=[]
            value['channels']=[{'funding_outpoint':'b'*64+':0','channel_id':'channel','peer_identity':'outside-peer','owned_balance_msat':1500999}]
        value.update(changes);self.event('treasury_inventory',value);return self.sequence()
    def assets(self,**wallet_changes):
        return capture_assets(self.store,{'rounds':self.inventory(self.wallet,**wallet_changes),'peer':self.inventory(self.peer)},self.chain)
class TreasuryTests(TreasuryFixture,unittest.TestCase):
    def test_actual_core_values_and_fractional_channel_sats_are_preserved(self):
        result=self.assets()
        self.assertEqual(2500999,result['total_msat']);self.assertEqual(1000000,result['operator_controlled_msat'])
        self.assertIn(('gettxout',('a'*64,0,False)),self.chain.calls)
    def test_complete_label_cannot_override_wrong_actual_outpoint_value(self):
        with self.assertRaises(InvariantError):self.assets(utxos=[{'outpoint':'a'*64+':0','amount_sat':999,'script':'wallet-script','descriptor_index':0,'child_index':0}])
        self.chain.coins.clear()
        with self.assertRaisesRegex(ValueError,'unspent backing'):self.assets()
    def test_missing_member_or_incomplete_inventory_is_not_zero_assets(self):
        with self.assertRaisesRegex(ValueError,'coverage'):self.assets(complete=False)
        with self.assertRaisesRegex(ValueError,'missing'):
            capture_assets(self.store,{'rounds':self.inventory(self.wallet)},self.chain)
    def test_descriptor_is_checked_and_duplicate_outpoint_rejected(self):
        coin={'outpoint':'a'*64+':0','amount_sat':1000,'script':'wallet-script','descriptor_index':0,'child_index':0}
        with self.assertRaises(InvariantError):self.assets(utxos=[coin,coin])
        self.chain.coins[('a'*64,0)]['scriptPubKey']['hex']='foreign-script'
        with self.assertRaises(InvariantError):self.assets()
    def test_node_balance_cannot_exceed_actual_channel_backing(self):
        sequence=self.inventory(self.peer,channels=[{'funding_outpoint':'b'*64+':0','channel_id':'channel','peer_identity':'outside-peer','owned_balance_msat':2000001}])
        with self.assertRaises(InvariantError):capture_assets(self.store,{'rounds':self.inventory(self.wallet),'peer':sequence},self.chain)
    def test_duplicate_real_member_identity_cannot_be_declared(self):
        duplicate=copy.deepcopy(self.declaration);duplicate['members'].append({**duplicate['members'][0],'id':'another-name'})
        with self.assertRaises(InvariantError):declare_boundary(self.store,duplicate,self.chain)
    def test_external_receipts_injections_and_router_subsats_conserve(self):
        members={m['id']:m for m in self.declaration['members']}
        flows=[{'id':'receive:0','source':'outside-payer','destination':'rounds','kind':'external_receipt','amount_msat':1000000},
               {'id':'inject:0','source':'outside-payer','destination':'rounds','kind':'injection','amount_msat':2000000},
               {'id':'fee:0','source':'rounds','destination':'bitcoin-miners','kind':'miner_cost','amount_msat':100000},
               {'id':'router','source':'rounds','destination':'outside-router','kind':'router_cost','amount_msat':1},
               {'id':'inside','source':'rounds','destination':'peer','kind':'internal_transfer','amount_msat':500000}]
        result=reconcile_edge({'total_msat':1000000},{'total_msat':3899999,'operator_controlled_msat':2000000},flows,
            [{'id':'liability','borrower':'rounds','amount_msat':500000}],members)
        self.assertEqual(1500000,result['operator_equity_msat']);self.assertEqual(100001,result['miner_router_cost_msat'])
    def test_internal_router_fee_is_not_external_loss_or_new_income(self):
        members={m['id']:m for m in self.declaration['members']}
        flow={'id':'router','source':'rounds','destination':'peer','kind':'router_cost','amount_msat':1}
        with self.assertRaises(InvariantError):reconcile_edge({'total_msat':1},{'total_msat':0,'operator_controlled_msat':0},[flow],[],members)
    def test_duplicate_receipt_injection_or_one_msat_gap_fails(self):
        members={m['id']:m for m in self.declaration['members']}
        flow={'id':'same-original-output','source':'outside-payer','destination':'rounds','kind':'external_receipt','amount_msat':1}
        with self.assertRaises(InvariantError):reconcile_edge({'total_msat':0},{'total_msat':2,'operator_controlled_msat':2},[flow,{**flow,'kind':'injection'}],[],members)
        with self.assertRaises(InvariantError):reconcile_edge({'total_msat':0},{'total_msat':0,'operator_controlled_msat':0},[flow],[],members)

    def test_two_channel_aliases_cannot_duplicate_one_nodes_physical_balance(self):
        channels=[{'funding_outpoint':'b'*64+':0','channel_id':name,'peer_identity':'outside-peer','owned_balance_msat':750000}
                  for name in ('long-id','short-id')]
        sequence=self.inventory(self.peer,channels=channels)
        with self.assertRaisesRegex(InvariantError,'physical channel'):
            capture_assets(self.store,{'rounds':self.inventory(self.wallet),'peer':sequence},self.chain)

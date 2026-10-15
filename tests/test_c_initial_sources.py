"""C source-shaped doubles only: no native, signature, Core or payment credit."""
import asyncio
import copy
import dataclasses
import hashlib
import json
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock,patch

from simulator import c_pilot,identity_bootstrap as bootstrap
from simulator.engine import Lease
from simulator.finite_funding_readiness import collect_initial_funding_sources,record_initial_funding_readiness,TABLES
from simulator.model import canonical,SIGNET_GENESIS
from simulator.operating_limits import declare_envelope,preflight
from simulator.ownership import record_verified
from simulator.treasury import declare_boundary
from tests.test_identity_bootstrap import IdentityBootstrapTests
from tests.test_finite_funding_readiness import Chain,address
from tests.test_c_pilot import pilot,initial_data


class CChain(Chain):
    def __init__(self):
        super().__init__();self.coin['amount']='0.00150000'
    def call(self,method,*args,**kwargs):
        if method=='gettxout':return {'confirmations':10,'value':'0.00150000','scriptPubKey':{'hex':self.coin['scriptPubKey']}}
        return super().call(method,*args,**kwargs)


class CInitialSourceControls(unittest.TestCase):
    def setUp(self):
        self.fixture=IdentityBootstrapTests();self.fixture.architecture_profile='direct_per_key';self.fixture.setUp()
        f=self.fixture;self.store=f.store;self.chain=CChain();self.store.attach_trace()
        f.config=dataclasses.replace(f.config,inventory_command=('synthetic-c-public-source',),board_amount_sat=20000,action_fee_reserve_sat=1000)
        self.config=f.config;c_pilot.declare(self.store,{**pilot(),'pins':f.pins});f.declare();self.data={}
        self.records=[];self.links=[]
        for actor,offset in (('actor-01',0),('actor-02',100)):
            action=f.action(actor=actor)
            with Lease(f.wallets):bootstrap.begin(self.store,f.config,f.snapshot,action)
            data,proofs=initial_data(offset);descriptor=actor+'-descriptor'
            data.update(funding_address=address(descriptor,1),onchain_inventory={
                'schema_version':1,'network':'signet','read_only':True,'complete':True,
                'descriptors':[{'keychain':'external','descriptor':descriptor,'last_revealed_index':1}],
                'utxos':[],'pending_transactions':[],'pending_parents':[],'unavailable_parent_txids':[]})
            response={'action_id':action['id'],'status':'ok','actual_fee_sat':0,'data':data}
            self.store.event('driver_response',{'action_id':action['id'],'response':response})
            self.store.finish(action['id'],'completed',response,0)
            bootstrap.verify_created(self.store,f.config,self.chain,actor,action['id'])
            (f.wallets/actor).mkdir(mode=0o700)
            for proof in proofs:proof['financial_pins']=f.pins
            record_verified(self.store,actor,action['id'],{'objects':[
                {'kind':'key','proof':proof,'request_origin':row['origin']} for proof,row in zip(proofs,data['initial_key_links'])], 'movements':[]})
            self.data[actor]=data
        from simulator.finite_funding_readiness import _c_records_links
        self.records,self.links=_c_records_links(self.store,self.data,f.pins)
        self.store.db.execute("INSERT INTO meta VALUES ('paused','initial C source controls')")
        current={owner+'_inventory':{owner:{'wallet':owner,'network':'signet','complete':True,
            'tip_height':100,'tip_hash':'a'*64,'public_descriptor':owner+'-descriptor','last_revealed_index':0,
            'utxos':[],'pending_transactions':[],'pending_parents':[],'unavailable_parent_txids':[],'reserved_outpoints':[]}}
            for owner in ('rounds','watchman')}
        self.current=f.root/'c-source.json';self.current.write_text(json.dumps(current))
        self.store.event('owned_runtime_configuration_verified',{'loaded_configuration_identity_verified':True,
            'architecture_profile':'direct_per_key','product_commit':f.pins['product_commit'],'schema_sha256':f.pins['schema_sha256'],
            'current_source_sha256':hashlib.sha256(self.current.read_bytes()).hexdigest(),'observed_at':time.time()})
        self.runtime_sequence=self.seq();self.bank_rpc=SimpleNamespace(wallet='actual-c-bank')
        self.bank={'schema_version':1,'genesis':SIGNET_GENESIS,
            'source_identity':{'wallet_name':'actual-c-bank','endpoint_path':'/wallet/actual-c-bank','descriptors':['bank-descriptor']},
            'height':100,'tip_hash':'a'*64,'completed_at':time.time(),'read_only':True,'stable_tip':True,'complete_source_projection':True,
            'listunspent':[{'txid':'b'*64,'vout':0,'amount':'0.00150000','confirmations':10,'spendable':True,'safe':True,'solvable':True,
                'scriptPubKey':self.chain.coin['scriptPubKey']}],
            'listdescriptors':{'wallet_name':'actual-c-bank','descriptors':[{'desc':'bank-descriptor','next_index':1,'range':[0,1000]}]},
            'listlockunspent':[],'listsinceblock':{'transactions':[]},'getwalletinfo':{'walletname':'actual-c-bank'},
            'getbalances':{'mine':{'trusted':'0.00150000','untrusted_pending':'0'}},'locked_coins':[],'pending_transactions':[],'pending_parents':[]}
        self.database={'kind':'closed_frontier','schema_version':1,'architecture_profile':'direct_per_key','fallback_protocol':4,
            'database_tables_complete':True,'inventory_consistent':True,'read_only':True,'complete':False,'qualified':False,
            'rows':{name:copy.deepcopy(self.records if name in {'records','journal_records'} else self.links if name in {'links','journal_links'} else []) for name in TABLES}}
    def tearDown(self):self.fixture.tearDown()
    def seq(self):return self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
    def bank_collect(self,*args,**kwargs):
        self.store.event('treasury_bank_original_source',self.bank);return self.seq()
    def collect(self):
        with patch('simulator.finite_funding_readiness.collect_funding_bank_source',side_effect=self.bank_collect),patch(
                'simulator.finite_funding_readiness.json_command',AsyncMock(return_value=self.database)):
            return asyncio.run(collect_initial_funding_sources(self.store,self.config,self.chain,self.bank_rpc,
                runtime_source_sequence=self.runtime_sequence,current_startup_path=self.current,boundary_id='c-treasury'))
    def test_common_source_emits_two_customers_one_grant_and_real_declared_opening_only(self):
        result=self.collect();source=result['source']
        self.assertEqual(5,len(source['members']));self.assertEqual(150000,source['opening_total_sat'])
        self.assertEqual(25000,source['principal_sat']);self.assertEqual(40000,source['urgent_fee_reserve_sat'])
        self.assertEqual([('actor-01',25000)],[(r['member_id'],r['amount_sat']) for r in source['funding_recipients']])
        self.assertFalse(any(self.database['rows'][name] for name in TABLES-{'links','journal_links','records','journal_records'}))
        self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM event WHERE kind='financial_operating_readiness'").fetchone()[0])
    def test_missing_or_extra_link_monetary_state_and_wrong_profile_hold(self):
        for name,change in [('links',self.links[:-1]),('journal_links',self.links+[self.links[0]]),
                            ('coins',[{'unknown':True}]),('journal_carriers',[{'unknown':True}])]:
            original=self.database['rows'][name];self.database['rows'][name]=change
            with self.subTest(name=name),self.assertRaises(ValueError):self.collect()
            self.database['rows'][name]=original
        self.database['architecture_profile']='direct_xpub'
        with self.assertRaises(ValueError):self.collect()
    def test_common_financial_admission_is_funding_only_and_cannot_spend_urgent_reserve(self):
        result=self.collect();f=self.fixture
        declare_boundary(self.store,result['boundary_declaration'],self.chain)
        limits={'id':'c-initial-only','pins':f.pins,'boundary_id':'c-treasury','capital_exposure_msat':150000000,
            'fee_budgets_msat':{'ordinary':60000000,'urgent':40000000},
            'fee_ceilings_sat_kvb':{'round':None,'pool':None,'sweep':20000,'payout':20000,'claim':None,'progression':None},
            'operation_fee_paths':{'funding':['sweep','payout'],'board':['sweep','payout'],'sync':['sweep','payout']},
            'per_action_fee_sat':1000,'grant_sat':25000,'board_sat':20000,'board_fee_reserve_sat':1000,
            'minimum_pool_sat':1,'minimum_channel_msat':1,'fee_assets':['b'*64+':0']}
        declare_envelope(self.store,limits,self.config,result['inventory_sequences'],self.chain)
        ready=record_initial_funding_readiness(self.store,self.config,self.chain,result['source_sequence'])
        snapshot={'financial_pins':f.pins,'height':100,'tip_hash':'a'*64,'operating_readiness_sequence':ready['operating_readiness_sequence']}
        self.assertTrue(preflight(self.store,self.config,snapshot,operation='funding',amount_sat=25000,maximum_fee_sat=1000)['allowed'])
        for operation in ('board','sync','claim','send_arkoor'):
            with self.subTest(operation=operation),self.assertRaises(ValueError):preflight(self.store,self.config,snapshot,operation=operation)
        with self.assertRaises(ValueError):preflight(self.store,self.config,snapshot,operation='funding',amount_sat=25000,maximum_fee_sat=1001)


if __name__=='__main__':unittest.main()

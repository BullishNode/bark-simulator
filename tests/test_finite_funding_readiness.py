"""Synthetic source/admission controls only; no native, Core or payment credit."""
import asyncio
import copy
import dataclasses
import hashlib
import json
import time
import unittest
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock,patch

from simulator import identity_bootstrap as bootstrap
from simulator.engine import Lease
from simulator.finite_funding_readiness import collect_initial_funding_sources,record_initial_funding_readiness,TABLES,CUSTOMERS
from simulator.model import SIGNET_GENESIS,canonical
from simulator.operating_limits import declare_envelope,preflight
from simulator.runtime_startup import PRODUCT_COMMIT
from simulator.treasury import declare_boundary
from tests import test_identity_bootstrap
from tests.owned_activity_fixture import capture as capture_activity


def address(descriptor,child):return descriptor+'-address-'+str(child)
def script(addr):return hashlib.sha256(addr.encode()).hexdigest()


class Chain:
    def __init__(self):
        self.tip={'chain':'signet','blocks':100,'bestblockhash':'a'*64,'initialblockdownload':False}
        self.coin={'txid':'b'*64,'vout':0,'scriptPubKey':script(address('bank-descriptor',0)),'amount':'0.00665454'}
        self.unexpected=[];self.mempool=[];self.mempool_views=[];self.pending_script='other';self.active_scan=False;self.scans=[]
    def identity(self):return self.tip.copy()
    def tx(self,txid):return {'txid':txid,'vin':[],'vout':[{'n':0,'scriptPubKey':{'hex':self.pending_script},'value':'0.00000001'}]}
    def call(self,method,*args,**kwargs):
        if method=='getdescriptorinfo':return {'hasprivatekeys':False,'isrange':True,'issolvable':True,'descriptor':args[0]}
        if method=='deriveaddresses':return [address(args[0],i) for i in range(args[1][0],args[1][1]+1)]
        if method=='validateaddress':return {'isvalid':True,'scriptPubKey':script(args[0])}
        if method=='scantxoutset':
            if args[0]=='status':return {'progress':1} if self.active_scan else None
            self.scans.extend(args[1]);coins=[self.coin] if any(row['desc']=='bank-descriptor' for row in args[1]) else []
            coins=copy.deepcopy(coins+self.unexpected)
            return {'success':True,'height':100,'bestblock':'a'*64,'unspents':coins,
                'total_amount':sum(Decimal(coin['amount']) for coin in coins)}
        if method=='getdescriptoractivity':
            result=getattr(self,'activity',{'activity':[{'type':'receive'}] if self.mempool and self.pending_script in [item[4:-1] for item in args[1]] else []})
            return capture_activity(self,self.store,args,result)
        if method=='getrawmempool':return self.mempool_views.pop(0) if self.mempool_views else self.mempool.copy()
        if method=='gettxout':return {'confirmations':10,'value':'0.00665454','scriptPubKey':{'hex':self.coin['scriptPubKey']}}
        if method=='estimatesmartfee':return {'feerate':'0.00001001','blocks':6}
        raise AssertionError(method)


class InitialFundingReadinessTests(unittest.TestCase):
    def setUp(self):
        self.fixture=test_identity_bootstrap.IdentityBootstrapTests('test_fresh_hashed_context_allows_only_zero_fee_create_with_existing_lease')
        self.fixture.setUp();f=self.fixture;f.value['actors']=sorted(CUSTOMERS);f.pins['product_commit']=PRODUCT_COMMIT
        self.store=f.store;self.chain=Chain();self.chain.store=self.store;self.store.attach_trace()
        f.config=dataclasses.replace(f.config,inventory_command=('fixed-bridge',),board_amount_sat=20000,action_fee_reserve_sat=4000)
        self.config=f.config;f.declare();self.bindings=[]
        for number,actor in enumerate(sorted(CUSTOMERS),1):
            action=f.action(actor=actor)
            with Lease(f.wallets):bootstrap.begin(self.store,f.config,f.snapshot,action)
            raw=bytes([3,22])+bytes([number])*22+bytes([number])*78+bytes([number])*128
            binding={'mailbox_pk':'02'+str(number)*64,'spk':(bytes([number])*22).hex(),
                'account_xpub':'public-account-'+str(number),'fallback_record':raw.hex()}
            self.bindings.append({'mailbox_pk':binding['mailbox_pk'],'spk':binding['spk'],
                'account_xpub':(bytes([number])*78).hex(),'mailbox_sig':(bytes([number])*64).hex(),'account_sig':(bytes([number])*64).hex()})
            descriptor=actor+'-descriptor'
            data={'funding_address':address(descriptor,1),'binding':binding,'onchain_inventory':{
                'schema_version':1,'network':'signet','read_only':True,'complete':True,
                'descriptors':[{'keychain':'external','descriptor':descriptor,'last_revealed_index':1}],
                'utxos':[],'pending_transactions':[],'pending_parents':[],'unavailable_parent_txids':[]}}
            response={'action_id':action['id'],'status':'ok','actual_fee_sat':0,'data':data}
            self.store.event('driver_response',{'action_id':action['id'],'response':response})
            self.store.finish(action['id'],'completed',response,0)
            bootstrap.verify_created(self.store,f.config,self.chain,actor,action['id'])
            (f.wallets/actor).mkdir(mode=0o700)
        self.store.db.execute("INSERT INTO meta VALUES ('paused','initial source qualification')")
        current={}
        for owner,frontier in [('rounds',141),('watchman',0)]:
            current[owner+'_inventory']={owner:{'wallet':owner,'network':'signet','complete':True,
                'tip_height':100,'tip_hash':'a'*64,'public_descriptor':owner+'-descriptor','last_revealed_index':frontier,
                'utxos':[],'pending_transactions':[],'pending_parents':[],'unavailable_parent_txids':[],'reserved_outpoints':[]}}
        self.current=f.root/'current-source.json';self.current.write_text(json.dumps(current))
        self.store.event('owned_runtime_configuration_verified',{'loaded_configuration_identity_verified':True,
            'product_commit':PRODUCT_COMMIT,'schema_sha256':f.pins['schema_sha256'],
            'current_source_sha256':hashlib.sha256(self.current.read_bytes()).hexdigest(),'observed_at':time.time()})
        self.runtime_sequence=self.seq();self.bank_rpc=SimpleNamespace(wallet='actual-bank')
        self.bank=self.bank_frame();self.database={'kind':'closed_frontier','schema_version':1,'fallback_protocol':3,'database_tables_complete':True,
            'inventory_consistent':True,'read_only':True,'complete':False,'qualified':False,
            'rows':{table:(copy.deepcopy(self.bindings) if table in {'records','journal_records'} else []) for table in TABLES}}
    def tearDown(self):self.fixture.tearDown()
    def seq(self):return self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
    def bank_frame(self):
        coin={'txid':'b'*64,'vout':0,'amount':'0.00665454','confirmations':10,'spendable':True,'safe':True,'solvable':True,
            'scriptPubKey':self.chain.coin['scriptPubKey']}
        return {'schema_version':1,'source_identity':{'wallet_name':'actual-bank','endpoint_path':'/wallet/actual-bank','descriptors':['bank-descriptor']},
            'height':100,'tip_hash':'a'*64,'completed_at':time.time(),'read_only':True,'stable_tip':True,'complete_source_projection':True,
            'listunspent':[coin],'listdescriptors':{'wallet_name':'actual-bank','descriptors':[{'desc':'bank-descriptor','next_index':1,'range':[0,1000]}]},
            'listlockunspent':[],'listsinceblock':{'transactions':[]},'getwalletinfo':{'walletname':'actual-bank'},
            'getbalances':{'mine':{'trusted':'0.00665454','untrusted_pending':'0'}},'locked_coins':[],'pending_transactions':[],'pending_parents':[]}
    def bank_collect(self,*args,**kwargs):
        self.store.event('treasury_bank_original_source',self.bank);return self.seq()
    def collect(self):
        with patch('simulator.finite_funding_readiness.collect_funding_bank_source',side_effect=self.bank_collect),patch(
                'simulator.finite_funding_readiness.json_command',AsyncMock(return_value=self.database)):
            return asyncio.run(collect_initial_funding_sources(self.store,self.config,self.chain,self.bank_rpc,
                runtime_source_sequence=self.runtime_sequence,current_startup_path=self.current,boundary_id='initial-six'))
    def test_complete_actual_source_contract_emits_six_members_and_exact_five_outputs(self):
        result=self.collect();source=result['source']
        self.assertEqual(6,len(source['members']));self.assertEqual(5,len(source['funding_recipients']))
        self.assertEqual(325000,sum(row['amount_sat'] for row in source['funding_recipients']))
        self.assertEqual(0,source['opening_liabilities_sat']);self.assertEqual(665454,source['opening_total_sat'])
        rounds=next(row for row in source['funding_recipients'] if row['member_id']=='rounds')
        self.assertEqual(0,rounds['child_index']);self.assertIn({'desc':'rounds-descriptor','range':[0,161]},self.chain.scans)
        self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM event WHERE kind='financial_operating_readiness'").fetchone()[0])
    def test_boundary_envelope_and_scope_admit_funding_but_refuse_wallet_actions(self):
        result=self.collect();declare_boundary(self.store,result['boundary_declaration'],self.chain)
        limits={'id':'initial-only','pins':self.fixture.pins,'boundary_id':'initial-six','capital_exposure_msat':665454000,
            'fee_budgets_msat':{'ordinary':60000000,'urgent':15000000},
            'fee_ceilings_sat_kvb':{'round':None,'pool':None,'sweep':20000,'payout':20000,'claim':None,'progression':None},
            'operation_fee_paths':{'funding':['sweep','payout'],'board':['sweep','payout'],'sync':['sweep','payout']},
            'per_action_fee_sat':10000,'grant_sat':50000,'board_sat':20000,'board_fee_reserve_sat':4000,
            'minimum_pool_sat':1,'minimum_channel_msat':1,'fee_assets':['b'*64+':0']}
        declare_envelope(self.store,limits,self.config,result['inventory_sequences'],self.chain)
        readiness=record_initial_funding_readiness(self.store,self.config,self.chain,result['source_sequence'])
        snapshot={'financial_pins':self.fixture.pins,'height':100,'tip_hash':'a'*64,
            'operating_readiness_sequence':readiness['operating_readiness_sequence']}
        self.assertTrue(preflight(self.store,self.config,snapshot,operation='funding',amount_sat=325000,maximum_fee_sat=10000)['allowed'])
        for operation in ('board','sync'):
            with self.subTest(operation=operation),self.assertRaisesRegex(ValueError,'scope'):
                preflight(self.store,self.config,snapshot,operation=operation)
    def test_existing_economic_or_unsupported_rows_and_unknown_bindings_refuse(self):
        for table in ('coins','journal_carriers','nursery','payments','rounds'):
            self.database['rows'][table]=[{'unknown':True}]
            with self.subTest(table=table),self.assertRaisesRegex(ValueError,'frontier'):self.collect()
            self.database['rows'][table]=[]
        self.database['rows']['records'][0]['spk']='other'
        with self.assertRaisesRegex(ValueError,'bindings'):self.collect()
    def test_unconfirmed_assets_existing_scan_and_descriptor_asset_gap_refuse(self):
        self.chain.mempool=['c'*64];self.chain.pending_script=script(address('rounds-descriptor',0))
        with self.assertRaisesRegex(ValueError,'unconfirmed assets'):self.collect()
        self.chain.mempool=[];self.chain.active_scan=True
        with self.assertRaisesRegex(ValueError,'existing Core scan'):self.collect()
        self.chain.active_scan=False;self.chain.unexpected=[{'txid':'c'*64,'vout':0,'scriptPubKey':script(address('actor-01-descriptor',0)),'amount':'0.00000001'}]
        with self.assertRaisesRegex(ValueError,'bank opening'):self.collect()
    def test_nonempty_owning_lockset_or_bank_pending_refuse_without_financial_proof(self):
        current=json.loads(self.current.read_text());current['rounds_inventory']['rounds']['reserved_outpoints']=['c'*64+':0']
        self.current.write_text(json.dumps(current))
        # A changed file itself must fail its original loaded-source hash.
        with self.assertRaisesRegex(ValueError,'runtime source'):self.collect()
        self.bank['pending_transactions']=[{'txid':'c'*64}]
        with self.assertRaises(ValueError):self.collect()
    def test_unenumerated_wallet_or_new_action_intent_refuses(self):
        foreign=self.fixture.wallets/'actor-05';foreign.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError,'unenumerated'):self.collect()
        foreign.rmdir()
        self.store.db.execute("UPDATE action SET operation='board' WHERE actor_id='actor-01'")
        with self.assertRaisesRegex(ValueError,'bootstrap'):self.collect()
    def test_activity_provenance_replaces_global_projection(self):
        self.chain.mempool=[f'{i:064x}' for i in range(10000)]
        with patch.object(self.chain,'tx',side_effect=AssertionError('no unrelated body')):
            source=self.collect()['source']
        self.assertEqual('core31-owned-script-activity-v1',source['mempool_activity']['source_schema'])
        self.assertNotIn('mempool_transactions_checked',source)
        self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM event WHERE kind='finite_initial_funding_mempool_outputs'").fetchone()[0])
    def test_nonempty_spend_and_missing_activity_refuse(self):
        for result in ({'activity':[{'type':'spend'}]}, {}):
            self.chain.activity=result
            with self.subTest(result=result),self.assertRaises(ValueError):self.collect()

if __name__=='__main__':unittest.main()

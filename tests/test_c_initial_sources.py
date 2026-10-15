"""C source-shaped doubles only: no native, signature, Core or payment credit."""
import asyncio
import copy
import dataclasses
import hashlib
import json
import sqlite3
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
from simulator.per_key import link_bytes,retained_origins


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
            path=f.wallets/actor/'db.sqlite';conn=sqlite3.connect(path)
            conn.execute('CREATE TABLE bark_vtxo_key(idx INTEGER,public_key TEXT,linked_proof BLOB,issued INTEGER)')
            conn.executemany('INSERT INTO bark_vtxo_key VALUES(?,?,?,?)',[(row['native_index'],row['origin']['user_pubkey'],
                bytes.fromhex(row['origin']['key_link_attestation']),int(row['native_index']==0)) for row in data['initial_key_links']])
            conn.commit();conn.close();path.chmod(0o600)
            for proof in proofs:proof['financial_pins']=f.pins
            record_verified(self.store,actor,action['id'],{'objects':[
                {'kind':'key','proof':proof,'request_origin':row['origin']} for proof,row in zip(proofs,data['initial_key_links'])], 'movements':[]})
            self.data[actor]=data
        from simulator.finite_funding_readiness import _c_records_links
        with Lease(f.wallets):self.records,self.links=_c_records_links(self.store,self.data,f.pins)
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
        with Lease(self.fixture.wallets),patch('simulator.finite_funding_readiness.collect_funding_bank_source',side_effect=self.bank_collect),patch(
                'simulator.finite_funding_readiness.json_command',AsyncMock(return_value=self.database)):
            return asyncio.run(collect_initial_funding_sources(self.store,self.config,self.chain,self.bank_rpc,
                runtime_source_sequence=self.runtime_sequence,current_startup_path=self.current,boundary_id='c-treasury'))
    def test_common_source_emits_two_customers_one_grant_and_real_declared_opening_only(self):
        result=self.collect();source=result['source']
        self.assertEqual(5,len(source['members']));self.assertEqual(150000,source['opening_total_sat'])
        self.assertEqual(125000,source['principal_sat']);self.assertEqual(25000,source['client_principal_sat'])
        self.assertEqual(40000,source['urgent_fee_reserve_sat']);self.assertFalse(source['urgent_isolation_qualified'])
        self.assertEqual([('actor-01',25000),('watchman',100000)],[(r['member_id'],r['amount_sat']) for r in source['funding_recipients']])
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
        self.assertTrue(preflight(self.store,self.config,snapshot,operation='funding',amount_sat=125000,maximum_fee_sat=1000)['allowed'])
        for operation in ('board','sync','claim','send_arkoor'):
            with self.subTest(operation=operation),self.assertRaises(ValueError):preflight(self.store,self.config,snapshot,operation=operation)
        with self.assertRaises(ValueError):preflight(self.store,self.config,snapshot,operation='funding',amount_sat=25000,maximum_fee_sat=1001)

    def test_synced_lookahead_growth_requires_real_native_proof_and_every_actual_public_row(self):
        from simulator.c_pilot import retained_links
        f=self.fixture
        with Lease(f.wallets):self.assertEqual(51,retained_links(self.store)['actor-01']['count'])
        data=copy.deepcopy(self.data['actor-01']);binding=data['binding'];key='03'+format(52,'064x')
        wire=link_bytes({'user_pubkey':key,'mailbox_pk':binding['mailbox_pk'],'sig':'55'*64,'recovery_index':51})
        origin={'user_pubkey':key,'binding':binding,'key_link_attestation':wire}
        rows=copy.deepcopy(data['initial_key_links'])+[{'native_index':51,'origin':origin}]
        frame={'schema_version':1,'scope':'fresh_synced_native_prefix','last_issued_index':1,
            'maximum_index':51,'binding':binding,'rows':rows}
        self.assertEqual(52,len(retained_origins(frame)))
        for change in ({'rows':rows[:-1]},{'maximum_index':50},{'last_issued_index':True}):
            with self.subTest(change=next(iter(change))),self.assertRaises(ValueError):retained_origins({**frame,**change})
        self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        action=f.action(operation='sync',actor='actor-01')
        response={'action_id':action['id'],'status':'ok','actual_fee_sat':0,'data':{'c_key_links':frame}}
        self.store.event('driver_response',{'action_id':action['id'],'response':response})
        self.store.finish(action['id'],'completed',response,0)
        path=f.wallets/'actor-01'/'db.sqlite';connection=sqlite3.connect(path)
        connection.execute('UPDATE bark_vtxo_key SET issued=1 WHERE idx=1')
        connection.execute('INSERT INTO bark_vtxo_key VALUES(?,?,?,0)',(51,key,bytes.fromhex(wire)))
        connection.commit();connection.close()
        with Lease(f.wallets),self.assertRaisesRegex(ValueError,'independent signature'):retained_links(self.store)
        proof={'user_pubkey':key,'financial_pins':f.pins,'binding':{**binding,'record_version':4,'key_link_version':1,
            'key_link_attestation':wire,'recovery_index':51,'policy_pubkey_full':key,
            'record_signature_valid':True,'key_link_signature_valid':True}}
        record_verified(self.store,'actor-01',action['id'],{'objects':[{'kind':'key','proof':proof,'request_origin':origin}],'movements':[]})
        with Lease(f.wallets):self.assertEqual(52,retained_links(self.store)['actor-01']['count'])
        connection=sqlite3.connect(path);connection.execute('INSERT INTO bark_vtxo_key VALUES(?,?,?,0)',(1000,'02'+'99'*32,b'extra'))
        connection.commit();connection.close()
        with Lease(f.wallets),self.assertRaisesRegex(ValueError,'actual C public key/proof rows'):retained_links(self.store)
        connection=sqlite3.connect(path);connection.execute('DELETE FROM bark_vtxo_key WHERE idx=1000')
        connection.execute('UPDATE bark_vtxo_key SET linked_proof=? WHERE idx=51',(b'changed',));connection.commit();connection.close()
        with Lease(f.wallets),self.assertRaisesRegex(ValueError,'actual C public key/proof rows'):retained_links(self.store)


if __name__=='__main__':unittest.main()

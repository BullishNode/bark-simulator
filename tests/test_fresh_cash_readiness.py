"""Synthetic cash-only context/SQLite controls; no native or Core success credit."""
import copy
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from simulator.engine import Lease,initialize
from simulator.fresh_cash_readiness import (OPERATIONS,ECONOMIC_TABLES,METADATA_TABLES,
    validate_client_action_scope,observe_empty_client_economics)
from simulator.model import canonical
from simulator.store import Store
from tests.test_final_campaign import PINS
from tests.test_identity_bootstrap import IdentityBootstrapTests


class CashActionScopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name),'synthetic',10000)
        initialize(self.store);self.actors=['actor-01','actor-02','actor-04']
        value={'actors':self.actors,'pins':PINS}
        self.store.db.execute("INSERT INTO meta VALUES ('zero_principal_identity_bootstrap',?)",(canonical(value),))
        self.store.event('identity_bootstrap_declared',{'declaration':value})
        self.proof={'financial_pins':PINS,'operation_scope':OPERATIONS,'client_action_scope':{
            'actors':self.actors,'operations':OPERATIONS,'maximum_fee_sat':0,'args':{}}}
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def check(self,proof=None,operation='sync',fee=0,action=None):
        return validate_client_action_scope(self.store,self.proof if proof is None else proof,
            operation=operation,maximum_fee_sat=fee,reserved_action_id=action)
    def action(self,actor='actor-01',operation='sync',args=None,fee=0):
        scenario=self.store.db.execute('SELECT id FROM scenario LIMIT 1').fetchone()[0]
        self.store.queue('cash-operation',actor,scenario,operation,args or {},fee)
        return self.store.claim({operation})
    def test_readiness_probes_and_exact_declared_zero_fee_action_are_allowed(self):
        for operation in OPERATIONS:self.check(operation=operation)
        action=self.action();self.check(action=action['id'])
    def test_undeclared_actor_nonempty_args_fee_and_unknown_action_refuse(self):
        for changes in ({'actor':'actor-03'},{'args':{'receive_payment_hash':'x'}},{'fee':1}):
            with self.subTest(changes=changes):
                self.store.db.execute('DELETE FROM action')
                action=self.action(**changes)
                with self.assertRaisesRegex(ValueError,'action context'):self.check(action=action['id'])
        self.store.db.execute('DELETE FROM action');action=self.action()
        self.store.finish(action['id'],'outcome_unknown',{'synthetic':'unknown'})
        with self.assertRaisesRegex(ValueError,'action context'):self.check(action=action['id'])
    def test_invalid_scope_wrong_pins_or_monetary_operation_refuse(self):
        for field,value in (('actors',['actor-01']),('operations',['board']),('maximum_fee_sat',1),('args',{'x':1})):
            proof=copy.deepcopy(self.proof);proof['client_action_scope'][field]=value
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'action scope'):self.check(proof)
        for operation in ('board','send_arkoor','funding','claim','progression'):
            with self.subTest(operation=operation),self.assertRaisesRegex(ValueError,'action scope'):
                self.check(operation=operation)
        with self.assertRaisesRegex(ValueError,'action scope'):self.check(fee=1)
        with self.assertRaisesRegex(ValueError,'action scope'):self.check({**self.proof,'client_action_scope':None})


class CashSQLiteControls(unittest.TestCase):
    def setUp(self):
        self.fixture=IdentityBootstrapTests();self.fixture.setUp()
        self.fixture.value['actors']=['actor-01','actor-02','actor-04'];self.fixture.declare()
        self.paths=[]
        for actor in self.fixture.value['actors']:
            directory=self.fixture.wallets/actor;directory.mkdir(mode=0o700)
            path=directory/'db.sqlite';connection=sqlite3.connect(path)
            connection.execute('CREATE TABLE migrations(value INTEGER)');connection.execute('INSERT INTO migrations VALUES (43)')
            for table in ECONOMIC_TABLES|METADATA_TABLES:connection.execute('CREATE TABLE '+table+'(dummy INTEGER)')
            connection.commit();connection.close();path.chmod(0o600);self.paths.append(path)
    def tearDown(self):self.fixture.tearDown()
    def collect(self):
        return observe_empty_client_economics(self.fixture.store,self.fixture.config)
    def test_all_three_actual_private_databases_are_counted_without_payload_reads(self):
        with Lease(self.fixture.wallets):sequence=self.collect()
        value=json.loads(self.fixture.store.db.execute('SELECT payload FROM event WHERE sequence=?',(sequence,)).fetchone()[0])
        self.assertEqual(3,len(value['clients']))
        self.assertNotIn('financial_operating_readiness',self.fixture.store.db.execute('SELECT kind FROM event WHERE sequence=?',(sequence,)).fetchone()[0])
    def test_existing_checkpoint_and_missing_economic_table_refuse(self):
        connection=sqlite3.connect(self.paths[0]);connection.execute('INSERT INTO bark_wallet_action_checkpoint VALUES (1)');connection.commit();connection.close()
        with Lease(self.fixture.wallets),self.assertRaisesRegex(ValueError,'existing monetary state'):self.collect()
        connection=sqlite3.connect(self.paths[0]);connection.execute('DELETE FROM bark_wallet_action_checkpoint');connection.execute('DROP TABLE bark_round_state');connection.commit();connection.close()
        with Lease(self.fixture.wallets),self.assertRaisesRegex(ValueError,'pinned client economic schema'):self.collect()


class CashSourceControls(unittest.IsolatedAsyncioTestCase):
    """Public source-shaped doubles, never evidence of a native/Core run."""
    def setUp(self):
        import time
        from types import SimpleNamespace
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name),'synthetic-cash',10000);initialize(self.store)
        self.actors=['actor-01','actor-02','actor-04'];self.height=100;self.txid='a'*64;self.openpoint='b'*64+':0';self.tip='c'*64
        self.members=[{'id':owner,'kind':'wallet','role':'customer' if owner in self.actors else 'operator',
            'identity':'public-'+owner,'descriptors':['desc-'+owner],'verification_sequence':1}
            for owner in ['bank','rounds','watchman',*self.actors]]
        self.recipients=[{'member_id':owner,'role':'customer' if owner in self.actors else 'operator','address':owner+'-0',
            'script':owner+':0','amount_sat':amount,'descriptor_index':0,'child_index':0}
            for owner,amount in [('rounds',100000),('watchman',75000),*[(actor,50000) for actor in self.actors]]]
        self.plan={'id':'cash','pins':PINS,'boundary_id':'finite','bank_wallet_name':'bank','recipients':self.recipients}
        self.transaction={'txid':self.txid,'inputs':[{'outpoint':self.openpoint,'amount_sat':665454,'script':'bank:0'}],
            'outputs':[{'vout':index,'script':row['script'],'amount_sat':row['amount_sat']} for index,row in enumerate(self.recipients)]
                +[{'vout':5,'script':'bank:1','amount_sat':339454}], 'fee_sat':1000,'confirmations':1,'blockhash':self.tip}
        self.db={'kind':'closed_frontier','database_tables_complete':True,'inventory_consistent':True,'read_only':True,
            'rows':{'records':3,'journal_records':3,'coins':0}}
        self.initial={'members':self.members,'inventory_sequences':{},'descriptor_ranges':[
            {'desc':member['descriptors'][0],'range':[0,19]} for member in self.members]}
        for member in self.members:
            coins=[{'outpoint':self.openpoint,'amount_sat':665454,'script':'bank:0','descriptor_index':0,'child_index':0}] if member['id']=='bank' else []
            self.initial['inventory_sequences'][member['id']]=self.event('treasury_inventory',{
                'member_id':member['id'],'financial_pins':PINS,'utxos':coins})
        self.initial['database_source_sequence']=self.event('closed_cohort_original_source',{'response':self.db})
        self.plan['finite_initial_source_sequence']=self.event('finite_initial_funding_sources_verified',self.initial)
        self.funding_sequence=self.event('fixture_funding_confirmed',{'synthetic':True})
        self.bank={'source_identity':{'wallet_name':'bank'},'height':100,'tip_hash':self.tip,
            'listunspent':[{'txid':self.txid,'vout':5,'amount':'0.00339454','scriptPubKey':'bank:1','spendable':True,'safe':True}],
            'pending_transactions':[],'pending_parents':[],'locked_coins':[],'listlockunspent':[],
            'getbalances':{'mine':{'trusted':'0.00339454','untrusted_pending':0}}}
        self.bankseq=self.event('treasury_bank_original_source',self.bank)
        self.config=SimpleNamespace(network='signet',expected_genesis=__import__('simulator.model',fromlist=['SIGNET_GENESIS']).SIGNET_GENESIS,inventory_command=['synthetic-readonly'])
        self.store.attach_trace();outer=self
        class Chain:
            def identity(self):return {'chain':'signet','initialblockdownload':False,'blocks':outer.height,'bestblockhash':outer.tip}
            def call(self,method,*args,**kwargs):
                if method=='getblockhash':return __import__('simulator.model',fromlist=['SIGNET_GENESIS']).SIGNET_GENESIS
                if method=='getblockchaininfo':return self.identity()
                if method=='getdescriptorinfo':return {'hasprivatekeys':False,'descriptor':args[0],'isrange':True}
                if method=='deriveaddresses':return [args[0][5:]+'-'+str(child) for child in range(args[1][0],args[1][1]+1)]
                if method=='validateaddress':return {'isvalid':True,'scriptPubKey':args[0].rsplit('-',1)[0]+':'+args[0].rsplit('-',1)[1]}
                if method=='getrawmempool':return []
                if method=='estimatesmartfee':return {'feerate':'0.00001000'}
                if method=='scantxoutset':
                    if args[0]=='status':return None
                    return outer.capture_scan({'success':True,'height':outer.height,'bestblock':outer.tip,'total_amount':'0.00664454',
                        'unspents':[{'txid':outer.txid,'vout':row['vout'],'amount':str(__import__('decimal').Decimal(row['amount_sat'])/100000000),'scriptPubKey':row['script']} for row in outer.transaction['outputs']]},args[1])
                if method=='gettxout':
                    row=outer.transaction['outputs'][args[1]]
                    return {'confirmations':1,'value':str(__import__('decimal').Decimal(row['amount_sat'])/100000000),'scriptPubKey':{'hex':row['script']}}
                raise AssertionError(method)
        self.chain=Chain()
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def event(self,kind,value):
        self.store.event(kind,value);return self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
    def capture_scan(self,result,coverage):
        self.chain.last_capture=self.store.trace_sample({'kind':'chain.rpc','payload':{'method':'scantxoutset',
            'params':['start',coverage],'error':None,'result':result},'raw':canonical({'result':result,'error':None}).encode()})
        return result
    def scan_identity(self,*args,**kwargs):
        return {'synthetic':True,'owners':sorted([{key:member[key] for key in ('id','kind','role','identity','descriptors')}
            for member in self.members],key=lambda row:row['id'])}
    def dependencies(self,frontier=1):
        from contextlib import ExitStack
        import sys
        from types import SimpleNamespace
        from unittest.mock import patch,AsyncMock
        stack=ExitStack()
        stack.enter_context(patch('simulator.confirmed_scan._identity',side_effect=self.scan_identity))
        current={field:{owner:{'complete':True,'network':'signet','wallet':owner,
            'public_descriptor':'desc-'+owner,'last_revealed_index':frontier,'tip_height':100,'tip_hash':self.tip}}
            for owner,field in (('rounds','rounds_inventory'),('watchman','watchman_inventory'))}
        stack.enter_context(patch.dict(sys.modules,{'simulator.runtime_startup':SimpleNamespace(_read=lambda p:(current,'synthetic-sha'))}))
        stack.enter_context(patch('simulator.fresh_cash_readiness._confirmed_funding',return_value=(
            self.plan,self.initial,{'txid':self.txid},self.transaction,self.funding_sequence)))
        stack.enter_context(patch('simulator.fresh_cash_readiness._phase_history'))
        stack.enter_context(patch('simulator.fresh_cash_readiness.observe_empty_client_economics',return_value=123))
        stack.enter_context(patch('simulator.funding_bank.collect_funding_bank_source',return_value=self.bankseq))
        stack.enter_context(patch('simulator.process.public_command_capture',return_value={}))
        stack.enter_context(patch('simulator.process.json_command',new=AsyncMock(side_effect=lambda *a,**k:copy.deepcopy(self.db))))
        return stack
    async def test_full_cash_closure_reconstructs_exact_five_recipients_and_bank_change(self):
        from simulator.fresh_cash_readiness import collect_fresh_cash_sources
        with self.dependencies():result=await collect_fresh_cash_sources(self.store,self.config,self.chain,None,current_startup_path='/synthetic-only')
        source=result['source'];self.assertEqual(664454,source['total_sat']);self.assertEqual(OPERATIONS,source['operation_scope'])
        self.assertEqual(6,len(source['inventory_sequences']));self.assertEqual(self.actors,source['actors'])
        self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM event WHERE kind='financial_operating_readiness'").fetchone()[0])
    async def test_actual_thirteen_descriptor_shape_uses_one_scan_and_seventeen_refuses(self):
        from simulator.fresh_cash_readiness import collect_fresh_cash_sources
        bank=next(member for member in self.members if member['id']=='bank')
        for index in range(7):
            descriptor='desc-bank-extra'+str(index);bank['descriptors'].append(descriptor)
            self.initial['descriptor_ranges'].append({'desc':descriptor,'range':[0,19]})
        calls=[];original=self.chain.call
        def capture(method,*args,**kwargs):
            if method=='scantxoutset' and args[0]=='start':calls.append(args[1])
            return original(method,*args,**kwargs)
        self.chain.call=capture
        with self.dependencies():await collect_fresh_cash_sources(self.store,self.config,self.chain,None,current_startup_path='/synthetic-only')
        self.assertEqual([13],[len(rows) for rows in calls])
        for index in range(7,11):
            descriptor='desc-bank-extra'+str(index);bank['descriptors'].append(descriptor)
            self.initial['descriptor_ranges'].append({'desc':descriptor,'range':[0,19]})
        calls.clear()
        with self.dependencies(),self.assertRaisesRegex(ValueError,'descriptor/script bound'):
            await collect_fresh_cash_sources(self.store,self.config,self.chain,None,current_startup_path='/synthetic-only')
        self.assertEqual([],calls)

    async def test_actual_grown_operator_frontier_covers_new_scripts_and_keeps_bounds(self):
        from simulator.fresh_cash_readiness import collect_fresh_cash_sources
        original=self.chain.call;scans=[]
        def capture(method,*args,**kwargs):
            if method=='scantxoutset' and args[0]=='start':scans.extend(args[1])
            return original(method,*args,**kwargs)
        self.chain.call=capture
        with self.dependencies(frontier=200):
            result=await collect_fresh_cash_sources(self.store,self.config,self.chain,None,current_startup_path='/synthetic-only')
        self.assertEqual([0,220],next(row['range'] for row in scans if row['desc']=='desc-rounds'))
        self.assertEqual('synthetic-sha',result['source']['range_runtime_source_sha256'])
        pending='d'*64
        def incoming(method,*args,**kwargs):
            if method=='getrawmempool':return [pending]
            return original(method,*args,**kwargs)
        self.chain.call=incoming;self.chain.tx=lambda txid:{'txid':txid,'vout':[{'scriptPubKey':{'hex':'rounds:200'}}]}
        with self.dependencies(frontier=200),self.assertRaisesRegex(ValueError,'unconfirmed output'):
            await collect_fresh_cash_sources(self.store,self.config,self.chain,None,current_startup_path='/synthetic-only')
        with self.dependencies(frontier=1979),self.assertRaisesRegex(ValueError,'descriptor/script bound'):
            await collect_fresh_cash_sources(self.store,self.config,self.chain,None,current_startup_path='/synthetic-only')

    async def test_changed_database_or_foreign_funding_output_refuses_no_readiness(self):
        from simulator.fresh_cash_readiness import collect_fresh_cash_sources
        original=copy.deepcopy(self.db);self.db['rows']['coins']=1
        with self.dependencies(),self.assertRaisesRegex(ValueError,'frontier'):await collect_fresh_cash_sources(self.store,self.config,self.chain,None,current_startup_path='/synthetic-only')
        self.db=original;self.transaction['outputs'][-1]['script']='foreign:0'
        with self.dependencies(),self.assertRaisesRegex(ValueError,'foreign output'):await collect_fresh_cash_sources(self.store,self.config,self.chain,None,current_startup_path='/synthetic-only')
        self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM event WHERE kind='financial_operating_readiness'").fetchone()[0])
    async def test_rounds_ineligible_cash_is_conserved_but_only_watchman_backs_fees(self):
        import sys,time
        from types import SimpleNamespace
        from unittest.mock import patch
        from simulator.fresh_cash_readiness import collect_fresh_cash_sources,record_fresh_cash_readiness
        with self.dependencies():result=await collect_fresh_cash_sources(self.store,self.config,self.chain,None,current_startup_path='/synthetic-only')
        source=result['source'];assets={}
        for row in self.transaction['outputs']:
            owner=row['script'].split(':')[0]
            assets[self.txid+':'+str(row['vout'])]={'member':owner,'amount_msat':row['amount_sat']*1000}
        current={}
        for owner,field in [('rounds','rounds_inventory'),('watchman','watchman_inventory')]:
            index=0 if owner=='rounds' else 1;output=self.transaction['outputs'][index]
            current[field]={owner:{'complete':True,'network':'signet','wallet':owner,'public_descriptor':'desc-'+owner,
                'last_revealed_index':1,'tip_height':100,'tip_hash':self.tip,'reserved_outpoints':[],'pending_transactions':[],'pending_parents':[],
                'unavailable_parent_txids':[],'utxos':[{'outpoint':self.txid+':'+str(index),'value_sat':output['amount_sat'],
                    'script_pubkey':output['script'],'confirmed_fee_eligible':owner=='watchman','trusted':owner=='watchman',
                    'reserved':False,'mature':True}]}}
        caps={'round':None,'pool':None,'sweep':20000,'payout':20000,'claim':None,'progression':None}
        runtime={'loaded_configuration_identity_verified':True,'current_source_sha256':'synthetic-sha','product_commit':PINS['product_commit'],
            'schema_sha256':PINS['schema_sha256'],'observed_at':time.time(),'effective_fee_ceilings_sat_kvb':caps}
        runtime_sequence=self.event('owned_runtime_configuration_verified',runtime)
        limits={'pins':PINS,'boundary_id':'finite','fee_ceilings_sat_kvb':caps,'operation_fee_paths':{op:['sweep','payout'] for op in OPERATIONS},
            'fee_budgets_msat':{'ordinary':60000000,'urgent':15000000}}
        bootstrap={'actors':self.actors,'pins':PINS};self.store.db.execute("INSERT INTO meta VALUES ('zero_principal_identity_bootstrap',?)",(canonical(bootstrap),))
        self.event('identity_bootstrap_declared',{'declaration':bootstrap})
        with self.dependencies(),patch.dict(sys.modules,{'simulator.runtime_startup':SimpleNamespace(_read=lambda p:(current,'synthetic-sha'))}),\
                patch('simulator.treasury.boundary',return_value={'id':'finite','members':self.members}),\
                patch('simulator.treasury.capture_assets',return_value={'height':100,'tip_hash':self.tip,'total_msat':664454000,'assets':assets}),\
                patch('simulator.operating_limits.envelope',return_value=limits),\
                patch('simulator.operating_limits.fee_totals',return_value={'ordinary':1000000,'urgent':0}):
            receipt=record_fresh_cash_readiness(self.store,self.config,self.chain,source_sequence=result['source_sequence'],
                runtime_source_sequence=runtime_sequence,current_startup_path='/synthetic-only')
            self.assertEqual(75000000,receipt['available_fee_funding_msat']);self.assertEqual(664454000,receipt['capital_exposure_msat'])
            current['watchman_inventory']['watchman']['utxos'][0]['confirmed_fee_eligible']=False
            with self.assertRaisesRegex(ValueError,'remaining fee budgets'):
                record_fresh_cash_readiness(self.store,self.config,self.chain,source_sequence=result['source_sequence'],runtime_source_sequence=runtime_sequence,current_startup_path='/synthetic-only')

    def test_confirmed_funding_uses_original_authenticated_events_and_independent_transaction(self):
        import sys
        from types import SimpleNamespace
        from unittest.mock import patch
        from simulator.fresh_cash_readiness import _confirmed_funding,_digest
        self.plan['maximum_miner_fee_sat']=10000;self.plan['bank_source_sequence']=self.bankseq
        self.initial.update(financial_pins=PINS,boundary_id='finite',funding_recipients=self.recipients)
        self.plan['finite_initial_source_sequence']=self.event('finite_initial_funding_sources_verified',self.initial)
        funded={'bank_source_sequence':self.bankseq,'batch':'finite:cash','txid':self.txid,'fee_sat':1000,'financial_pins':PINS,'boundary_id':'finite',
            'recipients':self.recipients,'funding_plan_sha256':_digest(self.recipients),
            'finite_initial_source_sequence':self.plan['finite_initial_source_sequence'],'confirmed_transaction':self.transaction}
        self.event('fixture_funding_confirmed',funded)
        self.event('financial_cost_verified',{'financial_pins':PINS,'monetary_id':'bitcoin-miner:'+self.txid,'amount_msat':1000000,'budget':'ordinary'})
        self.store.db.execute('CREATE TABLE funding_batch(id TEXT,state TEXT,txid TEXT,fee_sat INTEGER)')
        self.store.db.execute('INSERT INTO funding_batch VALUES (?,?,?,?)',('finite:cash','confirmed',self.txid,1000))
        chain=SimpleNamespace(transaction=lambda txid:copy.deepcopy(self.transaction))
        with patch.dict(sys.modules,{'simulator.finite_funding':SimpleNamespace(_plan=lambda store:self.plan)}):
            self.assertEqual(self.transaction,_confirmed_funding(self.store,chain)[3])
            self.transaction['confirmations']=0
            with self.assertRaisesRegex(ValueError,'independent confirmed'):_confirmed_funding(self.store,chain)
            self.transaction['confirmations']=1
            self.event('fixture_funding_confirmed',funded)
            with self.assertRaisesRegex(ValueError,'unique original'):_confirmed_funding(self.store,chain)

    def test_phase_history_refuses_unknown_or_received_monetary_work(self):
        from simulator.fresh_cash_readiness import _phase_history
        self.store.db.execute('CREATE TABLE funding_batch(state TEXT)')
        bootstrap={'actors':self.actors,'pins':PINS};self.store.db.execute("INSERT INTO meta VALUES ('zero_principal_identity_bootstrap',?)",(canonical(bootstrap),))
        self.event('identity_bootstrap_declared',{'declaration':bootstrap})
        scenario=self.store.db.execute('SELECT id FROM scenario LIMIT 1').fetchone()[0]
        self.store.queue('sync-only','actor-01',scenario,'sync',{},0);action=self.store.claim({'sync'})
        with self.assertRaisesRegex(ValueError,'unfinished'):_phase_history(self.store,PINS,self.actors)
        response={'status':'ok','actual_fee_sat':0,'data':{'receive_count_before':0,'receive_count_after':0,
            'before_evidence':{'coins':[],'movements':[]},'evidence':{'coins':[],'movements':[]}}}
        self.store.finish(action['id'],'completed',response,0);_phase_history(self.store,PINS,self.actors)
        response['data']['receive_count_after']=1
        self.store.db.execute('UPDATE action SET result=? WHERE id=?',(canonical(response),action['id']))
        with self.assertRaisesRegex(ValueError,'monetary state'):_phase_history(self.store,PINS,self.actors)


class CashEngineProbeControls(unittest.TestCase):
    def test_cash_only_proof_readies_engine_without_opening_board_or_undeclared_client(self):
        import time
        from unittest.mock import patch
        from simulator.engine import Engine
        from simulator.operating_limits import preflight
        from tests.test_scoped_operating_limits import ScopedOperatingTests
        fixture=ScopedOperatingTests();fixture.setUp()
        try:
            fixture.declare();actors=['actor-01','actor-02','actor-04'];value={'actors':actors,'pins':PINS}
            fixture.store.db.execute("INSERT INTO meta VALUES ('zero_principal_identity_bootstrap',?)",(canonical(value),))
            fixture.store.event('identity_bootstrap_declared',{'declaration':value})
            fixture.store.db.execute("INSERT INTO meta VALUES ('financial_qualification_required','true')")
            snapshot=fixture.readiness(operation_scope=OPERATIONS,client_action_scope={
                'actors':actors,'operations':OPERATIONS,'maximum_fee_sat':0,'args':{}})
            snapshot.update(observed_at=time.time(),stable_tip=True,initial_block_download=False,server_status={'status':'running'})
            engine=Engine.__new__(Engine);engine.store,engine.config=fixture.store,fixture.config
            with patch('simulator.identity_bootstrap.pending',return_value=False):
                self.assertTrue(engine.ready_for_actions(snapshot))
                for operation in ('board','funding','claim','progression','pay_invoice'):
                    with self.subTest(operation=operation),self.assertRaises(ValueError):preflight(fixture.store,fixture.config,snapshot,operation=operation)
                fixture.store.db.execute("DELETE FROM meta WHERE key='paused'")
                scenario=fixture.store.db.execute('SELECT id FROM scenario LIMIT 1').fetchone()[0]
                fixture.store.queue('not-cohort','actor-03',scenario,'sync',{},0);action=fixture.store.claim({'sync'})
                with self.assertRaisesRegex(ValueError,'action context'):preflight(fixture.store,fixture.config,snapshot,operation='sync',reserved_action_id=action['id'])
        finally:fixture.tearDown()

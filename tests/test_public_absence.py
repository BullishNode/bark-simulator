"""Synthetic public source controls only; no native/Core/live qualification."""
import asyncio
import copy
import hashlib
import io
import json
import sqlite3
import time
import unittest
from contextlib import ExitStack
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock,patch

from simulator import public_absence as public,ordinary_arkoor as ordinary
# Load the real module before patching treasury functions; a lazy first import
# inside a patched context would retain a mock in unrelated envelope controls.
from simulator import operating_limits
from simulator.model import SIGNET_GENESIS,InvariantError,canonical
from simulator.negative_checks import record_bytes
from simulator.public_treasury import confirmed_frontier
from tests import test_ordinary_arkoor as native_fixture
from tests.test_final_campaign import PINS
from tests import account_fixtures


class PublicAbsenceControls(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        f=native_fixture.NativeAdoptionControls();self.f=f;self.records={}
        def binding(actor,pubkey):
            number=int(actor.split('-')[1]);rec={'mailbox_pk':'02'+str(number)*64,'spk':'0014'+str(number)*40,
                'account_xpub':'11'*78,'mailbox_sig':'22'*64,'account_sig':'33'*64}
            self.records[actor]=rec
            return account_fixtures.proof({'user_pubkey':pubkey,'binding':{**{key:rec[key] for key in ('mailbox_pk','spk','account_xpub')},'fallback_record':record_bytes(rec)}})['binding']
        f.binding=binding;f.setUp();self.store=f.store;self.store.attach_trace()
        self.fund='d'*64;self.tip='e'*64;self.height=100;self.anchor_script='5120'+'a'*64
        f.origin.update(anchor_output={'vout':0,'amount_sat':20000,'script':self.anchor_script},
            transaction={'txid':'a'*64,'inputs':[{'outpoint':self.fund+':2','amount_sat':50000,'script':'actor-01:1'}],
                'outputs':[{'vout':0,'amount_sat':20000,'script':self.anchor_script},{'vout':1,'amount_sat':29829,'script':'actor-01:2'}],
                'fee_sat':171,'confirmations':1,'blockhash':self.tip},funding_plan={'bank_wallet_name':'bank'})
        source,_,initial_chain=f.terminal();graph,prior=f.graph(f.send_record)
        initial_chain.call=lambda *args:{'confirmations':1,'value':'0.00020000','scriptPubKey':{'hex':self.anchor_script}}
        graph['rows']={name:graph['rows'].get(name,[]) for name in public.TABLES}
        records=list(self.records.values());graph['rows'].update(records=copy.deepcopy(records),journal_records=copy.deepcopy(records))
        self.members=[{'id':member,'identity':'original-'+member,'kind':'wallet','role':'customer' if member.startswith('actor') else 'operator',
            'descriptors':['desc-'+member],'verification_sequence':1} for member in ('bank','rounds','watchman','actor-01','actor-02','actor-04')]
        self.opening={self.fund+':'+str(index):{'member_id':member,'amount_sat':amount,'script':script,'descriptor_index':0,'child_index':child}
            for index,member,amount,script,child in [(0,'rounds',100000,'rounds:0',0),(1,'watchman',75000,'watchman:0',0),
                (3,'actor-02',50000,'actor-02:1',1),(4,'actor-04',50000,'actor-04:1',1),(5,'bank',339746,'bank:1',1)]}
        self.opening['a'*64+':1']={'member_id':'actor-01','amount_sat':29829,'script':'actor-01:2','descriptor_index':0,'child_index':2}
        self.opening[f.anchor]={'member_id':'original-board-backing','amount_sat':20000,'script':self.anchor_script}
        self.physical=copy.deepcopy(self.opening);self.database=copy.deepcopy(graph)
        source.update(origin=f.origin,members=self.members,database=copy.deepcopy(graph),
            descriptor_ranges=[{'desc':member['descriptors'][0],'range':[0,19]} for member in self.members],
            physical_assets=copy.deepcopy(self.opening),physical_total_sat=664575)
        self.store.event(ordinary.KIND,source);original_source=self.sequence()
        # Retain public native-verifier-shaped proof paths for the SAME original
        # signed objects before absence. These are unit doubles, not signatures.
        for row in self.store.db.execute('SELECT id,proof FROM owned_coin').fetchall():
            proof=json.loads(row['proof']);proof.update(proof_encoding='ark-public-authorization-v1',
                ancestor_ids=[f.anchor,f.parent,row['id']])
            proof['path'].insert(0,{'txid':'b'*64,'inputs':[f.anchor],'outputs':[{'vout':0,'value_sat':19670,'script_pubkey':'source'},
                {'vout':1,'value_sat':330,'script_pubkey':'51024e73'}]})
            self.store.db.execute('UPDATE owned_coin SET proof=? WHERE id=?',(canonical(proof),row['id']))
        with f.dependencies(),patch.object(ordinary.backing,'_origin',return_value=f.origin):
            ordinary.record_ordinary_journey(self.store,f.config,initial_chain,source_sequence=original_source)
        self.journey=self.sequence();self.store.declare_permanent_absence('actor-02',reason='Original signed recipient receipt sealed; original wallet permanently closed')
        self.proofs={table:[tuple(row) for row in self.store.db.execute('SELECT * FROM '+table)] for table in ('owner_record','owner_key','owned_coin')}
        self.caps={'round':None,'pool':None,'sweep':20000,'payout':20000,'claim':None,'progression':None}
        self.runtime={'loaded_configuration_identity_verified':True,'current_source_sha256':'f'*64,'product_commit':PINS['product_commit'],
            'schema_sha256':PINS['schema_sha256'],'effective_fee_ceilings_sat_kvb':self.caps,'direct_carrier_max_miner_fee_sat':10000,'observed_at':time.time()}
        self.store.event('owned_runtime_configuration_verified',self.runtime);self.runtime_seq=self.sequence()
        for txid,fee,action in [('funding',708,None),('a'*64,171,'original-board')]:
            self.store.event('financial_cost_verified',{'monetary_id':'bitcoin-miner:'+txid,'financial_pins':PINS,'budget':'ordinary','amount_msat':fee*1000,**({'action_id':action} if action else {})})
        self.config=SimpleNamespace(network='signet',expected_genesis=SIGNET_GENESIS,inventory_command=('fixed-public-bridge',),wallet_root=f.root)
        self.current={};self.transactions={};self.raw_transactions={};self.mem=[];self.scan_extra=[];self.missing=set();self.started=[];self.mempool_reads=0;self.spend_after_mempool=False;self.late_pending=False;self.refresh_current();outer=self
        class Core:
            def identity(self):return {'chain':'signet','initialblockdownload':False,'blocks':outer.height,'bestblockhash':outer.tip}
            def transaction(self,txid):
                if txid not in outer.transactions:raise ValueError('not known by synthetic Core')
                return copy.deepcopy(outer.transactions[txid])
            def tx(self,txid):return copy.deepcopy(outer.raw_transactions[txid])
            def call(self,method,*args,**kwargs):
                if method=='getblockhash':return SIGNET_GENESIS if args[0]==0 else outer.tip
                if method=='getblockchaininfo':return self.identity()
                if method=='getdescriptorinfo':return {'descriptor':args[0],'hasprivatekeys':False,'isrange':True}
                if method=='deriveaddresses':return [args[0][5:]+':'+str(child) for child in range(args[1][0],args[1][1]+1)]
                if method=='validateaddress':return {'isvalid':True,'scriptPubKey':outer.script(args[0])}
                if method=='getrawmempool':
                    outer.mempool_reads+=1
                    if outer.spend_after_mempool and outer.mempool_reads>=2:outer.late_pending=True
                    return outer.mem
                if method=='estimatesmartfee':return {'feerate':'0.00001001'}
                if method=='gettxout':
                    point=args[0]+':'+str(args[1]);coin=outer.physical.get(point)
                    if point in outer.missing or coin is None or args[2] is True and outer.late_pending and point==outer.f.anchor:return None
                    return {'confirmations':1,'value':str(Decimal(coin['amount_sat'])/100000000),'scriptPubKey':{'hex':coin['script']}}
                if method=='scantxoutset':
                    if args[0]=='status':return None
                    outer.started.append(args[1]);rows=[{'txid':point.split(':')[0],'vout':int(point.split(':')[1]),'amount':str(Decimal(coin['amount_sat'])/100000000),'scriptPubKey':coin['script']}
                        for point,coin in outer.physical.items() if point!=outer.f.anchor]+copy.deepcopy(outer.scan_extra)
                    result={'success':True,'height':outer.height,'bestblock':outer.tip,'unspents':rows,'total_amount':str(sum(Decimal(row['amount']) for row in rows))}
                    self.last_capture=outer.store.trace_sample({'kind':'chain.rpc','payload':{'method':method,'params':list(args),'result':result,'error':None},'raw':canonical({'result':result,'error':None}).encode()})
                    return result
                raise AssertionError(method)
        self.chain=Core()
    def tearDown(self):self.f.tearDown()
    def sequence(self):return self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
    def script(self,address):
        actor,index=address.rsplit(':',1)
        if (actor,index)==('watchman','2'):return '0014'+'5'*40
        return self.records[actor]['spk'] if actor in self.records and index=='0' else address
    def refresh_current(self):
        for owner,field in [('rounds','rounds_inventory'),('watchman','watchman_inventory')]:
            self.current[field]={owner:{'complete':True,'network':'signet','wallet':owner,'public_descriptor':'desc-'+owner,
                'last_revealed_index':1,'tip_height':self.height,'tip_hash':self.tip,'reserved_outpoints':[],
                'pending_transactions':[],'pending_parents':[],'unavailable_parent_txids':[],
                'utxos':[{'outpoint':point,'value_sat':coin['amount_sat'],'script_pubkey':coin['script'],'confirmed_fee_eligible':True,'trusted':True,'mature':True,'reserved':False}
                    for point,coin in self.physical.items() if coin['member_id']==owner]}}
    def bank(self):
        coins=[(point,coin) for point,coin in self.physical.items() if coin['member_id']=='bank']
        value={'source_identity':{'wallet_name':'bank'},'height':self.height,'tip_hash':self.tip,
            'listunspent':[{'txid':point.split(':')[0],'vout':int(point.split(':')[1]),'amount':str(Decimal(coin['amount_sat'])/100000000),'scriptPubKey':coin['script'],'spendable':True,'safe':True} for point,coin in coins],
            'pending_transactions':[],'pending_parents':[],'locked_coins':[],'listlockunspent':[],
            'getbalances':{'mine':{'trusted':str(Decimal(sum(coin['amount_sat'] for _,coin in coins))/100000000),'untrusted_pending':0}}}
        self.store.event('treasury_bank_original_source',value);return self.sequence()
    def dependencies(self):
        stack=ExitStack();wallet=self.f.root
        original_connect=sqlite3.connect;original_open=io.open
        def connect(path,*args,**kwargs):
            if str(wallet) in str(path):raise AssertionError('original customer SQLite must remain closed')
            return original_connect(path,*args,**kwargs)
        def opened(path,*args,**kwargs):
            if str(wallet) in str(path):raise AssertionError('original customer wallet must remain closed')
            return original_open(path,*args,**kwargs)
        reads=0
        def bridge(argv,request,**kwargs):
            nonlocal reads
            if argv!=list(self.config.inventory_command) or request!={'kind':'closed_frontier'}:raise AssertionError('only fixed public database reads allowed')
            reads+=1
            if reads>1 and hasattr(self,'end_database'):return copy.deepcopy(self.end_database)
            return copy.deepcopy(self.database)
        stack.enter_context(patch('sqlite3.connect',side_effect=connect));stack.enter_context(patch('io.open',side_effect=opened))
        stack.enter_context(patch('builtins.open',side_effect=opened))
        stack.enter_context(patch('simulator.process.json_command',new=AsyncMock(side_effect=bridge)))
        stack.enter_context(patch('simulator.engine.json_command',side_effect=AssertionError('native driver forbidden')))
        for name in ('simulator.ordinary_arkoor._native','simulator.board_adoption._client_state','simulator.fresh_cash_readiness.observe_empty_client_economics'):
            stack.enter_context(patch(name,side_effect=AssertionError('original client access forbidden')))
        stack.enter_context(patch('simulator.public_absence._origin',return_value=self.f.origin))
        stack.enter_context(patch('simulator.runtime_startup._read',return_value=(self.current,'f'*64)))
        stack.enter_context(patch('simulator.confirmed_scan._identity',return_value={'owners':self.members,'scope':'synthetic immutable actual epoch'}))
        stack.enter_context(patch('simulator.funding_bank.collect_funding_bank_source',side_effect=lambda *args:self.bank()))
        stack.enter_context(patch('simulator.treasury.boundary',return_value={'id':'finite','pins':PINS,'members':self.members}))
        stack.enter_context(patch('simulator.operating_limits.envelope',return_value={'pins':PINS,'boundary_id':'finite','capital_exposure_msat':665454000,'fee_ceilings_sat_kvb':self.caps,'fee_budgets_msat':{'ordinary':60000000,'urgent':15000000}}))
        return stack
    async def collect(self):
        with self.dependencies():return (await public.collect_public_absence_sources(self.store,self.config,self.chain,None,journey_sequence=self.journey,runtime_source_sequence=self.runtime_seq,current_startup_path='/synthetic-current'))['source']
    def confirmed(self,fee=500):
        txid='9'*64;self.height=101;self.tip='8'*64;allocations=[];mapping=[]
        for point,amount,pub in [(self.f.fork+':0',2000,self.f.recipient_pk),*[(point,item['amount_sat'],item['user_pubkey']) for point,item in self.f.send_record['changes'].items()]]:
            actor='actor-02' if amount==2000 else 'actor-01';paid=1000 if actor=='actor-02' else (1000 if point.endswith(':1') else 0)
            allocations.append({'id':point,'freeze_set':'original-group','owner_pubkey':pub,'spk':self.records[actor]['spk'],'disposition':'pay','gross_sat':amount,
                'fee_sat':paid,'payout_sat':amount-paid,'forfeited_sat':0,'source':'registered','retirement_ids':[self.f.anchor],'frozen_at':'2026-10-15T00:00:00Z'})
            mapping.append({'txid':txid,'allocation_id':point,'vout':0 if actor=='actor-02' else 1})
        op={'id':'b'*64+':1','freeze_set':'original-group','owner_pubkey':None,'spk':None,'disposition':'operator','gross_sat':330,'fee_sat':0,'payout_sat':0,
            'forfeited_sat':0,'source':'transition-fee-anchor','retirement_ids':[self.f.anchor],'frozen_at':'2026-10-15T00:00:00Z'}
        allocations.append(op);mapping.append({'txid':txid,'allocation_id':op['id'],'vout':None})
        tx={'txid':txid,'inputs':[{'outpoint':self.f.anchor,'amount_sat':20000,'script':self.anchor_script}],
            'outputs':[{'vout':0,'amount_sat':1000,'script':self.records['actor-02']['spk']},{'vout':1,'amount_sat':16670,'script':self.records['actor-01']['spk']},
                {'vout':2,'amount_sat':2330-fee,'script':self.script('watchman:2')}],'fee_sat':fee,'confirmations':1,'blockhash':self.tip}
        raw=('02000000'+'01'+'aa'*32+'00000000'+'00'+'fdffffff'+'03'+''.join(
            output['amount_sat'].to_bytes(8,'little').hex()+bytes([len(bytes.fromhex(output['script']))]).hex()+output['script'] for output in tx['outputs'])+'00000000')
        from simulator.bundle_audit import decode_transaction
        body=decode_transaction(raw,public_body=True);txid=body['txid'];tx['txid']=txid
        for row in mapping:row['txid']=txid
        self.transactions[txid]=tx;self.raw_transactions[txid]={'txid':txid,'hex':raw,'weight':body['weight'],'vsize':body['vsize']}
        carrier={'txid':txid,'generation':1,'backing_ids':[self.f.anchor],'fee_inputs':[],'miner_fee_sat':fee,'funding_subsidy_sat':max(fee-2330,0),
            'created_at':'2026-10-15T00:00:00Z','confirmed_height':101,'confirmed_block':self.tip}
        self.database['rows'].update(journal_allocations=allocations,journal_carriers=[carrier],journal_mappings=mapping)
        for row in self.database['rows']['coins']:
            if row['vtxo_id']==self.f.anchor:row.update(onchain_spent_txid=txid,onchain_spent_height=101)
        del self.physical[self.f.anchor]
        for output,member,child in [(tx['outputs'][0],'actor-02',0),(tx['outputs'][1],'actor-01',0),(tx['outputs'][2],'watchman',2)]:
            self.physical[txid+':'+str(output['vout'])]={'member_id':member,'amount_sat':output['amount_sat'],'script':output['script'],'descriptor_index':0,'child_index':child}
        self.refresh_current();return txid
    async def test_unspent_root_whole_public_observation_never_opens_original_clients_or_admits(self):
        source=await self.collect();self.assertTrue(source['physical_complete'],source['gaps']);self.assertTrue(source['observation_complete'],source['gaps'])
        self.assertEqual(664575,source['physical_total_sat']);self.assertEqual(19670,source['outstanding_liability_sat']);self.assertEqual(1,sum(point==self.f.anchor for point in source['physical_assets']))
        self.assertFalse(source['complete']);self.assertFalse(source['qualified']);self.assertNotIn('operation_scope',source)
        for table,rows in self.proofs.items():self.assertEqual(rows,[tuple(row) for row in self.store.db.execute('SELECT * FROM '+table)])
        self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM event WHERE kind='financial_operating_readiness'").fetchone()[0])
    async def test_actual_direct_oracle_checked_successor_conserves_root_once_liability_separate_and_cost_dedup(self):
        txid=self.confirmed();first=await self.collect();second=await self.collect()
        self.assertTrue(first['observation_complete'],first['gaps']);self.assertTrue(second['observation_complete'],second['gaps'])
        self.assertEqual(664075,first['physical_total_sat']);self.assertNotIn(self.f.anchor,first['physical_assets']);self.assertEqual(0,first['outstanding_liability_sat'])
        recipient=[leaf for leaf in first['liabilities'] if leaf['actor']=='actor-02'];self.assertEqual([(2000,1000,1000,'confirmed_pay')],[(leaf['amount_sat'],leaf['payout_sat'],leaf['flat_fee_sat'],leaf['state']) for leaf in recipient])
        self.assertEqual({'ordinary':1379000,'urgent':0},first['budget_used_msat']);self.assertEqual(330,first['internal_service_sat'])
        self.assertEqual(1,self.store.db.execute("SELECT count(*) FROM event WHERE kind='financial_cost_verified' AND json_extract(payload,'$.monetary_id')=?",('bitcoin-miner:'+txid,)).fetchone()[0])
        self.assertEqual(1,self.store.db.execute("SELECT count(*) FROM event WHERE kind='direct_payment_checked'").fetchone()[0])
    async def test_wrong_owner_or_extra_mapped_leaf_refuses_existing_oracle(self):
        self.confirmed();self.database['rows']['journal_allocations'][0]['owner_pubkey']='02'+'7'*64
        with self.assertRaises(InvariantError):await self.collect()
    async def test_extra_owned_asset_missing_member_and_unaccounted_spender_stay_partial(self):
        self.scan_extra=[{'txid':'7'*64,'vout':0,'amount':'0.00000100','scriptPubKey':'bank:2'}]
        source=await self.collect();self.assertFalse(source['physical_complete']);self.assertIn('extra/missing/changed',source['gaps'][0])
    async def test_spent_source_without_accounted_successor_stays_partial(self):
        self.missing={self.f.anchor};source=await self.collect();self.assertFalse(source['physical_complete']);self.assertIn('accounted confirmed successor',source['gaps'][0])
    async def test_missing_actual_boundary_member_refuses(self):
        self.members.pop()
        with self.assertRaisesRegex(ValueError,'whole treasury'):await self.collect()
    async def test_mempool_or_unknown_version_never_paid_and_db_only_confirmation_refuses(self):
        txid=self.confirmed();self.transactions[txid]['confirmations']=0
        source=await self.collect();self.assertFalse(source['liabilities_complete']);self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM checked_settlement').fetchone()[0])
        self.transactions[txid]['confirmations']=1;self.database['rows']['journal_carriers'][0]['confirmed_height']=100
        source=await self.collect();self.assertFalse(source['observation_complete']);self.assertIn('height/block',source['gaps'][0])
    async def test_stale_runtime_and_undeclared_current_release_refuse(self):
        self.runtime['observed_at']=time.time()-91;self.store.event('owned_runtime_configuration_verified',self.runtime);self.runtime_seq=self.sequence()
        with self.assertRaisesRegex(ValueError,'fresh authenticated'):await self.collect()
        self.runtime.update(observed_at=time.time(),product_commit='4'*40);self.store.event('owned_runtime_configuration_verified',self.runtime);self.runtime_seq=self.sequence()
        with self.assertRaisesRegex(ValueError,'runtime identity'):await self.collect()
    async def test_unknown_reservations_do_not_become_eligible_fee_capital(self):
        self.current['watchman_inventory']['watchman']['reserved_outpoints']=[self.fund+':1']
        source=await self.collect();self.assertTrue(source['physical_complete']);self.assertFalse(source['fee_inventory_complete']);self.assertIsNone(source['eligible_fee_funding_msat']);self.assertFalse(source['observation_complete'])
    async def test_original_root_plus_confirmed_successor_and_duplicate_consumer_refuse(self):
        txid=self.confirmed();self.physical[self.f.anchor]=copy.deepcopy(self.opening[self.f.anchor])
        source=await self.collect();self.assertFalse(source['physical_complete']);self.assertNotIn(self.f.anchor,source.get('physical_assets',{}))
        tx=self.transactions[txid]
        owners={output['script']:{'member_id':self.physical[txid+':'+str(output['vout'])]['member_id']} for output in tx['outputs']}
        with self.assertRaises(InvariantError):confirmed_frontier(self.opening,[tx,tx],owners)

    async def test_current_declared_epoch_is_bound_without_rewriting_original_journey(self):
        release={'product_commit':'4'*40,'schema_sha256':'6'*64}
        manifest={'origin_financial_pins':PINS,'execution_release':release,'deployment_epoch_id':'actual-current-epoch','startup_source_sha256':'7'*64}
        self.runtime.update(product_commit=release['product_commit'],schema_sha256=release['schema_sha256'],
            execution_release=release,deployment_epoch_id=manifest['deployment_epoch_id'],startup_source_sha256=manifest['startup_source_sha256'])
        self.store.event('owned_runtime_configuration_verified',self.runtime);self.runtime_seq=self.sequence()
        original=tuple(self.store.db.execute('SELECT * FROM event WHERE sequence=?',(self.journey,)).fetchone())
        with patch('simulator.target_epochs.active_runtime_manifest',return_value=manifest):
            source=await self.collect()
            self.assertTrue(source['physical_complete'],source['gaps']);self.assertEqual(release,source['execution_release'])
            self.assertEqual(PINS,source['financial_pins']);self.assertEqual(manifest['deployment_epoch_id'],source['deployment_epoch_id'])
            self.assertEqual(original,tuple(self.store.db.execute('SELECT * FROM event WHERE sequence=?',(self.journey,)).fetchone()))
            manifest['execution_release']={'product_commit':'3'*40,'schema_sha256':'6'*64}
            with self.assertRaisesRegex(ValueError,'declared lineage'):await self.collect()
    async def test_changed_retained_signed_bytes_cannot_replace_original_native_snapshot(self):
        point=self.f.fork+':0';self.store.db.execute('UPDATE owned_coin SET signed_vtxo=?,signed_hash=? WHERE id=?',('bb',hashlib.sha256(bytes.fromhex('bb')).hexdigest(),point))
        with self.assertRaisesRegex(InvariantError,'original authenticated native snapshot'):await self.collect()
    async def test_actual_signed_body_mismatch_and_high_fee_forfeit_never_become_terminal(self):
        txid=self.confirmed();self.raw_transactions[txid]['weight']+=1
        source=await self.collect();self.assertFalse(source['liabilities_complete']);self.assertIn('body/weight',source['gaps'][0])
        self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM checked_settlement').fetchone()[0])
        self.raw_transactions[txid]['weight']-=1
        recipient=self.database['rows']['journal_allocations'][0];recipient.update(disposition='forfeit',fee_sat=0,payout_sat=0,forfeited_sat=2000)
        with self.assertRaises(InvariantError):await self.collect()
    async def test_retained_unknown_replacement_outcome_and_incomplete_full_database_hold(self):
        txid=self.confirmed();replacement={**self.database['rows']['journal_carriers'][0],'txid':'6'*64,'generation':2,'confirmed_height':None,'confirmed_block':None}
        self.database['rows']['journal_carriers'].append(replacement)
        self.database['rows']['journal_mappings'] += [{**row,'txid':replacement['txid']} for row in list(self.database['rows']['journal_mappings'])]
        source=await self.collect();self.assertFalse(source['observation_complete']);self.assertIn('outcome unknown',source['gaps'][0]);self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM checked_settlement').fetchone()[0])
        self.database['database_tables_complete']=False
        source=await self.collect();self.assertFalse(source['physical_complete']);self.assertIn('nineteen-table',source['gaps'][0])
    async def test_current_database_cannot_drop_a_previously_retained_known_generation(self):
        txid=self.confirmed();replacement='6'*64
        self.database['rows']['journal_carriers'].append({**self.database['rows']['journal_carriers'][0],'txid':replacement,'generation':2,'confirmed_height':None,'confirmed_block':None})
        self.database['rows']['journal_mappings'] += [{**row,'txid':replacement} for row in list(self.database['rows']['journal_mappings'])]
        self.transactions[replacement]={**self.transactions[txid],'txid':replacement,'confirmations':0,'blockhash':None}
        first=await self.collect();self.assertTrue(first['observation_complete'],first['gaps'])
        self.database['rows']['journal_carriers']=[row for row in self.database['rows']['journal_carriers'] if row['txid']!=replacement]
        self.database['rows']['journal_mappings']=[row for row in self.database['rows']['journal_mappings'] if row['txid']!=replacement]
        following=await self.collect();self.assertFalse(following['observation_complete']);self.assertIn('retained known history',following['gaps'][0])
    async def test_invalid_final_database_revokes_all_current_inventory_flags(self):
        self.end_database=copy.deepcopy(self.database);self.end_database['read_only']=False
        source=await self.collect()
        self.assertFalse(source['observation_complete']);self.assertFalse(source['physical_complete'])
        self.assertFalse(source['liabilities_complete']);self.assertFalse(source['fee_inventory_complete'])
        self.assertIsNone(source['eligible_fee_funding_msat']);self.assertIsNone(source['remaining_fee_budget_backed'])

    async def test_new_pending_spend_after_mempool_pass_revokes_current_fee_inventory(self):
        self.spend_after_mempool=True
        source=await self.collect()
        self.assertFalse(source['observation_complete']);self.assertFalse(source['physical_complete'])
        self.assertFalse(source['fee_inventory_complete']);self.assertIsNone(source['eligible_fee_funding_msat'])
        self.assertIn('unresolved mempool spend',source['gaps'][0])

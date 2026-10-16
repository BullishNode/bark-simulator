"""Synthetic source-boundary controls, not native/live financial qualification."""
import asyncio
import copy
import hashlib
import json
import subprocess
import tempfile
import time
import unittest
from decimal import Decimal
from pathlib import Path
from unittest.mock import AsyncMock, patch

from simulator import two_step_normal as adapter
from simulator.model import SIGNET_GENESIS, canonical
from simulator.store import Store
from tests.test_final_campaign import PINS
from tests.test_normal_native_fee import transaction


class TablesTests(unittest.TestCase):
    def setUp(self):
        self.source = {'read_only':'on', 'isolation':'repeatable read',
            'tables':{name:{'count':0,'rows':[]} for name in adapter.TABLES}}
    def raw(self): return ('BEGIN\nSET\n'+canonical(self.source)+'\nCOMMIT\n').encode()
    def parse(self):
        raw=self.raw(); return adapter.native_tables(raw,adapter.digest(raw))
    def test_exact_thirty_domains_include_owning_graph_and_native_fee_ledger(self):
        self.assertEqual(30,len(self.parse()))
        self.assertTrue({'wallet_changeset','fee_allowance_policy','fee_allowance_candidate'}<=set(self.parse()))
    def test_honest_psql_do_tag_preserved_while_unknown_tags_refuse(self):
        raw=self.raw().replace(b'SET\n',b'SET\nDO\n',1)
        self.assertEqual(30,len(adapter.native_tables(raw,adapter.digest(raw))))
        for tag in (b'UPDATE 1',b'DO\nDO',b'ROLLBACK'):
            changed=raw.replace(b'\nDO\n',b'\n'+tag+b'\n')
            with self.subTest(tag=tag),self.assertRaisesRegex(ValueError,'framing'):
                adapter.native_tables(changed,adapter.digest(changed))
    def test_literal_native_cli_wrapper_is_not_relabelled_or_complete_flag_authority(self):
        value={'rounds':{'wallet':'rounds','utxos':[]},'watchman':None,'complete':False}
        raw=canonical(value).encode()
        self.assertEqual(value['rounds'],adapter.native_wallet(raw,'rounds'))
        self.assertEqual(raw,canonical(value).encode())
        for wallet in ('watchman','unknown'):
            with self.assertRaises(ValueError):adapter.native_wallet(raw,wallet)
        with self.assertRaisesRegex(ValueError,'unavailable'):adapter.native_wallet(canonical(value['rounds']).encode(),'rounds')
    def test_missing_table_or_truncated_rows_do_not_mean_empty(self):
        del self.source['tables']['wallet_changeset']
        with self.assertRaisesRegex(ValueError,'all named'):self.parse()
        self.setUp();self.source['tables']['vtxo']['count']=1
        with self.assertRaisesRegex(ValueError,'coverage'):self.parse()
    def test_unknown_round_pool_conditional_work_holds_without_overwriting(self):
        for name in ('pending_board','round','vtxo_pool','htlc_vtxo','nursery_tx','recovery_capital_release'):
            self.setUp();self.source['tables'][name]={'count':1,'rows':[{'id':'unsupported'}]}
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'own resolver'):self.parse()
    def test_hash_tamper_duplicate_keys_and_writable_cut_refuse(self):
        raw=self.raw()
        with self.assertRaisesRegex(ValueError,'hash'):adapter.native_tables(raw,b'wrong')
        duplicate=raw.replace(b'"read_only":"on"',b'"read_only":"on","read_only":"on"')
        with self.assertRaisesRegex(ValueError,'duplicate'):adapter.native_tables(duplicate,adapter.digest(duplicate))
        self.source['read_only']='off'
        with self.assertRaisesRegex(ValueError,'all named'):self.parse()


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name),'source-controls',10000)
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def event(self,kind,value):
        self.store.event(kind,value)
        return self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]


class MoneyTests(StoreTests):
    def setUp(self):
        super().setUp();self.txid='a'*64
        self.cost={'monetary_id':'miner:'+self.txid,'kind':'miner_cost','txid':self.txid,'amount_msat':1030000,
            'budget':'ordinary','source':'rounds','destination':'miners','financial_pins':PINS}
        self.cost_seq=self.event('financial_cost_verified',self.cost)
        self.flow={'monetary_id':'injection:'+'b'*64+':0','kind':'injection','outpoint':'b'*64+':0',
            'amount_msat':200000000,'script':'51','original_declaration_sha256':'c'*64,'source':'owner','destination':'bank'}
        self.flow_seq=self.event('treasury_flow_verified',self.flow)
        self.source={'flow_sequences':[self.flow_seq],'cost_sequences':[self.cost_seq],
            'injection_declaration_hashes':['c'*64],'financial_pins':PINS,'boundary_id':'test','height':100,'tip_hash':'tip'}
        self.boundary={'id':'test','pins':PINS}
        class Chain:
            def transaction(inner,txid):return {'txid':txid,'confirmations':1,'fee_sat':1030}
            def tx(inner,txid):return {'txid':txid,'confirmations':1,'vout':[{'n':0,'value':Decimal('.002'),'scriptPubKey':{'hex':'51'}}]}
        self.chain=Chain()
        self.ownership=patch('simulator.normal_funding_ownership.verify_funding_ownership',return_value={'verified_flow_records':{self.flow['monetary_id']:self.flow}})
        self.ownership.start();self.addCleanup(self.ownership.stop)
    def test_historical_or_current_funding_labels_without_actual_rejoin_always_hold(self):
        for kind in ('injection',):
            original=self.store.db.execute('SELECT payload FROM event WHERE sequence=?',(self.flow_seq,)).fetchone()[0]
            with self.subTest(kind=kind),self.assertRaisesRegex(ValueError,'ownership rejoin'):
                adapter.verified_money(self.store,self.chain,self.source)
            self.assertEqual(original,self.store.db.execute('SELECT payload FROM event WHERE sequence=?',(self.flow_seq,)).fetchone()[0])
        proof={'preserved_history_opening':{'historical_cost_sequences':[self.cost_seq],'historical_flow_sequences':[self.flow_seq]}}
        sequence=self.event('financial_operating_readiness',proof)
        with self.assertRaisesRegex(ValueError,'ownership rejoin'):
            adapter.verified_money(self.store,self.chain,self.source,opening={'declaration':{'readiness_sequence':sequence}})
        with patch('simulator.normal_funding_ownership.verify_funding_ownership',self.ownership.temp_original),self.assertRaises((TypeError,ValueError)):
            adapter.verified_money(self.store,self.chain,self.source,funding_context={'verified':True})
        internal={**self.flow,'monetary_id':'internal:detached','kind':'internal_transfer','source':'bank','destination':'client'}
        sequence=self.event('treasury_flow_verified',internal)
        with self.assertRaisesRegex(ValueError,'ownership rejoin'):
            adapter.verified_money(self.store,self.chain,{**self.source,'flow_sequences':[self.flow_seq,sequence]})
    def test_original_sweep_is_once_only_cost_not_another_injection(self):
        flows,costs=adapter.verified_money(self.store,self.chain,self.source,funding_context={'qualification_sequence':1,'packages':{}},boundary=self.boundary)
        self.assertEqual(2,len(flows));self.assertEqual(1030000,costs[self.txid]['amount_msat'])
    def test_omitted_original_or_duplicate_monetary_id_refuses(self):
        self.source['cost_sequences']=[]
        with self.assertRaisesRegex(ValueError,'exhaustive'):adapter.verified_money(self.store,self.chain,self.source,funding_context={'qualification_sequence':1,'packages':{}},boundary=self.boundary)
        self.source['cost_sequences']=[self.cost_seq,self.event('financial_cost_verified',self.cost)]
        with self.assertRaisesRegex(ValueError,'twice'):adapter.verified_money(self.store,self.chain,self.source,funding_context={'qualification_sequence':1,'packages':{}},boundary=self.boundary)
    def test_service_charge_cannot_replace_actual_external_miner_fee(self):
        self.chain.transaction=lambda txid:{'txid':txid,'confirmations':1,'fee_sat':1360}
        with self.assertRaisesRegex(ValueError,'miner cost'):adapter.verified_money(self.store,self.chain,self.source,funding_context={'qualification_sequence':1,'packages':{}},boundary=self.boundary)
    def test_spent_injection_is_proved_by_original_tx_not_gettxout(self):
        self.chain.call=lambda *a:(_ for _ in ()).throw(AssertionError('not used for historical injection'))
        flows,_=adapter.verified_money(self.store,self.chain,self.source,funding_context={'qualification_sequence':1,'packages':{}},boundary=self.boundary)
        self.assertEqual(200000000,next(v for v in flows if v['kind']=='injection')['amount_msat'])
    def test_recorded_opening_old_costs_skip_new_edge_without_removing_history(self):
        proof={'preserved_history_opening':{'historical_cost_sequences':[self.cost_seq],'historical_flow_sequences':[self.flow_seq]}}
        seq=self.event('financial_operating_readiness',proof)
        flows,costs=adapter.verified_money(self.store,self.chain,self.source,opening={'declaration':{'readiness_sequence':seq}},funding_context={'qualification_sequence':1,'packages':{}},boundary=self.boundary)
        self.assertEqual([],flows);self.assertEqual(1030000,costs[self.txid]['amount_msat'])
        self.assertEqual(1,self.store.db.execute("SELECT count(*) FROM event WHERE kind='financial_cost_verified'").fetchone()[0])
    def test_wrong_injection_amount_unconfirmed_or_missing_declaration_refuses(self):
        for change in ('amount','confirmation','declaration'):
            with self.subTest(change=change):
                old=copy.deepcopy(self.source);original=self.chain.tx
                if change=='declaration':self.source['injection_declaration_hashes']=[]
                elif change=='confirmation':self.chain.tx=lambda txid:{**original(txid),'confirmations':0}
                else:self.chain.tx=lambda txid:{**original(txid),'vout':[{'n':0,'value':Decimal('.003'),'scriptPubKey':{'hex':'51'}}]}
                with self.assertRaisesRegex(ValueError,'injection'):adapter.verified_money(self.store,self.chain,self.source,funding_context={'qualification_sequence':1,'packages':{}},boundary=self.boundary)
                self.source=old;self.chain.tx=original


class ReservationTests(unittest.TestCase):
    def setUp(self):
        self.raw=transaction('a'*64+':0',1000,True)
        self.txid=adapter.decode_transaction(self.raw.hex())['txid']
        self.row={'candidate_bytes_hex':canonical({'raw':list(self.raw)}).encode().hex(),'fee_sat':1030,'urgent':False}
        self.tables={'fee_allowance_candidate':[self.row]}
        self.fee={'ordinary_booked_sat':1030,'urgent_booked_sat':0}
        class Chain:
            def tx(inner,txid):return {'txid':txid,'confirmations':2,'hex':self.raw.hex()}
        self.chain=Chain();self.costs={self.txid:{'amount_msat':1030000,'budget':'ordinary'}}
    def test_confirmed_import_has_zero_unpaid_exposure_and_stays_booked(self):
        held,_=adapter.native_fee_exposure(self.tables,self.fee,self.chain,self.costs)
        self.assertEqual({'ordinary':0,'urgent':0},held);self.assertEqual(1030,self.fee['ordinary_booked_sat'])
    def test_unconfirmed_reservation_is_exposure_not_miner_expense(self):
        self.chain.tx=lambda txid:{'txid':txid,'confirmations':0}
        held,_=adapter.native_fee_exposure(self.tables,self.fee,self.chain,{})
        self.assertEqual(1030000,held['ordinary'])
    def test_confirmed_carrier_missing_cost_or_wrong_class_refuses(self):
        for costs in ({},{self.txid:{'amount_msat':1030000,'budget':'urgent'}}):
            with self.assertRaisesRegex(ValueError,'once-only'):adapter.native_fee_exposure(self.tables,self.fee,self.chain,costs)


class OriginalAbsenceTests(unittest.TestCase):
    def setUp(self):
        from tests.test_core_rpc_error import CoreErrorTests
        self.fixture=CoreErrorTests();self.fixture.setUp()
    def tearDown(self):self.fixture.tearDown()
    def test_actual_matching_minus5_trace_preserves_signed_reservation_without_miner_payment(self):
        from tests.test_core_rpc_error import Response
        f=self.fixture
        with patch('simulator.chain.urllib.request.urlopen',return_value=Response(f.reply())):
            self.assertIsNone(adapter.transaction_or_absent(f.store,f.chain,f.txid))
    def test_other_backend_generic_missing_trace_and_wrong_response_id_stay_hold(self):
        from tests.test_core_rpc_error import Response
        f=self.fixture
        for reply in (f.reply(error={'code':-28}),f.reply(id=2)):
            with self.subTest(reply=reply),patch('simulator.chain.urllib.request.urlopen',return_value=Response(reply)):
                with self.assertRaises(ValueError):adapter.transaction_or_absent(f.store,f.chain,f.txid)
        f.chain.capture=None
        with patch('simulator.chain.urllib.request.urlopen',return_value=Response(f.reply())):
            with self.assertRaisesRegex(ValueError,'matching independent'):adapter.transaction_or_absent(f.store,f.chain,f.txid)
        with patch.object(f.chain,'tx',side_effect=ValueError('generic backend failure')):
            with self.assertRaisesRegex(ValueError,'generic backend'):adapter.transaction_or_absent(f.store,f.chain,f.txid)


class FeeCashTests(StoreTests):
    def setUp(self):
        super().setUp();self.points={'rounds':'a'*64+':0','watch':'b'*64+':0'};self.originals={};self.inventories={}
        self.members=[];self.assets={'assets':{}};self.source={'rounds_member_id':'rounds','watchman_member_id':'watch',
            'height':100,'tip_hash':'tip','inventory_source_sequences':{}}
        self.core={}
        for name,amount in [('rounds',254970),('watch',40000)]:
            point=self.points[name];self.members.append({'id':name,'kind':'wallet','role':'operator','identity':name,
                'descriptors':['wpkh(public)#fixture'],'verification_sequence':1})
            self.assets['assets'][point]={'member':name,'role':'operator','backing_outpoint':point,'amount_msat':amount*1000}
            row={'outpoint':point,'amount_sat':amount,'script':'51','descriptor_index':0,'child_index':0}
            self.inventories[name]=self.event('treasury_inventory',{'utxos':[row]})
            native={'outpoint':point,'value_sat':amount,'script_pubkey':'51','confirmed_fee_eligible':True,
                'trusted':True,'mature':True,'reserved':False,'confirmations':3}
            wallet={'network':'signet','tip_height':100,'tip_hash':'tip','pending_transactions':[],
                'unavailable_parent_txids':[],'reserved_outpoints':[],'utxos':[native],'min_trusted_confirmations':2}
            self.originals[name]={'reserved_outpoints':[],'wallet_inventory':wallet}
            self.core[point]={'bestblock':'tip','confirmations':3,'coinbase':False,'value':Decimal(amount)/100000000,'scriptPubKey':{'hex':'51'}}
        self.boundary={'id':'boundary','genesis':SIGNET_GENESIS,'pins':PINS,'members':self.members,'excluded':[]}
        self.envelope={'fee_assets':list(self.points.values())};self.tables={'recovery_source_hold':[{'held_sat':56000}],
            'recovery_reserve':[{'fee_headroom_sat':20000}],'fee_allowance_candidate':[]}
        self.fee={'reserved_urgent_prevouts':[],'urgent_required_confirmed_sat':40000}
        self.recovered={'source_holds_sat':56000,'fee_headroom_sat':20000}
        class Chain:
            def call(inner,method,*args):
                self.assertEqual('gettxout',method);self.assertIs(True,args[2]);return self.core.get(args[0]+':'+str(args[1]))
        self.chain=Chain()
    def calculate(self):
        for name,source in self.originals.items():self.source['inventory_source_sequences'][name]=self.event('treasury_native_inventory_source',source)
        return adapter.fee_cash(self.store,self.boundary,self.envelope,self.assets,self.source,self.inventories,
            self.tables,self.fee,self.recovered,None,self.chain)
    def test_r_plus_f_subtracted_once_not_customer_principal_twice(self):
        self.assertEqual((254970+40000-56000-20000)*1000,self.calculate())
    def test_reserved_prevout_is_never_available_cash(self):
        self.fee['reserved_urgent_prevouts']=[self.points['watch']]
        with self.assertRaisesRegex(ValueError,'watch liquidity'):self.calculate()
    def test_ordinary_signed_candidate_input_is_also_unavailable_not_just_urgent(self):
        raw=transaction(self.points['watch'],39000,True)
        self.tables['fee_allowance_candidate']=[{'candidate_bytes_hex':canonical({'raw':list(raw)}).encode().hex()}]
        with self.assertRaisesRegex(ValueError,'watch liquidity'):self.calculate()
    def test_native_untrusted_unknown_or_immature_cash_cannot_fund_policy(self):
        for field in ('trusted','confirmed_fee_eligible','mature'):
            old=self.originals['watch']['wallet_inventory']['utxos'][0][field]
            self.originals['watch']['wallet_inventory']['utxos'][0][field]=False
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'watch liquidity'):self.calculate()
            self.originals['watch']['wallet_inventory']['utxos'][0][field]=old
        self.core[self.points['watch']]['coinbase']=True
        with self.assertRaisesRegex(ValueError,'unreserved fee cash'):self.calculate()
    def test_literal_membership_omission_tip_race_and_pending_refuse(self):
        for field,value in [('utxos',[]),('tip_hash','other'),('pending_transactions',['pending'])]:
            wallet=self.originals['watch']['wallet_inventory'];old=wallet[field];wallet[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.calculate()
            wallet[field]=old
    def test_cash_below_full_native_r_plus_f_cannot_claim_collateralized(self):
        self.tables['recovery_source_hold'][0]['held_sat']=254970
        with self.assertRaisesRegex(ValueError,'native R\\+F'):self.calculate()


class PrivateToolTests(unittest.TestCase):
    def test_actual_timeout_keeps_private_originals_and_no_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent=Path(tmp);binary=parent/'tool';binary.write_bytes(b'fixture binary identity')
            tool={'command':[str(binary)],'sha256':adapter.digest(binary.read_bytes()),'evidence_directory':str(parent)}
            with patch('simulator.two_step_normal.subprocess.run',side_effect=subprocess.TimeoutExpired([str(binary)],12,output=b'partial',stderr=b'refused')):
                with self.assertRaisesRegex(ValueError,'timed out'):adapter.run_proof(tool,{'signed_vtxo':'opaque fixture'})
            directory=next(path for path in parent.iterdir() if path.is_dir())
            self.assertEqual(b'partial',(directory/'stdout').read_bytes());self.assertEqual(b'refused',(directory/'stderr').read_bytes())
            self.assertTrue(all(path.stat().st_mode&0o777==0o600 for path in directory.iterdir()))
    def test_retained_history_byte_hash_changes_without_exposing_transaction(self):
        value={'root_identity':'1:2','identity_bytes':b'policy','index_bytes':b'index\n','candidates':{'a'*64:b'private signed bytes'}}
        before=adapter.private_history_hash(value);value['candidates']['a'*64]+=b'!'
        self.assertNotEqual(before,adapter.private_history_hash(value))


class FreshBackingTests(unittest.TestCase):
    def setUp(self):
        self.raw=transaction('f'*64+':0',28000,True);self.txid=adapter.decode_transaction(self.raw.hex())['txid'];self.point=self.txid+':0'
        self.claim={'coin_id':'a'*64+':0','chain_anchor':self.point,'amount_sat':27670,'anchor_raw_sha256':adapter.digest(self.raw)}
        root={'vtxo_id':self.point,'policy_type':'expiry','anchor_point':self.point,'server_pubkey':'server','amount':28000,
            'onchain_spent_txid':None,'oor_spent_txid':None,'spent_in_round':None,'offboarded_in':None}
        self.root=root;self.leaf={**root,'vtxo_id':self.claim['coin_id'],'policy_type':'pubkey','amount':27670}
        self.tables={'vtxo':[root,self.leaf]}
        self.coin={'confirmations':3,'value':Decimal('.00028'),'scriptPubKey':{'hex':'51'}}
        self.tx={'hex':self.raw.hex(),'confirmations':3,'blockhash':'block98'}
        class Chain:
            def tx(inner,txid):return self.tx
            def call(inner,method,*args):return self.coin if method=='gettxout' else 'block98'
        self.chain=Chain()
    def verify(self,claims=None):return adapter.verify_fresh_backing(claims or [self.claim],self.tables,self.chain,height=100,server_pubkey='server')
    def test_unique_unspent_root_covers_authentic_ordinary_principal(self):
        self.assertEqual({self.point:{'root_sat':28000,'claim_sat':27670}},self.verify())
    def test_two_claims_cannot_duplicate_one_physical_backing_capacity(self):
        other={**self.claim,'coin_id':'b'*64+':0'};self.tables['vtxo'].append({**self.leaf,'vtxo_id':other['coin_id']})
        with self.assertRaisesRegex(ValueError,'exceed unique'):self.verify([self.claim,other])
    def test_spent_root_unconfirmed_body_or_wrong_native_full_anchor_holds(self):
        self.root['onchain_spent_txid']='foreign'
        with self.assertRaisesRegex(ValueError,'disposition'):self.verify()
        self.root['onchain_spent_txid']=None;self.tx['confirmations']=2
        with self.assertRaisesRegex(ValueError,'confirmed'):self.verify()
        self.tx['confirmations']=3;self.claim['anchor_raw_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'confirmed'):self.verify()


class AdmissionTests(StoreTests):
    async def capture(self,*args):raise AssertionError('not used in source admission control')
    def setUp(self):
        super().setUp();self.tools={name:{'command':['/not-run/'+name],'sha256':character*64}
            for name,character in [('policy','a'),('binding','b')]}
        self.collector=adapter.Collector(self.capture,1,self.tools)
        from simulator.financial_components import inspect as inspect_components
        self.value={'financial_pins':PINS,'component_sha256':{'adapter':adapter.digest(Path(adapter.__file__).read_bytes()),
            'capture':adapter.module_hash(self.capture),'native_fee':adapter.module_hash(adapter.verify_native_fee_epoch),
            'recovered_backing':adapter.module_hash(adapter.bind_native_claim),
            'money_sources':adapter.module_hash(adapter.collect_money_sources),'money_join':adapter.module_hash(adapter.journal_money_sources),'deadline':adapter.module_hash(adapter.Deadline),'financial_components':adapter.module_hash(inspect_components)},
            'proof_tool_sha256':{name:tool['sha256'] for name,tool in self.tools.items()},
            'proof_commands_sha256':{name:adapter.digest(canonical(tool['command']).encode()) for name,tool in self.tools.items()}}
    def admit(self):self.collector.admission_sequence=self.event('normal_financial_collector_qualified',self.value)
    def test_actual_installed_components_and_tool_command_arguments_are_bound(self):
        self.admit();self.assertEqual(self.value,self.collector.admission(self.store,PINS))
        self.tools['policy']['command'].append('--foreign-source')
        with self.assertRaisesRegex(ValueError,'qualification'):self.collector.admission(self.store,PINS)
    def test_wrong_module_hash_wrong_profile_pins_or_supplied_flag_does_not_qualify(self):
        for change in ('hash','pins','flag'):
            original=copy.deepcopy(self.value)
            if change=='hash':self.value['component_sha256']['capture']='0'*64
            elif change=='pins':self.value['financial_pins']={**PINS,'sdk_commit':'e'*40}
            else:
                self.value['complete']=True;self.value['component_sha256']={}
            self.admit()
            with self.subTest(change=change),self.assertRaisesRegex(ValueError,'qualification'):self.collector.admission(self.store,PINS)
            self.value=original


class RecurringTests(unittest.IsolatedAsyncioTestCase):
    async def test_recorded_first_opening_is_used_without_requiring_closed_dispatch_again(self):
        from tests.test_financial_transition import FinancialTransitionTests
        fixture=FinancialTransitionTests();fixture.setUp()
        try:
            fixture.admit();fixture.store.db.execute("DELETE FROM meta WHERE key='paused'")
            async def capture(*args):raise AssertionError('not called by wrapper test')
            collector=adapter.Collector(capture,1,{})
            with patch.object(collector,'produce',AsyncMock(return_value=123)) as produce, \
                    patch('simulator.two_step_normal.history',side_effect=AssertionError('opening history must not rerun')):
                self.assertEqual(123,await collector(fixture.store,fixture.config,fixture.chain,{},{}))
            self.assertIsNotNone(produce.call_args.kwargs['opening']);fixture.store.verify_event_chain()
        finally:fixture.tearDown()

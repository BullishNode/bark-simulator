"""Synthetic original-event controls; no native/Core or live Board credit."""
import copy
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from simulator.engine import initialize
from simulator.first_board_readiness import (ACTORS,BALANCES,declare_first_board_plan,
    board_plan,validate_board_action_scope,verify_synced_cash_snapshots,record_first_board_readiness)
from simulator.model import canonical
from simulator.store import Store
from tests.test_final_campaign import PINS
from tests.owned_activity_fixture import receipt as activity_receipt


class FirstBoardControls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name),'synthetic-first-board',60000)
        initialize(self.store)
        bootstrap={'actors':ACTORS,'pins':PINS}
        self.store.db.execute("INSERT INTO meta VALUES ('zero_principal_identity_bootstrap',?)",(canonical(bootstrap),))
        self.event('identity_bootstrap_declared',{'declaration':bootstrap})
        self.store.db.execute("INSERT INTO meta VALUES ('paused','declare')")
        self.plan={'id':'first','pins':PINS,'boundary_id':'finite','board_actions':{actor:'first-'+actor for actor in ACTORS},
            'amount_sat':20000,'maximum_fee_sat':4000}
        declare_first_board_plan(self.store,self.plan)
        self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        self.scope={'financial_pins':PINS,'boundary_id':'finite','operation_scope':['board'],
            'board_action_scope':{'plan_id':'first','action_id':'first-actor-01','actor':'actor-01',
                'operation':'board','args':{'amount_sat':20000},'maximum_fee_sat':4000}}
        self.tip='a'*64;self.source={'financial_pins':PINS,'boundary_id':'finite','height':100,'tip_hash':self.tip,
            'funding_confirmation_sequence':self.event('fixture_funding_confirmed',{'synthetic':True}),
            'members':[],'inventory_sequences':{}}
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def event(self,kind,payload):
        self.store.event(kind,payload)
        return self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
    def action(self,action_id,actor,operation,args,fee,state='dispatched',data=None):
        response={'action_id':action_id,'status':'ok','actual_fee_sat':0,'data':data or {}}
        now=time.time()
        self.store.db.execute('INSERT INTO action VALUES (?,?,NULL,?,?,?,?,?,?,?, ?,?)',
            (action_id,actor,operation,canonical(args),state,now,fee,0 if state=='completed' else None,
                canonical(response) if state=='completed' else None,now,now))
        self.event('action_intent',{'action_id':action_id,'actor':actor,'operation':operation,'args':args,
            'fee_reservation_sat':fee,'financial_pins':PINS})
        self.event('action_dispatched',{'action_id':action_id,'actor':actor,'financial_pins':PINS})
        if state=='completed':self.event('driver_response',{'action_id':action_id,'response':response})
        return response
    def check(self,proof=None,action=None,operation='board',fee=4000):
        return validate_board_action_scope(self.store,self.scope if proof is None else proof,
            operation=operation,maximum_fee_sat=fee,reserved_action_id=action)
    def native_snapshots(self):
        for index,actor in enumerate(ACTORS):
            point=str(index)*64+':0';script='script-'+actor
            self.source['members'].append({'id':actor,'descriptors':['desc-'+actor]})
            self.source['inventory_sequences'][actor]=self.event('treasury_inventory',{
                'utxos':[{'outpoint':point,'amount_sat':50000,'script':script,'child_index':1}]})
            evidence={'coins':[],'movements':[]}
            self.action('sync-'+actor,actor,'sync',{},0,'completed',{
                'receive_count_before':0,'receive_count_after':0,'before_evidence':evidence,'evidence':evidence})
            self.action('snapshot-'+actor,actor,'snapshot',{},0,'completed',{
                'balance':{key:0 for key in BALANCES},'vtxos':[],'evidence':evidence,
                'onchain':{'total_sat':50000,'trusted_spendable_sat':50000,'immature_sat':0,
                    'trusted_pending_sat':0,'untrusted_pending_sat':0,'confirmed_sat':50000},
                'onchain_inventory':{'schema_version':1,'complete':True,'read_only':True,'network':'signet',
                    'tip_height':100,'tip_hash':self.tip,'descriptors':[{'descriptor':'desc-'+actor}],
                    'pending_transactions':[],'pending_parents':[],'unavailable_parent_txids':[],
                    'utxos':[{'outpoint':point,'value_sat':50000,'script_pubkey':script,'keychain':'external',
                        'derivation_index':1,'confirmations':1,'coinbase':False,'mature':True}]}})
        self.source['descriptor_ranges']=[{'desc':row['descriptors'][0],'range':[0,19]} for row in self.source['members']]
        self.source['mempool']=activity_receipt(self.store,self.source,'finite_fresh_cash')
        self.source['observed_at']=time.time()
    def test_plan_is_exact_immutable_and_before_any_intent(self):
        self.assertEqual(self.plan,board_plan(self.store));self.assertFalse(declare_first_board_plan(self.store,self.plan))
        changed=copy.deepcopy(self.plan);changed['maximum_fee_sat']=5000
        with self.assertRaises(ValueError):declare_first_board_plan(self.store,changed)
        changed=copy.deepcopy(self.plan);changed['board_actions']['actor-01']='changed'
        with self.assertRaisesRegex(ValueError,'immutable'):declare_first_board_plan(self.store,changed)
    def test_exact_first_action_and_probe_allowed(self):
        self.check();self.action('first-actor-01','actor-01','board',{'amount_sat':20000},4000)
        self.check(action='first-actor-01')
    def test_wrong_actor_id_amount_fee_or_scope_refuses(self):
        for field,value in [('actor','actor-02'),('action_id','new'),('args',{'amount_sat':20001}),('maximum_fee_sat',4001)]:
            proof=copy.deepcopy(self.scope);proof['board_action_scope'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.check(proof)
        for op in ('ordinary','sync','send_arkoor','funding'):
            with self.subTest(op=op),self.assertRaises(ValueError):self.check(operation=op)
    def test_terminal_unknown_and_second_board_refuse(self):
        self.action('first-actor-01','actor-01','board',{'amount_sat':20000},4000)
        for state in ('completed','outcome_unknown','blocked','failed'):
            self.store.db.execute('UPDATE action SET state=?',(state,))
            with self.subTest(state=state),self.assertRaises(ValueError):self.check(action='first-actor-01')
        self.store.db.execute("UPDATE action SET state='dispatched'")
        self.action('first-actor-02','actor-02','board',{'amount_sat':20000},4000,'queued')
        with self.assertRaisesRegex(ValueError,'one original'):self.check()
    def test_concurrent_zero_fee_action_and_mutated_original_intent_refuse(self):
        self.action('first-actor-01','actor-01','board',{'amount_sat':20000},4000)
        self.action('sync','actor-02','sync',{},0,'queued')
        with self.assertRaisesRegex(ValueError,'unresolved'):self.check(action='first-actor-01')
        self.store.db.execute("DELETE FROM action WHERE id='sync'")
        self.store.db.execute("UPDATE action SET actor_id='actor-02' WHERE id='first-actor-01'")
        with self.assertRaises(ValueError):self.check(action='first-actor-01')
    def test_all_three_actual_source_shaped_snapshots_match_independent_cash(self):
        self.native_snapshots();self.assertEqual(set(ACTORS),set(verify_synced_cash_snapshots(self.store,self.source)))
    def test_missing_sync_stale_native_graph_and_ark_balance_refuse(self):
        self.native_snapshots()
        changed=copy.deepcopy(self.source);changed['tip_hash']='b'*64
        with self.assertRaisesRegex(ValueError,'snapshot'):verify_synced_cash_snapshots(self.store,changed)
        self.store.db.execute("DELETE FROM action WHERE id='sync-actor-02'")
        with self.assertRaisesRegex(ValueError,'all three'):verify_synced_cash_snapshots(self.store,self.source)
    def test_changed_native_result_without_original_event_refuses(self):
        self.native_snapshots()
        row=self.store.db.execute("SELECT result FROM action WHERE id='snapshot-actor-01'").fetchone()
        value=json.loads(row[0]);value['data']['balance']['spendable_sat']=20000
        self.store.db.execute("UPDATE action SET result=? WHERE id='snapshot-actor-01'",(canonical(value),))
        with self.assertRaisesRegex(ValueError,'response differs'):verify_synced_cash_snapshots(self.store,self.source)
    def test_positive_first_board_producer_retains_honest_fee_policy(self):
        from types import SimpleNamespace
        from contextlib import ExitStack
        self.native_snapshots();source_sequence=self.event('finite_fresh_cash_sources_verified',self.source)
        runtime=self.event('owned_runtime_configuration_verified',{'observed_at':time.time(),
            'loaded_configuration_identity_verified':True,'current_source_sha256':'runtime-sha',
            'product_commit':PINS['product_commit'],'schema_sha256':PINS['schema_sha256']})
        cash={**self.scope,'operation_scope':['sync','snapshot','address'],'complete':True,'observed_at':time.time(),
            'finite_fresh_cash_source_sequence':source_sequence,'runtime_source_sequence':runtime,
            'available_fee_funding_msat':75000000,'client_action_scope':{},'estimated_fee_rate_sat_kvb':1001}
        del cash['board_action_scope'];cash_sequence=self.event('financial_operating_readiness',cash)
        class Chain:
            def call(self,*args):return {'feerate':'0.00001001'}
            def identity(inner):return {'initialblockdownload':False,'blocks':100,'bestblockhash':self.tip}
        with ExitStack() as stack:
            stack.enter_context(patch('simulator.runtime_startup._read',return_value=({},'runtime-sha')))
            stack.enter_context(patch('simulator.fresh_cash_readiness._phase_history'))
            stack.enter_context(patch('simulator.fresh_cash_readiness._confirmed_funding',return_value=(None,None,None,{'fee_sat':1000},self.source['funding_confirmation_sequence'])))
            stack.enter_context(patch('simulator.fresh_cash_readiness.observe_empty_client_economics',return_value=1))
            stack.enter_context(patch('simulator.treasury.capture_assets',return_value={'height':100,'tip_hash':self.tip,'total_msat':664454000}))
            stack.enter_context(patch('simulator.operating_limits.envelope',return_value={'fee_budgets_msat':{'ordinary':60000000,'urgent':15000000},'operation_fee_paths':{'board':['sweep','payout']}}))
            stack.enter_context(patch('simulator.operating_limits.fee_totals',return_value={'ordinary':1000000,'urgent':0}))
            result=record_first_board_readiness(self.store,SimpleNamespace(),Chain(),cash_readiness_sequence=cash_sequence,current_startup_path='synthetic',actor='actor-01')
            self.assertEqual(['board'],result['operation_scope']);self.assertNotIn('client_action_scope',result)
            self.assertFalse(result['board_fee_policy']['hard_client_rate_cap_enforced'])
            self.assertEqual(4000,result['board_fee_policy']['hard_total_fee_sat'])
            self.assertEqual(1001,result['board_fee_policy']['observed_rate_sat_kvb'])


"""Synthetic source/controller controls; never native or live qualification."""
import copy
import hashlib
import tempfile
import time
import unittest
from datetime import datetime,timezone
from pathlib import Path
from types import SimpleNamespace

from simulator import exploratory as e
from simulator.engine import initialize
from simulator.model import SIGNET_GENESIS,canonical
from simulator.store import Store
from tests.test_final_campaign import PINS
from tests.test_wallet_projection import Core,DESCRIPTOR,SCRIPTS,native_coin


class CanaryCore(Core):
    def transaction(self,txid):return {'fee_sat':500}
    def tx(self,txid):return {'vsize':100}
    def call(self,method,*args):
        if method=='estimatesmartfee':return {'feerate':'0.00011002'}
        return super().call(method,*args)
    def identity(self):return self.call('getblockchaininfo')


class ExploratoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name),'synthetic',10000,architecture_profile='two_step_per_key');initialize(self.store)
        self.store.db.execute("INSERT INTO meta VALUES ('paused','declare')")
        self.now=time.time();self.config=SimpleNamespace();self.chain=CanaryCore()
        self.d={'id':'fixture-thirty-minute','pins':PINS,'source_key':'a'*64,'configuration_sha256':'b'*64,
            'image_digest':'sha256:'+'c'*64,'container':'abandon-signet-fallback-fixture','server_pubkey':'02'+'3'*64,
            'actors':['actor-01','actor-02'],'started_at':self.now-1,'deadline':self.now+1799,
            'fee_ceiling_sat_kvb':5000,'per_action_fee_sat':1000,'fee_budget_sat':2000,
            'capital_budget_sat':200000,'maximum_client_principal_sat':60000,'minimum_fee_cash_sat':1000,
            'funding_txids':['a'*64],'raw_estimate_above_cap_policy':'nonurgent_capped_broadcast_pending_allowed','qualified_seconds':0,'ark_send_amount_sat':1000,'maximum_ark_transfers':1,'client_board_fee_ceiling_sat_kvb':12000,'board_amount_sat':28000,'binary_sha256':{'captaind':'e'*64,'watchmand':'f'*64},'recovery_sweep_script':'5120'+'1'*64}
        point='a'*64+':0';self.chain.coin('a'*64,0,100000,0,confirmations=2)
        row=native_coin(point,100000,0,confirmations=2)
        stamp=datetime.fromtimestamp(self.now-0.1,timezone.utc).isoformat()
        wallet={'complete':True,'network':'signet','tip_height':1000,'tip_hash':self.chain.tip,
            'public_descriptor':DESCRIPTOR,'min_trusted_confirmations':2,'unavailable_parent_txids':[],
            'utxos':[row],'pending_transactions':[],'reserved_outpoints':[]}
        self.p={'observed_at':stamp,'completed_at':stamp,'network':'signet','genesis':SIGNET_GENESIS,
            'source_key':self.d['source_key'],'config_sha256':self.d['configuration_sha256'],
            'binary_sha256':self.d['binary_sha256'],'client_verified_server_info':{'server_pubkey':self.d['server_pubkey'],'network':'signet','vtxo_lifetime':48},
            'recovery_reserve':{'id':'rounds','sweep_spk':self.d['recovery_sweep_script'],'fee_headroom_sat':20000,'held_sat':0,'unknown_gross':False,'checkpoint_height':1000,'checkpoint_hash':self.chain.tip},
            'container_runtime_stable':True,'container_inspect':{'Image':self.d['image_digest'],'Name':'/'+self.d['container'],
                'State':{'Running':True,'OOMKilled':False}},'stable_tip':True,
            'core_before':self.chain.identity(),'core_after':self.chain.identity(),
            'public_policy':{'vtxo_lifetime':48,'required_board_confirmations':3,'vtxo_exit_delta':12,
                'vtxopool':{'vtxo_targets':[]},'expiry_payout':{'enabled':False},
                'max_ln_send_amount':'0 sat','max_ln_receive_amount':'0 sat','max_offboard_amount':'0 sat',
                'fee_estimator':{'max_fee_rate':'5sat/vb'}},
            'postgres_count_snapshot':'REPEATABLE READ READ ONLY',
            'postgres_public_table_counts':{'tables':{**dict.fromkeys(e.ZERO_TABLES,0),'vtxo':0,'round':0,'pending_board':0,'virtual_transaction':0}},
            'postgres_financial_rows':{'conditional_count':0,'exit_count':0,'payout_count':0,'recovery_hold_sat':0,
                'earliest_expiry_height':None,'customer_principal_sat':0,'total_capital_exposure_sat':10000,'funding_txids':[]},
            'rounds_inventory':{'exit':0,'data':{'rounds':wallet}},
            'watchman_inventory':{'exit':0,'data':{'watchman':{**wallet,'utxos':[]}}}}
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def checked(self):return e.checked_source(self.d,self.p,self.chain,now=self.now)
    def test_real_scope_is_immutable_and_never_clears_financial_requirement(self):
        e.declare(self.store,self.d);self.assertEqual('true',self.store.get_meta('financial_qualification_required'))
        changed={**self.d,'deadline':self.d['deadline']-1}
        with self.assertRaisesRegex(ValueError,'immutable'):e.declare(self.store,changed)
        self.assertEqual('0',self.store.get_meta('qualified_campaign_active_seconds'))
    def test_two_actor_thirty_minute_bound_is_not_a_general_dispatch_permission(self):
        for change in [{'actors':['actor-01','actor-02','actor-04']},{'deadline':self.now+1801},{'qualified_seconds':1}]:
            with self.assertRaises(ValueError):e.declare(self.store,{**self.d,**change})
    def test_checked_nonurgent_policy_reports_high_estimate_without_claiming_global_completion(self):
        p=self.checked();self.assertTrue(p['estimate_warning']);self.assertFalse(p['global_complete']);self.assertEqual(0,p['qualified_seconds']);self.assertEqual(500,p['miner_fees_sat'])
    def test_missing_or_changed_source_policy_and_chain_are_holds(self):
        original=copy.deepcopy(self.p)
        for update in [{'config_sha256':'f'*64},{'stable_tip':False},{'source_key':'f'*64}]:
            self.p={**copy.deepcopy(original),**update}
            with self.assertRaises(ValueError):self.checked()
        self.p=original;self.p['public_policy']['required_board_confirmations']=1
        with self.assertRaises(ValueError):self.checked()
    def test_reservations_and_pending_inputs_are_not_spendable_fee_cash(self):
        self.p['rounds_inventory']['data']['rounds']['reserved_outpoints']=['a'*64+':0']
        with self.assertRaisesRegex(ValueError,'cash insufficient'):self.checked()
    def test_unknown_mempool_spend_and_foreign_script_are_not_zero_or_owned(self):
        saved=copy.deepcopy(self.chain.mempool_unspent);self.chain.mempool_unspent.clear()
        with self.assertRaisesRegex(ValueError,'unknown chain'):self.checked()
        self.chain.mempool_unspent=saved;self.p['rounds_inventory']['data']['rounds']['utxos'][0]['script_pubkey']='00'
        with self.assertRaises(ValueError):self.checked()
    def test_expiry_boundary_and_unobserved_hazard_are_holds(self):
        self.p['postgres_financial_rows']['earliest_expiry_height']=1030
        with self.assertRaisesRegex(ValueError,'thirty'):self.checked()
        self.p['postgres_financial_rows']['earliest_expiry_height']=1031
        self.checked();del self.p['postgres_public_table_counts']['tables']['htlc_vtxo']
        with self.assertRaisesRegex(ValueError,'unobserved'):self.checked()
    def test_actual_signed_carrier_fee_and_capital_budget_are_checked(self):
        self.chain.transaction=lambda txid:{'fee_sat':501}
        with self.assertRaisesRegex(ValueError,'signed carrier'):self.checked()
        self.chain.transaction=lambda txid:{'fee_sat':500}
        self.d['capital_budget_sat']=99999
        with self.assertRaisesRegex(ValueError,'capital'):self.checked()
    def test_forbidden_rails_and_stale_readiness_remain_blocked(self):
        e.declare(self.store,self.d);proof=self.checked();self.store.event('exploratory_operating_readiness',proof)
        seq=self.store.db.execute('SELECT MAX(sequence) FROM event').fetchone()[0]
        snap={'height':proof['height'],'tip_hash':proof['tip_hash'],'exploratory_readiness_sequence':seq}
        self.assertTrue(e.preflight(self.store,self.config,snap,operation='sync',now=self.now)['allowed'])
        for op in ['invoice','pay_invoice','exit','refresh','refresh_delegated','raw_protocol_d13']:
            with self.assertRaisesRegex(ValueError,'outside'):e.preflight(self.store,self.config,snap,operation=op,now=self.now)
        with self.assertRaises(ValueError):e.preflight(self.store,self.config,snap,operation='sync',now=self.now+91)

    def test_recovery_row_is_required_but_not_a_zero_table_assumption(self):
        self.p['postgres_public_table_counts']['tables']['recovery_reserve']=1
        self.checked()
        self.p['recovery_reserve']['unknown_gross']=True
        with self.assertRaisesRegex(ValueError,'recovery reserve'):self.checked()
    def test_queue_refuses_third_actor_and_wrong_recipient_before_writing_intent(self):
        e.declare(self.store,self.d)
        for actor,op,args in [('actor-04','board',{'amount_sat':30000}),('actor-01','send_arkoor',{'recipient_actor':'actor-04','destination':'foreign','amount_sat':1000})]:
            with self.assertRaises(ValueError):self.store.queue('refused-'+actor,actor,'H07',op,args,1000)
        self.assertEqual(0,self.store.db.execute('SELECT COUNT(*) FROM action').fetchone()[0])
    def test_actual_server_key_and_binary_override_are_holds(self):
        self.p['client_verified_server_info']['server_pubkey']='02'+'f'*64
        with self.assertRaisesRegex(ValueError,'server identity'):self.checked()
        self.p['client_verified_server_info']['server_pubkey']=self.d['server_pubkey']
        self.p['binary_sha256']={}
        with self.assertRaisesRegex(ValueError,'executable'):self.checked()

    def test_progression_cannot_be_used_for_a_board_or_urgent_operation(self):
        e.declare(self.store,self.d);proof=self.checked();self.store.event('exploratory_operating_readiness',proof)
        seq=self.store.db.execute('SELECT MAX(sequence) FROM event').fetchone()[0]
        snap={'height':proof['height'],'tip_hash':proof['tip_hash'],'exploratory_readiness_sequence':seq}
        self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        self.store.queue('board-01','actor-01','H01','board',{'amount_sat':28000},1000)
        with self.assertRaisesRegex(ValueError,'existing ordinary sync'):
            e.preflight(self.store,self.config,snap,operation='progression',maximum_fee_sat=1000,reserved_action_id='board-01',now=self.now)
    def test_completed_client_cost_keeps_its_original_whole_fee_hold(self):
        e.declare(self.store,self.d);proof=self.checked();self.store.event('exploratory_operating_readiness',proof)
        seq=self.store.db.execute('SELECT MAX(sequence) FROM event').fetchone()[0]
        snap={'height':proof['height'],'tip_hash':proof['tip_hash'],'exploratory_readiness_sequence':seq}
        self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        self.store.queue('paid-board','actor-01','H01','board',{'amount_sat':28000},1000)
        self.store.db.execute("UPDATE action SET state='completed',actual_fee_sat=800 WHERE id='paid-board'")
        self.store.queue('next-board','actor-02','H01','board',{'amount_sat':28000},1000)
        with self.assertRaisesRegex(ValueError,'canary fees exceed'):
            e.preflight(self.store,self.config,snap,operation='board',maximum_fee_sat=1000,reserved_action_id='next-board',now=self.now)

    def test_existing_positive_clock_is_preserved_when_exploratory_declaration_is_refused(self):
        self.store.db.execute("INSERT INTO meta VALUES ('qualified_campaign_active_seconds','17')")
        with self.assertRaisesRegex(ValueError,'preserve previous qualified clock'):e.declare(self.store,self.d)
        self.assertEqual('17',self.store.get_meta('qualified_campaign_active_seconds'))
        self.assertIsNone(self.store.get_meta(e.KEY))
    def test_arbitrary_board_amount_is_refused_before_intent(self):
        e.declare(self.store,self.d)
        with self.assertRaisesRegex(ValueError,'board amount'):
            self.store.queue('bad-board','actor-01','H01','board',{'amount_sat':30000},1000)
        self.assertEqual(0,self.store.db.execute('SELECT COUNT(*) FROM action').fetchone()[0])

    def test_explicit_absolute_board_policy_preserves_original_fee_and_server_rate_bounds(self):
        self.d['client_board_fee_ceiling_sat_kvb']=None
        e.declare(self.store,self.d)
        board='b'*64
        self.chain.transaction=lambda txid: {'fee_sat': 1500 if txid==board else 500}
        proposals={board:{'planned_mining_fee_sat':1500,'estimated_service_fee_sat':100,'maximum_fee_sat':1700}}
        self.d['per_action_fee_sat']=1700
        self.d['fee_budget_sat']=3000
        result=e.checked_source(self.d,self.p,self.chain,now=self.now,client_board_proposals=proposals)
        self.assertEqual(1500,result['client_board_miner_fees_sat'])
        for invalid in [dict(proposals[board],planned_mining_fee_sat=1499),dict(proposals[board],maximum_fee_sat=1599)]:
            with self.assertRaisesRegex(ValueError,'affordable proposal'):
                e.checked_source(self.d,self.p,self.chain,now=self.now,client_board_proposals={board:invalid})
        self.chain.transaction=lambda txid: {'fee_sat':1500 if txid==board else 501}
        with self.assertRaisesRegex(ValueError,'signed carrier'):
            e.checked_source(self.d,self.p,self.chain,now=self.now,client_board_proposals=proposals)

    def closure_snapshot(self):
        proof=self.checked();self.store.event('exploratory_operating_readiness',proof)
        return {'height':proof['height'],'tip_hash':proof['tip_hash'],
            'exploratory_readiness_sequence':self.store.db.execute('SELECT MAX(sequence) FROM event').fetchone()[0]}

    def test_append_only_closure_preserves_board_history_holds_and_final_gate(self):
        e.declare(self.store,self.d);self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        self.store.queue('original-board','actor-01','H01','board',{'amount_sat':28000},1000)
        self.store.db.execute("UPDATE action SET state='completed' WHERE id='original-board'")
        self.store.db.execute("INSERT INTO meta VALUES ('paused','review closure')")
        snap=self.closure_snapshot();original=self.store.get_meta(e.KEY)
        closed=e.close(self.store,snap,'original window complete',now=self.now)
        self.assertIsNone(e.scope(self.store));self.assertEqual(original,self.store.get_meta(e.KEY))
        self.assertEqual(1000,closed['retained_fee_holds_sat']);self.assertEqual(500,closed['remaining_fee_budget_sat'])
        self.assertEqual('true',self.store.get_meta('financial_qualification_required'))
        self.store.db.execute("INSERT INTO meta VALUES ('final_financial_epoch','{}')")
        self.assertIsNone(e.scope(self.store))
        self.assertEqual('completed',self.store.db.execute("SELECT state FROM action WHERE id='original-board'").fetchone()[0])
        self.assertEqual('0',self.store.get_meta('qualified_campaign_active_seconds'));self.store.verify_event_chain()

    def test_continuation_carries_counts_and_budgets_without_resetting_original(self):
        e.declare(self.store,self.d);self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        self.store.queue('original-board','actor-01','H01','board',{'amount_sat':28000},1000)
        self.store.db.execute("UPDATE action SET state='completed' WHERE id='original-board'")
        self.store.db.execute("INSERT INTO meta VALUES ('paused','review continuation')")
        original=self.store.get_meta(e.KEY);e.close(self.store,self.closure_snapshot(),'carry original liabilities',now=self.now)
        new={**self.d,'id':'fixture-continuation','started_at':self.now,'deadline':self.now+1800}
        self.assertTrue(e.continue_scope(self.store,new,now=self.now));self.assertEqual(new,e.scope(self.store))
        self.assertEqual(original,self.store.get_meta(e.KEY))
        with self.assertRaisesRegex(ValueError,'one original board'):
            e.admit(self.store,'actor-01','board',{'amount_sat':28000})
        self.assertEqual(1,self.store.db.execute('SELECT COUNT(*) FROM action').fetchone()[0]);self.store.verify_event_chain()

    def test_closure_and_continuation_refuse_unknown_stale_and_raised_capital(self):
        e.declare(self.store,self.d);self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        self.store.queue('unknown-board','actor-01','H01','board',{'amount_sat':28000},1000)
        self.store.db.execute("UPDATE action SET state='outcome_unknown' WHERE id='unknown-board'")
        self.store.db.execute("INSERT INTO meta VALUES ('paused','unknown preserved')")
        snap=self.closure_snapshot()
        with self.assertRaisesRegex(ValueError,'zero queued'):e.close(self.store,snap,'cannot discard unknown',now=self.now)
        self.assertIsNotNone(e.scope(self.store))
        self.store.db.execute("UPDATE action SET state='completed' WHERE id='unknown-board'")
        e.close(self.store,snap,'measured reconciliation fixture',now=self.now)
        new={**self.d,'id':'fixture-continuation','started_at':self.now,'deadline':self.now+1800}
        with self.assertRaisesRegex(ValueError,'cannot change'):
            e.continue_scope(self.store,{**new,'capital_budget_sat':300000},now=self.now)
        with self.assertRaisesRegex(ValueError,'fresh unchanged'):
            e.continue_scope(self.store,new,now=self.now+91)
        self.assertIsNone(e.scope(self.store))

    def test_continuation_never_discards_a_positive_clock_after_closure(self):
        e.declare(self.store,self.d);e.close(self.store,self.closure_snapshot(),'preserve counter',now=self.now)
        self.store.db.execute("UPDATE meta SET value='19' WHERE key='qualified_campaign_active_seconds'")
        with self.assertRaisesRegex(ValueError,'preserve unexpected positive'):
            e.continue_scope(self.store,{**self.d,'id':'fixture-continuation','started_at':self.now,'deadline':self.now+1800},now=self.now)
        self.assertEqual('19',self.store.get_meta('qualified_campaign_active_seconds'));self.assertIsNone(e.scope(self.store))

    def input_limit_transition(self):
        self.p['public_policy']['max_arkoor_amount']='10000 sat'
        e.declare(self.store,self.d)
        e.close(self.store,self.closure_snapshot(),'explicit reviewed input limit correction',now=self.now)
        after=copy.deepcopy(self.p);after['config_sha256']='d'*64;after['public_policy']['max_arkoor_amount']='30000 sat'
        new={**self.d,'id':'fixture-policy-correction','started_at':self.now,'deadline':self.now+1800,
            'configuration_sha256':'d'*64,'pins':{**self.d['pins'],'configuration_sha256':'d'*64}}
        return new,after

    def test_explicit_input_limit_correction_binds_actual_source_and_preserves_other_pins(self):
        new,after=self.input_limit_transition();original=self.store.get_meta(e.KEY)
        self.assertTrue(e.continue_scope(self.store,new,now=self.now,arkoor_input_limit_transition=(self.p,after,self.chain)))
        self.assertEqual(new,e.scope(self.store));self.assertEqual(original,self.store.get_meta(e.KEY))
        self.assertEqual(200000,e.scope(self.store)['capital_budget_sat'])
        self.assertEqual(1000,e.scope(self.store)['ark_send_amount_sat']);self.assertEqual('0',self.store.get_meta('qualified_campaign_active_seconds'))
        self.store.verify_event_chain()

    def test_input_limit_correction_cannot_change_sdk_budget_or_other_server_policy(self):
        new,after=self.input_limit_transition()
        for change in [{'capital_budget_sat':300000},{'pins':{**new['pins'],'sdk_commit':'f'*40}}]:
            with self.assertRaises(ValueError):e.continue_scope(self.store,{**new,**change},now=self.now,arkoor_input_limit_transition=(self.p,after,self.chain))
        for field,value in [('vtxo_lifetime',24),('max_arkoor_amount','40000 sat')]:
            altered=copy.deepcopy(after);altered['public_policy'][field]=value
            with self.assertRaises(ValueError):e.continue_scope(self.store,new,now=self.now,arkoor_input_limit_transition=(self.p,altered,self.chain))
        altered=copy.deepcopy(after);altered['binary_sha256']={}
        with self.assertRaisesRegex(ValueError,'executable'):e.continue_scope(self.store,new,now=self.now,arkoor_input_limit_transition=(self.p,altered,self.chain))
        self.assertIsNone(e.scope(self.store))

    def test_input_limit_correction_rejects_substituted_before_packet(self):
        new,after=self.input_limit_transition()
        substituted=copy.deepcopy(self.p);substituted['observed_at']='2000-01-01T00:00:00+00:00'
        original_events=self.store.db.execute('SELECT COUNT(*) FROM event').fetchone()[0]
        with self.assertRaisesRegex(ValueError,'before packet differs from original closure source'):
            e.continue_scope(self.store,new,now=self.now,arkoor_input_limit_transition=(substituted,after,self.chain))
        self.assertIsNone(e.scope(self.store))
        self.assertEqual(original_events,self.store.db.execute('SELECT COUNT(*) FROM event').fetchone()[0])
        self.assertEqual('0',self.store.get_meta('qualified_campaign_active_seconds'))

    def test_only_exact_input_limit_transition_can_use_fresh_after_with_historical_closure(self):
        new,after=self.input_limit_transition();later=self.now+120
        after['observed_at']=after['completed_at']=datetime.fromtimestamp(later,timezone.utc).isoformat()
        new={**new,'started_at':later,'deadline':later+1800}
        oldclosure=self.store.get_meta(e.KEY+':closed:'+hashlib.sha256(canonical(self.d).encode()).hexdigest())
        self.assertTrue(e.continue_scope(self.store,new,now=later,arkoor_input_limit_transition=(self.p,after,self.chain)))
        self.assertEqual(oldclosure,self.store.get_meta(e.KEY+':closed:'+hashlib.sha256(canonical(self.d).encode()).hexdigest()))
        self.assertEqual(new,e.scope(self.store))

    def test_input_limit_transition_refuses_stale_after_despite_bound_historical_closure(self):
        new,after=self.input_limit_transition();later=self.now+120
        new={**new,'started_at':later,'deadline':later+1800}
        with self.assertRaisesRegex(ValueError,'stale owning source'):
            e.continue_scope(self.store,new,now=later,arkoor_input_limit_transition=(self.p,after,self.chain))
        self.assertIsNone(e.scope(self.store))

"""Synthetic financial openings; no producer, native or live qualification."""
import copy
import json
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from simulator import exploratory
from simulator import financial_transition as transition
from simulator.model import SIGNET_GENESIS,canonical
from simulator.operating_limits import declare_envelope,fee_totals,preflight
from simulator.target_epochs import declare as declare_target,declaration_hashes
from simulator.treasury import declare_boundary
from tests import test_exploratory as exploratory_fixture
from tests.test_treasury import Chain
from tests.test_final_campaign import PINS


class FinancialTransitionTests(unittest.TestCase):
    def setUp(self):
        self.fixture=exploratory_fixture.ExploratoryTests();self.fixture.setUp();self.store=self.fixture.store
        exploratory.declare(self.store,self.fixture.d)
        self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        self.store.queue('old-address','actor-01','H01','address',{},0)
        self.store.claim({'address'});self.store.finish('old-address','completed',{'status':'ok','data':{}},0)
        self.store.db.execute("INSERT INTO meta VALUES ('paused','close old scope')")
        proof=self.fixture.checked();self.store.event('exploratory_operating_readiness',proof)
        seq=self.seq();exploratory.close(self.store,{'height':proof['height'],'tip_hash':proof['tip_hash'],'exploratory_readiness_sequence':seq},'retain original exploratory history')
        old={'network':'signet','genesis':SIGNET_GENESIS,'container':'fixture-captaind','image_digest':'sha256:'+'1'*64,'server_pubkey':'02'+'2'*64}
        self.store.bind_target(old);self.store.bind_wallet_root(Path(self.fixture.tmp.name)/'wallets')
        for a in ('actor-03','actor-09','actor-10'):self.store.set_online(a,False)
        declare_target(self.store,{'id':'new-target','previous_identity':old,'identity':{**old,'image_digest':'sha256:'+'3'*64},
            'observed_at':time.time(),'sdk_commit':PINS['sdk_commit'],
            'native_hashes':{'bark-sim-driver':PINS['driver_sha256'],'vtxo-proof':'4'*64,'seed-restore':'5'*64},
            'receipt_hashes':{k:'6'*64 for k in ('upgrade_completion','independent_identity','sdk_qualification','simulator_release','nursery_reconciliation')},
            'ordinary_lifetime_blocks':48,'pool_lifetime_blocks':48,'recovery_guard_verified':True,
            'pending_server_payouts_preserved':True,'declaration_hashes':declaration_hashes(self.store)})
        self.chain=Chain();self.chain.transaction=lambda txid:{'txid':txid,'confirmations':1,'fee_sat':1};member={'id':'rounds','kind':'wallet','role':'operator','identity':'fixture-wallet','descriptors':['wpkh(public-fixture)#checksum']}
        self.store.event('treasury_member_verified',{'member':member,'genesis':SIGNET_GENESIS,'financial_pins':PINS});member={**member,'verification_sequence':self.seq()}
        self.boundary={'id':'new-boundary','pins':PINS,'genesis':SIGNET_GENESIS,'members':[member],'excluded':['miners','outside']}
        self.store.event('treasury_inventory',{'member_id':'rounds','identity':member['identity'],'financial_pins':PINS,'height':100,'tip_hash':'tip','complete':True,
            'utxos':[{'outpoint':'a'*64+':0','amount_sat':1000,'script':'wallet-script','descriptor_index':0,'child_index':0}]});self.inventories={'rounds':self.seq()}
        self.store.event('financial_cost_verified',{'monetary_id':'miner:'+'b'*64,'kind':'miner_cost','txid':'b'*64,'amount_msat':1000,'financial_pins':{**PINS,'product_commit':'9'*40},'budget':'ordinary'});self.cost_seq=self.seq()
        self.store.event('treasury_flow_verified',{'monetary_id':'historical-injection','amount_msat':1000000});self.flow_seq=self.seq()
        self.config=SimpleNamespace(board_amount_sat=800,action_fee_reserve_sat=200)
        self.envelope={'id':'new-envelope','pins':PINS,'boundary_id':'new-boundary','capital_exposure_msat':2000000,
            'fee_budgets_msat':{'ordinary':500000,'urgent':300000},'fee_ceilings_sat_kvb':{'round':2000,'pool':2000,'sweep':2000,'payout':2000,'claim':4000,'progression':4000},
            'per_action_fee_sat':200,'grant_sat':1000,'board_sat':800,'board_fee_reserve_sat':200,'minimum_pool_sat':100,'minimum_channel_msat':100000,'fee_assets':['a'*64+':0']}
        self.historical=transition.history(self.store)
        self.readiness={'complete':True,'financial_pins':PINS,'boundary_id':'new-boundary','height':100,'tip_hash':'tip','observed_at':time.time(),
            'capital_exposure_msat':1000000,'available_fee_funding_msat':1000000,'estimated_fee_rate_sat_kvb':1000,
            'effective_fee_ceilings_sat_kvb':self.envelope['fee_ceilings_sat_kvb'],
            'preserved_history_opening':{'history':self.historical,'inventory_sequences':self.inventories,
                'retained_client_rights':[],'pending_liabilities':[],'historical_cost_sequences':[self.cost_seq],'historical_flow_sequences':[self.flow_seq]}}
        self.opening={'id':'first-normal-opening','pins':PINS,'target_epoch_id':'new-target','boundary_sha256':transition._digest(self.boundary),
            'envelope_sha256':transition._digest(self.envelope),'history':self.historical,'readiness_sequence':0,'new_client_fee_budget_sat':500}
        self.source()
    def tearDown(self):self.fixture.tearDown()
    def seq(self):return self.store.db.execute('SELECT MAX(sequence) FROM event').fetchone()[0]
    def source(self):
        self.store.event('financial_operating_readiness',self.readiness);self.opening['readiness_sequence']=self.seq()
    def validate(self):return transition.validate(self.store,self.opening,self.boundary,self.inventories,self.chain)
    def admit(self):
        declare_boundary(self.store,self.boundary,self.chain,opening=self.opening,inventory_sequences=self.inventories)
        declare_envelope(self.store,self.envelope,self.config,self.inventories,self.chain)
    def test_explicit_opening_preserves_actions_old_budget_old_scopes_and_zero_clock(self):
        actions=[dict(r) for r in self.store.db.execute('SELECT * FROM action')];meta=declaration_hashes(self.store)
        self.admit();self.assertEqual(actions,[dict(r) for r in self.store.db.execute('SELECT * FROM action')]);self.assertEqual(meta,declaration_hashes(self.store))
        self.assertEqual('10000',self.store.get_meta('fee_budget_sat'));self.assertEqual(500,self.store.remaining_fee_budget());self.assertEqual('0',self.store.get_meta('qualified_campaign_active_seconds'));self.store.verify_event_chain()
    def test_default_historical_guard_remains_without_explicit_opening(self):
        with self.assertRaisesRegex(ValueError,'before funding or dispatch'):declare_boundary(self.store,self.boundary,self.chain)
    def test_omitted_or_stale_normal_source_is_never_replaced_by_declaration(self):
        for change in ({'complete':False},{'observed_at':time.time()-91},{'financial_pins':{}},{'boundary_id':'other'}):
            original=copy.deepcopy(self.readiness);self.readiness.update(change);self.source()
            with self.assertRaisesRegex(ValueError,'normal opening source'):self.validate()
            self.readiness=original
    def test_exact_original_action_or_declaration_tamper_is_refused(self):
        for change in ({'action_rows_sha256':'0'*64},{'action_ids':[]},{'original_fee_budget_sat':20000}):
            original=copy.deepcopy(self.opening);self.opening['history'].update(change)
            with self.assertRaisesRegex(ValueError,'original history'):self.validate()
            self.opening=original
    def test_target_or_native_pin_substitution_is_refused(self):
        self.opening['target_epoch_id']='other'
        with self.assertRaisesRegex(ValueError,'target epoch'):self.validate()
        self.opening['target_epoch_id']='new-target';self.opening['pins']={**PINS,'driver_sha256':'f'*64};self.boundary['pins']=self.opening['pins'];self.opening['boundary_sha256']=transition._digest(self.boundary)
        with self.assertRaisesRegex(ValueError,'target epoch'):self.validate()
    def test_unknown_or_unresolved_original_cost_never_becomes_carry_in(self):
        for field,value in [('state','outcome_unknown'),('actual_fee_sat',None)]:
            self.store.db.execute('UPDATE action SET '+field+'=?',(value,))
            with self.assertRaisesRegex(ValueError,'original outcomes and costs'):self.validate()
            self.store.db.execute("UPDATE action SET state='completed',actual_fee_sat=0")
    def test_missing_liabilities_costs_or_flow_coverage_is_not_zero(self):
        for key in ('retained_client_rights','pending_liabilities','historical_cost_sequences','historical_flow_sequences'):
            original=copy.deepcopy(self.readiness);del self.readiness['preserved_history_opening'][key];self.source()
            with self.assertRaises(ValueError):self.validate()
            self.readiness=original
        for key in ('historical_cost_sequences','historical_flow_sequences'):
            self.readiness['preserved_history_opening'][key]=[];self.source()
            with self.assertRaisesRegex(ValueError,'cannot be omitted'):self.validate()
            self.readiness['preserved_history_opening'][key]=[self.cost_seq if 'cost' in key else self.flow_seq]
    def test_incomplete_asset_inventory_and_wrong_tip_are_refused(self):
        row=self.store.db.execute('SELECT payload FROM event WHERE sequence=?',(self.inventories['rounds'],)).fetchone();inventory=json.loads(row[0]);inventory['complete']=False
        self.store.event('treasury_inventory',inventory);self.inventories={'rounds':self.seq()};self.readiness['preserved_history_opening']['inventory_sequences']=self.inventories;self.source()
        with self.assertRaisesRegex(ValueError,'coverage'):self.validate()
    def test_new_client_budget_is_funded_by_new_envelope_and_cannot_use_urgent(self):
        self.opening['new_client_fee_budget_sat']=501
        declare_boundary(self.store,self.boundary,self.chain,opening=self.opening,inventory_sequences=self.inventories)
        with self.assertRaisesRegex(ValueError,'before funding'):declare_envelope(self.store,self.envelope,self.config,self.inventories,self.chain)
        with self.assertRaisesRegex(ValueError,'envelope has not been admitted'):self.store.remaining_fee_budget()
    def test_queue_uses_separate_remaining_budget_without_rewriting_legacy_limit(self):
        self.admit();self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        with self.assertRaisesRegex(ValueError,'fee budget exhausted'):self.store.queue('too-large','actor-01','H01','board',{},501)
        self.store.queue('new','actor-01','H01','board',{},500);self.assertEqual(0,self.store.remaining_fee_budget());self.assertEqual('10000',self.store.get_meta('fee_budget_sat'))
    def test_old_costs_remain_history_without_becoming_new_epoch_costs(self):
        self.admit();self.assertEqual({'ordinary':0,'urgent':0},fee_totals(self.store,PINS))
        self.store.event('financial_cost_verified',{'financial_pins':PINS,'monetary_id':'miner:'+'b'*64,'kind':'miner_cost','txid':'b'*64,'amount_msat':1000,'budget':'ordinary'})
        with self.assertRaisesRegex(Exception,'counted twice'):fee_totals(self.store,PINS)
    def test_opening_does_not_authorize_stale_or_absent_operating_readiness(self):
        self.admit()
        with self.assertRaisesRegex(ValueError,'readiness missing'):preflight(self.store,self.config,{'financial_pins':PINS})
    def test_changed_original_rows_or_old_declarations_block_after_opening(self):
        self.admit();self.store.db.execute("UPDATE action SET actual_fee_sat=1 WHERE id='old-address'")
        with self.assertRaisesRegex(ValueError,'action history changed'):self.store.remaining_fee_budget()
    def test_positive_historical_clock_or_new_epoch_cannot_be_reset(self):
        self.store.db.execute("UPDATE meta SET value='1' WHERE key='qualified_campaign_active_seconds'")
        with self.assertRaisesRegex(ValueError,'qualified time'):self.validate()
        self.assertEqual('1',self.store.get_meta('qualified_campaign_active_seconds'))

    def test_current_row_cannot_replace_the_original_terminal_result(self):
        self.store.db.execute("UPDATE action SET result='{}' WHERE id='old-address'")
        with self.assertRaisesRegex(ValueError,'preserved terminal'):self.validate()
    def test_wrong_historical_intent_is_not_a_valid_opening_snapshot(self):
        self.store.db.execute("UPDATE action SET fee_reservation_sat=1 WHERE id='old-address'")
        with self.assertRaisesRegex(Exception,'changed since authorization'):self.validate()

    def test_expired_native_spent_is_still_an_unpaid_customer_right(self):
        import hashlib
        key='02'+'7'*64;binding={'mailbox_pk':'fixture-mailbox','seq':1,'spk':'fixture-script','record_signature_valid':True,'key_link_signature_valid':True}
        proof={'id':'expired:0','amount_sat':1000,'user_pubkey':key,'binding':binding,'signed_path_valid':True}
        self.store.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',(key,'actor-01','fixture-mailbox',canonical(proof)))
        self.store.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',('expired:0',key,1000,hashlib.sha256(bytes.fromhex('aa')).hexdigest(),'aa',canonical(proof)))
        self.store.db.execute('INSERT INTO coin_observation VALUES (?,?,?,?)',('expired:0','old-address','Spent',time.time()))
        claims=transition._current_claims(self.store);self.assertEqual(1,len(claims));self.assertEqual(1000,claims[0]['amount_sat'])
        with self.assertRaisesRegex(ValueError,'historical rights'):self.validate()
    def test_one_msat_wrong_historical_miner_cost_cannot_be_carry_in(self):
        self.store.event('financial_cost_verified',{'monetary_id':'miner:'+'b'*64,'kind':'miner_cost','txid':'b'*64,'amount_msat':1001})
        self.readiness['preserved_history_opening']['historical_cost_sequences']=[self.seq()];self.source()
        with self.assertRaisesRegex(ValueError,'confirmed Core'):self.validate()

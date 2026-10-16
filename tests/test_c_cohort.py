"""Actual Store/immutable history/limits; native reducers are explicit stubs.

No native signature, live readiness, create, funding or campaign credit.
"""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from simulator import c_cohort as c,c_pilot
from simulator.architecture import DIRECT_PER_KEY
from simulator.model import canonical
from simulator.store import Store
from tests.test_c_pilot import pilot


class PreservedCohortControls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.wallet=self.root/'wallets';self.wallet.mkdir(mode=0o700)
        self.store=Store(self.root/'state','synthetic',60000,architecture_profile=DIRECT_PER_KEY)
        self.addCleanup(self.store.close);self.store.db.execute("INSERT OR REPLACE INTO meta VALUES ('paused','test')")
        self.pilot={**pilot(),'bank_opening_sat':900000};c_pilot.declare(self.store,self.pilot)
        self.pins=self.pilot['pins']
        self.bootstrap={'declaration':{'id':'original-two','actors':['actor-01','actor-02'],'pins':self.pins,'wallet_root':str(self.wallet)},'filesystem':__import__('simulator.identity_bootstrap',fromlist=['_root'])._root(str(self.wallet))}
        self.event('identity_bootstrap_declared',self.bootstrap)
        self.store.db.execute('INSERT INTO meta VALUES (?,?)',('zero_principal_identity_bootstrap',canonical(self.bootstrap['declaration'])))
        for actor,operation,fee in [('actor-01','create',0),('actor-02','create',0),('actor-01','board',530)]:
            self.store.actor(actor,'original')
            self.store.db.execute('INSERT INTO action VALUES (?,?,NULL,?,\'{}\',\'completed\',0,0,?,\'{}\',0,0)',(actor+'-'+operation,actor,operation,fee))
        self.event('financial_cost_verified',{'monetary_id':'funding-miner','financial_pins':self.pins,'budget':'ordinary','amount_msat':100000})
        self.event('financial_cost_verified',{'monetary_id':'board-miner','financial_pins':self.pins,'budget':'ordinary','amount_msat':200000,'action_id':'actor-01-board'})
        self.store.db.execute('CREATE TABLE funding_batch(id TEXT PRIMARY KEY,state TEXT,txid TEXT,raw_tx TEXT,fee_sat INTEGER)')
        self.store.db.execute("INSERT INTO funding_batch VALUES ('finite:original','confirmed',?,'00',100)",('a'*64,))
        self.outputs=[{'vout':0,'amount_sat':25000,'script':'0014'+'11'*20},{'vout':1,'amount_sat':100000,'script':'0014'+'22'*20}]
        self.inputs=[{'outpoint':'b'*64+':0'}]
        self.sequence=self.event('ordinary_arkoor_sources_verified',{'height':100,'tip_hash':'c'*64,'complete':True})
        self.journey={'sequence':self.event('ordinary_arkoor_journey_verified',{'synthetic':True}),'financial_pins':self.pins,'physical_total_sat':899700}
        self.origin={'funding_plan':{'id':'original','recipients':[{'member_id':'actor-01','amount_sat':25000},{'member_id':'watchman','amount_sat':100000}]},'funding_fee_sat':100,'mining_fee_sat':200,'funding_confirmation_sequence':1}
        outer=self
        class Core:
            def transaction(self,txid):return {'confirmations':3,'fee_sat':100,'outputs':copy.deepcopy(outer.outputs),'inputs':copy.deepcopy(outer.inputs)}
            def identity(self):return {'chain':'signet','initialblockdownload':False,'blocks':100,'bestblockhash':'c'*64}
        self.chain=Core()
        for path,value in [('simulator.ordinary_arkoor.record_ordinary_journey',self.journey),('simulator.board_adoption._origin',self.origin),('simulator.finite_funding._retained',{'outputs':self.outputs,'inputs':self.inputs})]:
            patch=mock.patch(path,return_value=value);patch.start();self.addCleanup(patch.stop)

    def event(self,kind,value):
        self.store.event(kind,value);return self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
    def record(self):return c.seal_pilot(self.store,None,self.chain,source_sequence=self.sequence)
    def profile(self):
        return {'id':'initial-then-ramp','seal_sequence':c.seal(self.store)['seal_sequence'],'pins':self.pins,
            'initial_actors':list(c.INITIAL),'ramp_actors':list(c.RAMP),'grant_sat':25000,
            'maximum_client_principal_sat':600000,'fee_budgets_sat':{'ordinary':60000,'urgent':40000},'capital_exposure_sat':900000}

    def test_seal_and_profile_preserve_original_actions_budgets_and_once_only_funding_credits(self):
        before_actions=[tuple(row) for row in self.store.db.execute('SELECT * FROM action')]
        before_pilot=self.store.get_meta(c_pilot.KEY)
        self.assertTrue(self.record());self.assertFalse(self.record())
        self.assertEqual({'ordinary':300000,'urgent':0},c.seal(self.store)['used_fees_msat'])
        value=self.profile();self.assertTrue(c.declare_profile(self.store,value));self.assertFalse(c.declare_profile(self.store,value))
        requirements=c.cohort_request(self.store,'initial')
        self.assertEqual(list(c.INITIAL[2:]),requirements['new_actors'])
        self.assertEqual(0,requirements['funding_requirements_sat']['actor-01'])
        self.assertEqual(25000,requirements['funding_requirements_sat']['actor-02'])
        self.assertEqual(275000,sum(requirements['funding_requirements_sat'].values()))
        self.assertEqual({'watchman':100000},requirements['retained_operator_credits_sat'])
        self.assertEqual(before_actions,[tuple(row) for row in self.store.db.execute('SELECT * FROM action')])
        self.assertEqual(before_pilot,self.store.get_meta(c_pilot.KEY))
        self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM event WHERE kind='financial_operating_readiness'").fetchone()[0])
        self.assertEqual(2,self.store.db.execute('SELECT count(*) FROM actor').fetchone()[0])

    def test_distinct_retained_watchman_outputs_sum_once_without_changing_grants(self):
        self.origin['funding_plan']['recipients']=[
            {'member_id':'actor-01','amount_sat':25000},
            {'member_id':'watchman','amount_sat':50000},
            {'member_id':'watchman','amount_sat':50000}]
        self.outputs[1]['amount_sat']=50000
        self.outputs.append({'vout':2,'amount_sat':50000,'script':'0014'+'33'*20})
        # Both independently decoded and Core-observed outputs retain their
        # distinct vout/script identity. Aggregation grants no additional value.
        with mock.patch('simulator.finite_funding._retained',return_value={
                'outputs':copy.deepcopy(self.outputs),'inputs':self.inputs}):
            self.assertTrue(self.record())
        original=c.seal(self.store)
        self.assertEqual({'actor-01':25000,'watchman':100000},original['funding_credits_sat'])
        c.declare_profile(self.store,self.profile())
        self.assertEqual(275000,sum(c.cohort_request(self.store,'initial')['funding_requirements_sat'].values()))
        self.assertEqual({'ordinary':300000,'urgent':0},original['used_fees_msat'])
        self.assertEqual(1,self.store.db.execute('SELECT count(*) FROM funding_batch').fetchone()[0])

    def test_split_funding_wrong_total_or_chain_output_gets_no_sealed_credit(self):
        self.origin['funding_plan']['recipients']=[
            {'member_id':'actor-01','amount_sat':25000},
            {'member_id':'watchman','amount_sat':50000},
            {'member_id':'watchman','amount_sat':50001}]
        with self.assertRaisesRegex(ValueError,'exact original'):self.record()
        self.assertIsNone(self.store.get_meta(c.SEAL_KEY))
        self.origin['funding_plan']['recipients'][-1]['amount_sat']=50000
        self.outputs[1]['amount_sat']=50000
        self.outputs.append({'vout':2,'amount_sat':50000,'script':'0014'+'33'*20})
        retained={'outputs':copy.deepcopy(self.outputs),'inputs':self.inputs}
        self.outputs[-1]['script']='0014'+'44'*20
        with mock.patch('simulator.finite_funding._retained',return_value=retained):
            with self.assertRaisesRegex(ValueError,'ancestry'):self.record()
        self.assertIsNone(self.store.get_meta(c.SEAL_KEY))

    def test_claimed_complete_source_never_substitutes_for_native_reducer(self):
        with mock.patch('simulator.ordinary_arkoor.record_ordinary_journey',side_effect=ValueError('missing native source')):
            with self.assertRaisesRegex(ValueError,'native source'):self.record()
        self.assertIsNone(self.store.get_meta(c.SEAL_KEY))

    def test_unknown_action_or_pending_funding_refuses_before_reducer(self):
        for table,query in [('action',"UPDATE action SET state='outcome_unknown' WHERE operation='create'"),('funding',"UPDATE funding_batch SET state='broadcasting'")]:
            with self.subTest(table=table),self.store.transaction():
                self.store.db.execute(query)
                with self.assertRaises(ValueError):self.record()
                if table=='action':self.store.db.execute("UPDATE action SET state='completed'")
                else:self.store.db.execute("UPDATE funding_batch SET state='confirmed'")
        self.assertIsNone(self.store.get_meta(c.SEAL_KEY))

    def test_original_action_root_bootstrap_or_event_mutation_refuses_after_seal(self):
        self.record()
        self.store.db.execute("UPDATE action SET result='{} ' WHERE id='actor-01-create'")
        with self.assertRaisesRegex(ValueError,'action'):c.seal(self.store)
        self.store.db.execute("UPDATE action SET result='{}' WHERE id='actor-01-create'")
        self.store.db.execute("UPDATE event SET payload='{}' WHERE sequence=?",(self.sequence,))
        with self.assertRaises(ValueError):c.seal(self.store)

    def test_wrong_actual_funding_amount_inputs_outputs_or_fee_get_no_credit(self):
        self.outputs[0]['amount_sat']=25001
        # Retained decode stub is independently frozen, actual Core differs.
        with mock.patch('simulator.finite_funding._retained',return_value={'outputs':[{'different':True}],'inputs':self.inputs}):
            with self.assertRaisesRegex(ValueError,'ancestry'):self.record()
        self.assertIsNone(self.store.get_meta(c.SEAL_KEY))

    def test_profile_cannot_change_fee_epoch_grant_quota_or_new_id_reset(self):
        self.record();value=self.profile();c.declare_profile(self.store,value)
        for changed in ({'id':'new-reset'},{'pins':{**self.pins,'sdk_commit':'f'*40}},
                        {'grant_sat':30000},{'fee_budgets_sat':{'ordinary':60001,'urgent':40000}},
                        {'initial_actors':list(c.INITIAL[1:])},{'maximum_client_principal_sat':600001}):
            with self.subTest(changed=changed),self.assertRaises(ValueError):c.declare_profile(self.store,{**value,**changed})

    def test_counter_alone_cannot_open_ramp_and_actual_interval_credit_is_required(self):
        self.record();value=self.profile();c.declare_profile(self.store,value)
        final={'id':'final','pins':self.pins,'started_at':1,'windows_seconds':{'ark':60,'internal_lightning':60,'external_lightning':60},'minimum_observations':{'ark':1,'internal_lightning':1,'external_lightning':1}}
        self.store.db.execute("INSERT INTO meta VALUES ('final_financial_epoch',?)",(canonical(final),))
        self.event('final_financial_epoch_declared',final)
        self.store.db.execute("INSERT INTO meta VALUES ('qualified_campaign_active_seconds','10800')")
        with self.assertRaisesRegex(ValueError,'credited'):c.cohort_request(self.store,'ramp')
        for total in range(180,10801,180):self.event('qualified_campaign_active_interval',{'seconds':180,'total_seconds':total})
        request=c.cohort_request(self.store,'ramp')
        self.assertEqual(list(c.RAMP),request['new_actors']);self.assertEqual(300000,sum(request['funding_requirements_sat'].values()))
        self.assertEqual(2,self.store.db.execute('SELECT count(*) FROM actor').fetchone()[0])
        self.assertEqual(1,self.store.db.execute('SELECT count(*) FROM funding_batch').fetchone()[0])


if __name__=='__main__':unittest.main()

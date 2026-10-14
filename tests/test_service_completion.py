"""Synthetic service-completion fixtures; funded ongoing operation can terminate qualification."""
import copy,time,unittest
from simulator.service_completion import declare_contract,evaluate
from simulator.final_campaign import declare_epoch
from tests import test_treasury as fixtures
from tests.test_final_campaign import PINS

class ServiceCompletionTests(fixtures.TreasuryFixture,unittest.TestCase):
    def setUp(self):
        super().setUp();self.now=time.time()
        self.contract={'pins':PINS,'requirements':[{'id':'H01','variant':'board/absent/paid','outcome':'paid','proof_kinds':['direct_payout_verified','seed_recovery_spend_verified']}],
            'ordinary_bounds':{kind:{'blocks':10,'seconds':3600} for kind in ('maturity','confirmation','recovery')}}
        declare_contract(self.store,self.contract)
        declare_epoch(self.store,{'id':'fixture-final','pins':PINS,'started_at':self.now-10,
            'windows_seconds':{'ark':600,'internal_lightning':600,'external_lightning':600},
            'minimum_observations':{'ark':1,'internal_lightning':1,'external_lightning':1}})
        self.proofs=[]
        for kind in ('direct_payout_verified','seed_recovery_spend_verified'):
            self.event(kind,{'financial_pins':PINS,'txid':'c'*64});self.proofs.append(self.sequence())
        self.event('finite_scenario_terminal',{'financial_pins':PINS,'id':'H01','variant':'board/absent/paid','outcome':'paid','evidence_sequences':self.proofs})
    def coverage(self,liabilities=None,**changes):
        proof={'financial_pins':PINS,'complete':True,'tip_hash':'tip','height':100,'observed_at':self.now,
            'unexplained_ids':[],'pending_actions':[],'inventory_sequences':{'rounds':self.inventory(self.wallet),'peer':self.inventory(self.peer)},'liabilities':liabilities or []}
        proof.update(changes);self.event('continuing_obligations_verified',proof)
        return {'financial_pins':PINS,'height':100,'tip_hash':'tip','continuing_obligations_sequence':self.sequence()}
    def obligation(self,**changes):
        value={'id':'next-expiry','owner':'customer-wallet','borrower':'rounds','amount_msat':500000,'state':'maturity',
            'created_height':95,'created_at':self.now-100,'deadline_height':105,'deadline_at':self.now+3500,
            'backing':[{'asset_id':'a'*64+':0','amount_msat':500000}]}
        value.update(changes);self.event('ordinary_liability_verified',{'financial_pins':PINS,'liability':value})
        return {**value,'verification_sequence':self.sequence()}
    def test_nonzero_funded_service_with_bounded_backed_liability_can_complete(self):
        result=evaluate(self.store,self.coverage([self.obligation()]),self.chain,now=self.now)
        self.assertTrue(result['complete']);self.assertEqual(500000,result['ordinary_liability_msat'])
        self.assertEqual(2500999,result['remaining_assets_msat'])
    def test_completed_scenario_without_required_recovery_proof_is_not_terminal(self):
        self.store.db.execute("DELETE FROM event WHERE kind='finite_scenario_terminal'")
        # Deleting events corrupts the hash chain; fixture appends a fresh terminal
        # intentionally lacking one required original proof and checks rejection.
        self.event('finite_scenario_terminal',{'financial_pins':PINS,'id':'H01','variant':'board/absent/paid','outcome':'paid','evidence_sequences':self.proofs[:1]})
        with self.assertRaisesRegex(ValueError,'missing required'):evaluate(self.store,self.coverage(),self.chain,now=self.now)
    def test_unknown_client_action_prevents_qualification(self):
        self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        self.store.add_snapshot({'observed_at':time.time(),'financial_pins':PINS})
        self.store.queue('unknown','actor-01','H01','board',{},0);self.store.claim({'board'})
        result=evaluate(self.store,self.coverage(),self.chain,now=self.now)
        self.assertFalse(result['complete']);self.assertIn('action',result['unknown_client_or_controller_actions'])
    def test_expired_unbounded_or_insufficiently_backed_liability_is_rejected(self):
        for changes in ({'deadline_height':99},{'deadline_at':self.now-1},{'deadline_height':106},{'amount_msat':500001}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                evaluate(self.store,self.coverage([self.obligation(**changes)]),self.chain,now=self.now)
    def test_same_asset_cannot_back_two_liabilities_beyond_its_value(self):
        first=self.obligation(amount_msat=600000,backing=[{'asset_id':'a'*64+':0','amount_msat':600000}])
        second=self.obligation(id='second',amount_msat=500000)
        with self.assertRaisesRegex(Exception,'overallocated'):
            evaluate(self.store,self.coverage([first,second]),self.chain,now=self.now)
    def test_unexplained_or_missing_coverage_is_never_treated_as_zero(self):
        with self.assertRaisesRegex(ValueError,'unexplained'):
            evaluate(self.store,self.coverage(unexplained_ids=['lost-coin']),self.chain,now=self.now)
        with self.assertRaisesRegex(ValueError,'missing'):
            evaluate(self.store,{'financial_pins':PINS},self.chain,now=self.now)
    def test_result_contract_cannot_be_changed_after_campaign(self):
        changed=copy.deepcopy(self.contract);changed['ordinary_bounds']['maturity']['blocks']=20
        with self.assertRaisesRegex(ValueError,'immutable'):declare_contract(self.store,changed)

    def test_identified_bounded_original_action_can_remain_in_flight(self):
        self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        self.store.add_snapshot({'observed_at':time.time(),'financial_pins':PINS})
        self.store.queue('continuing','actor-01','H01','board',{},0)
        intent=self.sequence();self.store.claim({'board'});dispatch=self.sequence()
        pending={'action_id':'continuing','intent_sequence':intent,'dispatch_sequence':dispatch,'deadline_at':self.now+100}
        result=evaluate(self.store,self.coverage(pending_actions=[pending]),self.chain,now=self.now)
        self.assertTrue(result['complete']);self.assertEqual(1,len(result['known_bounded_client_actions']))
        self.store.db.execute("UPDATE action SET state='outcome_unknown' WHERE id='continuing'")
        with self.assertRaisesRegex(ValueError,'continuing client action'):
            evaluate(self.store,self.coverage(pending_actions=[pending]),self.chain,now=self.now)

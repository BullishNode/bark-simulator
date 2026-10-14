"""Synthetic financial readiness checks; these fixtures earn no live pilot credit."""
import copy
import time,unittest
from types import SimpleNamespace
from simulator.operating_limits import declare_envelope,preflight
from tests.test_treasury import TreasuryFixture
from tests.test_final_campaign import PINS

class OperatingLimitsTests(TreasuryFixture,unittest.TestCase):
    def setUp(self):
        super().setUp();self.config=SimpleNamespace(board_amount_sat=800,action_fee_reserve_sat=200)
        self.limits={'id':'fixture-envelope','pins':PINS,'boundary_id':'fixture','capital_exposure_msat':3000000,
            'fee_budgets_msat':{'ordinary':500000,'urgent':500000},
            'fee_ceilings_sat_kvb':{'round':2000,'pool':2000,'sweep':2000,'payout':2000,'claim':4000,'progression':4000},
            'per_action_fee_sat':200,'grant_sat':1000,'board_sat':800,'board_fee_reserve_sat':200,
            'minimum_pool_sat':100,'minimum_channel_msat':100000,'fee_assets':['a'*64+':0']}
        self.inventories={'rounds':self.inventory(self.wallet),'peer':self.inventory(self.peer)}
        declare_envelope(self.store,self.limits,self.config,self.inventories,self.chain)
        self.snapshot={'financial_pins':PINS,'tip_hash':'tip','height':100}
    def readiness(self,**changes):
        proof={'financial_pins':PINS,'boundary_id':'fixture','tip_hash':'tip','height':100,'complete':True,
               'observed_at':time.time(),'effective_fee_ceilings_sat_kvb':self.limits['fee_ceilings_sat_kvb'],
               'capital_exposure_msat':2000000,'available_fee_funding_msat':1000000,'estimated_fee_rate_sat_kvb':1000}
        proof.update(changes);self.event('financial_operating_readiness',proof)
        return {**self.snapshot,'operating_readiness_sequence':self.sequence()}
    def test_8000_grant_cannot_fund_12000_board_default(self):
        value={**self.limits,'grant_sat':8000,'board_sat':12000,'board_fee_reserve_sat':2000}
        with self.assertRaisesRegex(ValueError,'grant cannot fund'):
            declare_envelope(self.store,value,SimpleNamespace(board_amount_sat=12000,action_fee_reserve_sat=2000),self.inventories,self.chain)
    def test_limits_missing_or_mismatched_actual_ceilings_block_before_pilot(self):
        with self.assertRaisesRegex(ValueError,'missing'):preflight(self.store,self.config,self.snapshot)
        with self.assertRaisesRegex(ValueError,'ceilings differ'):
            preflight(self.store,self.config,self.readiness(effective_fee_ceilings_sat_kvb={}))
    def test_fee_spike_holds_ordinary_but_separately_bounded_urgent_can_progress(self):
        snapshot=self.readiness(estimated_fee_rate_sat_kvb=3000)
        self.assertFalse(preflight(self.store,self.config,snapshot)['allowed'])
        self.assertTrue(preflight(self.store,self.config,snapshot,operation='claim',maximum_fee_sat=200)['allowed'])
        self.assertFalse(preflight(self.store,self.config,self.readiness(estimated_fee_rate_sat_kvb=5000),operation='progression')['allowed'])
    def test_positive_channel_and_pool_evidence_required_for_lightning(self):
        with self.assertRaisesRegex(ValueError,'declared treasury|positive actual'):
            preflight(self.store,self.config,self.readiness(),operation='invoice',amount_sat=100)
    def test_cumulative_fees_unique_and_per_action_funding_are_checked(self):
        self.event('financial_cost_verified',{'financial_pins':PINS,'monetary_id':'actual-miner-tx','amount_msat':450000,'budget':'ordinary'})
        with self.assertRaisesRegex(ValueError,'limit exhausted'):
            preflight(self.store,self.config,self.readiness(),maximum_fee_sat=100)
        with self.assertRaisesRegex(ValueError,'no longer backed'):
            preflight(self.store,self.config,self.readiness(available_fee_funding_msat=549999))
        self.event('financial_cost_verified',{'financial_pins':PINS,'monetary_id':'actual-miner-tx','amount_msat':450000,'budget':'ordinary'})
        with self.assertRaisesRegex(Exception,'counted twice'):preflight(self.store,self.config,self.readiness())
    def test_current_exposure_or_stale_readiness_never_authorize(self):
        with self.assertRaisesRegex(ValueError,'exposure exhausted'):
            preflight(self.store,self.config,self.readiness(capital_exposure_msat=3000001))
        with self.assertRaisesRegex(ValueError,'fresh'):
            preflight(self.store,self.config,self.readiness(observed_at=time.time()-91))
    def test_unconfirmed_or_customer_funds_cannot_back_fee_budget(self):
        changed=copy.deepcopy(self.limits);changed['fee_assets']=['b'*64+':0']
        with self.assertRaisesRegex(ValueError,'actual confirmed operator'):
            declare_envelope(self.store,changed,self.config,self.inventories,self.chain)

    def test_live_channel_from_undeclared_nodes_does_not_authorize_lightning(self):
        from simulator.model import SIGNET_GENESIS
        snapshot=self.readiness();stamp=time.time()
        snapshot.update({'identity':{'genesis':SIGNET_GENESIS,'server_pubkey':'02'+'2'*64},
            'capabilities':{'lightning_configured':True},
            'pool_status':{'schema_version':1,'complete':True,'stable_tip':True,'observed_at':stamp,
                'genesis':SIGNET_GENESIS,'server_pubkey':'02'+'2'*64,'height':100,'tip_hash':'tip',
                'pool_pre_expiry_blocks':3,'pool':{'minimum_eligible_expiry_height':106,'confirmed_eligible_count':2,'confirmed_eligible_amount_sat':1000}},
            'lightning':{}})
        for role,node,other in [('operator','foreign-operator','foreign-peer'),('fixture_peer','foreign-peer','foreign-operator')]:
            snapshot['lightning'][role]={'node_id':node,'fully_synced':True,'blockheight':100,
                'channels':[{'state':'CHANNELD_NORMAL','peer_id':other,'spendable_msat':1000000,'receivable_msat':1000000,
                    'channel_id':'foreign-channel','funding_txid':'c'*64,'funding_outnum':0}]}
        with self.assertRaisesRegex(ValueError,'declared treasury'):
            preflight(self.store,self.config,snapshot,operation='pay_invoice',amount_sat=100,maximum_fee_sat=200)

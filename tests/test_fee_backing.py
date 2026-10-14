"""Confirmed Ark backing is capital, not automatically liquid miner-fee funding."""
import tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from simulator.engine import initialize
from simulator.store import Store
from simulator.model import SIGNET_GENESIS
from simulator.treasury import declare_boundary
from simulator.operating_limits import declare_envelope
from tests.test_final_campaign import PINS
from tests.test_treasury import Chain
class LockedFeeBackingTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.s=Store(Path(self.tmp.name),'synthetic',10000);initialize(self.s)
  self.s.db.execute("INSERT INTO meta VALUES('paused','initial declaration')")
  self.chain=Chain();member={'id':'tree','kind':'ark_backing','role':'operator','identity':'known-server','descriptors':[]}
  self.s.event('treasury_member_verified',{'member':member,'genesis':SIGNET_GENESIS,'financial_pins':PINS})
  member['verification_sequence']=self.seq()
  declare_boundary(self.s,{'id':'fresh-tree-boundary','genesis':SIGNET_GENESIS,'pins':PINS,'members':[member],'excluded':['miners']},self.chain)
  self.s.event('treasury_backing_verified',{'outpoint':'a'*64+':0','script':'wallet-script','financial_pins':PINS,'inside_members':['tree'],'server_identity':'known-server'})
  proof=self.seq()
  self.s.event('treasury_inventory',{'member_id':'tree','identity':'known-server','financial_pins':PINS,'tip_hash':'tip','height':100,'complete':True,
   'utxos':[{'outpoint':'a'*64+':0','amount_sat':1000,'script':'wallet-script','verification_sequence':proof}]})
  self.inventory={'tree':self.seq()}
  self.config=SimpleNamespace(board_amount_sat=800,action_fee_reserve_sat=200)
  self.limits={'id':'fee-envelope','pins':PINS,'boundary_id':'fresh-tree-boundary','capital_exposure_msat':1000000,
   'fee_budgets_msat':{'ordinary':500000,'urgent':500000},
   'fee_ceilings_sat_kvb':{'round':2000,'pool':2000,'sweep':2000,'payout':2000,'claim':4000,'progression':4000},
   'per_action_fee_sat':200,'grant_sat':1000,'board_sat':800,'board_fee_reserve_sat':200,
   'minimum_pool_sat':100,'minimum_channel_msat':100000,'fee_assets':['a'*64+':0']}
 def seq(self):return self.s.db.execute('SELECT MAX(sequence) FROM event').fetchone()[0]
 def tearDown(self):self.s.close();self.tmp.cleanup()
 def test_confirmed_operator_tree_cannot_back_liquid_fee_budget(self):
  with self.assertRaisesRegex(ValueError,'fee funding'):
   declare_envelope(self.s,self.limits,self.config,self.inventory,self.chain)
  self.assertIsNone(self.s.get_meta('financial_operating_envelope'))

"""A partial bridge cannot be promoted into funded-operation permission."""
import json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock,patch
from simulator.engine import initialize
from simulator.financial_observer import collect_partial
from simulator.ownership import EvidenceGap
from simulator.store import Store
from simulator.model import SIGNET_GENESIS
class FinancialPartialTests(unittest.IsolatedAsyncioTestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.s=Store(Path(self.tmp.name),'synthetic',10000);initialize(self.s)
  self.config=SimpleNamespace(inventory_command=('bridge',),network='signet',expected_genesis=SIGNET_GENESIS)
  self.tip={'bestblockhash':'aa'*32,'blocks':100,'initialblockdownload':False};self.chain=SimpleNamespace(identity=lambda:self.tip)
  self.reply={'kind':'financial_readiness','network':'signet','genesis':SIGNET_GENESIS,'height':100,'tip_hash':'aa'*32,'stable_tip':True,
   'complete':False,'qualified':False,'gaps':['actual_input_lock_inventory','effective_runtime_path_caps'],
   'disk_config':{'captaind':{'max_fee_rate_sat_kvb':1000}},'effective_fee_ceilings_sat_kvb':None,'capital_exposure_msat':None}
 def tearDown(self):self.s.close();self.tmp.cleanup()
 async def collect(self):
  with patch('simulator.financial_observer.json_command',AsyncMock(return_value=self.reply)) as call:
   result=await collect_partial(self.s,self.config,self.chain)
  self.assertEqual({'kind':'financial_readiness'},call.call_args.args[1]);return result
 async def test_actual_partial_facts_and_gaps_are_retained_without_permission(self):
  self.assertTrue((await self.collect())['independent_same_tip'])
  self.assertEqual(0,self.s.db.execute("SELECT COUNT(*) FROM event WHERE kind IN ('financial_operating_readiness','treasury_inventory')").fetchone()[0])
  event=json.loads(self.s.db.execute("SELECT payload FROM event WHERE kind='financial_source_partial'").fetchone()[0])
  self.assertEqual(self.reply,event['response']);self.assertEqual(0,self.s.db.execute('SELECT COUNT(*) FROM action').fetchone()[0]);self.s.verify_event_chain()
 async def test_disk_estimator_cap_does_not_qualify_runtime_path_limits(self):
  self.reply.update(qualified=True,complete=True,gaps=[])
  with self.assertRaises(EvidenceGap):await self.collect()
 async def test_unstable_or_wrong_tip_is_preserved_but_not_verified(self):
  self.reply['tip_hash']='bb'*32
  result=await self.collect();self.assertFalse(result['qualified']);self.assertFalse(result['independent_same_tip'])
 async def test_foreign_network_or_secret_payload_is_refused(self):
  self.reply['genesis']='cc'*32
  with self.assertRaises(EvidenceGap):await self.collect()
  self.reply['genesis']=SIGNET_GENESIS;self.reply['private_key']='never-record-this'
  with self.assertRaises(ValueError):await self.collect()
  self.assertEqual(0,self.s.db.execute("SELECT COUNT(*) FROM event WHERE kind='financial_source_partial'").fetchone()[0])

import asyncio,json,tempfile,unittest
from pathlib import Path
from simulator.engine import initialize
from simulator.fees import collect
from simulator.model import canonical,InvariantError
from simulator.store import Store

class ReceiveFeeTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.s=Store(Path(self.tmp.name),'synthetic',10000);initialize(self.s)
  self.key='02'+'11'*32;self.s.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',(self.key,'actor-01','m','{}'))
  self.s.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',('received',self.key,900,'digest','signed','{}'))
  self.s.queue('invoice','actor-01','H06','invoice',{'amount_sat':1000},1000);self.s.db.execute("UPDATE action SET state='dispatched' WHERE id='invoice'");self.s.finish('invoice','completed',{'data':{'payment_hash':'a'*64,'estimated_claim_fee_sat':100}})
  self.m={'id':'3','subsystem':'bark.lightning_receive','status':'successful','payment_hash':'a'*64,'input_vtxos':[],'output_vtxos':['received'],'offchain_fee_sat':100,'effective_balance_sat':900}
  self.data={'receive_count_before':1,'receive_count_after':0,'before_evidence':{'movements':[]},'evidence':{'movements':[self.m]}}
  self.make_sync('sync')
  self.save()
 def tearDown(self):self.s.close();self.tmp.cleanup()
 def make_sync(self,name):
  self.s.queue(name,'actor-01','H02','sync',{},1000);self.s.db.execute('UPDATE action SET state=\'dispatched\' WHERE id=?',(name,));self.s.finish(name,'completed',{'data':self.data})
 def save(self):self.s.db.execute('INSERT OR REPLACE INTO movement_evidence VALUES (?,?,?)',('actor-01',self.m['id'],canonical(self.m)))
 def run_collect(self):asyncio.run(collect(self.s,None))
 def fee(self,name='sync'):return self.s.db.execute('SELECT actual_fee_sat FROM action WHERE id=?',(name,)).fetchone()[0]
 def test_verified_new_receive_conserves_invoice_minus_signed_output_and_releases_once(self):
  self.run_collect();self.assertEqual(100,self.fee());self.run_collect();self.assertEqual(1,self.s.db.execute("SELECT count(*) FROM event WHERE kind='client_fee_reconciled'").fetchone()[0])
 def test_pending_receive_or_missing_signed_proof_stays_reserved(self):
  self.s.db.execute("DELETE FROM owned_coin");self.run_collect();self.assertIsNone(self.fee())
 def test_old_success_before_sync_cannot_be_charged_again(self):
  self.s.db.execute("UPDATE action SET result=? WHERE id='sync'",(canonical({'data':{**self.data,'before_evidence':{'movements':[self.m]}}}),));self.run_collect();self.assertIsNone(self.fee())
 def test_changed_signed_amount_is_an_incident(self):
  self.s.db.execute('UPDATE owned_coin SET amount_sat=899');self.assertRaises(InvariantError,self.run_collect)
 def test_wrong_owner_is_an_incident(self):
  self.s.db.execute("UPDATE owner_key SET actor='actor-02'");self.assertRaises(InvariantError,self.run_collect)
 def test_invoice_estimate_variance_is_reported_within_sync_reserve(self):
  self.s.db.execute("UPDATE action SET result=? WHERE id='invoice'",(canonical({'data':{'payment_hash':'a'*64,'estimated_claim_fee_sat':99}}),));self.run_collect();self.assertEqual(100,self.fee())
 def test_pending_remaining_claim_keeps_entire_sync_reserved(self):
  self.s.db.execute("UPDATE action SET result=? WHERE id='sync'",(canonical({'data':{**self.data,'receive_count_after':1}}),));self.run_collect();self.assertIsNone(self.fee())
 def test_same_success_not_assigned_to_two_syncs(self):
  self.run_collect();self.make_sync('sync2');self.assertRaises(InvariantError,self.run_collect)

 def test_missing_after_boundary_cannot_release_claim_reserve(self):
  self.s.db.execute("UPDATE action SET result=? WHERE id='sync'",(canonical({'data':{**self.data,'evidence':{'movements':[]}}}),));self.run_collect();self.assertIsNone(self.fee())

 def test_actual_sync_reservation_remains_a_hard_bound(self):
  self.s.db.execute("UPDATE action SET fee_reservation_sat=99 WHERE id='sync'");self.assertRaises(InvariantError,self.run_collect)

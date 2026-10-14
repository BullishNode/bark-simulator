"""Immutable record re-use preserves a seed's one payout destination."""
import tempfile,unittest,json
from pathlib import Path
from types import SimpleNamespace
from simulator.engine import initialize
from simulator.store import Store
from simulator.ownership import EvidenceGap
from simulator.immutable_record import queue_check
from simulator.model import canonical
class ImmutableRecordTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.s=Store(Path(self.tmp.name),'synthetic',10000);initialize(self.s)
  self.actor='actor-11';self.script='0014'+'11'*20;self.raw='03'+'44'*230
  self.config=SimpleNamespace(network='signet',expected_server_pubkey='02'+'33'*32)
  self.s.db.execute('INSERT INTO owner_record VALUES (?,?,?,?,?)',(self.actor,'mailbox','account',self.script,canonical({'fallback_record':self.raw})))
 def tearDown(self):self.s.close();self.tmp.cleanup()
 def paid(self):self.s.db.execute('INSERT INTO checked_settlement VALUES (?,?,?,?,?,?)',('coin','aa'*32,self.actor,self.script,4000,'{}'))
 def test_pre_payout_record_check_does_not_claim_recovery(self):
  with self.assertRaises(EvidenceGap):queue_check(self.s,self.config,self.actor)
 def test_exact_record_idempotence_is_once_only_and_preserves_destination(self):
  self.paid();first=queue_check(self.s,self.config,self.actor);self.assertEqual(first,queue_check(self.s,self.config,self.actor))
  row=self.s.db.execute('SELECT * FROM action WHERE id=?',(first['action_id'],)).fetchone()
  self.assertEqual('fallback_record_check',row['operation']);self.assertEqual(self.raw,json.loads(row['args'])['fallback_record']);self.assertEqual(0,row['fee_reservation_sat'])
  self.assertEqual(self.script,self.s.db.execute('SELECT script FROM owner_record').fetchone()[0]);self.s.verify_event_chain()
 def test_unknown_action_blocks_record_dispatch(self):
  self.paid();self.s.queue('unknown',self.actor,'H01','sync',{},0);self.s.db.execute("UPDATE action SET state='outcome_unknown' WHERE id='unknown'")
  with self.assertRaises(EvidenceGap):queue_check(self.s,self.config,self.actor)
 def test_absent_originals_and_paused_campaign_stay_closed(self):
  self.paid()
  for actor in ['actor-03','actor-09','actor-10']:
   with self.assertRaises(EvidenceGap):queue_check(self.s,self.config,actor)
  self.s.db.execute("INSERT OR REPLACE INTO meta VALUES('paused','owner stop')")
  with self.assertRaises(EvidenceGap):queue_check(self.s,self.config,self.actor)
 def test_missing_exact_public_record_does_not_dispatch(self):
  self.paid();self.s.db.execute("UPDATE owner_record SET proof='{}'")
  with self.assertRaises(EvidenceGap):queue_check(self.s,self.config,self.actor)

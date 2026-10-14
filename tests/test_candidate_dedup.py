from tests import account_fixtures
import json,tempfile,unittest
from pathlib import Path
from simulator.engine import initialize
from simulator.model import canonical
from simulator.ownership import record_candidates,record_verified
from simulator.store import Store
class CandidateDedupTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.s=Store(Path(self.tmp.name),'synthetic',10000);initialize(self.s)
  self.key='02'+'11'*32;self.binding=account_fixtures.binding({'mailbox_pk':'mailbox','spk':'script','seq':1,'record_attestation':'a1'})
  self.coin=account_fixtures.coin({'id':'coin','amount_sat':1000,'user_pubkey':self.key,'expiry_height':100,'state':'Spendable','signed_vtxo':'abcd'})
  self.proof=account_fixtures.proof({'id':'coin','user_pubkey':self.key,'amount_sat':1000,'expiry_height':100,'signed_path_valid':True,'anchor_confirmations':1,'binding':{**self.binding,'account_child_verified':True,'record_signature_valid':True}})
  self.s.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',(self.key,'actor-01','mailbox',canonical(self.proof)))
  import hashlib
  self.s.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',('coin',self.key,1000,hashlib.sha256(bytes.fromhex('abcd')).hexdigest(),'abcd',canonical(self.proof)))
  self.s.queue('observe','actor-01','H02','snapshot',{},0)
 def tearDown(self):self.s.close();self.tmp.cleanup()
 def save(self,coin=None,binding=None,actor='actor-01'):
  record_candidates(self.s,actor,'observe',{'evidence':{'coins':[coin or self.coin],'binding':binding or self.binding}})
 def count(self):return self.s.db.execute('select count(*) from client_coin_candidate').fetchone()[0]
 def test_identical_immutable_origin_does_not_duplicate_candidate(self):
  self.save();self.save(dict(self.coin),dict(self.binding));self.assertEqual(0,self.count())
 def test_unverified_source_still_keeps_distinct_raw_proofs(self):
  self.s.db.execute('delete from owned_coin');self.save();self.save({**self.coin,'blinded_mailbox_id':'03'+'22'*32});self.assertEqual(2,self.count())
 def test_changed_protocol_or_binding_keeps_new_candidate(self):
  self.save({**self.coin,'signed_vtxo':'abce'});self.save(binding={**self.binding,'account_xpub':'another-account'});self.save(binding={**self.binding,'spk':'other'});self.assertEqual(3,self.count())
 def test_changed_actor_or_amount_or_key_not_hidden_by_cache(self):
  self.save(actor='actor-02');self.save({**self.coin,'amount_sat':999});self.save({**self.coin,'user_pubkey':'03'+'22'*32});self.assertEqual(3,self.count())
 def test_incomplete_cached_proof_is_not_an_ownership_shortcut(self):
  self.proof['signed_path_valid']=False;self.s.db.execute('update owned_coin set proof=?',(canonical(self.proof),));self.save();self.assertEqual(1,self.count())
 def test_state_observation_still_records_without_redundant_candidate(self):
  from hashlib import sha256
  spent={**self.coin,'state':'Spent'};self.save(spent)
  record_verified(self.s,'actor-01','observe',{'objects':[{'kind':'coin','coin':spent,'proof':self.proof,'signed_hash':sha256(bytes.fromhex('abcd')).hexdigest(),'request_binding':self.binding}],'movements':[]})
  self.assertEqual('Spent',self.s.db.execute('select state from coin_observation').fetchone()[0]);self.assertEqual(0,self.count())

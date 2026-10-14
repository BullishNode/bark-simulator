"""Runtime account-proof guards; synthetic fixtures carry no live credit."""
import asyncio,hashlib,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from simulator.engine import initialize
from simulator.store import Store
from simulator.ownership import record_verified,verify_client_evidence
from simulator.model import InvariantError,canonical

class AccountOwnershipTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.s=Store(Path(self.tmp.name),'synthetic',10000);initialize(self.s)
  self.s.queue('a','actor-01','H01','snapshot',{},0)
  self.binding={'mailbox_pk':'mailbox','spk':'script','account_xpub':'xpub','fallback_record':'aa','record_signature_valid':True,'account_child_verified':True,'child_index':25,'policy_pubkey_full':'pub','blinded_mailbox_id':'B'}
  self.coin={'id':'coin','user_pubkey':'pub','amount_sat':1000,'signed_vtxo':'bb','expiry_height':100,'state':'Spendable','child_index':25,'blinded_mailbox_id':'B'}
  self.proof={'id':'coin','user_pubkey':'pub','amount_sat':1000,'signed_path_valid':True,'anchor_confirmations':1,'binding':self.binding}
 def tearDown(self):self.s.close();self.tmp.cleanup()
 def objects(self):return {'objects':[{'kind':'coin','coin':self.coin,'proof':self.proof,'signed_hash':hashlib.sha256(b'\xbb').hexdigest(),'request_binding':self.binding}],'movements':[]}
 def test_legacy_signature_bool_is_not_account_child_verification(self):
  self.binding.pop('account_child_verified');self.binding.update(key_link_signature_valid=True,seq=1)
  with self.assertRaises(InvariantError):record_verified(self.s,'actor-01','a',self.objects())
 def test_full_policy_and_child_origin_must_match_exact_coin(self):
  self.binding['child_index']=26
  with self.assertRaises(InvariantError):record_verified(self.s,'actor-01','a',self.objects())
 def test_account_immutable_record_conflict_is_not_second_sequence(self):
  record_verified(self.s,'actor-01','a',self.objects())
  self.binding['account_xpub']='another'
  with self.assertRaises(InvariantError):record_verified(self.s,'actor-01','a',self.objects())
 def test_current_pins_cannot_relabel_old_cached_proof(self):
  old={**self.proof,'financial_pins':{'sdk':'old'},'binding':{**self.binding,'seq':1}}
  self.s.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',('pub','actor-01','mailbox',canonical(old)))
  self.s.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',('coin','pub',1000,hashlib.sha256(b'\xbb').hexdigest(),'bb',canonical(old)))
  data={'evidence':{'binding':{**self.binding,'seq':1},'coins':[self.coin]}}
  async def verifier(*args,**kwargs):return self.proof
  with patch.object(self.s,'financial_context',return_value={'sdk':'new'}),patch('simulator.ownership.json_command',side_effect=verifier) as verify:
   result=asyncio.run(verify_client_evidence(self.s,'actor-01','snapshot',data,['proof']))
  self.assertEqual(1,verify.call_count)
  self.assertEqual({'sdk':'new'},result['objects'][0]['proof']['financial_pins'])

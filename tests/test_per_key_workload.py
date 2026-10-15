"""Controller storage contracts, not signature or native-wallet qualification."""
import json,tempfile,unittest
from pathlib import Path
from simulator.engine import initialize
from simulator.store import Store
from simulator.workload import record_actor_result

class PerKeyWorkloadTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name),'synthetic',10000,architecture_profile='two_step_per_key');initialize(self.store)
  self.binding={'mailbox_pk':'02'+'1'*64,'spk':'0014'+'2'*40,'seq':17,'record_attestation':'3'*128,'onchain_ownership_checked':True}
 def tearDown(self):self.store.close();self.tmp.cleanup()
 def test_genuine_per_key_create_contract_does_not_require_an_xpub(self):
  record_actor_result(self.store,'actor-01','create',{'funding_address':'tb1qfixture','fallback_script':self.binding['spk'],'account_xpub':None,'binding':self.binding})
  d=json.loads(self.store.db.execute("SELECT details FROM actor WHERE id='actor-01'").fetchone()[0]);self.assertTrue(d['created']);self.assertNotIn('account_xpub',d)
 def test_per_key_address_preserves_link_instead_of_fabricating_account_child(self):
  record_actor_result(self.store,'actor-01','address',{'address':'tarkfixture','user_pubkey':'02'+'4'*64,'key_link_attestation':'5'*128,'binding':self.binding})
  d=json.loads(self.store.db.execute("SELECT details FROM actor WHERE id='actor-01'").fetchone()[0]);self.assertIn('key_link_attestation',d['advertised_key_proof']);self.assertNotIn('child_index',d['advertised_key_proof'])

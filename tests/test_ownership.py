from tests import account_fixtures
import json,tempfile,unittest
from pathlib import Path
from simulator.engine import initialize
from simulator.model import InvariantError
from simulator.ownership import EvidenceGap,expiry_owner,record_candidates,record_server_page,record_verified
from simulator.store import Store

class OwnershipTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.s=Store(Path(self.tmp.name),'synthetic',10000);initialize(self.s)
        for actor in ['actor-01','actor-02']:
            self.s.queue('action-'+actor,actor,'H01','snapshot',{},0)
    def tearDown(self):self.s.close();self.tmp.cleanup()
    def proof(self,actor,coin,pub,amount=10000,inputs=None,state='Spendable'):
        b=account_fixtures.binding({'mailbox_pk':'mb-'+actor,'spk':'spk-'+actor,'seq':1,'record_signature_valid':True,'account_child_verified':True})
        c=account_fixtures.coin({'id':coin,'user_pubkey':pub,'amount_sat':amount,'signed_vtxo':'aa','state':state})
        p=account_fixtures.proof({'id':coin,'user_pubkey':pub,'amount_sat':amount,'binding':b,'signed_path_valid':True,'anchor_confirmations':1,
            'path':[{'inputs':inputs or ['anchor:0']}]})
        return {'objects':[{'kind':'coin','coin':c,'proof':p,'signed_hash':'hash-'+coin,'request_binding':b}], 'movements':[]}
    def record(self,actor,coin,pub,**kw):record_verified(self.s,actor,'action-'+actor,self.proof(actor,coin,pub,**kw))
    def server(self,coin,**fields):
        record_server_page(self.s,{'kind':'coins','rows':[{'vtxo_id':coin,**fields}],'next':None,'inventory_consistent':False})
    def test_unregistered_signed_recipient_does_not_take_senders_expiry_claim(self):
        self.record('actor-01','parent:0','sender-key')
        self.record('actor-02','transfer:1','recipient-key',inputs=['parent:0'])
        self.server('parent:0',oor_spent_txid='transfer')
        self.assertEqual('actor-01',expiry_owner(self.s,'transfer:1','unregistered')['actor'])
        self.assertEqual('actor-02',expiry_owner(self.s,'transfer:1','spendable')['actor'])
        self.assertEqual(10000,expiry_owner(self.s,'transfer:1','unregistered')['amount_sat'])
    def test_missing_and_ambiguous_parent_never_guesses_leaf_owner(self):
        self.record('actor-02','transfer:1','recipient-key',inputs=['missing:0'])
        with self.assertRaises(EvidenceGap):expiry_owner(self.s,'transfer:1','unregistered')
        self.record('actor-02','many:0','other-key',inputs=['first:0','second:0'])
        with self.assertRaises(EvidenceGap):expiry_owner(self.s,'many:0','unregistered')
    def test_parent_spend_must_match_exact_virtual_transaction(self):
        self.record('actor-01','parent:0','sender-key');self.record('actor-02','transfer:1','recipient-key',inputs=['parent:0'])
        self.server('parent:0',oor_spent_txid='different')
        with self.assertRaises(EvidenceGap):expiry_owner(self.s,'transfer:1','unregistered')
    def test_general_movement_edges_do_not_retire_predecessors(self):
        v=self.proof('actor-01','a:0','sender');v['movements']=[{'id':'round','status':'Pending','input_vtxos':['a:0','b:0'], 'output_vtxos':['c:0','d:0','e:0'],'offchain_fee_sat':150}]
        record_verified(self.s,'actor-01','action-actor-01',v)
        self.assertEqual(5,self.s.db.execute('SELECT COUNT(*) FROM movement_edge').fetchone()[0])
        self.assertEqual(0,self.s.db.execute('SELECT COUNT(*) FROM resolution').fetchone()[0])
        self.assertEqual('actor-01',expiry_owner(self.s,'a:0','spendable')['actor'])
    def test_conflicting_key_rolls_back_all_evidence(self):
        self.record('actor-01','a:0','shared')
        with self.assertRaises(InvariantError):self.record('actor-02','b:0','shared')
        self.assertIsNone(self.s.db.execute("SELECT 1 FROM owned_coin WHERE id='b:0'").fetchone())
    def test_reobserving_proof_and_server_page_is_idempotent_and_retains_versions(self):
        self.record('actor-01','a:0','key');self.record('actor-01','a:0','key')
        self.server('a:0',spend_state='spendable');self.server('a:0',spend_state='spendable');self.server('a:0',spend_state='spent')
        self.assertEqual(1,self.s.db.execute('SELECT COUNT(*) FROM owned_coin').fetchone()[0])
        self.assertEqual(2,self.s.db.execute('SELECT COUNT(*) FROM server_item_version').fetchone()[0])
        self.s.verify_event_chain()
    def test_unconfirmed_public_evidence_is_retained_without_waking_absent_owner(self):
        data={'evidence':{'binding':account_fixtures.binding({'mailbox_pk':'m','seq':1,'spk':'s'}),'coins':[{'id':'pending:0','signed_vtxo':'aa','state':'PendingBoard'}]}}
        with self.s.transaction():record_candidates(self.s,'actor-01','action-actor-01',data)
        self.s.set_online('actor-01',False)
        self.assertEqual(0,self.s.db.execute('SELECT verified FROM client_coin_candidate').fetchone()[0])
        with self.assertRaises(EvidenceGap):expiry_owner(self.s,'pending:0','pending-board')
    def test_synthetic_consistent_flag_cannot_impersonate_real_inventory(self):
        with self.assertRaises(ValueError):record_server_page(self.s,{'kind':'coins','rows':[],'next':None,'inventory_consistent':True})

if __name__=='__main__':unittest.main()

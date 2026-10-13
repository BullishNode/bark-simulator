"""Cached forfeit replay requires positive exact expiry cancellation evidence."""
import hashlib,json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from simulator.engine import initialize
from simulator.store import Store
from simulator.model import canonical,InvariantError
from simulator.ownership import EvidenceGap
class ForfeitReplayTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name),'synthetic',100000);initialize(self.store)
        self.ids=['aa'*32+':0'];self.unlock='ee'*32;self.server='02'+'33'*32
        self.frozen={'scenario':'D27','server_pubkey':self.server,'inputs':[{'coin_id':self.ids[0]}],'context':{'unlock_hash':self.unlock,'cancelled_output_ids':['bb'*32+':0'],'captured_forfeit':{'input_coin_ids':self.ids,'unlock_hash':self.unlock,'server_pubkey':self.server,'wire_sha256':'11'*32,'private_bundle_sha256':'22'*32,'captured_at':100,'source_action_id':'prior-real-sdk-attempt'}}}
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def cancellation(self,**extra):
        row={'id':self.unlock,'round_id':32,'input_ids':self.ids,'output_ids':['bb'*32+':0'],'exited_ids':self.ids,**extra}
        self.store.db.execute('INSERT INTO server_item VALUES (?,?,?,?)',('expiry_cancelled_participation',self.unlock,canonical(row),200))
    def readiness(self):
        from simulator.phase_replay import forfeit_readiness
        return forfeit_readiness(self.store,self.frozen)
    def test_absence_or_not_found_does_not_replace_positive_cancellation(self):
        with self.assertRaises(EvidenceGap):self.readiness()
    def test_exact_positive_cancellation_binds_original_cached_request_and_preserves_pending_scope(self):
        self.cancellation();ready=self.readiness()
        self.assertEqual(self.ids,ready['input_coin_ids']);self.assertEqual('22'*32,ready['private_bundle_sha256'])
        self.assertFalse(ready['financial_outcome_verified']);self.assertFalse(ready['customer_traffic_credit'])
    def test_cancellation_of_other_inputs_or_output_branch_cannot_release_cached_forfeit(self):
        self.cancellation(input_ids=['ff'*32+':0'])
        with self.assertRaises(InvariantError):self.readiness()
    def test_changed_unlock_or_capture_time_after_cancellation_is_held(self):
        self.cancellation();self.frozen['context']['captured_forfeit']['unlock_hash']='dd'*32
        with self.assertRaises(InvariantError):self.readiness()
        self.frozen['context']['captured_forfeit']['unlock_hash']=self.unlock;self.frozen['context']['captured_forfeit']['captured_at']=300
        with self.assertRaises(EvidenceGap):self.readiness()

class WrongSweepTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name),'synthetic',100000);initialize(self.store)
        self.right='a1'*32+':0';self.other='a2'*32+':1';self.txid='e1'*32
        self.server='02'+'33'*32;self.key='02'+'11'*32
        self.store.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',(self.key,'actor-11','mailbox','{}'))
        for identity in [self.right,self.other]:
            raw=identity.encode();proof={'signed_path_valid':True,'anchor_confirmations':2,'server_pubkey':self.server,'chain_anchor':('c1' if identity==self.right else 'c2')*32+':0','path':[{'txid':identity.split(':')[0],'output_index':int(identity.split(':')[1])}]}
            self.store.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',(identity,self.key,5000,hashlib.sha256(raw).hexdigest(),raw.hex(),canonical(proof)))
        self.intent={'scenario':'D28','server_pubkey':self.server,'inputs':[{'coin_id':self.right}], 'context':{'other_branch_coin_id':self.other,'candidate_sweep_txid':self.txid}}
        self.tx={'txid':self.txid,'confirmations':2,'inputs':[{'outpoint':self.other}],'outputs':[],'fee_sat':100}
        class Chain:
            def __init__(this,owner):this.owner=owner
            def transaction(this,txid):self.assertEqual(self.txid,txid);return dict(this.owner.tx)
        self.chain=Chain(self)
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def readiness(self):
        from simulator.phase_replay import wrong_sweep_readiness
        return wrong_sweep_readiness(self.store,self.intent,self.chain)
    def test_actual_other_signed_branch_and_confirmed_spender_are_selected_without_wallet(self):
        ready=self.readiness();self.assertEqual(self.txid,ready['candidate_sweep_txid']);self.assertFalse(ready['rightful_settlement_verified'])
    def test_candidate_spending_shared_rightful_ancestor_is_not_a_false_branch_trial(self):
        self.tx['inputs'].append({'outpoint':'c1'*32+':0'})
        with self.assertRaises(InvariantError):self.readiness()
    def test_unconfirmed_or_unrelated_to_both_branches_is_not_a_qualified_wrong_sweep(self):
        self.tx['confirmations']=0
        with self.assertRaises(EvidenceGap):self.readiness()
        self.tx['confirmations']=2;self.tx['inputs']=[{'outpoint':'ff'*32+':0'}]
        with self.assertRaises(EvidenceGap):self.readiness()

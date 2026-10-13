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

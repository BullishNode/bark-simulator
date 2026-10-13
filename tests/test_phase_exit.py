"""Real exit packages must contain exact independently signed original leaves."""
import hashlib,json,tempfile,unittest
from pathlib import Path
from simulator.store import Store
from simulator.engine import initialize
from simulator.model import canonical,InvariantError
from simulator.ownership import EvidenceGap
from simulator.bundle_audit import decode_transaction
class ExitPhaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name),'synthetic',100000);initialize(self.store)
        self.key='02'+'11'*32;self.server='02'+'33'*32
        self.raw='0200000001'+'aa'*32+'0000000000ffffffff01'+(5000).to_bytes(8,'little').hex()+'015100000000'
        tx=decode_transaction(self.raw);self.coin=tx['txid']+':0';serialized=b'exact-signed-original'
        self.proof={'signed_path_valid':True,'anchor_confirmations':2,'server_pubkey':self.server,'path':[{'txid':tx['txid'],'output_index':0,'output_amount_sat':5000,'output_script':'51'}]}
        self.store.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',(self.key,'actor-11','mailbox','{}'))
        self.store.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',(self.coin,self.key,5000,hashlib.sha256(serialized).hexdigest(),serialized.hex(),canonical(self.proof)))
        self.intent={'scenario':'D20','actor':'actor-11','server_pubkey':self.server,'principal_sat':5000,'maximum_fee_sat':2000,'inputs':[{'coin_id':self.coin,'signed_hash':hashlib.sha256(serialized).hexdigest()}], 'context':{'fee_rate_sat_per_vb':2,'fee_funding_outpoint':'ff'*32+':0'}}
        self.proposal={'input_vtxo_ids':[self.coin],'signed_vtxos':[serialized.hex()],'fee_cap_sat':2000,'fee_rate_kwu':500,'fee_funding_outpoint':'ff'*32+':0','packages':[{'vtxo_id':self.coin,'transactions':[{'txid':tx['txid'],'tx':self.raw}]}]}
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def verify(self):
        from simulator.phase_exit import validate_package
        return validate_package(self.store,self.intent,self.proposal)
    def test_actual_exit_package_binds_exact_signed_original_and_lifetime_fee_source(self):
        result=self.verify();self.assertFalse(result['financial_outcome_verified']);self.assertEqual([self.coin],result['exact_exit_leaf_ids'])
    def test_missing_sdk_package_is_pending_not_setup_refusal_qualification(self):
        self.proposal['packages']=[]
        with self.assertRaises(EvidenceGap):self.verify()
    def test_changed_locktime_or_fee_source_cannot_reuse_exit_fence(self):
        self.proposal['packages'][0]['transactions'][0]['tx']=self.raw[:-8]+'01000000'
        with self.assertRaises(InvariantError):self.verify()
        self.proposal['packages'][0]['transactions'][0]['tx']=self.raw;self.proposal['fee_funding_outpoint']='ee'*32+':0'
        with self.assertRaises(InvariantError):self.verify()

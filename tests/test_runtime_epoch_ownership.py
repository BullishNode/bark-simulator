"""Synthetic unchanged-object rechecks preserve original cryptographic evidence."""
import asyncio,copy,hashlib,json,unittest
from unittest.mock import patch
from simulator.model import InvariantError
from simulator.ownership import record_verified,verify_client_evidence
from tests import test_finite_runtime_epoch as runtime_fixture
from tests import test_account_ownership as account_fixture

class RuntimeEpochOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.epoch=runtime_fixture.FiniteRuntimeEpochTests();self.epoch.setUp();self.store=self.epoch.store
        self.account=account_fixture.AccountOwnershipTests();self.account.setUp()
        self.account.proof['financial_pins']=self.epoch.pins
        self.objects=self.account.objects()
        record_verified(self.store,'actor-01','original-send',self.objects)
        self.original=tuple(self.store.db.execute("SELECT * FROM owned_coin WHERE id='coin'").fetchone())
        # The source checkpoint is captured after all original ownership evidence.
        self.epoch.value['runtime_manifest']['checkpoint']=dict(self.store.db.execute('SELECT sequence,hash FROM event ORDER BY sequence DESC LIMIT 1').fetchone())
        sequence,_=self.epoch.install();self.epoch.snapshot(sequence);self.epoch.unpause()
        self.store.queue('current-snapshot','actor-01','H01','snapshot',{},0);self.store.claim({'snapshot'})
    def tearDown(self):self.account.tearDown();self.epoch.tearDown()
    def test_same_object_calls_native_again_and_records_current_proof_separately(self):
        current={**self.account.proof,'anchor_confirmations':9}
        async def verifier(*args,**kwargs):return current
        data={'evidence':{'binding':self.account.binding,'coins':[self.account.coin]}}
        with patch('simulator.ownership.json_command',side_effect=verifier) as verify:
            result=asyncio.run(verify_client_evidence(self.store,'actor-01','snapshot',data,['proof']))
        self.assertEqual(1,verify.call_count)
        record_verified(self.store,'actor-01','current-snapshot',result)
        self.assertEqual(self.original,tuple(self.store.db.execute("SELECT * FROM owned_coin WHERE id='coin'").fetchone()))
        row=self.store.db.execute("SELECT payload FROM event WHERE kind='public_ownership_reverified'").fetchone();payload=json.loads(row[0])
        self.assertEqual(9,payload['current_proof']['anchor_confirmations'])
        self.assertEqual(self.epoch.release,payload['execution_release'])
        self.assertEqual(hashlib.sha256(self.original[-1].encode()).hexdigest(),payload['original_proof_sha256'])
        self.store.verify_event_chain()
    def test_changed_signed_serialization_refuses_without_replacing_original(self):
        changed=copy.deepcopy(self.objects);changed['objects'][0]['signed_hash']='a'*64
        changed['objects'][0]['coin']['signed_vtxo']='cc'
        with self.assertRaisesRegex(InvariantError,'original signed object'):
            record_verified(self.store,'actor-01','current-snapshot',changed)
        self.assertEqual(self.original,tuple(self.store.db.execute("SELECT * FROM owned_coin WHERE id='coin'").fetchone()))
        self.assertIsNone(self.store.db.execute("SELECT 1 FROM event WHERE kind='public_ownership_reverified'").fetchone())

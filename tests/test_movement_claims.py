from tests import account_fixtures
"""Retain original receive history without accepting an incomplete proof batch."""
import asyncio,hashlib,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from simulator.engine import initialize
from simulator.model import canonical,InvariantError
from simulator.ownership import record_candidates,record_verified,retry_public_candidates,promote_public_movements,verify_client_evidence
from simulator.process import CommandError
from simulator.store import Store

class MovementClaimTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.s=Store(Path(self.tmp.name),'synthetic',10000);initialize(self.s)
        self.binding=account_fixtures.binding({'mailbox_pk':'mailbox','seq':1,'spk':'script','record_attestation':'signature'})
        self.key='02'+'11'*32
        self.coins=[account_fixtures.coin({'id':'receipt-1','user_pubkey':self.key,'amount_sat':400,'signed_vtxo':'aa','expiry_height':150,'state':'Spendable'}),
                    account_fixtures.coin({'id':'receipt-2','user_pubkey':self.key,'amount_sat':600,'signed_vtxo':'bb','expiry_height':150,'state':'Spendable'})]
        self.movement={'id':'receive-1','subsystem':'bark.arkoor','status':'successful','input_vtxos':[],
                       'output_vtxos':['receipt-1','receipt-2'],'effective_balance_sat':1000,'offchain_fee_sat':0,'payment_hash':None}
        self.data={'evidence':{'binding':self.binding,'coins':self.coins,'movements':[self.movement]}}
        self.s.queue('original','actor-01','H01','snapshot',{},2000);self.s.claim({'snapshot'})
    def tearDown(self):self.s.close();self.tmp.cleanup()
    def proof(self,coin):
        return account_fixtures.proof({'id':coin['id'],'user_pubkey':coin['user_pubkey'],'amount_sat':coin['amount_sat'],'signed_path_valid':True,
                'anchor_confirmations':3,'expiry_height':coin['expiry_height'],
                'binding':{**self.binding,'account_child_verified':True,'record_signature_valid':True}})
    def prove(self,coin):
        record_verified(self.s,'actor-01','original',{'objects':[{'kind':'coin','coin':coin,'proof':self.proof(coin),
            'signed_hash':hashlib.sha256(bytes.fromhex(coin['signed_vtxo'])).hexdigest(),'request_binding':self.binding}],'movements':[]})
    def finish(self):
        record_candidates(self.s,'actor-01','original',self.data,verification_failed=True)
        self.s.finish('original','completed',{'data':self.data},None)
        self.s.db.execute("UPDATE action SET updated_at=1000 WHERE id='original'")
    def accepted(self):return self.s.db.execute('SELECT COUNT(*) FROM movement_evidence').fetchone()[0]
    def test_claim_alone_never_accepts_a_receive_or_releases_its_reserve(self):
        self.finish();promote_public_movements(self.s)
        self.assertEqual(1,self.s.db.execute('SELECT COUNT(*) FROM client_movement_candidate').fetchone()[0])
        self.assertEqual(0,self.accepted());self.assertIsNone(self.s.db.execute('SELECT actual_fee_sat FROM action').fetchone()[0])
    def test_receipts_after_a_failing_board_promote_only_after_independent_retries(self):
        bad={**self.coins[0],'id':'unconfirmed-board'};self.data['evidence']['coins']=[bad,*self.coins]
        calls=[]
        async def verifier(command,request,**kwargs):
            calls.append(request['id'])
            if request['id']=='unconfirmed-board':raise CommandError('unconfirmed unrelated backing')
            return self.proof(request)
        with patch('simulator.ownership.json_command',verifier):
            with self.assertRaises(CommandError):asyncio.run(verify_client_evidence(self.s,'actor-01','snapshot',self.data,['public-proof']))
            self.s.event('ownership_proof_pending',{'action_id':'original','reason':'CommandError'});self.finish()
            self.assertEqual(0,self.accepted());asyncio.run(retry_public_candidates(self.s,['public-proof'],limit=8))
        self.assertEqual(1,self.accepted());self.assertEqual(1,self.s.db.execute("SELECT COUNT(*) FROM event WHERE kind='ownership_proof_pending'").fetchone()[0])
        event=json.loads(self.s.db.execute("SELECT payload FROM event WHERE kind='public_movement_claim_promoted'").fetchone()[0])
        self.assertEqual(1000,event['original_action_updated_at']);self.assertFalse(event['fee_reservation_released'])
        self.assertIsNone(self.s.db.execute('SELECT actual_fee_sat FROM action').fetchone()[0])
        self.assertEqual(0,self.s.db.execute("SELECT verified FROM client_coin_candidate WHERE id='unconfirmed-board'").fetchone()[0])
        self.assertEqual(['unconfirmed-board','unconfirmed-board','receipt-1','receipt-2'],calls)
        self.s.verify_event_chain()
    def test_one_proven_output_does_not_promote_the_other_output(self):
        self.finish();self.prove(self.coins[0]);promote_public_movements(self.s);self.assertEqual(0,self.accepted())
    def test_foreign_actor_or_unconfirmed_proof_cannot_promote_receipt(self):
        self.finish()
        for coin in self.coins:self.prove(coin)
        self.s.db.execute("UPDATE owner_key SET actor='actor-02'");promote_public_movements(self.s);self.assertEqual(0,self.accepted())
        self.s.db.execute("UPDATE owner_key SET actor='actor-01'")
        proof=self.proof(self.coins[0]);proof['anchor_confirmations']=0
        self.s.db.execute('UPDATE owned_coin SET proof=? WHERE id=?',(canonical(proof),'receipt-1'))
        promote_public_movements(self.s);self.assertEqual(0,self.accepted())
    def test_an_owner_contradiction_blocks_claim_even_with_all_signed_outputs(self):
        self.finish()
        for coin in self.coins:self.prove(coin)
        self.s.event('ownership_incident',{'action_id':'original','reason':'conflicting owner'})
        promote_public_movements(self.s);self.assertEqual(0,self.accepted())
    def test_mutated_claim_cannot_replace_original_sdk_response(self):
        self.finish()
        for coin in self.coins:self.prove(coin)
        changed={**self.movement,'effective_balance_sat':2000};payload=canonical(changed)
        self.s.db.execute('UPDATE client_movement_candidate SET payload=?,digest=?',(payload,hashlib.sha256(payload.encode()).hexdigest()))
        promote_public_movements(self.s);self.assertEqual(0,self.accepted())
    def test_promotion_is_idempotent_and_never_downgrades_conflicting_existing_history(self):
        self.finish()
        for coin in self.coins:self.prove(coin)
        promote_public_movements(self.s);promote_public_movements(self.s)
        self.assertEqual(1,self.s.db.execute("SELECT COUNT(*) FROM event WHERE kind='public_movement_claim_promoted'").fetchone()[0])
        self.s.db.execute('DELETE FROM movement_evidence')
        self.s.db.execute('UPDATE client_movement_candidate SET promoted=0')
        existing={**self.movement,'status':'pending'}
        self.s.db.execute('INSERT INTO movement_evidence VALUES (?,?,?)',('actor-01','receive-1',canonical(existing)))
        promote_public_movements(self.s)
        self.assertEqual('pending',json.loads(self.s.db.execute('SELECT payload FROM movement_evidence').fetchone()[0])['status'])

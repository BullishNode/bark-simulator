"""Synthetic scheduler evidence; native adoption is a separate fixture gate."""
import hashlib,json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from simulator.engine import initialize
from simulator.model import canonical,InvariantError
from simulator.store import Store

SERVER='02'+'33'*32
INPUT_KEY='02'+'11'*32
OUTPUT_KEY='03'+'22'*32
# Canonical one-input/one-output wire transaction, used to check nursery identity.
RAW='0200000001'+'00'*32+'ffffffff00ffffffff01'+'1027000000000000'+'0151'+'00000000'
TXID=hashlib.sha256(hashlib.sha256(bytes.fromhex(RAW)).digest()).digest()[::-1].hex()

class RoundAdoptionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.s=Store(Path(self.tmp.name),'synthetic',100000);initialize(self.s)
        self.c=SimpleNamespace(active=True,expected_server_pubkey=SERVER,action_fee_reserve_sat=2000,
            round_sync_required_confirmations=2,round_sync_retry_seconds=120,round_unclaimed_warning_blocks=6)
        self.snapshot={'height':101,'observed_at':1000,'stable_tip':True,'initial_block_download':False,'server_status':{'status':'running'}}
        self.actor='actor-02';self.coin='44'*32+':0'
        self.s.db.execute('UPDATE actor SET details=? WHERE id=?',(canonical({'created':True,'ark_address':'public-address','pending_in_round_sat':9900,'registered_spendable_sat':0}),self.actor))
        self.s.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',(INPUT_KEY,self.actor,'mailbox','{}'))
        self.s.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',('input:0',INPUT_KEY,10000,hashlib.sha256(bytes.fromhex('aa')).hexdigest(),'aa','{}'))
        self.s.queue('refresh',self.actor,'H17','refresh',{},2000)
        self.s.db.execute("UPDATE action SET state='completed',created_at=500,updated_at=510,result=? WHERE id='refresh'",(canonical({'data':{'round_state_id':'1','committed_fee_sat':100}}),))
        self.s.event('driver_evidence',{'action_id':'refresh','event':'refresh_proposal','data':{'participation':{'inputs':['aa'],'outputs':[{'policy':'00'+OUTPUT_KEY,'amount':9900}]},'committed_fee_sat':100}})
        movement={'id':'pending-round','subsystem':'bark.round','status':'pending','input_vtxos':['input:0'],'output_vtxos':[],'offchain_fee_sat':100,'effective_balance_sat':-100}
        self.s.db.execute('INSERT INTO movement_evidence VALUES (?,?,?)',(self.actor,movement['id'],canonical(movement)))
        self.server('coins',self.coin,{'vtxo_id':self.coin,'signed_vtxo':'bb','expiry':106,'policy_type':'pubkey','spend_state':'unclaimed'},900)
        self.server('nursery',TXID,{'txid':TXID,'raw_tx':RAW,'kind':'round','confirmed_at_height':100,'abandoned_at':None},950)
        self.decoded={self.coin:{'schema_version':1,'id':self.coin,'candidate_user_pubkey':OUTPUT_KEY,'amount_sat':9900,'expiry_height':106,
            'server_pubkey':SERVER,'chain_anchor':TXID+':0','arkoor_transition_count':0,'tree_padding':False,
            'client_owner_verified':False,'chain_contract_verified':False,'signed_hash':hashlib.sha256(bytes.fromhex('bb')).hexdigest(),'verifier_hash':'cc'*32}}
    def tearDown(self):self.s.close();self.tmp.cleanup()
    def server(self,kind,identity,value,at):
        self.s.db.execute('INSERT OR REPLACE INTO server_item VALUES (?,?,?,?)',(kind,identity,canonical(value),at))
    def decoder(self,store,row,**kwargs):return self.decoded.get(row['id'])
    def queue(self,now=1000):
        from simulator.round_adoption import queue_confirmed
        return queue_confirmed(self.s,self.c,self.snapshot,now=now,decoder=self.decoder)
    def queued(self):return self.s.db.execute("SELECT * FROM action WHERE state='queued'").fetchall()
    def test_confirmed_locked_refresh_queues_sync_before_dry_or_hourly_cadence(self):
        decision=self.queue();self.assertEqual('round_confirmed_sync',decision['rule_id']);self.assertEqual('queued',decision['outcome'])
        action=self.queued()[0];self.assertEqual((self.actor,'sync',2000),(action['actor_id'],action['operation'],action['fee_reservation_sat']))
        args=json.loads(action['args']);self.assertEqual('refresh',args['round_confirmed_for_action_id']);self.assertEqual(TXID,args['round_txid'])
        self.assertEqual([self.coin],args['expected_output_coin_ids']);self.assertIsNone(self.s.db.execute("SELECT actual_fee_sat FROM action WHERE id='refresh'").fetchone()[0])
        self.assertEqual(0,self.s.db.execute("SELECT count(*) FROM event WHERE kind IN ('ark_transfer_verified','client_fee_reconciled')").fetchone()[0]);self.s.verify_event_chain()
    def test_actual_sdk_confirmation_depth_is_preserved(self):
        self.snapshot['height']=100;self.assertIsNone(self.queue());self.assertEqual([],self.queued())
        self.snapshot['height']=101;self.assertEqual('queued',self.queue()['outcome'])
    def test_repeated_tick_restart_and_unknown_outcome_never_duplicate_sync(self):
        self.queue();self.queue();self.assertEqual(1,len(self.queued()))
        identity=self.queued()[0]['id'];self.s.db.execute("UPDATE action SET state='outcome_unknown' WHERE id=?",(identity,))
        self.queue(now=1200);self.assertEqual(0,len(self.queued()));self.assertEqual(2,self.s.db.execute('SELECT count(*) FROM action').fetchone()[0])
    def test_offline_permanent_absence_stale_or_unstable_snapshot_holds(self):
        self.s.set_online(self.actor,False);self.assertIsNone(self.queue());self.s.set_online(self.actor,True)
        self.s.db.execute('UPDATE actor SET details=? WHERE id=?',(canonical({'created':True,'ark_address':'public','permanent_absence':{'original_wallet_must_stay_closed':True}}),self.actor))
        self.assertIsNone(self.queue());self.s.db.execute('UPDATE actor SET details=? WHERE id=?',(canonical({'created':True,'ark_address':'public'}),self.actor))
        self.snapshot['stable_tip']=False;self.assertIsNone(self.queue());self.snapshot['stable_tip']=True;self.snapshot['observed_at']=800;self.assertIsNone(self.queue())
    def test_wrong_key_value_arkoor_output_padding_or_unrelated_anchor_cannot_trigger(self):
        original=dict(self.decoded[self.coin])
        for changes in [{'candidate_user_pubkey':INPUT_KEY},{'amount_sat':9901},{'arkoor_transition_count':1},{'tree_padding':True},{'chain_anchor':'ff'*32+':0'}]:
            with self.subTest(changes=changes):
                self.decoded[self.coin]={**original,**changes};self.assertIsNone(self.queue());self.assertEqual([],self.queued())
    def test_invalid_nursery_transaction_identity_is_an_incident(self):
        self.server('nursery',TXID,{'txid':TXID,'raw_tx':RAW[:-8]+'01000000','kind':'round','confirmed_at_height':100,'abandoned_at':None},950)
        with self.assertRaises(InvariantError):self.queue()
    def test_near_expiry_is_client_candidate_observation_without_owner_or_loss_claim(self):
        from simulator.round_adoption import near_expiry_findings
        findings=near_expiry_findings(self.s,self.c,self.snapshot,decoder=self.decoder)
        self.assertEqual(1,len(findings));value=findings[0];self.assertEqual(self.actor,value['actor']);self.assertEqual(5,value['blocks_remaining'])
        self.assertFalse(value['client_owner_verified']);self.assertFalse(value['traffic_credit']);self.assertEqual(self.coin,value['coin_id'])
        self.decoded[self.coin]['tree_padding']=True;self.assertEqual([],near_expiry_findings(self.s,self.c,self.snapshot,decoder=self.decoder))
    def test_successful_native_movement_or_claimed_server_state_removes_adoption_trigger(self):
        payload=json.loads(self.s.db.execute('SELECT payload FROM movement_evidence').fetchone()[0]);payload['status']='successful'
        self.s.db.execute('UPDATE movement_evidence SET payload=?',(canonical(payload),));self.assertIsNone(self.queue())
        self.server('coins',self.coin,{'vtxo_id':self.coin,'signed_vtxo':'bb','expiry':106,'policy_type':'pubkey','spend_state':'spendable'},999)
        from simulator.round_adoption import near_expiry_findings
        self.assertEqual([],near_expiry_findings(self.s,self.c,self.snapshot,decoder=self.decoder))

class RoundStderrTests(unittest.TestCase):
    def test_waiting_confirmed_and_partial_failures_are_distinct_public_diagnostics(self):
        from simulator.round_adoption import diagnose_stderr
        text='Syncing 1 pending round states...\nWaiting for confirmations for round funding tx '+TXID+'\nProcessing 1 rounds...\nError syncing round #1: chain source error\n'
        value=diagnose_stderr(text);self.assertEqual([TXID],value['waiting_funding_txids']);self.assertEqual([],value['confirmed_funding_txids']);self.assertEqual(1,value['round_error_count'])
        complete=diagnose_stderr('Round confirmed. Funding tx '+TXID+'\n');self.assertEqual([TXID],complete['confirmed_funding_txids'])
    def test_redacted_or_truncated_stderr_never_supplies_an_exact_anchor_association(self):
        from simulator.round_adoption import diagnose_stderr
        for fields in [{'redacted':True},{'truncated':True}]:
            value=diagnose_stderr('Waiting for confirmations for round funding tx '+TXID,**fields)
            self.assertFalse(value['complete']);self.assertEqual([],value['waiting_funding_txids'])

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
        self.s.event('driver_evidence',{'action_id':'refresh','event':'wallet_runtime_parameters','data':{'actor':self.actor,'round_tx_required_confirmations':2,'vtxo_exit_margin':12,'daemon_manual_sync':True,'run_daemon':False}})
        from simulator.round_adoption import record_input_params
        record_input_params(self.s,'aa',{'schema_version':1,'id':'input:0','candidate_user_pubkey':INPUT_KEY,'amount_sat':10000,'expiry_height':100,'exit_delta':12,'server_pubkey':SERVER,'client_owner_verified':False,'chain_contract_verified':False},SERVER,'cc'*32)
    def tearDown(self):self.s.close();self.tmp.cleanup()
    def server(self,kind,identity,value,at):
        self.s.db.execute('INSERT OR REPLACE INTO server_item VALUES (?,?,?,?)',(kind,identity,canonical(value),at))
    def decoder(self,store,row,**kwargs):return self.decoded.get(row['vtxo_id'])
    def queue(self,now=1000):
        from simulator.round_adoption import queue_confirmed
        return queue_confirmed(self.s,self.c,self.snapshot,now=now,decoder=self.decoder)
    def queued(self):return self.s.db.execute("SELECT * FROM action WHERE state='queued'").fetchall()
    def test_scheduled_refresh_is_observed_but_generic_sync_cannot_redelegate_it(self):
        from simulator.round_adoption import candidate_rounds,near_expiry_findings
        self.s.db.execute("UPDATE action SET operation='refresh_scheduled' WHERE id='refresh'")
        candidates=candidate_rounds(self.s,self.c,decoder=self.decoder)
        self.assertEqual(1,len(candidates))
        decision=self.queue()
        self.assertEqual('held',decision['outcome'])
        self.assertEqual('frozen_scheduled_intent',decision['reason'])
        self.assertEqual([],self.queued())
        self.assertTrue(near_expiry_findings(self.s,self.c,self.snapshot,decoder=self.decoder))

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

class RoundSecurityWindowTests(unittest.TestCase):
    setUp=RoundAdoptionTests.setUp
    tearDown=RoundAdoptionTests.tearDown
    server=RoundAdoptionTests.server
    decoder=RoundAdoptionTests.decoder
    queue=RoundAdoptionTests.queue
    queued=RoundAdoptionTests.queued
    def input_parameters(self,expiry=130):
        from simulator.round_adoption import record_input_params
        proof={'schema_version':1,'id':'input:0','candidate_user_pubkey':INPUT_KEY,'amount_sat':10000,'expiry_height':expiry,
            'exit_delta':12,'server_pubkey':SERVER,'client_owner_verified':False,'chain_contract_verified':False}
        self.s.db.execute('DELETE FROM round_input_params')
        record_input_params(self.s,'aa',proof,SERVER,'cc'*32)
    def test_confirmed_but_unsafe_output_window_is_explicit_hold_without_sdk_calls(self):
        self.input_parameters();decision=self.queue()
        self.assertEqual('held',decision['outcome']);self.assertEqual('sdk_exitability_window',decision['reason']);self.assertEqual([],self.queued())
        security=decision['inputs']['security_window'];self.assertEqual(137,security['minimum_output_expiry_height']);self.assertEqual(106,security['minimum_observed_output_expiry_height'])
        self.assertEqual(12,security['exit_margin_blocks']);self.assertEqual(12,security['maximum_input_exit_delta_blocks'])
    def test_original_inputs_expired_uses_existing_sdk_branch_without_lowering_margin(self):
        self.input_parameters(expiry=100);decision=self.queue()
        self.assertEqual('queued',decision['outcome']);self.assertTrue(decision['inputs']['security_window']['all_inputs_expired'])
        self.assertEqual(12,decision['inputs']['security_window']['exit_margin_blocks'])
    def test_safe_output_window_queues_with_original_depth_and_fee_ceiling(self):
        self.input_parameters();self.decoded[self.coin]['expiry_height']=160
        self.server('coins',self.coin,{'vtxo_id':self.coin,'signed_vtxo':'bb','expiry':160,'policy_type':'pubkey','spend_state':'unclaimed'},900)
        self.assertEqual('queued',self.queue()['outcome']);self.assertEqual(2000,self.queued()[0]['fee_reservation_sat'])
    def test_decoder_security_parameters_cannot_claim_another_frozen_input(self):
        from simulator.round_adoption import record_input_params
        proof={'schema_version':1,'id':'other:0','candidate_user_pubkey':INPUT_KEY,'amount_sat':10000,'expiry_height':130,
            'exit_delta':12,'server_pubkey':SERVER,'client_owner_verified':False,'chain_contract_verified':False}
        with self.assertRaises(InvariantError):record_input_params(self.s,'aa',proof,SERVER,'cc'*32)
    def test_sdk_security_window_is_reported_even_before_near_expiry_warning(self):
        from simulator.round_adoption import security_findings
        self.input_parameters();findings=security_findings(self.s,self.c,self.snapshot,decoder=self.decoder)
        self.assertEqual(1,len(findings));self.assertEqual('sdk_exitability_window',findings[0]['reason']);self.assertFalse(findings[0]['traffic_credit'])

class StructuredRoundDiagnosticTests(unittest.TestCase):
    def test_compact_public_diagnostic_preserves_refusal_without_copying_stderr(self):
        from simulator.round_adoption import diagnose_stderr,record_sync_diagnostic
        with tempfile.TemporaryDirectory() as tmp:
            store=Store(Path(tmp),'synthetic',10000);initialize(store);store.queue('sync','actor-02','H01','sync',{},2000)
            text='Syncing 1 pending round states...\nError syncing round #1: round VTXO tree expiry height 106 is below the required minimum 137; server may be trying to sweep before we can exit\n'
            diagnostic=diagnose_stderr(text);record_sync_diagnostic(store,'sync',diagnostic);record_sync_diagnostic(store,'sync',diagnostic)
            self.assertEqual(137,diagnostic['exit_window_rejections'][0]['minimum_expiry_height'])
            events=store.db.execute("SELECT payload FROM event WHERE kind='round_sync_diagnostic'").fetchall()
            self.assertEqual(1,len(events));self.assertNotIn('text',json.loads(events[0][0]));self.assertNotIn(text,events[0][0]);store.verify_event_chain();store.close()

class RoundSchedulingGuardTests(RoundSecurityWindowTests):
    def test_unsafe_first_does_not_starve_ready_second_actor(self):
        from unittest.mock import patch
        from simulator.round_adoption import candidate_rounds,queue_confirmed
        self.input_parameters()
        first=candidate_rounds(self.s,self.c,decoder=self.decoder)[0]
        self.s.db.execute('UPDATE actor SET details=? WHERE id=?',(canonical({'created':True,'ark_address':'public'}),'actor-05'))
        self.s.queue('refresh-second','actor-05','H17','refresh',{},2000)
        self.s.db.execute("UPDATE action SET state='completed' WHERE id='refresh-second'")
        self.s.event('driver_evidence',{'action_id':'refresh-second','event':'wallet_runtime_parameters','data':{'actor':'actor-05','round_tx_required_confirmations':2,'vtxo_exit_margin':12,'daemon_manual_sync':True,'run_daemon':False}})
        second={**first,'actor':'actor-05','refresh_action_id':'refresh-second','replacement_outputs':[{**first['replacement_outputs'][0],'expiry_height':160}]}
        decisions=[]
        with patch('simulator.round_adoption.candidate_rounds',return_value=[first,second]):
            result=queue_confirmed(self.s,self.c,self.snapshot,now=1000,decoder=self.decoder,decisions=decisions)
        self.assertEqual(('actor-05','queued'),(result['actor'],result['outcome']))
        self.assertEqual(['held','queued'],[d['outcome'] for d in decisions])
        self.assertEqual('actor-05',self.queued()[0]['actor_id'])
    def test_missing_actual_sdk_parameters_holds_without_guessing_defaults(self):
        self.s.db.execute("DELETE FROM event WHERE kind='driver_evidence' AND json_extract(payload,'$.event')='wallet_runtime_parameters'")
        decision=self.queue();self.assertEqual('held',decision['outcome']);self.assertEqual('sdk_parameters_unknown',decision['reason']);self.assertEqual([],self.queued())
    def test_declared_depth_cannot_override_actual_sdk_depth(self):
        self.c.round_sync_required_confirmations=1
        decision=self.queue();self.assertEqual('held',decision['outcome']);self.assertEqual('sdk_parameters_mismatch',decision['reason']);self.assertEqual([],self.queued())
    def test_missing_exact_input_params_holds_without_wallet_read(self):
        self.s.db.execute('DELETE FROM round_input_params')
        decision=self.queue();self.assertEqual('held',decision['outcome']);self.assertEqual('sdk_input_parameters_unknown',decision['reason'])
    def test_diagnostic_rejects_unsolicited_full_stderr(self):
        from simulator.round_adoption import diagnose_stderr,record_sync_diagnostic
        with self.assertRaises(ValueError):record_sync_diagnostic(self.s,'refresh',{**diagnose_stderr(''),'text':'full log'})

class RoundObservationGapTests(unittest.TestCase):
    setUp=RoundAdoptionTests.setUp
    tearDown=RoundAdoptionTests.tearDown
    server=RoundAdoptionTests.server
    decoder=RoundAdoptionTests.decoder
    def test_partial_inventory_still_warns_for_exact_unclaimed_frozen_output(self):
        from simulator.round_adoption import near_expiry_findings
        other_key='02'+'55'*32
        proposal={'participation':{'inputs':['aa'],'outputs':[{'policy':'00'+OUTPUT_KEY,'amount':4900},{'policy':'00'+other_key,'amount':5000}]},'committed_fee_sat':100}
        self.s.db.execute("UPDATE event SET payload=? WHERE kind='driver_evidence' AND json_extract(payload,'$.event')='refresh_proposal'",(canonical({'action_id':'refresh','event':'refresh_proposal','data':proposal}),))
        self.decoded[self.coin]['amount_sat']=4900
        findings=near_expiry_findings(self.s,self.c,self.snapshot,decoder=self.decoder)
        self.assertEqual(1,len(findings));self.assertEqual(4900,findings[0]['amount_sat']);self.assertFalse(findings[0]['client_owner_verified'])
    def test_warning_cannot_clear_when_decoder_evidence_disappears(self):
        from simulator.round_adoption import near_expiry_findings,observation_can_clear
        finding=near_expiry_findings(self.s,self.c,self.snapshot,decoder=self.decoder)[0]
        self.s.db.execute("INSERT INTO observation VALUES (?,?,'active',?,?,?,?,1)",(finding['key'],'warning','near expiry',canonical(finding),1000,1000))
        self.s.db.execute('DELETE FROM server_item')
        self.assertFalse(observation_can_clear(self.s,finding['key'],self.snapshot))

class RoundSchedulerCycleTests(unittest.TestCase):
    setUp=RoundAdoptionTests.setUp
    tearDown=RoundAdoptionTests.tearDown
    server=RoundAdoptionTests.server
    decoder=RoundAdoptionTests.decoder
    def test_normal_scheduler_prioritizes_confirmed_round_in_one_cycle(self):
        from unittest.mock import patch
        from simulator import continuous
        from simulator.round_adoption import queue_confirmed
        actual=queue_confirmed
        def decoded(*args,**kwargs):return actual(*args,**kwargs,decoder=self.decoder)
        with patch('simulator.round_adoption.queue_confirmed',side_effect=decoded),patch('simulator.round_adoption.time.time',return_value=1000):
            continuous.schedule(self.s,self.c,self.snapshot)
        queued=list(self.s.db.execute("SELECT * FROM action WHERE state='queued'"))
        self.assertEqual(1,len(queued));self.assertEqual(('actor-02','sync'),(queued[0]['actor_id'],queued[0]['operation']))
        tick=json.loads(self.s.db.execute("SELECT payload FROM event WHERE kind='scheduler_tick' ORDER BY sequence DESC LIMIT 1").fetchone()[0])
        self.assertEqual('round_confirmed_sync',tick['actors'][0]['rule_id']);self.assertEqual('queued',tick['actors'][0]['outcome'])

class RoundSecurityLifecycleTests(unittest.TestCase):
    setUp=RoundAdoptionTests.setUp
    tearDown=RoundAdoptionTests.tearDown
    server=RoundAdoptionTests.server
    decoder=RoundAdoptionTests.decoder
    def test_security_warning_clears_only_from_positive_current_safe_window(self):
        from simulator.round_adoption import security_findings,record_input_params,observation_can_clear
        from unittest.mock import patch
        self.s.db.execute('DELETE FROM round_input_params')
        record_input_params(self.s,'aa',{'schema_version':1,'id':'input:0','candidate_user_pubkey':INPUT_KEY,'amount_sat':10000,'expiry_height':130,'exit_delta':12,'server_pubkey':SERVER,'client_owner_verified':False,'chain_contract_verified':False},SERVER,'cc'*32)
        finding=security_findings(self.s,self.c,self.snapshot,decoder=self.decoder)[0]
        self.s.db.execute("INSERT INTO observation VALUES (?,?,'active',?,?,?,?,1)",(finding['key'],'warning','security window',canonical(finding),1000,1000))
        self.snapshot['height']=130
        from simulator.round_adoption import candidate_rounds
        candidates=candidate_rounds(self.s,self.c,decoder=self.decoder)
        with patch('simulator.round_adoption.candidate_rounds',return_value=candidates),patch('simulator.round_adoption.time.time',return_value=1000):
            self.assertTrue(observation_can_clear(self.s,finding['key'],self.snapshot,self.c))
        self.s.db.execute('DELETE FROM round_input_params')
        with patch('simulator.round_adoption.candidate_rounds',return_value=candidates),patch('simulator.round_adoption.time.time',return_value=1000):
            self.assertFalse(observation_can_clear(self.s,finding['key'],self.snapshot,self.c))

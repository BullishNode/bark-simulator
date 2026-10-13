"""Phase orchestration uses exact inputs and independent financial evidence."""
import hashlib,json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from simulator.engine import initialize
from simulator.store import Store
from simulator.model import canonical,InvariantError
from simulator.ownership import EvidenceGap

class PhaseTrialTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name),'synthetic',100000);initialize(self.store)
        self.config=SimpleNamespace(network='signet',expected_server_pubkey='02'+'33'*32,phase_enabled=False,phase_manifest_sha256=None)
        self.coin='aa'*32+':0';self.keys={'actor-11':'02'+'11'*32,'actor-04':'02'+'44'*32,'actor-06':'02'+'66'*32}
        for actor,key in self.keys.items():self.store.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',(key,actor,'mailbox-'+actor,'{}'))
        proof={'id':self.coin,'user_pubkey':self.keys['actor-11'],'amount_sat':5000,'signed_path_valid':True,'anchor_confirmations':2,'ancestor_ids':[]}
        self.store.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',(self.coin,self.keys['actor-11'],5000,hashlib.sha256(b'source').hexdigest(),b'source'.hex(),canonical(proof)))
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def trial(self,scenario='D17',**kw):
        from simulator.phase_trials import Controller
        self.controller=Controller(self.store,self.config,nonce_verifier=lambda _trial,_leg:True)
        context={'input_coin_ids':[self.coin],'recipients':[{'actor':'actor-04','pubkey':self.keys['actor-04']},{'actor':'actor-06','pubkey':self.keys['actor-06']}],**kw}
        return self.controller.declare(scenario,'actor-11',context)
    def prepared(self,trial,nonce='process_only'):
        return self.controller.prepare(trial,{'trial_id':trial,'intent_hash':self.controller.intent(trial)['intent_hash'],
            'legs':[{'leg_id':'left','rpc':'RequestArkoorCosign','input_coin_ids':[self.coin],'wire_sha256':'a1'*32,'nonce_retention':nonce,'private_checkpoint_sha256':'b1'*32,'input_spends':[{'coin_id':self.coin,'txid':'c1'*32}],'outputs':[{'coin_id':'d1'*32+':0','pubkey':self.keys['actor-04'],'amount_sat':5000}]},
                    {'leg_id':'right','rpc':'RequestArkoorCosign','input_coin_ids':[self.coin],'wire_sha256':'a2'*32,'nonce_retention':nonce,'private_checkpoint_sha256':'b2'*32,'input_spends':[{'coin_id':self.coin,'txid':'c2'*32}],'outputs':[{'coin_id':'d2'*32+':0','pubkey':self.keys['actor-06'],'amount_sat':5000}]}]})
    def add_output(self,identity,key,parents,spending_txid=None):
        proof={'id':identity,'user_pubkey':key,'amount_sat':5000,'signed_path_valid':True,'anchor_confirmations':2,'ancestor_ids':parents}
        if spending_txid:proof['path']=[{'txid':spending_txid,'inputs':parents}]
        self.store.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',(identity,key,5000,hashlib.sha256(identity.encode()).hexdigest(),identity.encode().hex(),canonical(proof)))
    def test_same_input_pair_is_one_principal_and_one_fee_cap(self):
        trial=self.trial();intent=self.controller.intent(trial)
        self.assertEqual(5000,intent['principal_sat']);self.assertEqual(2000,intent['maximum_fee_sat'])
        self.assertEqual(trial,self.trial());self.store.verify_event_chain()
    def test_identical_recipient_or_foreign_input_is_refused_before_preparation(self):
        with self.assertRaises(InvariantError):self.trial(recipients=[{'actor':'actor-04','pubkey':self.keys['actor-04']}]*2)
        self.store.db.execute('UPDATE owner_key SET actor="actor-06" WHERE pubkey=?',(self.keys['actor-11'],))
        with self.assertRaises(InvariantError):self.trial()
    def test_missing_manifest_and_process_only_nonces_never_release(self):
        trial=self.trial();self.prepared(trial)
        with self.assertRaises(EvidenceGap):self.controller.release(trial)
        self.config.phase_enabled=True;self.config.phase_manifest_sha256='ee'*32
        with self.assertRaises(EvidenceGap):self.controller.release(trial)
        self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM action').fetchone()[0])
    def test_preparation_cannot_change_frozen_inputs_or_destinations(self):
        trial=self.trial()
        with self.assertRaises(InvariantError):self.controller.prepare(trial,{'trial_id':trial,'intent_hash':'ff'*32,'legs':[]})
    def test_two_independently_signed_competing_successors_are_an_incident(self):
        trial=self.trial();self.prepared(trial)
        for prefix,actor in [('d1','actor-04'),('d2','actor-06')]:self.add_output(prefix*32+':0',self.keys[actor],[self.coin],spending_txid=('c1' if prefix=='d1' else 'c2')*32)
        with self.assertRaises(InvariantError):self.controller.judge(trial)
        self.assertEqual('phase contradiction',self.store.get_meta('paused'))
    def test_equal_amount_unrelated_receipt_is_not_a_winner(self):
        trial=self.trial();self.prepared(trial)
        self.add_output('d1'*32+':0',self.keys['actor-04'],['bb'*32+':0'])
        verdict=self.controller.judge(trial);self.assertEqual('pending',verdict['state']);self.assertIn('signed_successor_linkage',verdict['unknowns'])
    def test_lost_reply_retains_fee_and_input_fence_without_second_release(self):
        trial=self.trial();self.config.phase_enabled=True;self.config.phase_manifest_sha256='ee'*32
        first=self.controller.release(trial);self.assertEqual(first,self.controller.release(trial))
        self.controller.reply(trial,'left',{'kind':'transport_unknown','wire_sha256':'a1'*32})
        self.assertEqual('pending',self.controller.judge(trial)['state'])
        self.assertEqual(98000,self.store.remaining_fee_budget())
    def test_round_acceptance_is_not_a_finished_refresh_winner(self):
        trial=self.trial('D18');intent=self.controller.intent(trial)
        self.assertEqual(['RequestArkoorCosign','SubmitPayment'],intent['rpcs'])
        result=self.controller.judge(trial);self.assertEqual('pending',result['state']);self.assertIn('round_forfeit_and_confirmed_outputs',result['unknowns'])
    def test_delayed_registration_requires_all_original_payouts_checked(self):
        trial=self.trial('D24',courier_actor='actor-12',saved_successor_ids=['d1'*32+':0'])
        self.add_output('d1'*32+':0',self.keys['actor-04'],[self.coin])
        with self.assertRaises(EvidenceGap):self.controller.release(trial)
        self.store.db.execute('INSERT INTO checked_settlement VALUES (?,?,?,?,?,?)',('d1'*32+':0','ee'*32,'actor-11','0014'+'77'*20,5000,'{}'))
        self.config.phase_enabled=True;self.config.phase_manifest_sha256='ee'*32
        action=self.controller.release(trial);row=self.store.db.execute('SELECT * FROM action WHERE id=?',(action,)).fetchone()
        self.assertEqual('actor-12',row['actor_id']);self.assertEqual('phase_register_saved',row['operation'])
        self.assertEqual(0,row['fee_reservation_sat'])
    def test_generic_refusal_does_not_qualify_delayed_delivery(self):
        trial=self.trial('D24',courier_actor='actor-12',saved_successor_ids=['d1'*32+':0'])
        self.add_output('d1'*32+':0',self.keys['actor-04'],[self.coin])
        self.controller.reply(trial,'delivery',{'kind':'generic_refusal','wire_sha256':'aa'*32})
        self.assertEqual('pending',self.controller.judge(trial)['state'])
    def test_remaining_cases_have_real_prerequisites_without_a_malformed_alias(self):
        from simulator.phase_trials import requirements
        for scenario in ['D19','D20','D26','D27','D28','D33','D34','D36']:
            self.assertTrue(requirements(scenario));self.assertNotIn('RawMalformed',' '.join(requirements(scenario)))

    def test_d17_queues_one_native_process_without_invented_restartable_nonces(self):
        trial=self.trial();self.config.phase_enabled=True;self.config.phase_manifest_sha256='ee'*32
        action=self.controller.release(trial)
        row=self.store.db.execute('SELECT * FROM action WHERE id=?',(action,)).fetchone()
        self.assertEqual('phase_execute_d17',row['operation']);self.assertEqual(2000,row['fee_reservation_sat'])
        self.assertTrue(json.loads(row['args'])['native_prepare_before_submit'])
        self.assertEqual(action,self.controller.release(trial))
    def test_native_preparations_must_bind_distinct_sessions_to_released_action(self):
        trial=self.trial();self.config.phase_enabled=True;self.config.phase_manifest_sha256='ee'*32
        action=self.controller.release(trial);prepared=self.prepared(trial,'single_process')
        with self.assertRaises(InvariantError):self.controller.native_prepared(trial,'foreign-action',prepared)
        for leg in prepared['legs']:leg['signing_session_sha256']='f1'*32
        with self.assertRaises(InvariantError):self.controller.native_prepared(trial,action,prepared)
    def checked_delivery(self,*,fresh=True,state='spent'):
        trial=self.trial('D24',courier_actor='actor-12',saved_successor_ids=['d1'*32+':0'])
        self.add_output('d1'*32+':0',self.keys['actor-04'],[self.coin])
        txid='ee'*32;script='0014'+'77'*20
        self.store.db.execute('INSERT INTO checked_settlement VALUES (?,?,?,?,?,?)',('d1'*32+':0',txid,'actor-11',script,5000,canonical({'row':{'fee_sat':100}})))
        self.store.db.execute('INSERT INTO settlement_check VALUES (?,?,?,?)',(txid,'amounts_checked',None,1))
        self.store.db.execute('INSERT INTO chain_payout VALUES (?,?)',(txid,canonical({'txid':txid,'confirmations':2,'fee_sat':150,'inputs':[{'amount_sat':10000}],'outputs':[{'script':script,'amount_sat':4900},{'script':'0014'+'88'*20,'amount_sat':4950}]})))
        self.config.phase_enabled=True;self.config.phase_manifest_sha256='ee'*32;action=self.controller.release(trial)
        self.store.db.execute('UPDATE action SET actual_fee_sat=0 WHERE id=?',(action,))
        self.controller.reply(trial,'delivery',{'kind':'expiry_settled_refusal','wire_sha256':'a1'*32})
        row={'id':'d1'*32+':0','spend_state':state,'onchain_spent_txid':'f0'*32,'oor_spent_txid':None,'spent_in_round':None,'offboarded_in':None}
        self.store.db.execute('INSERT INTO server_item VALUES (?,?,?,?)',('coins',row['id'],canonical(row),1e12 if fresh else 0))
        return trial
    def test_delayed_paid_successor_can_close_only_after_fresh_terminal_state_and_real_fee_identity(self):
        trial=self.checked_delivery();verdict=self.controller.judge(trial)
        self.assertEqual('verified',verdict['state']);self.assertEqual(4900,verdict['financial_identity']['confirmed_original_net_sat'])
        self.assertEqual(100,verdict['financial_identity']['recipient_fee_sat']);self.assertEqual(0,verdict['financial_identity']['new_payee_entitlement_sat'])
        self.assertEqual(verdict,self.controller.judge(trial));self.assertFalse(verdict['customer_traffic_credit'])
    def test_old_inventory_and_reactivated_successor_do_not_close_delayed_delivery(self):
        trial=self.checked_delivery(fresh=False);self.assertEqual('pending',self.controller.judge(trial)['state'])
        self.store.db.execute('UPDATE server_item SET observed_at=1e12');row=json.loads(self.store.db.execute('SELECT payload FROM server_item').fetchone()[0]);row['spend_state']='spendable'
        self.store.db.execute('UPDATE server_item SET payload=?',(canonical(row),))
        with self.assertRaises(InvariantError):self.controller.judge(trial)
    def winning_race(self,*,path_txid=None):
        trial=self.trial();self.config.phase_enabled=True;self.config.phase_manifest_sha256='ee'*32
        action=self.controller.release(trial);self.prepared(trial)
        self.add_output('d1'*32+':0',self.keys['actor-04'],[self.coin])
        proof=json.loads(self.store.db.execute('SELECT proof FROM owned_coin WHERE id=?',('d1'*32+':0',)).fetchone()[0])
        proof['path']=[{'txid':path_txid or 'c1'*32,'inputs':[self.coin]}]
        self.store.db.execute('UPDATE owned_coin SET proof=? WHERE id=?',(canonical(proof),'d1'*32+':0'))
        self.controller.reply(trial,'left',{'kind':'sdk_signed_successors','wire_sha256':'a1'*32,'submitted_at_ns':100,'reply_at_ns':300})
        self.controller.reply(trial,'right',{'kind':'protocol_refusal','wire_sha256':'a2'*32,'code':'InvalidArgument','rejected_coin_ids':[self.coin],'submitted_at_ns':200,'reply_at_ns':400})
        for identity,payload in [(self.coin,{'id':self.coin,'spend_state':'spent','oor_spent_txid':'c1'*32,'spent_in_round':None,'offboarded_in':None,'onchain_spent_txid':None}),('d1'*32+':0',{'id':'d1'*32+':0','spend_state':'spendable','oor_spent_txid':None,'spent_in_round':None,'offboarded_in':None,'onchain_spent_txid':None})]:
            self.store.db.execute('INSERT INTO server_item VALUES (?,?,?,?)',('coins',identity,canonical(payload),1e12))
        self.store.db.execute('UPDATE action SET actual_fee_sat=0 WHERE id=?',(action,))
        return trial
    def test_one_signed_registered_race_winner_closes_exact_principal_once(self):
        trial=self.winning_race();verdict=self.controller.judge(trial)
        self.assertEqual('verified',verdict['state']);self.assertEqual(5000,verdict['financial_identity']['registered_successor_sat'])
        self.assertEqual(0,verdict['financial_identity']['identity_residual_sat']);before=self.store.db.execute('SELECT count(*) FROM event').fetchone()[0]
        self.assertEqual(verdict,self.controller.judge(trial));self.assertEqual(before,self.store.db.execute('SELECT count(*) FROM event').fetchone()[0])
    def test_signed_ancestor_alone_does_not_link_exact_prepared_spend(self):
        trial=self.winning_race(path_txid='cf'*32);verdict=self.controller.judge(trial)
        self.assertEqual('pending',verdict['state']);self.assertIn('exact signed prepared spending path unavailable',verdict['unknowns'])
    def test_race_winner_cannot_coexist_with_original_payout(self):
        trial=self.winning_race();self.store.db.execute('INSERT INTO checked_settlement VALUES (?,?,?,?,?,?)',(self.coin,'ea'*32,'actor-11','0014'+'77'*20,5000,'{}'))
        with self.assertRaises(InvariantError):self.controller.judge(trial)
    def test_sequential_submissions_are_not_qualified_as_a_race(self):
        trial=self.winning_race();self.store.db.execute('DELETE FROM phase_reply WHERE trial_id=?',(trial,))
        self.controller.reply(trial,'left',{'kind':'sdk_signed_successors','wire_sha256':'a1'*32,'submitted_at_ns':100,'reply_at_ns':110})
        self.controller.reply(trial,'right',{'kind':'protocol_refusal','wire_sha256':'a2'*32,'code':'InvalidArgument','rejected_coin_ids':[self.coin],'submitted_at_ns':120,'reply_at_ns':130})
        self.assertEqual('pending',self.controller.judge(trial)['state'])
    def test_full_signed_ancestry_with_unrelated_prepared_spends_does_not_create_incident(self):
        trial=self.trial();self.prepared(trial)
        for prefix,actor in [('d1','actor-04'),('d2','actor-06')]:self.add_output(prefix*32+':0',self.keys[actor],[self.coin])
        self.assertEqual('pending',self.controller.judge(trial)['state']);self.assertIsNone(self.store.get_meta('paused'))
    def test_finite_loser_absence_is_required_not_paginated_inventory_absence(self):
        trial=self.winning_race();verdict=self.controller.judge(trial)
        self.assertEqual('pending',verdict['state']);self.assertIn('exact losing-output read-only reconciliation unavailable',verdict['unknowns'])
    def test_delayed_reply_must_match_the_actual_frozen_wallet_free_request(self):
        trial=self.checked_delivery();action=self.controller.row(trial)['release_action']
        self.controller.delivery_prepared(trial,action,{'wire_sha256':'a1'*32,'intent_hash':self.controller.intent(trial)['intent_hash'],'saved_successor_ids':['d1'*32+':0'],'original_wallet_opened':False})
        with self.assertRaises(InvariantError):self.controller.reply(trial,'delivery',{'kind':'expiry_settled_refusal','wire_sha256':'bb'*32})

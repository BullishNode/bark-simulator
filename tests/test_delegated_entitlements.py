"""Delegated intent lifetime: no wallet return or payout assumption is needed."""
import asyncio
import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from simulator.config import Config
from simulator.engine import Engine, initialize
from simulator.model import SIGNET_GENESIS, canonical
from simulator.store import Store
from simulator import entitlements
from simulator.model import InvariantError
from simulator.ownership import record_server_page
from simulator.settlements import check_payment


class DelegatedEntitlementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.s = Store(self.root, 'synthetic', 100000)
        initialize(self.s)
        self.actor = 'actor-08'
        self.input_key = '02' + '11' * 32
        self.output_key = '02' + '22' * 32
        self.binding = {'mailbox_pk':'mailbox','spk':'owner-script','seq':1,
                        'record_signature_valid':True,'key_link_signature_valid':True}
        self.s.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',
                          (self.input_key,self.actor,'mailbox','{}'))
        self.s.db.execute('INSERT INTO owner_record VALUES (?,?,?,?,?)',
                          (self.actor,'mailbox',1,'owner-script',canonical(self.binding)))
        proof = {'id':'input','user_pubkey':self.input_key,'amount_sat':10000,
                 'signed_path_valid':True,'anchor_confirmations':1,
                 'chain_anchor':'a'*64+':0','binding':self.binding}
        self.s.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',
                          ('input',self.input_key,10000,hashlib.sha256(bytes.fromhex('aa')).hexdigest(),'aa',canonical(proof)))
        self.proposal = {'committed_fee_sat':100,'participation':{
            'inputs':['aa'],'outputs':[{'amount':9900,'policy':'00'+self.output_key}]}}
        self.result = {'action_id':'delegated','status':'ok','actual_fee_sat':None,
                       'data':{'round_state_id':'1','committed_fee_sat':100,
                       'actual_fee_sat':None,'evidence':{'coins':[], 'movements':[],
                       'binding':self.binding}}}
        self.s.queue('delegated',self.actor,'H20','refresh_delegated',{},2000)
        self.s.event('driver_evidence',{'action_id':'delegated','operation':'refresh_delegated',
                                      'event':'refresh_proposal','data':self.proposal})
        config = Config(self.root,(),('mock-driver',),self.root/'wallets',SIGNET_GENESIS,
                        'test','test','test',100000,1,1,True)
        with patch('simulator.engine.json_command',AsyncMock(return_value=self.result)) as command:
            asyncio.run(Engine(config,self.s).dispatch_one())
        self.assertEqual(1,command.await_count)

    def tearDown(self):
        self.s.close()
        self.tmp.cleanup()

    def entitlement(self):
        if not self.s.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='delegated_entitlement'").fetchone():
            return None
        return self.s.db.execute("SELECT * FROM delegated_entitlement WHERE action_id='delegated'").fetchone()

    def test_completed_delegated_intent_is_durable_without_any_later_sync(self):
        self.assertEqual('completed',self.s.db.execute("SELECT state FROM action WHERE id='delegated'").fetchone()[0])
        row = self.entitlement()
        self.assertIsNotNone(row,'completed delegated refresh has no durable submitted entitlement')
        self.assertEqual('submitted',row['state'])
        self.assertEqual(['input'],json.loads(row['input_coin_ids']))
        self.assertIsNone(row['round_txid'])
        self.assertEqual([],json.loads(row['replacement_ids']))
        self.assertIsNone(self.s.db.execute("SELECT actual_fee_sat FROM action WHERE id='delegated'").fetchone()[0])
        self.assertEqual(0,self.s.db.execute("SELECT count(*) FROM action WHERE operation='sync'").fetchone()[0])

    def coin(self, name='replacement', pubkey=None, amount=9900, anchor=None, signed='bb', actor=None):
        pubkey = pubkey or self.output_key
        actor = actor or self.actor
        proof = {'id':name,'user_pubkey':pubkey,'amount_sat':amount,'signed_path_valid':True,
                 'anchor_confirmations':1,'chain_anchor':(anchor or 'b'*64)+':0',
                 'expiry_height':1200,'binding':self.binding,'arkoor_transition_count':0}
        self.s.db.execute('INSERT OR IGNORE INTO owner_key VALUES (?,?,?,?)',
                          (pubkey,actor,'mailbox','{}'))
        self.s.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',
                          (name,pubkey,amount,hashlib.sha256(bytes.fromhex(signed)).hexdigest(),signed,canonical(proof)))
        self.s.db.execute('INSERT INTO coin_observation VALUES (?,?,?,?)',
                          (name,'delegated','Unclaimed',time.time()))

    def server(self, name='input', **changes):
        coin = self.s.db.execute('SELECT * FROM owned_coin WHERE id=?',(name,)).fetchone()
        value = {'vtxo_id':name,'id':1,'expiry':json.loads(coin['proof']).get('expiry_height',1000),
                 'policy_type':'pubkey','signed_vtxo':coin['signed_vtxo'],'spend_state':'spent',
                 'spent_in_round':12,'oor_spent_txid':None,'offboarded_in':None,
                 'spent_in_round_txid':'b'*64,
                 'confirmed_height':None,'onchain_spent_txid':None,'onchain_spent_height':None}
        value.update(changes)
        record_server_page(self.s,{'kind':'coins','rows':[value],'next':None,'inventory_consistent':False})

    def replacements(self):
        self.coin()
        self.server()
        self.server('replacement',spend_state='unclaimed',spent_in_round=None)

    def collect(self):
        entitlements.collect(self.s,limit=100)

    def fee(self):
        return self.s.db.execute("SELECT actual_fee_sat FROM action WHERE id='delegated'").fetchone()[0]

    def checked_payout(self, name, txid=None, state='spendable'):
        coin = self.s.db.execute('SELECT * FROM owned_coin WHERE id=?',(name,)).fetchone()
        txid = txid or ('c'*64 if name=='input' else 'd'*64)
        row = {'id':name,'txid':txid,'fee_sat':0,'spk':'owner-script','tx_settlement_count':1,
               'pre_commit_rows':[{'spend_state':state,'spent_in_round':None,'oor_spent_txid':None,'offboarded_in':None}],
               'htlc':None}
        tx = {'txid':txid,'confirmations':2,'fee_sat':10,
              'inputs':[{'outpoint':'funding:0','amount_sat':coin['amount_sat']+20,'script':'funding'}],
              'outputs':[{'vout':0,'amount_sat':coin['amount_sat'],'script':'owner-script'},
                         {'vout':1,'amount_sat':10,'script':'operator-change'}]}
        self.s.db.execute("INSERT OR IGNORE INTO operator_script VALUES ('operator-change','{}')")
        checked = check_payment(self.s,[row],tx)
        owner = checked['owners'][0][1]
        self.s.db.execute('INSERT INTO chain_payout VALUES (?,?)',(txid,canonical(tx)))
        self.s.db.execute('INSERT INTO checked_settlement VALUES (?,?,?,?,?,?)',
            (name,txid,self.actor,'owner-script',coin['amount_sat'],canonical({'row':row,'owner':owner})))
        self.s.db.execute('INSERT INTO settlement_check VALUES (?,?,?,?)',
                          (txid,'amounts_checked',None,time.time()))

    def test_inventory_and_signed_successors_replace_without_any_wallet_return(self):
        self.replacements()
        self.s.set_online(self.actor,False)
        with patch('simulator.process.json_command',side_effect=AssertionError('no wallet or node command')):
            self.collect()
        row = self.entitlement()
        self.assertEqual('replaced',row['state'])
        self.assertEqual(['replacement'],json.loads(row['replacement_ids']))
        self.assertEqual('b'*64,row['round_txid'])
        self.assertEqual(12,row['server_round_id'])
        self.assertNotEqual(str(row['server_round_id']),row['round_txid'])
        self.assertFalse(self.s.online(self.actor))
        self.assertIsNone(self.fee(),'server inventory alone cannot close a refresh reserve')

    def test_stable_collection_does_not_emit_repeated_entitlement_events(self):
        self.replacements();self.collect()
        count = self.s.db.execute('SELECT count(*) FROM event').fetchone()[0]
        self.collect();self.collect()
        self.assertEqual(count,self.s.db.execute('SELECT count(*) FROM event').fetchone()[0])
        self.s.verify_event_chain()

    def test_missing_independent_replacement_proof_stays_submitted_and_reserved(self):
        self.server();self.collect()
        self.assertEqual('submitted',self.entitlement()['state'])
        self.assertIsNone(self.fee())

    def test_missing_partial_or_stale_round_inventory_cannot_replace(self):
        self.coin();self.server('replacement',spend_state='unclaimed',spent_in_round=None)
        self.collect();self.assertEqual('submitted',self.entitlement()['state'])
        self.server();self.s.db.execute("UPDATE server_item SET observed_at=0 WHERE id='input'")
        self.collect();self.assertEqual('submitted',self.entitlement()['state'])
        self.assertIsNone(self.fee())

    def test_round_id_string_is_not_a_real_server_round_id(self):
        self.replacements();self.server(spent_in_round='12');self.collect()
        self.assertEqual('submitted',self.entitlement()['state'])
        self.assertIsNone(self.fee())

    def test_changed_server_signed_bytes_or_expiry_do_not_replace(self):
        self.replacements();self.server('replacement',spend_state='unclaimed',spent_in_round=None,signed_vtxo='cc')
        self.collect();self.assertEqual('submitted',self.entitlement()['state'])
        self.server('replacement',spend_state='unclaimed',spent_in_round=None,expiry=1201)
        self.collect();self.assertEqual('submitted',self.entitlement()['state'])

    def test_foreign_replacement_owner_is_an_incident(self):
        self.replacements();self.s.db.execute("UPDATE owner_key SET actor='actor-02' WHERE pubkey=?",(self.output_key,))
        self.assertRaises(InvariantError,self.collect)
        self.assertIsNone(self.fee())

    def test_unconfirmed_or_incomplete_replacement_signature_stays_reserved(self):
        self.replacements()
        proof = json.loads(self.s.db.execute("SELECT proof FROM owned_coin WHERE id='replacement'").fetchone()[0])
        proof['anchor_confirmations'] = 0
        self.s.db.execute("UPDATE owned_coin SET proof=? WHERE id='replacement'",(canonical(proof),))
        self.collect();self.assertEqual('submitted',self.entitlement()['state']);self.assertIsNone(self.fee())

    def test_ambiguous_multiple_matching_signed_successors_stay_submitted(self):
        self.replacements();self.coin('other',signed='cc');self.server('other',spend_state='unclaimed',spent_in_round=None)
        self.collect();self.assertEqual('submitted',self.entitlement()['state']);self.assertIsNone(self.fee())

    def test_preexisting_output_is_not_attributed_to_a_new_refresh(self):
        self.replacements();self.s.db.execute("UPDATE coin_observation SET observed_at=0 WHERE coin_id='replacement'")
        self.collect();self.assertEqual('submitted',self.entitlement()['state'])

    def test_frozen_proposal_mutation_is_an_incident(self):
        proposal = {**self.proposal,'committed_fee_sat':101}
        self.s.db.execute("UPDATE event SET payload=? WHERE kind='driver_evidence' AND json_extract(payload,'$.event')='refresh_proposal'",
            (canonical({'action_id':'delegated','event':'refresh_proposal','data':proposal}),))
        self.assertRaises(InvariantError,self.collect);self.assertIsNone(self.fee())

    def test_duplicate_frozen_proposal_is_held_without_replacement_or_fee(self):
        self.s.event('driver_evidence',{'action_id':'delegated','event':'refresh_proposal','data':self.proposal})
        self.replacements();self.collect()
        self.assertEqual('submitted',self.entitlement()['state']);self.assertIsNone(self.fee())

    def test_successful_independent_movement_closes_fee_exactly_once(self):
        self.replacements()
        movement = {'id':'round','subsystem':'bark.round','status':'successful','payment_hash':None,
            'input_vtxos':['input'],'output_vtxos':['replacement'],'offchain_fee_sat':100,'effective_balance_sat':-100}
        self.s.db.execute('INSERT INTO movement_evidence VALUES (?,?,?)',(self.actor,'round',canonical(movement)))
        self.collect();self.assertEqual(100,self.fee());self.collect()
        self.assertEqual(1,self.s.db.execute("SELECT count(*) FROM event WHERE kind='client_fee_reconciled'").fetchone()[0])

    def test_complete_checked_replacement_payout_closes_actual_refresh_charge(self):
        self.replacements();self.checked_payout('replacement',state='unclaimed')
        self.s.set_online(self.actor,False)
        self.collect();self.assertEqual('paid',self.entitlement()['state']);self.assertEqual(100,self.fee())
        self.assertEqual('replacement',json.loads(self.entitlement()['evidence'])['payout_source'])
        self.collect();self.assertEqual(1,self.s.db.execute("SELECT count(*) FROM event WHERE kind='client_fee_reconciled'").fetchone()[0])
        self.assertFalse(self.s.online(self.actor))

    def test_checked_original_payout_proves_cancellation_charge_zero(self):
        self.checked_payout('input')
        self.collect();self.assertEqual('paid',self.entitlement()['state']);self.assertEqual(0,self.fee())
        evidence = json.loads(self.entitlement()['evidence'])
        self.assertEqual('original',evidence['payout_source'])
        self.assertEqual(10000,evidence['checked_payouts'][0]['gross_sat'])

    def test_pending_or_unconfirmed_payout_cannot_release_reserve(self):
        self.checked_payout('input');self.s.db.execute("UPDATE settlement_check SET state='pending'")
        self.collect();self.assertEqual('submitted',self.entitlement()['state']);self.assertIsNone(self.fee())
        self.s.db.execute("UPDATE settlement_check SET state='amounts_checked'")
        self.s.db.execute("UPDATE chain_payout SET payload=?",(canonical({'confirmations':0}),))
        self.collect();self.assertIsNone(self.fee())

    def test_original_and_successor_payouts_are_a_double_principal_incident(self):
        self.replacements();self.checked_payout('input');self.checked_payout('replacement',state='unclaimed')
        self.assertRaises(InvariantError,self.collect);self.assertIsNone(self.fee())

    def test_unknown_dispatch_never_releases_fee_even_with_checked_payment(self):
        self.checked_payout('input');self.s.db.execute("UPDATE action SET state='outcome_unknown' WHERE id='delegated'")
        self.collect();self.assertEqual('paid',self.entitlement()['state']);self.assertIsNone(self.fee())
        self.s.db.execute("UPDATE action SET state='completed' WHERE id='delegated'")
        self.collect();self.assertEqual(0,self.fee())

    def test_positive_server_cancellation_preserves_history_and_reservation(self):
        self.replacements();self.collect();self.assertEqual('replaced',self.entitlement()['state'])
        self.server(spend_state='spendable',spent_in_round=None)
        self.server('replacement',spend_state='spent',spent_in_round=None)
        self.collect();row = self.entitlement()
        self.assertEqual('submitted',row['state']);self.assertEqual([],json.loads(row['replacement_ids']))
        self.assertEqual(['replacement'],json.loads(row['evidence'])['cancelled_replacement']['replacement_ids'])
        self.assertIsNone(self.fee())
        self.assertIsNotNone(self.s.db.execute("SELECT 1 FROM owned_coin WHERE id='replacement'").fetchone())

    def test_missing_inventory_is_not_a_cancellation_claim(self):
        self.replacements();self.collect();self.s.db.execute('DELETE FROM server_item')
        self.collect();self.assertEqual('replaced',self.entitlement()['state']);self.assertIsNone(self.fee())

    def test_expired_unclaimed_report_links_only_proved_successors(self):
        self.replacements();self.collect()
        report = entitlements.unclaimed_expired_report(self.s,1201)
        self.assertEqual('partial_inventory',report['status'])
        self.assertEqual(1,report['expired_unclaimed_public_key_rows'])
        self.assertEqual(['delegated'],report['rows'][0]['delegated_action_ids'])
        self.assertEqual(9900,report['rows'][0]['signed_amount_sat'])
        self.assertFalse(report['inventory_consistent'])

    def test_no_inventory_report_is_missing_evidence_not_a_zero_target_claim(self):
        report = entitlements.unclaimed_expired_report(self.s,1201)
        self.assertEqual('no_inventory',report['status'])
        self.assertEqual([],report['rows'])

    def test_additive_schema_reopen_keeps_intent_and_original_evidence(self):
        original = self.s.db.execute("SELECT result FROM action WHERE id='delegated'").fetchone()[0]
        self.s.close();self.s = Store(self.root,'synthetic',100000)
        self.assertEqual('submitted',self.entitlement()['state'])
        self.assertEqual(original,self.s.db.execute("SELECT result FROM action WHERE id='delegated'").fetchone()[0])
        self.s.verify_event_chain()

    def intent(self, name, outputs, signed_inputs=None):
        proposal = {'committed_fee_sat':100,'participation':{
            'inputs':signed_inputs or ['aa'],'outputs':outputs}}
        self.s.queue(name,self.actor,'H20','refresh_delegated',{},2000)
        self.s.event('driver_evidence',{'action_id':name,'event':'refresh_proposal','data':proposal})
        self.s.db.execute("UPDATE action SET state='dispatched' WHERE id=?",(name,))
        self.s.finish(name,'completed',{'data':{'committed_fee_sat':100}},
                      on_completed=lambda:entitlements.record_submitted(self.s,name))
        return self.s.db.execute('SELECT * FROM delegated_entitlement WHERE action_id=?',(name,)).fetchone()

    def test_partial_replacement_set_and_partial_payout_keep_whole_reserve(self):
        second_key = '03'+'33'*32
        self.intent('split',[{'amount':5000,'policy':'00'+self.output_key},
                             {'amount':4900,'policy':'00'+second_key}])
        self.coin('first',amount=5000);self.server();self.server('first',spend_state='unclaimed',spent_in_round=None)
        self.checked_payout('first',state='unclaimed');self.collect()
        row = self.s.db.execute("SELECT * FROM delegated_entitlement WHERE action_id='split'").fetchone()
        self.assertEqual('submitted',row['state'])
        self.assertIsNone(self.s.db.execute("SELECT actual_fee_sat FROM action WHERE id='split'").fetchone()[0])
        self.coin('second',pubkey=second_key,amount=4900,signed='cc')
        self.server('second',spend_state='unclaimed',spent_in_round=None);self.collect()
        row = self.s.db.execute("SELECT * FROM delegated_entitlement WHERE action_id='split'").fetchone()
        self.assertEqual('replaced',row['state'])
        self.assertIsNone(self.s.db.execute("SELECT actual_fee_sat FROM action WHERE id='split'").fetchone()[0])

    def test_matching_output_values_with_different_anchors_do_not_replace(self):
        second_key = '03'+'33'*32
        self.intent('split',[{'amount':5000,'policy':'00'+self.output_key},
                             {'amount':4900,'policy':'00'+second_key}])
        self.coin('first',amount=5000);self.coin('second',pubkey=second_key,amount=4900,anchor='c'*64,signed='cc')
        self.server();self.server('first',spend_state='unclaimed',spent_in_round=None)
        self.server('second',spend_state='unclaimed',spent_in_round=None);self.collect()
        self.assertEqual('submitted',self.s.db.execute("SELECT state FROM delegated_entitlement WHERE action_id='split'").fetchone()[0])

    def test_all_original_inputs_must_name_the_same_numeric_server_round(self):
        self.coin('input2',pubkey=self.input_key,amount=10000,anchor='a'*64,signed='cc')
        self.intent('multi',[{'amount':19900,'policy':'00'+self.output_key}],['aa','cc'])
        self.coin('replacement',amount=19900,signed='dd')
        self.server();self.server('input2',spent_in_round=13)
        self.server('replacement',spend_state='unclaimed',spent_in_round=None);self.collect()
        self.assertEqual('submitted',self.s.db.execute("SELECT state FROM delegated_entitlement WHERE action_id='multi'").fetchone()[0])

    def test_two_unresolved_intents_cannot_claim_the_same_key_value_successor(self):
        self.intent('duplicate',[{'amount':9900,'policy':'00'+self.output_key}])
        self.replacements();self.collect()
        self.assertEqual('submitted',self.entitlement()['state'])
        self.assertEqual('submitted',self.s.db.execute("SELECT state FROM delegated_entitlement WHERE action_id='duplicate'").fetchone()[0])
        self.assertIsNone(self.fee())

    def test_missing_original_proof_is_tracked_as_an_unproved_intent(self):
        self.s.db.execute("DELETE FROM owned_coin WHERE id='input'")
        self.intent('unproved',[{'amount':9800,'policy':'00'+'03'+'33'*32}])
        row = self.s.db.execute("SELECT * FROM delegated_entitlement WHERE action_id='unproved'").fetchone()
        self.assertEqual('submitted',row['state'])
        self.assertFalse(json.loads(row['evidence'])['input_ownership_verified'])
        self.assertEqual([],json.loads(row['input_coin_ids']))

    def test_existing_successful_movement_and_original_payout_are_a_contradiction(self):
        self.replacements();self.checked_payout('input')
        movement = {'id':'round','subsystem':'bark.round','status':'successful','payment_hash':None,
            'input_vtxos':['input'],'output_vtxos':['replacement'],'offchain_fee_sat':100,'effective_balance_sat':-100}
        self.s.db.execute('INSERT INTO movement_evidence VALUES (?,?,?)',(self.actor,'round',canonical(movement)))
        self.assertRaises(InvariantError,self.collect)
        self.assertIsNone(self.fee())

    def test_no_input_delegate_is_not_a_fictitious_entitlement(self):
        self.s.queue('empty',self.actor,'H20','refresh_delegated',{},2000)
        self.s.db.execute("UPDATE action SET state='dispatched' WHERE id='empty'")
        self.s.finish('empty','completed',{'data':{'no_inputs':True}},0,
                      on_completed=lambda:entitlements.record_submitted(self.s,'empty'))
        self.collect()
        self.assertIsNone(self.s.db.execute("SELECT 1 FROM delegated_entitlement WHERE action_id='empty'").fetchone())

    def test_foreign_input_pauses_completion_hook_without_losing_response(self):
        self.s.db.execute("UPDATE owner_key SET actor='actor-02' WHERE pubkey=?",(self.input_key,))
        self.intent('foreign',[{'amount':9900,'policy':'00'+self.output_key}])
        self.assertIsNotNone(self.s.get_meta('paused'))
        self.assertEqual('completed',self.s.db.execute("SELECT state FROM action WHERE id='foreign'").fetchone()[0])
        self.assertIsNone(self.s.db.execute("SELECT actual_fee_sat FROM action WHERE id='foreign'").fetchone()[0])

    def test_fee_ceiling_and_immutable_proof_digest_remain_hard_guards(self):
        self.s.db.execute("UPDATE action SET fee_reservation_sat=99 WHERE id='delegated'")
        self.assertRaises(InvariantError,self.collect)
        self.s.db.execute("UPDATE action SET fee_reservation_sat=2000 WHERE id='delegated'")
        self.s.db.execute("UPDATE owned_coin SET signed_hash='changed' WHERE id='input'")
        self.assertRaises(InvariantError,self.collect);self.assertIsNone(self.fee())

    def test_registered_forfeit_txid_does_not_look_like_a_foreign_arkoor_spend(self):
        self.replacements();self.server(oor_spent_txid='forfeit-transaction')
        self.collect();self.assertEqual('replaced',self.entitlement()['state'])

    def test_unclaimed_inventory_without_signed_proof_stays_unattributed(self):
        value = {'vtxo_id':'unknown','expiry':1000,'spend_state':'unclaimed','policy_type':'pubkey','signed_vtxo':'cc'}
        record_server_page(self.s,{'kind':'coins','rows':[value],'next':None,'inventory_consistent':False})
        report = entitlements.unclaimed_expired_report(self.s,1001)
        self.assertIsNone(report['rows'][0]['actor'])
        self.assertIsNone(report['rows'][0]['signed_amount_sat'])
        self.assertEqual([],report['rows'][0]['delegated_action_ids'])

    def test_legacy_missing_round_mapping_cannot_attribute_unrelated_receive(self):
        self.replacements();self.server(spent_in_round_txid=None)
        self.collect();self.assertEqual('submitted',self.entitlement()['state']);self.assertIsNone(self.fee())

    def test_wrong_round_anchor_and_oor_successor_cannot_close_from_payout(self):
        self.replacements();self.checked_payout('replacement',state='unclaimed')
        self.server(spent_in_round_txid='c'*64);self.collect()
        self.assertEqual('submitted',self.entitlement()['state']);self.assertIsNone(self.fee())
        self.server()
        proof = json.loads(self.s.db.execute("SELECT proof FROM owned_coin WHERE id='replacement'").fetchone()[0])
        proof['arkoor_transition_count']=1
        self.s.db.execute("UPDATE owned_coin SET proof=? WHERE id='replacement'",(canonical(proof),))
        self.collect();self.assertEqual('submitted',self.entitlement()['state']);self.assertIsNone(self.fee())

    def test_legacy_signed_proof_without_transition_kind_retains_inventory_only_fee(self):
        self.replacements()
        proof = json.loads(self.s.db.execute("SELECT proof FROM owned_coin WHERE id='replacement'").fetchone()[0])
        proof.pop('arkoor_transition_count')
        self.s.db.execute("UPDATE owned_coin SET proof=? WHERE id='replacement'",(canonical(proof),))
        self.collect();self.assertEqual('submitted',self.entitlement()['state']);self.assertIsNone(self.fee())

    def test_legacy_producers_can_use_the_existing_checked_round_movement(self):
        self.replacements();self.server(spent_in_round_txid=None)
        proof = json.loads(self.s.db.execute("SELECT proof FROM owned_coin WHERE id='replacement'").fetchone()[0])
        proof.pop('arkoor_transition_count')
        self.s.db.execute("UPDATE owned_coin SET proof=? WHERE id='replacement'",(canonical(proof),))
        movement = {'id':'round','subsystem':'bark.round','status':'successful','payment_hash':None,
            'input_vtxos':['input'],'output_vtxos':['replacement'],'offchain_fee_sat':100,'effective_balance_sat':-100}
        self.s.db.execute('INSERT INTO movement_evidence VALUES (?,?,?)',(self.actor,'round',canonical(movement)))
        self.collect()
        self.assertEqual('replaced',self.entitlement()['state']);self.assertEqual(100,self.fee())
        self.assertIn('SDK round movement',json.loads(self.entitlement()['evidence'])['round_mapping_scope'])

    def test_explicit_round_anchor_contradiction_is_not_hidden_by_movement_fallback(self):
        self.replacements();self.server(spent_in_round_txid='c'*64)
        movement = {'id':'round','subsystem':'bark.round','status':'successful','payment_hash':None,
            'input_vtxos':['input'],'output_vtxos':['replacement'],'offchain_fee_sat':100,'effective_balance_sat':-100}
        self.s.db.execute('INSERT INTO movement_evidence VALUES (?,?,?)',(self.actor,'round',canonical(movement)))
        self.collect()
        self.assertEqual('submitted',self.entitlement()['state'])
        self.assertIn('contradicts',json.loads(self.entitlement()['evidence'])['gap'])
        self.assertEqual(100,self.fee(),'the existing independent fee proof remains valid')


if __name__ == '__main__':
    unittest.main()

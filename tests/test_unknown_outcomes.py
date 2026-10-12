"""Unknown money requests remain held until a complete positive proof exists."""
import hashlib,json,tempfile,time,unittest
from pathlib import Path
from simulator.store import Store
from simulator.engine import initialize
from simulator.model import canonical
from simulator import unknown_outcomes

class UnknownOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.s=Store(Path(self.tmp.name),'synthetic',1000000);initialize(self.s)
        self.actor='actor-08';self.key='02'+'11'*32;self.output_key='02'+'22'*32
        self.binding={'mailbox_pk':'mailbox','seq':1,'spk':'owner-script','record_signature_valid':True,'key_link_signature_valid':True}
        self.s.db.execute('INSERT INTO owner_record VALUES (?,?,?,?,?)',(self.actor,'mailbox',1,'owner-script',canonical(self.binding)))
        self.coin('original',self.key,10000,'aa')
        self.coin('replacement',self.output_key,9900,'bb')
        self.s.queue('lost',self.actor,'H17','refresh',{},2000)
        self.s.db.execute("UPDATE action SET state='outcome_unknown',result=? WHERE id='lost'",(canonical({'reason':'TimeoutError'}),))
        self.original_time=self.row()['updated_at']
        self.proposal={'committed_fee_sat':100,'participation':{'inputs':['aa'],'outputs':[{'amount':9900,'policy':'00'+self.output_key}]}}
        self.s.event('driver_evidence',{'action_id':'lost','event':'refresh_proposal','data':self.proposal})
    def coin(self,name,key,amount,signed,actor=None):
        actor=actor or self.actor
        self.s.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',(key,actor,'mailbox','{}'))
        proof={'id':name,'user_pubkey':key,'amount_sat':amount,'signed_path_valid':True,'anchor_confirmations':1,'chain_anchor':'a'*64+':0','binding':self.binding}
        self.s.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',(name,key,amount,hashlib.sha256(bytes.fromhex(signed)).hexdigest(),signed,canonical(proof)))
    def movement(self):
        self.s.db.execute('INSERT INTO movement_evidence VALUES (?,?,?)',(self.actor,'round',canonical({'id':'round','subsystem':'bark.round','status':'successful','payment_hash':None,
            'input_vtxos':['original'],'output_vtxos':['replacement'],'offchain_fee_sat':100,'effective_balance_sat':-100})))
    def row(self):return self.s.db.execute("SELECT * FROM action WHERE id='lost'").fetchone()
    def tearDown(self):self.s.close();self.tmp.cleanup()
    def test_complete_signed_success_resolves_unknown_once_without_replaying_request(self):
        self.movement();self.s.set_online(self.actor,False)
        self.assertTrue(unknown_outcomes.resolve(self.s,'lost'),'complete independent success leaves the actor indefinitely unknown')
        row=self.row();self.assertEqual('completed',row['state']);self.assertEqual(100,row['actual_fee_sat'])
        self.assertEqual(self.original_time,row['updated_at'],'archived reconciliation must not manufacture current traffic')
        self.assertFalse(self.s.online(self.actor));self.assertFalse(unknown_outcomes.resolve(self.s,'lost'))
        self.assertEqual(1,self.s.db.execute("SELECT count(*) FROM event WHERE kind='unknown_outcome_resolved'").fetchone()[0])
        self.assertEqual(1,self.s.db.execute('SELECT count(*) FROM action').fetchone()[0])
        self.assertEqual({'reason':'TimeoutError'},json.loads(row['result'])['resolution']['original_result'])



    def test_missing_pending_failed_or_partial_movement_never_releases_reservation(self):
        before=dict(self.row())
        self.assertFalse(unknown_outcomes.resolve(self.s,'lost'))
        self.movement()
        for status in ('pending','failed'):
            m=json.loads(self.s.db.execute('SELECT payload FROM movement_evidence').fetchone()[0]);m['status']=status
            self.s.db.execute('UPDATE movement_evidence SET payload=?',(canonical(m),))
            self.assertFalse(unknown_outcomes.resolve(self.s,'lost'));self.assertEqual(before,dict(self.row()))
        self.s.db.execute("UPDATE movement_evidence SET payload=json_set(payload,'$.status','successful')")
        self.s.db.execute("DELETE FROM owned_coin WHERE id='replacement'")
        self.assertFalse(unknown_outcomes.resolve(self.s,'lost'));self.assertEqual(before,dict(self.row()))
    def test_foreign_principal_and_signed_identity_contradictions_are_atomic_incidents(self):
        from simulator.model import InvariantError
        self.movement();before=dict(self.row())
        self.s.db.execute("UPDATE owner_key SET actor='actor-02' WHERE pubkey=?",(self.output_key,))
        with self.assertRaises(InvariantError):unknown_outcomes.resolve(self.s,'lost')
        self.assertEqual(before,dict(self.row()))
        self.s.db.execute('UPDATE owner_key SET actor=? WHERE pubkey=?',(self.actor,self.output_key))
        proof=json.loads(self.s.db.execute("SELECT proof FROM owned_coin WHERE id='replacement'").fetchone()[0]);proof['amount_sat']=9899
        self.s.db.execute("UPDATE owned_coin SET proof=? WHERE id='replacement'",(canonical(proof),))
        with self.assertRaises(InvariantError):unknown_outcomes.resolve(self.s,'lost')
        self.assertEqual(before,dict(self.row()))
    def test_missing_signature_and_unconfirmed_backing_are_not_success(self):
        self.movement();before=dict(self.row())
        for change in ({'signed_path_valid':False},{'anchor_confirmations':0},{'binding':{}}):
            old=self.s.db.execute("SELECT proof FROM owned_coin WHERE id='replacement'").fetchone()[0]
            self.s.db.execute("UPDATE owned_coin SET proof=? WHERE id='replacement'",(canonical({**json.loads(old),**change}),))
            self.assertFalse(unknown_outcomes.resolve(self.s,'lost'));self.assertEqual(before,dict(self.row()))
            self.s.db.execute("UPDATE owned_coin SET proof=? WHERE id='replacement'",(old,))
    def test_signed_bytes_changed_multiple_successes_and_another_charge_never_resolve(self):
        from simulator.model import InvariantError
        self.movement()
        self.s.db.execute("UPDATE owned_coin SET signed_hash='bad' WHERE id='replacement'")
        with self.assertRaises(InvariantError):unknown_outcomes.resolve(self.s,'lost')
        self.s.db.execute("UPDATE owned_coin SET signed_hash=? WHERE id='replacement'",(hashlib.sha256(bytes.fromhex('bb')).hexdigest(),))
        m=json.loads(self.s.db.execute('SELECT payload FROM movement_evidence').fetchone()[0]);m['id']='another'
        self.s.db.execute('INSERT INTO movement_evidence VALUES (?,?,?)',(self.actor,'another',canonical(m)))
        with self.assertRaises(InvariantError):unknown_outcomes.resolve(self.s,'lost')
        self.s.db.execute("DELETE FROM movement_evidence WHERE movement_id='another'")
        self.s.event('client_fee_reconciled',{'action_id':'other','actor':self.actor,'movement_id':'round','actual_fee_sat':100})
        with self.assertRaises(InvariantError):unknown_outcomes.resolve(self.s,'lost')
        self.assertEqual('outcome_unknown',self.row()['state'])
    def test_dispatched_failed_unsupported_and_paused_rows_are_preserved(self):
        self.movement()
        for state in ('dispatched','failed','completed'):
            self.s.db.execute("UPDATE action SET state=? WHERE id='lost'",(state,));before=dict(self.row())
            self.assertFalse(unknown_outcomes.resolve(self.s,'lost'));self.assertEqual(before,dict(self.row()))
        self.s.queue('unsupported',self.actor,'H17','unsupported',{},2000)
        self.s.db.execute("UPDATE action SET state='outcome_unknown' WHERE id='unsupported'")
        self.assertFalse(unknown_outcomes.resolve(self.s,'unsupported'))
        self.s.db.execute("UPDATE action SET state='outcome_unknown' WHERE id='lost'")
        self.s.db.execute("INSERT INTO meta VALUES ('paused','incident')")
        self.assertFalse(unknown_outcomes.resolve(self.s,'lost'));self.assertIsNone(self.row()['actual_fee_sat'])
    def test_contradictory_native_fee_does_not_get_replaced_by_inference(self):
        from simulator.model import InvariantError
        self.movement()
        self.s.event('driver_response',{'action_id':'lost','response':{'action_id':'lost','status':'ok','actual_fee_sat':999,'data':{'committed_fee_sat':100}}})
        with self.assertRaises(InvariantError):unknown_outcomes.resolve(self.s,'lost')
        self.assertEqual('outcome_unknown',self.row()['state'])
    def test_resolved_actor_metadata_requires_a_fresh_read_and_preserves_absence_profile(self):
        self.movement();profile={'coin_ids':['original'],'original_wallet_must_stay_closed':True}
        self.s.db.execute('UPDATE actor SET details=? WHERE id=?',(canonical({'permanent_absence':profile,'registered_spendable_sat':10000}),self.actor))
        self.s.set_online(self.actor,False);before=[dict(r) for r in self.s.db.execute('SELECT * FROM owned_coin')]
        self.assertTrue(unknown_outcomes.resolve(self.s,'lost'))
        d=json.loads(self.s.db.execute('SELECT details FROM actor WHERE id=?',(self.actor,)).fetchone()[0])
        self.assertEqual(profile,d['permanent_absence']);self.assertTrue(d['needs_sync']);self.assertEqual(0,d['snapshot_at'])
        self.assertEqual(before,[dict(r) for r in self.s.db.execute('SELECT * FROM owned_coin')]);self.assertTrue(self.s.verify_event_chain())

class LightningUnknownTests(unittest.TestCase):
    coin=UnknownOutcomeTests.coin
    row=UnknownOutcomeTests.row
    tearDown=UnknownOutcomeTests.tearDown
    def setUp(self):
        UnknownOutcomeTests.setUp(self);self.hash='a'*64
        self.s.db.execute('DELETE FROM action');self.s.db.execute('DELETE FROM event')
        self.s.queue('lost',self.actor,'H40','pay_invoice',{'amount_sat':4000},2000)
        self.s.db.execute("UPDATE action SET state='outcome_unknown',result=? WHERE id='lost'",(canonical({'reason':'TimeoutError'}),))
        self.original_time=self.row()['updated_at']
        self.s.event('driver_evidence',{'action_id':'lost','event':'lightning_proposal','data':{'payment_hash':self.hash,'input_vtxo_ids':['original'],'amount_sat':4000,'fee_ceiling_sat':2000}})
        proof=json.loads(self.s.db.execute("SELECT proof FROM owned_coin WHERE id='replacement'").fetchone()[0]);proof['amount_sat']=5900
        self.s.db.execute("UPDATE owned_coin SET amount_sat=5900,proof=? WHERE id='replacement'",(canonical(proof),))
    def status(self,state='succeeded'):
        return {'action_id':'unknown-status:lost','status':'ok','actual_fee_sat':0,'data':{'payment_hash':self.hash,'state':state,'read_only':True,'success_preimage_hash_valid':state=='succeeded'}}
    def movement(self):
        self.s.db.execute('INSERT INTO movement_evidence VALUES (?,?,?)',(self.actor,'send',canonical({'id':'send','subsystem':'bark.lightning_send','status':'successful','payment_hash':self.hash,
            'input_vtxos':['original'],'output_vtxos':['replacement'],'offchain_fee_sat':100,'effective_balance_sat':-4100})))
    # Inherited generic monetary tests use refresh-specific evidence. Keep the
    # focused Lightning contract separate from those fixtures.
    def test_complete_signed_success_resolves_unknown_once_without_replaying_request(self):
        self.movement();self.s.set_online(self.actor,False)
        self.assertTrue(unknown_outcomes.resolve(self.s,'lost',payment_status=self.status()))
        self.assertEqual(100,self.row()['actual_fee_sat']);self.assertFalse(self.s.online(self.actor))
        self.assertFalse(unknown_outcomes.resolve(self.s,'lost',payment_status=self.status()))
    def test_status_without_signed_movement_and_failed_or_silent_status_remain_unknown(self):
        self.assertFalse(unknown_outcomes.resolve(self.s,'lost',payment_status=self.status()))
        self.movement()
        for status in (None,self.status('pending'),self.status('failed')):
            self.assertFalse(unknown_outcomes.resolve(self.s,'lost',payment_status=status));self.assertIsNone(self.row()['actual_fee_sat'])
    def test_wrong_hash_query_id_charge_or_preimage_flag_are_incidents(self):
        from simulator.model import InvariantError
        self.movement()
        for update in ({'payment_hash':'b'*64},{'read_only':False},{'success_preimage_hash_valid':False}):
            status=self.status();status['data'].update(update)
            with self.subTest(update=update),self.assertRaises(InvariantError):unknown_outcomes.resolve(self.s,'lost',payment_status=status)
        for update in ({'action_id':'wrong'},{'actual_fee_sat':1},{'actual_fee_sat':False}):
            with self.subTest(update=update),self.assertRaises(InvariantError):unknown_outcomes.resolve(self.s,'lost',payment_status={**self.status(),**update})
    def test_collection_only_issues_readonly_hash_query_without_actor_wallet(self):
        import asyncio
        from types import SimpleNamespace
        from unittest.mock import AsyncMock,patch
        self.movement();self.s.set_online(self.actor,False)
        config=SimpleNamespace(driver_command=('native',),expected_server_pubkey='server')
        command=AsyncMock(return_value=self.status())
        with patch('simulator.unknown_outcomes.json_command',command):asyncio.run(unknown_outcomes.collect(self.s,config))
        request=command.await_args.args[1]
        self.assertEqual('lightning_payment_status',request['operation']);self.assertIsNone(request['actor_dir']);self.assertEqual(0,request['maximum_fee_sat'])
        self.assertFalse(self.s.online(self.actor));self.assertEqual(100,self.row()['actual_fee_sat'])
    def test_native_status_transport_failure_preserves_unknown_and_full_reservation(self):
        import asyncio
        from types import SimpleNamespace
        from unittest.mock import AsyncMock,patch
        self.movement();before=dict(self.row());self.s.set_online(self.actor,False)
        config=SimpleNamespace(driver_command=('native',),expected_server_pubkey='server')
        with patch('simulator.unknown_outcomes.json_command',AsyncMock(side_effect=TimeoutError)):
            asyncio.run(unknown_outcomes.collect(self.s,config))
        self.assertEqual(before,dict(self.row()));self.assertFalse(self.s.online(self.actor))
        self.assertEqual(0,self.s.db.execute("SELECT count(*) FROM event WHERE kind='unknown_outcome_resolved'").fetchone()[0])



class ReadUnknownTests(unittest.TestCase):
    coin=UnknownOutcomeTests.coin
    row=UnknownOutcomeTests.row
    tearDown=UnknownOutcomeTests.tearDown
    def setUp(self):
        UnknownOutcomeTests.setUp(self)
        self.s.db.execute('DELETE FROM action');self.s.db.execute('DELETE FROM event')
        self.s.queue('lost',self.actor,'H01','snapshot',{},0)
        self.s.db.execute("UPDATE action SET state='outcome_unknown',result='{}' WHERE id='lost'")
        self.frame={'coins':[],'movements':[],'binding':self.binding}
    def reply(self,before=True,after=True):
        if before:self.s.event('driver_evidence',{'action_id':'lost','event':'client_evidence_before','data':{'fresh':True,'evidence':self.frame}})
        if after:self.s.event('driver_evidence',{'action_id':'lost','event':'client_evidence_after','data':{'fresh':True,'evidence':self.frame}})
        self.s.event('driver_response',{'action_id':'lost','response':{'action_id':'lost','status':'ok','actual_fee_sat':0,'data':{'balance':{'spendable_sat':0}}}})
    def test_native_ack_and_genuine_boundaries_resolve_read_without_updating_activity_time(self):
        self.reply();before=self.row()['updated_at'];self.s.set_online(self.actor,False)
        self.assertTrue(unknown_outcomes.resolve(self.s,'lost'))
        self.assertEqual(before,self.row()['updated_at']);self.assertFalse(self.s.online(self.actor));self.assertEqual(0,self.row()['actual_fee_sat'])
    def test_reply_without_either_fresh_boundary_is_not_reconstructed_from_old_inventory(self):
        self.reply(before=False);self.assertFalse(unknown_outcomes.resolve(self.s,'lost'))
    def test_changed_wallet_inventory_or_gap_never_becomes_read_success(self):
        self.s.event('driver_evidence',{'action_id':'lost','event':'client_evidence_before','data':{'fresh':True,'evidence':self.frame}})
        self.s.event('driver_evidence',{'action_id':'lost','event':'client_evidence_after','data':{'fresh':True,'evidence':{**self.frame,'movements':[{'id':'new'}]}}})
        self.s.event('driver_response',{'action_id':'lost','response':{'action_id':'lost','status':'ok','actual_fee_sat':0,'data':{}}})
        self.assertFalse(unknown_outcomes.resolve(self.s,'lost'))
    def test_authorizing_actor_arguments_and_budget_cannot_mutate(self):
        from simulator.model import InvariantError
        self.reply()
        for field,value in [('actor_id','actor-02'),('args','{"changed":true}'),('fee_reservation_sat',1000)]:
            old=self.row()[field];self.s.db.execute('UPDATE action SET '+field+'=? WHERE id=?',(value,'lost'))
            with self.subTest(field=field),self.assertRaises(InvariantError):unknown_outcomes.resolve(self.s,'lost')
            self.s.db.execute('UPDATE action SET '+field+'=? WHERE id=?',(old,'lost'))

class ArkUnknownTests(unittest.TestCase):
    coin=UnknownOutcomeTests.coin
    row=UnknownOutcomeTests.row
    tearDown=UnknownOutcomeTests.tearDown
    def setUp(self):
        UnknownOutcomeTests.setUp(self)
        self.s.db.execute('DELETE FROM action');self.s.db.execute('DELETE FROM event')
        self.recipient='actor-09';self.receipt_key='02'+'33'*32
        self.s.db.execute('INSERT INTO owner_record VALUES (?,?,?,?,?)',(self.recipient,'recipient-mailbox',1,'recipient-script',canonical({})))
        self.s.queue('address',self.recipient,'H07','address',{},0)
        self.s.db.execute("UPDATE action SET state='completed',result=? WHERE id='address'",(canonical({'data':{'address':'destination','user_pubkey':self.receipt_key}}),))
        self.s.queue('lost',self.actor,'H08','send_arkoor',{'amount_sat':1000,'destination':'destination','recipient_actor':self.recipient},2000)
        self.s.db.execute("UPDATE action SET state='outcome_unknown',result='{}' WHERE id='lost'")
        self.s.event('driver_evidence',{'action_id':'lost','event':'arkoor_request','data':{'destination':'destination','amount_sat':1000,'input_vtxo_ids':['original']}})
        proof=json.loads(self.s.db.execute("SELECT proof FROM owned_coin WHERE id='replacement'").fetchone()[0]);proof['amount_sat']=9000
        self.s.db.execute("UPDATE owned_coin SET amount_sat=9000,proof=? WHERE id='replacement'",(canonical(proof),))
        receipt='c'*64+':0';self.receipt=receipt
        self.s.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',(self.receipt_key,self.recipient,'recipient-mailbox','{}'))
        proof={'id':receipt,'user_pubkey':self.receipt_key,'amount_sat':1000,'signed_path_valid':True,'anchor_confirmations':1,
            'binding':{'mailbox_pk':'recipient-mailbox','seq':1,'spk':'recipient-script','record_signature_valid':True,'key_link_signature_valid':True},
            'path':[{'txid':'c'*64,'output_index':0,'inputs':['original'],'output_amount_sat':1000,'output_script':'receipt-script'}]}
        self.s.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',(receipt,self.receipt_key,1000,hashlib.sha256(bytes.fromhex('cc')).hexdigest(),'cc',canonical(proof)))
        for actor,movement in [(self.actor,{'id':'send','subsystem':'bark.arkoor','status':'successful','input_vtxos':['original'],'output_vtxos':['replacement'],'offchain_fee_sat':0,'effective_balance_sat':-1000}),
            (self.recipient,{'id':'receive','subsystem':'bark.arkoor','status':'successful','input_vtxos':[],'output_vtxos':[receipt],'offchain_fee_sat':0,'effective_balance_sat':1000})]:
            self.s.db.execute('INSERT INTO movement_evidence VALUES (?,?,?)',(actor,movement['id'],canonical(movement)))
        self.s.set_online(self.recipient,False)
    def test_directly_linked_receipt_and_exact_change_resolve_ark_without_opening_receiver(self):
        self.assertTrue(unknown_outcomes.resolve(self.s,'lost'));self.assertEqual(0,self.row()['actual_fee_sat']);self.assertFalse(self.s.online(self.recipient))
    def test_equal_amount_unrelated_or_partial_receipts_never_resolve(self):
        proof=json.loads(self.s.db.execute('SELECT proof FROM owned_coin WHERE id=?',(self.receipt,)).fetchone()[0]);proof['path'][0]['inputs']=['unrelated']
        self.s.db.execute('UPDATE owned_coin SET proof=? WHERE id=?',(canonical(proof),self.receipt))
        self.assertFalse(unknown_outcomes.resolve(self.s,'lost'));self.assertIsNone(self.row()['actual_fee_sat'])
    def test_a_receipt_cannot_resolve_a_second_send_and_inputs_cannot_be_reused(self):
        self.s.event('ark_transfer_verified',{'action_id':'other','recipient_actor':self.recipient,'receipt_movement_id':'receive'})
        self.assertFalse(unknown_outcomes.resolve(self.s,'lost'))
        self.s.db.execute("DELETE FROM event WHERE kind='ark_transfer_verified'")
        self.s.event('driver_evidence',{'action_id':'other','event':'arkoor_request','data':{'input_vtxo_ids':['original']}})
        self.assertFalse(unknown_outcomes.resolve(self.s,'lost'))



class ChainUnknownTests(unittest.TestCase):
    coin=UnknownOutcomeTests.coin
    row=UnknownOutcomeTests.row
    tearDown=UnknownOutcomeTests.tearDown
    def setUp(self):
        UnknownOutcomeTests.setUp(self)
        self.s.db.execute('DELETE FROM action');self.s.db.execute('DELETE FROM event')
    def action(self,operation,args):
        self.s.queue('lost',self.actor,'H01',operation,args,2000)
        self.s.db.execute("UPDATE action SET state='outcome_unknown',result='{}' WHERE id='lost'")
    def native(self,data):
        self.s.event('driver_response',{'action_id':'lost','response':{'action_id':'lost','status':'ok','actual_fee_sat':None,'data':data}})
    def board(self):
        self.action('board',{'amount_sat':11000});txid='a'*64
        self.s.event('driver_evidence',{'action_id':'lost','event':'board_proposal','data':{'funding_txid':txid,'amount_sat':11000,'estimated_service_fee_sat':1000,'planned_mining_fee_sat':100}})
        self.native({'board':{'vtxos':['original']},'sdk_service_fee_sat':1000})
        return {txid:{'txid':txid,'confirmations':2,'inputs':[{'outpoint':'fund:0','amount_sat':11100,'script':'funding'}],
            'outputs':[{'vout':0,'amount_sat':11000,'script':'board-script'}],'fee_sat':100}}
    def test_signed_board_and_its_confirmed_exact_funding_transaction_resolve(self):
        txs=self.board();self.assertTrue(unknown_outcomes.resolve(self.s,'lost',txs));self.assertEqual(1100,self.row()['actual_fee_sat'])
    def test_missing_or_unconfirmed_board_transactions_leave_unknown_and_reserved(self):
        txs=self.board();self.assertFalse(unknown_outcomes.resolve(self.s,'lost'))
        txs['a'*64]['confirmations']=0;self.assertFalse(unknown_outcomes.resolve(self.s,'lost',txs));self.assertIsNone(self.row()['actual_fee_sat'])
    def test_changed_board_output_fee_or_anchor_are_incidents(self):
        from simulator.model import InvariantError
        txs=self.board();txs['a'*64]['outputs'][0]['amount_sat']=10900;txs['a'*64]['fee_sat']=200
        with self.assertRaises(InvariantError):unknown_outcomes.resolve(self.s,'lost',txs)
        self.assertEqual('outcome_unknown',self.row()['state'])
    def test_offboard_matches_frozen_sdk_identity_and_confirmed_owner_net(self):
        self.action('offboard_all',{});txid='b'*64
        self.s.event('driver_evidence',{'action_id':'lost','event':'offboard_proposal','data':{'action_id':'sdk-off','input_vtxo_ids':['original'],'destination_script':'owner-script','net_sat':9900,'committed_fee_sat':100}})
        self.native({'offboard_action_id':'sdk-off','destination_script':'owner-script','committed_fee_sat':100,'txid':txid})
        tx={'txid':txid,'confirmations':1,'inputs':[{'outpoint':'operator:0','amount_sat':10100,'script':'operator'}],
            'outputs':[{'vout':0,'amount_sat':9900,'script':'owner-script'},{'vout':1,'amount_sat':100,'script':'operator-change'}],'fee_sat':100}
        self.assertTrue(unknown_outcomes.resolve(self.s,'lost',{txid:tx}));self.assertEqual(100,self.row()['actual_fee_sat'])
    def exit(self):
        point='c'*64+':0';self.s.db.execute("UPDATE owned_coin SET id=? WHERE id='original'",(point,))
        proof=json.loads(self.s.db.execute('SELECT proof FROM owned_coin WHERE id=?',(point,)).fetchone()[0]);proof['id']=point
        proof['path']=[{'txid':'c'*64,'output_index':0,'output_script':'exit-leaf','output_amount_sat':10000,'inputs':['ancestor:0']}]
        self.s.db.execute('UPDATE owned_coin SET proof=? WHERE id=?',(canonical(proof),point))
        self.action('exit',{'input_vtxo_ids':[point],'fee_funding_outpoint':'fund:0','fee_rate_sat_per_vb':1})
        self.s.event('driver_evidence',{'action_id':'lost','event':'exit_proposal','data':{'stage':'start','input_vtxo_ids':[point],'signed_vtxos':['aa'],'fee_cap_sat':2000,'destination_script':'owner-script','fee_funding_outpoint':'fund:0','fee_rate_kwu':250,'no_automatic_fee_bumps':True}})
        txid='d'*64
        self.s.event('driver_evidence',{'action_id':'lost','event':'exit_proposal','data':{'stage':'claim','input_vtxo_ids':[point],'fee_cap_sat':2000,'prior_reserved_fee_sat':0,'fee_sat':100,'txid':txid,
            'destination_script':'owner-script','inputs':[[point,{'value':10000,'script_pubkey':'exit-leaf'}]]}})
        return {txid:{'txid':txid,'confirmations':2,'inputs':[{'outpoint':point,'amount_sat':10000,'script':'exit-leaf'}],
            'outputs':[{'vout':0,'amount_sat':9900,'script':'owner-script'}],'fee_sat':100}}
    def test_complete_confirmed_exit_claim_resolves_without_reading_original_wallet(self):
        txs=self.exit();self.s.set_online(self.actor,False)
        self.assertTrue(unknown_outcomes.resolve(self.s,'lost',txs));self.assertEqual(100,self.row()['actual_fee_sat']);self.assertFalse(self.s.online(self.actor))
    def test_exit_partial_unconfirmed_wrong_owner_or_changed_exact_charge_never_resolves(self):
        from simulator.model import InvariantError
        txs=self.exit();self.assertFalse(unknown_outcomes.resolve(self.s,'lost'))
        tx=txs['d'*64];tx['confirmations']=0;self.assertFalse(unknown_outcomes.resolve(self.s,'lost',txs))
        tx['confirmations']=2;tx['outputs'][0]['script']='foreign'
        with self.assertRaises(InvariantError):unknown_outcomes.resolve(self.s,'lost',txs)
        self.assertEqual('outcome_unknown',self.row()['state'])
    def test_changed_exit_reserved_fee_budget_and_missing_original_leaf_proof_hold(self):
        from simulator.model import InvariantError
        txs=self.exit();coin=self.s.db.execute("SELECT id,proof FROM owned_coin WHERE signed_vtxo='aa'").fetchone()
        proof=json.loads(coin['proof']);proof.pop('path');self.s.db.execute('UPDATE owned_coin SET proof=? WHERE id=?',(canonical(proof),coin['id']))
        self.assertFalse(unknown_outcomes.resolve(self.s,'lost',txs));self.assertIsNone(self.row()['actual_fee_sat'])
        self.s.db.execute("UPDATE action SET fee_reservation_sat=2001 WHERE id='lost'")
        with self.assertRaises(InvariantError):unknown_outcomes.resolve(self.s,'lost',txs)
    def cpfp_exit(self):
        txs=self.exit();claim=json.loads(self.s.db.execute("SELECT payload FROM event WHERE json_extract(payload,'$.data.stage')='claim'").fetchone()[0])
        self.s.db.execute("DELETE FROM event WHERE json_extract(payload,'$.data.stage')='claim'")
        point='c'*64+':0';proof=json.loads(self.s.db.execute('SELECT proof FROM owned_coin WHERE id=?',(point,)).fetchone()[0])
        proof['path'].insert(0,{'txid':'e'*64,'output_index':0,'output_script':'ancestor-exit','output_amount_sat':10000,'inputs':['earlier:0']})
        self.s.db.execute('UPDATE owned_coin SET proof=? WHERE id=?',(canonical(proof),point))
        source='fund:0';value=5000
        for number,parent in enumerate(['e'*64,'c'*64]):
            txid=str(number+1)*64;anchor=parent+':1'
            inputs=[[source,{'value':value,'script_pubkey':'funding' if number==0 else 'owner-script'}],[anchor,{'value':0,'script_pubkey':'51024e73'}]]
            self.s.event('driver_evidence',{'action_id':'lost','event':'exit_proposal','data':{'stage':'cpfp','input_vtxo_ids':[point],'fee_cap_sat':2000,'prior_reserved_fee_sat':number*100,'fee_sat':100,'txid':txid,'destination_script':'owner-script','inputs':inputs}})
            txs[txid]={'txid':txid,'confirmations':2,'inputs':[{'outpoint':p,'amount_sat':o['value'],'script':o['script_pubkey']} for p,o in inputs],
                'outputs':[{'vout':0,'amount_sat':value-100,'script':'owner-script'}],'fee_sat':100}
            source=txid+':0';value-=100
        claim['data']['prior_reserved_fee_sat']=200;self.s.event('driver_evidence',claim)
        return txs
    def test_all_exact_chained_cpfp_fees_and_complete_claim_are_charged_once(self):
        txs=self.cpfp_exit();self.assertTrue(unknown_outcomes.resolve(self.s,'lost',txs))
        self.assertEqual(300,self.row()['actual_fee_sat']);self.assertFalse(unknown_outcomes.resolve(self.s,'lost',txs))
        self.assertEqual(1,self.s.db.execute("SELECT count(*) FROM event WHERE kind='client_fee_reconciled'").fetchone()[0])
    def test_one_missing_cpfp_confirmation_keeps_entire_exit_unknown(self):
        txs=self.cpfp_exit();txs['1'*64]['confirmations']=0
        self.assertFalse(unknown_outcomes.resolve(self.s,'lost',txs));self.assertIsNone(self.row()['actual_fee_sat'])
    def test_cpfp_changed_source_or_unrelated_parent_cannot_resolve_exit(self):
        from simulator.model import InvariantError
        txs=self.cpfp_exit();row=self.s.db.execute("SELECT sequence,payload FROM event WHERE json_extract(payload,'$.data.stage')='cpfp' ORDER BY sequence LIMIT 1").fetchone()
        original=json.loads(row['payload'])
        for field,index,value in [('source',0,'foreign:0'),('anchor',1,'f'*64+':1')]:
            payload=json.loads(row['payload']);old=payload['data']['inputs'][index][0];payload['data']['inputs'][index][0]=value
            txs['1'*64]['inputs'][index]['outpoint']=value
            self.s.db.execute('UPDATE event SET payload=? WHERE sequence=?',(canonical(payload),row['sequence']))
            with self.subTest(field=field),self.assertRaises(InvariantError):unknown_outcomes.resolve(self.s,'lost',txs)
            txs['1'*64]['inputs'][index]['outpoint']=old
        self.s.db.execute('UPDATE event SET payload=? WHERE sequence=?',(canonical(original),row['sequence']))
        self.assertEqual('outcome_unknown',self.row()['state'])
    def test_exit_proposal_cannot_change_authorized_rate_source_or_input_set(self):
        from simulator.model import InvariantError
        txs=self.exit();row=self.s.db.execute("SELECT sequence,payload FROM event WHERE json_extract(payload,'$.data.stage')='start'").fetchone()
        for change in ({'fee_rate_kwu':500},{'fee_funding_outpoint':'foreign:0'},{'input_vtxo_ids':['replacement']},{'no_automatic_fee_bumps':False}):
            payload=json.loads(row['payload']);payload['data'].update(change)
            self.s.db.execute('UPDATE event SET payload=? WHERE sequence=?',(canonical(payload),row['sequence']))
            with self.subTest(change=change),self.assertRaises(InvariantError):unknown_outcomes.resolve(self.s,'lost',txs)
        self.assertEqual('outcome_unknown',self.row()['state'])
    def test_chain_identity_failure_never_fetches_or_resolves_any_money_transaction(self):
        import asyncio
        from unittest.mock import Mock
        self.board();chain=Mock();chain.identity.side_effect=RuntimeError('wrong genesis');before=dict(self.row())
        asyncio.run(unknown_outcomes.collect(self.s,object(),chain))
        chain.transaction.assert_not_called();self.assertEqual(before,dict(self.row()))

if __name__=='__main__':unittest.main()

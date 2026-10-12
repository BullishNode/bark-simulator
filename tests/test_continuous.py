import json,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from simulator.continuous import schedule
from simulator.engine import initialize
from simulator.store import Store
from simulator.workload import record_actor_result
class ContinuousTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.s=Store(Path(self.tmp.name),'synthetic',1000000);initialize(self.s)
        self.c=SimpleNamespace(board_amount_sat=12000,action_fee_reserve_sat=2000)
        self.snapshot={'height':100,'capabilities':{'lightning_configured':False}}
        for i in range(1,13):self.detail(f'actor-{i:02}')
    def detail(self,actor,**extra):
        d={'created':True,'ark_address':'ark-'+actor,'snapshot_at':time.time(),'registered_spendable_sat':0,'onchain_confirmed_sat':0,'needs_sync':False}
        d.update(extra);self.s.db.execute('UPDATE actor SET details=? WHERE id=?',(json.dumps(d),actor))
    def tearDown(self):self.s.close();self.tmp.cleanup()
    def action(self):return self.s.db.execute("SELECT * FROM action WHERE state='queued'").fetchone()
    def test_unfunded_clients_are_observed_without_money_creation(self):
        schedule(self.s,self.c,self.snapshot);self.assertIsNone(self.action());self.assertEqual(0,self.s.db.execute('SELECT COUNT(*) FROM action').fetchone()[0])
    def test_absent_client_is_never_reopened_or_synchronized(self):
        self.detail('actor-09',created=False);self.s.set_online('actor-09',False)
        self.detail('actor-10',registered_spendable_sat=12000,board_submitted=True)
        schedule(self.s,self.c,self.snapshot);self.assertFalse(self.s.online('actor-10'));self.assertIsNone(self.action())

    def pending_board(self,actor='actor-10'):
        self.detail(actor,board_submitted=True,needs_sync=True,snapshot_at=0)
        self.s.queue('pending-board',actor,'H04','board',{},2000)
        self.s.db.execute("UPDATE action SET state='completed' WHERE id='pending-board'")
        self.s.db.execute('INSERT INTO client_coin_candidate(id,actor,action_id,digest,payload) VALUES (?,?,?,?,?)',
            ('candidate',actor,'pending-board','digest','{}'))

    def test_pending_board_client_stops_before_any_sync_or_snapshot(self):
        self.pending_board()
        schedule(self.s,self.c,self.snapshot)
        self.assertFalse(self.s.online('actor-10'))
        self.assertIsNone(self.action())
        event=json.loads(self.s.db.execute("SELECT payload FROM event WHERE kind='continuous_absence_armed'").fetchone()[0])
        self.assertEqual('H04',event['scenario'])
        self.assertTrue(event['independent_confirmation_pending'])
        self.assertEqual('not_qualified',event['scenario_verdict'])
        for _ in range(5):schedule(self.s,self.c,self.snapshot)
        self.assertEqual(1,self.s.db.execute('SELECT COUNT(*) FROM action').fetchone()[0])
        self.s.verify_event_chain()

    def test_pending_absence_requires_frozen_public_candidate(self):
        self.pending_board()
        self.s.db.execute('DELETE FROM client_coin_candidate')
        schedule(self.s,self.c,self.snapshot)
        self.assertTrue(self.s.online('actor-10'))
        self.assertEqual('sync',self.action()['operation'])

    def test_already_synchronized_ambiguous_board_is_not_claimed_pending(self):
        self.pending_board()
        self.s.queue('sync-done','actor-10','H01','sync',{},2000)
        self.s.db.execute("UPDATE action SET state='completed',updated_at=? WHERE id='sync-done'",(time.time(),))
        schedule(self.s,self.c,self.snapshot)
        self.assertTrue(self.s.online('actor-10'))
        self.assertFalse(self.s.db.execute("SELECT 1 FROM event WHERE kind='continuous_absence_armed'").fetchone())

    def test_stale_pending_snapshot_before_a_later_sync_does_not_claim_pending(self):
        self.pending_board()
        self.s.queue('old-snapshot','actor-10','H01','snapshot',{},0)
        self.s.db.execute("UPDATE action SET state='completed',result=? WHERE id='old-snapshot'",
            (json.dumps({'data':{'balance':{'pending_board_sat':10000}}}),))
        self.s.queue('new-sync','actor-10','H01','sync',{},2000)
        self.s.db.execute("UPDATE action SET state='completed',updated_at=? WHERE id='new-sync'",(time.time(),))
        schedule(self.s,self.c,self.snapshot)
        self.assertTrue(self.s.online('actor-10'))
        self.assertFalse(self.s.db.execute("SELECT 1 FROM event WHERE kind='continuous_absence_armed'").fetchone())

    def test_ramp_has_a_separate_pending_board_disappearance_actor(self):
        self.s.actor('actor-22','ramp');self.pending_board('actor-22')
        schedule(self.s,self.c,self.snapshot)
        self.assertFalse(self.s.online('actor-22'))
        self.assertIsNone(self.action())
    def test_ambiguous_money_action_never_retries_or_blocks_other_clients(self):
        self.detail('actor-01',created=False);self.s.queue('lost','actor-01','H01','board',{},2000)
        self.s.db.execute("UPDATE action SET state='outcome_unknown' WHERE id='lost'")
        self.detail('actor-02',created=False);schedule(self.s,self.c,self.snapshot)
        self.assertEqual('actor-02',self.action()['actor_id']);self.assertEqual('create',self.action()['operation'])
    def test_internal_lightning_is_not_queued_without_topology(self):
        self.detail('actor-06',registered_spendable_sat=12000,board_submitted=True)
        schedule(self.s,self.c,self.snapshot)
        self.assertNotEqual('invoice',self.action()['operation'])
    def test_ramp_clients_are_fresh_wallets_not_clones(self):
        self.s.actor('actor-13','ramp');schedule(self.s,self.c,self.snapshot)
        self.assertEqual('actor-13',self.action()['actor_id']);self.assertEqual('create',self.action()['operation']);self.assertEqual('{}',self.action()['args'])
    def test_repeated_scheduler_ticks_do_not_duplicate_work(self):
        self.detail('actor-01',created=False)
        for _ in range(20):schedule(self.s,self.c,self.snapshot)
        self.assertEqual(1,self.s.db.execute('SELECT COUNT(*) FROM action').fetchone()[0])
    def test_expensive_exit_does_not_starve_an_affordable_payment(self):
        self.s.db.execute("UPDATE meta SET value='3000' WHERE key='fee_budget_sat'")
        self.detail('actor-04',registered_spendable_sat=12000,board_submitted=True)
        self.detail('actor-05',registered_spendable_sat=12000,board_submitted=True)
        for actor in ['actor-04','actor-05']:
            self.s.queue('last-sync-'+actor,actor,'H01','sync',{},0)
            self.s.db.execute("UPDATE action SET state='completed',actual_fee_sat=0,updated_at=? WHERE id=?",(time.time(),'last-sync-'+actor))
        schedule(self.s,self.c,self.snapshot)
        self.assertEqual('actor-05',self.action()['actor_id'])
        self.assertEqual('send_arkoor',self.action()['operation'])
    def test_raw_requests_are_rate_limited_after_every_case(self):
        self.detail('actor-11',registered_spendable_sat=12000,board_submitted=True)
        self.s.queue('raw','actor-11','D03','raw_sequence_tamper',{},0)
        self.s.db.execute("UPDATE action SET state='expected_refusal',updated_at=? WHERE id='raw'",(time.time(),))
        schedule(self.s,self.c,self.snapshot)
        self.assertFalse(self.action()['operation'].startswith('raw_'))
    def test_snapshot_cannot_create_an_endless_sync_snapshot_loop(self):
        self.detail('actor-01',onchain_confirmed_sat=20000)
        record_actor_result(self.s,'actor-01','snapshot',{'balance':{'spendable_sat':0},'onchain':{'confirmed_sat':20000},'vtxos':[]})
        schedule(self.s,self.c,self.snapshot)
        self.assertEqual('board',self.action()['operation'])
    def test_recent_sync_debt_cannot_use_an_old_spendable_balance(self):
        self.detail('actor-01',registered_spendable_sat=12000,board_submitted=True,needs_sync=True)
        self.s.queue('sync','actor-01','H01','sync',{},2000)
        self.s.db.execute("UPDATE action SET state='completed',actual_fee_sat=0,updated_at=? WHERE id='sync'",(time.time(),))
        schedule(self.s,self.c,self.snapshot)
        self.assertIsNone(self.action())

    def test_twelve_clients_can_board_when_serial_reads_take_longer_than_snapshot_ttl(self):
        for i in range(1,13):
            self.detail(f'actor-{i:02}',onchain_confirmed_sat=20000,snapshot_at=time.time()-600)
        served=set()
        for _ in range(12):
            schedule(self.s,self.c,self.snapshot)
            a=self.s.claim({'board'})
            self.assertIsNotNone(a, 'periodic reads must not starve all twelve funded wallets')
            self.assertNotIn(a['actor_id'],served)
            served.add(a['actor_id'])
            self.s.finish(a['id'],'completed',{},0,on_completed=lambda a=a:
                record_actor_result(self.s,a['actor_id'],'board',{}))
        self.assertEqual(12,len(served))
        self.assertEqual(12,self.s.db.execute('SELECT count(*) FROM action').fetchone()[0])
        self.s.verify_event_chain()

    def test_read_after_sync_is_still_required_before_using_a_previous_balance(self):
        self.detail('actor-01',onchain_confirmed_sat=20000,snapshot_at=0)
        schedule(self.s,self.c,self.snapshot)
        self.assertEqual('snapshot',self.action()['operation'])

    def test_payment_rotation_replenishes_lightning_sender_and_includes_new_cohort(self):
        for i in range(13,25):
            self.s.actor(f'actor-{i:02}','ramp');self.detail(f'actor-{i:02}')
        self.detail('actor-01',registered_spendable_sat=12000,board_submitted=True)
        self.s.queue('last-sync','actor-01','H01','sync',{},0)
        self.s.db.execute("UPDATE action SET state='completed',actual_fee_sat=0,updated_at=? WHERE id='last-sync'",(time.time(),))
        self.s.set_online('actor-09',False)
        recipients=set()
        for _ in range(23):
            schedule(self.s,self.c,self.snapshot);a=self.action()
            self.assertEqual('send_arkoor',a['operation'])
            recipients.add(json.loads(a['args'])['recipient_actor'])
            self.s.db.execute("UPDATE action SET state='completed',actual_fee_sat=0,updated_at=? WHERE id=?",(time.time()-601,a['id']))
        self.assertEqual({f'actor-{i:02}' for i in range(2,25)},recipients)
        self.assertFalse(self.s.online('actor-09'))

    def boarded_actor(self,age=0):
        self.detail('actor-01',registered_spendable_sat=12000,board_submitted=True)
        for name,operation in [('board-done','board'),('sync-done','sync')]:
            self.s.queue(name,'actor-01','H01',operation,{},0)
            self.s.db.execute("UPDATE action SET state='completed',actual_fee_sat=0,updated_at=? WHERE id=?",
                (time.time()-age if operation=='board' else time.time(),name))

    def test_fresh_board_can_pay_before_an_unnecessary_round_locks_it(self):
        self.boarded_actor()
        schedule(self.s,self.c,self.snapshot)
        self.assertEqual('send_arkoor',self.action()['operation'])

    def test_hourly_refresh_still_runs_for_an_older_board(self):
        self.boarded_actor(age=3601)
        schedule(self.s,self.c,self.snapshot)
        self.assertEqual('refresh',self.action()['operation'])

    def test_recent_refresh_restarts_the_hourly_cadence(self):
        self.boarded_actor(age=7200)
        self.s.queue('refresh-done','actor-01','H17','refresh',{},0)
        self.s.db.execute("UPDATE action SET state='completed',actual_fee_sat=0 WHERE id='refresh-done'")
        schedule(self.s,self.c,self.snapshot)
        self.assertEqual('send_arkoor',self.action()['operation'])

    def test_reboarding_returned_funds_restarts_the_hourly_cadence(self):
        self.boarded_actor(age=7200)
        self.s.queue('reboard-done','actor-01','H06','board',{},0)
        self.s.db.execute("UPDATE action SET state='completed',actual_fee_sat=0 WHERE id='reboard-done'")
        schedule(self.s,self.c,self.snapshot)
        self.assertEqual('send_arkoor',self.action()['operation'])


    def test_empty_online_lightning_recipient_can_invoice_before_funding(self):
        self.snapshot['capabilities']['lightning_configured']=True
        schedule(self.s,self.c,self.snapshot)
        self.assertEqual(('actor-06','invoice'),(self.action()['actor_id'],self.action()['operation']))
        self.assertEqual(2000,self.action()['fee_reservation_sat'])
        self.assertEqual({'amount_sat':2000},json.loads(self.action()['args']))
    def test_empty_absent_recipient_rotates_without_opening_it(self):
        self.snapshot['capabilities']['lightning_configured']=True;self.s.set_online('actor-06',False)
        schedule(self.s,self.c,self.snapshot)
        self.assertEqual(('actor-08','invoice'),(self.action()['actor_id'],self.action()['operation']))
        self.assertFalse(self.s.online('actor-06'))
    def test_empty_recipient_sync_debt_must_finish_before_invoice(self):
        self.snapshot['capabilities']['lightning_configured']=True
        self.detail('actor-06',needs_sync=True)
        schedule(self.s,self.c,self.snapshot)
        self.assertEqual(('actor-06','sync'),(self.action()['actor_id'],self.action()['operation']))

class ReceiveThenDisappearTests(unittest.TestCase):
    setUp=ContinuousTests.setUp
    tearDown=ContinuousTests.tearDown
    detail=ContinuousTests.detail
    action=ContinuousTests.action
    def receive(self,actor,rail='ark',verified=True):
        self.detail(actor,board_submitted=True,registered_spendable_sat=5000,coin_ids=['receive:0'])
        self.s.queue('fresh-snapshot',actor,'H01','snapshot',{},0)
        self.s.db.execute("UPDATE action SET state='completed',actual_fee_sat=0 WHERE id='fresh-snapshot'")
        movement={'id':'1','status':'successful','subsystem':'bark.arkoor' if rail=='ark' else 'bark.lightning_receive',
            'input_vtxos':[],'output_vtxos':['receive:0'],'effective_balance_sat':2000,'offchain_fee_sat':0,
            'payment_hash':None if rail=='ark' else 'a'*64}
        self.s.db.execute('INSERT INTO movement_evidence VALUES (?,?,?)',(actor,'1',json.dumps(movement)))
        if verified:
            self.s.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',('key',actor,'mailbox','{}'))
            self.s.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',('receive:0','key',2000,'digest','signed','{}'))
            self.s.db.execute('INSERT INTO coin_observation VALUES (?,?,?,?)',('receive:0','fresh-snapshot','Spendable',time.time()))
        if rail=='lightning':
            self.s.queue('invoice-own',actor,'H40','invoice',{'amount_sat':2000},2000)
            self.s.db.execute("UPDATE action SET state='completed',actual_fee_sat=0,result=? WHERE id='invoice-own'",
                (json.dumps({'data':{'payment_hash':'a'*64}}),))
        return movement

    def test_ark_recipient_goes_permanently_silent_only_after_verified_receive(self):
        self.receive('actor-03')
        schedule(self.s,self.c,self.snapshot)
        self.assertFalse(self.s.online('actor-03'))
        self.assertIsNone(self.action())
        for _ in range(5):schedule(self.s,self.c,self.snapshot)
        self.assertFalse(self.s.online('actor-03'))
        self.assertEqual(1,self.s.db.execute("SELECT count(*) FROM event WHERE kind='receive_then_disappear_armed'").fetchone()[0])
        self.s.verify_event_chain()

    def test_missing_independent_receive_proof_keeps_client_online(self):
        self.receive('actor-03',verified=False)
        schedule(self.s,self.c,self.snapshot)
        self.assertTrue(self.s.online('actor-03'))

    def test_lightning_recipient_disappears_after_signed_claim_not_invoice_creation(self):
        self.receive('actor-06','lightning')
        schedule(self.s,self.c,self.snapshot)
        self.assertFalse(self.s.online('actor-06'))
        detail=json.loads(self.s.db.execute("SELECT details FROM actor WHERE id='actor-06'").fetchone()[0])
        self.assertEqual('lightning',detail['permanent_absence']['rail'])
        self.assertEqual(['receive:0'],detail['permanent_absence']['coin_ids'])

    def test_non_receive_or_pending_movement_cannot_arm_disappearance(self):
        for status,subsystem,balance in [('pending','bark.arkoor',2000),('successful','bark.round',2000),('successful','bark.arkoor',-2000)]:
            self.receive('actor-03',verified=False)
            self.s.db.execute("UPDATE movement_evidence SET payload=? WHERE actor='actor-03'",
                (json.dumps({'id':'1','status':status,'subsystem':subsystem,'effective_balance_sat':balance,'input_vtxos':[],'output_vtxos':['receive:0']}),))
            schedule(self.s,self.c,self.snapshot)
            self.assertTrue(self.s.online('actor-03'))
            self.s.db.execute('DELETE FROM action');self.s.db.execute('DELETE FROM movement_evidence')

    def test_lightning_workload_moves_to_online_peer_after_first_recipient_leaves(self):
        self.s.set_online('actor-06',False)
        self.detail('actor-08',registered_spendable_sat=5000,board_submitted=True)
        self.snapshot['capabilities']['lightning_configured']=True
        self.s.queue('recent-sync','actor-08','H01','sync',{},0)
        self.s.db.execute("UPDATE action SET state='completed',actual_fee_sat=0 WHERE id='recent-sync'")
        schedule(self.s,self.c,self.snapshot)
        self.assertEqual('actor-08',self.action()['actor_id'])
        self.assertEqual('invoice',self.action()['operation'])

    def test_stale_spent_output_cannot_arm_disappearance(self):
        self.receive('actor-03')
        self.s.db.execute("UPDATE coin_observation SET state='Spent'")
        schedule(self.s,self.c,self.snapshot)
        self.assertTrue(self.s.online('actor-03'))

    def test_wrong_owner_and_invoice_amount_are_incidents(self):
        from simulator.continuous import arm_receive_absence
        from simulator.model import InvariantError
        self.receive('actor-06','lightning')
        self.s.db.execute("UPDATE owner_key SET actor='actor-02'")
        with self.assertRaises(InvariantError):arm_receive_absence(self.s,'actor-06','lightning')
        self.s.db.execute("UPDATE owner_key SET actor='actor-06'")
        self.s.db.execute("UPDATE action SET args=? WHERE id='invoice-own'",(json.dumps({'amount_sat':2001}),))
        with self.assertRaises(InvariantError):arm_receive_absence(self.s,'actor-06','lightning')
        self.assertTrue(self.s.online('actor-06'))

    def test_report_keeps_absence_pending_until_independent_settlement(self):
        from simulator.continuous import arm_receive_absence,absence_report
        self.receive('actor-03')
        self.assertTrue(arm_receive_absence(self.s,'actor-03','ark'))
        result=absence_report(self.s)[0]
        self.assertEqual('pending',result['payout_verdict'])
        self.assertEqual(['receive:0'],result['waiting_coin_ids'])
        self.s.db.execute('INSERT INTO checked_settlement VALUES (?,?,?,?,?,?)',('receive:0','payout','actor-03','script',2000,'{}'))
        result=absence_report(self.s)[0]
        self.assertEqual('confirmed_amounts_checked',result['payout_verdict'])
        self.assertIn('separate',result['security_qualification'])
        self.assertFalse(self.s.online('actor-03'))

    def test_deployment_does_not_relabel_a_historical_receive(self):
        from simulator.continuous import arm_receive_absence
        self.receive('actor-03')
        self.s.db.execute("INSERT INTO meta VALUES ('receive_absence_seen_movements',?)",(json.dumps({'actor-03':['1']}),))
        self.assertFalse(arm_receive_absence(self.s,'actor-03','ark'))
        self.assertTrue(self.s.online('actor-03'))


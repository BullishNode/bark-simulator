"""Reproducible scheduling choices keep existing money and absence guards."""
import json,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from simulator.continuous import schedule
from simulator.engine import initialize
from simulator.store import Store

class SchedulingRealismTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.s=Store(Path(self.tmp.name),'synthetic',1000000);initialize(self.s)
        self.c=SimpleNamespace(board_amount_sat=12000,action_fee_reserve_sat=2000,
            interval_seconds=30,campaign_seed='public-test-campaign',absence_hazard_per_day=0.005,
            absent_payment_probability=0.05,dispatch_per_tick=2)
        self.now=time.time()
        for row in self.s.db.execute('SELECT id FROM actor').fetchall():
            name=row['id'];self.s.db.execute('UPDATE actor SET online=?,details=? WHERE id=?',
                (name in {'actor-01','actor-02'},json.dumps({'created':True,'ark_address':'ark-'+name,
                 'registered_spendable_sat':12000,'snapshot_at':self.now,'needs_sync':False}),name))
        self.snapshot={'height':100,'capabilities':{'lightning_configured':False}}
    def tearDown(self):self.s.close();self.tmp.cleanup()
    def test_seeded_scheduler_journals_choices_and_prepares_two_distinct_clients(self):
        with patch('simulator.continuous.time.time',return_value=self.now):schedule(self.s,self.c,self.snapshot)
        draws=self.s.db.execute("SELECT payload FROM event WHERE kind='random_draw'").fetchall()
        self.assertTrue(draws,'configured campaign has no journaled seeded decisions')
        actions=self.s.db.execute("SELECT * FROM action WHERE state='queued'").fetchall()
        self.assertEqual(2,len(actions));self.assertEqual(2,len({a['actor_id'] for a in actions}))
        for action in actions:self.assertLessEqual(json.loads(action['args'])['amount_sat'],10000)


from simulator.realism import Rng,hazard,ordinary
from simulator.continuous import arm_receive_absence,online_lightning_candidates,absence_report
from simulator.model import canonical
from dataclasses import replace
from simulator.config import Config

class DrawTests(SchedulingRealismTests):
    def draws(self):return [json.loads(r[0]) for r in self.s.db.execute("SELECT payload FROM event WHERE kind='random_draw' ORDER BY sequence")]
    def test_replay_seed_reproduces_decisions(self):
        with tempfile.TemporaryDirectory() as temp:
            other=Store(Path(temp),'synthetic')
            self.s.db.backup(other.db)
            with patch('simulator.continuous.time.time',return_value=self.now):
                schedule(self.s,self.c,self.snapshot);schedule(other,self.c,self.snapshot)
            actual=[dict(r) for r in self.s.db.execute('SELECT * FROM action ORDER BY id')]
            self.assertEqual(actual,[dict(r) for r in other.db.execute('SELECT * FROM action ORDER BY id')])
            draws=self.draws()
            self.assertEqual(draws,[json.loads(r[0]) for r in other.db.execute("SELECT payload FROM event WHERE kind='random_draw' ORDER BY sequence")])
            self.assertEqual(len(draws),Rng.replay(self.c.campaign_seed,draws));other.close()
    def test_restart_resumes_the_durable_counter(self):
        rng=Rng(self.s,self.c);rng.draw('first',{});rng.draw('second',{})
        with tempfile.TemporaryDirectory() as temp:
            other=Store(Path(temp),'synthetic');self.s.db.backup(other.db)
            expected=rng.draw('third',{'actor':'actor-01'})
            actual=Rng(other,self.c).draw('third',{'actor':'actor-01'})
            self.assertEqual(expected,actual);self.assertEqual('3',other.get_meta('campaign_rng_counter'));other.close()
        self.assertEqual(3,Rng.replay(self.c.campaign_seed,self.draws()))
    def test_replay_rejects_changed_value_counter_input_or_seed(self):
        rng=Rng(self.s,self.c);rng.draw('first',{'amount':100})
        draw=self.draws()[0]
        for change in [{'counter':2},{'value':0.999},{'inputs':{'amount':101}}]:
            with self.subTest(change=change),self.assertRaises(ValueError):Rng.replay(self.c.campaign_seed,[{**draw,**change}])
        with self.assertRaises(ValueError):Rng.replay('other',[draw])
    def test_seed_rates_and_enabled_state_are_immutable(self):
        Rng(self.s,self.c)
        for change in [{'campaign_seed':'other'},{'absence_hazard_per_day':0.006},{'absent_payment_probability':0.06},{'campaign_seed':''}]:
            with self.subTest(change=change),self.assertRaises(ValueError):Rng.configured(self.s,SimpleNamespace(**{**vars(self.c),**change}))
    def test_jitter_deadline_is_stable_and_bounded_until_completed_anchor_changes(self):
        rng=Rng(self.s,self.c);rng.due('actor-01','send',600,1000,1100)
        deadline=json.loads(self.s.get_meta('realism_cadences'))['actor-01/send']['deadline']
        self.assertGreaterEqual(deadline,1300);self.assertLess(deadline,1900)
        count=len(self.draws());self.assertFalse(rng.due('actor-01','send',600,1000,deadline-1))
        self.assertTrue(rng.due('actor-01','send',600,1000,deadline+1));self.assertEqual(count,len(self.draws()))
        rng.due('actor-01','send',600,2000,2100);self.assertEqual(count+1,len(self.draws()))
    def test_weighted_amounts_preserve_weights_and_cap_all_choices(self):
        rng=Rng(self.s,self.c)
        for i,amount in enumerate([300,900,900,1000,1000,1500,1500,3000,10000]):
            with patch.object(rng,'draw',return_value=(i+0.1)/9):self.assertEqual(amount,rng.amount('actor-01',12000,2000))
        for i in range(9):
            with patch.object(rng,'draw',return_value=(i+0.1)/9):self.assertEqual(100,rng.amount('actor-01',2100,2000))
        before=len(self.draws());self.assertIsNone(rng.amount('actor-01',2000,2000));self.assertEqual(before,len(self.draws()))
    def test_recipient_groups_enforce_absent_probability_and_advertisement(self):
        rng=Rng(self.s,self.c)
        with patch.object(rng,'draw',side_effect=[0.01,0.9]):self.assertEqual('actor-10',rng.recipient('actor-01',['actor-01','actor-02','actor-09','actor-10']))
        with patch.object(rng,'draw',side_effect=[0.06,0.9]):self.assertEqual('actor-02',rng.recipient('actor-01',['actor-02','actor-09','actor-10']))
        with patch.object(rng,'draw',return_value=0.9):self.assertIsNone(rng.recipient('actor-01',['actor-09']))
        self.assertIsNone(rng.recipient('actor-01',['actor-01']))
    def test_repeated_tick_preserves_queued_actions_and_draws(self):
        with patch('simulator.continuous.time.time',return_value=self.now):
            schedule(self.s,self.c,self.snapshot);draws=self.draws();schedule(self.s,self.c,self.snapshot)
        self.assertEqual(draws,self.draws());self.assertEqual(2,self.s.db.execute('SELECT count(*) FROM action').fetchone()[0])
    def test_dispatched_and_unknown_actors_do_not_block_other_eligible_clients(self):
        self.s.queue('busy','actor-01','H07','send_arkoor',{},2000)
        for state in ('dispatched','outcome_unknown'):
            self.s.db.execute('UPDATE action SET state=? WHERE id=?',(state,'busy'))
            schedule(self.s,self.c,self.snapshot)
            self.assertEqual(1,self.s.db.execute("SELECT count(*) FROM action WHERE actor_id='actor-02'").fetchone()[0])
        self.assertEqual(1,self.s.db.execute("SELECT count(*) FROM action WHERE actor_id='actor-01'").fetchone()[0])
    def test_three_slots_queue_three_distinct_clients(self):
        self.s.db.execute("UPDATE actor SET online=1 WHERE id='actor-05'")
        self.c.dispatch_per_tick=3;schedule(self.s,self.c,self.snapshot)
        self.assertEqual(3,self.s.db.execute("SELECT count(DISTINCT actor_id) FROM action WHERE state='queued'").fetchone()[0])
    def test_pause_never_draws_or_queues_traffic(self):
        self.s.db.execute("INSERT INTO meta VALUES ('paused','incident')")
        schedule(self.s,self.c,self.snapshot)
        self.assertEqual([],self.draws());self.assertEqual(0,self.s.db.execute('SELECT count(*) FROM action').fetchone()[0])

class AbsenceHazardTests(SchedulingRealismTests):
    def setUp(self):
        super().setUp()
        with patch('simulator.realism.time.time',return_value=self.now):self.rng=Rng(self.s,self.c)
    def run_hazard(self,now=None):
        with patch('simulator.realism.time.time',return_value=now or self.now),patch('simulator.realism._value',return_value=0):
            hazard(self.s,self.c,self.rng,arm_receive_absence,online_lightning_candidates)
    def boundary(self,actor='actor-01',operation='invoice'):
        self.s.queue('boundary-'+actor,actor,'H40',operation,{},2000)
        self.s.db.execute("UPDATE action SET state='completed',result='{}',updated_at=? WHERE id=?",(self.now+1,'boundary-'+actor))
    def test_hazard_waits_for_named_boundary_and_never_reopens_absent_actor(self):
        self.run_hazard();self.assertTrue(self.s.online('actor-01'))
        self.boundary();self.run_hazard(self.now+2);self.assertFalse(self.s.online('actor-01'))
        profile=json.loads(self.s.db.execute("SELECT details FROM actor WHERE id='actor-01'").fetchone()[0])['permanent_absence']
        self.assertEqual('boundary-actor-01',profile['boundary_action_id']);self.assertTrue(profile['original_wallet_must_stay_closed'])
        self.run_hazard(self.now+100);self.assertFalse(self.s.online('actor-01'))
        self.assertEqual(1,self.s.db.execute("SELECT count(*) FROM event WHERE kind='random_absence_armed'").fetchone()[0])
        self.assertEqual('pending',absence_report(self.s)[0]['payout_verdict'])
    def test_completed_delegated_refresh_is_a_safe_boundary(self):
        self.boundary(operation='refresh_delegated');self.run_hazard(self.now+2)
        self.assertFalse(self.s.online('actor-01'))
    def test_send_snapshot_and_unknown_are_not_completed_safe_boundaries(self):
        self.boundary(operation='send_arkoor');self.run_hazard(self.now+2);self.assertTrue(self.s.online('actor-01'))
        self.s.db.execute("UPDATE action SET operation='invoice',state='outcome_unknown' WHERE actor_id='actor-01'")
        self.run_hazard(self.now+40);self.assertTrue(self.s.online('actor-01'))
    def test_declared_profiles_are_excluded_and_two_lightning_candidates_survive(self):
        for name in ('actor-03','actor-04','actor-06','actor-09','actor-10','actor-11','actor-12','actor-15','actor-18','actor-22'):
            self.assertFalse(ordinary(name,{}))
        self.s.db.execute('UPDATE actor SET online=0')
        for name in ('actor-07','actor-08'):
            self.s.db.execute('UPDATE actor SET online=1 WHERE id=?',(name,));self.boundary(name,'refresh_delegated')
        self.run_hazard(self.now+2)
        self.assertEqual(2,len(online_lightning_candidates(self.s)))
        self.assertFalse(self.s.db.execute("SELECT 1 FROM event WHERE kind='random_absence_armed'").fetchone())
    def test_hazard_rate_is_per_actor_day_and_not_redrawn_twice_in_one_tick(self):
        self.run_hazard()
        draws=[json.loads(r[0]) for r in self.s.db.execute("SELECT payload FROM event WHERE kind='random_draw'")]
        self.assertEqual(2,len(draws))
        self.assertEqual(0.005*30/86400,draws[0]['inputs']['probability'])
        self.run_hazard();self.assertEqual(2,self.s.db.execute("SELECT count(*) FROM event WHERE kind='random_draw'").fetchone()[0])



    def test_new_independently_owned_receipt_is_a_safe_boundary(self):
        self.s.db.execute("UPDATE actor SET details=? WHERE id='actor-01'",(canonical({'created':True,'ark_address':'ark-actor-01','snapshot_at':self.now,'coin_ids':['receipt'],'needs_sync':False}),))
        self.s.db.execute("INSERT INTO owner_key VALUES ('receipt-key','actor-01','mailbox','{}')")
        self.s.db.execute("INSERT INTO owned_coin VALUES ('receipt','receipt-key',1000,'digest','signed','{}')")
        self.s.queue('read','actor-01','H01','snapshot',{},0)
        self.s.db.execute("UPDATE action SET state='completed' WHERE id='read'")
        self.s.db.execute("INSERT INTO coin_observation VALUES ('receipt','read','Spendable',?)",(self.now+1,))
        movement={'id':'new-receipt','subsystem':'bark.arkoor','status':'successful','input_vtxos':[],
            'output_vtxos':['receipt'],'effective_balance_sat':1000,'offchain_fee_sat':0}
        self.s.db.execute('INSERT INTO movement_evidence VALUES (?,?,?)',('actor-01','new-receipt',canonical(movement)))
        self.run_hazard(self.now+2)
        self.assertFalse(self.s.online('actor-01'))
        profile=json.loads(self.s.db.execute("SELECT details FROM actor WHERE id='actor-01'").fetchone()[0])['permanent_absence']
        self.assertEqual('new-receipt',profile['movement_id']);self.assertEqual(['receipt'],profile['coin_ids'])
    def test_missing_receive_proof_retains_pending_hazard_without_closing_wallet(self):
        self.s.db.execute("UPDATE actor SET details=? WHERE id='actor-01'",(canonical({'created':True,'ark_address':'ark-actor-01','snapshot_at':self.now,'coin_ids':['receipt'],'needs_sync':False}),))
        movement={'id':'new-receipt','subsystem':'bark.arkoor','status':'successful','input_vtxos':[],
            'output_vtxos':['receipt'],'effective_balance_sat':1000,'offchain_fee_sat':0}
        self.s.db.execute('INSERT INTO movement_evidence VALUES (?,?,?)',('actor-01','new-receipt',canonical(movement)))
        self.run_hazard(self.now+2);self.assertTrue(self.s.online('actor-01'))
        self.assertTrue(json.loads(self.s.get_meta('realism_hazards'))['actor-01']['pending'])

if __name__=='__main__':unittest.main()

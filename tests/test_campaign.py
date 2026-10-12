import json
import tempfile
import unittest
from pathlib import Path
from simulator.campaign import CampaignClock, RampPlan, traffic_ready
from simulator.engine import initialize
from simulator.store import Store

class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.store=Store(Path(self.temp.name),'synthetic',1000)
        initialize(self.store)
        self.now=0
        self.clock=CampaignClock(self.store,RampPlan(),maximum_gap_seconds=180,clock=lambda:self.now)
    def tearDown(self):
        self.store.close();self.temp.cleanup()
    def advance(self,seconds,healthy=True,started=True):
        self.now+=seconds
        return self.clock.tick(healthy=healthy,real_campaign_started=started)
    def test_setup_pause_and_downtime_are_excluded(self):
        self.advance(0,started=False);self.advance(120,started=False)
        self.assertEqual(self.advance(120),0)
        self.assertEqual(self.advance(120),120)
        self.advance(120,healthy=False);self.advance(120)
        self.assertEqual(self.advance(120),240)
        self.store.db.execute("INSERT INTO meta VALUES ('paused','incident')")
        self.advance(120);self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        self.assertEqual(self.advance(120),240)
        self.assertEqual(self.advance(3600),240)
        resumed=CampaignClock(self.store,RampPlan(),clock=lambda:self.now)
        self.now+=86400
        self.assertEqual(resumed.tick(healthy=True,real_campaign_started=True),240)
    def test_three_hour_ramp_is_atomic_and_not_funded_twice(self):
        self.advance(0)
        for _ in range(89):self.advance(120)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM actor').fetchone()[0],12)
        self.assertEqual(self.advance(120),10800)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM actor').fetchone()[0],24)
        self.store.set_online('actor-09',False)
        resumed=CampaignClock(self.store,RampPlan(),clock=lambda:self.now)
        resumed.tick(healthy=True,real_campaign_started=True)
        self.now+=120;resumed.tick(healthy=True,real_campaign_started=True)
        self.assertFalse(self.store.online('actor-09'))
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM event WHERE kind='client_ramp_applied'").fetchone()[0],1)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM action').fetchone()[0],0)
        self.store.verify_event_chain()
    def test_plan_change_does_not_mutate_existing_campaign(self):
        with self.assertRaises(ValueError):CampaignClock(self.store,RampPlan(added_clients=20))
        self.assertEqual(json.loads(self.store.get_meta('ramp_plan'))['added_clients'],12)
    def test_conflicting_cohort_rolls_back_ramp(self):
        self.advance(0)
        self.store.actor('actor-13','foreign')
        for _ in range(89):self.advance(120)
        with self.assertRaises(ValueError):self.advance(120)
        self.assertIsNone(self.store.get_meta('ramp_applied'))
        self.assertEqual(float(self.store.get_meta('campaign_active_seconds')),10680)

    def transfer(self, identity, operation, data, at, state='completed'):
        if operation == 'pay_invoice' and data.get('paid') is True:
            data = {**data, 'payment_status_verified': True, 'payment_state': 'succeeded'}
        self.store.queue(identity,'actor-01','H07',operation,{},0)
        self.store.db.execute('UPDATE action SET state=?,result=?,updated_at=? WHERE id=?',
            (state,json.dumps({'status':'ok','data':data}),at,identity))

    def test_setup_and_read_only_work_cannot_earn_campaign_time(self):
        self.transfer('setup-ark','send_arkoor',{'submitted':'send_arkoor'},90)
        self.transfer('setup-ln','pay_invoice',{'paid':True},90)
        self.assertFalse(traffic_ready(self.store,100))
        self.store.db.execute("INSERT INTO meta VALUES ('real_campaign_started','100')")
        self.transfer('reads','snapshot',{},105)
        self.transfer('invoice','invoice',{'paid':True},105)
        self.assertFalse(traffic_ready(self.store,110))

    def test_both_successful_rails_and_recent_customer_activity_are_required(self):
        self.store.db.execute("INSERT INTO meta VALUES ('real_campaign_started','100')")
        self.transfer('ark','send_arkoor',{'submitted':'send_arkoor'},101)
        self.transfer('pending-ln','pay_invoice',{'paid':False},102)
        self.assertFalse(traffic_ready(self.store,103))
        self.transfer('paid-ln','pay_invoice',{'paid':True},104)
        self.assertTrue(traffic_ready(self.store,704))
        self.assertFalse(traffic_ready(self.store,705))
        self.transfer('new-ark','send_arkoor',{'submitted':'send_arkoor'},710)
        self.assertTrue(traffic_ready(self.store,711))

    def test_uncertain_and_future_transfers_cannot_earn_time(self):
        self.store.db.execute("INSERT INTO meta VALUES ('real_campaign_started','100')")
        self.transfer('ark','send_arkoor',{'submitted':'send_arkoor'},101)
        self.transfer('uncertain-ln','pay_invoice',{'paid':True},102,'outcome_unknown')
        self.transfer('future-ln','pay_invoice',{'paid':True},10000)
        self.assertFalse(traffic_ready(self.store,103))

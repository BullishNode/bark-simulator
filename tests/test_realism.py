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

if __name__=='__main__':unittest.main()

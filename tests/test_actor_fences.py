"""Central selector and SQLite ownership races, using synthetic state only."""
import concurrent.futures
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from simulator.engine import initialize
from simulator.model import canonical
from simulator.store import Store
from tests import test_continuous as fixtures

NOAH_SCHEMA='''CREATE TABLE noah_control(id TEXT PRIMARY KEY,actor TEXT NOT NULL,
 intent TEXT NOT NULL,state TEXT NOT NULL);'''


class ActorFenceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)/'state'
        self.store=Store(self.path,'synthetic',10000);initialize(self.store)
        self.store.db.executescript(NOAH_SCHEMA)
    def tearDown(self):self.store.close();self.temp.cleanup()
    def hold(self,actor='actor-01',state='started'):
        self.store.db.execute('INSERT INTO noah_control VALUES (?,?,?,?)',('setup-'+actor,actor,'{}',state))

    def test_queued_action_is_not_marked_dispatched_under_legacy_private_hold(self):
        self.store.queue('before-hold','actor-01','H01','snapshot',{},0);self.hold()
        self.assertIsNone(self.store.claim({'snapshot'}))
        self.assertEqual('queued',self.store.db.execute('SELECT state FROM action').fetchone()[0])
        self.assertFalse(self.store.has_runnable_queue())
        self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM event WHERE kind='action_dispatched'").fetchone()[0])

    def test_real_overlapping_sqlite_claim_waits_then_observes_committed_hold(self):
        self.store.queue('racing','actor-01','H01','snapshot',{},0)
        entered=threading.Event();release=threading.Event();attempted=threading.Event()
        def holder():
            store=Store(self.path,'synthetic',10000)
            try:
                with store.transaction():
                    store.db.execute('INSERT INTO noah_control VALUES (?,?,?,?)',('setup-race','actor-01','{}','started'))
                    entered.set();release.wait(5)
            finally:store.close()
        def claimant():
            store=Store(self.path,'synthetic',10000)
            try:attempted.set();return store.claim({'snapshot'})
            finally:store.close()
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            first=pool.submit(holder);self.assertTrue(entered.wait(5))
            second=pool.submit(claimant)
            # The second Store's initialization also needs the writer lock.
            release.set();first.result(timeout=5);result=second.result(timeout=5)
        self.assertTrue(attempted.is_set());self.assertIsNone(result)
        self.assertEqual('queued',self.store.db.execute('SELECT state FROM action').fetchone()[0])

    def test_direct_lease_and_native_claim_exclude_each_other_and_unknown_survives_restart(self):
        self.store.queue('native-first','actor-01','H01','snapshot',{},0)
        self.assertIsNotNone(self.store.claim({'snapshot'}))
        self.assertFalse(self.store.acquire_actor_lease('actor-01','setup-1','noah_enrollment'))
        self.assertTrue(self.store.acquire_actor_lease('actor-02','setup-2','noah_enrollment'))
        with self.assertRaises(ValueError):self.store.queue('under-lease','actor-02','H01','sync',{},0)
        self.store.finish_actor_lease('actor-02','setup-2','outcome_unknown')
        self.store.close();self.store=Store(self.path,'synthetic',10000)
        self.assertTrue(self.store.actor_held('actor-02'))
        self.assertFalse(self.store.acquire_actor_lease('actor-02','new-setup','noah_enrollment'))
        with self.assertRaises(ValueError):self.store.finish_actor_lease('actor-02','another-owner','completed')

    def test_ordinary_extra_cohorts_work_and_noah_requires_explicit_namespace(self):
        self.store.actor('actor-25','additional realistic client')
        self.store.queue('extra','actor-25','H01','create',{},0)
        self.assertEqual('actor-25',self.store.claim({'create'})['actor_id'])
        for actor in ('actor-03','actor-09','actor-10'):
            self.store.set_online(actor,False);self.store.queue('closed-'+actor,actor,'H01','snapshot',{},0)
        self.assertIsNone(self.store.claim({'snapshot'}))
        self.store.actor('noah-phone-new','noah-phone')
        with self.assertRaises(ValueError):self.store.queue('ordinary-noah','noah-phone-new','H01','create',{},0)
        self.store.queue('explicit-noah','noah-phone-new','N01','invoice',{},0,namespace='noah')
        self.assertIsNone(self.store.claim({'invoice'}))
        self.assertEqual('explicit-noah',self.store.claim({'invoice'},namespace='noah')['id'])


class ActorSelectorTests(unittest.TestCase):
    setUp=fixtures.ContinuousTests.setUp
    tearDown=fixtures.ContinuousTests.tearDown
    detail=fixtures.ContinuousTests.detail
    action=fixtures.ContinuousTests.action

    def hold(self,actor):
        self.s.db.executescript(NOAH_SCHEMA)
        self.s.db.execute('INSERT INTO noah_control VALUES (?,?,?,?)',('setup',actor,'{}','started'))

    def test_new_phone_registration_never_triggers_ordinary_create_but_extra_cohort_does(self):
        from simulator.continuous import schedule
        for i in range(1,13):self.s.set_online(f'actor-{i:02}',False)
        self.s.actor('noah-phone-new','noah-phone');schedule(self.s,self.c,self.snapshot)
        self.assertIsNone(self.action())
        self.s.actor('actor-25','additional realistic client');schedule(self.s,self.c,self.snapshot)
        self.assertEqual(('actor-25','create'),(self.action()['actor_id'],self.action()['operation']))

    def test_ordinary_leased_actor_is_not_scheduled_or_selected_for_renewal(self):
        from simulator.continuous import schedule
        from simulator.renewal import eligible
        for i in range(1,13):self.s.set_online(f'actor-{i:02}',i==1)
        self.detail('actor-01',board_submitted=True,funding_address='tb1q-client-01')
        self.hold('actor-01');schedule(self.s,self.c,self.snapshot)
        self.assertIsNone(self.action());self.assertEqual([],eligible(self.s,self.c))

    def test_recycler_does_not_reboard_a_phone_or_actor_with_active_private_hold(self):
        from simulator.recycling import plan
        self.s.actor('noah-phone-new','noah-phone')
        self.c.board_amount_sat=5000
        for actor in ('noah-phone-new','actor-01'):
            source={'actor':actor,'outpoint':'a'*64+':0','script':'0014'+'b'*40,'amount_sat':8000,'confirmations':2,'checked_at':time.time()}
            self.s.event('recycle_source_unspent_verified',source)
            if actor=='actor-01':self.hold(actor)
            self.assertIsNone(plan(self.s,actor,{'board_submitted':True,'onchain_confirmed_sat':8000},self.c))

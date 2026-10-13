"""Atomic phone enrollment ownership; no native or backend calls."""
import unittest
import test_noah_controller as controller_tests

class NoahControllerLeaseTests(unittest.IsolatedAsyncioTestCase):
    setUp=controller_tests.NoahPrivateControllerTests.setUp
    tearDown=controller_tests.NoahPrivateControllerTests.tearDown
    adapter=controller_tests.NoahPrivateControllerTests.adapter
    controller=controller_tests.NoahPrivateControllerTests.controller

    def queue_snapshot(self):
        self.store.db.execute("INSERT OR IGNORE INTO scenario VALUES ('N01','separate phone observation',0)")
        self.store.queue('native-1','actor-41','N01','snapshot',{},0,namespace='noah')

    def test_native_claim_after_preflight_refuses_enrollment_before_start(self):
        controller,_,_=self.controller();controller._qualified('actor-41')
        self.queue_snapshot()
        self.assertEqual('native-1',self.store.claim({'snapshot'},namespace='noah')['id'])
        with self.assertRaises(ValueError):controller._start('setup-1','actor-41',{'operation':'enroll'})
        self.assertEqual(0,self.store.db.execute('SELECT COUNT(*) FROM noah_control').fetchone()[0])
        self.assertEqual(0,self.store.db.execute('SELECT COUNT(*) FROM actor_lease').fetchone()[0])

    def test_enrollment_lease_blocks_dispatch_until_qualified_completion(self):
        controller,_,_=self.controller();self.queue_snapshot()
        controller._start('setup-1','actor-41',{'operation':'enroll'})
        self.assertIsNone(self.store.claim({'snapshot'},namespace='noah'))
        controller._qualified('actor-41',owner='setup-1')
        controller._finish('setup-1','actor-41','completed')
        self.assertFalse(self.store.actor_held('actor-41'))
        self.assertEqual('native-1',self.store.claim({'snapshot'},namespace='noah')['id'])

    def test_unknown_enrollment_retains_lease_across_controller_reopen(self):
        controller,adapter,helper=self.controller()
        controller._start('setup-1','actor-41',{'operation':'enroll'})
        controller._finish('setup-1','actor-41','outcome_unknown')
        reopened=type(controller)(adapter,helper,controller.helper_sha256,controller.qualification)
        self.assertTrue(self.store.actor_held('actor-41'))
        with self.assertRaises(ValueError):reopened._qualified('actor-41')
        self.assertEqual('outcome_unknown',self.store.db.execute('SELECT state FROM actor_lease').fetchone()[0])

    def test_pause_after_preflight_refuses_enrollment_without_http_or_seed_access(self):
        controller,_,_=self.controller();controller._qualified('actor-41')
        self.store.db.execute("INSERT INTO meta VALUES ('paused','declared operator window')")
        with self.assertRaises(ValueError):controller._start('setup-1','actor-41',{'operation':'enroll'})
        self.assertEqual(0,self.store.db.execute('SELECT COUNT(*) FROM noah_control').fetchone()[0])

"""Synthetic Store lifecycle/public-oracle controls; no wallet or live credit."""
import asyncio
import concurrent.futures
import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock,patch

from simulator.engine import initialize
from simulator.model import InvariantError,canonical
from simulator.store import ActorHeld,Store


class PermanentAbsenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.store=Store(self.root,'synthetic',10000);initialize(self.store)
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def close_actor(self):return self.store.declare_permanent_absence('actor-02',reason='Original recipient permanently closed after authenticated receipt')
    def test_closed_actor_refuses_reactivation_new_intent_and_controller_lease_after_restart(self):
        proof=self.close_actor();self.assertFalse(self.store.online('actor-02'))
        self.assertEqual(proof,self.store.permanent_absence('actor-02'))
        self.store.close();self.store=Store(self.root,'synthetic',10000)
        with self.assertRaisesRegex(ActorHeld,'reactivation refused'):self.store.set_online('actor-02',True)
        for operation in ('create','snapshot','address','sync','board','send_arkoor','seed_recovery'):
            with self.subTest(operation=operation),self.assertRaisesRegex(ActorHeld,'new intent refused'):
                self.store.queue('new-'+operation,'actor-02','H01',operation,{},0)
        self.assertFalse(self.store.acquire_actor_lease('actor-02','controller','native setup'))
        self.assertFalse(self.store.ordinary_actor_available('actor-02'))
        self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM action').fetchone()[0])
    def test_queued_dispatched_or_unknown_action_prevents_close_without_cancel_or_rewrite(self):
        self.store.queue('original','actor-02','H01','snapshot',{},0)
        for state in ('queued','dispatched','outcome_unknown'):
            self.store.db.execute('UPDATE action SET state=? WHERE id=?',(state,'original'))
            before=[tuple(row) for row in self.store.db.execute('SELECT * FROM event ORDER BY sequence')]
            with self.subTest(state=state),self.assertRaisesRegex(ActorHeld,'no queued'):
                self.close_actor()
            self.assertEqual(state,self.store.db.execute('SELECT state FROM action').fetchone()[0])
            self.assertTrue(self.store.online('actor-02'));self.assertIsNone(self.store.permanent_absence('actor-02'))
            self.assertEqual(before,[tuple(row) for row in self.store.db.execute('SELECT * FROM event ORDER BY sequence')])
    def test_active_and_unknown_native_leases_prevent_close(self):
        self.assertTrue(self.store.acquire_actor_lease('actor-02','native-owner','setup'))
        for state in ('active','outcome_unknown'):
            self.store.db.execute('UPDATE actor_lease SET state=?',(state,))
            with self.subTest(state=state),self.assertRaises(ActorHeld):self.close_actor()
        self.store.db.execute("UPDATE actor_lease SET state='released'")
        self.close_actor()
    def test_legacy_private_controller_hold_prevents_close(self):
        self.store.db.execute('CREATE TABLE noah_control(id TEXT,actor TEXT,state TEXT)')
        self.store.db.execute("INSERT INTO noah_control VALUES('private','actor-02','started')")
        with self.assertRaises(ActorHeld):self.close_actor()
    def test_same_declaration_is_idempotent_and_original_actor_and_evidence_are_retained(self):
        self.store.queue('old-observation','actor-02','H01','snapshot',{},0)
        self.store.claim({'snapshot'});self.store.finish('old-observation','completed',{'status':'ok'},0)
        self.store.event('retained_public_receipt',{'actor':'actor-02','signed_source_reference':'public-original'})
        self.store.db.execute('UPDATE actor SET details=? WHERE id=?',(canonical({'retained':'original details'}),'actor-02'))
        before=[tuple(row) for row in self.store.db.execute('SELECT * FROM event ORDER BY sequence')]
        action=tuple(self.store.db.execute('SELECT * FROM action').fetchone());role=self.store.db.execute("SELECT role FROM actor WHERE id='actor-02'").fetchone()[0]
        proof=self.close_actor();count=self.store.db.execute('SELECT count(*) FROM event').fetchone()[0]
        self.assertEqual(proof,self.close_actor());self.assertEqual(count,self.store.db.execute('SELECT count(*) FROM event').fetchone()[0])
        with self.assertRaisesRegex(InvariantError,'immutable'):self.store.declare_permanent_absence('actor-02',reason='rewrite')
        self.assertEqual(before,[tuple(row) for row in self.store.db.execute('SELECT * FROM event ORDER BY sequence')][:len(before)])
        self.assertEqual(action,tuple(self.store.db.execute('SELECT * FROM action').fetchone()))
        actor=self.store.db.execute("SELECT role,details FROM actor WHERE id='actor-02'").fetchone()
        self.assertEqual(role,actor['role']);self.assertEqual('original details',json.loads(actor['details'])['retained'])
        self.store.verify_event_chain()
    def test_other_actor_and_reversible_offline_return_remain_available(self):
        self.close_actor();self.store.set_online('actor-01',False);self.store.queue('ordinary','actor-01','H01','snapshot',{},0)
        self.assertIsNone(self.store.claim({'snapshot'}));self.store.set_online('actor-01',True)
        self.assertEqual('ordinary',self.store.claim({'snapshot'})['id'])
        self.assertTrue(self.store.acquire_actor_lease('actor-04','another','setup'))
    def test_legacy_offline_metadata_alone_does_not_become_a_durable_declaration(self):
        self.store.db.execute('UPDATE actor SET details=? WHERE id=?',(canonical({'permanent_absence':True}),'actor-02'))
        self.store.set_online('actor-02',False);self.assertIsNone(self.store.permanent_absence('actor-02'))
        self.close_actor()
        with self.assertRaises(ActorHeld):self.store.set_online('actor-02',True)
    def test_claim_cannot_reactivate_stale_closed_actor_queue_or_ignore_missing_declaration(self):
        self.store.queue('previous','actor-02','H01','snapshot',{},0);self.store.claim({'snapshot'})
        self.store.finish('previous','completed',{'status':'ok'},0);self.close_actor()
        # Simulate stale/restored selector rows; the original closure still wins.
        self.store.db.execute("UPDATE actor SET online=1 WHERE id='actor-02'")
        self.store.db.execute("UPDATE action SET state='queued' WHERE id='previous'")
        self.assertIsNone(self.store.claim({'snapshot'}));self.assertFalse(self.store.has_runnable_queue())
        self.assertEqual(1,self.store.db.execute("SELECT count(*) FROM event WHERE kind='action_dispatched'").fetchone()[0])
        self.store.db.execute("DELETE FROM event WHERE kind='actor_permanent_absence_declared'")
        with self.assertRaisesRegex(InvariantError,'missing or changed'):self.store.set_online('actor-02',True)
    def test_unknown_actor_or_missing_reason_refuses(self):
        with self.assertRaisesRegex(ValueError,'unknown actor'):self.store.declare_permanent_absence('unknown',reason='closed')
        for reason in ('','x'*513,None):
            with self.subTest(reason=reason),self.assertRaises(ValueError):self.store.declare_permanent_absence('actor-02',reason=reason)

    def test_concurrent_queue_waits_for_closure_then_refuses_without_original_intent(self):
        entered=threading.Event();attempted=threading.Event();release=threading.Event();ready=threading.Barrier(2)
        def closer():
            store=Store(self.root,'synthetic',10000)
            try:
                ready.wait(timeout=5)
                with store.transaction():
                    store.declare_permanent_absence('actor-02',reason='prospective original identity closure')
                    entered.set();release.wait(5)
            finally:store.close()
        def queue():
            store=Store(self.root,'synthetic',10000)
            try:
                ready.wait(timeout=5);entered.wait(5);attempted.set()
                store.queue('racing-native','actor-02','H01','snapshot',{},0)
            finally:store.close()
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            closing=pool.submit(closer);queuing=pool.submit(queue)
            try:
                self.assertTrue(entered.wait(5));self.assertTrue(attempted.wait(5))
                with self.assertRaises(concurrent.futures.TimeoutError):queuing.result(timeout=0.05)
            finally:release.set()
            closing.result(timeout=5)
            with self.assertRaises(ActorHeld):queuing.result(timeout=5)
        self.assertFalse(self.store.online('actor-02'))
        self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM action').fetchone()[0])
        self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM event WHERE kind='action_intent'").fetchone()[0])


class AbsentPublicOracleTests(unittest.TestCase):
    def test_original_signed_public_proofs_and_direct_oracle_still_work_after_close(self):
        from tests.test_direct_settlements import DirectSettlementTests
        from simulator.direct_settlements import collect
        f=DirectSettlementTests();f.setUp()
        try:
            f.store.actor('actor-02','original absent recipient')
            f.store.db.execute("UPDATE owner_key SET actor='actor-02'");f.store.db.execute("UPDATE owner_record SET actor='actor-02'")
            original={table:[tuple(row) for row in f.store.db.execute('SELECT * FROM '+table)] for table in ('owner_key','owner_record','owned_coin')}
            f.store.declare_permanent_absence('actor-02',reason='Original public signed receipt retained; wallet closed')
            core=SimpleNamespace(transaction=lambda txid:f.tx)
            with patch('simulator.direct_settlements.json_command',new=AsyncMock(return_value=f.value)) as bridge,patch('simulator.engine.json_command',side_effect=AssertionError('native driver must remain closed')):
                checked=asyncio.run(collect(f.store,SimpleNamespace(inventory_command=('fixed-readonly-bridge',)),core))
            self.assertEqual(1,checked);self.assertEqual({'kind':'direct_journal'},bridge.call_args.args[1])
            self.assertEqual('actor-02',f.store.db.execute('SELECT actor FROM checked_settlement').fetchone()[0])
            for table,rows in original.items():self.assertEqual(rows,[tuple(row) for row in f.store.db.execute('SELECT * FROM '+table)])
            self.assertFalse(f.store.online('actor-02'));self.assertIsNotNone(f.store.permanent_absence('actor-02'))
        finally:f.tearDown()

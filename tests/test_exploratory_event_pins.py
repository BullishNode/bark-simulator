"""Actual Store queue/claim controls; synthetic sources earn no live credit."""
import json
import tempfile
import time
import unittest
from pathlib import Path

from simulator.engine import initialize
from simulator.final_campaign import _action_pins
from simulator.store import CampaignPaused, Store
from tests.test_final_campaign import PINS


class ExploratoryEventPinsTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name),'synthetic',10000)
        initialize(self.store)
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def qualify(self):self.store.db.execute("INSERT INTO meta VALUES ('financial_qualification_required','true')")
    def context(self,**changes):self.store.add_snapshot({'observed_at':time.time(),'financial_pins':PINS,**changes})
    def queue(self,identifier='cash-sync',operation='sync'):
        self.store.queue(identifier,'actor-01','H07',operation,{},0)

    def test_actual_exploratory_queue_and_claim_have_original_matching_pins(self):
        self.qualify();self.context()
        for operation in ('sync','snapshot'):
            identifier='cash-'+operation;self.queue(identifier,operation)
            self.assertEqual(identifier,self.store.claim({operation})['id'])
            _action_pins(self.store,identifier,PINS)
            self.store.finish(identifier,'completed',{'status':'ok'},0)
        for kind in ('action_intent','action_dispatched'):
            payload=json.loads(self.store.db.execute('SELECT payload FROM event WHERE kind=?',(kind,)).fetchone()[0])
            self.assertEqual(PINS,payload['financial_pins'])
        self.assertIsNone(self.store.get_meta('final_financial_epoch'));self.store.verify_event_chain()

    def test_missing_stale_or_malformed_context_refuses_queue_without_action(self):
        self.qualify()
        for snapshot in (None,{'observed_at':time.time()-91,'financial_pins':PINS},
                         {'observed_at':time.time(),'financial_pins':{}}, {'observed_at':time.time()}):
            with self.subTest(snapshot=snapshot):
                if snapshot is not None:self.store.add_snapshot(snapshot)
                with self.assertRaises(CampaignPaused):self.queue()
                self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM action').fetchone()[0])

    def test_latest_malformed_timestamp_cannot_reuse_a_previous_fresh_context(self):
        self.qualify();self.context()
        for observed in (None,True,'recent',{},-1):
            with self.subTest(observed=observed):
                payload={'financial_pins':PINS}
                if observed is not None:payload['observed_at']=observed
                # An old or malformed persisted row bypassed today's writer.
                self.store.db.execute('INSERT INTO snapshot(observed_at,payload) VALUES (?,?)',
                    (time.time(),json.dumps(payload)))
                with self.assertRaises(CampaignPaused):self.queue()
                self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM action').fetchone()[0])
                self.assertEqual(0,self.store.db.execute(
                    "SELECT count(*) FROM event WHERE kind='action_intent'").fetchone()[0])

    def test_stale_context_at_claim_rolls_back_without_dispatch(self):
        self.qualify();self.context();self.queue();self.context(observed_at=time.time()-91)
        with self.assertRaises(CampaignPaused):self.store.claim({'sync'})
        self.assertEqual('queued',self.store.db.execute('SELECT state FROM action').fetchone()[0])
        self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM event WHERE kind='action_dispatched'").fetchone()[0])

    def test_explicit_pins_cannot_bypass_missing_context_or_override_fresh_context(self):
        self.qualify()
        with self.assertRaises(CampaignPaused):self.store.event('action_intent',{'financial_pins':PINS})
        self.context()
        with self.assertRaises(CampaignPaused):self.store.event('action_intent',{'financial_pins':{**PINS,'sdk_commit':'9'*40}})

    def test_late_driver_evidence_is_preserved_without_inventing_current_pins(self):
        self.qualify();self.context();self.queue();self.store.claim({'sync'})
        self.context(observed_at=time.time()-120)
        evidence={'action_id':'cash-sync','progress':'retained after original admission'}
        self.store.event('driver_evidence',evidence)
        actual=json.loads(self.store.db.execute("SELECT payload FROM event WHERE kind='driver_evidence'").fetchone()[0])
        self.assertEqual(evidence,actual)

    def test_old_unqualified_events_are_not_rewritten_and_default_stays_unqualified(self):
        self.queue('old-unqualified')
        original=tuple(self.store.db.execute("SELECT * FROM event WHERE kind='action_intent'").fetchone())
        self.assertNotIn('financial_pins',json.loads(original[3]))
        self.qualify();self.context()
        self.assertEqual(original,tuple(self.store.db.execute("SELECT * FROM event WHERE kind='action_intent'").fetchone()))
        # The old intent still fails the unchanged reader, even if a future
        # dispatch is pinned. Operators must issue a new action identity.
        self.store.claim({'sync'})
        with self.assertRaisesRegex(ValueError,'original action pins differ'):
            _action_pins(self.store,'old-unqualified',PINS)


if __name__=='__main__':unittest.main()

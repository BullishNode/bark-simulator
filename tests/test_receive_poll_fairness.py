import json,time,unittest
from tests import test_continuous
from simulator.continuous import schedule


class ReceivePollFairnessTests(unittest.TestCase):
    setUp=test_continuous.ContinuousTests.setUp
    tearDown=test_continuous.ContinuousTests.tearDown
    detail=test_continuous.ContinuousTests.detail
    action=test_continuous.ContinuousTests.action

    def prior(self,state='completed',selected=None):
        hashes=[f'{i:064x}' for i in range(20)]
        self.detail('actor-06',needs_sync=True,board_submitted=True)
        self.s.queue('previous','actor-06','H01','sync',{},2000)
        data={'bounded_receive_sync':True,'receive_payment_hashes_before':hashes,
              'selected_receive_payment_hashes':hashes[:19] if selected is None else selected}
        self.s.db.execute('UPDATE action SET state=?,updated_at=?,result=? WHERE id=?',
            (state,time.time()-180,json.dumps({'data':data}),'previous'))
        return hashes

    def test_next_original_poll_starts_after_last_selected_checkpoint(self):
        hashes=self.prior()
        schedule(self.s,self.c,self.snapshot)
        action=self.action()
        self.assertEqual(('actor-06','sync'),(action['actor_id'],action['operation']))
        self.assertEqual({'receive_sync_start_after':hashes[18]},json.loads(action['args']))
        self.assertEqual(2000,action['fee_reservation_sat'])
        self.assertIsNone(self.s.db.execute('SELECT actual_fee_sat FROM action WHERE id="previous"').fetchone()[0])
        self.assertTrue(self.s.online('actor-06'))
        self.s.verify_event_chain()

    def test_unknown_prior_poll_is_not_replayed_or_rotated(self):
        self.prior(state='outcome_unknown')
        schedule(self.s,self.c,self.snapshot)
        self.assertIsNone(self.action())

    def test_malformed_boundary_is_not_used_as_a_cursor(self):
        self.prior(selected=['not-a-hash'])
        schedule(self.s,self.c,self.snapshot)
        self.assertEqual({},json.loads(self.action()['args']))

    def test_later_full_sync_discards_old_bounded_cursor(self):
        self.prior()
        self.s.queue('full','actor-06','H01','sync',{},2000)
        self.s.db.execute('UPDATE action SET state="completed",updated_at=?,result=? WHERE id="full"',
            (time.time()-180,json.dumps({'data':{'bounded_receive_sync':False}})))
        schedule(self.s,self.c,self.snapshot)
        self.assertEqual({},json.loads(self.action()['args']))

import json,time,unittest
from tests import test_continuous
from simulator.continuous import schedule,lightning_recipient
from simulator.workload import record_actor_result

class BoundedReceiveSyncTests(unittest.TestCase):
    setUp=test_continuous.ContinuousTests.setUp
    tearDown=test_continuous.ContinuousTests.tearDown
    detail=test_continuous.ContinuousTests.detail
    action=test_continuous.ContinuousTests.action
    def test_partial_native_sync_keeps_debt_and_invalidates_cached_balance(self):
        self.detail('actor-06',needs_sync=True)
        record_actor_result(self.s,'actor-06','sync',{'bounded_receive_sync':True,'receive_count_after':7})
        detail=json.loads(self.s.db.execute("SELECT details FROM actor WHERE id='actor-06'").fetchone()[0])
        self.assertTrue(detail['needs_sync'])
        self.assertEqual(0,detail['snapshot_at'])
        self.assertEqual(1000000,self.s.remaining_fee_budget())
    def test_final_normal_sync_clears_partial_debt(self):
        self.detail('actor-06',needs_sync=True)
        record_actor_result(self.s,'actor-06','sync',{'bounded_receive_sync':False,'receive_count_after':0})
        detail=json.loads(self.s.db.execute("SELECT details FROM actor WHERE id='actor-06'").fetchone()[0])
        self.assertFalse(detail['needs_sync'])
    def test_known_fee_block_does_not_immediately_repeat_unchanged_sync(self):
        self.detail('actor-12',registered_spendable_sat=12000)
        self.snapshot['capabilities']['lightning_configured']=True
        self.detail('actor-06',needs_sync=True)
        self.s.queue('fee-block','actor-06','H01','sync',{},2000)
        self.s.db.execute("UPDATE action SET state='blocked',actual_fee_sat=0,result=? WHERE id='fee-block'",(json.dumps({'data':{'blocked':True,'reason':'pending receive fees exceed this sync reserve'}}),))
        schedule(self.s,self.c,self.snapshot)
        queued=self.action()
        self.assertFalse(queued and queued['actor_id']=='actor-06' and queued['operation']=='sync')
        self.assertEqual(('actor-08','invoice'),(queued['actor_id'],queued['operation']))
        self.assertTrue(self.s.online('actor-06'))
    def test_unknown_receive_action_does_not_become_safe_fallback_or_retry(self):
        self.detail('actor-06',needs_sync=True)
        self.s.queue('lost','actor-06','H01','sync',{},2000)
        self.s.db.execute("UPDATE action SET state='outcome_unknown' WHERE id='lost'")
        schedule(self.s,self.c,self.snapshot)
        self.assertFalse(self.action())
        self.assertEqual(2000,self.s.db.execute("SELECT fee_reservation_sat FROM action WHERE id='lost'").fetchone()[0])

    def test_completed_partial_receive_sync_does_not_advertise_receiver_readiness(self):
        self.detail('actor-06',needs_sync=True)
        self.s.queue('partial','actor-06','H01','sync',{},2000)
        self.s.db.execute("UPDATE action SET state='completed',result=? WHERE id='partial'",(json.dumps({'data':{'bounded_receive_sync':True,'receive_count_after':20,'all_pending_receive_fee_ceiling_sat':2080,'selected_receive_fee_ceiling_sat':1976}}),))
        self.assertEqual('actor-08',lightning_recipient(self.s)[0])
        self.assertTrue(self.s.online('actor-06'))
        self.assertIsNone(self.s.db.execute("SELECT actual_fee_sat FROM action WHERE id='partial'").fetchone()[0])

    def test_full_original_sync_can_restore_receiver_selection(self):
        self.detail('actor-06',needs_sync=True)
        self.s.queue('partial','actor-06','H01','sync',{},2000)
        self.s.db.execute("UPDATE action SET state='completed',result=? WHERE id='partial'",(json.dumps({'data':{'bounded_receive_sync':True,'receive_count_after':0}}),))
        self.assertEqual('actor-08',lightning_recipient(self.s)[0])
        self.s.queue('full','actor-06','H01','sync',{},2000)
        self.s.db.execute("UPDATE action SET state='completed',actual_fee_sat=0,result=? WHERE id='full'",(json.dumps({'data':{'bounded_receive_sync':False,'receive_count_after':0}}),))
        record_actor_result(self.s,'actor-06','sync',{'bounded_receive_sync':False,'receive_count_after':0})
        self.assertEqual('actor-06',lightning_recipient(self.s)[0])

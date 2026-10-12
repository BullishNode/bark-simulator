import json
import time
import unittest
from test_continuous import ContinuousTests, ReceiveThenDisappearTests
from simulator.continuous import schedule, arm_receive_absence
from simulator.workload import record_actor_result


class LivenessRegressions(unittest.TestCase):
    setUp = ContinuousTests.setUp
    tearDown = ContinuousTests.tearDown
    detail = ContinuousTests.detail
    action = ContinuousTests.action
    boarded_actor = ContinuousTests.boarded_actor

    def test_snapshot_retains_refreshable_and_pending_round_balances(self):
        record_actor_result(self.s, 'actor-01', 'snapshot', {
            'balance': {'spendable_sat': 0, 'needs_refresh_sat': 2970,
                        'pending_in_round_sat': 500},
            'onchain': {'confirmed_sat': 1234}, 'vtxos': []})
        data = json.loads(self.s.db.execute(
            "SELECT details FROM actor WHERE id='actor-01'").fetchone()[0])
        self.assertEqual(2970, data.get('needs_refresh_sat'))
        self.assertEqual(500, data.get('pending_in_round_sat'))

    def test_zero_spendable_wallet_refreshes_before_dry_gate(self):
        self.boarded_actor(age=3601)
        self.detail('actor-01', registered_spendable_sat=0,
                    needs_refresh_sat=2970, board_submitted=True)
        schedule(self.s, self.c, self.snapshot)
        self.assertIsNotNone(self.action())
        self.assertEqual('refresh', self.action()['operation'])
        self.assertEqual(2000, self.action()['fee_reservation_sat'])

    def test_refreshable_coin_does_not_wait_for_hourly_cadence(self):
        self.boarded_actor(age=30)
        self.detail('actor-01', registered_spendable_sat=0,
                    needs_refresh_sat=2970, board_submitted=True)
        schedule(self.s, self.c, self.snapshot)
        self.assertIsNotNone(self.action())
        self.assertEqual('refresh', self.action()['operation'])

    def test_refreshable_wallet_syncs_before_refresh(self):
        self.detail('actor-01', registered_spendable_sat=0,
                    needs_refresh_sat=2970, board_submitted=True, needs_sync=True)
        schedule(self.s, self.c, self.snapshot)
        self.assertEqual('sync', self.action()['operation'])

    def test_delegated_refreshable_wallet_keeps_its_operation(self):
        self.detail('actor-07', registered_spendable_sat=0,
                    needs_refresh_sat=2970, board_submitted=True)
        self.s.queue('recent-sync', 'actor-07', 'H01', 'sync', {}, 0)
        self.s.db.execute("UPDATE action SET state='completed',actual_fee_sat=0 WHERE id='recent-sync'")
        schedule(self.s, self.c, self.snapshot)
        self.assertIsNotNone(self.action())
        self.assertEqual('refresh_delegated', self.action()['operation'])

    def payer(self, amount):
        self.snapshot['capabilities']['lightning_configured'] = True
        self.detail('actor-05', registered_spendable_sat=amount,
                    board_submitted=True, snapshot_at=time.time()-181)
        self.detail('actor-06', latest_invoice='fixture-invoice', invoice_action_id='invoice-peer')
        for actor in ['actor-05', 'actor-06']:
            self.s.queue('sync-'+actor, actor, 'H01', 'sync', {}, 0)
            self.s.db.execute("UPDATE action SET state='completed',actual_fee_sat=0 WHERE id=?", ('sync-'+actor,))
        self.s.queue('invoice-peer', 'actor-06', 'H40', 'invoice', {}, 0)
        self.s.db.execute("UPDATE action SET state='completed',actual_fee_sat=0 WHERE id='invoice-peer'")

    def test_payer_cannot_queue_two_thousand_plus_reserve_from_three_thousand(self):
        self.payer(3000)
        schedule(self.s, self.c, self.snapshot)
        self.assertEqual('snapshot', self.action()['operation'])

    def test_four_thousand_payer_can_queue_payment(self):
        self.payer(4000)
        schedule(self.s, self.c, self.snapshot)
        self.assertEqual('pay_invoice', self.action()['operation'])
        self.assertEqual(2000, json.loads(self.action()['args'])['amount_sat'])


class LightningAbsenceGuard(unittest.TestCase):
    setUp = ContinuousTests.setUp
    tearDown = ContinuousTests.tearDown
    detail = ContinuousTests.detail
    action = ContinuousTests.action
    receive = ReceiveThenDisappearTests.receive

    def test_retirement_never_leaves_only_one_online_invoice_candidate(self):
        self.receive('actor-06', rail='lightning')
        self.s.set_online('actor-07', False)
        self.s.set_online('actor-02', False)
        self.assertFalse(arm_receive_absence(self.s, 'actor-06', 'lightning'))
        self.assertTrue(self.s.online('actor-06'))

    def test_three_candidates_allow_retirement_and_leave_two(self):
        self.receive('actor-06', rail='lightning')
        self.s.set_online('actor-02', False)
        self.assertTrue(arm_receive_absence(self.s, 'actor-06', 'lightning'))
        self.assertFalse(self.s.online('actor-06'))
        self.assertTrue(self.s.online('actor-07'))
        self.assertTrue(self.s.online('actor-08'))

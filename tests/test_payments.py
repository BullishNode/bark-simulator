import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from simulator.campaign import traffic_ready
from simulator.engine import initialize
from simulator.model import InvariantError
from simulator.payments import collect, payment_hash, record_status
from simulator.store import Store


class PaymentOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name), 'synthetic', 10000)
        initialize(self.store)
        self.hash = 'a' * 64
        self.add_payment('send')

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def add_payment(self, identity):
        self.store.queue(identity, 'actor-05', 'H13', 'pay_invoice', {'amount_sat': 1000}, 500)
        self.store.db.execute("UPDATE action SET state='dispatched' WHERE id=?", (identity,))
        self.store.event('driver_evidence', {'action_id': identity, 'event': 'lightning_proposal',
            'data': {'payment_hash': self.hash, 'amount_sat': 1000, 'input_vtxo_ids': ['coin']}})
        self.store.finish(identity, 'completed', {'data': {
            'payment_hash': self.hash, 'initiated': True, 'paid': False}})

    def action(self, identity='send'):
        return self.store.db.execute('SELECT * FROM action WHERE id=?', (identity,)).fetchone()

    def response(self, state='succeeded', identity='send'):
        return {'action_id': 'payment-status:' + identity, 'status': 'ok', 'actual_fee_sat': 0,
            'data': {'payment_hash': self.hash, 'read_only': True, 'state': state,
                'success_preimage_hash_valid': state == 'succeeded'}}

    def record(self, response):
        record_status(self.store, self.action(), self.hash, response, 'payment-status:send')

    def test_success_earns_traffic_only_once_and_never_releases_fee_reserve(self):
        now = self.action()['updated_at']
        self.store.db.execute("INSERT INTO meta VALUES ('real_campaign_started',?)", (str(now - 1),))
        self.store.queue('ark', 'actor-01', 'H07', 'send_arkoor', {}, 0)
        self.store.db.execute("UPDATE action SET state='completed',result=?,updated_at=? WHERE id='ark'",
            (json.dumps({'data': {'submitted': 'send_arkoor'}}), now))
        # Payment outcome test starts with an already proven Ark receipt.
        self.store.event('ark_transfer_verified', {'action_id': 'ark', 'verified_at': now})
        self.assertFalse(traffic_ready(self.store))
        remaining = self.store.remaining_fee_budget()
        self.record(self.response())
        self.assertTrue(traffic_ready(self.store))
        observed_at = self.action()['updated_at']
        self.record(self.response())
        self.assertEqual(observed_at, self.action()['updated_at'])
        self.assertEqual(remaining, self.store.remaining_fee_budget())
        self.assertIsNone(self.action()['actual_fee_sat'])
        self.assertEqual(1, self.store.db.execute(
            "SELECT COUNT(*) FROM event WHERE kind='lightning_payment_outcome'").fetchone()[0])
        self.store.verify_event_chain()

    def test_pending_failed_and_silent_status_never_become_success_or_refund(self):
        updated = self.action()['updated_at']
        self.record(self.response('pending'))
        self.assertEqual(updated, self.action()['updated_at'])
        self.record(self.response('failed'))
        data = json.loads(self.action()['result'])['data']
        self.assertFalse(data['paid'])
        self.assertEqual('failed', data['payment_state'])
        self.assertIsNone(self.action()['actual_fee_sat'])
        self.assertEqual('completed', self.action()['state'])
        with self.assertRaises(InvariantError):
            self.record(self.response('succeeded'))

    def test_wrong_hash_query_or_missing_preimage_proof_is_an_incident(self):
        for field, value in [('payment_hash', 'b' * 64),
                             ('success_preimage_hash_valid', False), ('read_only', False)]:
            response = self.response()
            response['data'][field] = value
            with self.assertRaises(InvariantError):
                self.record(response)
        response = self.response()
        response['action_id'] = 'another-query'
        with self.assertRaises(InvariantError):
            self.record(response)
        self.assertFalse(json.loads(self.action()['result'])['data']['paid'])

    def test_result_hash_must_match_frozen_invoice_proposal(self):
        self.assertEqual(self.hash, payment_hash(self.store, self.action()))
        changed = json.loads(self.action()['result'])
        changed['data']['payment_hash'] = 'b' * 64
        self.store.db.execute('UPDATE action SET result=? WHERE id=?', (json.dumps(changed), 'send'))
        with self.assertRaises(InvariantError):
            payment_hash(self.store, self.action())

    def test_querying_offline_sender_does_not_open_wallet_or_dispatch_payment_again(self):
        self.store.set_online('actor-05', False)
        call = AsyncMock(return_value=self.response())
        with patch('simulator.payments.json_command', call):
            asyncio.run(collect(self.store, ['native-driver'], 'server'))
            asyncio.run(collect(self.store, ['native-driver'], 'server'))
        self.assertEqual(1, call.await_count)
        request = call.call_args.args[1]
        self.assertIsNone(request['actor_dir'])
        self.assertEqual('lightning_payment_status', request['operation'])
        self.assertFalse(self.store.online('actor-05'))
        self.assertEqual(1, self.store.db.execute('SELECT COUNT(*) FROM action').fetchone()[0])
        self.assertIsNone(self.action()['actual_fee_sat'])

    def test_timeout_preserves_reservation_and_pending_evidence(self):
        with patch('simulator.payments.json_command', AsyncMock(side_effect=TimeoutError)):
            asyncio.run(collect(self.store, ['native-driver'], 'server'))
        self.assertFalse(json.loads(self.action()['result'])['data']['paid'])
        self.assertIsNone(self.action()['actual_fee_sat'])
        self.store.verify_event_chain()

    def test_bounded_round_robin_checks_each_pending_payment(self):
        self.add_payment('send-2')
        self.add_payment('send-3')
        async def pending(command, request, timeout):
            return self.response('pending', request['action_id'].removeprefix('payment-status:'))
        call = AsyncMock(side_effect=pending)
        with patch('simulator.payments.json_command', call):
            asyncio.run(collect(self.store, ['native-driver'], 'server', limit=2))
            asyncio.run(collect(self.store, ['native-driver'], 'server', limit=2))
        ids = [c.args[1]['action_id'] for c in call.call_args_list]
        self.assertEqual(['payment-status:send', 'payment-status:send-2',
            'payment-status:send-3', 'payment-status:send'], ids)


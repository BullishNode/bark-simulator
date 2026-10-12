"""Clock tests use explicit synthetic public proofs, never client wallet reads."""
import json
import tempfile
import unittest
from pathlib import Path

from simulator import campaign
from simulator.engine import initialize
from simulator.model import canonical
from simulator.store import Store


class VerifiedClockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name), 'synthetic', 10000)
        initialize(self.store)
        self.store.db.execute("INSERT INTO meta VALUES ('real_campaign_started','100')")
        self.input_id = 'a' * 64 + ':0'
        self.output_id = 'c' * 64 + ':0'
        self.receive_tx = 'b' * 64
        self.address('address', 'actor-02', 'destination', 'recipient-key')
        self.coin(self.input_id, 'actor-01', 'sender-key', 6000, [], 'input-observation', 101)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def action(self, identity, actor, operation, args, data, at, state='completed'):
        if self.store.db.execute('SELECT 1 FROM action WHERE id=?', (identity,)).fetchone() is None:
            self.store.queue(identity, actor, 'H07', operation, args, 0)
        self.store.db.execute('UPDATE action SET state=?,result=?,updated_at=? WHERE id=?',
            (state, canonical({'data': data}), at, identity))

    def address(self, identity, actor, destination, key):
        self.action(identity, actor, 'address', {}, {'address': destination, 'user_pubkey': key}, 100)
        bound = {'mailbox_pk': actor, 'key_link_signature_valid': True, 'record_signature_valid': True}
        self.store.db.execute('INSERT OR IGNORE INTO owner_key VALUES (?,?,?,?)',
            (key, actor, actor, canonical({'binding': bound})))

    def coin(self, identity, actor, key, amount, path, observation, at, proven=True):
        bound = {'mailbox_pk': actor, 'key_link_signature_valid': True, 'record_signature_valid': True}
        self.store.db.execute('INSERT OR IGNORE INTO owner_key VALUES (?,?,?,?)',
            (key, actor, actor, canonical({'binding': bound})))
        proof = {'id': identity, 'user_pubkey': key, 'amount_sat': amount,
            'signed_path_valid': proven, 'anchor_confirmations': 1, 'binding': bound, 'path': path}
        self.store.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',
            (identity, key, amount, 'hash', '00', canonical(proof)))
        if self.store.db.execute('SELECT 1 FROM action WHERE id=?', (observation,)).fetchone() is None:
            self.action(observation, actor, 'sync', {}, {}, at)
        self.store.db.execute('INSERT INTO coin_observation VALUES (?,?,?,?)',
            (identity, observation, 'Spendable', at))

    def send(self, identity='send', at=200, recipient='actor-02', inputs=None, amount=1000, state='completed'):
        inputs = [self.input_id] if inputs is None else inputs
        movement = {'id': 'sender-movement', 'subsystem': 'bark.arkoor', 'status': 'successful',
            'input_vtxos': inputs, 'output_vtxos': [], 'effective_balance_sat': -amount,
            'offchain_fee_sat': 0, 'payment_hash': None}
        self.action(identity, 'actor-01', 'send_arkoor',
            {'recipient_actor': recipient, 'destination': 'destination', 'amount_sat': amount},
            {'submitted': 'send_arkoor', 'amount_sat': amount, 'evidence': {'movements': [movement]}}, at, state)
        self.store.event('driver_evidence', {'action_id': identity, 'event': 'arkoor_request',
            'data': {'destination': 'destination', 'amount_sat': amount, 'input_vtxo_ids': inputs}})
        self.store.db.execute('INSERT OR REPLACE INTO movement_evidence VALUES (?,?,?)',
            ('actor-01', movement['id'], canonical(movement)))

    def receipt(self, actor='actor-02', key='recipient-key', amount=1000, parent=None,
                at=201, proven=True, movement_status='successful', identity=None):
        identity = self.output_id if identity is None else identity
        path = [{'txid': self.receive_tx, 'output_index': 0, 'output_amount_sat': amount,
                 'inputs': [self.input_id if parent is None else parent]},
                {'txid': identity.split(':')[0], 'output_index': 0, 'output_amount_sat': amount,
                 'inputs': [self.receive_tx + ':0']}]
        self.coin(identity, actor, key, amount, path, 'receipt-observation', at, proven)
        movement = {'id': 'receive-movement', 'subsystem': 'bark.arkoor', 'status': movement_status,
            'input_vtxos': [], 'output_vtxos': [identity], 'effective_balance_sat': amount,
            'offchain_fee_sat': 0, 'payment_hash': None}
        self.store.db.execute('INSERT INTO movement_evidence VALUES (?,?,?)',
            (actor, movement['id'], canonical(movement)))

    def lightning(self, at=200, state='completed'):
        self.action('lightning', 'actor-05', 'pay_invoice', {},
            {'paid': True, 'payment_status_verified': True, 'payment_state': 'succeeded'}, at, state)

    def collect(self, now=201):
        campaign.collect_ark_receipts(self.store, now=now)

    def credit(self, at=200):
        self.store.event('ark_transfer_verified', {'action_id': 'send', 'verified_at': at})

    def test_submitted_only_does_not_qualify(self):
        self.send(); self.lightning()
        self.assertFalse(campaign.traffic_ready(self.store, 201))

    def test_stale_lightning_and_recent_ark_do_not_qualify(self):
        self.send(at=4000); self.credit(4000); self.lightning(at=200)
        self.assertFalse(campaign.traffic_ready(self.store, 4001))

    def test_each_rail_has_its_own_inclusive_window(self):
        self.send(at=3200); self.credit(3200); self.lightning(at=200)
        self.assertTrue(campaign.traffic_ready(self.store, 3800))
        self.assertFalse(campaign.traffic_ready(self.store, 3800.1))
        self.store.db.execute("UPDATE action SET updated_at=3800 WHERE id='lightning'")
        self.assertFalse(campaign.traffic_ready(self.store, 3800.1))

    def test_signed_receipt_tied_to_frozen_send_qualifies_once(self):
        self.send(); self.receipt(); self.lightning()
        self.collect()
        self.assertTrue(campaign.traffic_ready(self.store, 201))
        first = self.store.db.execute("SELECT payload FROM event WHERE kind='ark_transfer_verified'").fetchone()[0]
        self.collect(now=500)
        rows = self.store.db.execute("SELECT payload FROM event WHERE kind='ark_transfer_verified'").fetchall()
        self.assertEqual([first], [r[0] for r in rows])
        self.assertFalse(campaign.traffic_ready(self.store, 802))
        self.store.verify_event_chain()

    def test_wrong_recipient_key_amount_or_unrelated_parent_never_qualifies(self):
        for kwargs in ({'actor': 'actor-03'}, {'key': 'wrong-key'}, {'amount': 999},
                       {'parent': 'unrelated:0'}, {'proven': False}, {'movement_status': 'pending'}):
            with self.subTest(kwargs=kwargs):
                self.send(); self.receipt(**kwargs); self.lightning(); self.collect()
                self.assertFalse(campaign.traffic_ready(self.store, 201))
                self.store.db.execute("DELETE FROM movement_evidence WHERE actor<>'actor-01'")
                self.store.db.execute("DELETE FROM coin_observation WHERE coin_id=?", (self.output_id,))
                self.store.db.execute('DELETE FROM owned_coin WHERE id=?', (self.output_id,))
                self.store.db.execute("DELETE FROM action WHERE id IN ('send','lightning')")
                self.store.db.execute("DELETE FROM event WHERE kind='driver_evidence'")

    def test_unknown_send_and_unknown_receipt_observation_do_not_qualify(self):
        self.send(state='outcome_unknown'); self.receipt(); self.lightning(); self.collect()
        self.assertFalse(campaign.traffic_ready(self.store, 201))
        self.store.db.execute("UPDATE action SET state='completed' WHERE id='send'")
        self.store.db.execute("UPDATE action SET state='outcome_unknown' WHERE id='receipt-observation'")
        self.collect()
        self.assertFalse(campaign.traffic_ready(self.store, 201))

    def test_unproven_input_and_missing_frozen_request_do_not_qualify(self):
        self.send(); self.receipt(); self.lightning()
        proof = json.loads(self.store.db.execute('SELECT proof FROM owned_coin WHERE id=?', (self.input_id,)).fetchone()[0])
        proof['signed_path_valid'] = False
        self.store.db.execute('UPDATE owned_coin SET proof=? WHERE id=?', (canonical(proof), self.input_id))
        self.collect()
        self.assertFalse(campaign.traffic_ready(self.store, 201))
        proof['signed_path_valid'] = True
        self.store.db.execute('UPDATE owned_coin SET proof=? WHERE id=?', (canonical(proof), self.input_id))
        self.store.db.execute("DELETE FROM event WHERE kind='driver_evidence'")
        self.collect()
        self.assertFalse(campaign.traffic_ready(self.store, 201))

    def test_two_sends_sharing_frozen_inputs_are_ambiguous(self):
        self.send(); self.send('duplicate', at=200); self.receipt(); self.lightning(); self.collect()
        self.assertFalse(campaign.traffic_ready(self.store, 201))

    def test_archive_reverification_does_not_create_recent_activity(self):
        self.send(); self.receipt(); self.lightning(at=3900)
        self.collect(now=4000)
        self.assertFalse(campaign.traffic_ready(self.store, 4000))
        row = self.store.db.execute("SELECT payload FROM event WHERE kind='ark_transfer_verified'").fetchone()
        self.assertEqual(201, json.loads(row[0])['verified_at'])

    def test_future_setup_and_invoice_activity_are_excluded(self):
        self.send(at=90); self.credit(90); self.lightning(at=90)
        self.assertFalse(campaign.traffic_ready(self.store, 201))
        self.store.db.execute("UPDATE action SET updated_at=1000 WHERE id='send'")
        self.credit(1000); self.lightning(at=1000)
        self.assertFalse(campaign.traffic_ready(self.store, 201))

    def test_legacy_send_without_actor_label_uses_unique_frozen_address(self):
        self.send(); self.receipt(); self.lightning()
        self.store.db.execute("UPDATE action SET args=? WHERE id='send'", (canonical(
            {'destination': 'destination', 'amount_sat': 1000}),))
        self.collect()
        self.assertTrue(campaign.traffic_ready(self.store, 201))

    def test_legacy_send_with_ambiguous_advertising_actors_is_held(self):
        self.send(); self.receipt(); self.lightning()
        self.address('competing-address', 'actor-03', 'destination', 'competing-key')
        self.store.db.execute("UPDATE action SET args=? WHERE id='send'", (canonical(
            {'destination': 'destination', 'amount_sat': 1000}),))
        self.collect()
        self.assertFalse(campaign.traffic_ready(self.store, 201))

    def test_frozen_destination_amount_and_sender_movement_must_match(self):
        self.send(); self.receipt(); self.lightning()
        original = self.store.db.execute("SELECT result FROM action WHERE id='send'").fetchone()[0]
        for field, value in [('amount_sat', 999), ('destination', 'wrong-destination')]:
            args = {'recipient_actor': 'actor-02', 'destination': 'destination', 'amount_sat': 1000}
            args[field] = value
            self.store.db.execute("UPDATE action SET args=? WHERE id='send'", (canonical(args),))
            self.collect()
            self.assertFalse(campaign.traffic_ready(self.store, 201))
        self.store.db.execute("UPDATE action SET args=? WHERE id='send'", (canonical(
            {'recipient_actor': 'actor-02', 'destination': 'destination', 'amount_sat': 1000}),))
        for field, value in [('input_vtxos', ['unrelated:0']), ('effective_balance_sat', -999),
                             ('status', 'pending')]:
            result = json.loads(original)
            result['data']['evidence']['movements'][0][field] = value
            self.store.db.execute("UPDATE action SET result=? WHERE id='send'", (canonical(result),))
            self.collect()
            self.assertFalse(campaign.traffic_ready(self.store, 201))

    def test_receipt_without_completed_observation_or_future_observation_is_held(self):
        self.send(); self.receipt(); self.lightning()
        self.store.db.execute("UPDATE action SET updated_at=300 WHERE id='receipt-observation'")
        self.collect()
        self.assertFalse(campaign.traffic_ready(self.store, 201))
        self.store.db.execute("DELETE FROM coin_observation WHERE coin_id=?", (self.output_id,))
        self.collect(now=301)
        self.assertFalse(campaign.traffic_ready(self.store, 301))

    def test_offline_recipient_public_proofs_do_not_open_wallet_or_dispatch(self):
        self.send(); self.receipt(); self.lightning()
        self.store.set_online('actor-02', False)
        count = self.store.db.execute('SELECT COUNT(*) FROM action').fetchone()[0]
        reserve = self.store.remaining_fee_budget()
        self.collect()
        self.assertTrue(campaign.traffic_ready(self.store, 201))
        self.assertFalse(self.store.online('actor-02'))
        self.assertEqual(count, self.store.db.execute('SELECT COUNT(*) FROM action').fetchone()[0])
        self.assertEqual(reserve, self.store.remaining_fee_budget())

    def test_later_different_receive_cannot_reuse_a_frozen_input_as_arbitrary_ancestor(self):
        self.send(); self.receipt(); self.lightning()
        row = self.store.db.execute('SELECT proof FROM owned_coin WHERE id=?', (self.output_id,)).fetchone()
        proof = json.loads(row[0])
        proof['path'][0]['output_amount_sat'] = 2000
        self.store.db.execute('UPDATE owned_coin SET proof=? WHERE id=?', (canonical(proof), self.output_id))
        self.collect()
        self.assertFalse(campaign.traffic_ready(self.store, 201))

    def test_migration_preserves_old_counter_and_history_once(self):
        plan = campaign.RampPlan()
        self.store.db.execute("INSERT INTO meta VALUES ('ramp_plan',?)", (canonical(plan.__dict__),))
        self.store.db.execute("INSERT INTO meta VALUES ('campaign_active_seconds','5943.6')")
        self.store.event('campaign_active_interval', {'seconds': 120, 'total_seconds': 5943.6})
        now = [0]
        clock = campaign.CampaignClock(self.store, plan, clock=lambda: now[0])
        self.assertEqual('5943.6', self.store.get_meta('campaign_active_seconds'))
        self.assertEqual('5943.6', self.store.get_meta('legacy_clock_seconds'))
        self.assertEqual(0, float(self.store.get_meta('qualified_campaign_active_seconds')))
        clock.tick(healthy=True, real_campaign_started=True)
        now[0] = 120
        self.assertEqual(120, clock.tick(healthy=True, real_campaign_started=True))
        restarted = campaign.CampaignClock(self.store, plan, clock=lambda: now[0])
        now[0] += 86400
        self.assertEqual(120, restarted.tick(healthy=True, real_campaign_started=True))
        self.assertEqual('5943.6', self.store.get_meta('campaign_active_seconds'))
        self.assertEqual(1, self.store.db.execute("SELECT COUNT(*) FROM event WHERE kind='qualified_clock_migrated'").fetchone()[0])
        self.assertEqual(1, self.store.db.execute("SELECT COUNT(*) FROM event WHERE kind='campaign_active_interval'").fetchone()[0])
        self.store.verify_event_chain()

    def test_old_threshold_does_not_trigger_new_ramp_until_qualified_time_reaches_it(self):
        self.store.db.execute("INSERT INTO meta VALUES ('campaign_active_seconds','10800')")
        self.store.db.execute("INSERT INTO meta VALUES ('ramp_plan',?)", (canonical(campaign.RampPlan().__dict__),))
        now = [0]
        clock = campaign.CampaignClock(self.store, campaign.RampPlan(), clock=lambda: now[0])
        clock.tick(healthy=True, real_campaign_started=True)
        now[0] = 120
        self.assertEqual(120, clock.tick(healthy=True, real_campaign_started=True))
        self.assertIsNone(self.store.get_meta('ramp_applied'))
        self.assertEqual(12, self.store.db.execute('SELECT COUNT(*) FROM actor').fetchone()[0])
        for _ in range(89):
            now[0] += 120
            clock.tick(healthy=True, real_campaign_started=True)
        self.assertEqual('true', self.store.get_meta('ramp_applied'))
        self.assertEqual(24, self.store.db.execute('SELECT COUNT(*) FROM actor').fetchone()[0])
        self.assertEqual('10800', self.store.get_meta('campaign_active_seconds'))
        self.assertEqual(0, self.store.db.execute('SELECT COUNT(*) FROM action').fetchone()[0])
        self.store.verify_event_chain()

    def test_old_applied_ramp_never_replays(self):
        self.store.db.execute("INSERT INTO meta VALUES ('campaign_active_seconds','10800')")
        self.store.db.execute("INSERT INTO meta VALUES ('ramp_plan',?)", (canonical(campaign.RampPlan().__dict__),))
        self.store.db.execute("INSERT INTO meta VALUES ('ramp_applied','true')")
        self.store.actor('actor-13', 'previously ramped client')
        now = [0]
        clock = campaign.CampaignClock(self.store, campaign.RampPlan(after_active_seconds=10800), clock=lambda: now[0])
        clock.tick(healthy=True, real_campaign_started=True)
        now[0] = 120
        clock.tick(healthy=True, real_campaign_started=True)
        self.assertEqual(13, self.store.db.execute('SELECT COUNT(*) FROM actor').fetchone()[0])
        self.assertEqual(0, self.store.db.execute("SELECT COUNT(*) FROM event WHERE kind='client_ramp_applied'").fetchone()[0])

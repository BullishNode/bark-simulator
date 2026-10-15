"""Synthetic direct-settlement/recovery glue; no native or live money credit."""
import json
import unittest
from decimal import Decimal
from types import SimpleNamespace

import test_direct_settlements as fixtures
from simulator.direct_settlements import commit_checked, record
from simulator.model import InvariantError, SIGNET_GENESIS, canonical
from simulator.recovery import RecoveryController


class DirectRecoverySources(unittest.TestCase):
    def setUp(self):
        fixtures.DirectSettlementTests.setUp(self)
        self.store.actor('actor-02', 'synthetic absent recipient')
        self.store.set_online('actor-02', False)
        self.store.db.execute("UPDATE owner_key SET actor='actor-02'")
        self.store.db.execute("UPDATE owner_record SET actor='actor-02'")
        self.proof['path'][0]['outputs'][0]['value_sat'] = 2000
        self.store.db.execute('UPDATE owned_coin SET amount_sat=2000,proof=?', (canonical(self.proof),))
        self.alloc.update(gross_sat=2000, payout_sat=1000)
        self.tx['inputs'][0]['amount_sat'] = 3000
        self.tx['outputs'][0]['amount_sat'] = 1000
        record(self.store, self.value)
        result = fixtures.DirectSettlementTests.check(self)
        commit_checked(self.store, result, self.tx)
        fixture = self

        class PublicCore:
            def call(self, method, *args):
                if method == 'getrawtransaction':
                    fixture.assertEqual((fixture.tx['txid'], True), args)
                    return {'txid': fixture.tx['txid'], 'confirmations': fixture.tx['confirmations'],
                            'blockhash': fixture.tx['blockhash'], 'vout': [
                                {'n': output['vout'], 'value': Decimal(output['amount_sat']) / 100000000,
                                 'scriptPubKey': {'hex': output['script']}} for output in fixture.tx['outputs']]}
                if method == 'gettxout':
                    fixture.assertEqual((fixture.tx['txid'], 0, True), args)
                    return {'confirmations': fixture.tx['confirmations'], 'value': Decimal('0.00001000'),
                            'scriptPubKey': {'hex': fixture.script}}
                raise AssertionError('only independent public payout reads are permitted')

        config = SimpleNamespace(network='signet', expected_genesis=SIGNET_GENESIS,
                                 recovery_maximum_fee_sat=2000, action_fee_reserve_sat=2000,
                                 recovery_fee_rate_sat_vb=1, recovery_timeout_seconds=30,
                                 trace_enabled=False)
        self.controller = RecoveryController(self.store, config, rpc=PublicCore())

    tearDown = fixtures.DirectSettlementTests.tearDown

    def test_confirmed_direct_checked_payout_is_visible_without_legacy_marker(self):
        self.assertIsNone(self.store.db.execute('SELECT 1 FROM settlement_check').fetchone())
        self.assertEqual([{'outpoint': self.tx['txid'] + ':0', 'script': self.script, 'amount_sat': 1000}],
                         self.controller._sources('actor-02'))
        self.assertIsNone(self.store.db.execute('SELECT 1 FROM seed_recovery').fetchone())

    def test_unconfirmed_direct_payout_is_not_a_recovery_source(self):
        self.tx['confirmations'] = 0
        self.assertEqual([], self.controller._sources('actor-02'))

    def test_pending_marker_and_foreign_actor_never_select_the_payout(self):
        self.assertEqual([], self.controller._sources('actor-01'))
        self.store.db.execute("UPDATE direct_check SET state='pending'")
        self.store.db.execute("INSERT INTO settlement_check VALUES (?,'amounts_checked',NULL,0)", (self.tx['txid'],))
        self.assertEqual([], self.controller._sources('actor-02'))

    def test_current_core_output_must_still_match_the_checked_payout(self):
        self.tx['outputs'][0]['script'] = self.operator
        with self.assertRaises(InvariantError):
            self.controller._sources('actor-02')

    def test_unchecked_extra_allocation_cannot_claim_the_same_grouped_output(self):
        self.store.db.execute('INSERT INTO checked_settlement VALUES (?,?,?,?,?,?)',
                              ('99' * 32 + ':0', self.tx['txid'], 'actor-02', self.script, 1000, '{}'))
        with self.assertRaises(InvariantError):
            self.controller._sources('actor-02')

    def test_direct_mapping_must_match_exact_checked_output(self):
        key = canonical([self.tx['txid'], self.customer])
        self.store.db.execute("UPDATE direct_journal_object SET payload=? WHERE kind='mappings' AND id=?",
                              (canonical({'txid': self.tx['txid'], 'allocation_id': self.customer, 'vout': 1}), key))
        with self.assertRaises(InvariantError):
            self.controller._sources('actor-02')

    def test_direct_source_identity_and_original_checked_event_are_required(self):
        for mutation in ('actor', 'source', 'marker', 'event'):
            with self.subTest(mutation=mutation):
                self.store.db.execute('SAVEPOINT negative')
                try:
                    if mutation in ('actor', 'source'):
                        row = self.store.db.execute('SELECT evidence FROM checked_settlement').fetchone()
                        evidence = json.loads(row[0])
                        evidence[mutation] = 'actor-01' if mutation == 'actor' else 'unregistered'
                        self.store.db.execute('UPDATE checked_settlement SET evidence=?', (canonical(evidence),))
                    elif mutation == 'marker':
                        self.store.db.execute("UPDATE direct_check SET payload=?", (canonical({'txid': '99' * 32}),))
                    else:
                        self.store.db.execute("DELETE FROM event WHERE kind='direct_payment_checked'")
                    with self.assertRaises(InvariantError):
                        self.controller._sources('actor-02')
                finally:
                    self.store.db.execute('ROLLBACK TO negative')
                    self.store.db.execute('RELEASE negative')

    def test_already_frozen_input_is_not_selected_again(self):
        self.store.db.execute("INSERT INTO seed_recovery VALUES ('prior','actor-02','held','{}',NULL,NULL,NULL,NULL,0)")
        self.store.db.execute("INSERT INTO seed_recovery_input VALUES (?,'prior')", (self.tx['txid'] + ':0',))
        self.assertEqual([], self.controller._sources('actor-02'))

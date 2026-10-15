"""Synthetic original-event controls; no native wallet/Core/payment execution."""
import unittest
from types import SimpleNamespace

from simulator import identity_bootstrap as bootstrap
from simulator.engine import Lease
from simulator.model import SIGNET_GENESIS
from simulator.operating_limits import declare_envelope
from simulator.treasury import declare_boundary, capture_assets
from tests import test_identity_bootstrap
from tests.test_closed_cohort_sources import Chain as ZeroChain
from tests.test_treasury import Chain


class BootstrapFinancialDeclarationsTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_identity_bootstrap.IdentityBootstrapTests('test_fresh_hashed_context_allows_only_zero_fee_create_with_existing_lease')
        self.fixture.setUp()
        f = self.fixture
        f.value['actors'] = ['actor-01']
        f.declare()
        self.store = f.store
        self.store.attach_trace()
        action = f.action()
        with Lease(f.wallets):
            bootstrap.begin(self.store, f.config, f.snapshot, action)
        response = {'action_id': action['id'], 'status': 'ok', 'actual_fee_sat': 0,
            'data': {'onchain_inventory': {'schema_version': 1, 'network': 'signet', 'read_only': True,
                'complete': True, 'descriptors': [{'keychain': 'external',
                    'descriptor': 'wpkh(public)#checksum', 'last_revealed_index': 1}],
                'utxos': [], 'pending_transactions': [], 'pending_parents': [], 'unavailable_parent_txids': []}}}
        self.store.event('driver_response', {'action_id': action['id'], 'response': response})
        self.store.finish(action['id'], 'completed', response, 0)
        bootstrap.verify_created(self.store, f.config, ZeroChain(), 'actor-01', action['id'])
        self.store.db.execute("INSERT INTO meta VALUES ('paused','declare money boundary')")
        self.action_id = action['id']
        self.chain = Chain()
        self.members = []
        for identifier, role in [('operator', 'operator'), ('actor-01', 'customer')]:
            member = {'id': identifier, 'kind': 'wallet', 'role': role, 'identity': identifier,
                      'descriptors': ['wpkh(' + identifier + ')#checksum']}
            self.store.event('treasury_member_verified', {'member': member, 'genesis': SIGNET_GENESIS,
                                                         'financial_pins': f.pins})
            self.members.append({**member, 'verification_sequence': self.sequence()})
        self.boundary = {'id': 'after-bootstrap', 'genesis': SIGNET_GENESIS, 'pins': f.pins,
                         'members': self.members, 'excluded': ['miners']}
        self.limits = {'id': 'bounded', 'pins': f.pins, 'boundary_id': 'after-bootstrap',
            'capital_exposure_msat': 2000000, 'fee_budgets_msat': {'ordinary': 500000, 'urgent': 500000},
            'fee_ceilings_sat_kvb': dict.fromkeys(['round','pool','sweep','payout','claim','progression'], 2000),
            'per_action_fee_sat': 200, 'grant_sat': 1000, 'board_sat': 800, 'board_fee_reserve_sat': 200,
            'minimum_pool_sat': 100, 'minimum_channel_msat': 100000, 'fee_assets': ['a'*64+':0']}
        self.config = SimpleNamespace(board_amount_sat=800, action_fee_reserve_sat=200)

    def tearDown(self):
        self.fixture.tearDown()

    def sequence(self):
        return self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]

    def inventories(self):
        sequences = {}
        for member in self.members:
            rows = [] if member['role'] == 'customer' else [{'outpoint': 'a'*64+':0',
                'amount_sat': 1000, 'script': 'wallet-script', 'descriptor_index': 0, 'child_index': 0}]
            self.store.event('treasury_inventory', {'member_id': member['id'], 'identity': member['identity'],
                'financial_pins': self.fixture.pins, 'tip_hash': 'tip', 'height': 100, 'complete': True, 'utxos': rows})
            sequences[member['id']] = self.sequence()
        return sequences

    def test_verified_bootstrap_then_empty_customer_boundary_and_envelope(self):
        self.assertTrue(declare_boundary(self.store, self.boundary, self.chain))
        sources = self.inventories()
        assets = capture_assets(self.store, sources, self.chain)
        self.assertEqual(1000000, assets['total_msat'])
        self.assertTrue(declare_envelope(self.store, self.limits, self.config, sources, self.chain))
        self.assertEqual(1, len(assets['assets']))

    def refuse_both(self):
        with self.assertRaises(ValueError):
            declare_boundary(self.store, self.boundary, self.chain)
        # Preserve an independently source-verified boundary for exercising the
        # envelope guard alone; this test fixture is not live admission evidence.
        from simulator.model import canonical
        self.store.db.execute('INSERT INTO meta VALUES (?,?)', ('conserved_treasury_boundary', canonical(self.boundary)))
        self.store.event('treasury_boundary_declared', self.boundary)
        with self.assertRaises(ValueError):
            declare_envelope(self.store, self.limits, self.config, self.inventories(), self.chain)

    def test_missing_independent_zero_source_refuses_both(self):
        self.store.db.execute("DELETE FROM event WHERE kind='identity_bootstrap_zero_assets_verified'")
        self.refuse_both()

    def test_paid_or_other_dispatched_action_refuses_both(self):
        self.store.db.execute("UPDATE action SET operation='board' WHERE id=?", (self.action_id,))
        self.refuse_both()

    def test_nonzero_fee_or_unknown_create_refuses_shared_guard(self):
        for column, value in [('actual_fee_sat', 1), ('fee_reservation_sat', 1), ('state', 'outcome_unknown')]:
            with self.subTest(column=column):
                old = self.store.db.execute('SELECT '+column+' FROM action').fetchone()[0]
                self.store.db.execute('UPDATE action SET '+column+'=?', (value,))
                with self.assertRaises(ValueError):
                    bootstrap.require_only_verified_creates(self.store, self.fixture.pins)
                self.store.db.execute('UPDATE action SET '+column+'=?', (old,))

    def test_repeated_dispatch_refuses(self):
        self.store.event('action_dispatched', {'action_id': self.action_id, 'actor': 'actor-01'})
        with self.assertRaises(ValueError):
            bootstrap.require_only_verified_creates(self.store, self.fixture.pins)

    def test_changed_original_response_hash_refuses(self):
        self.store.db.execute("UPDATE event SET hash=? WHERE kind='driver_response'", ('0'*64,))
        with self.assertRaisesRegex(ValueError, 'event frame changed'):
            bootstrap.require_only_verified_creates(self.store, self.fixture.pins)

    def test_nonempty_create_args_or_wrong_pins_refuse(self):
        self.store.db.execute("UPDATE action SET args='{" + '"unexpected":1' + "}'")
        with self.assertRaises(ValueError):
            bootstrap.require_only_verified_creates(self.store, self.fixture.pins)
        self.store.db.execute("UPDATE action SET args='{}'")
        with self.assertRaises(ValueError):
            bootstrap.require_only_verified_creates(self.store, {**self.fixture.pins, 'schema_sha256': '0'*64})

    def test_unpaused_transition_refuses_shared_guard(self):
        self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        with self.assertRaisesRegex(ValueError, 'pause'):
            bootstrap.require_only_verified_creates(self.store, self.fixture.pins)

    def test_prior_funding_remains_forbidden(self):
        self.store.event('fixture_funding_intent', {'batch': 'forbidden-before-limits'})
        self.refuse_both()


if __name__ == '__main__':
    unittest.main()

"""Synthetic source-admission controls; no native or signet qualification."""
import copy
import json
import time
import unittest
from pathlib import Path

from simulator import preserved_treasury_upgrade as upgrade
from simulator.final_campaign import _source_event
from simulator.model import SIGNET_GENESIS, canonical
from simulator.operating_limits import envelope, fee_totals
from simulator.treasury import boundary
from tests import test_operating_limits as fixtures


class PreservedTreasuryUpgradeTests(unittest.TestCase):
    def setUp(self):
        self.case = fixtures.OperatingLimitsTests(); self.case.setUp()
        self.store = self.case.store; self.chain = self.case.chain
        from simulator.engine import Lease
        self.case.config.wallet_root = Path(self.case.tmp.name) / 'wallets'
        self.case.config.expected_image = 'sha256:' + 'b' * 64
        self.store.bind_wallet_root(self.case.config.wallet_root)
        self.state_lease = Lease(self.store.root).__enter__()
        self.wallet_lease = Lease(self.case.config.wallet_root).__enter__()
        self.pins = {**self.case.declaration['pins'], 'product_commit': '6' * 40,
                     'sdk_commit': '7' * 40, 'driver_sha256': '8' * 64,
                     'configuration_sha256': '9' * 64, 'schema_sha256': 'a' * 64}
        self.case.config.expected_sdk_commit = self.pins['sdk_commit']
        self.new_boundary = copy.deepcopy(self.case.declaration)
        self.new_boundary.update(id='preserved-new', pins=self.pins)
        self.new_boundary['members'].append({'id': 'added', 'kind': 'wallet', 'role': 'customer',
                                             'identity': 'separate-preexisting-wallet',
                                             'descriptors': ['wpkh(other-public)#checksum']})
        for member in self.new_boundary['members']:
            member.pop('verification_sequence', None)
            self.store.event('treasury_member_verified', {'member': dict(member), 'genesis': SIGNET_GENESIS,
                                                          'financial_pins': self.pins})
            member['verification_sequence'] = self.seq()
        from decimal import Decimal
        for txid, sat in [('c' * 64, 200), ('d' * 64, 100)]:
            self.chain.coins[(txid, 0)] = {'confirmations': 1, 'value': Decimal(sat) / 100000000,
                                         'scriptPubKey': {'hex': 'wallet-script'}}
        self.inventories = {}
        for member in self.new_boundary['members']:
            if member['kind'] == 'wallet':
                coins = [('a' * 64, 1000), ('d' * 64, 100)] if member['id'] == 'rounds' else [('c' * 64, 200)]
                rows = [{'outpoint': txid + ':0', 'amount_sat': sat, 'script': 'wallet-script',
                         'descriptor_index': 0, 'child_index': 0} for txid, sat in coins]
                fields = {'utxos': rows}
            else:
                fields = {'utxos': [], 'channels': [{'funding_outpoint': 'b' * 64 + ':0',
                    'channel_id': 'channel', 'peer_identity': 'outside-peer', 'owned_balance_msat': 1500999}]}
            self.store.event('treasury_inventory', {'member_id': member['id'], 'identity': member['identity'],
                'financial_pins': self.pins, 'height': 100, 'tip_hash': 'tip', 'complete': True, **fields})
            self.inventories[member['id']] = self.seq()
        self.limits = copy.deepcopy(self.case.limits)
        self.limits.update(id='preserved-envelope', boundary_id=self.new_boundary['id'], pins=self.pins)
        self.store.event('financial_cost_verified', {'monetary_id': 'bitcoin-miner:' + 'e' * 64,
            'amount_msat': 1000, 'financial_pins': self.case.declaration['pins'], 'budget': 'ordinary'})
        self.cost_seq = self.seq()
        self.chain.transaction = lambda txid: {'txid': txid, 'confirmations': 1, 'fee_sat': 1}
        self.store.event('treasury_flow_verified', {'id': 'original-outside-injection', 'kind': 'injection',
            'source': 'outside-payer', 'destination': 'rounds', 'amount_msat': 100000})
        self.flow_seq = self.seq()
        self.store.event('owned_runtime_configuration_verified', {
            'product_commit': self.pins['product_commit'], 'schema_sha256': self.pins['schema_sha256'],
            'loaded_configuration_identity_verified': True,
            'execution_release': {**self.pins, 'image_sha256': self.case.config.expected_image},
            'observed_at': time.time(), 'daemons': {name: {'pid': i, 'started_at': 'synthetic-start',
                'image_sha256': self.case.config.expected_image, 'binary_sha256': 'c' * 64,
                'config_sha256': 'd' * 64} for i, name in enumerate(('captaind', 'watchmand'), 1)},
            'startup_source_sha256': '1' * 64, 'current_source_sha256': '2' * 64})
        self.runtime_seq = self.seq()
        self.proof = {'opening_assets': {'total_msat': 2701999},
                      'inventory_sequences': self.inventories, 'flow_sequences': [self.flow_seq],
                      'liability_sequences': [], 'runtime_source_sequence': self.runtime_seq,
                      'cost_payers': {self.cost_seq: 'rounds'},
                      'source_sequences': [self.cost_seq, self.flow_seq]}
        self.declaration = {'id': 'ordinary-upgrade',
            'previous_boundary_sha256': upgrade._digest(self.case.declaration),
            'previous_envelope_sha256': upgrade._digest(self.case.limits),
            'boundary': self.new_boundary, 'envelope': self.limits}

    def seq(self): return self.store.db.execute('SELECT MAX(sequence) FROM event').fetchone()[0]
    def tearDown(self):
        self.wallet_lease.__exit__(); self.state_lease.__exit__(); self.case.tearDown()
    def verified(self, *args): return copy.deepcopy(self.proof)
    def admit(self, **kwargs):
        return upgrade.record_upgrade(self.store, self.case.config, self.chain, self.declaration,
                                      source_verifier=kwargs.get('verifier', self.verified))

    def test_append_overlay_preserves_exact_original_metadata_and_events(self):
        before = list(self.store.db.execute('SELECT * FROM event ORDER BY sequence'))
        meta = list(self.store.db.execute('SELECT * FROM meta ORDER BY key'))
        sequence = self.admit()
        self.assertEqual(before, list(self.store.db.execute('SELECT * FROM event WHERE sequence<? ORDER BY sequence', (sequence,))))
        self.assertEqual(meta, list(self.store.db.execute('SELECT * FROM meta ORDER BY key')))
        self.assertEqual(boundary(self.store), self.new_boundary)
        self.assertEqual(envelope(self.store, self.case.config), self.limits)
        self.assertEqual(fee_totals(self.store, self.pins), {'ordinary': 1000, 'urgent': 0})
        proof = _source_event(self.store, sequence)[1]
        self.assertFalse(proof['financial_readiness']); self.assertFalse(proof['fee_budget_reset'])
        self.store.verify_event_chain()

    def test_same_upgrade_idempotent_without_new_event(self):
        sequence = self.admit()
        self.assertEqual(self.admit(), sequence)
        self.assertEqual(self.seq(), sequence)

    def test_missing_admitted_source_verifier_refuses(self):
        with self.assertRaisesRegex(ValueError, 'verifier required'): self.admit(verifier=None)

    def test_complete_flag_cannot_replace_original_sources(self):
        with self.assertRaisesRegex(ValueError, 'source references'):
            self.admit(verifier=lambda *args: {'complete': True})

    def test_existing_member_cannot_be_dropped(self):
        self.new_boundary['members'].pop(0)
        with self.assertRaisesRegex(ValueError, 'member ownership'): self.admit()

    def test_existing_member_cannot_be_redirected(self):
        self.new_boundary['members'][0]['identity'] = 'foreign-wallet'
        with self.assertRaisesRegex(ValueError, 'member ownership'): self.admit()

    def test_new_member_needs_exact_owning_proof(self):
        self.new_boundary['members'][-1]['verification_sequence'] = self.cost_seq
        with self.assertRaisesRegex(ValueError, 'owning source'): self.admit()

    def test_runtime_with_wrong_final_sdk_refuses(self):
        _, proof = _source_event(self.store, self.runtime_seq)
        proof['execution_release']['sdk_commit'] = '0' * 40
        self.store.event('owned_runtime_configuration_verified', proof)
        self.proof['runtime_source_sequence'] = self.seq()
        with self.assertRaisesRegex(ValueError, 'runtime/SDK'): self.admit()

    def test_unexplained_closing_assets_fail_even_with_admitted_verifier(self):
        self.proof['opening_assets']['total_msat'] += 1
        with self.assertRaisesRegex(Exception, 'conserve'): self.admit()

    def test_duplicate_original_injection_refuses(self):
        self.proof['flow_sequences'].append(self.flow_seq)
        with self.assertRaisesRegex(Exception, 'counted twice'): self.admit()

    def test_false_current_inventory_refuses_independent_core(self):
        self.chain.coins[('c' * 64, 0)]['value'] *= 2
        with self.assertRaisesRegex(Exception, 'differs'): self.admit()

    def test_existing_budget_cannot_be_refilled(self):
        self.limits['fee_budgets_msat']['ordinary'] += 1000
        with self.assertRaisesRegex(ValueError, 'original budgets'): self.admit()

    def test_finite_fee_ceiling_cannot_become_unbounded(self):
        self.limits['operation_fee_paths'] = {'snapshot': ['pool', 'sweep', 'payout', 'claim', 'progression']}
        self.limits['fee_ceilings_sat_kvb']['round'] = None
        with self.assertRaisesRegex(ValueError, 'remove or raise'): self.admit()

    def test_original_per_action_guard_cannot_be_raised(self):
        self.limits['per_action_fee_sat'] += 1
        with self.assertRaisesRegex(ValueError, 'per-action'): self.admit()

    def test_real_wallet_root_lease_required(self):
        self.wallet_lease.__exit__()
        with self.assertRaisesRegex(ValueError, 'wallet-root Lease'): self.admit()

    def test_source_append_changes_context_and_cannot_admit_upgrade(self):
        def mutating(*args):
            self.store.event('synthetic_unrelated_source', {'value': 'unexpected source write'})
            return self.verified()
        with self.assertRaisesRegex(ValueError, 'append events'): self.admit(verifier=mutating)
        self.assertIsNone(upgrade.recorded(self.store))

    def test_old_costs_cannot_be_reintroduced_at_new_pins(self):
        self.admit()
        self.store.event('financial_cost_verified', {'monetary_id': 'miner:' + 'e' * 64,
                         'amount_msat': 1000, 'financial_pins': self.pins, 'budget': 'ordinary'})
        with self.assertRaisesRegex(ValueError, 'counted twice'): fee_totals(self.store, self.pins)

    def test_old_pin_cost_after_upgrade_refuses(self):
        self.admit()
        self.store.event('financial_cost_verified', {'monetary_id': 'miner:' + 'f' * 64,
            'amount_msat': 1000, 'financial_pins': self.case.declaration['pins'], 'budget': 'ordinary'})
        with self.assertRaisesRegex(ValueError, 'previous or foreign'): fee_totals(self.store, self.pins)

    def test_actual_configured_sdk_must_match_new_pins(self):
        self.case.config.expected_sdk_commit = '0' * 40
        with self.assertRaisesRegex(ValueError, 'configured SDK'):
            self.admit()

    def test_same_fee_on_another_transaction_is_not_original_money(self):
        self.chain.transaction = lambda txid: {'txid': 'f' * 64, 'confirmations': 1, 'fee_sat': 1}
        with self.assertRaisesRegex(ValueError, 'confirmed chain'):
            self.admit()

"""Synthetic raw Bitcoin/Core controls, never native or live qualification."""
import copy
import hashlib
import unittest
from decimal import Decimal
from unittest.mock import patch

from simulator.bundle_audit import decode_transaction
from simulator.model import SIGNET_GENESIS, InvariantError, canonical
from simulator.ownership import EvidenceGap
from simulator.wallet_projection import reduce_wallet_projection
from tests.test_final_campaign import PINS

TIP = '11'*32
DESCRIPTOR = 'tr(public-fixture/0/*)#fixture'
SCRIPTS = ['5120'+str(i+1).zfill(2)*32 for i in range(4)]
ADDRESSES = ['derived-public-'+str(i) for i in range(4)]


def transaction(inputs, outputs, *, witness=True, nonce=0, script_sig=b''):
    """Hand-encode distinct synthetic bodies; fee/value expectations are explicit."""
    body = bytearray((2).to_bytes(4, 'little'))
    if witness: body.extend(b'\x00\x01')
    body.extend(bytes([len(inputs)]))
    for point in inputs:
        txid, index = point.split(':')
        body.extend(bytes.fromhex(txid)[::-1]+int(index).to_bytes(4, 'little')
                    +bytes([len(script_sig)])+script_sig+b'\xfd\xff\xff\xff')
    body.extend(bytes([len(outputs)]))
    for amount, script in outputs:
        raw = bytes.fromhex(script)
        body.extend(amount.to_bytes(8, 'little')+bytes([len(raw)])+raw)
    if witness:
        for _ in inputs: body.extend(b'\x01\x40'+bytes([170+nonce])*64)
    body.extend(nonce.to_bytes(4, 'little'))
    return body.hex()


class Core:
    def __init__(self):
        self.tip, self.height, self.ibd = TIP, 1000, False
        self.transactions, self.unspent, self.mempool_unspent, self.calls = {}, {}, {}, []
        self.after_start = None

    def add(self, raw, confirmations=0):
        decoded = decode_transaction(raw, public_body=True)
        txid = decoded['txid']
        self.transactions[txid] = {'txid': txid, 'hex': raw, 'weight': decoded['weight'],
            'confirmations': confirmations, 'vout': [
                {'n': i, 'value': Decimal(o['amount_sat'])/100000000,
                 'scriptPubKey': {'hex': o['script'], **({'address': ADDRESSES[SCRIPTS.index(o['script'])]} if o['script'] in SCRIPTS else {})}}
                for i, o in enumerate(decoded['outputs'])]}
        return txid

    def coin(self, txid, index, amount, child, confirmations=1, *, coinbase=False, mempool=True):
        value = {'value': Decimal(amount)/100000000, 'scriptPubKey': {'hex': SCRIPTS[child]},
                 'confirmations': confirmations, 'coinbase': coinbase, 'bestblock': self.tip}
        self.unspent[(txid, index)] = value
        if mempool: self.mempool_unspent[(txid, index)] = value

    def call(self, method, *args):
        self.calls.append((method, args))
        if self.after_start and method == 'getblockchaininfo' and sum(m == method for m, _ in self.calls) == 2:
            self.after_start()
        if method == 'getblockhash': return SIGNET_GENESIS if args[0] == 0 else TIP
        if method == 'getblockchaininfo':
            return {'chain': 'signet', 'blocks': self.height, 'bestblockhash': self.tip, 'initialblockdownload': self.ibd}
        if method == 'getdescriptorinfo':
            return {'descriptor': args[0], 'hasprivatekeys': False, 'isrange': True}
        if method == 'deriveaddresses':
            first, last = args[1]; return ADDRESSES[first:last+1]
        if method == 'validateaddress':
            return {'isvalid': True, 'scriptPubKey': SCRIPTS[ADDRESSES.index(args[0])]}
        if method == 'getrawtransaction':
            if args[0] not in self.transactions: raise ValueError('synthetic RPC unavailable')
            return copy.deepcopy(self.transactions[args[0]])
        if method == 'gettxout':
            return copy.deepcopy((self.mempool_unspent if args[2] else self.unspent).get(args[:2]))
        raise AssertionError('unexpected/non-read-only RPC: '+method)


def public_row(core, txid):
    tx = core.transactions[txid]
    return {'txid': txid, 'transaction_body': decode_transaction(tx['hex'], public_body=True)['stripped_hex'],
            'signed_weight_wu': tx['weight'], 'encoding': 'bitcoin-stripped-body-v1'}


def native_coin(point, amount, child, *, confirmed=True, reserved=False, coinbase=False, confirmations=1, trusted=True):
    eligible = trusted and (not coinbase or confirmations >= 100) and not reserved
    return {'outpoint': point, 'value_sat': amount, 'script_pubkey': SCRIPTS[child], 'keychain': 'external',
            'derivation_index': child, 'confirmed_height_upper_bound': 1001-confirmations if confirmed else None,
            'confirmation_block_hash': TIP if confirmed else None, 'confirming_descendant_txid': None,
            'confirmation_time': 1 if confirmed else None, 'unconfirmed_first_seen': None if confirmed else 1,
            'unconfirmed_last_seen': None if confirmed else 2, 'coinbase': coinbase,
            'confirmations': confirmations if confirmed else 0, 'mature': not coinbase or confirmations >= 100,
            'trusted': trusted, 'reserved': reserved, 'transaction_eligible': eligible,
            'confirmed_fee_eligible': eligible and confirmed}


class WalletProjectionTests(unittest.TestCase):
    def setUp(self):
        self.core = Core()
        self.parent = self.core.add(transaction(['aa'*32+':1'], [(10000, SCRIPTS[0]), (2000, '51')]), 3)
        self.pending = self.core.add(transaction([self.parent+':0'], [(7000, SCRIPTS[1]), (2000, '51')], nonce=1))
        self.cash = self.core.add(transaction(['bb'*32+':2'], [(5000, SCRIPTS[2])], nonce=2), 1)
        self.core.coin(self.parent, 0, 10000, 0, 3, mempool=False)
        self.core.coin(self.cash, 0, 5000, 2)
        self.native = {'wallet': 'rounds', 'network': 'signet', 'public_descriptor': DESCRIPTOR,
            'tip_height': 1000, 'tip_hash': TIP, 'min_trusted_confirmations': 1, 'complete': True,
            'reserved_outpoints': [], 'last_revealed_index': 2,
            'utxos': [native_coin(self.pending+':0', 7000, 1, confirmed=False), native_coin(self.cash+':0', 5000, 2)],
            'pending_transaction_scope': 'canonical_wallet_graph_only',
            'pending_transactions': [public_row(self.core, self.pending)],
            'pending_parents': [public_row(self.core, self.parent)], 'unavailable_parent_txids': []}
        self.member = {'id': 'rounds', 'kind': 'wallet', 'role': 'operator', 'identity': 'declared-A-wallet', 'descriptors': [DESCRIPTOR]}
        self.facts = {'schema_version': 1, 'kind': 'financial_facts', 'architecture_profile': 'two_step_per_key',
            'network': 'signet', 'genesis': SIGNET_GENESIS, 'height': 1000, 'tip_hash': TIP,
            'observed_at': 95, 'completed_at': 98, 'financial_pins': copy.deepcopy(PINS),
            'source_identity': {'product_commit': PINS['product_commit'], 'schema_sha256': PINS['schema_sha256'],
                'bridge_sha256': 'ab'*32, 'daemon_binary_hashes': {'captaind': 'bc'*32, 'watchmand': 'cd'*32}},
            'sources': {'rounds_wallet': {'owner': 'rounds', 'observed_at': 95, 'completed_at': 97,
                'source': {'rounds': self.native, 'watchman': None, 'complete': False, 'missing_sources': ['watchman']}}},
            'source_gaps': ['native_source_not_yet_qualified']}

    def reduce(self):
        return reduce_wallet_projection(self.member, self.facts, self.core, PINS, owner='rounds', now=100)

    def test_pending_signed_change_never_duplicates_confirmed_inputs(self):
        result = self.reduce()
        self.assertEqual(result['known_confirmed_tip_sat'], 15000)  # 10,000 backing + 5,000 separate cash, never 7,000 change.
        self.assertEqual({row['outpoint'] for row in result['confirmed_tip_utxos']}, {self.parent+':0', self.cash+':0'})
        self.assertEqual(result['native_fee_candidates'], [self.cash+':0'])
        self.assertTrue(result['projection_complete'])
        self.assertFalse(any(result['coverage'][key] for key in ('exhaustive_wallet_discovery', 'economic_unreserved_funding', 'operating_readiness')))
        self.assertNotIn('available_fee_funding_msat', result)
        self.assertEqual(result['native_frame_sha256'], hashlib.sha256(canonical(self.facts['sources']['rounds_wallet']['source']).encode()).hexdigest())

    def test_aggregate_row_budget_covers_the_whole_native_frame(self):
        # Two UTXOs, one pending body and one parent are four source rows.
        # Each collection separately fits three; the complete frame does not.
        with patch('simulator.wallet_projection.MAX_ROWS', 3):
            with self.assertRaisesRegex(EvidenceGap, 'aggregate'):
                self.reduce()
        self.assertEqual(self.core.calls, [])
        with patch('simulator.wallet_projection.MAX_ROWS', 4):
            result = self.reduce()
        self.assertEqual(result['known_confirmed_tip_sat'], 15000)
        self.assertTrue(result['projection_complete'])

    def test_native_body_with_nonempty_script_sig_is_refused_before_core(self):
        raw = transaction([self.parent+':0'], [(7000, SCRIPTS[1]), (2000, '51')],
                          nonce=1, script_sig=b'\x20'+bytes([0x5a])*32)
        txid = self.core.add(raw)
        self.native['pending_transactions'] = [public_row(self.core, txid)]
        self.native['utxos'][0] = native_coin(txid+':0', 7000, 1, confirmed=False)
        with self.assertRaisesRegex(EvidenceGap, 'scriptSig'):
            self.reduce()
        self.assertEqual(self.core.calls, [])

    def test_actual_confirmation_transition_replaces_backing_with_change_once(self):
        before = self.reduce()
        self.core.transactions[self.pending]['confirmations'] = 1
        self.core.unspent.pop((self.parent, 0))
        self.core.coin(self.pending, 0, 7000, 1)
        self.native['pending_transactions'] = []; self.native['pending_parents'] = []
        self.native['utxos'][0] = native_coin(self.pending+':0', 7000, 1)
        after = self.reduce()
        self.assertEqual((before['known_confirmed_tip_sat'], after['known_confirmed_tip_sat']), (15000, 12000))
        # The 3,000 difference is independently specified: 2,000 foreign output + 1,000 fee.
        self.assertEqual(set(after['native_fee_candidates']), {self.pending+':0', self.cash+':0'})

    def test_impossible_core_parent_and_pending_change_coverage_is_rejected(self):
        # A contradictory controller must not create 22,000 sats from 15,000.
        self.core.coin(self.pending, 0, 7000, 1)
        with self.assertRaisesRegex(InvariantError, 'pending change and its confirmed input'):
            self.reduce()

    def test_real_reservation_and_mempool_spend_remove_fee_cash_but_not_tip_asset(self):
        self.native['reserved_outpoints'] = [self.cash+':0']
        self.native['utxos'][1] = native_coin(self.cash+':0', 5000, 2, reserved=True)
        result = self.reduce(); self.assertEqual(result['known_confirmed_tip_sat'], 15000)
        self.assertEqual(result['native_fee_candidates'], [])
        self.native['reserved_outpoints'] = []
        self.native['utxos'][1] = native_coin(self.cash+':0', 5000, 2)
        self.core.mempool_unspent.pop((self.cash, 0))
        result = self.reduce()
        self.assertEqual(result['native_fee_candidates'], [])
        self.assertIn('mempool_spend_not_in_supplied_pending_graph:'+self.cash+':0', result['projection_gaps'])

    def test_missing_parent_is_an_explicit_gap_even_with_forged_complete_flags(self):
        self.native['pending_parents'] = []; self.native['unavailable_parent_txids'] = [self.parent]
        self.core.transactions.pop(self.parent)
        self.native['complete'] = True; self.facts['complete'] = True; self.facts['qualified'] = True
        result = self.reduce()
        self.assertFalse(result['projection_complete'])
        self.assertIn('pending_parent_unavailable:'+self.parent, result['projection_gaps'])
        self.assertEqual(result['known_confirmed_tip_sat'], 5000)  # Explicit checked subset, never a full wallet balance.
        self.assertIn('native_parent_unresolved:'+self.parent, result['projection_gaps'])
        self.assertFalse(result['coverage']['native_source_qualified'])

    def test_missing_native_parent_can_be_resolved_only_from_actual_core_bytes(self):
        self.native['pending_parents'] = []; self.native['unavailable_parent_txids'] = [self.parent]
        result = self.reduce()
        self.assertTrue(result['projection_complete']); self.assertEqual(result['known_confirmed_tip_sat'], 15000)

    def test_signed_but_unbroadcast_native_body_preserves_confirmed_input(self):
        self.core.transactions.pop(self.pending)
        self.assertEqual(self.reduce()['known_confirmed_tip_sat'], 15000)
        self.assertEqual(self.reduce()['native_fee_candidates'], [self.cash+':0'])

    def test_missing_pending_body_or_consumed_confirmed_input_remains_a_gap(self):
        self.native['pending_transactions'] = []; self.native['pending_parents'] = []
        result = self.reduce()
        self.assertIn('native_unconfirmed_utxo_without_pending_body:'+self.pending+':0', result['projection_gaps'])
        self.assertEqual(result['known_confirmed_tip_sat'], 5000)
        self.native['pending_transactions'] = [public_row(self.core, self.pending)]
        self.native['pending_parents'] = [public_row(self.core, self.parent)]
        self.core.unspent.pop((self.parent, 0))
        result = self.reduce()
        self.assertIn('confirmed_pending_prevout_consumed:'+self.parent+':0', result['projection_gaps'])
        self.assertFalse(result['projection_complete'])

    def test_immature_coinbase_is_a_physical_asset_and_never_fee_cash(self):
        coinbase = self.core.add(transaction(['0'*64+':4294967295'], [(3000, SCRIPTS[3])], witness=False), 99)
        self.core.coin(coinbase, 0, 3000, 3, 99, coinbase=True)
        self.native['utxos'].append(native_coin(coinbase+':0', 3000, 3, coinbase=True, confirmations=99))
        result = self.reduce()
        self.assertEqual(result['known_confirmed_tip_sat'], 18000)
        self.assertNotIn(coinbase+':0', result['native_fee_candidates'])
        self.core.transactions[coinbase]['confirmations'] = 100
        self.core.coin(coinbase, 0, 3000, 3, 100, coinbase=True)
        self.native['utxos'][-1] = native_coin(coinbase+':0', 3000, 3, coinbase=True, confirmations=100)
        self.assertIn(coinbase+':0', self.reduce()['native_fee_candidates'])

    def test_conflicting_pending_generations_count_one_physical_input_and_keep_gap(self):
        other = self.core.add(transaction([self.parent+':0'], [(6000, SCRIPTS[3]), (2500, '51')], nonce=3))
        self.native['pending_transactions'].append(public_row(self.core, other))
        result = self.reduce()
        self.assertEqual(result['known_confirmed_tip_sat'], 15000)
        self.assertIn('conflicting_pending_spends:'+self.parent+':0', result['projection_gaps'])
        self.assertEqual(result['pending_spenders'][self.parent+':0'], sorted([self.pending, other]))

    def test_duplicate_rows_or_reservations_are_not_silently_deduplicated(self):
        self.native['utxos'].append(copy.deepcopy(self.native['utxos'][1]))
        with self.assertRaisesRegex(InvariantError, 'duplicate native UTXO'): self.reduce()
        self.native['utxos'].pop(); self.native['reserved_outpoints'] = [self.cash+':0']*2
        with self.assertRaisesRegex(InvariantError, 'duplicate native reservation'): self.reduce()

    def test_bad_raw_txid_body_or_signed_weight_is_rejected(self):
        for field, value in [('txid', 'ee'*32), ('transaction_body', '00'), ('signed_weight_wu', 1)]:
            original = self.native['pending_transactions'][0][field]
            self.native['pending_transactions'][0][field] = value
            with self.assertRaises(ValueError): self.reduce()
            self.native['pending_transactions'][0][field] = original
        self.native['pending_transactions'][0]['signed_weight_wu'] += 1
        with self.assertRaisesRegex(InvariantError, 'pending body/weight'): self.reduce()

    def test_actual_raw_output_amount_and_descriptor_must_agree(self):
        self.native['utxos'][1]['value_sat'] = 4999
        with self.assertRaisesRegex(InvariantError, 'raw prevout'): self.reduce()
        self.native['utxos'][1]['value_sat'] = 5000
        self.member['descriptors'] = ['foreign-descriptor']
        with self.assertRaisesRegex(ValueError, 'descriptor differs'): self.reduce()

    def test_core_utxo_amount_or_coinbase_lie_is_rejected(self):
        self.core.unspent[(self.cash, 0)]['value'] = Decimal('0.00004999')
        with self.assertRaisesRegex(InvariantError, 'exact raw prevout'): self.reduce()
        self.core.unspent[(self.cash, 0)]['value'] = Decimal('0.00005000')
        self.core.unspent[(self.cash, 0)]['coinbase'] = True
        with self.assertRaisesRegex(InvariantError, 'coinbase flag'): self.reduce()

    def test_conflicted_core_transaction_is_not_zero_confirmed_assets(self):
        self.core.transactions[self.parent]['confirmations'] = -1
        with self.assertRaisesRegex(EvidenceGap, 'conflicted or unknown'): self.reduce()

    def test_inconsistent_native_lock_and_eligibility_are_rejected_even_unbroadcast(self):
        self.core.transactions.pop(self.pending)
        self.native['utxos'][0]['reserved'] = True
        with self.assertRaisesRegex(InvariantError, 'reservation set'): self.reduce()
        self.native['utxos'][0]['reserved'] = False
        self.native['utxos'][0]['confirmed_fee_eligible'] = True
        with self.assertRaisesRegex(InvariantError, 'internally inconsistent'): self.reduce()

    def test_stale_source_changed_tip_ibd_network_and_pin_mismatch_refuse(self):
        self.facts['observed_at'] = 0
        with self.assertRaisesRegex(EvidenceGap, 'stale'): self.reduce()
        self.facts['observed_at'] = 95; self.core.ibd = True
        with self.assertRaisesRegex(EvidenceGap, 'not synchronized'): self.reduce()
        self.core.ibd = False; self.core.calls = []
        self.core.after_start = lambda: setattr(self.core, 'tip', '22'*32)
        with self.assertRaisesRegex(EvidenceGap, 'tip changed'): self.reduce()
        self.core.after_start = None; self.core.tip = TIP
        self.facts['financial_pins']['driver_sha256'] = 'ff'*32
        with self.assertRaisesRegex(ValueError, 'pin context'): self.reduce()
        self.facts['financial_pins'] = copy.deepcopy(PINS); self.native['network'] = 'mainnet'
        with self.assertRaisesRegex(ValueError, 'network differs'): self.reduce()

    def test_budget_exhaustion_cannot_promote_an_empty_or_partial_balance(self):
        with patch('simulator.wallet_projection.MAX_RPC_CALLS', 4):
            with self.assertRaisesRegex(EvidenceGap, 'budget exhausted'): self.reduce()
        with patch('simulator.wallet_projection.MAX_CORE_BYTES', 64):
            with self.assertRaisesRegex(EvidenceGap, 'byte budget exhausted'): self.reduce()
        self.native['last_revealed_index'] = 2000
        with self.assertRaisesRegex(EvidenceGap, 'descriptor range'): self.reduce()

    def test_old_sourcenative_without_pending_body_contract_stays_unqualified(self):
        self.native.pop('pending_transaction_scope')
        with self.assertRaisesRegex(EvidenceGap, 'native wallet'): self.reduce()

    def test_missing_frame_or_false_capture_times_are_explicit_gaps(self):
        self.facts['sources'].pop('rounds_wallet')
        with self.assertRaisesRegex(EvidenceGap, 'missing owning source'): self.reduce()
        self.facts['sources']['rounds_wallet'] = {'owner': 'rounds', 'observed_at': 94, 'completed_at': 97,
            'source': {'rounds': self.native, 'watchman': None}}
        with self.assertRaisesRegex(EvidenceGap, 'outside the original envelope'): self.reduce()

    def test_secrets_are_rejected_before_any_core_observation(self):
        self.native['mnemonic'] = 'sensitive synthetic field'
        with self.assertRaisesRegex(ValueError, 'secret field'): self.reduce()
        self.assertEqual(self.core.calls, [])

    def test_preprocessing_time_cannot_keep_an_expired_source_fresh(self):
        from simulator.model import public_payload
        clock = [0]
        self.facts['observed_at'] = 15
        self.facts['sources']['rounds_wallet']['observed_at'] = 15

        def validate(value):
            if value is self.facts: clock[0] = 10
            return public_payload(value)

        with patch('simulator.wallet_projection.time.monotonic', side_effect=lambda: clock[0]), \
                patch('simulator.wallet_projection.public_payload', side_effect=validate):
            with self.assertRaisesRegex(EvidenceGap, 'stale'): self.reduce()

    def test_completion_time_includes_preprocessing(self):
        from simulator.model import public_payload
        clock = [0]

        def validate(value):
            if value is self.facts: clock[0] = 5
            return public_payload(value)

        with patch('simulator.wallet_projection.time.monotonic', side_effect=lambda: clock[0]), \
                patch('simulator.wallet_projection.public_payload', side_effect=validate):
            result = self.reduce()
        self.assertEqual(result['completed_at'], 105)

    def test_final_source_hashing_is_inside_the_whole_call_budget(self):
        from simulator.wallet_projection import _hash
        clock = [0]

        def delayed_hash(value):
            if value is self.facts: clock[0] = 26
            return _hash(value)

        with patch('simulator.wallet_projection.time.monotonic', side_effect=lambda: clock[0]), \
                patch('simulator.wallet_projection._hash', side_effect=delayed_hash):
            with self.assertRaisesRegex(EvidenceGap, 'time budget'): self.reduce()


if __name__ == '__main__': unittest.main()

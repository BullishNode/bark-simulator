"""Consumer-boundary SOFTWARE STUB controls only: no signatures/native/live credit.

Opaque public fixture bytes are intentionally not Vtxo encodings. The qualified
Rust helper owns cryptographic validation; these tests exercise literal transport,
identity/hash/relation admission and refusal propagation at the Python boundary.
"""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from simulator import normal_lineage as m

ROOT = Path(__file__).resolve().parents[1]
KEY = '02'+'11'*32
GENESIS = 'aa'*32
COIN = '11'*32+':0'
ANCHOR = '22'*32+':1'
COMPLETED = b'public software stub completed bytes; not a Vtxo'
NATIVE = b'public software stub partial bytes; not a Vtxo'
ANCHOR_RAW = b'public software stub anchor; not a chain transaction'.hex()


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def fixture(equal=False):
    binding = {'mailbox_pk': KEY, 'spk': '0014'+'44'*20, 'seq': 7}
    original = {'id': COIN, 'amount_sat': 10000, 'pubkey': KEY, 'actor': 'actor-01',
        'signed_vtxo': COMPLETED.hex(), 'signed_hash': m.sha(COMPLETED),
        'proof': wire({'chain_anchor': ANCHOR, 'expiry_height': 200, 'binding': binding}).decode()}
    native = {'vtxo_id': COIN, 'policy_type': 'pubkey', 'amount': 10000,
        'server_pubkey': KEY, 'anchor_point': ANCHOR, 'expiry': 200,
        'signed_vtxo_hex': (COMPLETED if equal else NATIVE).hex()}
    request = {'signed_vtxo': original['signed_vtxo'],
        'binding': {**binding, 'record_attestation': '55'*64}, 'key_link_attestation': '66'*64}
    response = {'id': COIN, 'amount_sat': 10000, 'user_pubkey': KEY, 'chain_anchor': ANCHOR,
        'expiry_height': 200, 'genesis': GENESIS, 'server_pubkey': KEY,
        'signed_path_valid': True, 'authorization_path_valid': True, 'conditional_steps': 0,
        'binding': {**binding, 'record_signature_valid': True, 'key_link_signature_valid': True},
        'path': [{'txid': COIN.split(':')[0], 'output_index': 0, 'inputs': [ANCHOR], 'output_amount_sat': 10000}]}
    policy_request = {'signed_vtxo': original['signed_vtxo'], 'native_vtxo': native['signed_vtxo_hex'],
        'anchor_raw': ANCHOR_RAW, 'server_pubkey': KEY}
    policy = {'schema_version': 1, 'sdk_commit': m.NATIVE_COMPLETION_SDK, 'id': COIN,
        'amount_sat': 10000, 'candidate_user_pubkey': KEY, 'chain_anchor': ANCHOR,
        'server_pubkey': KEY, 'expiry_height': 200, 'policy': 'pubkey', 'tree_padding': False,
        'signed_path_valid': True, 'chain_contract_verified': True, 'client_owner_verified': False,
        'native_owner_verified': False, 'payment_verified': False,
        'native_vtxo_sha256': m.sha(COMPLETED if equal else NATIVE),
        'completed_vtxo_sha256': m.sha(COMPLETED),
        'native_completion_relation': 'exact_full_equality' if equal else 'final_hark_leaf_completion',
        'unlock_hash': '77'*32}
    return original, native, request, response, policy_request, policy


def bind(f, **overrides):
    owned, native, request, proof, policy_request, policy = f
    arguments = {'genesis': GENESIS, 'server_pubkey': KEY,
        'policy_request_raw': wire(policy_request), 'policy_response_raw': wire(policy),
        'anchor_raw': ANCHOR_RAW, 'policy_sdk_commit': m.NATIVE_COMPLETION_SDK}
    arguments.update(overrides)
    return m.bind_coin(owned, native, wire(request), wire(proof), **arguments)


class CompletionBoundaryControls(unittest.TestCase):
    def test_imports_are_actual_current_checkout_modules(self):
        from simulator import two_step_normal, unknown_outcomes
        for module,name in [(m,'normal_lineage'),(two_step_normal,'two_step_normal'),(unknown_outcomes,'unknown_outcomes')]:
            self.assertEqual(Path(module.__file__).resolve(),ROOT/'simulator'/(name+'.py'))

    def test_software_partial_pair_binds_both_literals_without_money_verdict(self):
        result = bind(fixture())
        self.assertEqual(result['native_full_sha256'], m.sha(NATIVE))
        self.assertEqual(result['completed_full_sha256'], m.sha(COMPLETED))
        self.assertEqual(result['native_completion_relation'], 'final_hark_leaf_completion')
        self.assertNotIn('ready', result)
        self.assertNotIn('paid', result)
        self.assertNotIn('owner_verified', result)

    def test_software_exact_pair_requires_exact_relation(self):
        self.assertEqual(bind(fixture(True))['native_completion_relation'], 'exact_full_equality')

    def test_identical_completed_legacy_binding_remains_supported(self):
        owned, native, request, proof, _, _ = fixture(True)
        result = m.bind_coin(owned, native, wire(request), wire(proof), genesis=GENESIS, server_pubkey=KEY)
        self.assertEqual(result['native_full_sha256'], result['completed_full_sha256'])

    def test_differing_literals_without_executed_pair_hold(self):
        owned, native, request, proof, _, _ = fixture()
        with self.assertRaisesRegex(ValueError, 'different native Full'):
            m.bind_coin(owned, native, wire(request), wire(proof), genesis=GENESIS, server_pubkey=KEY)

    def test_old_native_body_cannot_replace_retained_completed_binding_input(self):
        f = fixture(); f[2]['signed_vtxo'] = f[1]['signed_vtxo_hex']
        with self.assertRaisesRegex(ValueError, 'retained completed Full'):
            bind(f)

    def test_owned_original_hash_change_holds(self):
        f = fixture(); f[0]['signed_hash'] = '00'*32
        with self.assertRaisesRegex(ValueError, 'owned signed bytes'):
            bind(f)

    def test_native_and_completed_hashes_are_independently_bound(self):
        for field in ('native_vtxo_sha256', 'completed_vtxo_sha256'):
            f = fixture(); f[5][field] = '00'*32
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'completion proof differs'):
                bind(f)

    def test_exact_four_field_mode_refuses_projection_forfeit_and_detached_flags(self):
        for mutation in ('missing-native', 'missing-anchor', 'projection', 'verdict', 'forfeit'):
            f = fixture()
            if mutation == 'missing-native': del f[4]['native_vtxo']
            elif mutation == 'missing-anchor': del f[4]['anchor_raw']
            elif mutation == 'projection': f[4]['public_projection'] = {}
            elif mutation == 'verdict': f[4]['native_completion_relation'] = 'final_hark_leaf_completion'
            else: f[4]['forfeit_raw'] = '00'
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'literal completed/native'):
                bind(f)

    def test_literal_sql_native_and_anchor_are_not_reencoded_or_substituted(self):
        for field in ('native_vtxo', 'signed_vtxo', 'anchor_raw', 'server_pubkey'):
            f = fixture(); f[4][field] = '03'
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'literal completed/native'):
                bind(f)

    def test_identity_and_false_credit_flags_match_actual_helper_contract(self):
        changes = {'id': '99'*32+':0', 'amount_sat': 9999, 'candidate_user_pubkey': '03'+'22'*32,
            'chain_anchor': '88'*32+':0', 'server_pubkey': '03'+'22'*32, 'expiry_height': 201,
            'policy': 'htlc', 'tree_padding': True, 'signed_path_valid': False,
            'chain_contract_verified': False, 'client_owner_verified': True,
            'native_owner_verified': True, 'payment_verified': True, 'schema_version': True}
        for field, value in changes.items():
            f = fixture(); f[5][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'completion proof differs'):
                bind(f)

    def test_missing_or_changed_sdk_never_infers_current_helper_admission(self):
        f = fixture(); f[5].pop('sdk_commit')
        with self.assertRaises(ValueError): bind(f)
        f = fixture(); f[5]['sdk_commit'] = 'ab'*20
        with self.assertRaises(ValueError): bind(f)
        with self.assertRaisesRegex(ValueError, 'anchor/SDK'):
            bind(fixture(), policy_sdk_commit='ab'*20)

    def test_selected_source_sdk_is_exact_and_shared_with_current_claim_helper(self):
        from simulator import normal_recovered_backing
        self.assertEqual(m.NATIVE_COMPLETION_SDK, 'cccc3f5747ad11b07b4742df1a25fb7b3ebe29c9')
        self.assertEqual(m.NATIVE_COMPLETION_SDK, normal_recovered_backing.NATIVE_COMPLETION_SDK)

    def test_old_e217_paired_stdout_cannot_be_relabelled_as_current_sdk(self):
        old_sdk = 'e217792fe4d9d9cbade5f54464123941e253a37d'
        f = fixture(); f[5]['sdk_commit'] = old_sdk
        with self.assertRaisesRegex(ValueError, 'completion proof differs'):
            bind(f)
        with self.assertRaisesRegex(ValueError, 'anchor/SDK'):
            bind(fixture(), policy_sdk_commit=old_sdk)

    def test_relation_cannot_claim_equality_or_generic_witness_completion(self):
        for equal, relation in [(False, 'exact_full_equality'), (False, 'bare_equal'),
                                (False, 'witness_stripped'), (True, 'final_hark_leaf_completion')]:
            f = fixture(equal); f[5]['native_completion_relation'] = relation
            with self.subTest(equal=equal, relation=relation), self.assertRaisesRegex(ValueError, 'known-field-preserving'):
                bind(f)

    def test_old_invalid_signed_path_or_binding_cannot_gain_completion_credit(self):
        for flag in ('signed_path_valid', 'authorization_path_valid'):
            f = fixture(); f[3][flag] = False
            with self.subTest(flag=flag), self.assertRaisesRegex(ValueError, 'ordinary signed Full'):
                bind(f)
        f = fixture(); f[3]['binding']['record_signature_valid'] = False
        with self.assertRaisesRegex(ValueError, 'per-key ownership'):
            bind(f)

    def test_rotating_record_equality_remains_hold(self):
        f = fixture(); f[2]['binding']['seq'] = 8; f[3]['binding']['seq'] = 8
        with self.assertRaisesRegex(ValueError, 'original rotating owner binding differs'):
            bind(f)

    def test_genesis_and_native_row_identity_remain_bound(self):
        f = fixture(); f[3]['genesis'] = '99'*32
        with self.assertRaisesRegex(ValueError, 'Full proof identity'):
            bind(f)
        f = fixture(); f[1]['anchor_point'] = '88'*32+':0'
        with self.assertRaisesRegex(ValueError, 'native and owned'):
            bind(f)

    def test_duplicate_json_fields_and_oversize_private_pair_refuse(self):
        raw = wire(fixture()[5])
        raw = b'{"native_owner_verified":false,' + raw[1:]
        with self.assertRaisesRegex(ValueError, 'duplicate proof field'):
            bind(fixture(), policy_response_raw=raw)
        with self.assertRaisesRegex(ValueError, 'bounded original'):
            bind(fixture(), policy_response_raw=b' '*(2*1024*1024+1))

    def test_partially_supplied_pair_never_falls_back_to_legacy(self):
        for field in ('policy_request_raw', 'policy_response_raw', 'anchor_raw', 'policy_sdk_commit'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                bind(fixture(True), **{field: None})


class ExecutedTransportControls(unittest.TestCase):
    def run_source(self, mutation=None):
        from simulator import two_step_normal, unknown_outcomes
        f = fixture(); calls = []
        class Rows:
            def fetchall(self): return [f[0]]
        class DB:
            def execute(self, *args): return Rows()
        class Store:
            db = DB()
            verified = 0
            def verify_event_chain(self): self.verified += 1
        store = Store()
        tables = {'vtxo': [f[1]], 'virtual_transaction': [{'txid': ANCHOR.split(':')[0],
            'is_funding': True, 'signed_transaction_hex': ANCHOR_RAW}],
            'key_link': [{'user_pubkey': KEY, 'mailbox_pk': KEY, 'sig': '66'*64}],
            'fallback_record': [{'mailbox_pk': KEY, 'spk': '0014'+'44'*20, 'seq': 7, 'sig': '55'*64}]}
        def stub(tool, request):
            calls.append((tool, copy.deepcopy(request)))
            if tool == 'binding': return wire(request), wire(f[3])
            if mutation == 'native-crypto-refusal':
                raise ValueError('SOFTWARE STUB: native signature/known-field verifier refused')
            if mutation == 'changed-sent':
                request = {**request, 'native_vtxo': 'ff'}
            if mutation == 'old-three-key':
                request = {k: v for k, v in request.items() if k != 'native_vtxo'}
            return wire(request), wire(f[5])
        with patch.object(two_step_normal, 'run_proof', side_effect=stub), patch.object(unknown_outcomes, '_coins', return_value=None):
            result = m.authenticate_owned_originals(store, tables, {'binding': 'binding', 'policy': 'policy'},
                genesis=GENESIS, server_pubkey=KEY)
        return result, calls, store

    def test_source_executes_both_roles_with_exact_client_and_native_literals(self):
        result, calls, store = self.run_source()
        self.assertEqual([role for role, _ in calls], ['binding', 'policy'])
        self.assertEqual(calls[0][1]['signed_vtxo'], COMPLETED.hex())
        self.assertEqual(calls[1][1], fixture()[4])
        self.assertEqual(store.verified, 1)
        self.assertEqual(result[COIN]['native_policy_request_sha256'], m.sha(wire(fixture()[4])))

    def test_altered_executed_request_and_old_mode_fail_instead_of_fallback(self):
        for mutation in ('changed-sent', 'old-three-key'):
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'actual native completion request changed'):
                self.run_source(mutation)

    def test_native_cryptographic_refusal_is_propagated_without_retry(self):
        with self.assertRaisesRegex(ValueError, 'native signature/known-field verifier refused'):
            self.run_source('native-crypto-refusal')


if __name__ == '__main__':
    unittest.main(verbosity=2)

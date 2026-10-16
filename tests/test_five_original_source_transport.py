"""All-original transport controls; opaque stubs confer no native proof credit."""
import copy
import unittest
from unittest.mock import patch

from simulator import normal_lineage as lineage
from simulator import two_step_normal, unknown_outcomes
from tests import test_normal_lineage_native_completion as fixture


def originals():
    values = []
    for number in range(5):
        value = fixture.fixture(True)
        owned, native, request, proof, policy_request, policy = value
        identifier = f'{number + 1:064x}:0'
        retained = fixture.wire({'format': 'ark-public-authorization-v1',
            'bare_vtxo': f'{number:02x}', 'path': []})
        owned.update(id=identifier, signed_vtxo=retained.hex(), signed_hash=lineage.sha(retained))
        native.update(vtxo_id=identifier, oor_spent_txid='ff'*32 if number == 0 else None)
        request['signed_vtxo'] = retained.hex()
        proof['id'] = identifier
        proof['path'][0]['txid'] = identifier.split(':')[0]
        policy_request['retained_public_projection'] = retained.hex()
        policy.update(id=identifier, retained_public_projection_sha256=lineage.sha(retained),
            retained_public_projection_relation='exact_ordinary_public_encoding',
            retained_public_projection_verified=True, retained_original_owner_verified=False)
        values.append(value)
    return values


def execute(values, tables):
    class Rows:
        def fetchall(self):
            return [value[0] for value in values]

    class Database:
        def execute(self, sql):
            if 'WHERE' in sql or 'owned_coin' not in sql:
                raise AssertionError('source must select all retained ownership originals')
            return Rows()

    class Store:
        db = Database()
        verified = 0

        def verify_event_chain(self):
            self.verified += 1

    calls = []
    by_original = {value[0]['signed_vtxo']: value for value in values}

    def stub(tool, request):
        calls.append((tool, copy.deepcopy(request)))
        retained = request['signed_vtxo'] if tool == 'binding' else request['retained_public_projection']
        value = by_original[retained]
        expected, response = (value[2], value[3]) if tool == 'binding' else (value[4], value[5])
        if request != expected:
            raise AssertionError('literal original/native/anchor request changed')
        return fixture.wire(request), fixture.wire(response)

    store = Store()
    with patch.object(two_step_normal, 'run_proof', side_effect=stub), \
            patch.object(unknown_outcomes, '_coins', return_value=None):
        result = lineage.authenticate_owned_originals(store, tables,
            {'binding': 'binding', 'policy': 'policy'},
            genesis=fixture.GENESIS, server_pubkey=fixture.KEY)
    return result, calls, store


def source_tables(values):
    return {'vtxo': [value[1] for value in values],
        'virtual_transaction': [{'txid': fixture.ANCHOR.split(':')[0],
            'is_funding': True, 'signed_transaction_hex': fixture.ANCHOR_RAW}],
        'key_link': [{'user_pubkey': fixture.KEY, 'mailbox_pk': fixture.KEY, 'sig': '66'*64}],
        'fallback_record': [{'mailbox_pk': fixture.KEY, 'spk': '0014'+'44'*20,
            'seq': 7, 'sig': '55'*64}]}


class FiveOriginalSourceTransport(unittest.TestCase):
    def test_consumed_board_and_four_successors_all_execute_both_literal_proofs(self):
        values = originals()
        before = copy.deepcopy(values)
        result, calls, store = execute(values, source_tables(values))
        self.assertEqual(len(result), 5)
        self.assertEqual([role for role, _ in calls], ['binding', 'policy']*5)
        self.assertIn(values[0][0]['id'], result)
        self.assertEqual(values, before)
        self.assertEqual(store.verified, 1)
        for value in values:
            coin = result[value[0]['id']]
            self.assertEqual(coin['retained_original_sha256'], value[0]['signed_hash'])
            self.assertNotEqual(coin['retained_original_sha256'], coin['completed_full_sha256'])
            self.assertNotIn('ready', coin)
            self.assertNotIn('paid', coin)

    def test_current_only_native_cut_cannot_omit_consumed_board_original(self):
        values = originals()
        tables = source_tables(values)
        tables['vtxo'] = tables['vtxo'][1:]
        with self.assertRaisesRegex(ValueError, 'original/intermediate owned Full missing'):
            execute(values, tables)

    def test_missing_or_nonfunding_original_anchor_refuses(self):
        for mutation in ('absent', 'not-funding'):
            values = originals()
            tables = source_tables(values)
            if mutation == 'absent':
                tables['virtual_transaction'] = []
            else:
                tables['virtual_transaction'][0]['is_funding'] = False
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'Full anchor missing'):
                execute(values, tables)


if __name__ == '__main__':
    unittest.main()

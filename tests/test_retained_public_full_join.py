"""Software/parser stubs only; no native, signature or financial qualification."""
import copy
import json
import unittest

from simulator import normal_lineage as lineage
from tests import test_normal_lineage_native_completion as coin_fixture
from tests import test_current_claim_completion as current_fixture

RETAINED=json.dumps({'format':'ark-public-authorization-v1','bare_vtxo':'00','path':[]},
    sort_keys=True,separators=(',',':')).encode()


def relation():
    return {'retained_public_projection_sha256':lineage.sha(RETAINED),
        'retained_public_projection_relation':'exact_ordinary_public_encoding',
        'retained_public_projection_verified':True,'retained_original_owner_verified':False}


def projected_coin():
    value=coin_fixture.fixture(True)
    value[0].update(signed_vtxo=RETAINED.hex(),signed_hash=lineage.sha(RETAINED))
    value[2]['signed_vtxo']=RETAINED.hex()
    value[4]['retained_public_projection']=RETAINED.hex();value[5].update(relation())
    return value


def bind(value,**kwargs):
    return coin_fixture.bind(value,completed_vtxo=coin_fixture.COMPLETED.hex(),**kwargs)


def projected_current():
    value=current_fixture.fixture(True)
    value['store'].db.execute('UPDATE owned_coin SET signed_vtxo=?,signed_hash=?',
        (RETAINED.hex(),lineage.sha(RETAINED)))
    value['claim']['signed_hash']=lineage.sha(RETAINED)
    value['contract_request']['retained_public_projection']=RETAINED.hex()
    value['contract'].update(relation())
    context=value['context']['authenticated_coins'][current_fixture.COIN]
    context.update(retained_original_sha256=lineage.sha(RETAINED),
        native_policy_request_sha256=current_fixture.sha(current_fixture.wire(value['contract_request'])),
        native_policy_response_sha256=current_fixture.sha(current_fixture.wire(value['contract'])))
    return value


class RetainedProjectionBoundaryControls(unittest.TestCase):
    def test_history_projection_and_signed_hash_remain_original(self):
        value=projected_coin();original=copy.deepcopy(value[0]);result=bind(value)
        self.assertEqual(original,value[0]);self.assertEqual(result['retained_original_sha256'],lineage.sha(RETAINED))
        self.assertEqual(result['completed_full_sha256'],lineage.sha(coin_fixture.COMPLETED))
        self.assertEqual(result['completed_vtxo_hex'],coin_fixture.COMPLETED.hex())
        self.assertNotEqual(result['completed_full_sha256'],original['signed_hash'])
        self.assertNotIn('ready',result);self.assertNotIn('paid',result)

    def test_projection_cannot_be_used_without_separate_full(self):
        with self.assertRaisesRegex(ValueError,'separate genuine'):
            coin_fixture.bind(projected_coin())
        with self.assertRaisesRegex(ValueError,'separate genuine'):
            coin_fixture.bind(projected_coin(),completed_vtxo=RETAINED.hex())

    def test_literal_original_full_cannot_be_replaced_by_another_source(self):
        with self.assertRaisesRegex(ValueError,'cannot be replaced'):bind(coin_fixture.fixture(True))

    def test_detached_projection_relation_hash_owner_or_flag_refuses(self):
        for field,bad in [('retained_public_projection_sha256','00'*32),
                ('retained_public_projection_relation','bare_equal'),
                ('retained_public_projection_relation','witness_stripped'),
                ('retained_public_projection_verified',False),('retained_original_owner_verified',True)]:
            value=projected_coin();value[5][field]=bad
            with self.subTest(field=field,bad=bad),self.assertRaisesRegex(ValueError,'exact retained'):bind(value)

    def test_omitted_or_foreign_original_in_actual_request_refuses(self):
        for bad in [None,'00']:
            value=projected_coin()
            if bad is None:value[4].pop('retained_public_projection')
            else:value[4]['retained_public_projection']=bad
            with self.assertRaisesRegex(ValueError,'source anchor request'):bind(value)

    def test_current_claim_route_passes_both_literals_without_history_writes(self):
        value=projected_current();before=value['store'].db.total_changes
        try:
            (claims,verified),calls=current_fixture.run(value)
            self.assertEqual(value['claim']['signed_hash'],lineage.sha(RETAINED))
            self.assertEqual(calls[0][1]['retained_public_projection'],RETAINED.hex())
            self.assertEqual(calls[0][1]['signed_vtxo'],current_fixture.COMPLETE)
            self.assertEqual(verified[0]['completed_vtxo_sha256'],lineage.sha(bytes.fromhex(current_fixture.COMPLETE)))
            self.assertEqual(verified[0]['signed_hash'],lineage.sha(RETAINED))
            self.assertEqual(value['store'].db.total_changes,before)
        finally:value['store'].db.close()

    def test_current_claim_needs_original_source_hash_and_exact_lineage_request(self):
        for field in ['retained_original_sha256','native_policy_request_sha256','native_policy_response_sha256']:
            value=projected_current();value['context']['authenticated_coins'][current_fixture.COIN][field]='00'*32
            try:
                with self.subTest(field=field),self.assertRaises(ValueError):current_fixture.run(value)
            finally:value['store'].db.close()

    def test_current_claim_refuses_decode_only_or_false_projection_verification(self):
        for field,bad in [('chain_contract_verified',False),('signed_path_valid',False),
                ('retained_public_projection_verified',False),('retained_public_projection_sha256','00'*32)]:
            value=projected_current();value['contract'][field]=bad
            context=value['context']['authenticated_coins'][current_fixture.COIN]
            context['native_policy_response_sha256']=current_fixture.sha(current_fixture.wire(value['contract']))
            try:
                with self.subTest(field=field),self.assertRaises(ValueError):current_fixture.run(value)
            finally:value['store'].db.close()


if __name__=='__main__':unittest.main()

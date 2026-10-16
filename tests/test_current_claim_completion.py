"""SOFTWARE STUB boundary controls; no native signature or financial qualification.

Full bodies are public opaque test strings. Anchor is an unfunded public wire
transaction so the existing decoder is exercised without any Core/RPC call.
"""
from pathlib import Path
import copy
import hashlib
import json
import sqlite3
import unittest
from unittest.mock import patch

from simulator import normal_recovered_backing as helper
from simulator import two_step_normal as m

ROOT = Path(__file__).resolve().parents[1]
from simulator.bundle_audit import decode_transaction
KEY = '02'+'11'*32
NATIVE = b'public software partial; not Vtxo'.hex()
COMPLETE = b'public software completed; not Vtxo'.hex()
SOURCE = 'ab'*32
OBS = 'cd'*16
COIN = '44'*32+':0'
ANCHOR_RAW = ((2).to_bytes(4,'little')+b'\x01'+bytes.fromhex('55'*32)[::-1]
    +(0).to_bytes(4,'little')+b'\0'+b'\xff'*4+b'\x01'+(10000).to_bytes(8,'little')
    +b'\x01\x51'+b'\0'*4).hex()
ANCHOR = decode_transaction(ANCHOR_RAW)['txid']+':0'

def wire(value): return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def sha(raw): return hashlib.sha256(raw).hexdigest()

class Store:
    def __init__(self):
        self.db = sqlite3.connect(':memory:'); self.db.row_factory = sqlite3.Row
        self.db.execute('CREATE TABLE owned_coin(id TEXT PRIMARY KEY,signed_vtxo TEXT,signed_hash TEXT,proof TEXT)')


def fixture(equal=False):
    binding = {'mailbox_pk':KEY,'spk':'0014'+'66'*20,'seq':7}
    proof = {'server_pubkey':KEY,'user_pubkey':KEY,'chain_anchor':ANCHOR,'expiry_height':200,'binding':binding}
    store = Store(); store.db.execute('INSERT INTO owned_coin VALUES(?,?,?,?)',(COIN,COMPLETE,sha(bytes.fromhex(COMPLETE)),wire(proof).decode()))
    claim = {'coin_id':COIN,'actor':'actor-01','amount_sat':10000,'signed_hash':sha(bytes.fromhex(COMPLETE)),
        'state':'Spendable','observation_action_id':'public-fixture'}
    row = {'vtxo_id':COIN,'amount':10000,'anchor_point':ANCHOR,'expiry':200,
        'policy_type':'pubkey','server_pubkey':KEY,'signed_vtxo_hex':COMPLETE if equal else NATIVE}
    tables = {'vtxo':[row], 'virtual_transaction':[{'txid':ANCHOR.split(':')[0],'is_funding':True,'signed_transaction_hex':ANCHOR_RAW}],
        'key_link':[{'user_pubkey':KEY,'mailbox_pk':KEY,'sig':'77'*64}],
        'fallback_record':[{'mailbox_pk':KEY,'spk':binding['spk'],'seq':7,'sig':'88'*64}]}
    contract_request = {'signed_vtxo':COMPLETE,'native_vtxo':row['signed_vtxo_hex'],'anchor_raw':ANCHOR_RAW,'server_pubkey':KEY}
    contract = {'schema_version':1,'sdk_commit':helper.NATIVE_COMPLETION_SDK,'id':COIN,'amount_sat':10000,
        'chain_anchor':ANCHOR,'candidate_user_pubkey':KEY,'server_pubkey':KEY,'expiry_height':200,'exit_delta':12,
        'policy':'pubkey','tree_padding':False,'signed_path_valid':True,'chain_contract_verified':True,
        'native_vtxo_sha256':sha(bytes.fromhex(row['signed_vtxo_hex'])),'completed_vtxo_sha256':claim['signed_hash'],
        'native_completion_relation':'exact_full_equality' if equal else 'final_hark_leaf_completion',
        'client_owner_verified':False,'native_owner_verified':False,'payment_verified':False}
    binding_request = {'user_pubkey':KEY,'binding':{**binding,'record_attestation':'88'*64},'key_link_attestation':'77'*64}
    binding_reply = {'genesis':m.SIGNET_GENESIS,'user_pubkey':KEY,
        'binding':{**binding,'record_signature_valid':True,'key_link_signature_valid':True}}
    context = {'claims':[claim],'consumed_claim_ids':[],'source_observation_id':OBS,'native_source_sha256':SOURCE,
        'authenticated_coins':{COIN:{'completed_full_sha256':claim['signed_hash'],
            'native_full_sha256':sha(bytes.fromhex(row['signed_vtxo_hex'])),
            'native_policy_request_sha256':sha(wire(contract_request)),
            'native_policy_response_sha256':sha(wire(contract))}}}
    return {'store':store,'tables':tables,'claim':claim,'context':context,'contract_request':contract_request,
        'contract':contract,'binding_request':binding_request,'binding_reply':binding_reply}


def run(f, *, mutation=None, context=True, **arguments):
    calls=[]
    def stub(tool, request):
        calls.append((tool,copy.deepcopy(request)))
        if tool=='policy':
            if mutation=='native-refused': raise ValueError('SOFTWARE STUB: known signature/ancestor/preimage mismatch')
            if mutation=='old-mode': request={k:v for k,v in request.items()if k!='native_vtxo'}
            elif mutation=='changed-sent': request={**request,'native_vtxo':'00'}
            return wire(request),wire(f['contract'])
        return wire(request),wire(f['binding_reply'])
    args={'lineage_context':f['context'] if context else None,'native_source_sha256':SOURCE,'source_observation_id':OBS}
    args.update(arguments)
    with patch.object(m,'run_proof',side_effect=stub), patch.object(m,'_current_claims',return_value=[f['claim']]):
        result=m.authenticate_claims(f['store'],f['tables'],{'policy':'policy','binding':'binding'},KEY,**args)
    return result,calls


class CurrentClaimCompletionControls(unittest.TestCase):
    def test_imports_are_current_checkout_and_same_claim_helper(self):
        self.assertEqual(Path(m.__file__).resolve(),ROOT/'simulator/two_step_normal.py')
        self.assertEqual(Path(helper.__file__).resolve(),ROOT/'simulator/normal_recovered_backing.py')
        self.assertIs(m.bind_native_claim,helper.bind_native_claim)

    def test_same_literal_pair_executes_under_existing_current_claim_route(self):
        f=fixture();before=f['store'].db.total_changes
        (claims,verified),calls=run(f)
        self.assertEqual(calls,[('policy',f['contract_request']),('binding',f['binding_request'])])
        self.assertEqual(claims,[f['claim']]);value=verified[0]
        self.assertEqual(value['signed_vtxo_sha256'],sha(bytes.fromhex(NATIVE)))
        self.assertEqual(value['completed_vtxo_sha256'],f['claim']['signed_hash'])
        self.assertEqual(value['native_completion_relation'],'final_hark_leaf_completion')
        self.assertEqual(value['native_source_sha256'],SOURCE);self.assertEqual(value['source_observation_id'],OBS)
        self.assertEqual(f['store'].db.total_changes,before)
        self.assertNotIn('ready',value);self.assertNotIn('paid',value)

    def test_equal_pair_has_no_partial_or_payment_inference(self):
        (claims,verified),_=run(fixture(True))
        self.assertEqual(verified[0]['native_completion_relation'],'exact_full_equality')

    def test_initial_non_lineage_path_still_executes_pair_and_needs_nonce_sql(self):
        (_,verified),calls=run(fixture(),context=False)
        self.assertEqual(calls[0][1]['signed_vtxo'],COMPLETE)
        self.assertEqual(verified[0]['native_completion_relation'],'final_hark_leaf_completion')
        with self.assertRaisesRegex(ValueError,'SQL/observation'):
            run(fixture(),context=False,source_observation_id=None)

    def test_missing_or_malformed_source_identity_refuses_before_tools(self):
        for key,value in [('source_observation_id',None),('source_observation_id','cd'*32),
                          ('native_source_sha256',None),('native_source_sha256','NOT-A-HASH')]:
            with self.subTest(key=key,value=value),self.assertRaisesRegex(ValueError,'SQL/observation'):
                run(fixture(),**{key:value})

    def test_detached_lineage_nonce_or_sql_refuses(self):
        for key,value in [('source_observation_id','ab'*16),('native_source_sha256','bc'*32)]:
            f=fixture();f['context'][key]=value
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'lineage source/observation'):
                run(f)

    def test_missing_or_changed_retained_completed_original_refuses(self):
        f=fixture();f['store'].db.execute('DELETE FROM owned_coin')
        with self.assertRaisesRegex(ValueError,'completed claim original missing'):run(f)
        f=fixture();f['store'].db.execute('UPDATE owned_coin SET signed_hash=?',('00'*32,))
        with self.assertRaisesRegex(ValueError,'original hash differs'):run(f)

    def test_claim_signed_hash_cannot_select_other_client_original(self):
        f=fixture();f['claim']['signed_hash']='00'*32
        with self.assertRaisesRegex(ValueError,'original hash differs'):run(f)

    def test_lineage_native_and_completed_pair_hashes_must_match_current_source(self):
        for field in ('native_full_sha256','completed_full_sha256'):
            f=fixture();f['context']['authenticated_coins'][COIN][field]='00'*32
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'executed lineage Full pair'):
                run(f)

    def test_policy_request_and_response_originals_are_same_as_lineage_execution(self):
        for field in ('native_policy_request_sha256','native_policy_response_sha256'):
            f=fixture();f['context']['authenticated_coins'][COIN][field]='00'*32
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'originals differ'):
                run(f)

    def test_changed_executed_or_legacy_three_key_policy_mode_has_no_retry(self):
        for mutation in ('changed-sent','old-mode'):
            with self.subTest(mutation=mutation),self.assertRaisesRegex(ValueError,'request changed'):
                run(fixture(),mutation=mutation)

    def test_actual_tool_refusal_propagates_without_publishing_claim(self):
        with self.assertRaisesRegex(ValueError,'known signature/ancestor/preimage mismatch'):
            run(fixture(),mutation='native-refused')

    def test_policy_hash_identity_relation_and_sdk_are_not_supplied_flags(self):
        changes={'sdk_commit':'ab'*20,'native_vtxo_sha256':'00'*32,'completed_vtxo_sha256':'00'*32,
            'native_completion_relation':'bare_equal','native_owner_verified':True,'payment_verified':True,
            'client_owner_verified':True,'schema_version':True}
        for field,value in changes.items():
            f=fixture();f['contract'][field]=value
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'native-completion proof differs'):
                run(f,context=False)

    def test_invalid_client_signed_path_still_refuses(self):
        for field in ('signed_path_valid','chain_contract_verified'):
            f=fixture();f['contract'][field]=False
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'genuine ordinary Full'):
                run(f,context=False)

    def test_policy_metadata_still_binds_amount_identity_anchor_and_exit_delta(self):
        for field,value in [('id','99'*32+':0'),('amount_sat',9999),('candidate_user_pubkey','03'+'99'*32),
                            ('chain_anchor','88'*32+':0'),('expiry_height',201),('exit_delta',13)]:
            f=fixture();f['contract'][field]=value
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'preserved claim differ'):
                run(f,context=False)

    def test_fallback_rotation_equality_gate_remains_unchanged(self):
        f=fixture();f['tables']['fallback_record'][0]['seq']=8
        f['binding_reply']['binding']['seq']=8
        with self.assertRaisesRegex(ValueError,'rotating per-key binding differs'):run(f)

    def test_actual_anchor_body_cannot_be_replaced_by_same_reported_identity(self):
        f=fixture();f['tables']['virtual_transaction'][0]['signed_transaction_hex']=ANCHOR_RAW[:-8]+'01000000'
        with self.assertRaisesRegex(ValueError,'native proof root differs'):
            run(f,context=False)

    def test_legacy_helper_path_is_preserved_for_identical_native_original(self):
        f=fixture(True);expected={**f['claim'],'chain_anchor':ANCHOR,'user_pubkey':KEY,
            'server_pubkey':KEY,'expiry_height':200,'exit_delta':12,'binding':f['binding_request']['binding']}
        request={k:v for k,v in f['contract_request'].items()if k!='native_vtxo'}
        value=helper.bind_native_claim(expected,f['tables']['vtxo'][0],wire(request),wire(f['contract']),
            wire(f['binding_request']),wire(f['binding_reply']),genesis=m.SIGNET_GENESIS,server_pubkey=KEY)
        self.assertEqual(value['signed_vtxo_sha256'],sha(bytes.fromhex(COMPLETE)))
        self.assertNotIn('native_completion_relation',value)

    def test_a_native_facts_passes_actual_observation_to_lineage_without_global_default(self):
        from simulator import normal_lineage_join
        class StopAfterObservedNonce(Exception): pass
        seen=[]
        def checked_frontier(*args,**kwargs):
            seen.append((kwargs['observation_id'],kwargs['native_source_sha256']))
            raise StopAfterObservedNonce()
        collector=m.Collector(None,1,{})
        source={'original_sha256':{'native_sql':SOURCE},'identity':{'server_pubkey':KEY}}
        admitted={'proof_tool_sha256':{},'ordinary_lineage':{'test_scope':'software_only'}}
        with patch.object(m,'native_tables',return_value={}), patch.object(normal_lineage_join,'authenticate_frontier',side_effect=checked_frontier):
            with self.assertRaises(StopAfterObservedNonce):
                collector._a_native_facts(None,None,None,None,None,None,source,{'native_sql':b'public-test-source'},
                    admitted,None,0,{'id':OBS})
        self.assertEqual(seen,[(OBS,SOURCE)])

    def test_helper_requires_complete_pair_parameter_set(self):
        f=fixture();expected={**f['claim'],'chain_anchor':ANCHOR,'user_pubkey':KEY,
            'server_pubkey':KEY,'expiry_height':200,'exit_delta':12,'binding':f['binding_request']['binding']}
        for omitted in ('completed_vtxo','source_anchor_raw','policy_sdk_commit'):
            args={'completed_vtxo':COMPLETE,'source_anchor_raw':ANCHOR_RAW,'policy_sdk_commit':helper.NATIVE_COMPLETION_SDK}
            args[omitted]=None
            with self.subTest(omitted=omitted),self.assertRaisesRegex(ValueError,'source/SDK'):
                helper.bind_native_claim(expected,f['tables']['vtxo'][0],wire(f['contract_request']),wire(f['contract']),
                    wire(f['binding_request']),wire(f['binding_reply']),genesis=m.SIGNET_GENESIS,server_pubkey=KEY,**args)

if __name__=='__main__':
    unittest.main(verbosity=2)

"""Synthetic native-output binding tests. No native signature/ownership credit."""
import copy
import hashlib
import json
import unittest
from unittest.mock import patch
from simulator import c_native_body_proof as c
from tests import test_c_private_normal_cut as fixture
from tests import test_c_native_fee_sources as fee_fixture


class NativeBodyProof(unittest.TestCase):
    def setUp(self):
        self.x=fixture.CombinedNativeCut();self.x.setUp();self.addCleanup(self.x.doCleanups)
        self.f=self.x.fixture;self.funding=self.f.fixture.parent
        self.txid=c.decode_transaction(self.funding.hex())['txid'];self.point=self.txid+':0'
        model=self.x.x.f.projections()['coins']['fields'];metadata={n:None for n in model}
        metadata.update(vtxo_id=self.point,anchor_point=self.point,amount=25000,expiry=200,policy_type='pubkey',policy='00'+'02'+'a'*64,spend_state='spendable')
        self.x.x.rows['coins']=[metadata]
        self.x.x.pg['coins']=[{'metadata':copy.deepcopy(metadata),'native_id':1,'lightning_htlc_subscription_id':None,'source_encoding':'ServerVtxoFull','body_hex':'00aa'}]
        self.result=self.x.capture(self.x.pg());self.path=self.f.root/'proof-body.tar';self.loaded=self.x.load(self.result,self.path)
        self.row=self.loaded['private_pg']['coins'][0]
        self.tool={'sha256':'c'*64,'command':['/synthetic/unexecuted-native-full-proof'],'evidence_directory':'/synthetic/private'}
        self.identity={'source_commit':c.PROOF_SOURCE,'sdk_actual_GIT_HASH':'9'*40,'sdk_component_commit':self.f.observation['financial_pins']['sdk_commit'],'binary_sha256':'c'*64,'runtime_manifest_sha256':'d'*64}
        self.request={'schema_version':1,'kind':'native-full-path-request','source_encoding':'ServerVtxoFull','body_hex':'00aa','funding_transaction_hex':self.funding.hex(),'expected_server_pubkey':fee_fixture.KEY}
        sha=lambda raw:hashlib.sha256(raw).hexdigest()
        self.proof={'schema_version':1,'kind':'native-full-path-proof','source_encoding':'ServerVtxoFull','sdk_commit':'9'*40,
          'input_body_sha256':sha(bytes.fromhex('00aa')),'canonical_reencoding_sha256':sha(bytes.fromhex('00aa')),'canonical_reencoding_equal':True,
          'funding_txid':self.txid,'raw_funding_sha256':sha(self.funding),'id':self.point,'point':self.point,'chain_anchor':self.point,
          'amount_sat':25000,'expiry_height':200,'exit_delta':12,'server_pubkey':fee_fixture.KEY,'user_pubkey':'02'+'a'*64,
          'policy_type':'pubkey','policy_hex':'00'+'02'+'a'*64,'ancestor_ids':[],'path_steps':0,'anchor_only':True,'transitions':[],
          'unsigned_path_valid':True,'signed_path_valid':True,'all_native_witnesses_present':True,
          'witnessed_conditional_steps':0,'total_conditional_steps':None,'unresolved':[],'validation_scope':c.SCOPE}
    def encoded(self,value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
    def bind(self,**changes):
        args={'source_table':'coins','funding_raw':self.funding,'tool_identity':self.identity,'server_pubkey':fee_fixture.KEY};args.update(changes)
        return c.bind_path(self.row,self.encoded(self.request),self.encoded(self.proof),**args)
    def test_exact_full_proof_stays_economically_unresolved_and_private_originals_hashed(self):
        value=self.bind();self.assertTrue(value['signed_path_valid']);self.assertEqual('UNRESOLVED_REQUIRES_SAME_RR_CURRENT_SOURCE',value['economic_ownership'])
        self.assertNotIn('body_hex',value);self.assertNotIn('funding_transaction_hex',value)
    def test_unsigned_valid_signedfalse_or_incomplete_never_becomes_free_operator(self):
        self.proof.update(signed_path_valid=False,all_native_witnesses_present=False,unresolved=['native_signed_path_not_valid'])
        value=self.bind();self.assertFalse(value['signed_path_valid']);self.assertIn('UNRESOLVED',value['economic_ownership'])
        self.proof['unresolved']=[]
        with self.assertRaises(ValueError):self.bind()
    def test_actual_source_encoding_body_funding_owner_amount_policy_and_sdk_are_bound(self):
        for key,value in [('source_encoding','VtxoFull'),('input_body_sha256','e'*64),('raw_funding_sha256','f'*64),
          ('sdk_commit',self.identity['sdk_component_commit']),('server_pubkey','03'+'b'*64),('amount_sat',24999),
          ('expiry_height',201),('policy_hex','00'+'03'+'a'*64),('canonical_reencoding_equal',False),('unsigned_path_valid',False)]:
            original=copy.deepcopy(self.proof);self.proof[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.bind()
            self.proof=original
        self.request['body_hex']='00bb'
        with self.assertRaises(ValueError):self.bind()
    def test_secret_or_extra_fields_bool_amount_unknown_conditional_count_and_path_bounds_refuse(self):
        for mutate in [lambda p:p.update(body_hex='00aa'),lambda p:p.update(raw_witness='not-allowed'),lambda p:p.update(amount_sat=True),
          lambda p:p.update(total_conditional_steps=0),lambda p:p.update(path_steps=1),lambda p:p.update(witnessed_conditional_steps=1)]:
            original=copy.deepcopy(self.proof);mutate(self.proof)
            with self.assertRaises(ValueError):self.bind()
            self.proof=original
    def collect(self,**changes):
        outer=self
        class Core:
            def identity(self):return {'chain':'signet','blocks':100,'bestblockhash':fee_fixture.TIP,'initialblockdownload':False}
            def call(self,method,*args):
                if method=='getblockhash':return c.SIGNET_GENESIS
                if method=='getrawtransaction':return {'txid':outer.txid,'hex':outer.funding.hex(),'confirmations':3,'blockhash':fee_fixture.TIP}
                raise AssertionError('forbidden wallet/RPC')
        args={'tool_identity':self.identity,'observation':self.f.observation,'server_pubkey':fee_fixture.KEY};args.update(changes)
        def fake_run(tool,request):return self.encoded(request),self.encoded(self.proof)
        with patch.object(c,'run_proof',side_effect=fake_run)as execute:
            result=c.collect_paths(self.loaded,Core(),self.tool,**args)
            return result,execute.call_count
    def test_existing_shared_tool_lifecycle_called_exactly_once_per_original_body(self):
        value,calls=self.collect();self.assertEqual(1,calls);self.assertEqual(1,len(value['paths']));self.assertFalse(value['complete']);self.assertFalse(value['qualified'])
        self.assertFalse(value['current_economic_ownership_complete']);self.assertEqual([],value['unresolved_signed_paths'])
        self.proof.update(signed_path_valid=False,all_native_witnesses_present=False,unresolved=['native_signed_path_not_valid'])
        value,_=self.collect();self.assertEqual([self.point],value['unresolved_signed_paths'])
    def test_wrong_tool_extra_argv_or_component_holds_before_native_execution(self):
        self.tool['command'].append('--invented-mode')
        with patch.object(c,'run_proof')as execute,self.assertRaises(ValueError):self.collect()
        execute.assert_not_called()
        self.tool['command'].pop();identity={**self.identity,'sdk_component_commit':'8'*40}
        with self.assertRaises(ValueError):self.collect(tool_identity=identity)

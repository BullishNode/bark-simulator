"""Synthetic public-metadata algebra controls, no native/crypto/live credit."""
import copy
import hashlib
import importlib.util
import json
import pathlib
import unittest
from simulator import normal_lineage as m

P = pathlib.Path(__file__).parent
KEY = '02'+'11'*32
SOURCE = 'ab'*32


def ident(n):
    return format(n, '064x')+':0'


def coin(n, sat, actor='alice', parent=None):
    value = {'id': ident(n), 'amount_sat': sat, 'actor': actor, 'pubkey': KEY,
        'chain_anchor': ident(900), 'native_request_sha256': '11'*32,
        'native_response_sha256': '22'*32, 'native_full_sha256': '33'*32, 'path': []}
    if parent is not None:
        value['path'] = [{'txid': ident(n).split(':')[0], 'output_index': 0,
            'inputs': [ident(parent)], 'output_amount_sat': sat}]
    return value


def edge(name, inputs, outputs, fee=0, kind='arkoor'):
    return {'action_id': name, 'kind': kind, 'inputs': [ident(x) for x in inputs],
        'outputs': [ident(x) for x in outputs], 'service_fee_sat': fee,
        'evidence_sha256': '44'*32}


def wire(parent, sat):
    return ((2).to_bytes(4,'little')+b'\x01'+bytes.fromhex(parent.split(':')[0])[::-1]
        +(0).to_bytes(4,'little')+b'\0'+b'\xff'*4+b'\x01'+sat.to_bytes(8,'little')
        +b'\x01\x51'+b'\0'*4).hex()


from simulator import bundle_audit as d


class Controls(unittest.TestCase):
    def reduce(self, coins, origins, edges):
        return m.reduce_lineage({c['id']:c for c in coins},[ident(x) for x in origins],edges,native_source_sha256=SOURCE)

    def test_two_synthetic_immediate_splits_preserve_original_obligation(self):
        coins = [coin(1,10000),coin(2,6000),coin(3,4000,'bob'),coin(4,2000),coin(5,4000,'carol')]
        result = self.reduce(coins,[1],[edge('a',[1],[2,3]),edge('b',[2],[4,5])])
        self.assertEqual(result['current_claim_ids'],[ident(3),ident(4),ident(5)])
        self.assertEqual(result['obligation_groups'][0]['original_principal_sat'],10000)
        self.assertEqual(result['obligation_groups'][0]['current_principal_sat'],10000)
        self.assertNotIn('ready',result); self.assertNotIn('paid',result)

    def test_refresh_replaces_right_with_exact_internal_sdk_fee(self):
        result = self.reduce([coin(1,10000),coin(2,9800)],[1],[edge('r',[1],[2],200,'refresh')])
        self.assertEqual(result['consumed_claim_ids'],[ident(1)])
        self.assertEqual(result['obligation_groups'][0]['sdk_service_charge_sat'],200)

    def test_joint_origins_have_no_invented_fee_allocation(self):
        result = self.reduce([coin(1,6000),coin(2,4000),coin(3,9900)],[1,2],[edge('r',[1,2],[3],100,'refresh')])
        group=result['obligation_groups'][0]
        self.assertEqual(group['original_claim_ids'],[ident(1),ident(2)])
        self.assertIsNone(group['per_origin_fee_allocation'])

    def test_two_disjoint_edges_in_same_group_do_not_duplicate_fee_or_liability(self):
        cs=[coin(1,10000),coin(2,6000),coin(3,4000),coin(4,5900),coin(5,3900)]
        result=self.reduce(cs,[1],[edge('a',[1],[2,3]),edge('r1',[2],[4],100,'refresh'),edge('r2',[3],[5],100,'refresh')])
        self.assertEqual(result['obligation_groups'][0]['current_principal_sat'],9800)
        self.assertEqual(result['obligation_groups'][0]['sdk_service_charge_sat'],200)

    def test_missing_unattributed_input_or_output_fails(self):
        for cs,origins,edges in [([coin(1,10),coin(2,10),coin(3,1)],[1],[edge('a',[1],[2])]),
                ([coin(1,10)],[1],[edge('a',[1],[2])])]:
            with self.subTest(origins=origins),self.assertRaises(ValueError):self.reduce(cs,origins,edges)

    def test_duplicate_consumption_output_action_and_original_rewrite_fail(self):
        cs=[coin(1,10),coin(2,10),coin(3,10)]
        cases=[[edge('a',[1],[2]),edge('b',[1],[3])], [edge('a',[1],[2]),edge('b',[3],[2])],
            [edge('a',[1],[2]),edge('a',[2],[3])], [edge('a',[1],[1])]]
        for edges in cases:
            with self.subTest(edges=edges),self.assertRaises(ValueError):self.reduce(cs,[1],edges)

    def test_cycles_cannot_create_a_frontier(self):
        with self.assertRaises(ValueError):self.reduce([coin(1,10),coin(2,10),coin(3,10)],[1],
            [edge('a',[2],[3]),edge('b',[3],[2])])

    def test_wrong_fee_negative_fee_and_ark_charge_fail(self):
        for fee,kind in [(1,'refresh'),(-1,'refresh'),(2,'arkoor')]:
            with self.subTest(fee=fee),self.assertRaises(ValueError):self.reduce([coin(1,10),coin(2,8)],[1],[edge('a',[1],[2],fee,kind)])

    def test_expired_unconsumed_original_stays_liability(self):
        result=self.reduce([coin(1,10)],[1],[])
        self.assertEqual(result['current_claim_ids'],[ident(1)])
        self.assertEqual(result['obligation_groups'][0]['sdk_service_charge_sat'],0)

    def test_full_proof_original_identity_and_binding_are_required(self):
        binding={'mailbox_pk':KEY,'spk':'0014'+'44'*20,'seq':7}
        original={'id':ident(1),'amount_sat':10000,'pubkey':KEY,'actor':'alice','signed_vtxo':'01',
            'signed_hash':hashlib.sha256(b'\x01').hexdigest(),
            'proof':json.dumps({'chain_anchor':ident(900),'expiry_height':200,'binding':binding})}
        native={'vtxo_id':ident(1),'policy_type':'pubkey','amount':10000,'server_pubkey':KEY,
            'anchor_point':ident(900),'expiry':200,'signed_vtxo_hex':'02'}
        request={'signed_vtxo':'02','binding':{**binding,'record_attestation':'55'*64},'key_link_attestation':'66'*64}
        proof={'id':ident(1),'amount_sat':10000,'user_pubkey':KEY,'chain_anchor':ident(900),
            'expiry_height':200,'genesis':'aa'*32,'server_pubkey':KEY,'signed_path_valid':True,
            'authorization_path_valid':True,'conditional_steps':0,
            'binding':{**binding,'record_signature_valid':True,'key_link_signature_valid':True},
            'path':[{'txid':ident(1).split(':')[0],'output_index':0,'inputs':[ident(900)],'output_amount_sat':10000}]}
        encode=lambda value:json.dumps(value,sort_keys=True).encode()
        result=m.bind_coin(original,native,encode(request),encode(proof),genesis='aa'*32,server_pubkey=KEY)
        self.assertEqual(result['native_full_sha256'],hashlib.sha256(b'\x02').hexdigest())
        for mutate in ['binding-only','foreign-owner','native-bytes','wrong-genesis','conditional','path']:
            req=copy.deepcopy(request);reply=copy.deepcopy(proof)
            if mutate=='binding-only':del req['signed_vtxo']
            elif mutate=='foreign-owner':reply['binding']['seq']=8
            elif mutate=='native-bytes':req['signed_vtxo']='03'
            elif mutate=='wrong-genesis':reply['genesis']='bb'*32
            elif mutate=='conditional':reply['conditional_steps']=1
            else:reply['path'][0]['output_index']=1
            with self.subTest(mutation=mutate),self.assertRaises(ValueError):m.bind_coin(original,native,encode(req),encode(reply),genesis='aa'*32,server_pubkey=KEY)

    def test_immediate_ark_parent_and_every_input_must_match_native(self):
        cs={x['id']:x for x in [coin(1,10000),coin(2,6000,parent=1),coin(3,4000,'bob',parent=1)]}
        # Separate leaves can have one shared real branch transaction; this
        # synthetic path gives each a different branch, so it MUST refuse.
        native={ident(1):{'oor_spent_txid':ident(2).split(':')[0],'spent_in_round':None,
            'offboarded_in':None,'onchain_spent_txid':None,'spend_state':'spent'}}
        with self.assertRaises(ValueError):m.arkoor_edge('a',[ident(1)],[ident(2),ident(3)],[ident(3)],cs,native,
            sender='alice',recipient='bob',transfer_sat=4000,evidence_sha256=SOURCE)
        cs[ident(3)]['path'][0].update(txid=ident(2).split(':')[0],output_index=1)
        cs[ident(3)]['id']=ident(2).split(':')[0]+':1';del cs[ident(3)];cs[ident(2).split(':')[0]+':1']=coin3=coin(3,4000,'bob',parent=1)
        coin3.update(id=ident(2).split(':')[0]+':1',path=[{'txid':ident(2).split(':')[0],'output_index':1,'inputs':[ident(1)],'output_amount_sat':4000}])
        valid=m.arkoor_edge('a',[ident(1)],[ident(2),coin3['id']],[coin3['id']],cs,native,
            sender='alice',recipient='bob',transfer_sat=4000,evidence_sha256=SOURCE)
        self.assertEqual(valid['service_fee_sat'],0)
        coin3['path'][0]['inputs']=[ident(99)]
        with self.assertRaisesRegex(ValueError,'immediate signed parent'):m.arkoor_edge('a',[ident(1)],[ident(2),coin3['id']],[coin3['id']],cs,native,
            sender='alice',recipient='bob',transfer_sat=4000,evidence_sha256=SOURCE)

    def round_fixture(self):
        cs={x['id']:x for x in [coin(1,10000),coin(2,9800)]}
        funding=wire(ident(77),9800);ftx=d.decode_transaction(funding)['txid'];cs[ident(2)].update(chain_anchor=ftx+':0',unlock_hash='66'*32,native_policy_response_sha256='77'*32)
        forfeit=wire(ident(1),9900);ff=d.decode_transaction(forfeit)['txid']
        tables={'virtual_transaction':[{'txid':ident(900).split(':')[0],'is_funding':True,'signed_transaction_hex':wire(ident(88),10000)}],'vtxo':[{'vtxo_id':ident(1),'signed_vtxo_hex':'01','server_pubkey':KEY,'spent_in_round':7,'oor_spent_txid':ff,'spend_state':'spent','offboarded_in':None,'onchain_spent_txid':None},
            {'vtxo_id':ident(2),'signed_vtxo_hex':'02'}],
            'round':[{'id':7,'funding_txid':ftx,'funding_tx_hex':funding,'signed_tree_bytes':1}],
            'round_participation':[{'id':10,'round_id':ftx,'unlock_hash':'66'*32,'forfeited_at':'captured-native-timestamp','unlock_preimage_present':True}],
            'round_part_input':[{'participation_id':10,'vtxo_id':ident(1),'signed_forfeit_tx_hex':forfeit}],
            'round_part_output':[{'participation_id':10,'policy_hex':'00'+KEY,'amount':9800,'unblinded_mailbox_id':None}]}
        return cs,tables

    def refresh(self,cs,tables,executor=None):
        return m.refresh_edge('r',[ident(1)],[ident(2)],cs,tables,actor='alice',committed_fee_sat=200,
            evidence_sha256=SOURCE,decode_transaction=d.decode_transaction,round_proof_executor=executor)

    def test_round_metadata_and_detached_forfeited_timestamp_cannot_retire_right(self):
        cs,t=self.round_fixture()
        with self.assertRaisesRegex(ValueError,'admitted native original-forfeit'):self.refresh(cs,t)

    def test_round_wrong_parent_missing_input_duplicate_allocation_and_wrong_round_id_fail(self):
        for mutation in ['parent','missing','duplicate','roundid','unforfeited','unlock','owner']:
            cs,t=self.round_fixture()
            if mutation=='parent':t['round_part_input'][0]['signed_forfeit_tx_hex']=wire(ident(99),9900)
            elif mutation=='missing':t['round_part_input']=[]
            elif mutation=='duplicate':t['round_part_output']*=2
            elif mutation=='roundid':t['vtxo'][0]['spent_in_round']=t['round'][0]['funding_txid']
            elif mutation=='unforfeited':t['round_participation'][0]['forfeited_at']=None
            elif mutation=='unlock':cs[ident(2)]['unlock_hash']='88'*32
            else:cs[ident(2)]['actor']='bob'
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.refresh(cs,t)

    def test_round_executor_original_buffers_are_bound_but_stub_is_not_crypto_qualification(self):
        cs,t=self.round_fixture()
        def stub(request):
            proof={'signed_path_valid':True,'chain_contract_verified':True,'forfeit_signature_valid':True,
                'id':ident(1),'forfeit_input_coin_id':ident(1),'forfeit_unlock_hash':request['forfeit_unlock_hash'],
                'forfeit_txid':d.decode_transaction(request['forfeit_raw'])['txid'],
                'forfeit_raw_sha256':m.sha(bytes.fromhex(request['forfeit_raw']))}
            return json.dumps(request,sort_keys=True).encode(),json.dumps(proof,sort_keys=True).encode()
        e=self.refresh(cs,t,stub);self.assertEqual(e['service_fee_sat'],200)
        def altered(request):
            a,b=stub(request);v=json.loads(b);v['forfeit_input_coin_id']=ident(99);return a,json.dumps(v).encode()
        with self.assertRaisesRegex(ValueError,'native original forfeit'):self.refresh(cs,t,altered)



if __name__=='__main__':
    unittest.main()

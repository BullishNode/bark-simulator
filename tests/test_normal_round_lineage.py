"""SOFTWARE STUBS ONLY. No native cryptographic, source or financial qualification."""
import copy,json,unittest
from simulator import normal_lineage as m
from tests import test_normal_lineage as base
from tests.test_normal_lineage import ident,coin,edge,KEY,SOURCE,d
SDK=m.NATIVE_COMPLETION_SDK
J=lambda v:json.dumps(v,sort_keys=True,separators=(',',':')).encode()
class TreeControls(unittest.TestCase):
 def fixture(self):
  cs,t=base.Controls().round_fixture()
  pins={'tool_sha256':'81'*32,'commands_sha256':'82'*32,'admission_sha256':'83'*32,
   'sdk_commit':SDK,'source_observation_id':'84'*16,'source_sha256':SOURCE,
   'qualification_scope':'software_stub_no_native_credit'}
  r=t['round'][0];c=cs[ident(2)];raw=t['vtxo'][1]['signed_vtxo_hex'];h=t['round_participation'][0]['unlock_hash']
  leaf={'leaf_index':0,'id':ident(2),'amount_sat':9800,'policy':'pubkey','user_pubkey':KEY,
   'user_policy_hex':'00'+KEY,'unlock_hash':h,'completed_vtxo_sha256':m.sha(bytes.fromhex(raw)),
   'leaf_spec_sha256':'85'*32,'tree_native_vtxo_sha256':'86'*32,'tree_completion_relation':'final_hark_leaf_completion',
   'literal_native_vtxo_sha256':m.sha(bytes.fromhex(raw)),'literal_native_completion_relation':'exact_full_equality'}
  tree={'schema_version':1,'sdk_commit':SDK,'mode':'round_allocation','server_pubkey':KEY,'participation_unlock_hash':h,
   'signed_tree_sha256':m.sha(bytes.fromhex(r['signed_tree_hex'])),'anchor_raw_sha256':m.sha(bytes.fromhex(r['funding_tx_hex'])),
   'chain_anchor':c['chain_anchor'],'tree_leaf_count':2,'verified_internal_signature_count':1,
   'all_matching_leaf_indices':[0],'allocations':[leaf],'allocation_sat':9800,'all_matching_leaves_verified':True,
   'client_owner_verified':False,'payment_verified':False}
  pending_leaf={k:v for k,v in leaf.items()if k not in {'completed_vtxo_sha256','tree_completion_relation','literal_native_vtxo_sha256','literal_native_completion_relation'}}
  pending_leaf.update(chain_anchor=c['chain_anchor'],unsigned_path_verified=True,
   derived_native_path=[{'txid':ident(2).split(':')[0],'output_index':0,'transaction_sha256':'87'*32}],
   signed_leaf_verified=False,current_spendability_verified=False,client_owner_verified=False,retirement_verified=False,payment_verified=False)
  pending={k:v for k,v in tree.items()if k not in {'all_matching_leaf_indices','allocations','allocation_sat','all_matching_leaves_verified'}}
  pending.update(mode='pending_entitlement',pending_allocation_membership_verified=True,
   all_matching_pending_leaf_indices=[0],pending_allocations=[pending_leaf],pending_entitlement_sat=9800,
   original_sha256={'signed_tree':tree['signed_tree_sha256'],'anchor_raw':tree['anchor_raw_sha256']},
   signed_leaf_verified=False,current_spendability_verified=False,retirement_verified=False)
  def forfeit(request,*,expected):
   original=next(row for row in t['vtxo']if row['signed_vtxo_hex']==request['signed_vtxo'])
   original_id=original['vtxo_id']
   v={'schema_version':1,'sdk_commit':SDK,'signed_path_valid':True,'chain_contract_verified':True,
    'forfeit_signature_valid':True,'id':original_id,'forfeit_input_coin_id':original_id,
    'chain_anchor':cs[original_id]['chain_anchor'],'server_pubkey':KEY,'policy':'pubkey',
    'amount_sat':cs[original_id]['amount_sat'],'candidate_user_pubkey':KEY,'tree_padding':False,'client_owner_verified':False,
    'forfeit_unlock_hash':h,'forfeit_txid':d.decode_transaction(request['forfeit_raw'])['txid'],
    'forfeit_raw_sha256':m.sha(bytes.fromhex(request['forfeit_raw'])),
    'native_vtxo_sha256':m.sha(bytes.fromhex(request['native_vtxo'])),
    'completed_vtxo_sha256':m.sha(bytes.fromhex(request['signed_vtxo'])),
    'native_completion_relation':cs[original_id]['native_completion_relation'],
    'native_owner_verified':False,'payment_verified':False}
   return J(request),J(v),dict(pins)
  def executor(proof):
   def run(request,*,expected):
    self.assertEqual(expected,pins)
    return J(request),J(proof),dict(pins)
   return run
  return cs,t,pins,tree,pending,forfeit,executor
 def refresh(self,f,tree=None,forfeit=None,pins=None):
  cs,t,p,proof,_,ff,exe=f
  return m.refresh_edge('r',[ident(1)],[ident(2)],cs,t,actor='alice',committed_fee_sat=200,
   evidence_sha256=SOURCE,decode_transaction=d.decode_transaction,round_proof_executor=forfeit or ff,
   tree_proof_executor=exe(tree if tree is not None else proof),tree_proof_pins=pins or p)
 def pending(self,f,proof=None):
  cs,t,p,_,pending,_,exe=f
  return m.pending_refresh_entitlement('pending-r',[ident(1)],cs,t,actor='alice',committed_fee_sat=200,
   evidence_sha256=SOURCE,decode_transaction=d.decode_transaction,tree_proof_executor=exe(proof or pending),tree_proof_pins=p)
 def test_completed_callback_binds_every_original_and_explicit_stub_scope(self):
  f=self.fixture();e=self.refresh(f)
  self.assertEqual(e['proof_qualification_scope'],'software_stub_no_native_credit')
  self.assertEqual(len(e['native_forfeit_originals']),1)
  self.assertEqual(e['native_tree_originals']['signed_tree_sha256'],f[3]['signed_tree_sha256'])
  result=m.reduce_lineage(f[0],[ident(1)],[e],native_source_sha256=SOURCE)
  self.assertEqual(result['current_claim_ids'],[ident(2)])
  self.assertEqual(result['obligation_groups'][0]['sdk_service_charge_sat'],200)
  self.assertNotIn('ready',result);self.assertNotIn('paid',result)
 def test_sql_count_timestamp_and_hash_only_without_original_tree_fail(self):
  for mode in ['missing','count-only','raw-changed']:
   f=self.fixture();row=f[1]['round'][0]
   if mode=='missing':del row['signed_tree_hex']
   elif mode=='count-only':row['signed_tree_hex']=''
   else:row['signed_tree_hex']='aabc'
   with self.subTest(mode=mode),self.assertRaises(ValueError):self.refresh(f)
 def test_all_matching_indexes_extra_leaf_duplicate_and_samehash_wrong_allocation_fail(self):
  for change in ['extra','dup-index','wrong-amount','wrong-policy','wrong-index','missing-relation','wrong-full']:
   f=self.fixture();proof=copy.deepcopy(f[3]);leaf=proof['allocations'][0]
   if change=='extra':
    extra=copy.deepcopy(leaf);extra.update(id=ident(3),leaf_index=1);proof['allocations'].append(extra);proof['all_matching_leaf_indices'].append(1)
   elif change=='dup-index':proof['all_matching_leaf_indices']=[0,0]
   elif change=='wrong-amount':leaf['amount_sat']=9801
   elif change=='wrong-policy':leaf['user_policy_hex']='00'+'03'+'99'*32
   elif change=='wrong-index':leaf['leaf_index']=1
   elif change=='missing-relation':del leaf['tree_completion_relation']
   else:leaf['completed_vtxo_sha256']='00'*32
   with self.subTest(change=change),self.assertRaises(ValueError):self.refresh(f,proof)
 def test_merge_requires_every_original_forfeit_and_preserves_joint_origin_fee_allocation(self):
  f=self.fixture();cs,t,p,proof,_,ff,exe=f
  cs[ident(1)]['amount_sat']=6000
  cs[ident(3)]=coin(3,4000);cs[ident(3)].update(native_full_sha256=m.sha(b'\x03'),completed_full_sha256=m.sha(b'\x03'),completed_vtxo_hex='03',native_completion_relation='exact_full_equality')
  first=t['round_part_input'][0];first['signed_forfeit_tx_hex']=base.wire(ident(1),5900)
  t['vtxo'][0]['oor_spent_txid']=d.decode_transaction(first['signed_forfeit_tx_hex'])['txid']
  second=base.wire(ident(3),3900)
  t['round_part_input'].append({'participation_id':10,'vtxo_id':ident(3),'signed_forfeit_tx_hex':second})
  t['vtxo'].append({'vtxo_id':ident(3),'signed_vtxo_hex':'03','server_pubkey':KEY,'spent_in_round':7,
   'oor_spent_txid':d.decode_transaction(second)['txid'],'spend_state':'spent','offboarded_in':None,'onchain_spent_txid':None})
  def merge(forfeit):
   return m.refresh_edge('merge',[ident(1),ident(3)],[ident(2)],cs,t,actor='alice',committed_fee_sat=200,
    evidence_sha256=SOURCE,decode_transaction=d.decode_transaction,round_proof_executor=forfeit,
    tree_proof_executor=exe(proof),tree_proof_pins=p)
  e=merge(ff);self.assertEqual({x['input_id']for x in e['native_forfeit_originals']},{ident(1),ident(3)})
  result=m.reduce_lineage(cs,[ident(1),ident(3)],[e],native_source_sha256=SOURCE)
  self.assertEqual(result['obligation_groups'][0]['original_principal_sat'],10000)
  self.assertIsNone(result['obligation_groups'][0]['per_origin_fee_allocation'])
  def bad_second(request,*,expected):
   sent,res,binding=ff(request,expected=expected);v=json.loads(res)
   if request['signed_vtxo']=='03':v['forfeit_signature_valid']=False
   return sent,J(v),binding
  with self.assertRaises(ValueError):merge(bad_second)

 def test_pending_proof_cannot_enter_completed_refresh_edge(self):
  f=self.fixture()
  with self.assertRaises(ValueError):self.refresh(f,f[4])
 def test_pinned_callback_tool_nonce_source_sdk_schema_and_exact_request_are_bound(self):
  for key in ['tool_sha256','commands_sha256','admission_sha256','source_observation_id','source_sha256','sdk_commit','qualification_scope','request','schema']:
   f=self.fixture();ff=f[5]
   def altered(request,*,expected):
    sent,res,binding=ff(request,expected=expected)
    if key=='request':req=json.loads(sent);req['forfeit_unlock_hash']='00'*32;sent=J(req)
    elif key=='schema':v=json.loads(res);v['schema_version']=True;res=J(v)
    else:binding[key]='wrong'
    return sent,res,binding
   with self.subTest(key=key),self.assertRaises(ValueError):self.refresh(f,forfeit=altered)
 def test_every_input_forfeit_wrong_original_or_signature_result_refuses(self):
  for mode in ['forfeit','native-full','parent']:
   f=self.fixture();ff=f[5]
   if mode=='native-full':f[1]['vtxo'][0]['signed_vtxo_hex']='99'
   elif mode=='parent':f[1]['round_part_input'][0]['signed_forfeit_tx_hex']=f[1]['round'][0]['funding_tx_hex']
   def bad(request,*,expected):
    sent,res,b=ff(request,expected=expected);v=json.loads(res)
    if mode=='forfeit':v['forfeit_signature_valid']=False
    return sent,J(v),b
   with self.subTest(mode=mode),self.assertRaises(ValueError):self.refresh(f,forfeit=bad)
 def test_fee_refund_or_cost_mutation_cannot_retire_or_increase_obligation(self):
  f=self.fixture();cs,t,p,proof,_,ff,exe=f
  for fee in [-1,0,199,201]:
   with self.subTest(fee=fee),self.assertRaises(ValueError):
    m.refresh_edge('r',[ident(1)],[ident(2)],cs,t,actor='alice',committed_fee_sat=fee,evidence_sha256=SOURCE,
     decode_transaction=d.decode_transaction,round_proof_executor=ff,tree_proof_executor=exe(proof),tree_proof_pins=p)
  with self.assertRaises(ValueError):m.reduce_lineage(cs,[ident(1)],[edge('refund',[1],[2],200,'refund')],native_source_sha256=SOURCE)
 def test_pending_reference_preserves_original_right_and_creates_no_extra_liability_or_edge(self):
  f=self.fixture();f[1]['round_participation'][0]['forfeited_at']=None
  result=self.pending(f)
  self.assertEqual(result['preserved_obligation_input_ids'],[ident(1)])
  self.assertEqual(result['additional_principal_sat'],0);self.assertEqual(result['retired_claim_ids'],[])
  self.assertEqual(result['paid_sat'],0);self.assertEqual(result['transfer_sat'],0)
  for key in ['signed_leaf_verified','owner_verified','current_spendability_verified']:self.assertIs(result[key],False)
  # The reference cannot be submitted as a completed transition, even twice.
  with self.assertRaises(ValueError):m.reduce_lineage(f[0],[ident(1)],[result,result],native_source_sha256=SOURCE)
  current=m.reduce_lineage({ident(1):f[0][ident(1)]},[ident(1)],[],native_source_sha256=SOURCE)
  self.assertEqual(current['current_claim_ids'],[ident(1)])
 def test_pending_modes_flags_original_hashset_path_duplicate_allocation_and_fee_mutations_refuse(self):
  for change in ['completed-mode','signed','owner','paid','retired','spendable','hashset','path','duplicate','amount','request-counter']:
   f=self.fixture();proof=copy.deepcopy(f[4]);leaf=proof['pending_allocations'][0]
   if change=='completed-mode':proof['mode']='round_allocation'
   elif change=='hashset':proof['original_sha256']['signed_tree']='00'*32
   elif change=='path':leaf['derived_native_path'][0]['txid']=ident(99).split(':')[0]
   elif change=='duplicate':proof['pending_allocations']*=2;proof['all_matching_pending_leaf_indices']=[0,0]
   elif change=='amount':leaf['amount_sat']=9900
   elif change=='request-counter':f[1]['round_part_output'][0]['amount']=9900
   else:
    key={'signed':'signed_leaf_verified','owner':'client_owner_verified','paid':'payment_verified','retired':'retirement_verified','spendable':'current_spendability_verified'}[change]
    leaf[key]=True
   with self.subTest(change=change),self.assertRaises(ValueError):self.pending(f,proof)
 def test_double_split_merge_preserves_joint_origins_and_closed_unconsumed_right(self):
  cs=[coin(1,10000),coin(2,6000),coin(3,4000),coin(4,2000),coin(5,4000),coin(6,5900),coin(7,100,'closed-03')]
  edges=[edge('split1',[1],[2,3]),edge('split2',[2],[4,5]),edge('merge',[4,3],[6],100,'refresh')]
  result=m.reduce_lineage({c['id']:c for c in cs},[ident(1),ident(7)],edges,native_source_sha256=SOURCE)
  self.assertEqual(result['current_claim_ids'],[ident(5),ident(6),ident(7)])
  group=next(g for g in result['obligation_groups']if ident(1)in g['original_claim_ids'])
  self.assertEqual(group['current_principal_sat'],9900);self.assertEqual(group['sdk_service_charge_sat'],100)
  self.assertIsNone(group['per_origin_fee_allocation'])
if __name__=='__main__':unittest.main()

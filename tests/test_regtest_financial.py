import copy,hashlib,json,os,tempfile,time,unittest
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch
from integration import regtest_financial as f

class FinancialSourceControls(unittest.TestCase):
 def declaration(self):
  return {'schema':'regtest-fixture-financial-v1','network':'regtest','genesis':f.REGTEST_GENESIS,
   'architecture_profile':'two_step_per_key','sdk_commit':'1'*40,'native_commit':'2'*40,
   'actors':['actor-01','actor-02','actor-03','actor-04','actor-05'],'operator_opening_sat':1000000,
   'client_grants_sat':{f'actor-{i:02}':20000 for i in range(1,6)},'board_amount_sat':10000,
   'action_fee_cap_sat':2000,'lifetime_blocks':432,'board_confirmations':6,'pool_enabled':False,'lightning_enabled':False}
 def wallet(self):
  return {'complete':True,'network':'regtest','wallet':'watchman','tip_height':100,'tip_hash':'a'*64,
   'reserved_outpoints':[],'pending_transactions':[],'pending_parents':[],'unavailable_parent_txids':[],
   'public_descriptor':'synthetic-public-descriptor','min_trusted_confirmations':3,'last_revealed_index':0,
   'pending_transaction_scope':'canonical_wallet_graph_only',
   'utxos':[{'outpoint':'b'*64+':0','value_sat':100000,'script_pubkey':'0014'+'1'*40,
    'confirmed_fee_eligible':True,'trusted':True,'mature':True,'reserved':False}]}
 def chain(self,script=None):
  class Chain:
   def call(self,*args,**kwargs):return {'confirmations':3,'value':Decimal('0.001'),'scriptPubKey':{'hex':script or '0014'+'1'*40}}
  return Chain()
 def test_core_native_fact_matching_synthetic_control(self):
  value=f._wallet_facts(self.chain(),self.wallet(),'watchman',{'blocks':100,'bestblockhash':'a'*64})
  self.assertEqual(100000,value['confirmed_eligible_unreserved_sat'])
 def test_no_core_value_or_script_substitution(self):
  with self.assertRaises(ValueError):f._wallet_facts(self.chain('0014'+'2'*40),self.wallet(),'watchman',{'blocks':100,'bestblockhash':'a'*64})
 def test_reserved_coin_cannot_count_twice(self):
  w=self.wallet();w['reserved_outpoints']=[w['utxos'][0]['outpoint']]
  with self.assertRaises(ValueError):f._wallet_facts(self.chain(),w,'watchman',{'blocks':100,'bestblockhash':'a'*64})
 def test_foreign_tip_or_network_and_duplicates_refused(self):
  for field,value in [('tip_hash','c'*64),('network','signet')]:
   w=self.wallet();w[field]=value
   with self.assertRaises(ValueError):f._wallet_facts(self.chain(),w,'watchman',{'blocks':100,'bestblockhash':'a'*64})
  w=self.wallet();w['utxos']*=2
  with self.assertRaises(ValueError):f._wallet_facts(self.chain(),w,'watchman',{'blocks':100,'bestblockhash':'a'*64})
 def test_existing_declaration_never_raised_or_overwritten(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d)/'declaration.json';r=f.freeze_declaration(p,self.declaration());self.assertFalse(r['admitted']);before=p.read_bytes()
   changed=self.declaration();changed['operator_opening_sat']+=1
   with self.assertRaises(FileExistsError):f.freeze_declaration(p,changed)
   self.assertEqual(before,p.read_bytes());self.assertEqual(0o600,p.stat().st_mode&0o777)
 def test_fresh_filesystem_is_not_zero_asset_proof(self):
  with tempfile.TemporaryDirectory()as d:
   result=f.fresh_directory_fact(d,self.declaration()['actors']);self.assertFalse(result['zero_assets_verified'])
   (Path(d)/'actor-01').mkdir()
   with self.assertRaises(ValueError):f.fresh_directory_fact(d,self.declaration()['actors'])
 def test_profile_does_not_relax_genesis_or_caps(self):
  for key,value in [('genesis','0'*64),('action_fee_cap_sat',None),('operator_opening_sat',True)]:
   v=self.declaration();v[key]=value
   with self.assertRaises(ValueError):f.validate_declaration(v)
 def test_fixed_native_verb_refuses_foreign_endpoint_and_binary(self):
  with self.assertRaises(ValueError):f._native_inventory('/does-not-exist','0'*64,'http://example.com:3536',1)
  with tempfile.NamedTemporaryFile()as n:
   n.write(b'not native');n.flush()
   with self.assertRaises(ValueError):f._native_inventory(n.name,'0'*64,'http://127.0.0.1:3536',1)
 def native_script(self,d,body):
  p=Path(d)/'harmless-child';p.write_text('#!/usr/bin/python3\n'+body);p.chmod(0o700)
  return p,hashlib.sha256(p.read_bytes()).hexdigest()
 def test_actual_pipe_oversize_refused_before_child_finishes(self):
  with tempfile.TemporaryDirectory()as d:
   p,h=self.native_script(d,"import os,time\nos.write(1,b'x'*(2*1024*1024+1))\ntime.sleep(5)\n")
   started=time.monotonic()
   with self.assertRaisesRegex(ValueError,'byte bound'):f._native_inventory(p,h,'http://127.0.0.1:3536',2)
   self.assertLess(time.monotonic()-started,2)
 def test_actual_pipe_prefix_hang_and_closed_pipe_hang_have_real_deadline(self):
  for body in ["import os,time\nos.write(1,b'{')\ntime.sleep(5)\n", "import os,time\nos.close(1)\ntime.sleep(5)\n"]:
   with self.subTest(body=body),tempfile.TemporaryDirectory()as d:
    p,h=self.native_script(d,body);started=time.monotonic()
    with self.assertRaises((TimeoutError, __import__('subprocess').TimeoutExpired)):f._native_inventory(p,h,'http://127.0.0.1:3536',0.15)
    self.assertLess(time.monotonic()-started,1)
 def test_actual_pipe_requires_successful_exit_and_exact_original_digest(self):
  with tempfile.TemporaryDirectory()as d:
   p,h=self.native_script(d,"import os\nos.write(1,b'{\"complete\":false}\\n')\n")
   value,receipt=f._native_inventory(p,h,'http://127.0.0.1:3536',1)
   raw=b'{"complete":false}\n'
   self.assertEqual({'complete':False},value);self.assertEqual(hashlib.sha256(raw).hexdigest(),receipt['sha256']);self.assertEqual(len(raw),receipt['bytes'])
   p,h=self.native_script(d,"import os\nos.write(1,b'{}')\nraise SystemExit(1)\n")
   with self.assertRaisesRegex(ValueError,'process failed'):f._native_inventory(p,h,'http://127.0.0.1:3536',1)
 def owner_response(self,role):
  value=self.wallet();value['wallet']=role;value['utxos'][0]['outpoint']=('b'if role=='rounds'else'c')*64+':0'
  return {'rounds':value if role=='rounds'else None,'watchman':value if role=='watchman'else None,
   'complete':False,'missing_sources':[f.OWNER_MISSING[role]]}
 def test_actual_source_shaped_two_daemons_remain_partial_not_global(self):
  class Chain:
   def __init__(self,*args,**kwargs):pass
   def identity(self):return {'chain':'regtest','blocks':100,'bestblockhash':'a'*64,'initialblockdownload':False}
   def call(self,*args,**kwargs):return {'confirmations':3,'value':Decimal('0.001'),'scriptPubKey':{'hex':'0014'+'1'*40}}
  def native(binary,sha,address,timeout):
   return self.owner_response('rounds'if address.endswith(':3536')else'watchman'),{'sha256':'b'*64,'bytes':100,'exit':0}
  with patch.object(f,'ChainReader',Chain),patch.object(f,'_native_inventory',native):
   result=f._collect_worker('http://127.0.0.1:18443','unused','unused','b'*64,'http://127.0.0.1:3536','http://127.0.0.1:3538')
  self.assertEqual({'rounds','watchman'},set(result['wallets']))
  for field in ('complete','atomic','qualified','financial_readiness'):self.assertIs(False,result[field])
  for role in ('rounds','watchman'):
   source=result['native_source_digests'][role];self.assertIs(False,source['response_complete']);self.assertIs(True,source['owning_inventory_complete']);self.assertEqual([f.OWNER_MISSING[role]],source['missing_sources'])
 def test_foreign_missing_partial_owner_and_global_claim_refused(self):
  for role in ('rounds','watchman'):
   frame=self.owner_response(role);self.assertEqual(role,f._owned_inventory_frame(frame,role)['wallet'])
   other='watchman'if role=='rounds'else'rounds'
   mutations=[lambda v:v.update(complete=True),lambda v:v.update(missing_sources=[]),lambda v:v.update({role:None}),
    lambda v:v.update({other:self.wallet()}),lambda v:v[role].update(complete=False),
    lambda v:v[role].update(wallet=other),lambda v:v[role].update(network='signet'),
    lambda v:v[role].pop('pending_parents')]
   for change in mutations:
    bad=copy.deepcopy(frame);change(bad)
    with self.subTest(role=role,bad=bad),self.assertRaises(ValueError):f._owned_inventory_frame(bad,role)
 def test_distinct_fixed_owner_endpoints_required_before_RPC(self):
  with patch.object(f,'ChainReader',side_effect=AssertionError('must not call Core')):
   with self.assertRaisesRegex(ValueError,'distinct'):f._collect_worker('http://127.0.0.1:18443','x','x','b'*64,'http://127.0.0.1:3536','http://127.0.0.1:3536')
 def test_duplicate_source_keys_refused(self):
  with self.assertRaises(ValueError):json.loads('{"complete":false,"complete":true}',object_pairs_hook=f._pairs)

if __name__=='__main__':unittest.main()

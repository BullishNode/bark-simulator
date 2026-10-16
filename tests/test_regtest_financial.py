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
   'reserved_outpoints':[],'pending_transactions':[],'unavailable_parent_txids':[],
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
 def test_duplicate_source_keys_refused(self):
  with self.assertRaises(ValueError):json.loads('{"complete":false,"complete":true}',object_pairs_hook=f._pairs)

if __name__=='__main__':unittest.main()

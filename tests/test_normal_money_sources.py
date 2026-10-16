"""Synthetic raw-wire/Store controls only; no native or live financial credit."""
import copy,hashlib,json,pathlib,tempfile,unittest
from simulator.normal_money_sources import collect_money_sources
from simulator.bundle_audit import decode_transaction
from simulator.store import Store
from simulator.engine import initialize

H=lambda raw:hashlib.sha256(raw).hexdigest()
TIP='b'*64
GENESIS='00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6'
KEY='02'+'1'*64
PINS={'unit':'synthetic'}
MEMBERS=[{'id':'R','role':'operator','kind':'wallet','identity':'r'},{'id':'W','role':'operator','kind':'wallet','identity':'w'},{'id':'B','role':'operator','kind':'wallet','identity':'b'},{'id':'K','role':'operator','kind':'ark_backing','identity':KEY},{'id':'actor-01','role':'customer','kind':'wallet','identity':'c'}]
def wire(inputs,outputs):
 raw=(2).to_bytes(4,'little')+bytes([len(inputs)])
 for txid,vout in inputs:raw+=bytes.fromhex(txid)[::-1]+vout.to_bytes(4,'little')+b'\x00'+bytes.fromhex('ffffffff')
 raw+=bytes([len(outputs)])
 for value,script in outputs:raw+=value.to_bytes(8,'little')+bytes([len(script)])+script
 return raw+b'\0'*4
class Chain:
 def __init__(self,raws):
  self.values={}
  for raw in raws:
   tx=decode_transaction(raw.hex());self.values[tx['txid']]={'txid':tx['txid'],'hex':raw.hex(),'confirmations':1,'blockhash':TIP}
 def identity(self):return {'blocks':100,'bestblockhash':TIP,'initialblockdownload':False}
 def call(self,method,*args):
  assert method=='getblockhash';return GENESIS if args==(0,) else TIP
 def tx(self,txid):return self.values[txid]
class Controls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.store=Store(pathlib.Path(self.tmp.name),'synthetic',100000);initialize(self.store)
  self.parent=wire([('0'*64,4294967295)],[(1000,b'\x51')]);self.pid=decode_transaction(self.parent.hex())['txid'];self.raw=wire([(self.pid,0)],[(900,b'\x51')]);self.txid=decode_transaction(self.raw.hex())['txid'];self.chain=Chain([self.parent,self.raw]);self.tables={'fee_allowance_policy':[{'policy_bytes_hex':json.dumps({'server_pubkey':KEY,'genesis':GENESIS}).encode().hex()}],'fee_allowance_candidate':[],'recovery_receipt':[]};self.fee={'candidate_ids':[],'epoch_id':'a'*64}
 def tearDown(self):self.store.close();self.tmp.cleanup()
 def native(self,path='Sweep',fee=100,raw=None,parents=None):
  raw=self.raw if raw is None else raw;parents=[self.parent]if parents is None else parents
  candidate={'epoch_id':'a'*64,'path':path,'raw':list(raw),'input_parents':[list(v)for v in parents],'package_parents':[],'package_input_parents':[]};body=json.dumps(candidate,separators=(',',':')).encode();wtxid=hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex();self.tables['fee_allowance_candidate'].append({'id':wtxid,'candidate_bytes_hex':body.hex(),'urgent':path in {'Claim','ProgressParent','ProgressChild'},'fee_sat':fee});self.fee['candidate_ids']=sorted(v['id']for v in self.tables['fee_allowance_candidate'])
 def collect(self,**kwargs):return collect_money_sources(self.store,self.chain,financial_pins=PINS,boundary_members=MEMBERS,native_tables=self.tables,native_fee=self.fee,native_source_sha256='c'*64,native_member_ids={'rounds':'R','watchman':'W'},height=100,tip_hash=TIP,**kwargs)
 def test_native_raw_parent_fee_and_reuse_without_writes(self):
  self.native();before=self.store.db.execute('SELECT count(*) FROM event').fetchone()[0];v=self.collect();self.assertEqual(v['cost_records'][0]['amount_msat'],100000);self.assertEqual(v['cost_records'][0]['source'],'K');self.assertEqual(self.store.db.execute('SELECT count(*) FROM event').fetchone()[0],before)
  self.store.event('financial_cost_verified',v['cost_records'][0]);v=self.collect();self.assertEqual(v['cost_records'],[]);self.assertEqual(v['reused_cost_ids'],['miner:'+self.txid])
 def test_receipt_and_candidate_parentonce(self):
  self.native();self.tables['recovery_receipt']=[{'id':self.txid,'transaction_bytes_hex':self.raw.hex(),'proof_state':'physical_bound','block_hash':TIP,'block_height':100}];v=self.collect();self.assertEqual(len(v['cost_records']),1);self.assertEqual(len(v['evidence_hashes']['carrier_sources'][self.txid]),2)
 def test_unconfirmed_reservation_is_not_paid(self):
  self.native();self.chain.values[self.txid]['confirmations']=0;v=self.collect();self.assertEqual(v['cost_records'],[]);self.assertIn(self.txid,v['pending_carriers']);self.assertEqual(v['zero_fee_carriers'],{})
 def test_confirmed_zero_is_separate_from_expense(self):
  raw=wire([(self.pid,0)],[(1000,b'\x51')]);self.chain=Chain([self.parent,raw]);self.native('ProgressParent',0,raw);v=self.collect();self.assertEqual(v['cost_records'],[]);self.assertEqual(len(v['zero_fee_carriers']),1)
 def test_tampered_budget_or_fee_refuses(self):
  self.native();self.tables['fee_allowance_candidate'][0]['urgent']=True
  with self.assertRaises(ValueError):self.collect()
  self.tables['fee_allowance_candidate'][0]['urgent']=False;self.tables['fee_allowance_candidate'][0]['fee_sat']=99
  with self.assertRaisesRegex(ValueError,'fee differs'):self.collect()
 def test_core_body_and_parent_substitution_refuse(self):
  self.native();self.chain.values[self.txid]['hex']=wire([(self.pid,0)],[(901,b'\x51')]).hex()
  with self.assertRaisesRegex(ValueError,'txid differs'):self.collect()
  self.chain.values[self.txid]['hex']=self.raw.hex();self.chain.values[self.pid]['hex']=wire([('0'*64,4294967295)],[(1001,b'\x51')]).hex()
  with self.assertRaisesRegex(ValueError,'txid differs'):self.collect()
 def test_active_block_and_missing_parent_refuse(self):
  self.native();self.chain.values[self.txid]['blockhash']='e'*64
  with self.assertRaisesRegex(ValueError,'active chain'):self.collect()
  self.chain.values[self.txid]['blockhash']=TIP;del self.chain.values[self.pid]
  with self.assertRaises(KeyError):self.collect()
 def test_duplicate_native_membership_refuses(self):
  self.native();self.tables['fee_allowance_candidate'].append(copy.deepcopy(self.tables['fee_allowance_candidate'][0]))
  with self.assertRaisesRegex(ValueError,'membership'):self.collect()
 def test_existing_conflicting_cost_never_rewritten(self):
  self.native();v=self.collect();record=v['cost_records'][0];record['amount_msat']=99000;self.store.event('financial_cost_verified',record)
  with self.assertRaisesRegex(ValueError,'conflicts'):self.collect()
 def index(self,raw):
  sha=H(raw);self.store.event('normal_money_declarations_admitted',{'financial_pins':PINS,'declarations':[{'sha256':sha,'source':'owner','destination':'B'}]});seq=self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0];return sha,{'original_bytes':raw,'declaration_index_sequence':seq}
 def injection(self):return {'schema':'track-a-supplemental-funding-declaration-v1','track':'A','classification':'EXTERNAL_INJECTION','recycled_principal_sat':0,'txid':self.txid,'vout':0,'amount_sat':900,'script_pubkey':'51','recipient_confirmation':False,'batch_fee_sat':999999}
 def test_valid_declared_injection_still_requires_independent_member_ownership(self):
  raw=json.dumps(self.injection()).encode();sha,source=self.index(raw);
  with self.assertRaisesRegex(ValueError,'ownership source join unqualified'):self.collect(funding_intents=[source],admitted_funding_sha256=[sha])
 def test_injection_absent_index_wrong_amount_and_recycling_refuse(self):
  raw=json.dumps(self.injection()).encode();source={'original_bytes':raw,'declaration_index_sequence':999}
  with self.assertRaises(ValueError):self.collect(funding_intents=[source],admitted_funding_sha256=[H(raw)])
  for field,value in [('amount_sat',899),('script_pubkey','52'),('classification','RECYCLED'),('recycled_principal_sat',1)]:
   doc=self.injection();doc[field]=value;raw=json.dumps(doc).encode();sha,source=self.index(raw)
   with self.subTest(field=field),self.assertRaises(ValueError):self.collect(funding_intents=[source],admitted_funding_sha256=[sha])
 def test_exact_declared_transfer_still_requires_independent_input_and_destination_ownership(self):
  doc={'schema':'track-a-bank-transfer-intent-v1','classification':'INTERNAL_TRANSFER','source_member':'B','txid':self.txid,'signed_raw_sha256':H(self.raw),'input_outpoints':[self.pid+':0'],'outputs':[{'vout':0,'script':'51','amount_sat':900,'destination_member':'actor-01'}],'maximum_miner_fee_sat':100,'recycled_principal_sat':0};raw=json.dumps(doc).encode();sha=H(raw);self.store.event('normal_money_declarations_admitted',{'financial_pins':PINS,'declarations':[{'sha256':sha,'source':'B','destination':'multiple-internal'}]});source={'original_bytes':raw,'declaration_index_sequence':self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]};
  with self.assertRaisesRegex(ValueError,'ownership source join unqualified'):self.collect(funding_intents=[source],admitted_funding_sha256=[sha])
 def test_board_miner_and_service_distinct_and_original_intent_bound(self):
  parent=wire([('0'*64,4294967295)],[(12100,b'\x51')]);pid=decode_transaction(parent.hex())['txid'];raw=wire([(pid,0)],[(12000,b'\x51')]);txid=decode_transaction(raw.hex())['txid'];self.chain=Chain([parent,raw])
  self.store.queue('board','actor-01','H01','board',{'amount_sat':12000},2000);self.store.db.execute("UPDATE action SET state='dispatched' WHERE id='board'");self.store.finish('board','completed',{'data':{'board':{'vtxos':['coin']},'sdk_service_fee_sat':330}})
  self.store.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',('key','actor-01','mailbox','{}'));self.store.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',('coin','key',11670,'digest','signed',json.dumps({'chain_anchor':txid+':0'})))
  self.store.event('driver_evidence',{'action_id':'board','event':'board_proposal','data':{'funding_txid':txid,'unsigned_funding_tx':raw.hex(),'planned_mining_fee_sat':100,'estimated_service_fee_sat':330}})
  v=self.collect();self.assertEqual(v['cost_records'][0]['amount_msat'],100000);self.assertEqual(v['client_service_charges'][0]['amount_msat'],330000)
  self.store.db.execute("UPDATE action SET fee_reservation_sat=1999 WHERE id='board'")
  with self.assertRaisesRegex(ValueError,'original intent'):self.collect()
if __name__=='__main__':unittest.main()

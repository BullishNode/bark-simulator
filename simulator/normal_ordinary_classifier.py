"""Bounded local decoding of captured MessagePack, not financial state synthesis.
Tag dispatch follows installed rmp0.8.15 marker.rs. Unknown tags/types refuse.
"""
import struct
class Map(list):
 def get(self,key,default=None):
  return next((v for k,v in self if k==key),default)
 def keys(self):return [k for k,v in self]
class Reader:
 def __init__(self,raw):
  if len(raw)>2*1024*1024:raise ValueError('record bound')
  self.raw=raw;self.pos=0;self.nodes=0
 def take(self,n):
  if n<0 or n>2*1024*1024 or self.pos+n>len(self.raw):raise ValueError('truncated/bounded MessagePack')
  out=self.raw[self.pos:self.pos+n];self.pos+=n;return out
 def uint(self,n):return int.from_bytes(self.take(n),'big')
 def value(self,depth=0):
  self.nodes+=1
  if depth>64 or self.nodes>100000:raise ValueError('complexity bound')
  t=self.uint(1)
  if t<0x80:return t
  if t>=0xe0:return t-256
  if t==0xc0:return None
  if t in [0xc2,0xc3]:return t==0xc3
  if t in [0xcc,0xcd,0xce,0xcf]:return self.uint(1<<(t-0xcc))
  if t in [0xd0,0xd1,0xd2,0xd3]:return int.from_bytes(self.take(1<<(t-0xd0)),'big',signed=True)
  if t in [0xca,0xcb]:return struct.unpack('>f' if t==0xca else '>d',self.take(4 if t==0xca else 8))[0]
  if 0xa0<=t<=0xbf:return self.take(t&31).decode('utf-8')
  if t in [0xd9,0xda,0xdb]:return self.take(self.uint(1<<(t-0xd9))).decode('utf-8')
  if t in [0xc4,0xc5,0xc6]:return self.take(self.uint(1<<(t-0xc4)))
  if 0x90<=t<=0x9f:n=t&15;kind='array'
  elif t in [0xdc,0xdd]:n=self.uint(2 if t==0xdc else 4);kind='array'
  elif 0x80<=t<=0x8f:n=t&15;kind='map'
  elif t in [0xde,0xdf]:n=self.uint(2 if t==0xde else 4);kind='map'
  else:raise ValueError('unsupported MessagePack tag '+hex(t))
  if n>100000:raise ValueError('container bound')
  if kind=='array':return [self.value(depth+1)for _ in range(n)]
  pairs=Map();seen=set()
  for _ in range(n):
   k=self.value(depth+1);v=self.value(depth+1);identity=repr(k)
   if identity in seen:raise ValueError('duplicate MessagePack map key')
   seen.add(identity);pairs.append((k,v))
  return pairs
 def decode(self):
  value=self.value()
  if self.pos!=len(self.raw):raise ValueError('trailing MessagePack bytes')
  return value

# Classification of fixed, already privacy-projected owning SQL. This is not a
# signature, backing, monetary, source-completeness or reservation verifier.
import hashlib,json,re
CONDITIONAL={'htlc_vtxo','htlc_settlement','lightning_invoice','lightning_htlc_subscription','lightning_payment_attempt','lightning_payment_attempt_htlc_vtxo','offboards','expiry_settlement','expiry_cancelled_participation','recovery_capital_release','lightning_node'}
POLICIES={'pubkey':(0,34),'checkpoint':(3,34),'expiry':(4,33),'server-owned':(7,1),'hark-leaf':(5,66),'hark-forfeit':(6,66),'hark-leaf-v1':(10,66),'hark-forfeit-v1':(11,66)}
VTXO_FIELDS=set('id vtxo_id signed_vtxo_hex expiry oor_spent_txid spent_in_round created_at updated_at lightning_htlc_subscription_id offboarded_in vtxo_txid exit_delta policy_type policy_hex server_pubkey amount anchor_point banned_until_height spend_state frontier_at confirmed_height onchain_spent_height onchain_spent_txid'.split())
NEW_FIELDS={
 'round':set('id seq funding_txid funding_tx_hex expiry swept_at created_at signed_tree_bytes'.split()),
 'round_participation':set('id unlock_hash unlock_preimage_present round_id created_at forfeited_at scheduled_height'.split()),
 'round_part_input':set('participation_id vtxo_id signed_forfeit_tx_hex'.split()),
 'round_part_output':set('participation_id policy_hex amount unblinded_mailbox_id'.split()),
 'vtxo_pool':set('id vtxo_id expiry_height amount created_at spent_at signed_vtxo_hex'.split()),
 'nursery_tx':set('id txid kind signed_transaction_hex confirm_target_height confirmed_at_height created_at updated_at abandoned_at'.split()),
 'sweep':set('id txid signed_transaction_hex confirmed_at abandoned_at created_at'.split()),
 'ephemeral_tweak':set('id pubkey secret_tweak_present created_at expires_at'.split())}
POOL_FIELDS=set('schema_version network genesis server_pubkey height tip_hash pool_pre_expiry_blocks max_exit_depth candidate_snapshot_complete complete missing_sources candidates'.split())
POOL_COIN_FIELDS=set('id amount_sat expiry_height exit_depth runtime_member pool_spent spend_state has_spend_reference key_present key_matches in_flux signed_vtxo'.split())
TABLES=frozenset(('vtxo', 'virtual_transaction', 'pending_board', 'fallback_record', 'key_link', 'round', 'round_participation', 'round_part_input', 'round_part_output', 'htlc_vtxo', 'htlc_settlement', 'lightning_invoice', 'lightning_htlc_subscription', 'lightning_payment_attempt', 'lightning_payment_attempt_htlc_vtxo', 'offboards', 'vtxo_pool', 'expiry_settlement', 'expiry_cancelled_participation', 'recovery_reserve', 'recovery_source_hold', 'recovery_capital_release', 'recovery_receipt', 'nursery_tx', 'sweep', 'lightning_node', 'ephemeral_tweak', 'wallet_changeset', 'fee_allowance_policy', 'fee_allowance_candidate'))
FORBIDDEN={'preimage','unlock_preimage','tweak','secret','secret_key','private_key','seed','mnemonic','keymap','key_map','xpriv','xprv'}

def need(ok,message):
 if not ok:raise ValueError(message)
def integer(v,minimum=0,maximum=2**63-1):
 need(type(v)is int and minimum<=v<=maximum,'ordinary source integer differs');return v
def hexbytes(v,limit=2097152):
 need(isinstance(v,str)and 0<len(v)<=limit*2 and len(v)%2==0 and re.fullmatch('[0-9a-f]+',v)is not None,'ordinary source bounded canonical hex required');return bytes.fromhex(v)
def txid(v):
 need(isinstance(v,str)and re.fullmatch('[0-9a-f]{64}',v)is not None,'ordinary source transaction identity malformed');return v
def point(v):
 need(isinstance(v,str)and re.fullmatch('[0-9a-f]{64}:[0-9]+',v)is not None,'ordinary source point malformed');a,b=v.split(':');integer(int(b),0,2**32-1);return a,int(b)
def public_key(v):
 raw=hexbytes(v,33);need(len(raw)==33 and raw[0]in(2,3),'ordinary public key encoding differs');return raw
def policy(v,kind=None):
 raw=hexbytes(v,66)
 if kind is None:kind='pubkey'
 need(kind in POLICIES and (raw[0],len(raw))==POLICIES[kind],'conditional or unknown policy encoding')
 if kind in {'pubkey','checkpoint','hark-leaf','hark-forfeit','hark-leaf-v1','hark-forfeit-v1'}:public_key(raw[1:34].hex())
 return raw

def privacy_fields(v):
 if isinstance(v,Map):items=v
 elif isinstance(v,dict):items=v.items()
 else:items=None
 if items is not None:
  for k,w in items:
   if isinstance(k,str):
    need(k.casefold()not in FORBIDDEN,'raw sensitive source field refused')
    if k.endswith('_present'):need(type(w)is bool,'sensitive presence projection must be boolean')
   privacy_fields(w)
 elif isinstance(v,(list,tuple)):
  for w in v:privacy_fields(w)
 elif isinstance(v,float):raise ValueError('unknown floating-point wallet source value')
 elif isinstance(v,str):need(not re.search(r'(?i)(?:xprv|tprv|-----BEGIN [A-Z ]*PRIVATE KEY)',v),'private descriptor/key material refused')

def raw_bytes(v):
 if isinstance(v,bytes):return v
 need(isinstance(v,list)and all(type(n)is int and 0<=n<=255 for n in v),'exact native serialized bytes required');return bytes(v)
def compact(n):
 integer(n,0,100000)
 return bytes([n])if n<253 else b'\xfd'+n.to_bytes(2,'little')if n<=65535 else b'\xfe'+n.to_bytes(4,'little')
def exact_map(v,fields):need(isinstance(v,Map)and set(v.keys())==set(fields),'unknown/partial native ChangeSet structure')
def wallet_transaction(v):
 exact_map(v,{'version','lock_time','input','output'});version=v.get('version');need(type(version)is int and -(2**31)<=version<2**31,'wallet transaction version differs')
 lock=integer(v.get('lock_time'),0,2**32-1);inputs=v.get('input');outputs=v.get('output');need(isinstance(inputs,list)and 0<len(inputs)<=100000 and isinstance(outputs,list)and len(outputs)<=100000,'wallet transaction dimensions')
 ins=[];witness=[]
 for row in inputs:
  exact_map(row,{'previous_output','script_sig','sequence','witness'});prev=row.get('previous_output');exact_map(prev,{'txid','vout'});ident=raw_bytes(prev.get('txid'));need(len(ident)==32,'wallet txid bytes differ');index=integer(prev.get('vout'),0,2**32-1);script=raw_bytes(row.get('script_sig'));seq=integer(row.get('sequence'),0,2**32-1);stack=row.get('witness');need(isinstance(stack,list)and len(stack)<=100000,'wallet witness dimensions');stack=[raw_bytes(x)for x in stack]
  ins.append(ident+index.to_bytes(4,'little')+compact(len(script))+script+seq.to_bytes(4,'little'));witness.append(compact(len(stack))+b''.join(compact(len(x))+x for x in stack))
 outs=[];total=0
 for row in outputs:
  exact_map(row,{'value','script_pubkey'});amount=integer(row.get('value'),0,21000000*100000000);total+=amount;script=raw_bytes(row.get('script_pubkey'));outs.append(amount.to_bytes(8,'little')+compact(len(script))+script)
 need(total<=21000000*100000000,'wallet transaction total differs');segwit=any(x!=b'\x00'for x in witness)
 raw=version.to_bytes(4,'little',signed=True)+(b'\x00\x01'if segwit else b'')+compact(len(ins))+b''.join(ins)+compact(len(outs))+b''.join(outs)+(b''.join(witness)if segwit else b'')+lock.to_bytes(4,'little');need(len(raw)<=2097152,'wallet raw transaction bound');return raw

def wallet_graphs(rows,decode):
 result={};shapes={};standard_witness={}
 for row in rows:
  need(set(row)=={'id','kind','changeset_hex','created_at'},'partial owning wallet ChangeSet row');need(row['kind']in {'rounds','watchman'},'unknown owning wallet kind')
  graph=Reader(hexbytes(row['changeset_hex'])).decode();privacy_fields(graph);exact_map(graph,{'descriptor','change_descriptor','network','local_chain','tx_graph','indexer','locked_outpoints'})
  need(graph.get('network')in (None,'signet'),'owning wallet source network differs')
  for name in ('descriptor','change_descriptor'):
   desc=graph.get(name);need(desc is None or isinstance(desc,str),'public descriptor field differs')
  exact_map(graph.get('local_chain'),{'blocks'});exact_map(graph.get('tx_graph'),{'txs','txouts','anchors','last_seen','first_seen','last_evicted'});exact_map(graph.get('indexer'),{'last_revealed','spk_cache'});exact_map(graph.get('locked_outpoints'),{'outpoints'})
  txs=graph.get('tx_graph').get('txs');need(isinstance(txs,list)and len(txs)<=10000,'wallet graph transaction bound')
  for item in txs:
   raw=wallet_transaction(item);ident=decode(raw.hex())['txid'];old=result.get(ident);need(old is None or old==raw,'conflicting wallet graph signed body');result[ident]=raw
   # Unknown graph bodies may carry only familiar wallet signature stacks.
   # This is a shape refusal fence, never signature or secret-absence proof.
   ordinary=True
   for entry in item.get('input'):
    stack=[raw_bytes(x)for x in entry.get('witness')];script=raw_bytes(entry.get('script_sig'))
    signature_stack=(not stack or len(stack)==1 and len(stack[0])in(64,65)or len(stack)==2 and 9<=len(stack[0])<=73 and stack[0][0]==0x30 and len(stack[1])==33 and stack[1][0]in(2,3))
    ordinary=ordinary and not script and signature_stack
   standard_witness[ident]=standard_witness.get(ident,True)and ordinary
  shapes[row['kind']]=shapes.get(row['kind'],0)+1
 return result,shapes,standard_witness

def unique_object(items):
 result={}
 for k,v in items:
  need(k not in result,'duplicate native candidate field');result[k]=v
 return result

def plan_ordinary(tables,decode,server_pubkey,epoch_id):
 public_key(server_pubkey);txid(epoch_id);need(isinstance(tables,dict)and set(tables)==TABLES,'exact ordinary table coverage required')
 for table in tables.values():
  need(isinstance(table,dict)and set(table)=={'count','rows'}and isinstance(table['rows'],list)and type(table['count'])is int and table['count']==len(table['rows'])<10000,'partial/malformed ordinary table rows')
  need(all(isinstance(row,dict)for row in table['rows']),'ordinary SQL object rows required')
 privacy_fields(tables)
 for name in CONDITIONAL:need(not tables[name]['rows'] and tables[name]['count']==0,'conditional source domain remains unqualified')
 for name,fields in NEW_FIELDS.items():
  for row in tables[name]['rows']:need(set(row)==fields,'ordinary source row partial or unknown columns')
 coins={}
 for row in tables['vtxo']['rows']:
  need(set(row)==VTXO_FIELDS,'ordinary VTXO source row partial');ident=row['vtxo_id'];point(ident);need(ident not in coins,'duplicate ordinary VTXO');hexbytes(row['signed_vtxo_hex']);policy(row['policy_hex'],row['policy_type']);need(row['server_pubkey']==server_pubkey,'ordinary VTXO server differs');integer(row['amount'],0);integer(row['expiry']);point(row['anchor_point']);txid(row['vtxo_txid'])
  need(row['lightning_htlc_subscription_id']is None and row['offboarded_in']is None and row['spend_state']in {'spendable','unclaimed','spent','pool','round-forfeit','unregistered'},'conditional/offboard VTXO reference or state');coins[ident]=row
 allowed={};candidates={};classes={}
 def body(raw,expected=None):
  raw=hexbytes(raw)if isinstance(raw,str)else raw;need(isinstance(raw,bytes)and 0<len(raw)<=2097152,'ordinary signed body unavailable');tx=decode(raw.hex());ident=tx['txid'];need(expected is None or ident==expected,'ordinary signed transaction identity differs');return ident,raw
 for row in tables['fee_allowance_candidate']['rows']:
  need(set(row)=={'id','epoch_id','candidate_bytes_hex','urgent','fee_sat'},'native fee candidate row partial');c=json.loads(hexbytes(row['candidate_bytes_hex']),object_pairs_hook=unique_object);need(set(c)=={'epoch_id','path','raw','input_parents','package_parents','package_input_parents'},'native signed candidate structure differs');txid(c['epoch_id']);need(c['epoch_id']==row['epoch_id']==epoch_id,'native candidate epoch differs');integer(row['fee_sat']);need(all(isinstance(c[k],list)for k in ['raw','input_parents','package_parents','package_input_parents']),'native candidate byte collections malformed');need(c['path']in {'Round','Pool','Sweep'}and row['urgent']is False,'unsupported signed candidate class');raw=raw_bytes(c['raw']);ident,raw=body(raw);wtxid=hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex();need(wtxid==row['id'],'ordinary signed candidate witness identity differs');candidates.setdefault(ident,set()).add(c['path']);allowed.setdefault(ident,set()).add(raw);classes[row['id']]=c['path']
 rounds={}
 for row in tables['round']['rows']:
  integer(row['id'],1);integer(row['seq']);integer(row['signed_tree_bytes'],1);ident,raw=body(row['funding_tx_hex'],txid(row['funding_txid']));need('Round'in candidates.get(ident,set())and raw in allowed[ident],'round funding lacks original ordinary permit');need(ident not in rounds,'duplicate round funding identity');rounds[ident]=row
 participations={};input_participations=set();output_participations=set()
 for row in tables['round_participation']['rows']:
  ident=integer(row['id'],1);need(ident not in participations,'duplicate participation');need(type(row['unlock_preimage_present'])is bool,'raw participation unlock secret refused');need(row['round_id']in rounds,'partial/unassigned ordinary round participation');txid(row['unlock_hash']);participations[ident]=row
 for row in tables['round_part_input']['rows']:
  need(row['participation_id']in participations and row['vtxo_id']in coins,'partial/foreign round input');input_participations.add(row['participation_id']);ident,raw=body(row['signed_forfeit_tx_hex']);need(row['vtxo_id']in {x['outpoint']for x in decode(raw.hex())['inputs']},'forfeit input differs from ordinary VTXO');allowed.setdefault(ident,set()).add(raw)
 for row in tables['round_part_output']['rows']:
  need(row['participation_id']in participations,'partial round output');output_participations.add(row['participation_id']);policy(row['policy_hex']);integer(row['amount'],1)
 need(input_participations==output_participations==set(participations),'partial round participation allocations')
 pools={}
 for row in tables['vtxo_pool']['rows']:
  integer(row['id'],1);integer(row['amount'],1);integer(row['expiry_height']);ident=row['vtxo_id'];need(ident in coins and ident not in pools,'pool VTXO membership differs');coin=coins[ident];policy(coin['policy_hex']);need(coin['policy_type']=='pubkey'and row['amount']==coin['amount']and row['expiry_height']==coin['expiry'],'pool ordinary metadata differs');hexbytes(row['signed_vtxo_hex'],65536);pools[ident]=row
 for row in tables['nursery_tx']['rows']:
  need(row['kind']in {'round','vtxopool'},'unsupported nursery kind');ident,raw=body(row['signed_transaction_hex'],txid(row['txid']));expected='Round'if row['kind']=='round'else'Pool';need(expected in candidates.get(ident,set())and raw in allowed[ident],'nursery body lacks exact ordinary permit')
 receipts={r['id']:r for r in tables['recovery_receipt']['rows']}
 for row in tables['sweep']['rows']:
  ident,raw=body(row['signed_transaction_hex'],txid(row['txid']));receipt=receipts.get(ident);need(('Sweep'in candidates.get(ident,set())and raw in allowed[ident])or(receipt is not None and receipt['proof_state']=='physical_bound'and receipt['transaction_bytes_hex']==raw.hex()),'unclassified Sweep original')
 tweaks={}
 for row in tables['ephemeral_tweak']['rows']:
  public_key(row['pubkey']);need(type(row['secret_tweak_present'])is bool,'raw key tweak refused');need(row['pubkey']not in tweaks,'duplicate ephemeral public key');tweaks[row['pubkey']]=row['secret_tweak_present']
 graph,shapes,standard_witness=wallet_graphs(tables['wallet_changeset']['rows'],decode)
 return {'coins':coins,'pools':pools,'allowed_signed':allowed,'classes':classes,'wallet_graph':graph,'wallet_changesets':shapes,'standard_wallet_witness':standard_witness,'tweaks':tweaks,'counts':{k:v['count']for k,v in tables.items()}}

def finish_ordinary(plan,pool,core_transactions,*,network,genesis,server_pubkey,height,tip_hash,sql_sha256,pool_sha256):
 need(set(pool)==POOL_FIELDS and type(pool['schema_version'])is int and pool['schema_version']==1 and pool['complete']is False and pool['candidate_snapshot_complete']is True,'native pool source flags/shape differ')
 integer(pool['height']);need((pool['network'],pool['genesis'],pool['server_pubkey'],pool['height'],pool['tip_hash'])==(network,genesis,server_pubkey,height,tip_hash),'native pool source identity/tip differs');integer(pool['max_exit_depth'],0,65535);integer(pool['pool_pre_expiry_blocks'],0,65535)
 need(pool['missing_sources']==['independent signed-path and raw Core backing qualification'],'native pool source proof gap differs');items=pool['candidates'];need(isinstance(items,list)and len(items)<=256,'native private pool bound');seen=set();ancestry=0
 for item in items:
  need(set(item)==POOL_COIN_FIELDS,'native pool row partial or unknown');ident=item['id'];need(ident in plan['pools']and ident not in seen,'native pool source/SQL membership differs');seen.add(ident);row=plan['pools'][ident];coin=plan['coins'][ident]
  need(item['signed_vtxo']==row['signed_vtxo_hex']and(item['amount_sat'],item['expiry_height'])==(row['amount'],row['expiry_height']),'native pool original Full/metadata differs');ancestry+=len(hexbytes(item['signed_vtxo'],65536));need(ancestry<=524288,'native pool ancestry bound');integer(item['exit_depth'],0,65535);integer(item['amount_sat'],1);integer(item['expiry_height'])
  for name in ['runtime_member','pool_spent','has_spend_reference','key_present','key_matches','in_flux']:need(type(item[name])is bool,'native pool flags not literal booleans')
  need(item['runtime_member']and item['pool_spent']==(row['spent_at']is not None)and item['spend_state']==coin['spend_state'],'native pool literal state differs');refs=any(coin[k]is not None for k in ['oor_spent_txid','spent_in_round','offboarded_in','onchain_spent_txid','confirmed_height','onchain_spent_height','lightning_htlc_subscription_id']);need(item['has_spend_reference']==refs,'native pool source references differ');need(not item['key_matches']or item['key_present'],'native key flags inconsistent');need(item['key_present']==plan['tweaks'].get(coin['policy_hex'][2:],False),'native key availability/SQL cut differs')
 graph_hashes={}
 for ident,raw in plan['wallet_graph'].items():
  candidate=raw in plan['allowed_signed'].get(ident,set());actual=core_transactions.get(ident)
  confirmed=isinstance(actual,dict)and type(actual.get('confirmations'))is int and actual['confirmations']>0 and actual.get('hex')==raw.hex()
  need(candidate or confirmed,'wallet graph body lacks ordinary original or confirmed Core provenance');need(candidate or plan['standard_wallet_witness'].get(ident)is True,'unknown wallet graph witness class refused');graph_hashes[ident]=hashlib.sha256(raw).hexdigest()
 return {'schema_version':1,'scope':'private ordinary-source classification only; no ancestry signature, backing, money, eligibility, readiness or reservation verdict','table_counts':plan['counts'],'native_candidate_classes':plan['classes'],'pool_candidate_ids':sorted(seen),'wallet_changeset_counts':plan['wallet_changesets'],'wallet_graph_original_sha256':graph_hashes,'original_sha256':{'native_sql':sql_sha256,'owning_pool_inventory':pool_sha256},'privacy_projection':'Named SQL unlock preimage/tweak fields omitted by pinned SQL; bounded original Full/witnesses remain private. This is not arbitrary encoded-secret absence proof.'}

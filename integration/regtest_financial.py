"""Read-only REGTEST fixture facts and immutable prospective declarations.

This first contribution does not issue financial/bootstrap readiness. Native pool,
liability and architecture-specific owner proof producers remain explicit gaps.
"""
import hashlib,json,os,re,selectors,signal,stat,subprocess,sys,time
from pathlib import Path
from urllib.parse import urlsplit
if __package__ in (None,''):
 sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from simulator.chain import ChainReader
from simulator.model import btc_to_sat,canonical,public_payload

REGTEST_GENESIS='0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206'
HEX64=re.compile('[0-9a-f]{64}')
MISSING=('native exhaustive pool state','native exhaustive liabilities/current ownership',
         'architecture-specific signed actor ownership','independent fresh actor zero-assets proof',
         'actual signed six-path fee caps/cumulative native ledger','treasury/envelope admission','immutable original native/chain trace capture','protected native/SDK release and process provenance')

def _pairs(items):
 result={}
 for k,v in items:
  if k in result:raise ValueError('duplicate fixture source key')
  result[k]=v
 return result

def _read(path,maximum):
 path=Path(path)
 for item in (path,*path.parents):
  if stat.S_ISLNK(item.lstat().st_mode):raise ValueError('fixture symlink refused')
 with path.open('rb') as f:
  before=os.fstat(f.fileno());raw=f.read(maximum+1);after=os.fstat(f.fileno())
 if not stat.S_ISREG(before.st_mode) or len(raw)>maximum:raise ValueError('bounded regular fixture source required')
 if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):raise ValueError('fixture source changed')
 return raw

def _integer(value):
 if type(value)is not int or not 0<=value<=2_100_000_000_000_000:raise ValueError('exact finite satoshi amount required')
 return value

def validate_declaration(value):
 fields={'schema','network','genesis','architecture_profile','sdk_commit','native_commit','actors',
         'operator_opening_sat','client_grants_sat','board_amount_sat','action_fee_cap_sat',
         'lifetime_blocks','board_confirmations','pool_enabled','lightning_enabled'}
 if not isinstance(value,dict) or set(value)!=fields:raise ValueError('complete bounded fixture declaration required')
 if value['schema']!='regtest-fixture-financial-v1' or value['network']!='regtest' or value['genesis']!=REGTEST_GENESIS:raise ValueError('actual REGTEST declaration required')
 if value['architecture_profile'] not in {'two_step_per_key','direct_xpub','direct_per_key'}:raise ValueError('explicit fixture architecture required')
 for key in ('sdk_commit','native_commit'):
  if not isinstance(value[key],str) or re.fullmatch('[0-9a-f]{40}',value[key])is None:raise ValueError('exact actual component commit required')
 actors=value['actors'];grants=value['client_grants_sat']
 if not isinstance(actors,list) or not 1<=len(actors)<=12 or len(set(actors))!=len(actors) or any(not isinstance(a,str) or re.fullmatch('actor-[0-9]{2}',a)is None for a in actors):raise ValueError('bounded unique actor IDs required')
 if not isinstance(grants,dict) or set(grants)!=set(actors):raise ValueError('every grant must have one declared owner')
 for amount in grants.values():_integer(amount)
 _integer(sum(grants.values())+_integer(value['operator_opening_sat']))
 for key in ('operator_opening_sat','board_amount_sat','action_fee_cap_sat'):_integer(value[key])
 if value['board_amount_sat']==0 or value['action_fee_cap_sat']==0:raise ValueError('positive finite Board/cap required')
 if any(value['board_amount_sat']+value['action_fee_cap_sat']>g for g in grants.values()):raise ValueError('grant cannot fund declared Board and cap')
 if type(value['lifetime_blocks'])is not int or not 1<=value['lifetime_blocks']<=65535:raise ValueError('finite lifetime required')
 if type(value['board_confirmations'])is not int or not 1<=value['board_confirmations']<=100:raise ValueError('finite confirmations required')
 if type(value['pool_enabled'])is not bool or type(value['lightning_enabled'])is not bool:raise ValueError('actual route declarations required')
 public_payload(value)
 return value

def freeze_declaration(path,value):
 """Prospective bytes only; never grants a native action or financial admission."""
 validate_declaration(value);path=Path(path);parent=path.parent
 for item in (parent,*parent.parents):
  if stat.S_ISLNK(item.lstat().st_mode):raise ValueError('fixture declaration symlink refused')
 info=parent.stat()
 if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('owned private declaration directory required')
 raw=(canonical(value)+'\n').encode();fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
  parent_fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
  try:os.fsync(parent_fd)
  finally:os.close(parent_fd)
 except BaseException:raise # A failed partial file remains; never overwrite/retry it.
 return {'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'admitted':False}

def fresh_directory_fact(wallet_root,actors):
 """Filesystem freshness is deliberately not an on-chain zero-asset proof."""
 root=Path(wallet_root)
 for p in (root,*root.parents):
  if stat.S_ISLNK(p.lstat().st_mode):raise ValueError('fresh fixture root symlink refused')
 st=root.stat()
 if st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o700 or not stat.S_ISDIR(st.st_mode)or any(root.iterdir()):raise ValueError('empty owned private wallet root required')
 if not actors or len(set(actors))!=len(actors)or len(actors)>12:raise ValueError('bounded fresh actors required')
 return {'device':st.st_dev,'inode':st.st_ino,'actors':actors,'actor_directories_absent':True,
         'zero_assets_verified':False,'financial_readiness':False}

def _native_inventory(binary,binary_sha256,address,timeout):
 if not isinstance(address,str)or re.fullmatch(r'http://127\.0\.0\.1:[1-9][0-9]{0,4}',address)is None:raise ValueError('fixed loopback native admin endpoint required')
 if not HEX64.fullmatch(binary_sha256)or hashlib.sha256(_read(binary,128*1024*1024)).hexdigest()!=binary_sha256:raise ValueError('native fixture executable differs')
 # No shell or caller-supplied verb, SQL, operation, executable arguments or callback.
 if not isinstance(timeout,(int,float))or isinstance(timeout,bool)or not 0<timeout<=12:raise ValueError('bounded native inventory deadline required')
 deadline=time.monotonic()+timeout;maximum=2*1024*1024;raw=bytearray()
 # Inherit the fixed worker's process group, so its outer deadline also kills this child.
 proc=subprocess.Popen([str(binary),'rpc','--addr',address,'wallet-inventory'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
 try:
  with selectors.DefaultSelector()as ready:
   ready.register(proc.stdout,selectors.EVENT_READ)
   while True:
    remaining=deadline-time.monotonic()
    if remaining<=0:raise TimeoutError('native owning inventory deadline exceeded')
    if not ready.select(remaining):raise TimeoutError('native owning inventory deadline exceeded')
    chunk=os.read(proc.stdout.fileno(),min(65536,maximum+1-len(raw)))
    if not chunk:break
    raw.extend(chunk)
    if len(raw)>maximum:raise ValueError('native owning inventory byte bound exceeded')
  remaining=deadline-time.monotonic()
  if remaining<=0:raise TimeoutError('native owning inventory deadline exceeded')
  proc.wait(timeout=remaining)
  if proc.returncode!=0:raise ValueError('native owning inventory process failed')
  if time.monotonic()>deadline:raise TimeoutError('native owning inventory late result refused')
 finally:
  if proc.poll()is None:proc.kill()
  proc.wait(timeout=3)
  proc.stdout.close()
 value=json.loads(raw,object_pairs_hook=_pairs)
 return value,{'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'exit':proc.returncode}

OWNER_MISSING={
 'rounds':'watchmand owns its wallet; inventory unavailable from captaind',
 'watchman':'captaind owns its rounds wallet; collect its separate source without assuming global atomicity',
}
OWNER_FIELDS={'wallet','network','public_descriptor','tip_height','tip_hash','min_trusted_confirmations',
 'complete','reserved_outpoints','last_revealed_index','utxos','pending_transaction_scope',
 'pending_transactions','pending_parents','unavailable_parent_txids'}

def _owned_inventory_frame(frame,role):
 """Each daemon speaks only for its OWN wallet, never global atomic completeness."""
 if role not in OWNER_MISSING:raise ValueError('unknown native owning role')
 other='watchman'if role=='rounds'else'rounds'
 if (not isinstance(frame,dict)or set(frame)!={'rounds','watchman','complete','missing_sources'}
     or frame['complete']is not False or frame[other]is not None
     or frame['missing_sources']!=[OWNER_MISSING[role]]):
  raise ValueError('exact owning-only native response with truthful missing other owner required')
 owner=frame[role]
 if (not isinstance(owner,dict)or set(owner)!=OWNER_FIELDS or owner['complete']is not True
     or owner['wallet']!=role or owner['network']!='regtest'
     or owner['pending_transaction_scope']!='canonical_wallet_graph_only'):
  raise ValueError('complete actual owning-role inventory required')
 return owner

def _wallet_facts(chain,value,role,tip,deadline=None):
 if value.get('complete')is not True or value.get('network')!='regtest' or value.get('wallet')!=role:raise ValueError('complete actual owning wallet source required')
 if value.get('tip_height')!=tip['blocks']or value.get('tip_hash')!=tip['bestblockhash']:raise ValueError('owning wallet source tip differs')
 rows=value.get('utxos');reserved=value.get('reserved_outpoints')
 if not isinstance(rows,list)or len(rows)>2000 or not isinstance(reserved,list)or len(reserved)>2000:raise ValueError('complete native wallet row bound exceeded')
 if any(value.get(field)!=[]for field in ('pending_transactions','pending_parents','unavailable_parent_txids')):raise ValueError('quiescent complete native wallet source required')
 seen=set();total=eligible=0
 for row in rows:
  point=row['outpoint']
  if not isinstance(point,str)or re.fullmatch('[0-9a-f]{64}:[0-9]{1,10}',point)is None or point in seen:raise ValueError('unique native outpoints required')
  seen.add(point);txid,vout=point.split(':')
  remaining=12 if deadline is None else min(12,deadline-time.monotonic())
  if remaining<=0:raise TimeoutError('fixture row deadline exceeded')
  actual=chain.call('gettxout',txid,int(vout),True,timeout=remaining)
  if actual is None or actual.get('confirmations',0)<1:raise ValueError('actual confirmed unspent owning output required')
  amount=_integer(row['value_sat'])
  if btc_to_sat(actual['value'])!=amount or actual['scriptPubKey']['hex']!=row['script_pubkey']:raise ValueError('Core/native value or script mismatch')
  total+=amount
  if row.get('confirmed_fee_eligible')is True:
   if not(row.get('trusted')is True and row.get('mature')is True and row.get('reserved')is False and point not in reserved):raise ValueError('eligible source contradicts actual reservations')
   eligible+=amount
 return {'wallet':role,'confirmed_physical_sat':total,'confirmed_eligible_unreserved_sat':eligible,
         'reserved_outpoints':reserved,'source_rows':len(rows),'tip_height':tip['blocks'],'tip_hash':tip['bestblockhash']}

def _collect_worker(core_url,cookie,native_binary,native_sha256,rounds_admin,watch_admin):
 """Actual fixed RPC producer. Returns partial factual evidence, NEVER readiness."""
 parsed=urlsplit(core_url)
 if (parsed.scheme!='http' or parsed.hostname!='127.0.0.1' or parsed.username or parsed.password
     or not parsed.port or not 1<=parsed.port<=65535 or parsed.query or parsed.fragment
     or (parsed.path and re.fullmatch(r'/wallet/[A-Za-z0-9_.%~-]{1,128}',parsed.path)is None)):
  raise ValueError('exact local fixture Core endpoint required')
 if rounds_admin==watch_admin:raise ValueError('distinct explicit owning daemon endpoints required')
 began=time.monotonic();chain=ChainReader(core_url,cookie,REGTEST_GENESIS,consumer='regtest-fixture-financial')
 before=chain.identity()
 if before.get('chain')!='regtest'or before.get('initialblockdownload')is not False:raise ValueError('verified non-IBD REGTEST required')
 facts={};raw_sources={}
 for role,address in [('rounds',rounds_admin),('watchman',watch_admin)]:
  remaining=25-(time.monotonic()-began)
  if remaining<=0:raise TimeoutError('fixture source total deadline exceeded')
  frame,source=_native_inventory(native_binary,native_sha256,address,min(12,remaining))
  owner=_owned_inventory_frame(frame,role)
  facts[role]=_wallet_facts(chain,owner,role,before,began+25)
  raw_sources[role]={**source,'requested_admin_address':address,'owning_role':role,
   'owning_inventory_complete':owner['complete'],'response_complete':frame['complete'],
   'other_owner_absent':True,'missing_sources':frame['missing_sources']}
 after=chain.identity()
 if before['blocks']!=after['blocks']or before['bestblockhash']!=after['bestblockhash']or after.get('initialblockdownload')is not False:raise ValueError('fixture source tip changed')
 if time.monotonic()-began>25:raise TimeoutError('fixture source late result refused')
 return {'schema':'regtest-fixture-financial-facts-v1','network':'regtest','genesis':REGTEST_GENESIS,
  'height':after['blocks'],'tip_hash':after['bestblockhash'],'stable_tip':True,'wallets':facts,
  'native_binary_sha256':native_sha256,'native_source_digests':raw_sources,'atomic':False,'complete':False,'qualified':False,'financial_readiness':False,
  'missing_sources':list(MISSING),'scope':'actual Core plus owning native R/F; does not authorize actors or money'}


def collect(core_url,cookie,native_binary,native_sha256,rounds_admin,watch_admin):
 """A real process deadline covers RPC reads and all native child processes."""
 request=[str(v) for v in (core_url,cookie,native_binary,native_sha256,rounds_admin,watch_admin)]
 proc=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'_worker'],
  stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True)
 try:
  raw,_=proc.communicate(json.dumps(request).encode(),timeout=25)
 except BaseException:
  try:os.killpg(proc.pid,signal.SIGKILL)
  except ProcessLookupError:pass
  proc.communicate(timeout=3)
  raise
 if proc.returncode!=0:raise ValueError('fixed REGTEST financial source worker failed')
 if len(raw)>1024*1024:raise ValueError('financial source aggregate byte bound exceeded')
 result=json.loads(raw,object_pairs_hook=_pairs)
 if result.get('complete')is not False or result.get('qualified')is not False:raise ValueError('partial source cannot issue qualification')
 return result

if __name__=='__main__':
 if sys.argv[1:]!=['_worker']:raise SystemExit('fixed internal fixture worker only')
 request=json.loads(sys.stdin.buffer.read(64*1024+1),object_pairs_hook=_pairs)
 if not isinstance(request,list)or len(request)!=6 or any(not isinstance(v,str)or len(v)>4096 for v in request):raise SystemExit('bounded fixed fixture inputs required')
 value=_collect_worker(*request)
 print(json.dumps(value,separators=(',',':')))

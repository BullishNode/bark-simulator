"""C two-host CLN auxiliary using existing lifecycle, topology and money joins.

Only trusted, explicitly admitted complete readonly argv are accepted. The
operator and fixture node may be on distinct hosts. No Docker/default paths,
payments, SDK open, daemon setup, global completeness or ready booleans.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
import time
from . import c_lightning_source as native
from .architecture import DIRECT_PER_KEY,profile
from .final_campaign import _source_event
from .model import SIGNET_GENESIS,canonical,integer,public_payload
from .normal_source_deadline import timeout as source_timeout,check as deadline_check
from .process import text_command,decode_object
from .two_step_capture import cln_projection
from .two_step_normal import module_hash

ALIASES=('operator','fixture_peer')
KIND='c_owned_cln_auxiliary_source'
RAW_KIND='c_owned_cln.original'


def digest(raw):return hashlib.sha256(raw).hexdigest()


class FixedClnReads:
    """Explicit actual two-host commands; methods have no arguments/shell input."""
    def __init__(self,commands):
        if not isinstance(commands,dict)or set(commands)!=set(ALIASES):raise ValueError('two fixed owned CLN sources required')
        self.commands={}
        for alias,methods in commands.items():
            if not isinstance(methods,dict)or set(methods)!=set(native.METHODS):raise ValueError('exact three fixed readonly methods required')
            self.commands[alias]={}
            for method,argv in methods.items():
                if(not isinstance(argv,(list,tuple))or not 2<=len(argv)<=40
                        or any(not isinstance(v,str)or not v or '\0'in v for v in argv)
                        or not Path(argv[0]).is_absolute()or argv[-1]!=method):
                    raise ValueError('literal qualified CLN command required')
                self.commands[alias][method]=tuple(argv)
        if self.commands['operator']==self.commands['fixture_peer']:raise ValueError('distinct real owning node command scopes required')
    def hashes(self):return {a:{m:digest(canonical(list(v)).encode())for m,v in ms.items()}for a,ms in self.commands.items()}
    async def read(self,alias,method):
        if alias not in ALIASES or method not in native.METHODS:raise ValueError('fixed CLN source method required')
        originals=[]
        output=await text_command(list(self.commands[alias][method]),timeout=source_timeout(8),on_stdout_raw=originals.append)
        if(len(originals)!=1 or originals[0]['truncated']or type(originals[0]['exit_code'])is not int
                or originals[0]['exit_code']!=0 or not isinstance(originals[0]['raw'],bytes)
                or not 0<len(originals[0]['raw'])<=native.MAX_BYTES or output.encode()!=originals[0]['raw']):
            raise ValueError('actual complete bounded CLN stdout required')
        return originals[0]['raw']


def replay_original(store,reference,*,alias,method,observation,command_sha256):
    from .trace import partition_paths,readonly,record_hash,SCHEMA_VERSION
    if not isinstance(reference,dict)or set(reference)!={'partition','seq','hash'}:raise ValueError('actual CLN source trace reference required')
    paths=[p for p in partition_paths(store.trace.root)if p.name==reference['partition']]
    if len(paths)!=1:raise ValueError('CLN source trace partition missing')
    db=readonly(paths[0])
    try:
        size=db.execute('SELECT length(raw)FROM trace WHERE seq=?',(reference['seq'],)).fetchone()
        if size is None or type(size[0])is not int or not 0<size[0]<=native.MAX_BYTES:raise ValueError('bounded CLN original missing')
        row=db.execute('SELECT * FROM trace WHERE seq=?',(reference['seq'],)).fetchone()
    finally:db.close()
    context={'alias':alias,'method':method,'source_observation':observation,'command_sha256':command_sha256}
    if(row['schema_version']!=SCHEMA_VERSION or row['kind']!=RAW_KIND or row['hash']!=reference['hash']
            or record_hash(row)!=reference['hash']or json.loads(row['payload'])!=context or not isinstance(row['raw'],bytes)):
        raise ValueError('actual CLN trace scope/command/hash differs')
    return decode_object(row['raw'].decode()),row['raw']


def _normalized(raw):
    """Exact CLN amount notation normalization; literal originals are retained."""
    value=copy.deepcopy(raw)
    fields={'outputs':('amount_msat',),'channels':('amount_msat','our_amount_msat')}
    for group,names in fields.items():
        for row in value['listfunds'][group]:
            for name in names:
                if name in row:row[name]=native._msat(row[name])
    for row in value['listpeerchannels']['channels']:
        for name in ('total_msat','to_us_msat','spendable_msat','receivable_msat'):
            if name in row:row[name]=native._msat(row[name])
    return value


async def collect(store,config,chain,observation,*,boundary,reader,member_ids,
                  context_sha256,qualification_sequence,runtime_source_sequence,current_startup_path):
    """Return two-node source component only, never normal financial readiness."""
    from .c_normal_source import _context
    from .treasury import _members,_capture_assets
    from .runtime_startup import _read
    from .target_epochs import verified_runtime_source
    from .c_runtime_profile import validate as validate_profile
    _context(store,observation);original=canonical(observation);deadline_check()
    if(not isinstance(reader,FixedClnReads)or not isinstance(member_ids,dict)or set(member_ids)!=set(ALIASES)
            or len(set(member_ids.values()))!=2 or getattr(store,'trace',None)is None
            or boundary['pins']!=observation['financial_pins']or boundary['id']!=observation['boundary_id']):
        raise ValueError('explicit traced C CLN boundary/reader required')
    members=_members(boundary);selected={};ids={}
    for alias,name in member_ids.items():
        member=members.get(name)
        if member is None or member['kind']!='lightning_peer'or member['role']!=('operator'if alias=='operator'else'fixture_peer'):
            raise ValueError('actual distinct declared CLN membership required')
        event,proof=_source_event(store,member['verification_sequence'])
        if(event['kind']!='treasury_member_verified'or proof.get('member')!={k:v for k,v in member.items()if k!='verification_sequence'}
                or proof.get('financial_pins')!=boundary['pins']or proof.get('genesis')!=SIGNET_GENESIS):
            raise ValueError('independent original CLN member verification differs')
        selected[alias]=member;ids[alias]=member['identity']
    native._ids(ids);native._hex(context_sha256)
    _,runtime_sha=_read(current_startup_path)
    verified_runtime_source(store,runtime_source_sequence,origin_pins=boundary['pins'],current_source_sha256=runtime_sha)
    runtime_event,runtime=_source_event(store,runtime_source_sequence)
    operating=validate_profile(runtime.get('operating_profile'))
    if(runtime_event['kind']!='owned_runtime_configuration_verified'
            or runtime.get('product_commit')!=boundary['pins']['product_commit']or runtime.get('schema_sha256')!=boundary['pins']['schema_sha256']
            or not observation['started_at']<=runtime.get('observed_at',-1)<=time.time()
            or operating['node_ids']!=ids or operating['lightning_context_sha256']!=context_sha256):
        raise ValueError('actual loaded C CLN runtime/source context differs')
    event,admitted=_source_event(store,qualification_sequence)
    expected={'architecture_profile':DIRECT_PER_KEY,'financial_pins':boundary['pins'],'node_ids':ids,
      'context_sha256':context_sha256,'commands_sha256':reader.hashes(),'startup_source_sha256':runtime['startup_source_sha256'],
      'component_sha256':{'adapter':digest(Path(__file__).read_bytes()),'native':module_hash(native.verify_source),
        'shared_cln_projection':module_hash(cln_projection),'native_projection_helpers':module_hash(native.peer_channel),
        'treasury':module_hash(_capture_assets)}}
    if event['kind']!='c_native_cln_source_qualified'or admitted!=expected:raise ValueError('actual C twohost CLN source qualification missing')
    if store.db.execute("SELECT 1 FROM event WHERE kind=? AND json_extract(payload,'$.source_observation.id')=?",(KIND,observation['id'])).fetchone():
        raise ValueError('CLN observation already collected')
    before_hashes=reader.hashes();raws={};references={}
    async def actual_rpc(alias,method):
        raw=await reader.read(alias,method);value=decode_object(raw.decode());public_payload(value)
        raws[(alias,method)]=raw;return value
    async def independent_tip():
        value=chain.identity()
        return {'genesis':chain.call('getblockhash',0),'height':value['blocks'],'tip_hash':value['bestblockhash'],'initialblockdownload':value['initialblockdownload']}
    source=await native.OwnedClnReader(actual_rpc,independent_tip,context_sha256=context_sha256,node_ids=ids).collect()
    projected=native.verify_source(source,context_sha256=context_sha256,node_ids=ids,height=observation['height'],tip_hash=observation['tip_hash'])
    if source['started_at']<observation['started_at']or source['completed_at']>time.time():raise ValueError('current invocation did not produce CLN source')
    nodes=[];projections={}
    for alias in ALIASES:
        for method in native.METHODS:
            context={'alias':alias,'method':method,'source_observation':observation,'command_sha256':before_hashes[alias][method]}
            ref=store.trace_capture(RAW_KIND,context,raw=raws[(alias,method)]);references[alias+':'+method]=ref
            value,raw=replay_original(store,ref,alias=alias,method=method,observation=observation,command_sha256=before_hashes[alias][method])
            if value!=source['nodes'][alias][method]or raw!=raws[(alias,method)]:raise ValueError('actual CLN original replay differs')
        raw=source['nodes'][alias];selected_raw=_normalized(raw)
        literal,cash,channels=cln_projection(selected[alias],selected_raw,height=observation['height'])
        original_sha=digest(canonical({m:digest(raws[(alias,m)])for m in native.METHODS}).encode())
        projections[alias]=(literal,cash,channels,original_sha)
        nodes.append({'id':member_ids[alias],'source_sha256':original_sha,**literal})
    from .financial_components import inspect
    component=inspect([],nodes,[],chain,height=observation['height'],tip_hash=observation['tip_hash'],
      gaps=['two CLN nodes only; native current liabilities, other members, pool/router policy and normal readiness remain separate'])
    if reader.hashes()!=before_hashes or canonical(observation)!=original or _read(current_startup_path)[1]!=runtime_sha:
        raise ValueError('CLN command/source context changed during collection')
    verified_runtime_source(store,runtime_source_sequence,origin_pins=boundary['pins'],current_source_sha256=runtime_sha);deadline_check()
    inventories={};sources={}
    with store.transaction():
        for alias in ALIASES:
            member=selected[alias];name=member['id'];literal,cash,channels,original_sha=projections[alias]
            ctx={'member_id':name,'identity':member['identity'],'financial_pins':boundary['pins'],'height':observation['height'],
              'tip_hash':observation['tip_hash'],'observed_at':time.time()}
            store._event('treasury_cln_wallet_source',{**ctx,'genesis':SIGNET_GENESIS,'member_verification_sequence':member['verification_sequence'],
              'getinfo':literal['getinfo'],'listfunds':literal['listfunds']})
            cash_sequence=store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
            cash=[{**r,'source_sequence':cash_sequence}for r in cash]
            frame={**ctx,**literal,'reported_utxos':cash,'reported_channels':channels,'pending_transactions':[],
              'reserved_outpoints':[],'discovery_gaps':[],'source_kind':'actual_cln_public_money_fields',
              'original_source_sha256':original_sha,'original_traces':{m:references[alias+':'+m]for m in native.METHODS}}
            public_payload(frame);store._event('treasury_native_inventory_source',frame);sources[name]=store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
            store._event('treasury_inventory',{**ctx,'complete':True,'utxos':cash,'channels':channels,
              'scope':'actual checked one CLN member only; not treasury or readiness'})
            inventories[name]=store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
        subset={**boundary,'members':list(selected.values())};assets=_capture_assets(store,subset,inventories,chain)
        from .topology import ready
        topology_snapshot={'height':observation['height'],'capabilities':{'lightning_configured':True},'lightning':projected}
        result={'source_observation':copy.deepcopy(observation),'financial_pins':boundary['pins'],'boundary_id':boundary['id'],
          'height':observation['height'],'tip_hash':observation['tip_hash'],'observed_at':time.time(),
          'runtime_source_sequence':runtime_source_sequence,'qualification_sequence':qualification_sequence,
          'source':source,'original_traces':references,'inventory_sequences':inventories,'inventory_source_sequences':sources,
          'component':component,'actual_cln_assets':assets,'topology':topology_snapshot,'channel_route_observed':ready(topology_snapshot),
          'complete':False,'qualified':False,'financial_readiness':False,
          'scope':'twohost native CLN component only; no pending HTLC resolution, router fee budget or other-source completeness'}
        public_payload(result);store._event(KIND,result);result['source_sequence']=store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
    return result

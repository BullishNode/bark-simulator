"""Versioned C joint-fee originals in the existing public/body/fee RR cut.

No policy accounting, signatures, publication or monetary admission. Original
BYTEA witnesses remain private0600/encrypted wire. Native validators must later
reconcile them; a missing source never grants zero or old121 compatibility.
"""
import io
import hashlib
import os
from pathlib import Path
import re
import stat
import tarfile
import time

from . import c_private_normal_cut as normal
from . import c_private_fee_cut as fee
from . import c_private_native_body_cut as body

ABI_COMMIT='d6e17330454168e1628c7619f27a9d96004c57fe'
ABI_SHA256='fe08a60e263c3c411f1fbbc622dfad00184fcf3da8b45f0794174176859cb456'
ROUND_ABI_COMMIT='6d0a44b2b4b5921cfc4f9598370c143b3016885a'
ROUND_ABI_SHA256='5c4728af2a4b167914d359684673e516282795ec1f6d8b2b895d7eb9ba8e41b0'
VERSION=4
KIND='c-native-joint-normal-private-cut'
SCOPE='One actual RR public19/body/carrier/joint/urgent/Round-rights originals; no current ownership, native validation, relay or readiness authority'
MAX_BYTES=16*1024*1024
MAX_FILES=4096
MAX_FILE_BYTES=4*1024*1024
MAX_WITNESS_BYTES=64*1024*1024
# Exact closed source d6 migrations78..81. No request-selected SQL/columns.
PROJECTIONS={
 'native_fee_publication':('wtxid','wtxid,txid,purpose,record_hash,policy_hash,opening_hash,encode(signed_tx,\'hex\') AS signed_tx_hex,created_at::text,published_at::text',
    ('wtxid','txid','purpose','record_hash','policy_hash','opening_hash','signed_tx','created_at','published_at')),
 'native_fee_input':('outpoint','outpoint,wtxid',('outpoint','wtxid')),
 'native_fee_opening':('id','id,opening_hash,encode(policy_bytes,\'hex\') AS policy_bytes_hex,encode(opening_bytes,\'hex\') AS opening_bytes_hex,history_identity,created_at::text',
    ('id','opening_hash','policy_bytes','opening_bytes','history_identity','created_at')),
 'native_urgent_attempt':('attempt_index','attempt_index,candidate_hash,publication_txid,purpose,policy_hash,opening_hash,encode(reservation_entry,\'hex\') AS reservation_entry_hex,encode(candidate,\'hex\') AS candidate_hex,encode(signed_entry,\'hex\') AS signed_entry_hex,encode(signed_record,\'hex\') AS signed_record_hex,created_at::text',
    ('attempt_index','candidate_hash','publication_txid','purpose','policy_hash','opening_hash','reservation_entry','candidate','signed_entry','signed_record','created_at')),
 'native_urgent_input':('outpoint','outpoint,attempt_index',('outpoint','attempt_index')),
 'nursery_tx':('txid','txid,kind::text,encode(tx,\'hex\') AS tx_hex,confirm_target_height,confirmed_at_height,abandoned_at::text,created_at::text,updated_at::text',
    ('txid','kind','tx','confirm_target_height','confirmed_at_height','abandoned_at','created_at','updated_at')),
 'wallet_changeset':('id','id,kind::text,encode(content,\'hex\') AS content_hex',('id','kind','content')),
 'expiry_carrier':('txid','txid,encode(signed_tx,\'hex\') AS signed_tx_hex,backing_ids,fee_inputs,miner_fee_sat,funding_subsidy_sat,confirmed_height,confirmed_block',
    ('txid','signed_tx','backing_ids','fee_inputs','miner_fee_sat','funding_subsidy_sat','confirmed_height','confirmed_block'))}
# Exact Round-rights ABI: the other three dependencies are already in the
# SAME body.vtxo / native_fee_publication / native_fee_opening original stream.
PROJECTIONS.update({
 'rounds':('id',"id,seq,expiry,funding_txid,encode(funding_tx,'hex') AS funding_tx_hex,encode(signed_tree,'hex') AS signed_tree_hex",('id','seq','expiry','funding_txid','funding_tx','signed_tree')),
 'round_participation':('id','id,round_id,unlock_hash',('id','round_id','unlock_hash')),
 'round_part_input':('participation_id,vtxo_id','participation_id,vtxo_id',('participation_id','vtxo_id')),
 'round_part_output':('participation_id,policy_hex,amount,unblinded_mailbox_id',"participation_id,encode(policy,'hex') AS policy_hex,amount,unblinded_mailbox_id",('participation_id','policy','amount','unblinded_mailbox_id')),
 'virtual_transaction':('txid',"txid,encode(signed_tx,'hex') AS signed_tx_hex",('txid','signed_tx'))})
TABLES={'rounds':'round'}
ADDITIONAL_SELECT_COLUMNS={**normal.ADDITIONAL_SELECT_COLUMNS,
    **{'public.'+TABLES.get(table,table):list(spec[2]) for table,spec in PROJECTIONS.items()}}
HEX_FIELDS={'rounds':{'funding_tx','signed_tree'},'round_part_output':{'policy'},'virtual_transaction':{'signed_tx'},
    'native_fee_publication':{'signed_tx'},'native_fee_opening':{'policy_bytes','opening_bytes'},
    'native_urgent_attempt':{'reservation_entry','candidate','signed_entry','signed_record'},
    'nursery_tx':{'tx'},'wallet_changeset':{'content'},'expiry_carrier':{'signed_tx'}}
IDENTITY_FIELDS={'snapshot','backend_pid','database','role','read_only','isolation'}
EXTRA_FILES={'joint-preflight.json','joint-pg.json','joint-files.json'}


def _sql():
    sizes=[];tables=[]
    for table,(order,columns,_) in PROJECTIONS.items():
        actual_table=TABLES.get(table,table)
        projected='(SELECT %s FROM public.%s ORDER BY %s) q'%(columns,actual_table,order)
        sizes.extend(["'%s',(SELECT count(*) FROM public.%s)"%(table,actual_table),
            "'%s_bytes',COALESCE((SELECT sum(octet_length(row_to_json(q)::text)+1) FROM %s),0)"%(table,projected),
            "'%s_max',COALESCE((SELECT max(octet_length(row_to_json(q)::text)) FROM %s),0)"%(table,projected)])
        tables.append("'%s',COALESCE((SELECT jsonb_agg(row_to_json(q) ORDER BY %s) FROM %s),'[]'::jsonb)"%(table,order,projected))
    identity="'snapshot',pg_current_snapshot()::text,'backend_pid',pg_backend_pid(),'database',current_database(),'role',current_user,'read_only',current_setting('transaction_read_only'),'isolation',current_setting('transaction_isolation')"
    return 'SELECT jsonb_build_object('+','.join(sizes)+')','SELECT jsonb_build_object('+identity+','+','.join(tables)+')'


PREFLIGHT_SQL,PRIVATE_SQL=_sql()


def preflight(value):
    fields={table+suffix for table in PROJECTIONS for suffix in ('','_bytes','_max')}
    if (not isinstance(value,dict) or set(value)!=fields or any(type(v)is not int or v<0 for v in value.values())
            or any(value[t]>50000 or value[t+'_max']>MAX_FILE_BYTES*2+8192 for t in PROJECTIONS)
            or sum(value[t+'_bytes'] for t in PROJECTIONS)>MAX_BYTES-65536):
        raise ValueError('whole joint fee source count/byte preflight exceeds unchanged bound')


def assemble(pg,identity,sizes):
    preflight(sizes)
    if (not isinstance(pg,dict) or set(pg)!=IDENTITY_FIELDS|set(PROJECTIONS)
            or any(pg[k]!=identity[k] for k in ('snapshot','backend_pid','database','read_only','isolation'))
            or pg.get('role')!=body.ROLE or pg['database']!='trackc' or pg['read_only']!='on'
            or pg['isolation']!='repeatable read' or type(pg['backend_pid'])is not int or pg['backend_pid']<=0):
        raise ValueError('actual joint source must share original body/public RR identity')
    for table,(order,columns,_) in PROJECTIONS.items():
        fields={name+'_hex' if name in HEX_FIELDS.get(table,set()) else name for name in PROJECTIONS[table][2]}
        rows=pg[table]
        if not isinstance(rows,list) or len(rows)!=sizes[table]:raise ValueError('complete joint table count differs')
        keys=[]
        for row in rows:
            if not isinstance(row,dict) or set(row)!=fields:raise ValueError('closed joint source columns differ')
            keys.append(tuple(row[field]for field in order.split(',')))
            if len(fee.canonical(row).encode())>sizes[table+'_max']:raise ValueError('joint row exceeds original preflight')
            for name,value in row.items():
                if name.endswith('_hex'):
                    nullable=(table=='native_urgent_attempt'and name in {'signed_entry_hex','signed_record_hex'})or(table=='wallet_changeset'and name=='content_hex')or(table=='virtual_transaction'and name=='signed_tx_hex')
                    if value is None:
                        if not nullable:raise ValueError('required original BYTEA is missing')
                    else:fee._raw(value,4096 if name in {'policy_bytes_hex','reservation_entry_hex','signed_entry_hex'}else MAX_FILE_BYTES)
            if table=='native_urgent_attempt'and ((row['signed_entry_hex']is None)!=(row['signed_record_hex']is None)):
                raise ValueError('paired actual urgent signed originals required')
        if table=='rounds':
            if(any(type(row['id'])is not int or row['id']<=0 or type(row['seq'])is not int or row['seq']<0
                    or not isinstance(row['funding_txid'],str)or re.fullmatch('[0-9a-f]{64}',row['funding_txid'])is None for row in rows)
                    or len({row['funding_txid']for row in rows})!=len(rows)):
                raise ValueError('unique actual Round id/funding txid and independent seq required')
        columns_order=order.split(',')
        for key in keys:
            for name,value in zip(columns_order,key):
                if value is None and name=='unblinded_mailbox_id':continue
                if type(value)is not (int if name in {'id','seq','attempt_index','participation_id','amount'}else str):
                    raise ValueError('actual ordered SQL key type differs')
        sortkey=lambda key:tuple((v is None,v)for v in key)
        if keys!=sorted(keys,key=sortkey)or(table not in {'round_part_input','round_part_output'}and len(set(keys))!=len(keys)):
            raise ValueError('joint table ordering/unique identity differs')
    if len(fee.canonical(pg).encode())>MAX_BYTES:raise ValueError('whole joint source reply exceeds bound')
    return pg


def _identity(st):return (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns,st.st_mode,st.st_uid,st.st_nlink)


def _sibling(suffix,expected,*,budget):
    """Only exact D-derived siblings, including original protected absence."""
    history=fee.HISTORY_ROOT
    path=history.with_name(history.name+suffix)
    if any(p.is_symlink() for p in [path,*path.parents]):raise ValueError('fixed witness sibling symlink refused')
    parent=path.parent.stat()
    try:st=path.lstat()
    except FileNotFoundError:
        return {'exists':False,'parent_identity':_identity(parent),'directory_identity':None,'files':None}
    if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode)!=0o700 or st.st_uid!=expected['uid']:
        raise ValueError('actual native witness owner0700 directory required')
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);files={}
    try:
        if _identity(os.fstat(fd))!=_identity(st):raise ValueError('witness directory changed before read')
        names=os.listdir(fd)
        if suffix=='.ordinary-native-opening':
            if set(names)!={'certificate.json','validated.sha256'}:raise ValueError('whole native opening witness set required')
        elif suffix=='.ordinary-native-round-rights':
            if(not {'identity.json','history'}<=set(names)or len(names)>MAX_FILES+2
                    or any(n not in {'identity.json','history'}and re.fullmatch(r'[0-9a-f]{64}\.json',n)is None for n in names)):
                raise ValueError('whole original Round-rights namespace required')
        elif len(names)>MAX_FILES or any(re.fullmatch(r'(?:[0-9a-f]{64}|urgent-[1-9][0-9]*\.(?:candidate|signed))\.json',n)is None for n in names):
            raise ValueError('unknown/bounded native publication witness filename')
        size=0
        for name in sorted(names):
            f=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
            limit=(4096 if name=='identity.json'else 4096*65 if name=='history'else MAX_FILE_BYTES)if suffix=='.ordinary-native-round-rights'else MAX_FILE_BYTES
            with os.fdopen(f,'rb')as stream:
                before=os.fstat(stream.fileno())
                if (not stat.S_ISREG(before.st_mode) or before.st_uid!=expected['uid'] or before.st_nlink!=1
                        or stat.S_IMODE(before.st_mode)!=0o600 or not 0<=before.st_size<=limit or(before.st_size==0 and not(suffix=='.ordinary-native-round-rights'and name=='history'))):
                    raise ValueError('actual native witness owner0600 regular bounded file required')
                counted=suffix!='.ordinary-native-opening'and name.endswith('.json')and name!='identity.json'
                if (budget['bytes']+before.st_size>MAX_WITNESS_BYTES
                        or budget['files']+int(counted)>MAX_FILES):
                    raise ValueError('whole witness bounds exceeded before read')
                remaining=MAX_WITNESS_BYTES-budget['bytes']
                raw=stream.read(min(limit,remaining)+1);after=os.fstat(stream.fileno())
            if _identity(before)!=_identity(after) or len(raw)!=before.st_size:raise ValueError('native witness changed during read')
            budget['bytes']+=len(raw);budget['files']+=int(counted)
            size+=len(raw)
            if size>MAX_WITNESS_BYTES:raise ValueError('native witness combined bound exceeded')
            files[name]={'raw':raw,'identity':_identity(before),'sha256':fee.digest(raw)}
        if sorted(os.listdir(fd))!=sorted(names) or _identity(os.fstat(fd))!=_identity(st) or _identity(path.stat())!=_identity(st):
            raise ValueError('native witness directory changed during read')
    finally:os.close(fd)
    return {'exists':True,'parent_identity':_identity(parent),'directory_identity':_identity(st),'files':files}


def _files(expected):
    # Share the unchanged whole-source quota across namespaces before buffering
    # each original, rather than only checking their combined size afterwards.
    budget={'bytes':0,'files':0}
    result={name:_sibling(suffix,expected,budget=budget) for name,suffix in (
        ('publications','.ordinary-native-publications'),('opening','.ordinary-native-opening'),('round_rights','.ordinary-native-round-rights'))}
    _witness_files(result,expected)
    return result


def capture(raw_connection,adapter,*,limits,binding,observation,expected_financial_pins,
        chain_identity,expected_history_identity,expected_policy_sha256):
    """One actual existing IDENTITY/RR; all preflight families precede bodies."""
    started=time.monotonic();before=_files(expected_history_identity);private=[];sizes=[];f=adapter.frontier()
    class JointAdapter:
        frontier=staticmethod(adapter.frontier)
        class _FixedConnection(adapter._FixedConnection):
            def execute(self,sql):
                super().execute(sql)
                if sql==f.IDENTITY_SQL and not private:
                    size=fee._pg_query(self.raw,PREFLIGHT_SQL);preflight(size)
                    old=fee._pg_query(self.raw,fee.PREFLIGHT_SQL)
                    if (set(old)!={'allocations','carriers','mappings','bytes'} or any(type(v)is not int or v<0 for v in old.values())
                            or sum(old[k]for k in ('allocations','carriers','mappings'))>fee.MAX_ROWS or old['bytes']>fee.MAX_ORIGINAL_BYTES):
                        raise ValueError('original fee preflight exceeds unchanged bound')
                    body._preflight(fee._pg_query(self.raw,body.PREFLIGHT_SQL));self.check()
                    sizes.append(size);private.append(fee._pg_query(self.raw,PRIVATE_SQL));self.check()
    base=normal.capture(raw_connection,JointAdapter,limits=limits,binding=binding,observation=observation,
        expected_financial_pins=expected_financial_pins,chain_identity=chain_identity,
        expected_history_identity=expected_history_identity,expected_policy_sha256=expected_policy_sha256)
    after=_files(expected_history_identity)
    if before!=after or time.monotonic()-started>=limits['deadline_ms']/1000 or len(private)!=1:
        raise ValueError('whole joint source witnesses/deadline/single cut changed')
    identity=f.strict_json(base['public_lines'][0])['identity'];assemble(private[0],identity,sizes[0])
    if len(base['history']['ordinary-fee-policy.json'])>1024:raise ValueError('actual native policy file exceeds native bound')
    return {**base,'joint_kind':KIND,'joint_scope':SCOPE,'joint_source_sha256':fee.digest(Path(__file__).read_bytes()),
        'joint_preflight':sizes[0],'joint_pg':private[0],'joint_files':before,'joint_abi_sha256':ABI_SHA256,'round_abi_sha256':ROUND_ABI_SHA256}


def _name(name):
    from . import c_private_fee_package as rules
    if name in normal.FIXED_FILES|EXTRA_FILES|{'manifest.json'}:return name
    if name.startswith('history/'):return rules._name(name)
    if name.startswith('joint-witness/'):
        parts=name.split('/')
        if len(parts)==3 and parts[1]in {'opening','publications','round_rights'}:
            if parts[1]=='opening'and parts[2]in {'certificate.json','validated.sha256'}:return name
            if parts[1]=='round_rights'and(parts[2]in {'identity.json','history'}or re.fullmatch('[0-9a-f]{64}\\.json',parts[2])):return name
            if parts[1]=='publications'and re.fullmatch(r'(?:[0-9a-f]{64}|urgent-[1-9][0-9]*\.(?:candidate|signed))\.json',parts[2]):return name
    raise ValueError('joint private member outside fixed source grammar')


def _witness_files(groups,expected):
    """Validate captured metadata and return original bytes, never declarations."""
    if not isinstance(groups,dict)or set(groups)!={'opening','publications','round_rights'}:raise ValueError('whole joint witness groups required')
    result={};index={};total=0
    for group,value in groups.items():
        if(not isinstance(value,dict)or set(value)!={'exists','parent_identity','directory_identity','files'}
                or type(value['exists'])is not bool):raise ValueError('closed actual witness state required')
        def identity(v):
            return isinstance(v,(list,tuple))and len(v)==8 and all(type(n)is int and n>=0 for n in v)
        if not identity(value['parent_identity']):raise ValueError('original witness parent identity required')
        item={**value}
        if value['exists']is False:
            if value['directory_identity']is not None or value['files']is not None:raise ValueError('missing witness is not empty witness')
        else:
            d=value['directory_identity']
            if(not identity(d)or not stat.S_ISDIR(d[5])or stat.S_IMODE(d[5])!=0o700 or d[6]!=expected['uid']
                    or not isinstance(value['files'],dict)):
                raise ValueError('original protected witness directory identity differs')
            if group=='opening'and set(value['files'])!={'certificate.json','validated.sha256'}:raise ValueError('whole original opening witness required')
            if group=='round_rights'and not {'identity.json','history'}<=set(value['files']):raise ValueError('whole original Round-rights metadata required')
            item['files']={}
            for name,entry in value['files'].items():
                full=_name('joint-witness/'+group+'/'+name)
                if not isinstance(entry,dict)or set(entry)!={'raw','identity','sha256'}:raise ValueError('original witness metadata differs')
                raw=entry['raw'];i=entry['identity']
                if(not isinstance(raw,bytes)or not 0<=len(raw)<=MAX_FILE_BYTES or(len(raw)==0 and not(group=='round_rights'and name=='history')) or not identity(i)
                        or i[2]!=len(raw)or not stat.S_ISREG(i[5])or stat.S_IMODE(i[5])!=0o600
                        or i[6]!=expected['uid']or i[7]!=1 or entry['sha256']!=fee.digest(raw)):
                    raise ValueError('original protected witness file identity/hash differs')
                total+=len(raw);result[full]=raw
                item['files'][name]={'identity':i,'sha256':entry['sha256'],'size_bytes':len(raw)}
        if value['exists']and group=='round_rights':
            raw=value['files']['history']['raw']
            if(len(value['files']['identity.json']['raw'])>4096 or len(raw)>4096*65
                    or re.fullmatch(rb'(?:[0-9a-f]{64}\n)*',raw)is None):
                raise ValueError('canonical bounded original Round-rights index required')
            rows=raw.decode().splitlines()
            if len(rows)!=len(set(rows))or {n+'.json'for n in rows}!=set(value['files'])-{'identity.json','history'}:
                raise ValueError('whole reciprocal Round-rights index/file set differs')
        index[group]=item
    if sum(n.endswith('.json')and '/opening/'not in n and not n.endswith('/identity.json')for n in result)>MAX_FILES or total>MAX_WITNESS_BYTES:raise ValueError('whole witness bounds exceeded')
    return result,index


def write_private_package(result,path):
    """V4 originals; unchanged strict32MiB payload and48MiB archive ceilings."""
    from . import c_private_fee_package as rules
    path=Path(path)
    if(not path.is_absolute()or any(p.is_symlink()for p in [path,*path.parents])
            or path.parent.stat().st_uid!=os.getuid()or path.parent.stat().st_mode&0o077):
        raise ValueError('owned0700 private evidence directory required')
    if(result.get('kind')!=normal.KIND or result.get('joint_kind')!=KIND or result.get('joint_scope')!=SCOPE
            or result.get('joint_abi_sha256')!=ABI_SHA256 or result.get('round_abi_sha256')!=ROUND_ABI_SHA256):raise ValueError('exact versioned joint capture required')
    witnesses,index=_witness_files(result['joint_files'],result['history_identity'])
    history=result['history']
    if not fee.POLICY_NAMES<=set(history):raise ValueError('whole original history required')
    files={'cut.json':fee.canonical({'schema_version':1,'kind':'c-native-body-preflight','preflight':result['preflight']}).encode(),
        'private-pg.json':result['private_pg'],'public-frontier.ndjson':b''.join(result['public_lines']),
        'fee-cut.json':result['private_fee_cut'],'fee-private-pg.json':result['private_fee_pg'],
        'joint-preflight.json':fee.canonical(result['joint_preflight']).encode(),
        'joint-pg.json':fee.canonical(result['joint_pg']).encode(),'joint-files.json':fee.canonical(index).encode(),
        **{'history/'+n:raw for n,raw in history.items()},**witnesses}
    for name in files:_name(name)
    if(len(files)+1>rules.MAX_MEMBERS or any(not isinstance(raw,bytes)or len(raw)>fee.MAX_BYTES for raw in files.values())
            or sum(map(len,files.values()))>normal.MAX_PAYLOAD_BYTES):raise ValueError('unchanged whole private payload bound exceeded')
    manifest={'schema_version':VERSION,'kind':KIND,'scope':SCOPE,
        **{n:result[n]for n in ('financial_pins','source_observation','chain','source_sha256','body_source_sha256','policy_sha256','history_identity','joint_source_sha256','joint_abi_sha256','round_abi_sha256')},
        'files':{n:{'sha256':fee.digest(raw),'size_bytes':len(raw)}for n,raw in files.items()}}
    files['manifest.json']=fee.canonical(manifest).encode()
    if len(files['manifest.json'])>rules.MAX_MANIFEST_BYTES:raise ValueError('private manifest bound exceeded')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb')as stream:
        with tarfile.open(fileobj=stream,mode='w',format=tarfile.USTAR_FORMAT)as archive:
            for name,raw in files.items():
                item=tarfile.TarInfo(name);item.size=len(raw);item.mode=0o600;archive.addfile(item,io.BytesIO(raw))
        stream.flush();os.fsync(stream.fileno())
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    if path.stat().st_size>rules.MAX_TAR_BYTES:raise ValueError('private physical archive bound exceeded')
    return {'sha256':fee.digest(path.read_bytes()),'bytes':path.stat().st_size,'manifest_sha256':fee.digest(files['manifest.json'])}


def _manifest(files):
    raw=files.get('manifest.json');value=fee._json(raw)if isinstance(raw,bytes)else None
    fields={'schema_version','kind','scope','financial_pins','source_observation','chain','source_sha256','body_source_sha256','policy_sha256','history_identity','joint_source_sha256','joint_abi_sha256','round_abi_sha256','files'}
    if(not isinstance(value,dict)or set(value)!=fields or type(value['schema_version'])is not int or value['schema_version']!=VERSION
            or value['kind']!=KIND or value['scope']!=SCOPE or value['joint_abi_sha256']!=ABI_SHA256 or value['round_abi_sha256']!=ROUND_ABI_SHA256
            or fee.canonical(value).encode()!=raw or not isinstance(value['files'],dict)
            or set(value['files'])!=set(files)-{'manifest.json'} or not normal.FIXED_FILES|EXTRA_FILES<=set(files)):
        raise ValueError('exact joint V4 original manifest required')
    for name,entry in value['files'].items():
        if(not isinstance(entry,dict)or set(entry)!={'sha256','size_bytes'}or type(entry['size_bytes'])is not int
                or entry['size_bytes']!=len(files[name])or entry['sha256']!=fee.digest(files[name])):
            raise ValueError('joint original hash/size differs')
    return value


def decode_transport(path,*,producer_exit):
    """Stateless admitted transport only; expected authority is checked later."""
    from . import c_private_native_body_package as package
    if type(status:=producer_exit())is not int or status!=0:raise ValueError('actual joint transport exit required')
    path=Path(path)
    # Protected inode/mode/whole digest and USTAR EOF are rechecked by _read_files.
    if not path.is_absolute()or any(p.is_symlink()for p in [path,*path.parents]):raise ValueError('fixed protected artifact required')
    from . import c_private_fee_package as rules
    st=path.stat()
    if(not stat.S_ISREG(st.st_mode)or st.st_uid!=os.getuid()or stat.S_IMODE(st.st_mode)!=0o600 or st.st_nlink!=1
            or path.parent.stat().st_uid!=os.getuid()or path.parent.stat().st_mode&0o077 or not 0<st.st_size<=rules.MAX_TAR_BYTES):
        raise ValueError('owned protected regular private archive required')
    h=hashlib.sha256()
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb')as stream:
        before=os.fstat(stream.fileno())
        if _identity(before)!=_identity(st):raise ValueError('private artifact changed before hash')
        while raw:=stream.read(65536):h.update(raw)
        if _identity(os.fstat(stream.fileno()))!=_identity(before):raise ValueError('private artifact changed while hashing')
    digest=h.hexdigest();files=package._read_files(path,digest,name_validator=_name);manifest=_manifest(files)
    if type(status:=producer_exit())is not int or status!=0:raise ValueError('actual joint transport terminal changed')
    return {'kind':'c-private-joint-transport-only','path':path,'archive_sha256':digest,'manifest':manifest,
        'producer_exit':producer_exit,'complete':False,'qualified':False,'scope':'Private transport only; native and expected-context validation mandatory'}


def load_target_tar(path,*,expected_package_sha256,expected_source_sha256,expected_body_source_sha256,
        expected_joint_source_sha256,expected_financial_pins,expected_observation,expected_chain,
        expected_history_identity,expected_policy_sha256,adapter,limits,binding,producer_exit):
    from . import c_private_native_body_package as package
    from . import c_private_fee_package as rules
    for sha in (expected_source_sha256,expected_body_source_sha256,expected_joint_source_sha256,expected_policy_sha256):rules._sha(sha)
    pins=fee._pins(expected_financial_pins)
    fee._observation({'source_observation':expected_observation},pins,expected_chain.get('height'),expected_chain.get('tip_hash'))
    if(expected_chain.get('genesis')!=fee.SIGNET_GENESIS or expected_chain.get('ibd')is not False
            or binding.get('schema_sha256')!=pins['schema_sha256']or binding.get('genesis')!=expected_chain['genesis']
            or binding.get('network')!='signet'or binding.get('database')!='trackc'):
        raise ValueError('joint independent chain/financial binding differs')
    files=package._read_files(path,expected_package_sha256,name_validator=_name);_manifest(files)
    loaded=normal._consume_files(dict(files),expected_package_sha256=expected_package_sha256,expected_source_sha256=expected_source_sha256,
        expected_body_source_sha256=expected_body_source_sha256,expected_joint_source_sha256=expected_joint_source_sha256,
        expected_financial_pins=pins,expected_observation=expected_observation,expected_chain=expected_chain,
        expected_history_identity=expected_history_identity,expected_policy_sha256=expected_policy_sha256,
        adapter=adapter,limits=limits,binding=binding,producer_exit=producer_exit)
    sizes=fee._json(files['joint-preflight.json']);pg=fee._json(files['joint-pg.json'])
    assemble(pg,loaded['database']['database_identity'],sizes)
    index=fee._json(files['joint-files.json']);groups={}
    if not isinstance(index,dict):raise ValueError('actual witness index required')
    for group,value in index.items():
        if not isinstance(value,dict):raise ValueError('actual witness group required')
        groupfiles=value.get('files')
        if groupfiles is not None:
            if not isinstance(groupfiles,dict):raise ValueError('original witness entries required')
            originals={}
            for name,entry in groupfiles.items():
                if not isinstance(entry,dict)or set(entry)!={'identity','sha256','size_bytes'}:raise ValueError('original witness closed metadata required')
                raw=files.get('joint-witness/'+group+'/'+name)
                if not isinstance(raw,bytes)or type(entry['size_bytes'])is not int or entry['size_bytes']!=len(raw):raise ValueError('original witness body missing/size differs')
                originals[name]={'raw':raw,'identity':entry['identity'],'sha256':entry['sha256']}
            groupfiles=originals
        groups[group]={**value,'files':groupfiles}
    originals,rebuilt=_witness_files(groups,expected_history_identity)
    if(set(originals)!={n for n in files if n.startswith('joint-witness/')}
            or fee.canonical(rebuilt).encode()!=files['joint-files.json']
            or fee.canonical(sizes).encode()!=files['joint-preflight.json']or fee.canonical(pg).encode()!=files['joint-pg.json']):
        raise ValueError('whole canonical joint source originals differ')
    refs=loaded['original_private_source_references'];refs.update(joint_source_sha256=expected_joint_source_sha256,joint_abi_sha256=ABI_SHA256,round_abi_sha256=ROUND_ABI_SHA256)
    return {**loaded,'joint_pg':pg,'joint_witnesses':groups,'scope':SCOPE,'native_validation_required':True,'complete':False,'qualified':False}

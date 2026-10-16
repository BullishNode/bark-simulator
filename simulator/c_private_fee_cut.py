"""Fixed C private fee-cut component for the existing admitted source worker.

Runs only inside its owned deadline supervisor. It performs no connection setup,
SQL admin, signing or dispatch. The trusted launcher authenticates the existing
protected PG modules and this module before supplying their live connection.
Opaque SQL/history originals stay in the returned private package, never Trace.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import time

from .c_native_fee_sources import MAX_BYTES, MAX_ROWS, digest, _json, _raw, _observation, _pins
from .model import SIGNET_GENESIS, canonical, integer

HISTORY_ROOT = Path('/srv/track-c-data/captaind/direct-expiry-witness')
MAX_ORIGINAL_BYTES = 4*1024*1024
POLICY_NAMES = {'identity.json','ordinary-fee-policy.json','ordinary-fee-budget','history'}
PREFLIGHT_SQL = """SELECT jsonb_build_object(
'allocations',(SELECT count(*) FROM expiry_allocation),
'carriers',(SELECT count(*) FROM expiry_carrier),
'mappings',(SELECT count(*) FROM expiry_carrier_allocation),
'bytes',COALESCE((SELECT sum(octet_length(id)+octet_length(freeze_set)+COALESCE(octet_length(owner_pubkey),0)+COALESCE(octet_length(spk),0)+octet_length(source_evidence::text)+octet_length(retirement_ids::text)+256) FROM expiry_allocation),0)+COALESCE((SELECT sum(octet_length(txid)+octet_length(signed_tx)+octet_length(backing_ids::text)+octet_length(fee_inputs::text)+256) FROM expiry_carrier),0)+COALESCE((SELECT sum(octet_length(txid)+octet_length(allocation_id)+32) FROM expiry_carrier_allocation),0))"""
PRIVATE_SQL = """SELECT jsonb_build_object(
'snapshot',pg_current_snapshot()::text,'database',current_database(),'role',current_user,
'read_only',current_setting('transaction_read_only'),'isolation',current_setting('transaction_isolation'),
'allocations',COALESCE((SELECT jsonb_agg(jsonb_build_object('freeze_set',freeze_set,'id',id,'witness',witness) ORDER BY freeze_set,id) FROM (SELECT freeze_set,id,jsonb_build_object('id',id,'owner',owner_pubkey,'spk',spk,'disposition',disposition,'gross',gross_sat,'fee',fee_sat,'payout',payout_sat,'forfeited',forfeited_sat,'source',source,'evidence',source_evidence,'retirement',retirement_ids)::text AS witness FROM expiry_allocation ORDER BY freeze_set,id LIMIT 10001) a),'[]'::jsonb),
'carriers',COALESCE((SELECT jsonb_agg(jsonb_build_object('txid',txid,'signed_tx_hex',encode(signed_tx,'hex'),'witness',witness) ORDER BY txid) FROM (SELECT txid,signed_tx,jsonb_build_object('generation',generation,'backing',backing_ids,'fee_inputs',fee_inputs,'miner',miner_fee_sat,'subsidy',funding_subsidy_sat,'mappings',(SELECT jsonb_agg(jsonb_build_object('id',m.allocation_id,'vout',m.vout) ORDER BY m.allocation_id) FROM expiry_carrier_allocation m WHERE m.txid=expiry_carrier.txid))::text AS witness FROM expiry_carrier ORDER BY txid LIMIT 10001) c),'[]'::jsonb))"""


def _history_identity(info):
    return {'device':info.st_dev,'inode':info.st_ino,'uid':info.st_uid,'mode':stat.S_IMODE(info.st_mode)}


def _open_history(expected):
    """Production has one literal path; no caller/request pathname or fallback."""
    parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for component in HISTORY_ROOT.parts[1:]:
            before=os.fstat(parent)
            if before.st_uid not in (0,expected['uid']) or before.st_mode&0o022:
                raise ValueError('unprotected private history parent')
            child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            os.close(parent);parent=child
        if _history_identity(os.fstat(parent))!=expected:raise ValueError('actual private history root differs')
        result=parent;parent=None;return result
    finally:
        if parent is not None:os.close(parent)


def _history(fd, expected):
    """Read exactly allowlisted regular native originals; no secrets or glob copy."""
    root=os.fstat(fd)
    if _history_identity(root)!=expected or expected['mode']!=0o700:raise ValueError('private native directory identity/permissions differ')
    names=os.listdir(fd)
    if (len(names)>MAX_ROWS+4 or not POLICY_NAMES<=set(names)
            or any(name not in POLICY_NAMES and re.fullmatch('[0-9a-f]{64}\\.json',name)is None for name in names)):
        raise ValueError('missing/unrelated/inflight private history file; reconcile')
    files={};total=0
    for name in sorted(names):
        file=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
        with os.fdopen(file,'rb')as stream:
            before=os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid!=expected['uid']
                    or before.st_nlink!=1 or stat.S_IMODE(before.st_mode)!=0o600 or before.st_size>MAX_ORIGINAL_BYTES):
                raise ValueError('unprotected/oversized private native original')
            raw=stream.read(MAX_ORIGINAL_BYTES+1);after=os.fstat(stream.fileno())
        signature=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        if len(raw)!=before.st_size or signature(before)!=signature(after):raise ValueError('private original changed while reading')
        total+=len(raw)
        if total>MAX_ORIGINAL_BYTES:raise ValueError('whole private native history exceeds bound')
        files[name]={'raw':raw,'stat':signature(before),'sha256':digest(raw)}
    if sorted(os.listdir(fd))!=sorted(names):raise ValueError('private history membership changed')
    return files


def _same_history(before,after):
    if set(before)!=set(after)or any(before[k]!=after[k]for k in before):
        raise ValueError('native signing/history changed across PG cut; retain HOLD')


def _pg_query(connection, sql):
    with connection.cursor()as cursor:
        cursor.execute(sql);row=cursor.fetchone()
        if row is None or len(row)!=1:raise ValueError('one fixed private PG reply required')
        value=row[0]if isinstance(row[0],dict)else _json(row[0])
        if len(canonical(value).encode())>MAX_BYTES:raise ValueError('private PG reply exceeds aggregate bound')
        return value


def _assemble(files, pg, expected):
    if (not isinstance(pg,dict) or set(pg)!={'snapshot','database','role','read_only','isolation','allocations','carriers'}
            or pg['database']!='trackc'or pg['role']!='trackcfeeobserver'or pg['read_only']!='on'or pg['isolation']!='repeatable read'
            or not isinstance(pg['snapshot'],str)or not pg['snapshot']
            or any(not isinstance(pg[k],list)or len(pg[k])>MAX_ROWS for k in('allocations','carriers'))):
        raise ValueError('actual same-RR private native PG frame required')
    allocations={};seen=set()
    for row in pg['allocations']:
        if set(row)!={'freeze_set','id','witness'}or(row['freeze_set'],row['id'])in seen or not isinstance(row['witness'],str):raise ValueError('private allocation source duplicate/malformed')
        seen.add((row['freeze_set'],row['id']));allocations.setdefault(row['freeze_set'],[]).append(row['witness'])
    # SQL returns exact native ORDER BY freeze_set,id, not a re-encoded witness.
    if [(v['freeze_set'],v['id'])for v in pg['allocations']]!=sorted(seen):raise ValueError('private allocation witness ordering differs')
    records={name[:-5]:item['raw'].hex()for name,item in files.items()if name.endswith('.json')and name not in POLICY_NAMES}
    witnesses={}
    for row in pg['carriers']:
        txid=row['txid']
        if set(row)!={'txid','signed_tx_hex','witness'}or txid in witnesses or txid not in records or not isinstance(row['witness'],str):raise ValueError('private carrier/history membership differs')
        record=_json(_raw(records[txid]));signed=record.get('tx')
        if not isinstance(signed,list)or any(type(v)is not int or not 0<=v<=255 for v in signed)or _raw(row['signed_tx_hex'])!=bytes(signed):raise ValueError('private PG signed bytes differ from independent history')
        witnesses[txid]=row['witness']
    if set(witnesses)!=set(records):raise ValueError('private PG omitted retained signed carrier')
    result={'schema_version':1,'root_identity':expected,'identity_hex':files['identity.json']['raw'].hex(),
            'policy_hex':files['ordinary-fee-policy.json']['raw'].hex(),'budget_hex':files['ordinary-fee-budget']['raw'].hex(),
            'history_hex':files['history']['raw'].hex(),'records':records,'allocation_witnesses':allocations,
            'carrier_witnesses':witnesses,'database_snapshot':pg['snapshot']}
    if len(canonical(result).encode())>MAX_BYTES:raise ValueError('assembled private source exceeds existing reducer bound')
    return result


def capture(raw_connection, adapter, *, limits, binding, expected_history_identity, observation, expected_financial_pins, chain_identity):
    """Same existing protected stream, with private reads in THAT transaction.

    adapter is the already preauthenticated protected dbapi_adapter module, never
    a wire-selected module. raw_connection is a dedicated autocommit psycopg
    connection using the isolated trackcfeeobserver peer role. Caller retains
    originals privately and consumes public_lines only after actual worker exit0
    through existing frontier_v2_contract.consume_original/TraceStore seam.
    """
    began=time.monotonic()
    f=adapter.frontier();limits=f.declaration(limits);binding=f.binding(binding)
    if limits['deadline_ms']>25000:raise ValueError('existing caller deadline cannot be raised')
    pins=_pins(expected_financial_pins);start=chain_identity()
    _observation({'source_observation':observation},pins,start.get('height'),start.get('tip_hash'))
    if (start.get('genesis')!=SIGNET_GENESIS or start.get('ibd')is not False
            or(start.get('height'),start.get('tip_hash'))!=(observation['height'],observation['tip_hash'])):
        raise ValueError('actual independent source tip/context differs')
    deadline=began+limits['deadline_ms']/1000
    if time.monotonic()>=deadline:raise ValueError('private cut allowance consumed before history read')
    fd=_open_history(expected_history_identity)
    try:
        before=_history(fd,expected_history_identity);private=[];lines=[]
        class FeeConnection(adapter._FixedConnection):
            def execute(self,sql):
                super().execute(sql)
                if sql==f.IDENTITY_SQL and not private:
                    size=_pg_query(self.raw,PREFLIGHT_SQL)
                    if (set(size)!={'allocations','carriers','mappings','bytes'}
                            or any(type(v)is not int or v<0 for v in size.values())
                            or sum(size[k]for k in('allocations','carriers','mappings'))>MAX_ROWS
                            or size['bytes']>MAX_ORIGINAL_BYTES):raise ValueError('whole private PG preflight exceeds declared cut')
                    private.append(_pg_query(self.raw,PRIVATE_SQL))
                    self.check()
        connection=FeeConnection(raw_connection,f,limits,deadline,time.monotonic)
        f.produce(connection,limits,binding,lines.append)
        after=_history(fd,expected_history_identity);_same_history(before,after)
        end=chain_identity()
        if end!=start or time.monotonic()>=deadline:raise ValueError('private cut chain/deadline changed')
        if len(private)!=1:raise ValueError('private cut was not captured in original RR transaction')
        cut=_assemble(before,private[0],expected_history_identity)
        # The header's actual PG snapshot must equal the private query snapshot.
        header=f.strict_json(lines[0])
        if header['identity']['snapshot']!=cut['database_snapshot']:raise ValueError('private/public PG snapshots differ')
        return {'private_cut':canonical(cut).encode(),'private_pg':canonical(private[0]).encode(),
                'public_lines':lines,'history':{name:item['raw']for name,item in before.items()},
                'financial_pins':pins,'source_observation':observation,'chain':start}
    finally:os.close(fd)


def write_private_package(result, output):
    """Exclusive0600 original tar; caller transport is existing admitted reader.

    No file extraction, symlinks, stdout JSON, seeds or arbitrary filenames.
    This C fee-only package is not an A six-originals package: its loader must be
    explicitly integrated/admitted rather than fabricating other role sources.
    """
    path=Path(output)
    if (not path.is_absolute()or any(p.is_symlink()for p in [path.parent,*path.parent.parents])
            or path.parent.stat().st_uid!=os.getuid()or path.parent.stat().st_mode&0o077):raise ValueError('owned private evidence directory required')
    if (not POLICY_NAMES<=set(result['history'])or len(result['history'])>MAX_ROWS+4
            or any(name not in POLICY_NAMES and re.fullmatch('[0-9a-f]{64}\\.json',name)is None for name in result['history'])):
        raise ValueError('private package history names outside fixed native allowlist')
    files={'cut.json':result['private_cut'],'private-pg.json':result['private_pg'],
           'public-frontier.ndjson':b''.join(result['public_lines']),
           **{'history/'+name:raw for name,raw in result['history'].items()}}
    total=sum(map(len,files.values()))
    if total>32*1024*1024:raise ValueError('whole private original package exceeds bounded transport')
    manifest={'schema_version':1,'kind':'c-native-fee-private-cut','source_observation':result['source_observation'],
              'financial_pins':result['financial_pins'],'chain':result['chain'],
              'source_sha256':digest(Path(__file__).read_bytes()),
              'files':{name:{'sha256':digest(raw),'size_bytes':len(raw)}for name,raw in files.items()},
              'scope':'Actual private originals only, no readiness/producer-exit/financial authority claim'}
    files['manifest.json']=canonical(manifest).encode()
    file=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(file,'wb')as stream:
        with tarfile.open(fileobj=stream,mode='w',format=tarfile.USTAR_FORMAT)as archive:
            for name,raw in files.items():
                entry=tarfile.TarInfo(name);entry.size=len(raw);entry.mode=0o600
                archive.addfile(entry,io.BytesIO(raw))
        stream.flush();os.fsync(stream.fileno())
    directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(directory)
    finally:os.close(directory)
    return {'sha256':digest(path.read_bytes()),'bytes':path.stat().st_size,'manifest_sha256':digest(files['manifest.json'])}

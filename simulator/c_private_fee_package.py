"""Strict private C fee-only package loader; no extraction or readiness authority.

Trusted caller preauthenticates this module/capture module, context and adapter.
The producer_exit accessor MUST be the owned transport's actual reaped status.
Returned opaque originals stay private and must never be journaled as payloads.
"""
import os
from pathlib import Path
import re
import stat
import tarfile

from . import c_private_fee_cut as capture
from .c_native_fee_sources import NATIVE_SIGNET_CHAIN_HASH

MAX_TAR_BYTES=48*1024*1024
MAX_PAYLOAD_BYTES=32*1024*1024
MAX_MANIFEST_BYTES=4*1024*1024
MAX_MEMBERS=capture.MAX_ROWS+8
FIELDS={'schema_version','kind','source_observation','financial_pins','chain','source_sha256','files','scope'}


def _identity(s):return(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)

def _sha(value):
    if not isinstance(value,str)or re.fullmatch('[0-9a-f]{64}',value)is None:raise ValueError('independent exact source hash required')
    return value

def _name(value):
    if value in {'cut.json','private-pg.json','public-frontier.ndjson','manifest.json'}:return value
    if isinstance(value,str)and value.startswith('history/'):
        leaf=value[len('history/'):]
        if leaf in capture.POLICY_NAMES or re.fullmatch('[0-9a-f]{64}\\.json',leaf):return value
    raise ValueError('private package member outside exact native source allowlist')


def _files(stream,size):
    files={};payload=0;offset=0
    while True:
        header=stream.read(512);offset+=len(header)
        if len(header)!=512:raise ValueError('truncated private tar header/EOF')
        if header==b'\0'*512:
            # Require a full standard terminator and only bounded zero padding.
            end=stream.read();offset+=len(end)
            if len(end)<512 or len(end)>10240 or any(end)or offset!=size or size%10240:
                raise ValueError('private tar trailing data/noncanonical EOF')
            break
        if header[257:265]!=b'ustar\00000':raise ValueError('only fixed USTAR originals accepted')
        member=tarfile.TarInfo.frombuf(header,'utf-8','strict');name=_name(member.name)
        if ('manifest.json'in files or member.type!=tarfile.REGTYPE or member.linkname
                or member.mode!=0o600 or member.uid!=0 or member.gid!=0
                or member.uname or member.gname or name in files or len(files)>=MAX_MEMBERS
                or member.size<0 or member.size>(MAX_MANIFEST_BYTES if name=='manifest.json'else capture.MAX_BYTES)):
            raise ValueError('private tar type/owner/mode/member/byte bound differs')
        raw=stream.read(member.size);padding=stream.read((-member.size)%512);offset+=len(raw)+len(padding)
        if len(raw)!=member.size or len(padding)!=(-member.size)%512 or any(padding):raise ValueError('private tar original/padding truncated')
        if name!='manifest.json':payload+=len(raw)
        if payload>MAX_PAYLOAD_BYTES:raise ValueError('private tar whole payload bound exceeded')
        files[name]=raw
    return files


def load_target_tar(path,*,expected_package_sha256,expected_source_sha256,expected_financial_pins,
                    expected_observation,expected_history_identity,expected_policy_sha256,
                    expected_server_pubkey,adapter,limits,binding,producer_exit):
    """Admitted C loader callback for the existing owned TargetTarReader.

    Expected hashes/context are fixed trusted caller inputs, never manifest-
    selected authority. Public PG frame is consumed before raw originals return;
    caller still captures/replays original lines with the existing TraceStore.
    """
    _sha(expected_package_sha256);_sha(expected_source_sha256);_sha(expected_policy_sha256)
    path=Path(path)
    if not path.is_absolute()or any(p.is_symlink()for p in [path,*path.parents]):raise ValueError('private package absolute protected path required')
    if path.parent.stat().st_uid!=os.getuid()or path.parent.stat().st_mode&0o077:raise ValueError('owned0700 private package parent required')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb')as stream:
        before=os.fstat(stream.fileno())
        if(not stat.S_ISREG(before.st_mode)or before.st_uid!=os.getuid()or before.st_nlink!=1
                or stat.S_IMODE(before.st_mode)!=0o600 or not 0<before.st_size<=MAX_TAR_BYTES):
            raise ValueError('owned regular0600 bounded private package required')
        import hashlib
        h=hashlib.sha256()
        while chunk:=stream.read(65536):h.update(chunk)
        if h.hexdigest()!=expected_package_sha256:raise ValueError('whole private tar hash differs')
        stream.seek(0);files=_files(stream,before.st_size);after=os.fstat(stream.fileno())
        if _identity(before)!=_identity(after)or _identity(path.stat(follow_symlinks=False))!=_identity(before):raise ValueError('private tar changed across read')
    raw_manifest=files.pop('manifest.json',None)
    if raw_manifest is None:raise ValueError('private manifest missing')
    manifest=capture._json(raw_manifest)
    if(set(manifest)!=FIELDS or type(manifest['schema_version'])is not int or manifest['schema_version']!=1
            or manifest['kind']!='c-native-fee-private-cut'
            or manifest['scope']!='Actual private originals only, no readiness/producer-exit/financial authority claim'
            or capture.canonical(manifest).encode()!=raw_manifest
            or manifest['source_sha256']!=expected_source_sha256 or manifest['financial_pins']!=capture._pins(expected_financial_pins)
            or manifest['source_observation']!=expected_observation):raise ValueError('private manifest source/context/pins/schema differs')
    expected_chain={'genesis':capture.SIGNET_GENESIS,'height':expected_observation['height'],'tip_hash':expected_observation['tip_hash'],'ibd':False}
    if manifest['chain']!=expected_chain:raise ValueError('private package independent chain differs')
    capture._observation({'source_observation':expected_observation},expected_financial_pins,expected_chain['height'],expected_chain['tip_hash'])
    if not isinstance(manifest['files'],dict)or set(manifest['files'])!=set(files):raise ValueError('private manifest whole member coverage differs')
    for name,raw in files.items():
        entry=manifest['files'][name]
        if(not isinstance(entry,dict)or set(entry)!={'sha256','size_bytes'}or type(entry['size_bytes'])is not int
                or entry['size_bytes']!=len(raw)or entry['sha256']!=capture.digest(raw)):
            raise ValueError('private original hash/size differs')
    if not {'cut.json','private-pg.json','public-frontier.ndjson'}<=set(files):raise ValueError('private originals missing')
    history={name[len('history/'):]:{'raw':raw}for name,raw in files.items()if name.startswith('history/')}
    if not capture.POLICY_NAMES<=set(history):raise ValueError('whole private native metadata missing')
    if sum(len(v['raw'])for v in history.values())>capture.MAX_ORIGINAL_BYTES:raise ValueError('native whole-history original bound exceeded')
    pg=capture._json(files['private-pg.json']);cut=capture._assemble(history,pg,expected_history_identity)
    if capture.canonical(cut).encode()!=files['cut.json']:raise ValueError('private cut differs from original PG/history reconstruction')
    identity=capture._json(history['identity.json']['raw'])
    if(type(identity.get('version'))is not int or capture.digest(history['ordinary-fee-policy.json']['raw'])!=expected_policy_sha256
            or identity!={'version':1,'genesis':NATIVE_SIGNET_CHAIN_HASH,'server_pubkey':expected_server_pubkey}):
        raise ValueError('private native policy/network/server identity differs')
    raw_public=files['public-frontier.ndjson']
    if not raw_public.endswith(b'\n'):raise ValueError('public original stream EOF missing')
    lines=raw_public.splitlines(keepends=True);database=adapter.frontier().consume(lines,limits,binding,producer_exit)
    if database['snapshot']!=cut['database_snapshot']:raise ValueError('private/public same-RR snapshot differs')
    references={'archive_sha256':expected_package_sha256,'manifest_sha256':capture.digest(raw_manifest),
                'source_sha256':expected_source_sha256,'private_cut_sha256':capture.digest(files['cut.json']),
                'private_pg_sha256':capture.digest(files['private-pg.json']),'public_frontier_sha256':capture.digest(raw_public),
                'native_original_sha256':{name:capture.digest(item['raw'])for name,item in history.items()},
                'source_observation_id':expected_observation['id']}
    return {'manifest':manifest,'private_cut':files['cut.json'],'private_pg':files['private-pg.json'],
            'public_lines':lines,'database':database,'original_private_source_references':references}

"""Fixed private fee cut for the protected B runtime producer loop.

Call only BETWEEN that producer's before/after owner/process/route/FLOCK
samples. Returned buffers are private TargetTarReader members, NEVER runtime
observation fields, Store payloads, public RPC or traces. No producer is started
or installed by this module; private capture/admission remains operator-owned.
"""
import os
from pathlib import Path
import stat

from . import b_normal_runtime_source as runtime
from .b_private_native_fee_cut import sql
from .model import canonical
from .two_step_normal import digest,strict_json

MAX_SQL_BYTES=2*1024*1024
ROLES={'policy_raw':'ordinary-fee-policy.json','opening_raw':'ordinary-fee-opening.json',
       'journal_raw':'ordinary-fee-budget'}
META={'device','inode','bytes','mtime_ns','ctime_ns','sha256'}


def _meta(value):
    return {'device':value.st_dev,'inode':value.st_ino,'bytes':value.st_size,
            'mtime_ns':value.st_mtime_ns,'ctime_ns':value.st_ctime_ns}


def bound_original(path,expected,maximum):
    """Nofollow regular-file bytes matching the actual owning metadata sample."""
    path=Path(path)
    if (not path.is_absolute()or path!=Path(os.path.abspath(path))or set(expected)!=META
            or any(type(expected[k])is not int or expected[k]<0 for k in META-{'sha256'})
            or type(expected['sha256'])is not str or type(maximum)is not int or maximum<=0):
        raise ValueError('exact native private original path/metadata bound required')
    parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in path.parts[1:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            os.close(parent);parent=child
        descriptor=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
    finally:os.close(parent)
    with os.fdopen(descriptor,'rb')as source:
        before=os.fstat(source.fileno())
        metadata={k:expected[k]for k in META-{'sha256'}}
        if not stat.S_ISREG(before.st_mode)or _meta(before)!=metadata or before.st_size>maximum:
            raise ValueError('owning native private file identity differs')
        chunks=[];size=0
        while True:
            runtime._require_time()
            block=source.read(min(65536,maximum+1-size))
            if not block:break
            chunks.append(block);size+=len(block)
            if size>maximum:raise ValueError('whole native private original exceeds bound')
        after=os.fstat(source.fileno());raw=b''.join(chunks)
    if (_meta(after)!=metadata or len(raw)!=expected['bytes']or digest(raw)!=expected['sha256']):
        raise ValueError('owning native private bytes changed')
    return raw


def capture_private_cut(expected,budget):
    """Fixed function for the existing protected loop; no generic callbacks.

    Root's ONE runtime producer must compare the actual owner/process/route/
    FLOCK/file samples AFTER this returns. A caller's budget dict cannot admit
    itself. The installed source/package and original declarations are pinned.
    """
    if runtime._CAPTURE_END.get() is None:
        raise ValueError('bounded protected runtime capture loop required')
    runtime._expected(expected);runtime._check_owner_budget(budget)
    helper=runtime._helper(expected);directory,binding=helper.source_mount()
    if (str(directory.parent)!=expected['data_mount']['source']
            or runtime.identity(binding)!=budget['source_mount_identity_sha256']):
        raise ValueError('private source is outside the same owning mount')
    originals={role:bound_original(directory/name,budget['files'][name],helper.LIMITS[name])
               for role,name in ROLES.items()}
    raw=runtime._run(['/usr/bin/docker','exec',expected['postgres_container'],'psql',
        '-X','-A','-t','-U','postgres','-d',expected['database'],'-v','ON_ERROR_STOP=1','-c',sql()],
        maximum=MAX_SQL_BYTES)
    if type(raw)is not bytes or len(raw)>MAX_SQL_BYTES:
        raise ValueError('whole private SQL capture exceeds bound')
    lines=raw.splitlines()
    if not raw.endswith(b'\n')or len(lines)!=6 or lines[:3]!=[b'BEGIN',b'SET',b'DO']or lines[-1]!=b'COMMIT':
        raise ValueError('literal same-RR bounded private SQL stdout required')
    # Strict syntax only here; existing native/direct validators authenticate all
    # actual rows and source paths. Neither JSON line supplies a readiness bit.
    strict_json(lines[3]);strict_json(lines[4])
    for role,name in ROLES.items():
        if bound_original(directory/name,budget['files'][name],helper.LIMITS[name])!=originals[role]:
            raise ValueError('private original changed around same-RR query')
    if helper.source_mount()!=(directory,binding):
        raise ValueError('private owning mount changed during query')
    originals={name:value.decode('utf8')for name,value in originals.items()}
    originals['sql_raw']=raw.decode('utf8')
    return {'raw_sql':lines[3]+b'\n','auxiliary_originals':{
        'b-native-fee-originals.json':canonical(originals).encode(),
        'b-native-fee-snapshot.json':budget['owner_snapshot_raw'].encode('utf8')}}

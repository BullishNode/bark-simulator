"""Bounded private source transport and manifest join, never public trace data."""
import asyncio
import json
import os
import signal
import tarfile
import uuid
from pathlib import Path, PurePosixPath

from .model import canonical, integer
from .normal_source_deadline import timeout as source_timeout
from .two_step_normal import digest, private_history_hash, strict_json

MAX_BYTES = 128*1024*1024
MAX_FILES = 12000
ORIGINALS = {'native_sql','policy','core','rounds_inventory','watchman_inventory','runtime'}


def relative(name):
    if (not isinstance(name,str) or not name or '\\' in name or '\x00' in name
            or PurePosixPath(name).is_absolute() or str(PurePosixPath(name)) != name
            or any(value in {'.','..',''} for value in name.split('/'))):
        raise ValueError('private package path is not a canonical relative file')
    return name


def load_target_tar(path):
    """Read only named regular originals; never extract paths from a tar file."""
    path=Path(path)
    if (not path.is_absolute() or path.is_symlink() or not path.is_file()
            or path.stat().st_mode&0o077 or not 0<path.stat().st_size<=MAX_BYTES):
        raise ValueError('bounded private original package required')
    before=path.stat();files={};total=0
    with tarfile.open(path,mode='r:') as archive:
        for member in archive:
            name=relative(member.name)
            if (not member.isfile() or member.issym() or member.islnk() or name in files
                    or len(files)>=MAX_FILES+1 or not 0<=member.size<=64*1024*1024
                    or any(key in member.pax_headers for key in ('path','linkpath'))):
                raise ValueError('private package type/link/duplicate/file bound differs')
            total+=member.size
            if total>MAX_BYTES or name=='manifest.json' and member.size>4*1024*1024:
                raise ValueError('private package aggregate/manifest byte bound exceeded')
            source=archive.extractfile(member)
            if source is None:raise ValueError('private package original missing')
            raw=source.read(member.size+1)
            if len(raw)!=member.size:raise ValueError('private package original size differs')
            files[name]=raw
    after=path.stat()
    if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):
        raise ValueError('private package changed while loading')
    manifest_raw=files.pop('manifest.json',None)
    if manifest_raw is None:raise ValueError('original private manifest missing')
    manifest=strict_json(manifest_raw)
    if set(manifest['files'])!=set(files) or len(files)>MAX_FILES:
        raise ValueError('private manifest file coverage differs')
    for name,entry in manifest['files'].items():
        relative(name)
        if (set(entry)!={'sha256','size_bytes'} or integer(entry['size_bytes'],'original size')!=len(files[name])
                or entry['sha256']!=digest(files[name])):
            raise ValueError('private original hash/size differs')
    mapping=manifest['originals_map']
    if set(mapping)!=ORIGINALS or any(relative(name) not in files for name in mapping.values()):
        raise ValueError('complete named private originals required')
    originals={name:files[path] for name,path in mapping.items()}
    if manifest['original_sha256']!={name:digest(raw) for name,raw in originals.items()}:
        raise ValueError('private originals role/hash differs')
    paths=manifest['fee_history_paths']
    if (set(paths)-{'root_identity','identity','index','candidates','opening_certificate','validated_digest'}
            or not {'root_identity','identity','index','candidates'}<=set(paths)
            or not isinstance(paths['candidates'],dict)):
        raise ValueError('exact retained fee history path contract required')
    def original(name):
        if relative(name) not in files:raise ValueError('retained fee history original missing')
        return files[name]
    history={'root_identity':paths['root_identity'],'identity_bytes':original(paths['identity']),
        'index_bytes':original(paths['index']),
        'candidates':{identifier:original(name) for identifier,name in paths['candidates'].items()}}
    for name,field in [('opening_certificate','opening_certificate_bytes'),('validated_digest','validated_digest_bytes')]:
        if name in paths:history[field]=original(paths[name])
    if manifest['fee_history_sha256']!=private_history_hash(history):
        raise ValueError('retained private history hash differs')
    return {'manifest':manifest,'raw_manifest':manifest_raw,'manifest_sha256':digest(manifest_raw),
        'raw_sql':originals['native_sql'],'raw_policy':originals['policy'],'raw_core':originals['core'],
        'raw_rounds_inventory':originals['rounds_inventory'],'raw_watchman_inventory':originals['watchman_inventory'],
        'raw_runtime':originals['runtime'],'fee_history':history,'auxiliary_originals':files}


class TargetTarReader:
    """An explicitly installed forced-reader argv, no shell or response-selected command.

    Its command/configuration/source and authenticated transport must be admitted
    separately. The only request is the public observation nonce/context. Opaque
    stdout/stderr and any partial failure stay in private exclusive evidence.

    Trusted code may install a loader(path, producer_exit=accessor) and enable
    the existing bounded public request on stdin. Admission binds that loader's
    module, qualified name and source bytes, plus the stdin mode. The accessor
    exposes the actual reaped return code; a failed producer never reaches it.
    """
    def __init__(self,command,evidence_directory,*,timeout=45,loader=None,request_stdin=False):
        if loader is not None and not callable(loader):raise ValueError('trusted code loader required')
        if type(request_stdin)is not bool:raise ValueError('trusted code stdin mode required')
        self.loader=loader;self.request_stdin=request_stdin
        self.command=tuple(command);self.evidence_directory=Path(evidence_directory);self.timeout=timeout

    async def read(self,observation):
        deadline=asyncio.get_running_loop().time()+source_timeout(self.timeout)
        parent=self.evidence_directory
        if (not self.command or not Path(self.command[0]).is_absolute() or not 0<self.timeout<=45
                or not parent.is_absolute() or parent.is_symlink() or not parent.is_dir()
                or parent.stat().st_mode&0o077 or parent.stat().st_uid!=os.getuid()):
            raise ValueError('admitted bounded private source-reader context required')
        directory=parent/uuid.uuid4().hex;directory.mkdir(mode=0o700)
        nonce=uuid.UUID(observation['id'])
        if nonce.hex!=observation['id']:raise ValueError('canonical source observation ID required')
        token='financial-source '+str(nonce)
        command=(*self.command,token)
        def create(name):
            return os.fdopen(os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')
        encoded=(canonical(observation)+'\n').encode()
        if len(encoded)>65536:raise ValueError('public source request exceeds bound')
        with create('request.json') as output:output.write(encoded);output.flush();os.fsync(output.fileno())
        process=await asyncio.create_subprocess_exec(*command,stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,start_new_session=True)
        terminal={'pid':process.pid,'command_sha256':digest(canonical(command).encode()),
            'source_observation_id':observation['id'],'remote_command':token,'timed_out':False}
        async def drain(stream,name,maximum):
            count=0
            with create(name) as output:
                while True:
                    chunk=await stream.read(65536)
                    if not chunk:break
                    remaining=maximum-count;count+=len(chunk)
                    output.write(chunk[:max(0,remaining)])
                    if count>maximum:
                        output.flush();os.fsync(output.fileno());raise ValueError('private source stream exceeds bound')
                output.flush();os.fsync(output.fileno())
            return count
        stdout=asyncio.create_task(drain(process.stdout,'source.tar',MAX_BYTES))
        stderr=asyncio.create_task(drain(process.stderr,'stderr',65536))
        async def send():
            try:
                if self.request_stdin:
                    # asyncio transport writes are nonblocking; drain concurrently
                    # with BOTH output pipes under the one absolute deadline.
                    for offset in range(0,len(encoded),4096):
                        process.stdin.write(encoded[offset:offset+4096])
                        await process.stdin.drain()
            finally:process.stdin.close()
        sender=asyncio.create_task(send())
        try:
            remaining=deadline-asyncio.get_running_loop().time()
            if remaining<=0:raise TimeoutError('private source deadline consumed')
            sizes=await asyncio.wait_for(asyncio.gather(stdout,stderr,process.wait(),sender),timeout=remaining)
            terminal.update(exit=process.returncode,stdout_bytes=sizes[0],stderr_bytes=sizes[1])
            if process.returncode:raise ValueError('private source command refused')
        except BaseException as error:
            terminal.update(error_type=type(error).__name__,timed_out=isinstance(error,TimeoutError))
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            await process.wait();await asyncio.gather(stdout,stderr,sender,return_exceptions=True)
            terminal['exit']=process.returncode
            raise
        finally:
            with create('terminal.json') as output:
                output.write(canonical(terminal).encode());output.flush();os.fsync(output.fileno())
        if self.loader is None:return load_target_tar(directory/'source.tar')
        return self.loader(directory/'source.tar',producer_exit=lambda:process.returncode)

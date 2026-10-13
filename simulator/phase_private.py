"""Protected append-only phase evidence; public events carry hashes only.

Signing nonces remain in the native signing process. This vault does not claim
that hashing a checkpoint makes SDK secret state restartable or trustworthy.
"""
from __future__ import annotations
import fcntl,hashlib,json,os,re,stat
from pathlib import Path

LABEL=re.compile(r'[A-Za-z0-9_-]{1,160}\Z')
CHECKSUM=re.compile(r'[0-9a-f]{64}\Z')
MAX_BYTES=16*1024*1024
NOFOLLOW=getattr(os,'O_NOFOLLOW',0)

class Vault:
    def __init__(self,root):
        self.root=Path(root).absolute()
        for part in [*reversed(self.root.parents),self.root]:
            if part.is_symlink():raise ValueError('private evidence path contains symlink')
        self.root.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.objects=self.root/'objects';self.objects.mkdir(mode=0o700,exist_ok=True)
        for directory in (self.root,self.objects):
            info=directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077:
                raise ValueError('private evidence directory must be owned and mode0700')
    def _directory(self):
        descriptor=os.open(self.objects,os.O_RDONLY|os.O_DIRECTORY|NOFOLLOW)
        info=os.fstat(descriptor)
        if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077:
            os.close(descriptor);raise ValueError('private evidence directory permissions changed')
        return descriptor
    def _read(self,checksum):
        descriptor=self._directory()
        try:
            fd=os.open(checksum,os.O_RDONLY|NOFOLLOW,dir_fd=descriptor)
            with os.fdopen(fd,'rb') as source:
                info=os.fstat(source.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077 or info.st_size>MAX_BYTES:
                    raise ValueError('unsafe private evidence object')
                return source.read(MAX_BYTES+1)
        finally:os.close(descriptor)
    def put(self,kind,payload,*,trial_id,leg_id):
        for value in (kind,trial_id,leg_id):
            if not isinstance(value,str) or not LABEL.fullmatch(value):raise ValueError('invalid private reference label')
        if not isinstance(payload,bytes) or not payload or len(payload)>MAX_BYTES:raise ValueError('private evidence size outside bound')
        checksum=hashlib.sha256(payload).hexdigest()
        ref={'kind':kind,'sha256':checksum,'bytes':len(payload),'trial_id':trial_id,'leg_id':leg_id}
        descriptor=self._directory()
        try:
            try:fd=os.open(checksum,os.O_WRONLY|os.O_CREAT|os.O_EXCL|NOFOLLOW,0o600,dir_fd=descriptor)
            except FileExistsError:
                if self._read(checksum)!=payload:raise ValueError('private checkpoint content changed')
            else:
                with os.fdopen(fd,'wb') as destination:
                    destination.write(payload);destination.flush();os.fsync(destination.fileno())
                os.fsync(descriptor)
        finally:os.close(descriptor)
        # References contain no signer payloads, but are protected with the vault.
        rootfd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|NOFOLLOW)
        try:
            fd=os.open('index.jsonl',os.O_WRONLY|os.O_CREAT|os.O_APPEND|NOFOLLOW,0o600,dir_fd=rootfd)
            with os.fdopen(fd,'ab') as index:
                fcntl.flock(index.fileno(),fcntl.LOCK_EX)
                info=os.fstat(index.fileno())
                if info.st_nlink!=1 or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077:raise ValueError('unsafe private evidence index')
                index.write((json.dumps(ref,sort_keys=True,separators=(',',':'))+'\n').encode());index.flush();os.fsync(index.fileno())
            os.fsync(rootfd)
        finally:os.close(rootfd)
        return ref
    def verify(self,ref):
        try:
            if set(ref)!= {'kind','sha256','bytes','trial_id','leg_id'} or not isinstance(ref['sha256'],str) or not CHECKSUM.fullmatch(ref['sha256']):return False
            if any(not isinstance(ref[v],str) or not LABEL.fullmatch(ref[v]) for v in ('kind','trial_id','leg_id')):return False
            payload=self._read(ref['sha256'])
            return type(ref['bytes']) is int and len(payload)==ref['bytes'] and hashlib.sha256(payload).hexdigest()==ref['sha256']
        except (ValueError,OSError,TypeError,KeyError):return False

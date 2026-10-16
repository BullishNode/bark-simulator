"""Existing root-owned immutable file reader, copied unchanged from C observer."""
import hashlib
import os
from pathlib import Path
import stat

def checked_file(path, *, maximum=2*1024*1024):
    path=Path(path)
    if not path.is_absolute():raise ValueError('absolute installed file required')
    if '..' in path.parts:raise ValueError('canonical installed path required')
    directory=os.open(path.anchor,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for component in path.parts[1:-1]:
            info=os.fstat(directory)
            if info.st_uid!=0 or info.st_mode&0o022:raise ValueError('root-owned immutable installed parent required')
            child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
            os.close(directory);directory=child
        parent=os.fstat(directory)
        if parent.st_uid!=0 or parent.st_mode&0o022:raise ValueError('root-owned immutable installed parent required')
        file=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
    finally:os.close(directory)
    with os.fdopen(file,'rb') as stream:
        first=os.fstat(stream.fileno())
        if not stat.S_ISREG(first.st_mode) or first.st_uid!=0 or first.st_mode&0o022:raise ValueError('root-owned immutable installed file required')
        raw=stream.read(maximum+1);last=os.fstat(stream.fileno())
    if len(raw)>maximum or (first.st_dev,first.st_ino,first.st_size,first.st_mtime_ns,first.st_ctime_ns)!=(last.st_dev,last.st_ino,last.st_size,last.st_mtime_ns,last.st_ctime_ns):
        raise ValueError('installed file changed or exceeds bound')
    return raw,hashlib.sha256(raw).hexdigest()


"""Strict private native-body transport; default A/fee transports are unchanged.

Trusted constructor supplies expected source/observation/pins and actual reaped
transport exit. No manifest-selected authority, extraction or public raw bodies.
"""
import hashlib
import io
import os
from pathlib import Path
import stat
import tarfile

from . import c_private_fee_cut as common
from . import c_private_native_body_cut as capture

KIND='c-native-body-private-cut'
SCOPE='Same-RR native bodies and public19 originals only; no economic ownership, paid, readiness or producer authority'
FILES={'cut.json','private-pg.json','public-frontier.ndjson'}
MAX_PAYLOAD_BYTES=32*1024*1024 # unchanged strict fee-transport aggregate ceiling
FIELDS={'schema_version','kind','source_observation','financial_pins','chain','source_sha256','files','scope'}


def write_private_package(result,path):
    """Exclusive USTAR600 package, no stdout, seeds, credentials or new paths."""
    path=Path(path)
    if(not path.is_absolute()or any(p.is_symlink()for p in [path,*path.parents])
            or path.parent.stat().st_uid!=os.getuid()or path.parent.stat().st_mode&0o077):
        raise ValueError('owned0700 private body evidence directory required')
    if result.get('kind')!=KIND or result.get('schema_version')!=1:raise ValueError('exact body capture required')
    files={'private-pg.json':result['private_pg'],'public-frontier.ndjson':b''.join(result['public_lines']),
      'cut.json':common.canonical({'schema_version':1,'kind':'c-native-body-preflight','preflight':result['preflight']}).encode()}
    if any(not isinstance(v,bytes)or len(v)>capture.MAX_BYTES for v in files.values())or sum(map(len,files.values()))>MAX_PAYLOAD_BYTES:
        raise ValueError('whole private body package exceeds unchanged transport bound')
    manifest={'schema_version':1,'kind':KIND,'source_observation':result['source_observation'],
      'financial_pins':result['financial_pins'],'chain':result['chain'],'source_sha256':result['source_sha256'],
      'files':{n:{'sha256':common.digest(v),'size_bytes':len(v)}for n,v in files.items()},'scope':SCOPE}
    files['manifest.json']=common.canonical(manifest).encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb')as stream:
        with tarfile.open(fileobj=stream,mode='w',format=tarfile.USTAR_FORMAT)as archive:
            for name,raw in files.items():
                item=tarfile.TarInfo(name);item.size=len(raw);item.mode=0o600;archive.addfile(item,io.BytesIO(raw))
        stream.flush();os.fsync(stream.fileno())
    directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(directory)
    finally:os.close(directory)
    return {'bytes':path.stat().st_size,'sha256':common.digest(path.read_bytes()),'manifest_sha256':common.digest(files['manifest.json'])}


def _read_files(path,expected_package_sha256,*,name_validator=None):
    """Protected read reused by fixed C loaders, never a wire-selected callback."""
    from . import c_private_fee_package as tar_rules
    tar_rules._sha(expected_package_sha256)
    path=Path(path)
    if(not path.is_absolute()or any(p.is_symlink()for p in [path,*path.parents])
            or path.parent.stat().st_uid!=os.getuid()or path.parent.stat().st_mode&0o077):
        raise ValueError('owned0700 private body evidence directory required')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb')as stream:
        before=os.fstat(stream.fileno())
        if(not stat.S_ISREG(before.st_mode)or before.st_uid!=os.getuid()or before.st_nlink!=1
                or stat.S_IMODE(before.st_mode)!=0o600 or not 0<before.st_size<=tar_rules.MAX_TAR_BYTES):
            raise ValueError('owned regular0600 bounded private body archive required')
        h=hashlib.sha256()
        while raw:=stream.read(65536):h.update(raw)
        if h.hexdigest()!=expected_package_sha256:raise ValueError('private body package hash differs')
        stream.seek(0);files=tar_rules._files(stream,before.st_size,**({}if name_validator is None else {'name_validator':name_validator}));after=os.fstat(stream.fileno())
        if tar_rules._identity(before)!=tar_rules._identity(after)or tar_rules._identity(path.stat(follow_symlinks=False))!=tar_rules._identity(before):
            raise ValueError('private body archive changed during read')
    return files


def load_target_tar(path,*,expected_package_sha256,expected_source_sha256,expected_financial_pins,
                    expected_observation,expected_chain,adapter,limits,binding,producer_exit):
    """Fixed trusted loader injection only; root code admits worker/terminal.

    Existing private fee USTAR parser is reused with an EXACT smaller member set.
    Full output remains private. Caller must retain actual source originals and
    TraceStore references, same-current-source runtime/chain and native proof ELF
    provenance. Successful body transport never implies current economic owner.
    """
    from . import c_private_fee_package as tar_rules
    tar_rules._sha(expected_package_sha256);tar_rules._sha(expected_source_sha256)
    pins=common._pins(expected_financial_pins)
    common._observation({'source_observation':expected_observation},pins,expected_chain.get('height'),expected_chain.get('tip_hash'))
    if (expected_chain.get('genesis')!=common.SIGNET_GENESIS or expected_chain.get('ibd')is not False
            or binding.get('schema_sha256')!=pins['schema_sha256']or binding.get('genesis')!=expected_chain['genesis']
            or binding.get('network')!='signet'or binding.get('database')!='trackc'):
        raise ValueError('private body chain/binding differs')
    files=_read_files(path,expected_package_sha256)
    if set(files)!=FILES|{'manifest.json'}:raise ValueError('exact native body package members required')
    manifest_raw=files.pop('manifest.json');manifest=common._json(manifest_raw)
    if(not isinstance(manifest,dict)or set(manifest)!=FIELDS or type(manifest['schema_version'])is not int or manifest['schema_version']!=1
            or manifest['kind']!=KIND or manifest['scope']!=SCOPE or common.canonical(manifest).encode()!=manifest_raw
            or manifest['financial_pins']!=pins or manifest['source_observation']!=expected_observation
            or manifest['chain']!=expected_chain or manifest['source_sha256']!=expected_source_sha256
            or not isinstance(manifest['files'],dict)or set(manifest['files'])!=FILES):
        raise ValueError('private body manifest/context/source differs')
    for name,raw in files.items():
        item=manifest['files'][name]
        if(not isinstance(item,dict)or set(item)!={'sha256','size_bytes'}or type(item['size_bytes'])is not int
                or item['size_bytes']!=len(raw)or item['sha256']!=common.digest(raw)):
            raise ValueError('private body original hash/size differs')
    f=adapter.frontier();lines=files['public-frontier.ndjson'].splitlines(keepends=True)
    # This invokes the actual transport wait/reap callback, never a manifest bit.
    database=f.consume(lines,limits,binding,producer_exit)
    context=common._json(files['cut.json'])
    if(not isinstance(context,dict)or set(context)!={'schema_version','kind','preflight'}
            or type(context['schema_version'])is not int or context['schema_version']!=1
            or context['kind']!='c-native-body-preflight'or common.canonical(context).encode()!=files['cut.json']):
        raise ValueError('private body preflight original malformed')
    capture._preflight(context['preflight']);pg=common._json(files['private-pg.json'])
    if common.canonical(pg).encode()!=files['private-pg.json']:raise ValueError('noncanonical private body original')
    capture._assemble(pg,{'identity':database['database_identity']},database['rows'],context['preflight'])
    return {'database':database,'private_pg':pg,'manifest':manifest,'originals':files,
      'manifest_sha256':common.digest(manifest_raw),'private_pg_sha256':common.digest(files['private-pg.json']),
      'public_source_sha256':common.digest(files['public-frontier.ndjson']),
      'scope':SCOPE,'complete':False,'qualified':False}

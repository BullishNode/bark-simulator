"""Read admitted immutable funding originals; no wallet, RPC or journal writes."""
import os
import re
from pathlib import Path

from .final_campaign import _source_event
from .model import canonical, integer
from .normal_member_source import private_file
from .private_source_package import relative
from .two_step_normal import digest, strict_json

MAX_BYTES=16*1024*1024


class FundingReader:
    def __init__(self, configuration, wallet_root):
        if (not isinstance(configuration,dict) or set(configuration)!={'qualification_sequence','packages'}
                or not isinstance(configuration['packages'],dict) or not 0<len(configuration['packages'])<=32):
            raise ValueError('explicit admitted funding original package configuration required')
        integer(configuration['qualification_sequence'],'funding qualification sequence',1)
        self.configuration=configuration;self.wallet_root=Path(wallet_root)

    def _path(self,path):
        path=Path(path)
        if (not path.is_absolute() or path!=Path(os.path.abspath(path))or any(p.is_symlink()for p in (path,*path.parents))
                or path==self.wallet_root or self.wallet_root in path.parents):
            raise ValueError('funding evidence must be outside wallet directories and unaliased')
        return path

    def read(self,store,boundary):
        """Return raw context for a new independent ownership rejoin each time."""
        from .normal_funding_ownership import verify_funding_ownership
        from .two_step_normal import module_hash
        cfg=self.configuration;event,qualified=_source_event(store,cfg['qualification_sequence'])
        if (event['kind']!='normal_funding_ownership_sources_qualified'
                or qualified['financial_pins']!=boundary['pins']
                or qualified['boundary_sha256']!=digest(canonical(boundary).encode())
                or qualified['module_sha256']!=module_hash(verify_funding_ownership)):
            raise ValueError('funding original reader admission differs')
        entries={v['declaration_sha256']:v for v in qualified['declarations']}
        if len(entries)!=len(qualified['declarations'])or set(entries)!=set(cfg['packages']):
            raise ValueError('complete original funding declaration membership required')
        result={};cache={};total=0
        def read(path,maximum):
            nonlocal total
            path=self._path(path)
            if path not in cache:
                raw=private_file(path,maximum);total+=len(raw)
                if total>MAX_BYTES:raise ValueError('aggregate funding original bytes exceed bound')
                cache[path]=raw
            if len(cache[path])>maximum:raise ValueError('funding original role exceeds bound')
            return cache[path]
        for sha,config in cfg['packages'].items():
            if (not isinstance(sha,str)or re.fullmatch('[0-9a-f]{64}',sha)is None
                    or not isinstance(config,dict)or set(config)!={'declaration_path','manifest_path','files_root'}):
                raise ValueError('fixed funding original paths required')
            declaration=read(config['declaration_path'],65536);manifest_raw=read(config['manifest_path'],4*1024*1024)
            if digest(declaration)!=sha or digest(manifest_raw)!=entries[sha]['bank_manifest_sha256']:
                raise ValueError('funding original declaration/manifest changed')
            manifest=strict_json(manifest_raw);root=self._path(config['files_root']);meta=root.stat()
            if (not root.is_dir()or meta.st_mode&0o077 or meta.st_uid!=os.getuid()
                    or not isinstance(manifest['files'],dict)or not 0<len(manifest['files'])<=512):
                raise ValueError('bounded private funding original file root required')
            files={}
            for name,entry in manifest['files'].items():
                raw=read(root/relative(name),2*1024*1024)
                if (not isinstance(entry,dict)or type(entry.get('size_bytes'))is not int
                        or entry!={'sha256':digest(raw),'size_bytes':len(raw)}):
                    raise ValueError('funding original file membership/hash differs')
                files[name]=raw
            result[sha]={'declaration_bytes':declaration,'manifest_bytes':manifest_raw,'files':files}
        store.verify_event_chain()
        return {'qualification_sequence':cfg['qualification_sequence'],'packages':result}

"""Fixed read-only CLN payment source, stdout PRIVATE to admitted SSH transport.

Install this module and a private static configuration on the owned payer host.
The fixed command supplies configuration path and digest, never an observer.
No account, wallet, invoice or payment is created or changed by this source.
"""
import asyncio
import hashlib
import json
import os
import signal
from pathlib import Path
import sys

from .c_cln_payment_parts import CompletedPartsReader
from .model import canonical
from .normal_member_source import private_file
from .two_step_normal import digest, strict_json


class FixedClnRpc:
    """One hash-pinned local lightning-cli and owned static existing node dir."""
    def __init__(self, configuration, expected_sha256):
        raw=private_file(configuration,65536)
        if digest(raw)!=expected_sha256:raise ValueError('installed private CLN source configuration differs')
        cfg=strict_json(raw)
        if (set(cfg)!={'schema_version','node_alias','node_ids','network','lightning_cli','lightning_cli_sha256','lightning_dir'}
                or type(cfg['schema_version'])is not int or cfg['schema_version']!=1
                or cfg['node_alias']not in {'operator','fixture_peer'} or cfg['network']!='signet'):
            raise ValueError('fixed owned Signet selected-node source configuration required')
        binary=Path(cfg['lightning_cli']);directory=Path(cfg['lightning_dir'])
        if (not binary.is_absolute() or not binary.is_file() or not os.access(binary,os.X_OK)
                or any(p.is_symlink()for p in (binary,*binary.parents)) or binary.stat().st_mode&0o022
                or binary.stat().st_uid not in {0,os.getuid()}
                or not directory.is_absolute() or not directory.is_dir()
                or any(p.is_symlink()for p in (directory,*directory.parents))
                or directory.stat().st_uid!=os.getuid() or directory.stat().st_mode&0o077):
            raise ValueError('fixed source binary and existing private owned node directory required')
        self.cfg=cfg;self.configuration_sha256=expected_sha256;self.binary=binary
        self.check_binary()
        # Reuse exact compressed identities/network checks before any process.
        CompletedPartsReader(self.read,node_ids=cfg['node_ids'],network=cfg['network'])

    def check_binary(self):
        meta=self.binary.lstat()
        if not self.binary.is_file() or self.binary.is_symlink() or meta.st_mode&0o022 or meta.st_size>64*1024*1024:
            raise ValueError('local selected-reader executable changed')
        with self.binary.open('rb')as source:
            if hashlib.file_digest(source,'sha256').hexdigest()!=self.cfg['lightning_cli_sha256']:
                raise ValueError('actual local lightning-cli binary differs from source qualification')

    async def _run(self, argv):
        """Bound both PRIVATE pipes while reading and reap this process only."""
        from .c_cln_payment_parts import MAX_REPLY
        process=await asyncio.create_subprocess_exec(*argv,stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,start_new_session=True)
        async def drain(stream,maximum,retain):
            raw=bytearray();size=0
            while True:
                chunk=await stream.read(65536)
                if not chunk:break
                size+=len(chunk)
                if size>maximum:raise ValueError('private native CLI reply exceeded stream bound')
                if retain:raw.extend(chunk)
            return bytes(raw)
        stdout=asyncio.create_task(drain(process.stdout,MAX_REPLY,True))
        stderr=asyncio.create_task(drain(process.stderr,65536,False))
        success=False
        try:
            out,_,_=await asyncio.wait_for(asyncio.gather(stdout,stderr,process.wait()),timeout=25)
            if process.returncode!=0:raise ValueError('actual local CLN read refused')
            success=True
            return out
        finally:
            if not success:
                try:os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
            await process.wait()
            await asyncio.gather(stdout,stderr,return_exceptions=True)

    async def read(self, alias, method, params):
        if alias!=self.cfg['node_alias']:raise ValueError('selected payer belongs to another fixed source host')
        if method=='getinfo':
            if params!={}:raise ValueError('getinfo takes no observer parameters')
            arguments=[]
        elif method in {'listpays','listinvoices','listsendpays'}:
            from .controlled_peer_evidence import _hash
            if set(params)!={'payment_hash'}:raise ValueError('unfiltered exact-hash selection required')
            arguments=['payment_hash='+json.dumps(_hash(params['payment_hash']))]
        elif method=='decode':
            if set(params)!={'string'} or not isinstance(params['string'],str) or not 1<=len(params['string'])<=16000:
                raise ValueError('bounded original signed invoice required')
            # Local exec argv, no shell/SSH joining or public capture callbacks.
            arguments=['string='+json.dumps(params['string'])]
        else:raise ValueError('CLN source method is not a fixed read')
        self.check_binary()
        argv=[str(self.binary),'--lightning-dir='+self.cfg['lightning_dir'],'--network=signet','--json','--notifications=none','-k',method,*arguments]
        raw=await self._run(argv)
        self.check_binary()
        return raw


async def produce(configuration, configuration_sha256, request):
    """Actual read then exact private originals; no completeness or safe flag."""
    if not isinstance(request,dict) or set(request)!= {'id','started_at','architecture_profile','financial_pins','boundary_id','height','tip_hash',
            'normal_source_sequence','normal_source_hash','external_sequence','external_hash','payer_alias','payment_hash'}:
        raise ValueError('fixed original normal-source request required')
    source=FixedClnRpc(configuration,configuration_sha256)
    if request['payer_alias']!=source.cfg['node_alias']:raise ValueError('normal source selected another owned node')
    result=await CompletedPartsReader(source.read,node_ids=source.cfg['node_ids'],network='signet').read(
        request['payer_alias'],request['payment_hash'])
    return {'schema_version':1,'request_sha256':digest((canonical(request)+'\n').encode()),
            'source_program_sha256':digest(Path(__file__).read_bytes()),'source_configuration_sha256':configuration_sha256,
            'query_times':result['query_times'],'originals':[
                {k:row[k]for k in ('alias','method','params')}|{'raw_hex':row['raw'].hex()}for row in result['private_originals']]}


def main():
    try:
        if len(sys.argv)!=4:raise ValueError('fixed config path/hash and transport nonce required')
        # TargetTarReader appends exactly this transport token; it is not a CLI.
        raw=sys.stdin.buffer.readline(65537)
        if len(raw)>65536 or not raw.endswith(b'\n') or sys.stdin.buffer.read(1):raise ValueError('bounded sole source request required')
        request=strict_json(raw)
        import uuid
        if sys.argv[3]!='financial-source '+str(uuid.UUID(request['id'])):raise ValueError('transport nonce differs')
        value=asyncio.run(produce(sys.argv[1],sys.argv[2],request))
        sys.stdout.write(canonical(value)+'\n')
    except Exception as error:
        # Never expose a private invoice/preimage/CLN failure diagnostic.
        sys.stderr.write('selected CLN source refused: '+type(error).__name__+'\n')
        raise SystemExit(1)from None


if __name__=='__main__':main()

"""One fixed C RR cut for BOTH native fee originals and typed Full bodies.

This auxiliary reuses the actual existing fee/history and body source methods.
No independent captures are coalesced by same block. It opens no PG connection,
selects no request SQL or source path and emits no readiness/ownership verdict.
"""
import io
import os
from pathlib import Path
import tarfile
import time
from . import c_private_fee_cut as fee
from . import c_private_native_body_cut as body

KIND='c-native-normal-private-cut'
SCOPE='One-RR fee/history/native-body/public19 originals only; no current ownership, paid, readiness or producer authority'
ADDITIONAL_SELECT_COLUMNS={**body.ADDITIONAL_SELECT_COLUMNS,
  'public.expiry_allocation':['source_evidence'], 'public.expiry_carrier':['signed_tx']}
BODY_FILES={'cut.json','private-pg.json','public-frontier.ndjson'}
FIXED_FILES=BODY_FILES|{'fee-cut.json','fee-private-pg.json'}
MAX_PAYLOAD_BYTES=32*1024*1024


def capture(raw_connection,adapter,*,limits,binding,observation,expected_financial_pins,
            chain_identity,expected_history_identity,expected_policy_sha256):
    """Root-owned caller must supervise bootstrap/connect/history/cut/reap <=25s.

    Both private query pairs run after ONE IDENTITY in the SAME existing public19
    RR transaction. Original role metadata is never rewritten to the fee role.
    The exact immutable native fee policy and entire history are bracketed, not
    independently sampled. Existing installed fee-only diagnostic is unchanged.
    """
    began=time.monotonic();fd=fee._open_history(expected_history_identity);private=[]
    try:
        before=fee._history(fd,expected_history_identity)
        if fee.digest(before['ordinary-fee-policy.json']['raw'])!=expected_policy_sha256:
            raise ValueError('actual immutable normal fee policy differs')
        f=adapter.frontier()
        class CombinedAdapter:
            frontier=staticmethod(adapter.frontier)
            class _FixedConnection(adapter._FixedConnection):
                def execute(self,sql):
                    super().execute(sql)
                    if sql==f.IDENTITY_SQL and not private:
                        size=fee._pg_query(self.raw,fee.PREFLIGHT_SQL)
                        if(set(size)!={'allocations','carriers','mappings','bytes'}
                                or any(type(v)is not int or v<0 for v in size.values())
                                or sum(size[n]for n in ['allocations','carriers','mappings'])>fee.MAX_ROWS
                                or size['bytes']>fee.MAX_ORIGINAL_BYTES):
                            raise ValueError('combined fee preflight exceeds unchanged bound')
                        # The body role is checked before any opaque fee/body read.
                        size_body=fee._pg_query(self.raw,body.PREFLIGHT_SQL);body._preflight(size_body);self.check()
                        private.append(fee._pg_query(self.raw,fee.PRIVATE_SQL));self.check()
        result=body.capture(raw_connection,CombinedAdapter,limits=limits,binding=binding,
          observation=observation,expected_financial_pins=expected_financial_pins,chain_identity=chain_identity)
        after=fee._history(fd,expected_history_identity);fee._same_history(before,after)
        if time.monotonic()-began>=limits['deadline_ms']/1000 or len(private)!=1:
            raise ValueError('whole combined cut deadline/single transaction differs')
        fee_cut=fee._assemble(before,private[0],expected_history_identity,expected_role=body.ROLE)
        native=fee._json(result['private_pg'])
        if fee_cut['database_snapshot']!=native['snapshot']:
            raise ValueError('combined actual fee/body RR snapshot differs')
        return {**result,'kind':KIND,'scope':SCOPE,
          'private_fee_cut':fee.canonical(fee_cut).encode(),'private_fee_pg':fee.canonical(private[0]).encode(),
          'history':{n:v['raw']for n,v in before.items()},'history_identity':expected_history_identity,
          'policy_sha256':expected_policy_sha256,'source_sha256':fee.digest(Path(__file__).read_bytes()),
          'body_source_sha256':result['source_sha256']}
    finally:os.close(fd)


def write_private_package(result,path):
    """Exclusive0600 private originals under the unchanged32MiB payload ceiling."""
    path=Path(path)
    if(not path.is_absolute()or any(p.is_symlink()for p in [path,*path.parents])
            or path.parent.stat().st_uid!=os.getuid()or path.parent.stat().st_mode&0o077):
        raise ValueError('owned0700 combined private evidence directory required')
    if result.get('kind')!=KIND or result.get('scope')!=SCOPE:raise ValueError('exact combined cut required')
    history=result['history']
    if(not fee.POLICY_NAMES<=set(history)or len(history)>fee.MAX_ROWS+4
            or any(n not in fee.POLICY_NAMES and __import__('re').fullmatch('[0-9a-f]{64}\\.json',n)is None for n in history)):
        raise ValueError('combined original history member differs')
    files={'cut.json':fee.canonical({'schema_version':1,'kind':'c-native-body-preflight','preflight':result['preflight']}).encode(),
      'private-pg.json':result['private_pg'],'public-frontier.ndjson':b''.join(result['public_lines']),
      'fee-cut.json':result['private_fee_cut'],'fee-private-pg.json':result['private_fee_pg'],
      **{'history/'+n:raw for n,raw in history.items()}}
    if any(not isinstance(raw,bytes)or len(raw)>fee.MAX_BYTES for raw in files.values())or sum(map(len,files.values()))>MAX_PAYLOAD_BYTES:
        raise ValueError('combined private payload exceeds unchanged whole bound')
    manifest={'schema_version':1,'kind':KIND,'scope':SCOPE,'financial_pins':result['financial_pins'],
      'source_observation':result['source_observation'],'chain':result['chain'],
      'source_sha256':result['source_sha256'],'body_source_sha256':result['body_source_sha256'],
      'policy_sha256':result['policy_sha256'],'history_identity':result['history_identity'],
      'files':{n:{'sha256':fee.digest(raw),'size_bytes':len(raw)}for n,raw in files.items()}}
    files['manifest.json']=fee.canonical(manifest).encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb')as stream:
        with tarfile.open(fileobj=stream,mode='w',format=tarfile.USTAR_FORMAT)as archive:
            for name,raw in files.items():
                item=tarfile.TarInfo(name);item.size=len(raw);item.mode=0o600;archive.addfile(item,io.BytesIO(raw))
        stream.flush();os.fsync(stream.fileno())
    directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(directory)
    finally:os.close(directory)
    return {'sha256':fee.digest(path.read_bytes()),'bytes':path.stat().st_size,'manifest_sha256':fee.digest(files['manifest.json'])}


def load_target_tar(path,*,expected_package_sha256,expected_source_sha256,expected_body_source_sha256,
                    expected_financial_pins,expected_observation,expected_chain,expected_history_identity,
                    expected_policy_sha256,adapter,limits,binding,producer_exit):
    """Exact normal auxiliary loader, with actual terminal/EOF and no row aliases."""
    from . import c_private_native_body_package as package
    from . import c_private_fee_package as tar_rules
    from .c_native_fee_sources import NATIVE_SIGNET_CHAIN_HASH
    for sha in [expected_source_sha256,expected_body_source_sha256,expected_policy_sha256]:tar_rules._sha(sha)
    pins=fee._pins(expected_financial_pins)
    fee._observation({'source_observation':expected_observation},pins,expected_chain.get('height'),expected_chain.get('tip_hash'))
    if(expected_chain.get('genesis')!=fee.SIGNET_GENESIS or expected_chain.get('ibd')is not False
            or binding.get('schema_sha256')!=pins['schema_sha256']or binding.get('genesis')!=expected_chain['genesis']
            or binding.get('network')!='signet'or binding.get('database')!='trackc'):
        raise ValueError('combined independent chain/financial binding differs')
    def allowed(name):
        if name in FIXED_FILES|{'manifest.json'}:return name
        if name.startswith('history/'):return tar_rules._name(name)
        raise ValueError('combined original name outside fixed scope')
    files=package._read_files(path,expected_package_sha256,name_validator=allowed)
    manifest_raw=files.pop('manifest.json',None)
    if manifest_raw is None:raise ValueError('combined manifest missing')
    manifest=fee._json(manifest_raw)
    fields={'schema_version','kind','scope','financial_pins','source_observation','chain','source_sha256',
      'body_source_sha256','policy_sha256','history_identity','files'}
    if(not isinstance(manifest,dict)or set(manifest)!=fields or type(manifest['schema_version'])is not int
            or manifest['schema_version']!=1 or manifest['kind']!=KIND or manifest['scope']!=SCOPE
            or fee.canonical(manifest).encode()!=manifest_raw or manifest['financial_pins']!=pins
            or manifest['source_observation']!=expected_observation or manifest['chain']!=expected_chain
            or manifest['source_sha256']!=expected_source_sha256 or manifest['body_source_sha256']!=expected_body_source_sha256
            or manifest['policy_sha256']!=expected_policy_sha256 or manifest['history_identity']!=expected_history_identity
            or not isinstance(manifest['files'],dict)or set(manifest['files'])!=set(files)
            or not FIXED_FILES<=set(files)):
        raise ValueError('combined manifest source/context/history differs')
    for name,raw in files.items():
        item=manifest['files'][name]
        if(not isinstance(item,dict)or set(item)!={'sha256','size_bytes'}or type(item['size_bytes'])is not int
                or item['size_bytes']!=len(raw)or item['sha256']!=fee.digest(raw)):
            raise ValueError('combined original hash/size differs')
    history={n[8:]:{'raw':raw}for n,raw in files.items()if n.startswith('history/')}
    if not fee.POLICY_NAMES<=set(history)or sum(len(v['raw'])for v in history.values())>fee.MAX_ORIGINAL_BYTES:
        raise ValueError('combined whole native history missing/oversized')
    if fee.digest(history['ordinary-fee-policy.json']['raw'])!=expected_policy_sha256:
        raise ValueError('combined immutable policy differs')
    identity=fee._json(history['identity.json']['raw'])
    if identity!={'version':1,'genesis':NATIVE_SIGNET_CHAIN_HASH,'server_pubkey':binding['server_pubkey']}:
        raise ValueError('combined native server/network identity differs')
    if not files['public-frontier.ndjson'].endswith(b'\n'):raise ValueError('combined public EOF missing')
    lines=files['public-frontier.ndjson'].splitlines(keepends=True);f=adapter.frontier()
    database=f.consume(lines,limits,binding,producer_exit)
    context=fee._json(files['cut.json'])
    if(not isinstance(context,dict)or set(context)!={'schema_version','kind','preflight'}
            or type(context['schema_version'])is not int or context['schema_version']!=1
            or context['kind']!='c-native-body-preflight'or fee.canonical(context).encode()!=files['cut.json']):
        raise ValueError('combined native preflight malformed')
    body._preflight(context['preflight']);native=fee._json(files['private-pg.json'])
    body._assemble(native,{'identity':database['database_identity']},database['rows'],context['preflight'])
    fee_pg=fee._json(files['fee-private-pg.json'])
    cut=fee._assemble(history,fee_pg,expected_history_identity,expected_role=body.ROLE)
    if(fee.canonical(cut).encode()!=files['fee-cut.json']or cut['database_snapshot']!=database['snapshot']
            or fee.canonical(native).encode()!=files['private-pg.json']or fee.canonical(fee_pg).encode()!=files['fee-private-pg.json']):
        raise ValueError('combined original reconstruction/same RR differs')
    references={'archive_sha256':expected_package_sha256,'manifest_sha256':fee.digest(manifest_raw),
      'source_sha256':expected_source_sha256,'body_source_sha256':expected_body_source_sha256,
      'source_observation_id':expected_observation['id'],'file_sha256':{n:fee.digest(raw)for n,raw in files.items()}}
    return {'manifest':manifest,'database':database,'private_pg':native,'fee_private_pg':fee_pg,
      'fee_cut':cut,'originals':files,'public_lines':lines,'original_private_source_references':references,
      'complete':False,'qualified':False,'scope':SCOPE}

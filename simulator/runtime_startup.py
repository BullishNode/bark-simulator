"""Verify the owned, same-process startup source for the finite signet cohort.

This consumes root-authenticated bounded original observations, not a generic
configuration assertion. It establishes loaded configuration identity only;
treasury, economic closure, reservations and cumulative budgets remain separate.
"""
import datetime
import hashlib
import json
import re
import stat
import time
from pathlib import Path

from .model import public_payload

PRODUCT_COMMIT='5e5994d3ab6844a443cef1e9d19a9195ed785486'
SERVICES={'captaind','watchmand'}


def _read(path):
    path=Path(path)
    if not path.is_absolute():raise ValueError('absolute original startup source path required')
    for part in (path,*path.parents):
        if stat.S_ISLNK(part.lstat().st_mode):raise ValueError('startup source symlink refused')
    with path.open('rb') as stream:
        before=stream.fileno()
        import os
        first=os.fstat(before)
        if not stat.S_ISREG(first.st_mode):raise ValueError('regular startup source required')
        raw=stream.read(2*1024*1024+1);last=os.fstat(before)
    if len(raw)>2*1024*1024:raise ValueError('startup source byte bound exceeded')
    if (first.st_dev,first.st_ino,first.st_size,first.st_mtime_ns)!=(last.st_dev,last.st_ino,last.st_size,last.st_mtime_ns):
        raise ValueError('startup source changed while reading')
    return json.loads(raw),hashlib.sha256(raw).hexdigest()


def _time_ns(value):
    if not isinstance(value,str):raise ValueError('original timestamp required')
    match=re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|\+00:00)',value)
    if not match:raise ValueError('UTC original timestamp required')
    base=datetime.datetime.fromisoformat(match[1]+'+00:00')
    return int(base.timestamp())*10**9+int((match[2] or '').ljust(9,'0'))


def _sha(value):
    if not isinstance(value,str) or re.fullmatch('[0-9a-f]{64}',value) is None:raise ValueError('exact source SHA256 required')
    return value


def _rate(value,unit,amount):
    return isinstance(value,str) and value.replace(' ','').lower()==str(amount)+unit


def verify_owned_startup_sources(store, startup_path, current_path, *, expected):
    """Bind original launch/current source files to explicit trusted release pins.

    Root owns capture and deployment. Required current fields are the original
    startup fields plus running, process_cmdline, process_exe_sha256,
    environment_names, config_path, config_ctime_ns, config_device, config_inode,
    container_config_sha256 and config_mount={source,destination,read_only}.
    The original observation and current observation must name the SAME live
    process. Current ctime/mtime before process start proves the file has not
    changed since Config::load, under the trusted-host/sole-writer model.
    """
    required={'product_commit','image_sha256','schema_sha256','database','containers','binary_sha256','config_sha256','config_paths'}
    if not isinstance(expected,dict) or set(expected)!=required or expected['product_commit']!=PRODUCT_COMMIT:
        raise ValueError('exact reviewed finite release declaration required')
    _sha(expected['schema_sha256'])
    if not isinstance(expected['image_sha256'],str) or not expected['image_sha256'].startswith('sha256:'):
        raise ValueError('exact expected image required')
    _sha(expected['image_sha256'][7:])
    for key in ('containers','binary_sha256','config_sha256','config_paths'):
        if not isinstance(expected[key],dict) or set(expected[key])!=SERVICES:raise ValueError('both declared daemon identities required')
    startup,startup_sha=_read(startup_path);current,current_sha=_read(current_path)
    for observation in (startup,current):
        if (observation.get('kind')!='owned_startup_source' or observation.get('product_commit')!=PRODUCT_COMMIT
                or not isinstance(observation.get('daemons'),dict) or set(observation['daemons'])!=SERVICES):
            raise ValueError('actual startup source release/schema/daemon scope differs')
        _sha(observation.get('schema_sha256'))
    if startup['schema_sha256']!=expected['schema_sha256']:
        raise ValueError('original pinned schema artifact differs')
    canonical_schema=current.get('canonical_schema')
    if canonical_schema is not None:
        if (not isinstance(canonical_schema,dict) or canonical_schema.get('protocol')!='pg-dump-restrict-lines-v1'
                or canonical_schema.get('removed_line_kinds')!=['restrict','unrestrict']
                or canonical_schema.get('sha256')!=canonical_schema.get('repeat_sha256')):
            raise ValueError('current canonical schema observation differs or is unstable')
        _sha(canonical_schema.get('sha256'))
    observed=_time_ns(current['observed_at']);original_at=_time_ns(startup['observed_at'])
    if not 0<=time.time_ns()-observed<=90*10**9 or original_at>observed:
        raise ValueError('fresh current startup observation required')
    verified={}
    for service in sorted(SERVICES):
        original=startup['daemons'][service];now=current['daemons'][service]
        paths=expected['config_paths'][service]
        if (not isinstance(paths,dict) or set(paths)!={'host','container'}
                or not all(isinstance(value,str) and value.startswith('/') for value in paths.values())):
            raise ValueError('explicit absolute host and container config paths required')
        _sha(expected['binary_sha256'][service]);_sha(expected['config_sha256'][service])
        pinned={'container':expected['containers'][service],'image_sha256':expected['image_sha256'],
            'binary_sha256':expected['binary_sha256'][service],'config_sha256':expected['config_sha256'][service]}
        if any(original.get(key)!=value or now.get(key)!=value for key,value in pinned.items()):
            raise ValueError('actual process artifact or configuration differs from declared release')
        if (type(original.get('pid')) is not int or original['pid']<=0 or now.get('pid')!=original['pid']
                or now.get('started_at')!=original.get('started_at') or now.get('restart_count')!=0
                or original.get('restart_count')!=0 or now.get('running') is not True):
            raise ValueError('original same running daemon process required')
        started=_time_ns(now['started_at'])
        if started>original_at:raise ValueError('original observation predates actual process')
        for key in ('config_ctime_ns','config_mtime_ns'):
            if type(now.get(key)) is not int or not 0<now[key]<=started:
                raise ValueError('config changed after daemon load or lacks original filesystem proof')
        if (original.get('config_mtime_ns')!=now['config_mtime_ns']
                or now.get('config_path')!=paths['host'] or now.get('container_config_sha256')!=pinned['config_sha256']
                or now.get('config_mount')!={'source':paths['host'],'destination':paths['container'],'read_only':True}
                or now.get('mount_read_only') is not True
                or type(now.get('config_device')) is not int or type(now.get('config_inode')) is not int
                or now['config_device']<0 or now['config_inode']<=0):
            raise ValueError('actual immutable mounted config identity incomplete')
        command=now.get('process_cmdline')
        if (not isinstance(command,list) or len(command)!=4 or Path(command[0]).name!=service
                or command[1:]!=['--config',paths['container'],'start']
                or now.get('process_exe_sha256')!=pinned['binary_sha256']
                or PRODUCT_COMMIT not in now.get('version','') or PRODUCT_COMMIT not in original.get('version','')):
            raise ValueError('actual running executable or config command differs')
        names=now.get('environment_names');overrides=now.get('config_overrides')
        if (not isinstance(names,list) or len(names)>256 or len(set(names))!=len(names)
                or any(not isinstance(name,str) or re.fullmatch('[A-Za-z_][A-Za-z_0-9]{0,127}',name) is None for name in names)
                or not isinstance(overrides,dict)):
            raise ValueError('complete bounded environment names required')
        relevant={name for name in names if name.upper().startswith(('CAPTAIND_','WATCHMAND_','BARK_SERVER_'))}
        if (relevant!=set(overrides) or any(name not in {'CAPTAIND_LOG','WATCHMAND_LOG'} or value!='info' for name,value in overrides.items())):
            raise ValueError('actual config environment override present or unobserved')
        config=now.get('public_loaded_config_provenance',{})
        if config.get('network')!='signet' or config.get('postgres_database')!=expected['database']:
            raise ValueError('actual loaded chain/database differs')
        if not _rate(config.get('fee_estimator',{}).get('max_fee_rate'),'sat/vb',20):
            raise ValueError('actual estimator ceiling differs')
        if service=='captaind':
            if (config.get('lightning_configured') is not False or config.get('vtxopool',{}).get('vtxo_targets')!=[]
                    or config.get('vtxo_lifetime')!=48 or config.get('round_interval')!='10m'
                    or config.get('required_board_confirmations')!=2 or config.get('direct_expiry',{}).get('enabled') is not True
                    or config.get('expiry_payout',{}).get('enabled') is not False):
                raise ValueError('actual finite Board/online Ark configuration differs')
        elif not _rate(config.get('watchman',{}).get('direct_expiry',{}).get('max_miner_fee'),'sat',10000):
            raise ValueError('actual direct carrier absolute fee ceiling differs')
        verified[service]={**pinned,'pid':now['pid'],'started_at':now['started_at'],
            'process_cmdline':command,'config_path':paths['host'],'config_mount':now['config_mount'],
            'config_device':now['config_device'],'config_inode':now['config_inode'],
            'config_ctime_ns':now['config_ctime_ns'],'config_mtime_ns':now['config_mtime_ns'],
            'environment_names':names,'config_overrides':overrides,'public_loaded_config_provenance':config}
    receipt={'kind':'owned_runtime_configuration_verified','product_commit':PRODUCT_COMMIT,
        'schema_sha256':expected['schema_sha256'],'startup_source_sha256':startup_sha,'current_source_sha256':current_sha,
        'current_schema_artifact_sha256':current['schema_sha256'],'current_canonical_schema':canonical_schema,
        'schema_identity_scope':'original pin identifies its immutable raw artifact; current canonical observation does not prove equality to an unavailable original canonical dump',
        'observed_at':observed/10**9,'daemons':verified,'loaded_configuration_identity_verified':True,
        'effective_fee_ceilings_sat_kvb':{'round':None,'pool':None,'sweep':20000,'payout':20000,'claim':None,'progression':None},
        'direct_carrier_max_miner_fee_sat':10000,'complete':False,'qualified':False,
        'scope':'trusted owned host same-process loaded configuration only; no treasury, cumulative budget, economic closure or financial readiness claim'}
    public_payload(receipt);store.event('owned_runtime_configuration_verified',receipt)
    return receipt

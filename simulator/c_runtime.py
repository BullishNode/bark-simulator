"""C systemd same-process configuration proof, within the common startup gate."""
import re
import time

from .model import public_payload

SERVICES={'captaind','watchmand'}


def verify(store,startup_path,current_path,*,expected,execution_release=None):
    from .runtime_startup import _read,_sha,_time_ns,_rate
    from .c_pilot import declaration
    pilot=declaration(store);pins=pilot['pins']
    from .c_execution_context import active
    context=active(store)
    if context is not None:
        if expected!=context['expected']:raise ValueError('actual C runtime expectations differ from activation')
        if execution_release is not None and execution_release!=context['execution_release']:
            raise ValueError('actual C runtime release differs from activation')
        execution_release=context['execution_release']
    product=execution_release['product_commit'] if execution_release is not None else pins['product_commit']
    schema=execution_release['schema_sha256'] if execution_release is not None else pins['schema_sha256']
    if (not isinstance(expected,dict) or set(expected)!={'architecture_profile','product_commit','schema_sha256','database','services'}
            or expected['architecture_profile']!='direct_per_key' or expected['product_commit']!=product
            or expected['schema_sha256']!=schema or expected['database']!='trackc'
            or not isinstance(expected['services'],dict) or set(expected['services'])!=SERVICES):
        raise ValueError('explicit exact C native startup expectations required')
    startup,startup_sha=_read(startup_path);current,current_sha=_read(current_path)
    if context is not None and startup_sha!=context['startup_source_sha256']:
        raise ValueError('C startup source differs from activated original capture')
    for frame in (startup,current):
        if (not isinstance(frame,dict) or frame.get('kind')!='owned_native_startup_source'
                or frame.get('architecture_profile')!='direct_per_key' or frame.get('runtime_transport')!='systemd'
                or frame.get('product_commit')!=product or frame.get('schema_sha256')!=schema
                or not isinstance(frame.get('daemons'),dict) or set(frame['daemons'])!=SERVICES):
            raise ValueError('actual C native release/schema/source differs')
    observed=_time_ns(current['observed_at']);original_at=_time_ns(startup['observed_at'])
    if not 0<=time.time_ns()-observed<=90*10**9 or original_at>observed:
        raise ValueError('fresh C current process observation required')
    verified={}
    for service in sorted(SERVICES):
        spec=expected['services'][service];original=startup['daemons'][service];now=current['daemons'][service]
        required={'unit','executable_path','executable_sha256','config_path','config_sha256','admin_address'}
        if (not isinstance(spec,dict) or set(spec)!=required
                or not isinstance(spec['unit'],str) or re.fullmatch(r'[a-zA-Z0-9_-]+\.service',spec['unit']) is None
                or any(not isinstance(spec[k],str) or not spec[k].startswith('/') for k in ('executable_path','config_path'))):
            raise ValueError('exact native service executable/config expectations required')
        _sha(spec['executable_sha256']);_sha(spec['config_sha256'])
        actual={'unit':spec['unit'],'process_exe_path':spec['executable_path'],
            'process_exe_sha256':spec['executable_sha256'],'binary_sha256':spec['executable_sha256'],
            'config_path':spec['config_path'],'config_sha256':spec['config_sha256']}
        if any(frame.get(k)!=v for frame in (original,now) for k,v in actual.items()):
            raise ValueError('actual native executable or config identity differs')
        if (type(original.get('pid')) is not int or original['pid']<=0
                or any(now.get(k)!=original.get(k) for k in ('pid','started_at','boot_id','start_ticks','invocation_id'))
                or not isinstance(now.get('boot_id'),str) or re.fullmatch('[0-9a-f-]{36}',now['boot_id']) is None
                or type(now.get('start_ticks')) is not int or now['start_ticks']<=0
                or not isinstance(now.get('invocation_id'),str) or re.fullmatch('[0-9a-f]{32}',now['invocation_id']) is None
                or any(frame.get('restart_count')!=0 or frame.get('running') is not True for frame in (original,now))):
            raise ValueError('original same native daemon process required')
        started=_time_ns(now['started_at'])
        if started>original_at:raise ValueError('original native observation predates process')
        for key in ('config_ctime_ns','config_mtime_ns','config_device','config_inode'):
            if type(now.get(key)) is not int or now[key]<0 or original.get(key)!=now[key]:
                raise ValueError('same native config filesystem identity required')
        if (not 0<now['config_ctime_ns']<=started or not 0<now['config_mtime_ns']<=started
                or now['config_inode']<=0):
            raise ValueError('native configuration changed after process load')
        pre=original.get('pre_exec_config')
        pre_fields={'path','sha256','device','inode','mtime_ns','ctime_ns','captured_at_ns','invocation_id'}
        if (not isinstance(pre,dict) or set(pre)!=pre_fields
                or pre['path']!=spec['config_path'] or pre['sha256']!=spec['config_sha256']
                or pre['invocation_id']!=now['invocation_id']
                or any(pre[k]!=now['config_'+k] for k in ('device','inode','mtime_ns','ctime_ns'))
                or type(pre['captured_at_ns']) is not int or not max(pre['mtime_ns'],pre['ctime_ns'])<=pre['captured_at_ns']<=started):
            raise ValueError('root original pre-exec native config provenance required')
        if (now.get('process_cmdline')!=[spec['executable_path'],'--config',spec['config_path'],'start']
                or now['process_cmdline']!=original.get('process_cmdline')
                or any(product not in frame.get('version','') for frame in (original,now))):
            raise ValueError('actual native command/release differs')
        names=now.get('environment_names');overrides=now.get('config_overrides')
        if (not isinstance(names,list) or len(names)>256 or len(set(names))!=len(names)
                or any(not isinstance(name,str) or re.fullmatch('[A-Za-z_][A-Za-z_0-9]{0,127}',name) is None for name in names)
                or not isinstance(overrides,dict)):
            raise ValueError('complete native config environment names required')
        relevant={name for name in names if name.upper().startswith(('CAPTAIND_','WATCHMAND_','BARK_SERVER_'))}
        if relevant!=set(overrides) or any(k not in {'CAPTAIND_LOG','WATCHMAND_LOG'} or v!='info' for k,v in overrides.items()):
            raise ValueError('native environment configuration override holds')
        cfg=now.get('public_loaded_config_provenance',{})
        if (cfg.get('network')!='signet' or cfg.get('postgres_database')!='trackc'
                or not _rate(cfg.get('fee_estimator',{}).get('max_fee_rate'),'sat/vb',20)):
            raise ValueError('actual native chain/database/estimator differs')
        if service=='captaind':
            if (cfg.get('vtxo_lifetime')!=48 or cfg.get('pool_lifetime_blocks')!=48
                    or cfg.get('required_board_confirmations')!=3
                    or cfg.get('direct_expiry',{}).get('enabled') is not True
                    or cfg.get('expiry_payout',{}).get('enabled') is not False
                    or cfg.get('lightning_configured') is not False or cfg.get('vtxopool',{}).get('vtxo_targets')!=[]):
                raise ValueError('C native pilot policy differs: 48-block lifetimes and 3 Board confirmations required')
        verified[service]={**now,'pre_exec_config':pre}
    receipt={'kind':'owned_runtime_configuration_verified','architecture_profile':'direct_per_key',
        'runtime_transport':'systemd','product_commit':product,'schema_sha256':schema,
        'startup_source_sha256':startup_sha,'current_source_sha256':current_sha,
        'current_schema_artifact_sha256':current['schema_sha256'],'observed_at':observed/10**9,
        'daemons':verified,'loaded_configuration_identity_verified':True,
        'effective_fee_ceilings_sat_kvb':{'round':None,'pool':None,'sweep':20000,'payout':20000,'claim':None,'progression':None},
        'complete':False,'qualified':False,
        'scope':'root-authenticated same native process and pre-exec configuration identity only; no treasury or financial admission'}
    if execution_release is not None:
        receipt.update(execution_release=execution_release,origin_financial_pins=pins)
    public_payload(receipt);store.event('owned_runtime_configuration_verified',receipt)
    return receipt

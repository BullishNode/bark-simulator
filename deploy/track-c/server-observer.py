#!/usr/bin/env python3
"""Track C native systemd read-only observer. Root installs and activates it.

The request cannot select a host, executable, SQL statement or RPC method.
Declaration pins are assertions; runtime and wallet observations remain separate.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

import public_observer as public

MANIFEST = Path('/etc/track-c/deployment-public.json')
GENESIS = '00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6'
SERVICES = {'captaind','watchmand'}
RUNTIME_FIELDS = {'unit','pid','started_at','restart_count','running','binary_sha256',
    'process_exe_path','process_exe_sha256','process_cmdline','version',
    'config_path','config_sha256','config_ctime_ns','config_mtime_ns',
    'config_device','config_inode','environment_names','config_overrides','boot_id','start_ticks','invocation_id','pre_exec_config'}


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


def validate_manifest(value):
    if isinstance(value,dict) and 'operating_projection' in value:
        binding=value['operating_projection']
        if(not isinstance(binding,dict) or set(binding)!={'c_runtime_profile.py','model.py','bip39-english.txt'}):
            raise ValueError('exact public C operating projection source package required')
        for digest in binding.values():public.public_hash(digest)
        validate_manifest({key:item for key,item in value.items() if key!='operating_projection'})
        return value
    required={'schema_version','track','architecture_profile','active','deployment_id',
              'genesis','financial_pins','observer_files','ops','services'}
    if (not isinstance(value,dict) or set(value)!=required or type(value['schema_version']) is not int
            or value['schema_version']!=1 or value['track']!='C'
            or value['architecture_profile']!='direct_per_key' or value['active'] is not True
            or value['genesis']!=GENESIS or not isinstance(value['deployment_id'],str)
            or re.fullmatch('[a-zA-Z0-9_-]{1,100}',value['deployment_id']) is None):
        raise ValueError('active exact C deployment declaration required')
    pins=value['financial_pins']
    lengths={'product_commit':40,'sdk_commit':40,'driver_sha256':64,'configuration_sha256':64,'schema_sha256':64}
    if (not isinstance(pins,dict) or set(pins)!=set(lengths)
            or any(not isinstance(pins[k],str) or re.fullmatch('[0-9a-f]{'+str(n)+'}',pins[k]) is None for k,n in lengths.items())):
        raise ValueError('exact C financial pins required')
    if set(value['observer_files'])!={'server-observer.py','public_observer.py'}:
        raise ValueError('both exact observer source hashes required')
    for digest in value['observer_files'].values():public.public_hash(digest)
    ops=value['ops']
    if (not isinstance(ops,dict) or set(ops)!={'path','sha256'}
            or not isinstance(ops['path'],str) or not ops['path'].startswith('/opt/track-c/')):
        raise ValueError('declared C root-owned ops path required')
    public.public_hash(ops['sha256'])
    if not isinstance(value['services'],dict) or set(value['services'])!=SERVICES:
        raise ValueError('both declared native services required')
    for service,row in value['services'].items():
        if (not isinstance(row,dict) or set(row)!={'unit','executable_path','executable_sha256','config_path','config_sha256','admin_address'}
                or not isinstance(row['unit'],str) or re.fullmatch(r'[a-zA-Z0-9_-]+\.service',row['unit']) is None
                or any(not isinstance(row[k],str) or not row[k].startswith('/') for k in ('executable_path','config_path'))
                or not isinstance(row['admin_address'],str) or re.fullmatch(r'127\.0\.0\.1:[0-9]{1,5}',row['admin_address']) is None):
            raise ValueError('explicit native service artifact/config/admin scope required')
        public.public_hash(row['executable_sha256']);public.public_hash(row['config_sha256'])
    if value['services']['captaind']['admin_address']!='127.0.0.1:3536':
        raise ValueError('C captaind admin target differs')
    return value


def installed_manifest():
    raw,digest=checked_file(MANIFEST,maximum=65536)
    value=validate_manifest(json.loads(raw))
    for name,expected in value['observer_files'].items():
        if checked_file(Path(__file__).absolute().with_name(name))[1]!=expected:
            raise ValueError('installed observer differs from active declaration')
    if checked_file(value['ops']['path'])[1]!=value['ops']['sha256']:
        raise ValueError('installed native ops differs from active declaration')
    return value,digest


def transport(manifest,*args):
    if not args:raise ValueError('fixed ops verb required')
    verb=args[0]
    if verb=='sql':
        if len(args)!=2 or len(args[1])>65536 or not re.match(r'^BEGIN(?: ISOLATION LEVEL REPEATABLE READ)? READ ONLY;',args[1]):
            raise ValueError('fixed read-only SQL required')
    elif verb=='cli':
        if len(args)<2 or args[1] not in {'getblockchaininfo','getblockhash','getdescriptorinfo','decoderawtransaction'}:
            raise ValueError('fixed read-only Core operation required')
        if (args[1]=='getblockchaininfo' and len(args)!=2
                or args[1]=='getblockhash' and args[2:]!=('0',)
                or args[1] in {'getdescriptorinfo','decoderawtransaction'} and len(args)!=3):
            raise ValueError('fixed Core argument scope required')
    elif verb in {'runtime-identity','public-config'}:
        if len(args)!=2 or args[1] not in SERVICES:raise ValueError('fixed native service required')
    elif verb=='wallet-inventory':
        if len(args)!=2 or args[1] not in {'rounds','watchman'}:raise ValueError('fixed wallet owner required')
    elif verb=='logs':
        if len(args)!=6 or args[1] not in SERVICES:raise ValueError('fixed bounded log scope required')
    else:raise ValueError('unsupported native ops verb')
    return public.run([manifest['ops']['path'],*args])


def runtime(service,manifest):
    value=json.loads(public.ops('runtime-identity',service))
    expected=manifest['services'][service]
    if (not isinstance(value,dict) or set(value) not in (RUNTIME_FIELDS,RUNTIME_FIELDS|{'public_loaded_config_provenance'})
            or value['unit']!=expected['unit'] or value['process_exe_path']!=expected['executable_path']
            or value['process_exe_sha256']!=expected['executable_sha256'] or value['binary_sha256']!=expected['executable_sha256']
            or value['config_path']!=expected['config_path'] or value['config_sha256']!=expected['config_sha256']
            or value['process_cmdline']!=[expected['executable_path'],'--config',expected['config_path'],'start']
            or type(value['pid']) is not int or value['pid']<=0 or type(value['restart_count']) is not int
            or type(value['running']) is not bool):
        raise ValueError('actual native process differs from declaration')
    names=value['environment_names'];overrides=value['config_overrides']
    if (not isinstance(names,list) or len(names)>256 or len(set(names))!=len(names)
            or any(not isinstance(name,str) or re.fullmatch('[A-Za-z_][A-Za-z_0-9]{0,127}',name) is None for name in names)
            or not isinstance(overrides,dict) or any(k not in {'CAPTAIND_LOG','WATCHMAND_LOG'} or v!='info' for k,v in overrides.items())):
        raise ValueError('public native environment names/log levels only')
    pre=value['pre_exec_config']
    if (not isinstance(pre,dict) or set(pre)!={'path','sha256','device','inode','mtime_ns','ctime_ns','captured_at_ns','invocation_id'}
            or pre['path']!=expected['config_path'] or pre['sha256']!=expected['config_sha256']
            or pre['invocation_id']!=value['invocation_id']):
        raise ValueError('public original pre-exec configuration scope differs')
    value.pop('public_loaded_config_provenance',None)
    return value


def wallet(owner,network):
    value=json.loads(public.ops('wallet-inventory',owner))
    public.validate_wallet_frame(value,owner,network)
    return value


def config(service):
    value=json.loads(public.ops('public-config',service))
    allowed={'sha256','network','postgres_database','vtxo_lifetime','pool_lifetime_blocks',
        'min_trusted_confs','round_interval','required_board_confirmations','fee_estimator',
        'watchman','direct_expiry','expiry_payout','lightning_configured','vtxopool','operating_source'}
    if not isinstance(value,dict) or set(value)-allowed or 'sha256' not in value:
        raise ValueError('allowlisted public config only')
    public.public_hash(value['sha256'])
    def public_only(item):
        if isinstance(item,dict):
            if any(not isinstance(k,str) or re.search(r'secret|password|private|credential|mnemonic|preimage|authorization|rpc_pass',k,re.I) for k in item):
                raise ValueError('private nested configuration field refused')
            for nested in item.values():public_only(nested)
        elif isinstance(item,list):
            if len(item)>2000:raise ValueError('public config array bound exceeded')
            for nested in item:public_only(nested)
        elif isinstance(item,str) and (len(item)>4096 or re.search(r'xprv|tprv',item)):
            raise ValueError('private or unbounded configuration value refused')
    public_only(value)
    return value


def snapshot(manifest):
    before=json.loads(public.ops('cli','getblockchaininfo'))
    identities={service:runtime(service,manifest) for service in sorted(SERVICES)}
    configs={service:config(service) for service in sorted(SERVICES)}
    for service in SERVICES:
        if configs[service]['sha256']!=identities[service]['config_sha256']:
            raise ValueError('actual public config identity differs')
        identities[service]['public_loaded_config_provenance']={k:v for k,v in configs[service].items() if k!='sha256'}
    genesis=public.ops('cli','getblockhash','0').strip().strip('"')
    ending=json.loads(public.ops('cli','getblockchaininfo'))
    if genesis!=GENESIS or ending.get('chain')!='signet':raise ValueError('actual C chain differs')
    cap=identities['captaind'];cfg=configs['captaind']
    return {'kind':'snapshot','observed_at':time.time(),'network':'signet','genesis':genesis,
        'height':ending['blocks'],'tip_hash':ending['bestblockhash'],
        'stable_tip':before['bestblockhash']==ending['bestblockhash'],
        'initial_block_download':ending['initialblockdownload'],
        'runtime_transport':'systemd','native_runtime':identities,'disk_config':configs,
        # Compatibility field names identify a systemd unit/executable digest;
        # runtime_transport makes their native meaning explicit to consumers.
        'container':cap['unit'],'server_status':{'status':'running' if cap['running'] else 'stopped',
            'restarts':cap['restart_count'],'image_digest':'sha256:'+cap['process_exe_sha256']},
        'wallet':None,'wallet_inventory_complete':False,
        'wallet_scope':'owning runtime wallet-inventory is a separate read-only source',
        'timings':cfg.get('expiry_payout',{}),'direct_expiry_enabled':cfg.get('direct_expiry',{}).get('enabled'),
        'lightning_configured':cfg.get('lightning_configured'),
        'complete':False,'qualified':False}


def collect(kind,after,manifest):
    if kind=='closed_frontier':return public.closed_frontier()
    if kind=='direct_journal':return public.direct_journal()
    if kind=='claimant_inventory':return public.claimant_inventory()
    if kind=='snapshot':return snapshot(manifest)
    if kind=='financial_readiness':
        base=snapshot(manifest);frames={}
        for owner in ('rounds','watchman'):
            try:frames[owner]={'available':True,'source':wallet(owner,'signet')}
            except Exception as error:frames[owner]={'available':False,'missing_source':owner+'_inventory_'+type(error).__name__}
        return {**base,'kind':'financial_readiness','runtime_wallet_inventory':{'frames':frames,
            'owning_sources_available':all(v['available'] for v in frames.values())},
            'candidate_inventory':public.claimant_inventory(),'effective_fee_ceilings_sat_kvb':None,
            'capital_exposure_msat':None,'available_fee_funding_msat':None,'budget_remaining_msat':None,
            'pool_ready':None,'channel_route_ready':None,
            'gaps':['independent_loaded_runtime_receipt','resolved_ownership_and_backing','treasury_budget_and_reservations','lightning_readiness'],
            'validation_scope':'original public native facts only; declaration pins do not qualify dispatch'}
    if kind in {'coins','pending','links','records','nursery'}:return public.page(kind,after)
    raise ValueError('C operation source not implemented; retain coverage hold')


def main():
    manifest,digest=installed_manifest()
    public.DEPLOY=Path('/opt/track-c/runtime')
    public.READ_DEADLINE=time.monotonic()+25
    public.ops=lambda *args:transport(manifest,*args)
    kind,after=public.request(sys.stdin.buffer.read(4097))
    result=collect(kind,after,manifest)
    result.update(architecture_profile='direct_per_key',fallback_protocol=4,
        deployment_declaration_sha256=digest,deployment_id=manifest['deployment_id'],
        declared_financial_pins=manifest['financial_pins'])
    encoded=json.dumps(result,allow_nan=False)
    if len(encoded.encode())>public.MAX_BYTES:raise ValueError('whole response exceeds byte bound')
    print(encoded)


if __name__=='__main__':
    try:main()
    except Exception:
        print('read-only C native observation unavailable',file=sys.stderr);sys.exit(1)

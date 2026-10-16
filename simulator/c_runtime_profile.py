"""Typed C full-normal configuration source, never financial qualification.

The fixed root ops may call project() after authenticating the actual loaded
configuration file. Only public certificates are read through its existing
protected reader. Private keys, endpoints, credentials and file paths are not
exported. The normal collector still proves membership, budgets and ownership.
"""
import hashlib
import re
from urllib.parse import urlsplit

from .model import canonical, integer, public_payload

CAPS = ('max_vtxo_amount','max_board_amount','max_offboard_amount','max_arkoor_amount',
        'max_ln_send_amount','max_ln_receive_amount','max_round_amount')


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def _sha(value):
    if not isinstance(value,str) or re.fullmatch('[0-9a-f]{64}',value) is None:
        raise ValueError('exact C operating source hash required')
    return value


def _sat(value):
    # Source restriction only: deployment must use explicit integer sat units.
    # This does not replace or broaden the native amount parser.
    if not isinstance(value,str) or re.fullmatch(r'(0|[1-9][0-9]*) ?sat',value) is None:
        raise ValueError('explicit canonical integer sat native configuration required')
    amount=int(value.split('sat')[0].strip())
    if amount>21_000_000*100_000_000:
        raise ValueError('native configured amount exceeds money bound')
    return amount


def _connection(value,read_certificate):
    if not isinstance(value,dict):
        raise ValueError('actual native TLS connection configuration required')
    uri=value.get('uri');parsed=urlsplit(uri) if isinstance(uri,str) else None
    if (parsed is None or parsed.scheme!='https' or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment):
        raise ValueError('actual native HTTPS mutual TLS connection required')
    if parsed.port is not None and not 1<=parsed.port<=65535:
        raise ValueError('actual native TLS port differs')
    certificates={}
    for role,key in (('server','server_cert_path'),('client','client_cert_path')):
        # Never touch client_key_path. Root's reader already enforces fixed
        # config ownership, no symlinks and bounded stable file descriptors.
        raw,facts=read_certificate(value[key],65536)
        if (not isinstance(raw,bytes) or len(raw)>65536 or b'-----BEGIN CERTIFICATE-----' not in raw
                or b'PRIVATE KEY' in raw or facts.get('sha256')!=hashlib.sha256(raw).hexdigest()):
            raise ValueError('actual public TLS certificate source required')
        selected={k:facts[k] for k in ('sha256','device','inode','mtime_ns','ctime_ns')}
        _sha(selected['sha256'])
        for key in ('device','inode','mtime_ns','ctime_ns'):
            integer(selected[key],'public certificate filesystem identity')
        certificates[role]=selected
    return {'uri_sha256':hashlib.sha256(uri.encode()).hexdigest(),'certificates':certificates}


def _targets(values):
    if not isinstance(values,list) or not 1<=len(values)<=100:
        raise ValueError('actual bounded positive native pool targets required')
    targets=[]
    for raw in values:
        if not isinstance(raw,str) or raw.count(':')!=1:
            raise ValueError('actual native pool amount:count target required')
        amount,count=raw.split(':')
        if re.fullmatch('[1-9][0-9]*',count) is None:
            raise ValueError('positive native pool target count required')
        targets.append({'amount_sat':_sat(amount),'count':int(count)})
    return targets


def project(cfg,service,read_certificate):
    """Pure config projection with a fixed-ops public-certificate reader seam."""
    if service=='watchmand':
        direct=cfg['watchman']['direct_expiry']
        policy=direct['ordinary_fee_policy']
        if set(policy)!={'ordinary_budget_sat','urgent_reserve_sat'} or any(type(v)is not int for v in policy.values()):
            raise ValueError('explicit native ordinary fee policy required')
        result={'direct_max_miner_fee_sat':_sat(direct['max_miner_fee']),
            'ordinary_fee_policy':dict(policy)}
    elif service=='captaind':
        amounts={key:_sat(cfg[key]) for key in CAPS}
        targets=_targets(cfg['vtxopool']['vtxo_targets'])
        connections=[]
        for node in cfg['cln_array']:
            connection=_connection(node,read_certificate)
            connection['priority']=integer(node['priority'],'actual CLN priority')
            connection['hold_invoice']=None if node.get('hold_invoice') is None else _connection(node['hold_invoice'],read_certificate)
            connections.append(connection)
        result={'amount_caps_sat':amounts,'min_board_sat':_sat(cfg['min_board_amount']),
            'pool_targets':targets,'pool_pre_expiry_blocks':cfg['vtxopool']['vtxo_pre_expiry'],
            'lightning_connections':connections}
    else:
        raise ValueError('named C native service required')
    public_payload(result)
    return result


def validate(profile):
    fields={'schema_version','mode','operating_source_sha256','lightning_context_sha256','node_ids','ordinary_fee_policy_sha256'}
    if (not isinstance(profile,dict) or set(profile)!=fields or type(profile['schema_version'])is not int
            or profile['schema_version']!=1 or profile['mode']!='fullnormal_sources'
            or not isinstance(profile['operating_source_sha256'],dict)
            or set(profile['operating_source_sha256'])!={'captaind','watchmand'}
            or not isinstance(profile['node_ids'],dict) or set(profile['node_ids'])!={'operator','fixture_peer'}
            or len(set(profile['node_ids'].values()))!=2):
        raise ValueError('explicit typed C fullnormal source profile required')
    for sha in [*profile['operating_source_sha256'].values(),profile['lightning_context_sha256'],profile['ordinary_fee_policy_sha256']]:_sha(sha)
    for key in profile['node_ids'].values():
        if not isinstance(key,str) or re.fullmatch('0[23][0-9a-f]{64}',key)is None:
            raise ValueError('two actual owned compressed CLN identities required')
    public_payload(profile)
    return profile


def verify_loaded(cfg,profile,service,*,started_ns):
    validate(profile)
    source=cfg.get('operating_source')
    if not isinstance(source,dict) or digest(source)!=profile['operating_source_sha256'][service]:
        raise ValueError('actual C operating config source differs from immutable declaration')
    if service=='watchmand':
        if (set(source)!={'direct_max_miner_fee_sat','ordinary_fee_policy'}
                or type(source['direct_max_miner_fee_sat'])is not int or source['direct_max_miner_fee_sat']!=20000
                or source['ordinary_fee_policy']!={'ordinary_budget_sat':58000,'urgent_reserve_sat':40000}
                or any(type(v)is not int for v in source['ordinary_fee_policy'].values())):
            raise ValueError('original C direct fee cap and immutable allowance/reserve required')
        return source
    if (set(source)!={'amount_caps_sat','min_board_sat','pool_targets','pool_pre_expiry_blocks','lightning_connections'}
            or set(source['amount_caps_sat'])!=set(CAPS) or cfg.get('lightning_configured')is not True
            or type(source['min_board_sat'])is not int or source['min_board_sat']<=0
            or type(source['pool_pre_expiry_blocks'])is not int or source['pool_pre_expiry_blocks']<0):
        raise ValueError('complete actual fullrail C native capability source required')
    for key,amount in source['amount_caps_sat'].items():
        integer(amount,'native operation amount cap')
        if key not in {'max_offboard_amount','max_round_amount'} and amount<=0:
            raise ValueError('actual declared Ark and both LN directions must be enabled')
    targets=source['pool_targets']
    if (not isinstance(targets,list) or not 1<=len(targets)<=100
            or len({canonical(v)for v in targets})!=len(targets)
            or targets!=_targets(cfg.get('vtxopool',{}).get('vtxo_targets'))):
        raise ValueError('positive bounded actual pool target source required')
    count=0
    for target in targets:
        if set(target)!={'amount_sat','count'}:
            raise ValueError('actual native pool target shape differs')
        integer(target['amount_sat'],'native pool amount',1);integer(target['count'],'native pool count',1);count+=target['count']
    if count>2000:
        raise ValueError('native pool target exceeds existing bounded discovery scope')
    connections=source['lightning_connections']
    if not isinstance(connections,list) or not 1<=len(connections)<=8:
        raise ValueError('actual owned native CLN TLS connection source required')
    for connection in connections:
        if set(connection)!={'uri_sha256','certificates','priority','hold_invoice'}:
            raise ValueError('native TLS binding fields differ')
        integer(connection['priority'],'native CLN priority')
        if connection['hold_invoice']is None:
            raise ValueError('actual LN receive hold-invoice transport source required')
        if not isinstance(connection['hold_invoice'],dict) or set(connection['hold_invoice'])!={'uri_sha256','certificates'}:
            raise ValueError('actual hold-invoice public TLS fields differ')
        for endpoint in (connection,connection['hold_invoice']):
            _sha(endpoint['uri_sha256'])
            if set(endpoint['certificates'])!={'server','client'}:
                raise ValueError('both public mutual TLS certificate originals required')
            for certificate in endpoint['certificates'].values():
                if set(certificate)!={'sha256','device','inode','mtime_ns','ctime_ns'}:
                    raise ValueError('public certificate metadata source differs')
                _sha(certificate['sha256'])
                for key in ('device','inode','mtime_ns','ctime_ns'):integer(certificate[key],'actual public certificate metadata')
                if certificate['inode']<=0 or not 0<max(certificate['mtime_ns'],certificate['ctime_ns'])<=started_ns:
                    raise ValueError('TLS certificate changed after actual native process load')
    return source

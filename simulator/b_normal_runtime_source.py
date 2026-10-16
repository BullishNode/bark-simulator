"""B-owned read-only runtime provenance; never emits treasury readiness.

The root operator admits an exact expected artifact manifest and saves a pre-start
checkpoint. Capture runs on the owned target as root. No service, wallet, lock or
journal is changed. A separate financial verifier authenticates retained versions,
actual fees and whole-input urgent reserve from independent sources.
"""
import hashlib
import ipaddress
import contextvars
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time
import types
import tomllib
from decimal import Decimal

from .frontier_source import checked_file
from .runtime_startup import _sha, _time_ns

SERVICES = ('captaind', 'watchmand')
PINS = ('product_commit', 'sdk_commit', 'driver_sha256', 'configuration_sha256', 'schema_sha256')
LOAD_GATES = {'server/src/lib.rs': 'cc98d24d38b0ca0a380dd9f5a44d41ed58b5ffb64ab4d7c41df92356ee6b3596',
 'server/src/payout_witness.rs': 'cf2c725908cea206b24d13f00d93b155827566f6e00c3d9f29548f11cf0279e4',
 'server/src/watchman/daemon.rs': '63b8d12b5f6dbd8ead363135de3337309a798ea2c241c658f7b10278a61070bb',
 'server/src/watchman/expiry_runtime.rs': 'e97479e7248de051b2d82fa2d9f429498c13bd6bda192ed1b5ef3ade738bc120',
 'server/src/watchman/ordinary_fee.rs': '61a604e7ba1bc3c307d8dec78b2cda33d3c07d935e704248620a19c222a3f23b',
 'server/src/watchman/ordinary_fee_snapshot.rs': 'f1bb857d83eb467c1815b678941747b7a6ef63f6c818faae479fd4ba5812ddee',
 'server/src/watchman/funding_owner.rs': 'd0812b7bf8b6b63defa9a547514ced8059677683030d8ea8a4204ab33219ea85',
 'server/src/rpcserver/admin.rs': '5c11b0c02d6d7eb937e730b1084a9aac9cb8dfd1aead5c14dffeeccb3c27171b',
 'server/src/watchman/urgent.rs': '41bb64748f73806785342975cb1537287b1de202b7334db56ba15e8a37c5f68e'}
BUDGET_HELPER_SHA256 = 'a21adb02d3f0033ecf82dea1562e53bd9e46856388f009c56ae6ce8c37d25827'
MAX_CAPTURE_NS = 60*10**9
MAX_PROCESS_ENTRIES = 16384
MAX_EXECUTABLE_BYTES = 768*1024*1024
_CAPTURE_END = contextvars.ContextVar('b_runtime_capture_end', default=None)
BUDGET_FILES = ('ordinary-fee-policy.json', 'ordinary-fee-opening.json', 'ordinary-fee-budget')


def _require_time(reserve=0):
    end = _CAPTURE_END.get()
    if end is not None and time.monotonic()+reserve >= end:
        raise ValueError('aggregate runtime capture deadline exceeded')
    return end


def digest(value):
    return hashlib.sha256(value).hexdigest()


def identity(value):
    return digest(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode())


def _expected(value):
    required = {'execution_release', 'containers', 'binary_sha256', 'config_sha256',
                'config_paths', 'data_mount', 'budget_helper_path', 'budget_helper_sha256',
                'accounting_receipt_path', 'load_gate_sources', 'driver_artifact_sha256',
                'postgres_container', 'database', 'canonical_schema_sha256'}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError('exact reviewed B runtime artifact declaration required')
    release = value['execution_release']
    if set(release) != {*PINS, 'image_sha256'}:
        raise ValueError('all paired financial/runtime pins required')
    for name in ('product_commit', 'sdk_commit'):
        if not re.fullmatch('[0-9a-f]{40}', release[name]):
            raise ValueError('immutable product/SDK commit required')
    for name in PINS[2:]:
        _sha(release[name])
    if release['image_sha256'] != 'sha256:' + _sha(release['image_sha256'].removeprefix('sha256:')):
        raise ValueError('exact image digest required')
    if value['driver_artifact_sha256'] != release['driver_sha256']:
        raise ValueError('actual paired driver artifact differs')
    if value['load_gate_sources'] != LOAD_GATES:
        raise ValueError('reviewed mandatory-load-before-admin source required')
    for name in ('containers', 'binary_sha256', 'config_sha256', 'config_paths'):
        if set(value[name]) != set(SERVICES):
            raise ValueError('both owned daemons required')
    for service in SERVICES:
        if not re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}', value['containers'][service]):
            raise ValueError('fixed owned container required')
        _sha(value['binary_sha256'][service]); _sha(value['config_sha256'][service])
        paths = value['config_paths'][service]
        if set(paths) != {'host', 'container'}:
            raise ValueError('exact config mount required')
        for path in paths.values():
            _path(path)
    for name in ('postgres_container', 'database'):
        if not re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}', value[name]):
            raise ValueError('fixed owned schema source required')
    _sha(value['canonical_schema_sha256'])
    _sha(value['budget_helper_sha256'])
    if value['budget_helper_sha256'] != BUDGET_HELPER_SHA256:
        raise ValueError('reviewed schema-2 native disk reader required')
    _path(value['budget_helper_path']); _path(value['accounting_receipt_path'])
    if set(value['data_mount']) != {'source', 'destination'} or value['data_mount']['destination'] != '/data/captaind':
        raise ValueError('exact shared owned history mount required')
    _path(value['data_mount']['source'])
    return value


def _path(value):
    if not isinstance(value, str) or not value.startswith('/') or '..' in Path(value).parts or str(Path(value)) != value:
        raise ValueError('canonical absolute fixed source path required')
    return value


def history_txids(raw, prefix):
    if (type(raw) is not bytes or len(raw) > 650000 or len(raw) % 65
            or type(prefix) is not int or not 0 <= prefix <= len(raw) or prefix % 65):
        raise ValueError('canonical bounded native history/prefix required')
    rows = [raw[n:n+65] for n in range(0, len(raw), 65)]
    if any(re.fullmatch(b'[0-9a-f]{64}\\n', row) is None for row in rows):
        raise ValueError('canonical native transaction history required')
    txids = [row[:-1].decode('ascii') for row in rows]
    if len(set(txids)) != len(txids): raise ValueError('duplicate native history transaction')
    return txids









POLICY_PRODUCT_COMMIT = '15e4fd7085802ba5f7b1d9a2c87aab7277d5a7e4'
POLICY_SOURCE_SHA256 = {'server/src/config.rs': 'b5880d6210721f4ee080000cbb6e2187b1173c6e190f24e427cbc8b3fc70f344',
 'server/src/watchman/config.rs': 'c1737bfeb783cbcc7eccecf525491953a5ccc635ddec3f2b38812e24ecb38bdd',
 'server/src/utils/serde.rs': '1a47258d50814a23914321e689ff8283e58c34bf71500babf0f8fb1a0ea944ee',
 'server/src/fee_estimator.rs': '7c4dc5dd37aa046048388555b53baced74d1009e167c7854b822653f36179cfe',
 'server/src/vtxopool.rs': '93374601830777ce15ed8a10e86ac11f9a06f0c2ad085d78cbd7801fa3e63bed',
 'server/src/expiry_dispatch.rs': 'b76668ade7329a3d00d9a68570bf42448174cd9f46ad4131bdddee2234ba0604',
 'server/src/expiry_payout.rs': '9481d1745718232985592fd0b1ed2e5725dd15b0f7e113a9ea31bcbdee3bf05b',
 'server/src/wallet/mod.rs': '0481a86aff6a7cfa2c9d1a46b47c35b8236f4d486194522f5364dad61171d4a7',
 'server/src/watchman/carrier.rs': '5ed4ce9606ba16ec69870d6ea17f8d3891e1d6d5aae3e196c63dba4193fb4843',
 'server/src/watchman/urgent.rs': '41bb64748f73806785342975cb1537287b1de202b7334db56ba15e8a37c5f68e',
 'server/src/ln/mod.rs': 'b71f1d4297b66305ee88d75f9f28bdfb02f4f173588dc90252699e812f0a49b6'}


def _public_uint(value, maximum=2**64-1):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError('bounded public native policy integer required')
    return value


def _public_rate(value):
    if value is None: return None  # Native Option::None is NO finite ceiling.
    if not isinstance(value, str): raise ValueError('native string fee rate required')
    match = re.fullmatch(r'([0-9]{1,20})\s*(sat/kwu|sat/kvb|sat/vb)', value)
    if not match: raise ValueError('supported native fee-rate encoding required')
    amount = _public_uint(int(match[1]))
    return _public_uint(amount*250 if match[2] == 'sat/vb' else (amount+3)//4 if match[2] == 'sat/kvb' else amount)


def _public_amount(value):
    # Deliberately support only these actual native config encodings. Unknown
    # denominations fail closed rather than pretending a public ceiling exists.
    if not isinstance(value, str): raise ValueError('native string amount required')
    match = re.fullmatch(r'([0-9]+(?:\.[0-9]{1,8})?)\s*(sat|sats|BTC|btc)', value)
    if not match: raise ValueError('supported native amount encoding required')
    amount = Decimal(match[1]) * (100_000_000 if match[2].lower() == 'btc' else 1)
    if amount != amount.to_integral_value(): raise ValueError('whole satoshi policy amount required')
    return _public_uint(int(amount), 21_000_000*100_000_000)


def _public_ordinary(value):
    if not isinstance(value, dict) or set(value) != {'urgent_reserve_sat','ordinary_budget_sat','external_future_reserved_sat','opening_sha256'}:
        raise ValueError('explicit adopted native fee policy required')
    result = {key:_public_uint(value[key],21_000_000*100_000_000) for key in ('urgent_reserve_sat','ordinary_budget_sat','external_future_reserved_sat')}
    if not result['urgent_reserve_sat'] or not result['ordinary_budget_sat'] or result['external_future_reserved_sat'] > result['ordinary_budget_sat']:
        raise ValueError('invalid native ordinary policy amounts')
    result['opening_sha256'] = _sha(value['opening_sha256'])
    if result['opening_sha256'] == '0'*64: raise ValueError('original adopted opening required')
    return result



def _socket_address(value):
    # This owned bridge deployment uses explicit native IPv4 SocketAddr values.
    # Unknown/DNS/IPv6 forms remain unqualified here, not relabelled reachable.
    if not isinstance(value,str)or value.count(':')!=1:
        raise ValueError('explicit owned IPv4 admin socket required')
    address,port=value.split(':')
    address=str(ipaddress.IPv4Address(address))
    if not re.fullmatch('[1-9][0-9]{0,4}',port)or not 0<int(port)<=65535:
        raise ValueError('bounded owning admin port required')
    return {'address':address,'port':int(port)}


def _network_identity(container):
    rows=container['NetworkSettings']['Networks']
    if not isinstance(rows,dict)or len(rows)>32:raise ValueError('owned network inventory bound')
    result=[]
    for network in rows.values():
        ip=network.get('IPAddress')
        if ip:
            result.append({'network_id':_sha(network['NetworkID']),
                           'address':str(ipaddress.IPv4Address(ip))})
    return sorted(result,key=lambda row:(row['network_id'],row['address']))


def _listener(raw,fd_links,*,address,port):
    if not isinstance(raw,bytes)or len(raw)>2*1024*1024 or len(fd_links)>4096:
        raise ValueError('bounded owning listener inventory required')
    target=ipaddress.IPv4Address(address);matches=[]
    for row in raw.decode('ascii').splitlines()[1:]:
        fields=row.split()
        if len(fields)<10:raise ValueError('malformed kernel listener row')
        encoded,encoded_port=fields[1].split(':')
        actual=ipaddress.IPv4Address(int.from_bytes(bytes.fromhex(encoded),'little'))
        if fields[3]!='0A'or actual!=target or int(encoded_port,16)!=port:continue
        inode=int(fields[9])
        descriptors=[fd for fd,link in fd_links.items()if link=='socket:['+str(inode)+']']
        if len(descriptors)==1:matches.append({'fd':descriptors[0],'inode':inode,'tcp_table_sha256':digest(raw)})
    if len(matches)!=1:raise ValueError('one actual watch-owned listening socket required')
    return matches[0]


def _verify_owner_route(daemons,route):
    cap=daemons['captaind'];watch=daemons['watchmand']
    destination=cap['public_configuration']['native_funding_owner_address']
    listener=watch['public_configuration']['admin_address']
    if (destination['port']!=3538 or listener['port']!=3538
            or route['cap_pid']!=cap['pid']or route['watch_pid']!=watch['pid']
            or route['destination']!=destination or route['listener']!=listener):
        raise ValueError('configured native owner route/actual process differs')
    namespaces=route['network_namespaces']
    if set(namespaces)!=set(SERVICES)or any(re.fullmatch(r'net:\[[1-9][0-9]*\]',v)is None for v in namespaces.values()):
        raise ValueError('actual owning network namespace required')
    same=namespaces['captaind']==namespaces['watchmand']
    address=destination['address'];bound=listener['address']
    if same and ipaddress.IPv4Address(address).is_loopback:
        if bound not in ('0.0.0.0',address)or route['shared_network_id']is not None:
            raise ValueError('same-namespace owning listener differs')
    else:
        network=route['shared_network_id'];_sha(network)
        if (bound!='0.0.0.0'or ipaddress.IPv4Address(address).is_loopback
                or not any(n['network_id']==network for n in cap['networks'])
                or {'network_id':network,'address':address}not in watch['networks']):
            raise ValueError('cap route does not reach owning watch service on shared network')
    socket=route['watch_listener']
    if (type(socket['fd'])is not int or socket['fd']<0 or type(socket['inode'])is not int or socket['inode']<=0):
        raise ValueError('actual watchman listener descriptor required')
    _sha(socket['tcp_table_sha256'])
    return route



def _route_identity(route):
    # Other legitimate TCP connections change the full kernel table during the
    # admin calls. Retain both table hashes as provenance, compare only the
    # authenticated owning listener's actual identity across the bracket.
    return {**route,'watch_listener':{key:route['watch_listener'][key]for key in ('fd','inode')}}


def _owner_route(daemons):
    cap=daemons['captaind'];watch=daemons['watchmand'];pid=watch['pid']
    namespaces={name:os.readlink('/proc/'+str(row['pid'])+'/ns/net')for name,row in daemons.items()}
    destination=cap['public_configuration']['native_funding_owner_address'];listener=watch['public_configuration']['admin_address']
    names=os.listdir('/proc/'+str(pid)+'/fd')
    if len(names)>4096:raise ValueError('bounded watchman descriptor inventory required')
    links={}
    for name in names:
        _require_time()
        if not name.isdecimal():continue
        try:links[int(name)]=os.readlink('/proc/'+str(pid)+'/fd/'+name)
        except FileNotFoundError:continue
    raw=_proc_bytes('/proc/'+str(pid)+'/net/tcp',2*1024*1024)
    socket=_listener(raw,links,address=listener['address'],port=listener['port'])
    shared=None
    if not(namespaces['captaind']==namespaces['watchmand']and ipaddress.IPv4Address(destination['address']).is_loopback):
        matching={n['network_id']for n in watch['networks']if n['address']==destination['address']} & {n['network_id']for n in cap['networks']}
        if len(matching)!=1:raise ValueError('unique actual shared native-owner network required')
        shared=matching.pop()
    route={'cap_pid':cap['pid'],'watch_pid':watch['pid'],'destination':destination,'listener':listener,
           'network_namespaces':namespaces,'shared_network_id':shared,'watch_listener':socket}
    return _verify_owner_route(daemons,route)


def public_configuration(raw, service):
    """Whitelist public facts from the SAME bounded bytes hashed by _file.

    This is configuration provenance, not current rates, available cash, a
    per-path satoshi ceiling, cumulative global policy, or financial readiness.
    """
    if type(raw) is not bytes or len(raw) > 2*1024*1024 or service not in SERVICES:
        raise ValueError('bounded owned native configuration required')
    config = tomllib.loads(raw.decode('utf8'))
    if config['network'] not in ('bitcoin','testnet','testnet4','signet','regtest'):
        raise ValueError('native network required')
    result = {'network':config['network'], 'fee_estimator_max_sat_kwu':_public_rate(config['fee_estimator'].get('max_fee_rate')),
              'admin_address':_socket_address(config['admin_address'])}
    if service == 'watchmand':
        direct = config['watchman']['direct_expiry']
        result['direct_expiry'] = {'max_miner_fee_sat':_public_amount(direct['max_miner_fee']),
                                  'ordinary_fee_policy':_public_ordinary(direct['ordinary_fee_policy'])}
        return result
    result.update({key:_public_uint(config[key],2**32-1) for key in ('vtxo_lifetime','vtxo_exit_delta','htlc_expiry_delta','htlc_send_expiry_delta')})
    direct = config.get('direct_expiry', {}); enabled = direct.get('enabled', False)
    legacy = config.get('expiry_payout', {}).get('enabled', False)
    if type(enabled) is not bool or type(legacy) is not bool: raise ValueError('native producer booleans required')
    result['native_funding_owner_address'] = _socket_address(config['native_funding_owner_address'])
    result.update(direct_expiry={'enabled':enabled,'grace_blocks':_public_uint(direct.get('grace_blocks',6),2**32-1)},
                  legacy_expiry_payout_enabled=legacy,ln_max_fee_ppm=_public_uint(config['ln_max_fee_ppm']),
                  ordinary_fee_policy=_public_ordinary(config['direct_expiry_fee_policy']))
    pool = config['vtxopool']; targets = pool['vtxo_targets']
    if not isinstance(targets,list) or len(targets)>10000: raise ValueError('bounded native pool targets required')
    parsed = []
    for target in targets:
        if not isinstance(target,str) or len(target)>128 or target.count(':')!=1: raise ValueError('native pool target required')
        amount,count = target.split(':')
        if not re.fullmatch('[0-9]{1,20}',count): raise ValueError('native pool target count required')
        parsed.append({'amount_sat':_public_amount(amount),'count':_public_uint(int(count))})
    result['vtxopool'] = {'targets':parsed, **{key:_public_uint(pool[key],2**32-1) for key in ('vtxo_lifetime','vtxo_pre_expiry','vtxo_target_issue_threshold')},
                          'max_vtxo_exit_depth':_public_uint(pool.get('max_vtxo_exit_depth',pool.get('vtxo_max_arkoor_depth')),65535)}
    return result


def _configuration_pair(expected, checkpoint, daemons, owner):
    if expected['execution_release']['product_commit'] != POLICY_PRODUCT_COMMIT:
        raise ValueError('public configuration source is pinned to actual15e native semantics')
    projected = {}
    for service in SERVICES:
        value = daemons[service]['public_configuration']
        if value != checkpoint['configs'][service]['public_configuration'] or checkpoint['configs'][service]['sha256'] != expected['config_sha256'][service]:
            raise ValueError('same-byte original loaded policy projection required')
        projected[service] = value
    cap = projected['captaind']; watch = projected['watchmand']
    if (cap['ordinary_fee_policy'] != watch['direct_expiry']['ordinary_fee_policy']
            or cap['network'] != watch['network']or owner['opening']['network']!=cap['network']):
        raise ValueError('paired adopted fee policies or networks differ')
    if owner['policy'] != cap['ordinary_fee_policy']:
        raise ValueError('loaded public fee policy differs from same native owner')
    return {'schema_version':1,'product_commit':POLICY_PRODUCT_COMMIT,'config_sha256':dict(expected['config_sha256']),
            'policy_source_sha256':dict(POLICY_SOURCE_SHA256), **projected}


def _file(path, maximum, prefix=None, *, public_history=False, configuration_service=None, opening_identity=False):
    """No-follow metadata/digest read; raw private contents never returned."""
    path = Path(_path(str(path)))
    _require_time()
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory); directory = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_size > maximum:
                raise ValueError('runtime source type/size bound')
            full = hashlib.sha256(); head = hashlib.sha256(); count = 0; records = bytearray()
            while block := os.read(fd, 65536):
                _require_time()
                if count + len(block) > maximum:
                    raise ValueError('runtime source growth bound')
                full.update(block)
                if public_history or configuration_service or opening_identity: records.extend(block)
                if prefix is not None and count < prefix:
                    head.update(block[:prefix-count])
                count += len(block)
            last = os.fstat(fd); named = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if fields(first) != fields(last) or fields(first) != fields(named) or count != first.st_size:
                raise ValueError('runtime source changed during capture')
            result = dict(zip(('device', 'inode', 'bytes', 'mtime_ns', 'ctime_ns'), fields(first)))
            result['sha256'] = full.hexdigest()
            if prefix is not None:
                if not 0 <= prefix <= count: raise ValueError('history prefix outside actual history')
                result.update(prefix_bytes=prefix, prefix_sha256=head.hexdigest())
            if public_history: result['txids'] = history_txids(bytes(records), prefix)
            if configuration_service: result['public_configuration'] = public_configuration(bytes(records), configuration_service)
            if opening_identity: result['opening_identity'] = _opening_identity(json.loads(records))
            return result
        finally: os.close(fd)
    finally: os.close(directory)


def _process_identity(pid):
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    return {'pid': pid, 'ppid': int(fields[1]), 'session': int(fields[3]),
            'start_ticks': int(fields[19]), 'state': fields[0]}


def _signal_owned(original, sig):
    """Signal one verified PID through pidfd; never a name or process group."""
    try:
        fd = os.pidfd_open(original['pid'])
        try:
            current = _process_identity(original['pid'])
            if any(current[key] != original[key] for key in ('pid', 'session', 'start_ticks')):
                raise ValueError('owned command PID identity changed')
            signal.pidfd_send_signal(fd, sig)
        finally:
            os.close(fd)
    except ProcessLookupError:
        pass
    except FileNotFoundError:
        pass


def _command_descendants(root, *, end):
    rows = {}
    for count, path in enumerate(Path('/proc').iterdir(), 1):
        if time.monotonic() >= end or count > MAX_PROCESS_ENTRIES:
            raise ValueError('owned process discovery bound exceeded')
        if not path.name.isdecimal(): continue
        try: rows[int(path.name)] = _process_identity(int(path.name))
        except (FileNotFoundError, ProcessLookupError): continue
    # The fresh session belongs to the exact Popen leader. It also retains
    # provenance for already orphaned helpers after their parent exits. Each
    # signal still verifies PID/startticks through pidfd individually.
    owned = {root['pid']: root}
    owned.update({pid: row for pid, row in rows.items()
                  if row['session'] == root['session'] and row['start_ticks'] >= root['start_ticks']})
    while True:
        added = {pid: row for pid, row in rows.items() if pid not in owned and row['ppid'] in owned
                 and row['session'] == root['session'] and row['start_ticks'] >= root['start_ticks']}
        if not added: return owned
        owned.update(added)


def _stop_command(process, root, end):
    # Freeze the exact leader first, then its discovered descendants, so cleanup
    # cannot race a new helper launch. Daemon-owned Dockerexec is NOT a child.
    _signal_owned(root, signal.SIGSTOP)
    owned = {root['pid']: root}
    try:
        for _ in range(3):
            found = _command_descendants(root, end=end)
            new = {pid: row for pid, row in found.items() if pid not in owned}
            owned.update(new)
            for row in new.values(): _signal_owned(row, signal.SIGSTOP)
            if not new: break
    finally:
        # Discovery can itself fail or exhaust its bound. Always terminate and
        # reap the direct command and every descendant already identified.
        try:
            for pid, row in owned.items():
                if pid != root['pid']: _signal_owned(row, signal.SIGKILL)
        finally:
            _signal_owned(root, signal.SIGKILL)
            process.wait(timeout=max(.001, end-time.monotonic()))
    # The direct Popen child is reaped above. Orphaned descendants are reaped by
    # init, not falsely claimed as waitpid children of this producer.
    while True:
        alive = []
        for pid, row in owned.items():
            try:
                current = _process_identity(pid)
                if (current['session'], current['start_ticks']) == (row['session'], row['start_ticks']) and current['state'] != 'Z':
                    alive.append(pid)
            except (FileNotFoundError, ProcessLookupError): pass
        if not alive: break
        if time.monotonic() >= end: raise ValueError('owned command descendant cleanup incomplete')
        time.sleep(.005)


def _run(argv, maximum=2*1024*1024, *, timeout=8):
    if type(maximum) is not int or not 0 < maximum <= 2*1024*1024 or not 0 < timeout <= 8:
        raise ValueError('readonly command resource bounds')
    if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
        raise ValueError('verified owned PID cleanup unavailable')
    shared = _require_time()
    end = min(time.monotonic()+timeout, shared) if shared is not None else time.monotonic()+timeout
    if end-time.monotonic() < .01: raise ValueError('aggregate runtime capture deadline exceeded')
    work_end = end-min(.75, (end-time.monotonic())/2)
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'}, bufsize=0)
    root = None; owned_fd = None; selector = None
    try:
        owned_fd = os.pidfd_open(process.pid)
        observed = _process_identity(process.pid)
        if observed['session'] != process.pid:
            raise ValueError('isolated owned command identity required')
        root = observed
        output = bytearray(); errors = bytearray(); selector = selectors.DefaultSelector()
        for pipe, name in ((process.stdout, 'out'), (process.stderr, 'err')):
            os.set_blocking(pipe.fileno(), False); selector.register(pipe, selectors.EVENT_READ, name)
        while selector.get_map():
            remaining = work_end-time.monotonic()
            if remaining <= 0: raise ValueError('readonly command deadline exceeded')
            ready = selector.select(remaining)
            if not ready: raise ValueError('readonly command deadline exceeded')
            for key, _ in ready:
                try: block = os.read(key.fd, 65536)
                except BlockingIOError: continue
                if not block:
                    selector.unregister(key.fileobj); continue
                target, limit = (output, maximum) if key.data == 'out' else (errors, 65536)
                if len(target)+len(block) > limit:
                    raise ValueError('readonly runtime command response bound')
                target.extend(block)
        try: code = process.wait(timeout=max(.001, work_end-time.monotonic()))
        except subprocess.TimeoutExpired: raise ValueError('readonly command deadline exceeded') from None
        if code: raise subprocess.CalledProcessError(code, argv)
        return bytes(output)
    finally:
        try:
            if root is not None:
                try:
                    _stop_command(process, root, end)
                finally:
                    # Keep the retained direct-child pidfd usable even if
                    # descendant discovery or its initial signal fails.
                    if process.poll() is None:
                        try: signal.pidfd_send_signal(owned_fd, signal.SIGKILL)
                        except ProcessLookupError: pass
                        process.wait(timeout=max(.001, end-time.monotonic()))
            else:
                # A setup failure must still reap the exact direct Popen child.
                # Before wait(), it cannot have been reaped and reused here.
                if owned_fd is not None:
                    try: signal.pidfd_send_signal(owned_fd, signal.SIGKILL)
                    except ProcessLookupError: pass
                else:
                    process.kill()
                process.wait(timeout=max(.001, end-time.monotonic()))
        finally:
            if selector is not None: selector.close()
            process.stdout.close(); process.stderr.close()
            if owned_fd is not None: os.close(owned_fd)


def _inspect(container):
    return json.loads(_run(['/usr/bin/docker', 'inspect', container]))[0]


def _helper(expected):
    raw, sha = checked_file(expected['budget_helper_path'], maximum=32768)
    if sha != expected['budget_helper_sha256']:
        raise ValueError('installed native disk reader differs')
    module = types.ModuleType('_b_admitted_native_budget')
    exec(compile(raw, expected['budget_helper_path'], 'exec'), module.__dict__)
    return module


def _opening_identity(value):
    keys={'version','network','genesis','server_pubkey','history_prefix_bytes','history_prefix_sha256','native_spent_sat','external_spent_sat','accounting_receipt_sha256'}
    if not isinstance(value,dict) or set(value)!=keys or type(value['version'])is not int or value['version']!=1:
        raise ValueError('exact native opening identity required')
    _sha(value['genesis']);_sha(value['history_prefix_sha256']);_sha(value['accounting_receipt_sha256'])
    prefix=_public_uint(value['history_prefix_bytes'],650000)
    if prefix%65:raise ValueError('canonical native signed-history prefix required')
    return {key:value[key]for key in ('history_prefix_bytes','history_prefix_sha256','accounting_receipt_sha256')}


def _owner_snapshot(expected):
    # This fixed inside-watchman call reaches the actual owning admin service.
    # Its configured captaind route is authenticated separately against the
    # owning listener, Docker network and PID, rather than endpoint text alone.
    raw=_run(['/usr/bin/docker','exec',expected['containers']['watchmand'],'captaind','rpc',
              '--addr','127.0.0.1:3538','native-fee-budget'])
    return _owner_document(raw),raw.decode('utf8')


def _owner_document(raw):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError('duplicate native owner reply field')
            result[key]=value
        return result
    value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite native owner reply')))
    required={'schema','policy_sha256','opening_sha256','journal_sha256','journal_device','journal_inode','journal_bytes',
        'policy','opening','charged_sat','remaining_total_sat','urgent_remaining_sat','discretionary_remaining_sat',
        'direct_attempt_count','direct_reserved_sat','funding_reserved_sat','round_reserved_sat','pool_reserved_sat',
        'urgent_reserved_sat','funding','urgent','resolutions'}
    if not isinstance(value,dict)or set(value)!=required or type(value['schema'])is not int or value['schema']!=1:
        raise ValueError('actual complete native owner snapshot required')
    return value


def _check_owner_budget(budget):
    owner=budget['owner_snapshot'];raw=budget['owner_snapshot_raw']
    if (not isinstance(raw,str)or len(raw.encode())>2*1024*1024
            or digest(raw.encode())!=budget['owner_snapshot_raw_sha256']or _owner_document(raw)!=owner):
        raise ValueError('actual original native owner reply differs')
    for field,name in [('policy_sha256','ordinary-fee-policy.json'),('opening_sha256','ordinary-fee-opening.json'),('journal_sha256','ordinary-fee-budget')]:
        if _sha(owner[field])!=budget['files'][name]['sha256']:
            raise ValueError('native owner/file source identity differs')
    file=budget['files']['ordinary-fee-budget']
    for key,name in [('journal_device','device'),('journal_inode','inode'),('journal_bytes','bytes')]:
        if type(owner[key])is not int or owner[key]!=file[name]:
            raise ValueError('native owner journal custody differs')
    original=_opening_identity(owner['opening'])
    if (original['history_prefix_bytes']!=budget['history']['prefix_bytes']
            or original['history_prefix_sha256']!=budget['history']['prefix_sha256']
            or original['accounting_receipt_sha256']!=budget['accounting_receipt_sha256']):
        raise ValueError('native owner original history/accounting receipt differs')
    if owner['policy']['opening_sha256']!=owner['opening_sha256']:
        raise ValueError('native owner adopted opening differs')
    return owner


def _budget(expected, helper, *, before_start=False):
    _require_time(5)
    directory,binding=helper.source_mount()
    if str(directory.parent)!=expected['data_mount']['source']:
        raise ValueError('native budget source outside declared owning mount')
    files={name:_file(directory/name,helper.LIMITS[name],opening_identity=name=='ordinary-fee-opening.json')for name in BUDGET_FILES}
    opening=files['ordinary-fee-opening.json'].pop('opening_identity')
    history=_file(directory/'history',650000,opening['history_prefix_bytes'],public_history=True)
    receipt=_file(expected['accounting_receipt_path'],2*1024*1024)
    if (history['prefix_sha256']!=opening['history_prefix_sha256']
            or receipt['sha256']!=opening['accounting_receipt_sha256']):
        raise ValueError('original signed history/accounting receipt differs')
    result={'files':files,'history':history,'accounting_receipt_sha256':receipt['sha256'],
            'source_mount_identity_sha256':identity(binding)}
    if not before_start:
        owner,raw=_owner_snapshot(expected)
        result.update(owner_snapshot=owner,owner_snapshot_raw=raw,owner_snapshot_raw_sha256=digest(raw.encode()))
        _check_owner_budget(result)
    repeated={name:_file(directory/name,helper.LIMITS[name])for name in BUDGET_FILES}
    _require_time(5)
    if repeated!=files or helper.source_mount()!=(directory,binding):
        raise ValueError('native budget bytes/mount changed during capture')
    return result


def prepare_checkpoint(expected):
    """Run BEFORE starting the new pair; root privately retains these facts."""
    _expected(expected)
    configs = {name: _file(expected['config_paths'][name]['host'], 2*1024*1024, configuration_service=name) for name in SERVICES}
    if any(configs[name]['sha256'] != expected['config_sha256'][name] for name in SERVICES):
        raise ValueError('pre-start configuration differs from reviewed bytes')
    return {'kind': 'b_runtime_before_start', 'observed_at_ns': time.time_ns(),
            'expected_sha256': identity(expected), 'configs': configs, 'native_budget': _budget(expected, _helper(expected), before_start=True)}


def parse_flock(raw, *, pid, device, inode):
    """Linux fdinfo FLOCK identity, including major/minor in hex and inode decimal."""
    if not isinstance(raw, str) or len(raw.encode()) > 65536:
        raise ValueError('bounded actual fdinfo required')
    matches = []
    for line in raw.splitlines():
        match = re.fullmatch(r'lock:\s+\d+:\s+FLOCK\s+ADVISORY\s+WRITE\s+(\d+)\s+([0-9a-fA-F]+):([0-9a-fA-F]+):(\d+)\s+0\s+EOF', line)
        if match and (int(match[1]), os.makedev(int(match[2], 16), int(match[3], 16)), int(match[4])) == (pid, device, inode):
            matches.append(line)
    if len(matches) != 1:
        raise ValueError('actual watchman exclusive whole-file FLOCK required')
    return matches[0]


def _lock(pid, budget_file):
    candidates = []
    names = os.listdir(f'/proc/{pid}/fd')
    if len(names) > 4096: raise ValueError('watchman descriptor bound')
    for name in names:
        _require_time()
        if not name.isdecimal(): continue
        try:
            info = os.stat(f'/proc/{pid}/fd/{name}')
            if (info.st_dev, info.st_ino) != (budget_file['device'], budget_file['inode']): continue
            raw = Path(f'/proc/{pid}/fdinfo/{name}').read_text()
            line = parse_flock(raw, pid=pid, device=info.st_dev, inode=info.st_ino)
            candidates.append({'pid': pid, 'fd': int(name), 'device': info.st_dev, 'inode': info.st_ino,
                               'fdinfo_sha256': digest(raw.encode()), 'lock_line': line})
        except FileNotFoundError: continue
    if not candidates: raise ValueError('watchman does not hold actual native budget file lock')
    return candidates[0]


def _proc_bytes(path, maximum):
    _require_time()
    with open(path, 'rb') as stream:
        raw = stream.read(maximum+1)
    _require_time()
    if len(raw) > maximum:
        raise ValueError('bounded process metadata required')
    return raw


def _executable_digest(path):
    with open(path, 'rb') as stream:
        size = os.fstat(stream.fileno()).st_size
        if not 0 < size <= MAX_EXECUTABLE_BYTES:
            raise ValueError('running executable size bound')
        hashed = hashlib.sha256(); count = 0
        while block := stream.read(1024*1024):
            _require_time(); count += len(block)
            if count > MAX_EXECUTABLE_BYTES: raise ValueError('running executable growth bound')
            hashed.update(block)
        return hashed.hexdigest()


def _daemon(expected, name):
    container = expected['containers'][name]; value = _inspect(container)
    state = value['State']; pid = state['Pid']; paths = expected['config_paths'][name]
    if not state['Running'] or type(pid) is not int or pid <= 0 or value['Image'] != expected['execution_release']['image_sha256']:
        raise ValueError('actual current daemon image/process differs')
    mounts = value['Mounts']
    configs = [m for m in mounts if m['Destination'] == paths['container']]
    data = [m for m in mounts if m['Destination'] == '/data/captaind']
    if (len(configs) != 1 or configs[0]['Source'] != paths['host'] or configs[0]['RW'] is not False
            or len(data) != 1 or data[0]['Source'] != expected['data_mount']['source'] or data[0]['RW'] is not True
            or any(m['Destination'].startswith('/data/captaind/') for m in mounts)):
        raise ValueError('actual immutable config/shared history mount differs')
    config = _file(paths['host'], 2*1024*1024, configuration_service=name)
    # /proc/PID/exe is intentionally a kernel symlink; hash the opened running
    # image, not a named file in the container that can have been replaced.
    binary = _executable_digest(f'/proc/{pid}/exe')
    command = _proc_bytes(f'/proc/{pid}/cmdline', 131072).rstrip(b'\0').decode().split('\0')
    environ = _proc_bytes(f'/proc/{pid}/environ', 131072)
    entries = environ.rstrip(b'\0').decode().split('\0'); env = dict(x.split('=', 1) for x in entries)
    relevant = {k: v for k, v in env.items() if k.upper().startswith(('CAPTAIND_', 'WATCHMAND_', 'BARK_SERVER_'))}
    if any(k not in ('CAPTAIND_LOG', 'WATCHMAND_LOG') or v != 'info' for k, v in relevant.items()):
        raise ValueError('unreviewed runtime config override')
    if config['sha256'] != expected['config_sha256'][name] or binary != expected['binary_sha256'][name]:
        raise ValueError('actual running binary/config differs')
    if command[1:] != ['--config', paths['container'], 'start'] or Path(command[0]).name != name:
        raise ValueError('actual daemon config command differs')
    container_sha = _run(['/usr/bin/docker', 'exec', container, 'sha256sum', paths['container']], 1024).decode().split()[0]
    version = _run(['/usr/bin/docker', 'exec', container, name, '--version'], 4096).decode().strip()
    if container_sha != config['sha256'] or expected['execution_release']['product_commit'] not in version:
        raise ValueError('container binary/config source identity differs')
    start_ticks = int(Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19])
    return {'container': container, 'image_sha256': value['Image'], 'pid': pid, 'started_at': state['StartedAt'],
            'proc_start_ticks': start_ticks, 'restart_count': value['RestartCount'], 'binary_sha256': binary,
            'process_exe_sha256': binary, 'version': version, 'config_sha256': config['sha256'],
            'config_device': config['device'], 'config_inode': config['inode'], 'config_ctime_ns': config['ctime_ns'],
            'config_mtime_ns': config['mtime_ns'], 'config_mount': {'source': paths['host'], 'destination': paths['container'], 'read_only': True},
            'process_cmdline': command, 'environment_names': sorted(env), 'config_overrides': relevant,
            'public_configuration':config['public_configuration'], 'networks':_network_identity(value)}


def verify(expected, checkpoint, observation, *, now_ns=None):
    """Pure admission of captured metadata; installed producer remains trusted."""
    _expected(expected); now_ns = time.time_ns() if now_ns is None else now_ns
    if checkpoint.get('kind') != 'b_runtime_before_start' or checkpoint.get('expected_sha256') != identity(expected):
        raise ValueError('original before-start release checkpoint required')
    if not 0 <= now_ns-observation['completed_at_ns'] <= 90*10**9 or observation['started_at_ns'] > observation['completed_at_ns']:
        raise ValueError('fresh bounded runtime observation required')
    elapsed = observation.get('elapsed_ns')
    if (type(elapsed) is not int or not 0 <= elapsed <= MAX_CAPTURE_NS
            or not 0 <= observation['completed_at_ns']-observation['started_at_ns'] <= MAX_CAPTURE_NS):
        raise ValueError('bounded actual runtime capture duration required')
    before = observation['before']; after = observation['after']
    if before != after or set(before) != set(SERVICES):
        raise ValueError('same actual paired process/config before and after admin required')
    for name, daemon in before.items():
        started = _time_ns(daemon['started_at'])
        if not checkpoint['observed_at_ns'] < started <= observation['started_at_ns']:
            raise ValueError('pre-start checkpoint must precede actual new process')
        pinned = {'container': expected['containers'][name], 'image_sha256': expected['execution_release']['image_sha256'],
                  'binary_sha256': expected['binary_sha256'][name], 'process_exe_sha256': expected['binary_sha256'][name],
                  'config_sha256': expected['config_sha256'][name]}
        if any(daemon.get(k) != v for k, v in pinned.items()) or daemon['restart_count'] != 0:
            raise ValueError('actual paired artifact or restart differs')
        config = checkpoint['configs'][name]
        if any(daemon['config_'+key] != config[key] for key in ('device', 'inode', 'ctime_ns', 'mtime_ns')) or max(config['ctime_ns'], config['mtime_ns']) > checkpoint['observed_at_ns']:
            raise ValueError('configuration changed since original before-start checkpoint')
        if type(daemon['pid']) is not int or daemon['pid'] <= 0 or type(daemon['proc_start_ticks']) is not int or daemon['proc_start_ticks'] <= 0:
            raise ValueError('actual host process identity required')
        _sha(observation['admin_responses'][name])
    if observation['canonical_schema_sha256'] != expected['canonical_schema_sha256'] or observation['canonical_schema_repeat_sha256'] != expected['canonical_schema_sha256']:
        raise ValueError('actual canonical schema differs or changed')
    budget = observation['native_budget']; owner = _check_owner_budget(budget)
    if observation['native_budget_after'] != budget:
        raise ValueError('native budget/history changed during process capture')
    for name in BUDGET_FILES[:2]:
        if budget['files'][name] != checkpoint['native_budget']['files'][name] or budget['files'][name]['ctime_ns'] > checkpoint['observed_at_ns']:
            raise ValueError('policy/opening changed after before-start checkpoint')
    lock = observation['budget_lock']; watch = before['watchmand']; actual = budget['files']['ordinary-fee-budget']
    parse_flock(lock['lock_line'], pid=watch['pid'], device=actual['device'], inode=actual['inode'])
    if (lock['pid'], lock['device'], lock['inode']) != (watch['pid'], actual['device'], actual['inode']) or observation['budget_lock_after'] != lock:
        raise ValueError('actual same-watchman budget lock changed')
    _sha(lock['fdinfo_sha256'])
    route = _verify_owner_route(before, observation['owner_route'])
    if _route_identity(route) != _route_identity(_verify_owner_route(before,observation['owner_route_after'])):
        raise ValueError('native owner route changed during capture')
    configuration = _configuration_pair(expected, checkpoint, before, owner)
    result = {'public_configuration':configuration, 'kind': 'owned_runtime_configuration_verified', **{k: expected['execution_release'][k] for k in ('product_commit', 'schema_sha256')},
              'execution_release': expected['execution_release'], 'observed_at': observation['completed_at_ns']/10**9,
              'startup_source_sha256': identity(checkpoint), 'current_source_sha256': identity(observation),
              'current_canonical_schema': {'protocol': 'pg-dump-restrict-lines-v1', 'sha256': observation['canonical_schema_sha256'], 'repeat_sha256': observation['canonical_schema_repeat_sha256']},
              'daemons': {name: {**value, 'admin_response_sha256': observation['admin_responses'][name]} for name, value in before.items()},
              'native_budget': {**budget, 'lock': lock}, 'native_owner_route':route, 'reviewed_load_gate_sources': expected['load_gate_sources'],
              'loaded_configuration_identity_verified': True, 'retained_signed_fee_coverage_verified': False,
              'urgent_selection_isolation_verified': False, 'complete': False, 'qualified': False}
    return result


def _capture(expected, checkpoint, *, _native_fee_cut=False):
    """Privileged fixed-owned readonly capture; caller retains privately, no append."""
    _expected(expected); started = time.time_ns(); monotonic = time.monotonic_ns(); helper = _helper(expected)
    before = {name: _daemon(expected, name) for name in SERVICES}
    route = _owner_route(before)
    budget = _budget(expected, helper); lock = _lock(before['watchmand']['pid'], budget['files']['ordinary-fee-budget'])
    responses = {}; private_inventories = {}
    for name, port in (('captaind', '3536'), ('watchmand', '3538')):
        raw = _run(['/usr/bin/docker', 'exec', expected['containers'][name], 'captaind', 'rpc', '--addr', '127.0.0.1:'+port, 'wallet-inventory'], 65536)
        if not isinstance(json.loads(raw), dict): raise ValueError('actual successful admin inventory required')
        responses[name] = digest(raw)
        if _native_fee_cut:
            role = 'rounds_inventory' if name == 'captaind' else 'watchman_inventory'
            private_inventories[role] = raw
    private_cut = None
    if _native_fee_cut:
        from .b_private_native_fee_capture import capture_private_cut
        private_cut = capture_private_cut(expected, budget)
    after_budget = _budget(expected, helper); after_lock = _lock(before['watchmand']['pid'], after_budget['files']['ordinary-fee-budget'])
    schemas = []
    for _ in range(2):
        raw = _run(['/usr/bin/docker', 'exec', expected['postgres_container'], 'pg_dump', '-U', 'postgres', '--schema-only', '--no-owner', '--no-privileges', expected['database']])
        canonical = b'\n'.join(line for line in raw.splitlines() if not line.startswith((b'\\restrict ', b'\\unrestrict '))) + b'\n'
        schemas.append(digest(canonical))
    after = {name: _daemon(expected, name) for name in SERVICES}
    route_after = _owner_route(after)
    observation = {'owner_route':route,'owner_route_after':route_after,'started_at_ns': started, 'completed_at_ns': time.time_ns(), 'before': before, 'after': after,
                   'native_budget': budget, 'native_budget_after': after_budget, 'budget_lock': lock,
                   'budget_lock_after': after_lock, 'admin_responses': responses,
                   'canonical_schema_sha256': schemas[0], 'canonical_schema_repeat_sha256': schemas[1],
                   'elapsed_ns': time.monotonic_ns()-monotonic}
    result = observation, verify(expected, checkpoint, observation)
    if _native_fee_cut:
        # Keep the exact already-read replies private. Their hashes are in the
        # verified observation; another RPC or JSON re-encoding is not this cut.
        private_cut['wallet_inventory_originals'] = private_inventories
    return (*result, private_cut) if _native_fee_cut else result


def capture(expected, checkpoint):
    token = _CAPTURE_END.set(time.monotonic()+MAX_CAPTURE_NS/10**9)
    try:
        return _capture(expected, checkpoint)
    finally:
        _CAPTURE_END.reset(token)


def _capture_protected_originals(expected_path, checkpoint_path):
    """Installed entry point: root-protected original declarations only.

    Installation/source admission is external and must pin this module's bytes.
    Root records the checkpoint during its declared operator window. This reader
    never writes a checkpoint, an event or a financial observation to a Store.
    """
    expected_raw, expected_sha = checked_file(expected_path)
    checkpoint_raw, checkpoint_sha = checked_file(checkpoint_path)
    expected = json.loads(expected_raw); checkpoint = json.loads(checkpoint_raw)
    observation, receipt = capture(expected, checkpoint)
    if checked_file(expected_path)[1] != expected_sha or checked_file(checkpoint_path)[1] != checkpoint_sha:
        raise ValueError('protected operator declaration changed during capture')
    receipt['operator_expected_source_sha256'] = expected_sha
    receipt['operator_checkpoint_source_sha256'] = checkpoint_sha
    receipt['producer_source_sha256'] = checked_file(Path(__file__))[1]
    return observation, receipt, expected_raw, checkpoint_raw


def capture_protected(expected_path, checkpoint_path):
    observation, receipt, _, _ = _capture_protected_originals(expected_path, checkpoint_path)
    return observation, receipt


def capture_originals_protected(expected_path, checkpoint_path):
    """Private transport only: exact originals, NEVER an event/public trace."""
    observation, receipt, expected_raw, checkpoint_raw = _capture_protected_originals(expected_path, checkpoint_path)
    encode = lambda value: json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)
    return {'expected_raw':expected_raw.decode('utf8'),'checkpoint_raw':checkpoint_raw.decode('utf8'),
            'observation_raw':encode(observation),'protected_receipt_raw':encode(receipt)}


def capture_native_fee_originals_protected(expected_path, checkpoint_path):
    """PRIVATE fixed fee cut inside the existing single custody loop."""
    expected_raw, expected_sha = checked_file(expected_path)
    checkpoint_raw, checkpoint_sha = checked_file(checkpoint_path)
    expected, checkpoint = json.loads(expected_raw), json.loads(checkpoint_raw)
    token = _CAPTURE_END.set(time.monotonic()+MAX_CAPTURE_NS/10**9)
    try:
        observation, receipt, private_cut = _capture(expected, checkpoint, _native_fee_cut=True)
    finally:
        _CAPTURE_END.reset(token)
    if checked_file(expected_path)[1] != expected_sha or checked_file(checkpoint_path)[1] != checkpoint_sha:
        raise ValueError('protected operator declaration changed during capture')
    receipt['operator_expected_source_sha256'] = expected_sha
    receipt['operator_checkpoint_source_sha256'] = checkpoint_sha
    receipt['producer_source_sha256'] = checked_file(Path(__file__))[1]
    encode = lambda value: json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)
    runtime_originals = {'expected_raw':expected_raw.decode('utf8'),'checkpoint_raw':checkpoint_raw.decode('utf8'),
        'observation_raw':encode(observation),'protected_receipt_raw':encode(receipt)}
    return runtime_originals, private_cut

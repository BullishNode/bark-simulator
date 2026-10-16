"""B-owned read-only runtime provenance; never emits treasury readiness.

The root operator admits an exact expected artifact manifest and saves a pre-start
checkpoint. Capture runs on the owned target as root. No service, wallet, lock or
journal is changed. A separate financial verifier authenticates retained versions,
actual fees and whole-input urgent reserve from independent sources.
"""
import hashlib
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
LOAD_GATES = {
    'server/src/lib.rs': '39f915558bbdce2cd1e527653aa4d8ef982fa2f55fa131c5eb6a2736f4511265',
    'server/src/payout_witness.rs': 'c06c9bb24cb45564fcc0f17d88d3b6f4d7187be95df57482b3fc8cadc267d4c0',
    'server/src/watchman/daemon.rs': '0b4a1e3c3b99b534dbbe277984659e7a03e78fdac20d049a82a7540c99422f8a',
    'server/src/watchman/expiry_runtime.rs': 'e97479e7248de051b2d82fa2d9f429498c13bd6bda192ed1b5ef3ade738bc120',
    'server/src/watchman/ordinary_fee.rs': 'e882bc4052cd952f66b05c687067d0704462179ee5ebb69bc3c5933ef0658d4b',
    'server/src/watchman/urgent.rs': '41bb64748f73806785342975cb1537287b1de202b7334db56ba15e8a37c5f68e',
}
BUDGET_HELPER_SHA256 = 'a21adb02d3f0033ecf82dea1562e53bd9e46856388f009c56ae6ce8c37d25827'
MAX_PUBLIC_LEDGER_RECORDS = 10000
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


def ledger_projection(raw):
    """Expose charge prefixes only after the admitted helper checks the same bytes.

    Urgent package bytes remain private. This projection does not establish
    signed-package validity, retirement, fee coverage or urgent readiness.
    """
    if type(raw) is not bytes or len(raw) > 2*1024*1024 or (raw and not raw.endswith(b'\n')):
        raise ValueError('bounded complete native ledger required')
    lines = raw.split(b'\n')[:-1]
    if len(lines) > MAX_PUBLIC_LEDGER_RECORDS:
        raise ValueError('public ledger record bound')
    result = {'budget_file_sha256': digest(raw), 'ordinary_reservations': [],
              'urgent_reservations': [], 'urgent_bindings': [], 'record_count': len(lines)}
    for number, line in enumerate(lines, 1):
        line = line.removesuffix(b'\r')
        if re.fullmatch(b'[1-9][0-9]{0,15}', line):
            result['ordinary_reservations'].append({'line': number, 'ceiling_sat': int(line)})
        elif match := re.fullmatch(b'u:([1-9][0-9]{0,15}):([1-9][0-9]{0,15})', line):
            result['urgent_reservations'].append({'line': number, 'attempt_index': int(match[1]), 'ceiling_sat': int(match[2])})
        else:
            parts = line.split(b':', 3)
            if (len(parts) != 4 or parts[0] != b'p' or not re.fullmatch(b'[1-9][0-9]{0,15}', parts[1])
                    or not re.fullmatch(b'[0-9a-f]{64}', parts[2]) or not parts[3]):
                raise ValueError('canonical public ledger charge prefix required')
            result['urgent_bindings'].append({'line': number, 'attempt_index': int(parts[1]), 'binding_sha256': parts[2].decode('ascii')})
    return result


def _ledger_matches(ledger, disk, file_sha256):
    if disk.get('schema_version') != 2 or ledger['budget_file_sha256'] != file_sha256 or file_sha256 != disk['budget_file_sha256']:
        raise ValueError('schema-2 exact native ledger bytes required')
    ordinary = ledger['ordinary_reservations']; urgent = ledger['urgent_reservations']; bindings = ledger['urgent_bindings']
    actual = {'ordinary_attempt_count': len(ordinary), 'urgent_attempt_count': len(urgent),
              'urgent_binding_count': len(bindings), 'attempt_count': len(ordinary)+len(urgent),
              'urgent_reserved_ceiling_sum_sat': sum(row['ceiling_sat'] for row in urgent),
              'reserved_ceiling_sum_sat': sum(row['ceiling_sat'] for row in ordinary+urgent)}
    if any(disk.get(name) != value for name, value in actual.items()):
        raise ValueError('public ledger differs from admitted schema-2 charges')
    if ledger['record_count'] != len(ordinary)+len(urgent)+len(bindings):
        raise ValueError('public ledger record inventory differs')
    return ledger



POLICY_PRODUCT_COMMIT = '5a6702018bedc37d4d27cec1205abe828ea14ee5'
POLICY_SOURCE_SHA256 = {
    'server/src/config.rs': '0d8882088ea192403025bc58297811963c82381c3de133bfe308d6df5541993f',
    'server/src/watchman/config.rs': 'c1737bfeb783cbcc7eccecf525491953a5ccc635ddec3f2b38812e24ecb38bdd',
    'server/src/utils/serde.rs': '1a47258d50814a23914321e689ff8283e58c34bf71500babf0f8fb1a0ea944ee',
    'server/src/fee_estimator.rs': '7c4dc5dd37aa046048388555b53baced74d1009e167c7854b822653f36179cfe',
    'server/src/vtxopool.rs': '201035455969c724f3953f680af98ccb4596677fb32f082d94fd8f331a44ee57',
    'server/src/expiry_dispatch.rs': 'b76668ade7329a3d00d9a68570bf42448174cd9f46ad4131bdddee2234ba0604',
    'server/src/expiry_payout.rs': '9481d1745718232985592fd0b1ed2e5725dd15b0f7e113a9ea31bcbdee3bf05b',
    'server/src/wallet/mod.rs': '0481a86aff6a7cfa2c9d1a46b47c35b8236f4d486194522f5364dad61171d4a7',
    'server/src/watchman/carrier.rs': '5ed4ce9606ba16ec69870d6ea17f8d3891e1d6d5aae3e196c63dba4193fb4843',
    'server/src/watchman/urgent.rs': '41bb64748f73806785342975cb1537287b1de202b7334db56ba15e8a37c5f68e',
    'server/src/ln/mod.rs': 'b71f1d4297b66305ee88d75f9f28bdfb02f4f173588dc90252699e812f0a49b6',
}


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
    result = {'network':config['network'], 'fee_estimator_max_sat_kwu':_public_rate(config['fee_estimator'].get('max_fee_rate'))}
    if service == 'watchmand':
        direct = config['watchman']['direct_expiry']
        result['direct_expiry'] = {'max_miner_fee_sat':_public_amount(direct['max_miner_fee']),
                                  'ordinary_fee_policy':_public_ordinary(direct['ordinary_fee_policy'])}
        return result
    result.update({key:_public_uint(config[key],2**32-1) for key in ('vtxo_lifetime','vtxo_exit_delta','htlc_expiry_delta','htlc_send_expiry_delta')})
    direct = config.get('direct_expiry', {}); enabled = direct.get('enabled', False)
    legacy = config.get('expiry_payout', {}).get('enabled', False)
    if type(enabled) is not bool or type(legacy) is not bool: raise ValueError('native producer booleans required')
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


def _configuration_pair(expected, checkpoint, daemons, disk):
    if expected['execution_release']['product_commit'] != POLICY_PRODUCT_COMMIT:
        raise ValueError('public configuration source is pinned to actual 5a native semantics')
    projected = {}
    for service in SERVICES:
        value = daemons[service]['public_configuration']
        if value != checkpoint['configs'][service]['public_configuration'] or checkpoint['configs'][service]['sha256'] != expected['config_sha256'][service]:
            raise ValueError('same-byte original loaded policy projection required')
        projected[service] = value
    cap = projected['captaind']; watch = projected['watchmand']
    if cap['ordinary_fee_policy'] != watch['direct_expiry']['ordinary_fee_policy'] or cap['network'] != watch['network']:
        raise ValueError('paired adopted fee policies or networks differ')
    if any(disk.get(key) != value for key,value in cap['ordinary_fee_policy'].items()):
        raise ValueError('loaded public fee policy differs from same locked budget bytes')
    return {'schema_version':1,'product_commit':POLICY_PRODUCT_COMMIT,'config_sha256':dict(expected['config_sha256']),
            'policy_source_sha256':dict(POLICY_SOURCE_SHA256), **projected}


def _file(path, maximum, prefix=None, *, public_history=False, public_ledger=False, configuration_service=None):
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
                if public_history or public_ledger or configuration_service: records.extend(block)
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
            if public_ledger: result['public_ledger'] = ledger_projection(bytes(records))
            if configuration_service: result['public_configuration'] = public_configuration(bytes(records), configuration_service)
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


def _budget(expected, helper):
    _require_time(5)  # Existing fixed source_mount has its own4s RPC timeout.
    directory, binding = helper.source_mount()
    if str(directory.parent) != expected['data_mount']['source']:
        raise ValueError('native budget source outside declared owning mount')
    first = helper.read_directory(directory)
    files = {name: _file(directory/name, helper.LIMITS[name], public_ledger=name == 'ordinary-fee-budget') for name in BUDGET_FILES}
    ledger = files['ordinary-fee-budget'].pop('public_ledger')
    _ledger_matches(ledger, first, files['ordinary-fee-budget']['sha256'])
    history = _file(directory/'history', 650000, first['history_prefix_bytes'], public_history=True)
    receipt = _file(expected['accounting_receipt_path'], 2*1024*1024)
    last = helper.read_directory(directory)
    _require_time(5)
    if first != last or helper.source_mount() != (directory, binding):
        raise ValueError('budget bytes/mount changed during capture')
    expected_hashes = (first['policy_sha256'], first['opening_sha256'], first['budget_file_sha256'])
    if any(files[name]['sha256'] != sha for name, sha in zip(BUDGET_FILES, expected_hashes)):
        raise ValueError('budget metadata/disk projection differs')
    if history['prefix_sha256'] != first['history_prefix_sha256'] or receipt['sha256'] != first['accounting_receipt_sha256']:
        raise ValueError('original signed history/accounting receipt differs')
    return {'disk_budget': first, 'files': files, 'history': history, 'public_ledger': ledger,
            'accounting_receipt_sha256': receipt['sha256'], 'source_mount_identity_sha256': identity(binding)}


def prepare_checkpoint(expected):
    """Run BEFORE starting the new pair; root privately retains these facts."""
    _expected(expected)
    configs = {name: _file(expected['config_paths'][name]['host'], 2*1024*1024, configuration_service=name) for name in SERVICES}
    if any(configs[name]['sha256'] != expected['config_sha256'][name] for name in SERVICES):
        raise ValueError('pre-start configuration differs from reviewed bytes')
    return {'kind': 'b_runtime_before_start', 'observed_at_ns': time.time_ns(),
            'expected_sha256': identity(expected), 'configs': configs, 'native_budget': _budget(expected, _helper(expected))}


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
            'public_configuration':config['public_configuration']}


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
    budget = observation['native_budget']; disk = budget['disk_budget']
    _ledger_matches(budget['public_ledger'], disk, budget['files']['ordinary-fee-budget']['sha256'])
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
    if budget['history']['prefix_sha256'] != disk['history_prefix_sha256'] or budget['accounting_receipt_sha256'] != disk['accounting_receipt_sha256']:
        raise ValueError('authenticated original history/accounting join differs')
    for flag in ('runtime_loaded_identity_verified', 'retained_signed_fee_coverage_verified', 'urgent_selection_isolation_verified', 'complete', 'qualified'):
        if disk.get(flag) is not False: raise ValueError('disk labels cannot confer runtime/financial proof')
    configuration = _configuration_pair(expected, checkpoint, before, disk)
    result = {'public_configuration':configuration, 'kind': 'owned_runtime_configuration_verified', **{k: expected['execution_release'][k] for k in ('product_commit', 'schema_sha256')},
              'execution_release': expected['execution_release'], 'observed_at': observation['completed_at_ns']/10**9,
              'startup_source_sha256': identity(checkpoint), 'current_source_sha256': identity(observation),
              'current_canonical_schema': {'protocol': 'pg-dump-restrict-lines-v1', 'sha256': observation['canonical_schema_sha256'], 'repeat_sha256': observation['canonical_schema_repeat_sha256']},
              'daemons': {name: {**value, 'admin_response_sha256': observation['admin_responses'][name]} for name, value in before.items()},
              'native_budget': {**budget, 'lock': lock}, 'reviewed_load_gate_sources': expected['load_gate_sources'],
              'loaded_configuration_identity_verified': True, 'retained_signed_fee_coverage_verified': False,
              'urgent_selection_isolation_verified': False, 'complete': False, 'qualified': False}
    return result


def _capture(expected, checkpoint):
    """Privileged fixed-owned readonly capture; caller retains privately, no append."""
    _expected(expected); started = time.time_ns(); monotonic = time.monotonic_ns(); helper = _helper(expected)
    before = {name: _daemon(expected, name) for name in SERVICES}
    budget = _budget(expected, helper); lock = _lock(before['watchmand']['pid'], budget['files']['ordinary-fee-budget'])
    responses = {}
    for name, port in (('captaind', '3536'), ('watchmand', '3538')):
        raw = _run(['/usr/bin/docker', 'exec', expected['containers'][name], 'captaind', 'rpc', '--addr', '127.0.0.1:'+port, 'wallet-inventory'], 65536)
        if not isinstance(json.loads(raw), dict): raise ValueError('actual successful admin inventory required')
        responses[name] = digest(raw)
    after_budget = _budget(expected, helper); after_lock = _lock(before['watchmand']['pid'], after_budget['files']['ordinary-fee-budget'])
    schemas = []
    for _ in range(2):
        raw = _run(['/usr/bin/docker', 'exec', expected['postgres_container'], 'pg_dump', '-U', 'postgres', '--schema-only', '--no-owner', '--no-privileges', expected['database']])
        canonical = b'\n'.join(line for line in raw.splitlines() if not line.startswith((b'\\restrict ', b'\\unrestrict '))) + b'\n'
        schemas.append(digest(canonical))
    after = {name: _daemon(expected, name) for name in SERVICES}
    observation = {'started_at_ns': started, 'completed_at_ns': time.time_ns(), 'before': before, 'after': after,
                   'native_budget': budget, 'native_budget_after': after_budget, 'budget_lock': lock,
                   'budget_lock_after': after_lock, 'admin_responses': responses,
                   'canonical_schema_sha256': schemas[0], 'canonical_schema_repeat_sha256': schemas[1],
                   'elapsed_ns': time.monotonic_ns()-monotonic}
    return observation, verify(expected, checkpoint, observation)


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

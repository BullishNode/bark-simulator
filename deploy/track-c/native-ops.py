#!/usr/bin/env python3
"""Root-installed C public observer operations. No shell or financial mutation."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import stat
import subprocess
import sys
import time
import tomllib

MANIFEST = Path('/etc/track-c/deployment-public.json')
CORE = '/opt/track-c/core-31.0/bin/bitcoin-cli'
PSQL = '/nix/store/f5bx5vyjvfc52a93q6p7gy7aidwg3jpx-postgresql-17.11/bin/psql'
MAX_BYTES = 2 * 1024 * 1024
SERVICES = {'captaind': 'track-c-captaind.service', 'watchmand': 'track-c-watchmand.service'}
SAFE_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC', 'HOME': '/nonexistent'}


def public_file(path, maximum=MAX_BYTES):
    """Open each installed component without following links; detect replacement."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('absolute installed path required')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:-1]:
            info = os.fstat(directory)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('unprotected installed directory')
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        info = os.fstat(directory)
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('unprotected installed parent')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022:
            raise ValueError('unprotected installed file')
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    if len(raw) > maximum or identity(before) != identity(after):
        raise ValueError('installed file changed or exceeds bound')
    return raw, {'sha256': hashlib.sha256(raw).hexdigest(), 'device': before.st_dev,
                 'inode': before.st_ino, 'mtime_ns': before.st_mtime_ns, 'ctime_ns': before.st_ctime_ns}


def run(argv, timeout=15):
    deadline = time.monotonic() + timeout
    output = bytearray()
    with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, env=SAFE_ENV, cwd='/') as child:
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(child.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not ready.select(remaining):
                        raise ValueError('public operation deadline exceeded')
                    chunk = os.read(child.stdout.fileno(), min(4096, MAX_BYTES + 1 - len(output)))
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > MAX_BYTES:
                        raise ValueError('public operation output exceeds bound')
            child.wait(timeout=max(0.001, deadline - time.monotonic()))
            if child.returncode:
                raise ValueError('public operation failed')
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
    return output.decode()


def declaration():
    raw, _ = public_file(MANIFEST, 65536)
    value = json.loads(raw)
    if value.get('track') != 'C' or value.get('architecture_profile') != 'direct_per_key' or value.get('active') is not True:
        raise ValueError('active C declaration required')
    if set(value['services']) != set(SERVICES):
        raise ValueError('exact C services required')
    for name, unit in SERVICES.items():
        service = value['services'][name]
        if (service['unit'] != unit or service['executable_path'] != '/opt/track-c/runtime/' + name
                or service['config_path'] != '/etc/track-c/' + name + '.toml'
                or service['admin_address'] != ('127.0.0.1:3536' if name == 'captaind' else '127.0.0.1:3538')):
            raise ValueError('C service scope differs')
    return value


def helper(manifest):
    path = Path(__file__).absolute().with_name('public_observer.py')
    raw, facts = public_file(path)
    if facts['sha256'] != manifest['observer_files']['public_observer.py']:
        raise ValueError('public SQL generator differs from declaration')
    module = type(sys)('track_c_public')
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def allowed_sql(sql, public):
    if len(sql) > 65536:
        return False
    if sql in (public.claimant_sql(), public.claimant_sql(closed=True), public.direct_journal_sql()):
        return True
    match = re.search(r" > '([a-zA-Z0-9:_-]{0,128})' ORDER BY ", sql)
    if not match:
        return False
    # Recreate fixed page SQL using the installed generator, without any DB call.
    class Captured(Exception):
        pass
    generated = []
    def capture(*args):
        generated.append(args)
        raise Captured()
    previous = public.ops
    public.ops = capture
    try:
        for kind in ('coins', 'pending', 'links', 'records', 'nursery'):
            try:
                public.page(kind, match[1])
            except Captured:
                pass
    finally:
        public.ops = previous
    return any(args == ('sql', sql) for args in generated)


def core(args):
    if args == ['getblockchaininfo'] or args == ['getblockhash', '0']:
        pass
    elif len(args) == 2 and args[0] == 'getdescriptorinfo':
        if len(args[1]) > 1024 or not re.fullmatch(r"[a-zA-Z0-9\[\]/(),#*<>;']+", args[1]) or re.search(r'xprv|tprv|(?:^|[^1-9A-HJ-NP-Za-km-z])[59cKL][1-9A-HJ-NP-Za-km-z]{50,51}(?:[^1-9A-HJ-NP-Za-km-z]|$)', args[1]):
            raise ValueError('public descriptor required')
    elif len(args) == 2 and args[0] == 'decoderawtransaction':
        if not re.fullmatch(r'(?:[0-9a-f]{2}){10,1048576}', args[1]):
            raise ValueError('bounded public stripped body required')
    else:
        raise ValueError('unsupported public Core operation')
    return run([CORE, '-signet', '-datadir=/srv/track-c-data/bitcoin',
                '-rpccookiefile=/srv/track-c-data/bitcoin/signet/.cookie', *args])


def operating_projection(cfg, service, manifest):
    """Execute the exact existing public projector and its fixed dependencies.

    The installed deployment declaration chooses hashes, never code paths or a
    caller-supplied callback. All bytes are authenticated before execution. This
    supplies configuration facts only; it grants no financial admission.
    """
    if 'operating_projection' not in manifest:
        return None
    binding = manifest['operating_projection']
    names = {'c_runtime_profile.py', 'model.py', 'bip39-english.txt'}
    if not isinstance(binding, dict) or set(binding) != names:
        raise ValueError('exact C operating projection package required')
    root = Path('/opt/track-c/observer/operating-projection')
    originals = {}
    for name in sorted(names):
        expected = binding[name]
        if not isinstance(expected, str) or re.fullmatch('[0-9a-f]{64}', expected) is None:
            raise ValueError('exact C operating projection source hash required')
        raw, facts = public_file(root / name, 256 * 1024)
        if facts['sha256'] != expected:
            raise ValueError('installed C operating projection source differs')
        originals[name] = raw
    # A literal private package namespace prevents a sys.path or cached-module
    # selection from replacing the already authenticated sibling model module.
    namespace = '_track_c_operating_projection'
    selected = (namespace, namespace + '.model', namespace + '.c_runtime_profile')
    previous = {key: sys.modules.get(key) for key in selected}
    try:
        package = type(sys)(namespace)
        package.__path__ = []
        sys.modules[namespace] = package
        for name in ('model', 'c_runtime_profile'):
            module = type(sys)(namespace + '.' + name)
            module.__package__ = namespace
            module.__file__ = str(root / (name + '.py'))
            sys.modules[module.__name__] = module
            exec(compile(originals[name + '.py'], module.__file__, 'exec'), module.__dict__)
        # Only the existing protected reader reaches public certificates. The
        # shared projector never reads a private key and exports no endpoint.
        result = module.project(cfg, service, public_file)
        for name, raw in originals.items():
            if public_file(root / name, 256 * 1024)[0] != raw:
                raise ValueError('C operating projection package changed during read')
        return result
    finally:
        for key in selected:
            if previous[key] is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = previous[key]


def projected_config(service, manifest):
    declared = manifest['services'][service]
    raw, facts = public_file(declared['config_path'], 65536)
    if facts['sha256'] != declared['config_sha256']:
        raise ValueError('config differs from declaration')
    cfg = tomllib.loads(raw.decode())
    if cfg.get('network') != 'signet' or cfg.get('postgres', {}).get('name') != 'trackc':
        raise ValueError('C chain/database differs')
    if (cfg.get('data_dir') != '/srv/track-c-data/captaind'
            or service == 'watchmand' and cfg.get('watchman', {}).get('direct_expiry', {}).get('history_dir') != '/srv/track-c-data/captaind'):
        raise ValueError('C shared protected history directory differs')
    result = {'sha256': facts['sha256'], 'network': cfg['network'], 'postgres_database': cfg['postgres']['name']}
    for name in ('vtxo_lifetime', 'min_trusted_confs', 'round_interval', 'required_board_confirmations'):
        if name in cfg:
            result[name] = cfg[name]
    result['fee_estimator'] = {name: cfg['fee_estimator'][name] for name in
        ('update_interval', 'history_duration', 'fallback_fee_rate_fast', 'fallback_fee_rate_regular',
         'fallback_fee_rate_slow', 'max_fee_rate') if name in cfg.get('fee_estimator', {})}
    if 'watchman' in cfg:
        result['watchman'] = {name: cfg['watchman'][name] for name in
            ('reaction_interval', 'sweep_interval', 'progress_grace_period', 'claim_chunksize',
             'incremental_relay_fee', 'min_cpfp_amount') if name in cfg['watchman']}
        if cfg['watchman'].get('direct_expiry') is not None:
            result['watchman']['direct_expiry'] = {name: cfg['watchman']['direct_expiry'][name]
                for name in ('history_dir', 'max_miner_fee') if name in cfg['watchman']['direct_expiry']}
    if service == 'captaind':
        # Never infer defaults: pilot policy must be explicit in the actual file.
        result['vtxopool'] = {name: cfg['vtxopool'][name] for name in ('vtxo_lifetime', 'vtxo_targets')}
        result['pool_lifetime_blocks'] = cfg['vtxopool']['vtxo_lifetime']
        result['direct_expiry'] = {name: cfg['direct_expiry'][name] for name in
            ('enabled', 'interval', 'grace_blocks', 'max_groups_per_tick') if name in cfg['direct_expiry']}
        result['expiry_payout'] = {'enabled': cfg['expiry_payout']['enabled']}
        result['lightning_configured'] = bool(cfg.get('cln_array', []))
    operating = operating_projection(cfg, service, manifest)
    if operating is not None:
        result['operating_source'] = operating
    if public_file(declared['config_path'], 65536) != (raw, facts):
        raise ValueError('native config changed during public projection')
    return result, facts


def systemd(service):
    properties = ('MainPID', 'ExecMainStartTimestamp', 'InvocationID', 'NRestarts', 'ActiveState', 'SubState')
    raw = run(['/usr/bin/systemctl', '--timestamp=us', 'show', SERVICES[service],
               '--no-pager', '--property=' + ','.join(properties)])
    values = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
    if set(values) != set(properties):
        raise ValueError('incomplete native systemd properties')
    return values


def start_ticks(pid):
    raw = Path('/proc/' + str(pid) + '/stat').read_text()
    return int(raw[raw.rindex(')') + 2:].split()[19])


def started_at(value):
    match = re.fullmatch(r'[A-Za-z]{3} (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d{1,6})?) UTC', value)
    if not match:
        raise ValueError('exact UTC native process start time required')
    parsed = datetime.datetime.fromisoformat(match[1]).replace(tzinfo=datetime.timezone.utc)
    return parsed.isoformat().replace('+00:00', 'Z')


def runtime(service, manifest):
    expected = manifest['services'][service]
    before = systemd(service)
    pid = int(before['MainPID'])
    if pid <= 0 or before['ActiveState'] != 'active' or before['SubState'] != 'running':
        raise ValueError('native C daemon is not running')
    ticks = start_ticks(pid)
    proc = Path('/proc/' + str(pid))
    uid = pwd.getpwnam('trackcserver').pw_uid
    statuses = [line for line in (proc / 'status').read_text().splitlines() if line.startswith('Uid:')]
    if len(statuses) != 1 or [int(value) for value in statuses[0].split()[1:]] != [uid] * 4:
        raise ValueError('actual native process owner differs')
    exe = os.readlink(proc / 'exe')
    if exe != expected['executable_path']:
        raise ValueError('actual native executable path differs')
    # Hash the actual running executable through its kernel handle.
    with (proc / 'exe').open('rb') as stream:
        actual_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
    installed_hash = public_file(exe, 128 * 1024 * 1024)[1]['sha256']
    if actual_hash != installed_hash or actual_hash != expected['executable_sha256']:
        raise ValueError('actual native executable bytes differ')
    cmdline = (proc / 'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
    if cmdline != [exe, '--config', expected['config_path'], 'start']:
        raise ValueError('actual native command differs')
    env_bytes = (proc / 'environ').read_bytes()
    if len(env_bytes) > 131072:
        raise ValueError('native environment bound exceeded')
    env = dict(item.split(b'=', 1) for item in env_bytes.split(b'\0') if item)
    names = sorted(name.decode('ascii') for name in env)
    if len(names) > 256 or any(re.fullmatch('[A-Za-z_][A-Za-z_0-9]{0,127}', name) is None for name in names):
        raise ValueError('invalid native environment names')
    invocation = before['InvocationID']
    if not re.fullmatch('[0-9a-f]{32}', invocation) or env.get(b'INVOCATION_ID', b'').decode() != invocation:
        raise ValueError('native invocation differs')
    overrides = {}
    for name in names:
        if name.upper().startswith(('CAPTAIND_', 'WATCHMAND_', 'BARK_SERVER_')):
            if name not in ('CAPTAIND_LOG', 'WATCHMAND_LOG') or env[name.encode()] != b'info':
                raise ValueError('native config environment override refused')
            overrides[name] = 'info'
    config, facts = projected_config(service, manifest)
    capture_path = '/run/track-c-startup/' + service + '-' + invocation + '.json'
    pre = json.loads(public_file(capture_path, 4096)[0])
    fields = {'path', 'sha256', 'device', 'inode', 'mtime_ns', 'ctime_ns', 'captured_at_ns', 'invocation_id'}
    if (set(pre) != fields or pre['path'] != expected['config_path'] or pre['invocation_id'] != invocation
            or any(pre[k] != facts[k] for k in facts)):
        raise ValueError('original pre-exec config facts differ')
    version = run([exe, '--version']).strip()
    if manifest['financial_pins']['product_commit'] not in version:
        raise ValueError('actual native release version differs')
    if before != systemd(service) or ticks != start_ticks(pid):
        raise ValueError('native daemon changed during observation')
    return {'unit': SERVICES[service], 'pid': pid, 'started_at': started_at(before['ExecMainStartTimestamp']),
        'restart_count': int(before['NRestarts']), 'running': True, 'binary_sha256': installed_hash,
        'process_exe_path': exe, 'process_exe_sha256': actual_hash, 'process_cmdline': cmdline, 'version': version,
        'config_path': expected['config_path'], 'config_sha256': facts['sha256'],
        'config_ctime_ns': facts['ctime_ns'], 'config_mtime_ns': facts['mtime_ns'],
        'config_device': facts['device'], 'config_inode': facts['inode'], 'environment_names': names,
        'config_overrides': overrides, 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'start_ticks': ticks, 'invocation_id': invocation, 'pre_exec_config': pre,
        'public_loaded_config_provenance': config}


def dispatch(args):
    if not args:
        raise ValueError('fixed public operation required')
    manifest = declaration()
    verb = args[0]
    if args == ['closed-frontier-v2']:
        # NEW fixed streaming command only: preserve original stdin/NDJSON and
        # producer status; never pass this through the aggregate run() helper.
        path = '/opt/track-c/runtime/frontier-v2/target_worker.py'
        # This already-trusted ops entry authenticates the complete fixed set
        # BEFORE executing target code that imports any sibling. Root-owned
        # non-writable parents/files prevent an unprivileged replacement.
        names={'adapter_v3.py','frontier_v2_contract.py','dbapi_adapter.py','frontier_stream.py',
            'public-projections.json','wiring_contract.py','protected_files.py','target_worker.py','controller_wrapper.py'}
        expected=manifest.get('closed_frontier_v2',{}).get('source_files')
        if not isinstance(expected,dict) or set(expected)!=names:
            raise ValueError('complete fixed frontier source declaration required')
        directory=Path(path).parent
        for name in sorted(names):
            if public_file(directory/name)[1]['sha256']!=expected[name]:
                raise ValueError('fixed frontier sibling source differs')
        originals=manifest.get('observer_files')
        if not isinstance(originals,dict) or set(originals)!={'server-observer.py','public_observer.py'}:
            raise ValueError('complete original observer source declaration required')
        for name in sorted(originals):
            if public_file(directory/name)[1]['sha256']!=originals[name]:
                raise ValueError('fixed original observer source differs')
        os.execve('/usr/bin/python3', ['/usr/bin/python3', '-I', path], SAFE_ENV)
    if verb == 'sql' and len(args) == 2:
        if not allowed_sql(args[1], helper(manifest)):
            raise ValueError('SQL is not an exact generated public query')
        # Separate OS/database identity and read-only transaction policy.
        return run(['/usr/sbin/runuser', '-u', 'trackcobserver', '--', PSQL,
            '-X', '--no-password', '--host=/run/track-c-postgres', '--dbname=trackc',
            '--username=trackcobserver', '--tuples-only', '--no-align', '--quiet',
            '--set=ON_ERROR_STOP=1', '--command=' + args[1]], timeout=12)
    if verb == 'cli':
        return core(args[1:])
    if verb in ('runtime-identity', 'public-config') and len(args) == 2 and args[1] in SERVICES:
        result = runtime(args[1], manifest) if verb == 'runtime-identity' else projected_config(args[1], manifest)[0]
        return json.dumps(result, separators=(',', ':')) + '\n'
    if verb == 'wallet-inventory' and len(args) == 2 and args[1] in ('rounds', 'watchman'):
        service = 'captaind' if args[1] == 'rounds' else 'watchmand'
        spec = manifest['services'][service]
        if public_file('/opt/track-c/runtime/captaind', 128 * 1024 * 1024)[1]['sha256'] != manifest['services']['captaind']['executable_sha256']:
            raise ValueError('native admin client differs')
        raw = run(['/opt/track-c/runtime/captaind', 'rpc', '--addr', spec['admin_address'], 'wallet-inventory'])
        public = helper(manifest)
        public.ops = lambda *operation: core(list(operation[1:])) if operation[0] == 'cli' else (_ for _ in ()).throw(ValueError('unsupported validation operation'))
        public.validate_wallet_frame(json.loads(raw), args[1], 'signet')
        return raw
    raise ValueError('unsupported public operation')


if __name__ == '__main__':
    try:
        sys.stdout.write(dispatch(sys.argv[1:]))
    except Exception:
        # Subprocess/config error text may contain private transport details.
        print('C public observation held', file=sys.stderr)
        sys.exit(1)

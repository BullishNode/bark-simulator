"""Once-only zero-principal creation of a fresh, predeclared native identity.

This admits no funding or financial readiness. A native reply is followed by a
hold until the independent source verifier records its original zero-asset proof.
"""
import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path

from .final_campaign import _pins, _source_event
from .model import canonical, public_payload, timestamp

KEY = 'zero_principal_identity_bootstrap'


def _hash(path):
    path = Path(path)
    for item in (path, *path.parents):
        if stat.S_ISLNK(item.lstat().st_mode): raise ValueError('bootstrap symlink refused')
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode): raise ValueError('bootstrap regular file required')
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(stream.fileno())
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError('bootstrap context changed while reading')
    return digest


def _root(path):
    root = Path(path)
    if not root.is_absolute() or str(root) != path: raise ValueError('exact absolute bootstrap root required')
    for item in (root, *root.parents):
        if stat.S_ISLNK(item.lstat().st_mode): raise ValueError('bootstrap symlink refused')
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
        raise ValueError('bootstrap root must be owned private directory')
    return {'path': path, 'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid, 'mode': 0o700}


def _sole_writer(root):
    """The existing Engine wallet-root Lease must belong to this process."""
    lock=Path(root)/'supervisor.lock'
    info=lock.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid():
        raise ValueError('bootstrap existing wallet-root Lease required')
    expected=(os.major(info.st_dev),os.minor(info.st_dev),info.st_ino)
    for line in Path('/proc/locks').read_text().splitlines():
        fields=line.split()
        if len(fields)<6 or fields[1]!='FLOCK' or fields[3]!='WRITE' or fields[4]!=str(os.getpid()):continue
        major,minor,inode=fields[5].split(':')
        if (int(major,16),int(minor,16),int(inode))==expected:return
    raise ValueError('bootstrap requires this process to hold the existing wallet-root Lease')


def _context(config, value, *, store=None):
    selected = getattr(config, 'architecture_profile', None)
    if (selected not in {'two_step_per_key','direct_xpub','direct_per_key'}
            or config.expected_sdk_commit != value['pins']['sdk_commit']
            or str(config.wallet_root) != value['wallet_root']
            or len(config.driver_command) != 1):
        raise ValueError('exact profiled bootstrap driver context required')
    genesis_by_network={'signet':'00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6',
        'regtest':'0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206'}
    if config.network not in genesis_by_network or config.expected_genesis!=genesis_by_network[config.network]:
        raise ValueError('exact bootstrap network/genesis required')
    identity = {'network': config.network, 'genesis': config.expected_genesis,
                'container': config.expected_container, 'image_digest': config.expected_image,
                'server_pubkey': config.expected_server_pubkey}
    from .target_epochs import active_runtime_manifest,active_identity
    manifest=active_runtime_manifest(store) if store is not None else None
    if manifest is None:
        if value['identity'] != identity: raise ValueError('bootstrap target identity differs')
    else:
        original=declaration(store)
        if (original is None or original['declaration']!=value
                or value['identity']!=manifest['previous_identity'] or identity!=active_identity(store)):
            raise ValueError('historical native context differs from declared deployment')
        if _root(value['wallet_root'])!=original['filesystem']:
            raise ValueError('original historical wallet root identity changed')
    driver = Path(config.driver_command[0])
    if not driver.is_absolute() or _hash(driver) != value['pins']['driver_sha256']:
        raise ValueError('bootstrap native driver differs')
    path = Path(os.environ.get('SIM_DRIVER_CONFIG', ''))
    if not path.is_absolute() or _hash(path) != value['driver_config_sha256']:
        raise ValueError('bootstrap driver configuration differs')
    raw = path.read_bytes()
    if len(raw) > 65536 or hashlib.sha256(raw).hexdigest() != value['driver_config_sha256']:
        raise ValueError('bootstrap driver configuration changed')
    native = json.loads(raw)
    if selected in {'two_step_per_key','direct_per_key'} and native.get('architecture_profile') != selected:
        raise ValueError('per-key bootstrap requires the actual explicitly profiled native adapter')
    if (native.get('wallet_root') != value['wallet_root'] or native.get('network') != config.network
            or not isinstance(native.get('ark_endpoint'), str) or not native['ark_endpoint']):
        raise ValueError('bootstrap native configuration scope differs')
    wallet_config = Path(native['wallet_config'])
    if not wallet_config.is_absolute() or _hash(wallet_config) != value['wallet_config_sha256']:
        raise ValueError('bootstrap wallet configuration differs')
    return {'driver_sha256': value['pins']['driver_sha256'],
            'driver_config_sha256': value['driver_config_sha256'],
            'wallet_config_sha256': value['wallet_config_sha256']}


def declaration(store):
    encoded = store.get_meta(KEY)
    if encoded is None: return None
    rows = store.db.execute("SELECT sequence,payload FROM event WHERE kind='identity_bootstrap_declared'").fetchall()
    if len(rows) != 1: raise ValueError('original bootstrap declaration missing')
    _, proof = _source_event(store, rows[0]['sequence'])
    if canonical(proof['declaration']) != encoded: raise ValueError('bootstrap declaration changed')
    return proof


def declare(store, config, value):
    fields = {'id', 'pins', 'identity', 'wallet_root', 'actors', 'driver_config_sha256', 'wallet_config_sha256'}
    if not isinstance(value, dict) or set(value) != fields or not value['id']:
        raise ValueError('complete zero-principal bootstrap declaration required')
    _pins(value['pins']); public_payload(value)
    for key in ('driver_config_sha256', 'wallet_config_sha256'):
        if not isinstance(value[key], str) or re.fullmatch('[0-9a-f]{64}', value[key]) is None:
            raise ValueError('exact bootstrap configuration hashes required')
    actors = value['actors']
    if (not isinstance(actors, list) or not 1 <= len(actors) <= 12
            or any(not isinstance(actor, str) or re.fullmatch('actor-[0-9]{2}', actor) is None for actor in actors)
            or len(set(actors)) != len(actors)):
        raise ValueError('bounded predeclared bootstrap actors required')
    old = declaration(store)
    if old is not None:
        if old['declaration'] != value: raise ValueError('bootstrap declaration immutable')
        return False
    context = _context(config, value)
    filesystem = _root(value['wallet_root'])
    if any(Path(value['wallet_root']).iterdir()): raise ValueError('bootstrap root must initially be empty')
    with store.transaction():
        if not store.get_meta('paused'): raise ValueError('pause before bootstrap declaration')
        if store.db.execute('SELECT 1 FROM action LIMIT 1').fetchone(): raise ValueError('bootstrap precedes all client actions')
        if store.db.execute("SELECT 1 FROM event WHERE kind LIKE 'fixture_funding_%' AND kind!='fixture_funding_declared' LIMIT 1").fetchone():
            raise ValueError('bootstrap precedes funding')
        for actor in actors:
            row = store.db.execute('SELECT details FROM actor WHERE id=?', (actor,)).fetchone()
            if row is None or json.loads(row[0]) or not store.ordinary_actor_available(actor):
                raise ValueError('bootstrap actor must be fresh and uncontrolled')
        store.db.execute('INSERT INTO meta VALUES (?,?)', (KEY, canonical(value)))
        store._event('identity_bootstrap_declared', {'declaration': value, 'context': context,
            'filesystem': filesystem, 'filesystem_sha256': hashlib.sha256(canonical(filesystem).encode()).hexdigest(),
            'allowed_operation': 'create', 'maximum_fee_sat': 0, 'financial_readiness': False})
        store.db.execute("INSERT OR IGNORE INTO meta VALUES ('financial_qualification_required','true')")
    return True


def pending(store):
    proof = declaration(store)
    if proof is None: return False
    value = proof['declaration']
    verified = set()
    for row in store.db.execute("SELECT sequence FROM event WHERE kind='identity_bootstrap_zero_assets_verified'"):
        _, item = _source_event(store, row['sequence'])
        if item.get('financial_pins') != value['pins'] or item.get('bootstrap_id') != value['id']:
            raise ValueError('bootstrap zero-asset source context differs')
        actor = item.get('actor')
        if actor not in value['actors'] or actor in verified or item.get('complete') is not True or item.get('zero_assets') is not True:
            raise ValueError('bootstrap zero-asset proof invalid or repeated')
        event, native = _source_event(store, item['driver_response_sequence'])
        if (event['kind'] != 'driver_response' or native.get('action_id') != item.get('action_id')
                or native['response'].get('status') != 'ok' or native['response'].get('actual_fee_sat') != 0
                or hashlib.sha256(canonical(native['response']).encode()).hexdigest() != item.get('native_response_sha256')):
            raise ValueError('bootstrap native response source differs')
        action = store.db.execute('SELECT actor_id,operation,state,actual_fee_sat FROM action WHERE id=?', (item['action_id'],)).fetchone()
        if action is None or tuple(action) != (actor, 'create', 'completed', 0):
            raise ValueError('bootstrap original completed create missing')
        verified.add(actor)
    return verified != set(value['actors'])


def require_only_verified_creates(store, pins):
    """Permit historical bootstrap dispatches before paused money declarations.

    A completed zero-fee action alone is insufficient: the immutable bootstrap
    intent, original response and independent zero-asset proof must all agree.
    This checks historical admission only and grants no financial readiness.
    """
    if not store.get_meta('paused'):
        raise ValueError('pause before checking pre-funding bootstrap history')
    dispatches = store.db.execute("SELECT sequence FROM event WHERE kind='action_dispatched' LIMIT 13").fetchall()
    if not dispatches:
        return
    original = declaration(store)
    if original is None or len(dispatches) > 12 or original['declaration']['pins'] != pins or pending(store):
        raise ValueError('only independently verified bootstrap creates may precede financial declarations')
    value = original['declaration']
    declared = store.db.execute("SELECT sequence FROM event WHERE kind='identity_bootstrap_declared'").fetchone()[0]
    seen = set()
    for row in dispatches:
        dispatch_event, dispatch = _source_event(store, row['sequence'])
        action_id = dispatch.get('action_id')
        action = store.db.execute('SELECT * FROM action WHERE id=?', (action_id,)).fetchone()
        if (action is None or action['actor_id'] not in value['actors'] or action['actor_id'] in seen
                or action['operation'] != 'create' or action['state'] != 'completed'
                or json.loads(action['args']) != {} or action['fee_reservation_sat'] != 0
                or action['actual_fee_sat'] != 0 or dispatch.get('actor') != action['actor_id']):
            raise ValueError('non-bootstrap, repeated, paid or unfinished dispatch precedes financial declaration')
        seen.add(action['actor_id'])

        def one(kind):
            rows = store.db.execute("SELECT sequence FROM event WHERE kind=? AND json_extract(payload,'$.action_id')=?", (kind, action_id)).fetchall()
            if len(rows) != 1:
                raise ValueError('unique original verified bootstrap action sources required')
            return _source_event(store, rows[0][0])

        intent_event, intent = one('action_intent')
        begin_event, begin = one('identity_bootstrap_create_intent')
        response_event, native = one('driver_response')
        verified_event, verified = one('identity_bootstrap_zero_assets_verified')
        response = native['response']
        if (intent.get('actor') != action['actor_id'] or intent.get('operation') != 'create'
                or intent.get('args') != {} or intent.get('fee_reservation_sat') != 0
                or begin.get('actor') != action['actor_id'] or begin.get('operation') != 'create'
                or begin.get('bootstrap_id') != value['id'] or begin.get('financial_pins') != pins
                or begin.get('maximum_fee_sat') != 0 or begin.get('actor_path_absent') is not True
                or response != json.loads(action['result']) or response.get('action_id') != action_id
                or verified.get('actor') != action['actor_id']
                or verified.get('bootstrap_declaration_sha256') != hashlib.sha256(canonical(value).encode()).hexdigest()
                or verified.get('source_sequence') != response_event['sequence']
                or verified.get('driver_response_sequence') != response_event['sequence']
                or verified.get('source_event_hash') != response_event['hash']
                or verified.get('confirmed_assets_sat') != 0 or verified.get('unconfirmed_assets_sat') != 0
                or not declared < intent_event['sequence'] < dispatch_event['sequence']
                    < begin_event['sequence'] < response_event['sequence'] < verified_event['sequence']):
            raise ValueError('original verified zero-fee bootstrap history differs')
    if seen != set(value['actors']):
        raise ValueError('every declared bootstrap identity requires its original verified dispatch')


def eligible(store, config, snapshot, action=None):
    proof = declaration(store)
    if proof is None or not pending(store): return False
    value = proof['declaration']
    _context(config, value)
    if _root(value['wallet_root']) != proof['filesystem']: raise ValueError('bootstrap root identity changed')
    _sole_writer(value['wallet_root'])
    config.validate_identity(snapshot)
    if snapshot.get('financial_pins') != value['pins']: raise ValueError('bootstrap actual financial pins differ')
    if (not 0 <= time.time()-timestamp(snapshot['observed_at'],'bootstrap observation') <= 90
            or snapshot.get('stable_tip') is not True or snapshot.get('initial_block_download') is not False
            or snapshot.get('server_status',{}).get('status') != 'running'):
        raise ValueError('bootstrap requires fresh healthy target observation')
    if store.db.execute("SELECT 1 FROM action WHERE state='outcome_unknown' LIMIT 1").fetchone():
        raise ValueError('bootstrap unknown outcome parked; never retry')
    if store.db.execute("SELECT 1 FROM event WHERE kind LIKE 'fixture_funding_%' AND kind!='fixture_funding_declared' LIMIT 1").fetchone():
        raise ValueError('bootstrap funding detected')
    # A completed create waits for its independent native/Core zero-asset proof
    # before even another zero-principal identity is admitted.
    verified = {json.loads(row[0])['actor'] for row in store.db.execute(
        "SELECT payload FROM event WHERE kind='identity_bootstrap_zero_assets_verified'")}
    intents = [json.loads(row[0]) for row in store.db.execute("SELECT payload FROM event WHERE kind='identity_bootstrap_create_intent'")]
    allowed={'supervisor.lock'}|{item['actor'] for item in intents}
    if any(path.name not in allowed or path.is_symlink() for path in Path(value['wallet_root']).iterdir()):
        raise ValueError('bootstrap root contains unexpected files')
    if any(item['actor'] not in verified for item in intents): raise ValueError('bootstrap awaiting independent zero-asset proof')
    if action is None: return True
    actor = action['actor_id']
    if action['operation'] != 'create' or action['fee_reservation_sat'] != 0 or action['args'] or actor not in value['actors']:
        raise ValueError('bootstrap permits only predeclared zero-fee create')
    if any(item['actor'] == actor for item in intents): raise ValueError('bootstrap create already attempted; never retry')
    if os.path.lexists(Path(value['wallet_root']) / actor): raise ValueError('bootstrap actor path already exists')
    if store.db.execute("SELECT 1 FROM action WHERE state='dispatched' AND id!=? LIMIT 1", (action['id'],)).fetchone():
        raise ValueError('bootstrap requires sole writer')
    return True


def begin(store, config, snapshot, action):
    if not eligible(store, config, snapshot, action): raise ValueError('bootstrap is not active')
    proof = declaration(store)
    value = proof['declaration']
    with store.transaction():
        store._event('identity_bootstrap_create_intent', {'bootstrap_id': value['id'],
            'financial_pins': value['pins'], 'actor': action['actor_id'], 'action_id': action['id'],
            'operation': 'create', 'maximum_fee_sat': 0, 'actor_path_absent': True,
            'filesystem': _root(value['wallet_root']), 'context': _context(config, value),
            'unknown_outcome': 'park; never retry or regenerate identity'})


def verify_created(store,config,chain,actor,action_id):
    """Invoke the actual native/Core verifier; a reply or balance is insufficient."""
    proof=declaration(store)
    if proof is None:raise ValueError('bootstrap declaration missing')
    value=proof['declaration']
    _context(config,value)
    if _root(value['wallet_root'])!=proof['filesystem']:raise ValueError('bootstrap root identity changed')
    from .closed_cohort_sources import verify_bootstrap_zero_assets
    return verify_bootstrap_zero_assets(store,config,chain,actor,action_id,bootstrap_declaration=value)

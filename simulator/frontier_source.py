"""Explicit protected schema-2 source collection and original-trace re-admission.

The fixed installed packet grants no readiness. Every existing financial,
owner, runtime, independent chain, freshness and asset predicate remains needed.
"""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import threading
import types

from .architecture import DIRECT_PER_KEY
from .final_campaign import _pins, _source_event
from .model import canonical, public_payload

BINDING = Path('/etc/track-c/frontier-v2-controller.json')
SOURCE_ROOT = Path('/opt/track-c/runtime/frontier-v2')
WRAPPER = Path('/opt/track-c/bin/observer-v2')
SOURCE_FILES = frozenset({
    'adapter_v3.py', 'frontier_v2_contract.py', 'dbapi_adapter.py',
    'frontier_stream.py', 'public-projections.json', 'wiring_contract.py',
    'protected_files.py', 'target_worker.py', 'controller_wrapper.py'})
_IMPORT_LOCK = threading.RLock()


# Reused unchanged from the existing trusted observer reader. This must run
# BEFORE importing any installed sibling, including protected_files itself.
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



def _strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate protected binding key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite binding')))


def schema(config):
    value = getattr(config, 'closed_frontier_schema', 1)
    if type(value) is not int or value not in (1, 2):
        raise ValueError('explicit frontier schema must be 1 or 2')
    if value == 2 and (config.architecture_profile != DIRECT_PER_KEY
                      or config.trace_enabled is not True):
        raise ValueError('schema 2 requires explicit C profile and original trace')
    return value


def _bootstrap():
    raw, digest = checked_file(BINDING, maximum=65536)
    binding = _strict_json(raw)
    if (not isinstance(binding, dict)
            or set(binding) != {'expected_contract', 'observer_wrapper_sha256', 'source_files'}):
        raise ValueError('exact protected frontier binding required')
    files = binding['source_files']
    if (not isinstance(files, dict) or set(files) != SOURCE_FILES
            or any(not isinstance(v, str) or re.fullmatch('[0-9a-f]{64}', v) is None
                   for v in files.values())
            or not isinstance(binding['observer_wrapper_sha256'], str)
            or re.fullmatch('[0-9a-f]{64}', binding['observer_wrapper_sha256']) is None):
        raise ValueError('all exact protected source hashes required before import')
    sources = {}
    for name in sorted(SOURCE_FILES):
        source, actual = checked_file(SOURCE_ROOT / name)
        if actual != files[name]:
            raise ValueError('protected source differs before import')
        sources[name] = source
    if checked_file(WRAPPER)[1] != binding['observer_wrapper_sha256']:
        raise ValueError('protected fixed wrapper differs before import')
    # Execute only bytes authenticated above. Do not inherit an unrelated module
    # with a colliding top-level name from an earlier application import.
    with _IMPORT_LOCK:
        saved = {name: sys.modules.get(name) for name in ('protected_files', 'wiring_contract')}
        try:
            modules = {}
            for name in ('protected_files', 'wiring_contract', 'controller_wrapper'):
                module = types.ModuleType(name)
                module.__file__ = str(SOURCE_ROOT / (name + '.py'))
                exec(compile(sources[name + '.py'], module.__file__, 'exec'), module.__dict__)
                modules[name] = module
                if name != 'controller_wrapper':
                    sys.modules[name] = module
            controller = modules['controller_wrapper']
        finally:
            for name, previous in saved.items():
                if previous is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = previous
    if checked_file(BINDING, maximum=65536)[1] != digest:
        raise ValueError('protected binding changed during import')
    return controller, binding, digest


def _context(controller, binding, config, pins, *, timeout=None):
    _pins(pins)
    expected = controller.protected_binding()
    source = expected['source_binding']
    if expected != binding['expected_contract'] or expected['financial_pins'] != pins:
        raise ValueError('protected frontier financial context differs')
    if config is not None and (source['network'] != config.network
            or source['genesis'] != config.expected_genesis
            or source['server_pubkey'] != config.expected_server_pubkey):
        raise ValueError('protected frontier chain/server identity differs')
    if timeout is not None and expected['resource_declaration']['deadline_ms'] > int(timeout * 1000):
        raise ValueError('protected producer deadline exceeds existing caller allowance')
    return expected


def _same_binding(digest):
    if checked_file(BINDING, maximum=65536)[1] != digest:
        raise ValueError('protected binding changed during source use')


def verify_frame(store, config, frame, pins):
    selected = schema(config) if config is not None else None
    if not isinstance(frame, dict):
        raise ValueError('original frontier object required')
    actual = frame.get('schema_version')
    if selected == 1:
        if actual == 2:
            raise ValueError('frontier schema differs from explicit selection')
        return frame  # Preserve existing legacy validators unchanged.
    if type(actual) is not int or actual not in (1, 2) or selected == 2 and actual != 2:
        raise ValueError('frontier schema differs from explicit selection')
    if actual == 1:
        return frame
    public_payload(frame)
    controller, binding, digest = _bootstrap()
    _context(controller, binding, config, pins)
    if getattr(store, 'trace', None) is None:
        raise ValueError('original TraceStore required for schema 2')
    result = controller.verify(frame, store.trace)
    _same_binding(digest)
    return result


async def collect(store, config, pins, *, timeout=25):
    if schema(config) != 2:
        raise ValueError('protected collection requires explicit schema 2 opt-in')
    controller, binding, digest = _bootstrap()
    _context(controller, binding, config, pins, timeout=timeout)
    trace = getattr(store, 'trace', None)
    if trace is None:
        raise ValueError('original TraceStore required for schema 2')
    # Producer pipes retain the declared deadline and are killed/reaped by the
    # frozen adapter. Existing caller allowance is never enlarged. Cancellation
    # cannot hard-interrupt filesystem/SQLite trace I/O in the worker thread;
    # that inherited resource qualification remains OPEN, not a claimed bound.
    result = await asyncio.wait_for(asyncio.to_thread(controller.collect, trace), timeout=timeout)
    controller.verify(result, trace)
    _same_binding(digest)
    return result


def verify_event(store, config, sequence, pins):
    event, source = _source_event(store, sequence)
    frame = source.get('response')
    if (event['kind'] != 'closed_cohort_original_source'
            or source.get('source_kind') != 'closed_frontier'
            or source.get('financial_pins') != pins
            or source.get('response_sha256') != hashlib.sha256(canonical(frame).encode()).hexdigest()):
        raise ValueError('original frontier source event/context/digest differs')
    return verify_frame(store, config, frame, pins)


def verify_source(store, config, source, pins, *, _depth=0):
    """Replay each current DB source and its retained funding/cash ancestors."""
    if _depth > 2:
        raise ValueError('frontier source ancestry exceeds fixed funding/cash/backing chain')
    selected = schema(config) if config is not None else None
    if not isinstance(source,dict):
        if selected == 1:return  # Legacy fixture/consumer shape unchanged.
        raise ValueError('retained frontier source object required')
    frame = source.get('database')
    sequence = source.get('database_source_sequence')
    # Legacy source shape stays untouched. A v2 inline frame can never enter
    # without its separate immutable original event, even in config-free plan validation.
    if sequence is None:
        if selected == 2 or isinstance(frame, dict) and frame.get('schema_version') == 2:
            raise ValueError('original frontier source event required')
        return
    _, retained = _source_event(store, sequence)
    version = retained.get('response', {}).get('schema_version')
    if selected == 1:
        if version == 2 or isinstance(frame, dict) and frame.get('schema_version') == 2:
            raise ValueError('schema 2 requires explicit consumer opt-in')
        return
    if selected is None and version != 2:
        return  # No legacy plan-validation behavior change.
    if source.get('financial_pins') != pins:
        raise ValueError('retained frontier source financial context differs')
    original = verify_event(store, config, sequence, pins)
    if frame is not None and frame != original:
        raise ValueError('inline frontier differs from immutable original event')
    if ('database_response_sha256' in source and source['database_response_sha256']
            != hashlib.sha256(canonical(original).encode()).hexdigest()):
        raise ValueError('retained frontier digest differs')
    for key, kind in (('finite_initial_source_sequence', 'finite_initial_funding_sources_verified'),
                      ('cash_source_sequence', 'finite_fresh_cash_sources_verified')):
        if key in source:
            event, parent = _source_event(store, source[key])
            if event['kind'] != kind:
                raise ValueError('retained frontier ancestor kind differs')
            verify_source(store, config, parent, pins, _depth=_depth + 1)

"""Proposed controller seam: fixed protected wrapper -> frozen v3 trace replay."""
import importlib.util
import re
from pathlib import Path

from protected_files import checked_file
import wiring_contract as w

CONTROLLER_BINDING = Path('/etc/track-c/frontier-v2-controller.json')
OBSERVER_WRAPPER = Path('/opt/track-c/bin/observer-v2')
ADAPTER_SHA256 = '8f3bdabf931e9188e00d9023da5c0389b9da9f2901530f734796bb76d00728c2'


def adapter():
    path = Path(__file__).resolve().with_name('adapter_v3.py')
    if checked_file(path)[1] != ADAPTER_SHA256:
        raise ValueError('protected frozen original-trace adapter differs')
    spec = importlib.util.spec_from_file_location('protected_fixed_frontier_adapter', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def protected_binding():
    raw, _ = checked_file(CONTROLLER_BINDING, maximum=65536)
    f = w.contract().adapter().frontier()
    value = f.strict_json(raw)
    if (not isinstance(value, dict) or set(value) != {'expected_contract', 'observer_wrapper_sha256', 'source_files'}
            or not isinstance(value['observer_wrapper_sha256'], str)
            or re.fullmatch('[0-9a-f]{64}', value['observer_wrapper_sha256']) is None):
        raise ValueError('explicit protected fixed observer binding required')
    files = value['source_files']
    if (not isinstance(files, dict) or set(files) != w.SOURCE_FILES
            or any(not isinstance(digest, str) or re.fullmatch('[0-9a-f]{64}', digest) is None
                   for digest in files.values())):
        raise ValueError('exact protected fixed sibling source hashes required')
    # The already-trusted common caller MUST check this same protected map
    # BEFORE importing this module or any sibling. Rechecking here is defense
    # in depth, never retrospective proof that the initial import was safe.
    for name in sorted(w.SOURCE_FILES):
        if checked_file(Path(__file__).resolve().with_name(name))[1] != files[name]:
            raise ValueError('actual protected fixed sibling source differs')
    expected = w.contract().expected_contract(value['expected_contract'])
    if checked_file(OBSERVER_WRAPPER)[1] != value['observer_wrapper_sha256']:
        raise ValueError('actual protected fixed observer wrapper differs')
    return expected


def collect(trace_store):
    """No caller-selected SQL, command, host, expected claims or proof callbacks."""
    expected = protected_binding()
    # Existing exact deployment SSH transport belongs inside the root-installed
    # wrapper. Its path is fixed here and its actual bytes independently pinned.
    # Only the original public fixed request enters stdin, never PG credentials.
    return adapter()._run([str(OBSERVER_WRAPPER)], w.contract().request(expected),
                          expected, trace_store)


def verify(frame, trace_store):
    """Re-admit only the original whole stream under current protected pins.

    Consumers must retain every existing independent chain, owner, signed-proof,
    runtime, accounting, source-event and freshness check around this DB frame.
    This method alone does not create financial readiness.
    """
    expected = protected_binding()
    a = adapter()
    return a.contract().verify_snapshot(
        frame, expected,
        lambda reference: a._load(trace_store, reference, expected['resource_declaration']))

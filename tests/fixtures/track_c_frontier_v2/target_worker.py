#!/usr/bin/env python3
"""Proposed NEW fixed closed-frontier-v2 target command; not installed."""
import importlib.util
import os
from pathlib import Path
import sys

DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(DIRECTORY))
from protected_files import checked_file
import wiring_contract as w

MANIFEST = Path('/etc/track-c/deployment-public.json')
PRIVATE_CONNECTION = Path('/etc/track-c/frontier-readonly.json')


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def authenticate():
    raw, digest = checked_file(MANIFEST, maximum=65536)
    # Strict duplicate-key parser is content-pinned by the frozen contract.
    f = w.contract().adapter().frontier()
    value = f.strict_json(raw)
    if not isinstance(value, dict) or w.EXTENSION not in value:
        raise ValueError('protected fixed v2 extension unavailable')
    base = {key: item for key, item in value.items() if key != w.EXTENSION}
    if not isinstance(base.get('observer_files'), dict):
        raise ValueError('original observer source declaration missing')
    for name in ['server-observer.py', 'public_observer.py']:
        if checked_file(DIRECTORY / name)[1] != base['observer_files'].get(name):
            raise ValueError('original protected observer source differs')
    actual = {name: checked_file(DIRECTORY / name)[1] for name in w.SOURCE_FILES}
    w.validate_installed_sources(value, actual)
    # Load only after exact original source authentication; never reuse a module
    # supplied from a caller-controlled Python import path.
    public = _module('public_observer', DIRECTORY / 'public_observer.py')
    sys.modules['public_observer'] = public
    legacy = _module('authenticated_original_observer', DIRECTORY / 'server-observer.py')
    legacy.validate_manifest(base)  # All original schema/pin/service/ops gates.
    if checked_file(base['ops']['path'])[1] != base['ops']['sha256']:
        raise ValueError('original installed native ops differs')
    return w.derive_expected(value, digest)


def produce(raw_request):
    expected = authenticate()
    c = w.contract()
    c.validate_request(raw_request, expected)
    raw, _ = checked_file(PRIVATE_CONNECTION, maximum=4096)
    # Private role credentials remain local, never argv/output/public evidence.
    if PRIVATE_CONNECTION.stat().st_mode & 0o077:
        raise ValueError('private observer role file must be mode0600 or stricter')
    params = c.adapter().connection_parameters(c.adapter().frontier().strict_json(raw),
                                              expected['source_binding']['database'])
    c.produce_command(raw_request, expected, params, sys.stdout.buffer.write)
    sys.stdout.buffer.flush()


def main():
    if sys.argv[1:] == ['--produce']:
        produce(sys.stdin.buffer.read(4097))
        return
    if sys.argv[1:]:
        raise ValueError('fixed target operation takes no arguments')
    expected = authenticate()
    # The real target process tree is bounded independently of SSH disconnects.
    # exec preserves the original public request stdin; the child reauthenticates
    # manifest/source bytes before opening its single read-only DB connection.
    duration = '%.3fs' % (expected['resource_declaration']['deadline_ms'] / 1000)
    os.execv('/usr/bin/timeout', ['/usr/bin/timeout', '--signal=KILL', duration,
                               sys.executable, '-I', str(Path(__file__).resolve()), '--produce'])


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('fixed read-only frontier source unavailable', file=sys.stderr)
        sys.exit(1)

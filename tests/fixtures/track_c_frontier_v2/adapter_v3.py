"""Source-only fixed worker -> bounded pipe -> actual TraceStore -> source replay."""
import hashlib
import importlib.util
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

CONTRACT_SHA256 = '91890edd02af0a6b70b47c3abeb4aaa62009d85088ee2bea1c97536b56b24ecb'
TRACE_SOURCE_HASHES = {
    'trace.py': '93534e0a2528dafe578c7f72b6477235448367942648c8815c5a80a4760b2b41',
    'model.py': '8574055927dda49096b169a0a0ff54b7da30a5a5d458173edaa2770b778e05c7',
    'bip39-english.txt': '2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda',
}


def contract():
    path = Path(__file__).resolve().with_name('frontier_v2_contract.py')
    if hashlib.sha256(path.read_bytes()).hexdigest() != CONTRACT_SHA256:
        raise ValueError('frozen integration contract differs')
    spec = importlib.util.spec_from_file_location('fixed_frontier_v2_contract', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def trace_api():
    # The existing simulator package is supplied by the immutable build layout.
    # No new source trace implementation or caller-supplied loader is accepted.
    from simulator import trace
    for name, expected in TRACE_SOURCE_HASHES.items():
        if hashlib.sha256(Path(trace.__file__).with_name(name).read_bytes()).hexdigest() != expected:
            raise ValueError('declared existing trace/public validation source differs')
    return trace


def _load(store, reference, limits):
    api = trace_api()
    f = contract().adapter().frontier()
    paths = [p for p in api.partition_paths(store.root) if p.name == reference['partition']]
    if len(paths) != 1:
        raise ValueError('original stream trace partition unavailable')
    connection = api.readonly(paths[0])
    try:
        connection.execute('BEGIN')
        sizes = connection.execute('SELECT length(raw),length(payload) FROM trace WHERE seq=?',
                                   (reference['seq'],)).fetchone()
        if sizes is None or sizes[0] is None or sizes[0] > limits['max_page_bytes'] or sizes[1] > 8192:
            raise ValueError('original stream raw trace missing or unbounded')
        row = connection.execute('SELECT seq,utc,schema_version,kind,actor,action_id,payload,raw,previous_hash,hash FROM trace WHERE seq=?',
                                 (reference['seq'],)).fetchone()
    finally:
        connection.close()
    if (row['schema_version'] != api.SCHEMA_VERSION or row['kind'] != 'frontier_v2.original_line'
            or row['actor'] is not None or row['action_id'] is not None
            or row['hash'] != reference['hash'] or api.record_hash(row) != reference['hash']):
        raise ValueError('original stream trace record hash/kind differs')
    api.public_raw(row['raw'])
    return f.strict_json(row['payload']), row['raw']


def _trace_position(store):
    api = trace_api()
    paths = api.partition_paths(store.root)
    if not paths:
        return ('', 0)
    connection = api.readonly(paths[-1])
    try:
        sequence = connection.execute('SELECT coalesce(max(seq),0) FROM trace').fetchone()[0]
        return (paths[-1].name, sequence)
    finally:
        connection.close()


def _run(command, private, expected, trace_store, *, inherited_session=False):
    """Fixed caller command only; internal argument exists for pure fault tests.

    Every pipe is nonblocking and every select/wait uses the same absolute
    deadline. Process status is obtained after EOF, never accepted from JSON.
    No complete frame escapes before the producer is reaped successfully.
    """
    if type(inherited_session) is not bool:
        raise ValueError('explicit fixed worker session mode required')
    c = contract()
    expected = c.expected_contract(expected)
    f = c.adapter().frontier()
    limits, source = expected['resource_declaration'], expected['source_binding']
    api = trace_api()
    if not isinstance(trace_store, api.TraceStore):
        raise ValueError('actual existing TraceStore required')
    request = f.canonical(private) + b'\n'
    if len(request) > 4096:
        raise ValueError('private connection request exceeds bound')
    deadline = time.monotonic() + limits['deadline_ms'] / 1000
    last_reference = _trace_position(trace_store)
    if time.monotonic() >= deadline:
        raise ValueError('initial trace read exceeded admission deadline')
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=not inherited_session, bufsize=0)
    selector = selectors.DefaultSelector()
    diagnostic_bytes = 0
    successful = False
    try:
        for pipe in [child.stdin, child.stdout, child.stderr]:
            os.set_blocking(pipe.fileno(), False)
        selector.register(child.stdin, selectors.EVENT_WRITE, 'input')
        selector.register(child.stdout, selectors.EVENT_READ, 'output')
        selector.register(child.stderr, selectors.EVENT_READ, 'diagnostic')
        pending, sent, total = bytearray(), 0, 0

        def lines():
            nonlocal sent, total, diagnostic_bytes
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError('absolute producer process deadline exceeded')
                ready = selector.select(remaining)
                if not ready:
                    raise ValueError('absolute producer process deadline exceeded')
                for key, _ in ready:
                    try:
                        if key.data == 'input':
                            sent += os.write(key.fd, request[sent:])
                            if sent == len(request):
                                selector.unregister(key.fileobj)
                                key.fileobj.close()
                            continue
                        data = os.read(key.fd, 65536)
                    except BlockingIOError:
                        continue
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == 'diagnostic':
                        diagnostic_bytes += len(data)
                        if diagnostic_bytes > 65536:
                            raise ValueError('producer diagnostic byte bound exceeded')
                        continue  # Do not copy private DB errors into public output.
                    total += len(data)
                    if total > limits['max_total_bytes']:
                        raise ValueError('producer stream byte bound exceeded')
                    pending.extend(data)
                    while b'\n' in pending:
                        line, _, rest = pending.partition(b'\n')
                        pending[:] = rest
                        if len(line) + 1 > limits['max_page_bytes']:
                            raise ValueError('producer record bound exceeded')
                        yield bytes(line) + b'\n'
                    if len(pending) >= limits['max_page_bytes']:
                        raise ValueError('producer incomplete record bound exceeded')
            if pending:
                raise ValueError('truncated final producer record')

        def actual_exit():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('absolute producer exit deadline exceeded')
            try:
                return child.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                raise ValueError('absolute producer exit deadline exceeded') from None

        def within_deadline():
            if time.monotonic() >= deadline:
                raise ValueError('source capture/replay exceeded absolute admission deadline')
        def capture(metadata, raw):
            nonlocal last_reference
            within_deadline()
            reference = c._reference(trace_store.capture('frontier_v2.original_line', metadata, raw=raw))
            position = (reference['partition'], reference['seq'])
            if position <= last_reference:
                raise ValueError('capture reference is stale or reused')
            last_reference = position
            within_deadline()
            return reference
        def load(reference):
            within_deadline()
            result = _load(trace_store, reference, limits)
            within_deadline()
            return result
        result = c.consume_original(lines(), actual_exit, expected, api.public_payload, capture, load)
        within_deadline()
        successful = True
        return result
    finally:
        selector.close()
        # A failed producer can exit while a descendant holds a pipe open.
        # Kill the owned session on failure even when its leader has exited.
        if not successful or child.poll() is None:
            try:
                (child.kill() if inherited_session else os.killpg(child.pid, signal.SIGKILL))
            except ProcessLookupError:
                pass
            child.wait(timeout=5)
        for pipe in [child.stdin, child.stdout, child.stderr]:
            pipe.close()


def collect(private_connection, protected_expected, trace_store):
    """Fixed public API: no caller-selected SQL, command or proof callbacks.

    Protected expected declarations and the actual TraceStore remain supplied by
    reviewed installed code. This source does not install an ops/schema route.
    """
    c = contract()
    expected = c.expected_contract(protected_expected)
    a = c.adapter()
    params = a.connection_parameters(private_connection, expected['source_binding']['database'])
    private = {'connection': params, 'declaration': expected['resource_declaration'],
               'binding': expected['source_binding']}
    command = [sys.executable, '-I', str(Path(a.__file__).resolve()), '--worker']
    return _run(command, private, expected, trace_store)

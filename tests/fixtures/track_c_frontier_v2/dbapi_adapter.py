"""Source-only fixed PG adapter. No installed ops, credentials or host defaults."""
import hashlib
import importlib.util
import math
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

FRONTIER_SHA256 = '44db50364d15034e70accfd85df91d94666fdb7165a8692b0fab9f4e9eb352d9'
MAX_PRIVATE_INPUT = 4096
MAX_DIAGNOSTIC_BYTES = 65536


def frontier():
    path = Path(__file__).resolve().with_name('frontier_stream.py')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != FRONTIER_SHA256:
        raise ValueError('fixed frontier source differs')
    spec = importlib.util.spec_from_file_location('fixed_frontier_v1', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def connection_parameters(value, expected_database):
    # No DSN, arbitrary options, environment defaults or remote/DNS host selection.
    fields = {'host', 'port', 'dbname', 'user', 'password'}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('explicit private local connection fields required')
    if any(not isinstance(value[k], str) or not value[k] or '\x00' in value[k]
           for k in ['host', 'dbname', 'user']):
        raise ValueError('invalid private connection parameters')
    if not isinstance(value['password'], str) or '\x00' in value['password']:
        raise ValueError('explicit private password field required')
    host = value['host']
    if host not in {'127.0.0.1', '::1'} and not (host.startswith('/') and '..' not in Path(host).parts and ',' not in host):
        raise ValueError('one explicit loopback or Unix socket host required')
    if type(value['port']) is not int or not 1 <= value['port'] <= 65535 or value['dbname'] != expected_database:
        raise ValueError('database source identity differs')
    # psycopg named arguments replace connection/service defaults for each field.
    return dict(value)


class _FixedConnection:
    """Translate pinned SQL cursor operations to named cursors on one connection."""
    autocommit = True

    def __init__(self, raw, f, limits, deadline, clock):
        if raw.autocommit is not True:
            raise ValueError('dedicated autocommit connection required')
        self.raw, self.f, self.limits = raw, f, limits
        self.deadline, self.clock = deadline, clock
        self.tables = list(f.projections().items())
        self.control = raw.cursor()
        self.named = {}
        self.answer = []
        self.mode = None
        counts = ["'%s',(SELECT count(*) FROM %s)" % (name, item['table']) for name, item in self.tables]
        self.counts_sql = 'SELECT jsonb_build_object(' + ','.join(counts) + ')'
        self.simple = {'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY', 'ROLLBACK',
                       "SET LOCAL statement_timeout = '%dms'" % limits['statement_timeout_ms'],
                       "SET LOCAL idle_in_transaction_session_timeout = '%dms'" % limits['deadline_ms'],
                       f.IDENTITY_SQL, self.counts_sql}

    def check(self):
        # This detects late results. The supervisor, not this check, interrupts a
        # stalled connect/execute/fetch/rollback/emit and bounds the whole process.
        if self.clock() >= self.deadline:
            raise ValueError('absolute adapter deadline exceeded')

    def cursor(self):
        return self

    def execute(self, sql):
        self.check()
        self.mode = None
        if sql in self.simple:
            self.control.execute(sql)
            self.mode = 'control'
        else:
            for number, (_, spec) in enumerate(self.tables):
                name = 'frontier_%d' % number
                select = 'SELECT row_to_json(q) FROM (SELECT %s FROM %s ORDER BY %s) q' % (spec['columns'], spec['table'], spec['order_by'])
                declare = 'DECLARE %s NO SCROLL CURSOR FOR ' % name + select
                if sql == declare:
                    if name in self.named:
                        raise ValueError('duplicate named cursor')
                    cursor = self.raw.cursor(name=name, scrollable=False, withhold=False)
                    self.named[name] = cursor
                    cursor.execute(select)
                    break
                if sql in ['FETCH FORWARD %d FROM %s' % (self.limits['max_page_rows'], name), 'FETCH FORWARD 1 FROM ' + name]:
                    if name not in self.named:
                        raise ValueError('missing fixed named cursor')
                    count = int(sql.split()[2])
                    self.answer = self.named[name].fetchmany(count)
                    self.mode = 'fetch'
                    break
                if sql == 'CLOSE ' + name:
                    if name not in self.named:
                        raise ValueError('missing fixed named cursor')
                    self.named.pop(name).close()
                    break
            else:
                raise ValueError('SQL outside fixed public projection protocol')
        self.check()

    def fetchone(self):
        if self.mode != 'control':
            raise ValueError('unexpected fixed scalar operation')
        self.check()
        result = self.control.fetchone()
        self.check()
        return result

    def fetchall(self):
        if self.mode != 'fetch':
            raise ValueError('unexpected fixed page operation')
        self.check()
        return self.answer

    def rollback(self):
        self.raw.rollback()

    def close(self):
        try:
            for cursor in list(self.named.values()):
                cursor.close()
        finally:
            self.control.close()


def _produce_worker(private, emit, clock=time.monotonic):
    """Only call in the separately supervised worker; lazy optional dependency."""
    f = frontier()
    if not isinstance(private, dict) or set(private) != {'connection', 'declaration', 'binding'}:
        raise ValueError('invalid private adapter request')
    limits, source = f.declaration(private['declaration']), f.binding(private['binding'])
    params = connection_parameters(private['connection'], source['database'])
    deadline = clock() + limits['deadline_ms'] / 1000
    # Never inherit ambient PG service/option settings into this private worker.
    for name in list(os.environ):
        if name.startswith('PG'):
            os.environ.pop(name)
    import psycopg
    raw = psycopg.connect(**params, autocommit=True,
                          connect_timeout=max(1, math.ceil(limits['deadline_ms'] / 1000)),
                          passfile=os.devnull,
                          options='-c default_transaction_read_only=on',
                          application_name='track_c_fixed_public_frontier')
    try:
        connection = _FixedConnection(raw, f, limits, deadline, clock)
        f.produce(connection, limits, source, emit, clock=clock)
    finally:
        raw.close()


def _supervised(command, private, limits, source):
    """Fixed caller command only; internal argument exists for pure fault tests.

    Every pipe is nonblocking and every select/wait uses the same absolute
    deadline. Process status is obtained after EOF, never accepted from JSON.
    No complete frame escapes before the producer is reaped successfully.
    """
    f = frontier()
    limits, source = f.declaration(limits), f.binding(source)
    request = f.canonical(private) + b'\n'
    if len(request) > MAX_PRIVATE_INPUT:
        raise ValueError('private connection request exceeds bound')
    deadline = time.monotonic() + limits['deadline_ms'] / 1000
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
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
                        if diagnostic_bytes > MAX_DIAGNOSTIC_BYTES:
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

        result = f.consume(lines(), limits, source, actual_exit)
        successful = True
        return result
    finally:
        selector.close()
        # A failed producer can exit while a descendant holds a pipe open.
        # Kill the owned session on failure even when its leader has exited.
        if not successful or child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=5)
        for pipe in [child.stdin, child.stdout, child.stderr]:
            pipe.close()


def collect(private_connection, limits, source):
    """Explicit new source API only; not connected to any installed observer."""
    f = frontier()
    limits, source = f.declaration(limits), f.binding(source)
    params = connection_parameters(private_connection, source['database'])
    private = {'connection': params, 'declaration': limits, 'binding': source}
    command = [sys.executable, '-I', str(Path(__file__).resolve()), '--worker']
    return _supervised(command, private, limits, source)


def _worker_main():
    raw = sys.stdin.buffer.read(MAX_PRIVATE_INPUT + 1)
    if len(raw) > MAX_PRIVATE_INPUT:
        raise ValueError('private request byte bound exceeded')
    private = frontier().strict_json(raw)
    _produce_worker(private, lambda line: (sys.stdout.buffer.write(line), sys.stdout.buffer.flush()))


if __name__ == '__main__':
    if sys.argv[1:] != ['--worker']:
        raise SystemExit('adapter worker requires exact private protocol')
    try:
        _worker_main()
    except Exception:
        # DB exceptions can contain credentials, SQL or connection strings.
        sys.stderr.write('fixed public snapshot producer failed\n')
        raise SystemExit(1)

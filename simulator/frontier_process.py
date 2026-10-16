"""Fixed schema-2 worker lifecycle; no caller-selected command or SQL.

The supervisor is a fresh session leader and a Linux subreaper ONLY inside
that owned process. Bootstrap, producer execution and all TraceStore I/O occur
in a fresh interpreter below it. Existing common command bounds remain in force.
"""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

# Match the existing common process transport. Larger schema-2 frames HOLD;
# the stream's larger declared ceiling does not enlarge the caller transport.
MAX_BYTES = 2 * 1024 * 1024
MAX_DIAGNOSTIC_BYTES = 256 * 1024


def _members():
    """Only this isolated session's process group, never Engine children."""
    group = os.getpgrp()
    result = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            fields = (entry / 'stat').read_text().rsplit(')', 1)[1].split()
            if int(fields[2]) == group:
                result.append(int(entry.name))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return result


def _stop_and_reap(child, end):
    # Stop the worker first so it cannot create another producer during cleanup.
    if child.poll() is None:
        try: os.kill(child.pid, signal.SIGSTOP)
        except ProcessLookupError: pass
    while True:
        for pid in _members():
            try: os.kill(pid, signal.SIGKILL)
            except ProcessLookupError: pass
        # Popen retains ownership of the direct worker's exit status.
        child.poll()
        while True:
            try:
                pid, _ = os.waitpid(-os.getpgrp(), os.WNOHANG)
                if pid == 0: break
            except ChildProcessError: break
        if not _members():
            child.wait(timeout=max(0.001, end - time.monotonic()))
            return
        if time.monotonic() >= end:
            raise RuntimeError('owned frontier cleanup incomplete')
        time.sleep(0.005)


def _supervise(request):
    if sys.platform != 'linux' or os.getpgrp() != os.getpid():
        raise ValueError('isolated Linux frontier session required')
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
        raise ValueError('owned frontier subreaper unavailable')
    end = request['deadline']
    if type(end) not in (float, int) or not 0 < end - time.monotonic() <= 25:
        raise ValueError('existing frontier deadline required')
    # Cleanup is reserved WITHIN, never added to, the caller allowance.
    work_end = end - 0.75
    raw = (json.dumps(request, allow_nan=False) + '\n').encode()
    if len(raw) > MAX_BYTES:
        raise ValueError('frontier request exceeds existing transport bound')
    child = subprocess.Popen([sys.executable, '-I', str(Path(__file__).resolve()), '--work'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    output = bytearray(); diagnostic = 0; sent = 0
    selector = selectors.DefaultSelector()
    try:
        for pipe, kind in ((child.stdin, 'in'), (child.stdout, 'out'), (child.stderr, 'err')):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_WRITE if kind == 'in' else selectors.EVENT_READ, kind)
        while selector.get_map():
            remaining = work_end - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('frontier owned worker deadline')
            ready = selector.select(remaining)
            if not ready:
                raise TimeoutError('frontier owned worker deadline')
            for key, _ in ready:
                try:
                    if key.data == 'in':
                        sent += os.write(key.fd, raw[sent:])
                        if sent == len(raw):
                            selector.unregister(key.fileobj); key.fileobj.close()
                        continue
                    data = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                if not data:
                    selector.unregister(key.fileobj)
                elif key.data == 'out':
                    output.extend(data)
                    if len(output) > MAX_BYTES:
                        raise ValueError('frontier response exceeds existing transport bound')
                else:
                    diagnostic += len(data)
                    if diagnostic > MAX_DIAGNOSTIC_BYTES:
                        raise ValueError('frontier diagnostics exceed existing transport bound')
        child.wait(timeout=max(0.001, work_end-time.monotonic()))
        if child.returncode or time.monotonic() >= work_end or _members():
            raise ValueError('frontier worker incomplete or descendants remain')
        return bytes(output)
    finally:
        selector.close()
        _stop_and_reap(child, end-0.05)
        for pipe in (child.stdin, child.stdout, child.stderr):
            pipe.close()


def _work(request):
    # -I ignores ambient PYTHONPATH/user-site. Load ONLY this checked-out common
    # source; installed packet sources still require their protected preauth.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from types import SimpleNamespace
    from simulator import frontier_source as source
    from simulator.trace import TraceStore
    trace = TraceStore(request['trace']['root'],
        retention_days=request['trace']['retention_days'],
        max_record_bytes=request['trace']['max_record_bytes'])
    try:
        controller, binding, digest = source._bootstrap()
        config = SimpleNamespace(**request['config']) if request['config'] is not None else None
        source._context(controller, binding, config, request['pins'], timeout=request['allowance'])
        if request['operation'] == 'collect':
            frame = controller.collect(trace, inherited_session=True)
        elif request['operation'] == 'verify':
            frame = request['frame']
        else:
            raise ValueError('fixed frontier operation required')
        result = controller.verify(frame, trace)
        source._same_binding(digest)
        return result
    finally:
        trace.close()


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError('frontier input bound')
        request = json.loads(raw)
        if sys.argv[1:] == ['--supervise']:
            response = _supervise(request)
            sys.stdout.buffer.write(response)
        elif sys.argv[1:] == ['--work']:
            response = json.dumps({'ok': True, 'frame': _work(request)}, allow_nan=False).encode()
            if len(response) > MAX_BYTES:
                raise ValueError('frontier response bound')
            sys.stdout.buffer.write(response)
        else:
            raise ValueError('fixed frontier entry required')
        sys.stdout.buffer.flush()
    except BaseException:
        # Neither private argv nor untrusted diagnostics/exceptions leave here.
        sys.stdout.buffer.write(b'{"ok":false}\n')
        sys.stdout.buffer.flush()
        raise SystemExit(1)


if __name__ == '__main__':
    main()

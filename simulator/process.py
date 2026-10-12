from __future__ import annotations

import asyncio
import json
import os
import signal
from collections.abc import Callable

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_STDERR_BYTES = 256 * 1024


class CommandError(RuntimeError):
    pass


def decode_object(output: str) -> dict:
    def nonfinite(_):
        raise ValueError("nonfinite JSON")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result
    try:
        value = json.loads(output, object_pairs_hook=pairs, parse_constant=nonfinite)
    except ValueError:
        raise CommandError("command did not return a valid JSON object") from None
    if not isinstance(value, dict):
        raise CommandError("command response must be an object")
    return value


async def text_command(argv: list[str], request: dict | None = None, timeout: int = 120,
                       on_line: Callable[[str], None] | None = None,
                       on_stderr: Callable[[dict], None] | None = None,
                       on_stdout_raw: Callable[[dict], None] | None = None,
                       on_stderr_raw: Callable[[dict], None] | None = None) -> str:
    """No shell, bounded output/time, and cleanup only of this child's session."""
    if not argv:
        raise ValueError("empty command")
    proc = await asyncio.create_subprocess_exec(*argv, stdin=asyncio.subprocess.PIPE,
                                               stdout=asyncio.subprocess.PIPE,
                                               stderr=asyncio.subprocess.PIPE, start_new_session=True)

    output = bytearray(); stdout_bytes = 0

    async def drain_stderr():
        captured=bytearray();size=0
        while True:
            chunk=await proc.stderr.read(65536)
            if not chunk:break
            size+=len(chunk)
            if on_stderr is not None or on_stderr_raw is not None:
                captured.extend(chunk[:max(0,MAX_STDERR_BYTES-len(captured))])
        if on_stderr_raw is not None:
            on_stderr_raw({'raw':bytes(captured),'bytes':size,'truncated':size>MAX_STDERR_BYTES})
        if on_stderr is not None and size:
            on_stderr({'text':captured.decode('utf-8',errors='replace'),
                       'bytes':size,'truncated':size>MAX_STDERR_BYTES})

    stderr_task=asyncio.create_task(drain_stderr())

    async def exchange():
        nonlocal stdout_bytes
        if request is not None:
            proc.stdin.write((json.dumps(request, allow_nan=False) + "\n").encode())
            await proc.stdin.drain()
        proc.stdin.close()
        pending = bytearray()
        while True:
            chunk = await proc.stdout.read(65536)
            if not chunk:
                break
            stdout_bytes += len(chunk)
            output.extend(chunk[:max(0,MAX_RESPONSE_BYTES-len(output))])
            if stdout_bytes > MAX_RESPONSE_BYTES:
                raise CommandError("command response exceeded byte limit")
            if on_line is not None:
                pending.extend(chunk)
                while b"\n" in pending:
                    line, _, rest = pending.partition(b"\n")
                    pending = bytearray(rest)
                    if line.strip():
                        on_line(line.decode("utf-8"))
        if pending.strip() and on_line is not None:
            on_line(pending.decode("utf-8"))
        await proc.wait()
        await stderr_task
        if proc.returncode:
            # Do not copy untrusted stderr/command text containing credentials to the ledger.
            raise CommandError(f"command exited with status {proc.returncode}")
        try:
            return output.decode("utf-8")
        except UnicodeDecodeError:
            raise CommandError("command returned invalid UTF-8") from None

    try:
        return await asyncio.wait_for(exchange(), timeout)
    finally:
        if proc.returncode is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await proc.wait()
        if not stderr_task.done():
            # Drain the remaining pipe after stopping our child; capture any
            # diagnostic already emitted without leaving a task behind.
            await stderr_task
        if on_stdout_raw is not None:
            on_stdout_raw({'raw':bytes(output),'bytes':stdout_bytes,'truncated':stdout_bytes>MAX_RESPONSE_BYTES,
                           'exit_code':proc.returncode})


async def json_command(argv: list[str], request: dict | None = None, timeout: int = 120,
                       on_event: Callable[[dict], None] | None = None,
                       on_stderr: Callable[[dict], None] | None = None,
                       on_stdout_raw: Callable[[dict], None] | None = None,
                       on_stderr_raw: Callable[[dict], None] | None = None) -> dict:
    if on_event is None:
        return decode_object(await text_command(argv, request, timeout,on_stderr=on_stderr,
            on_stdout_raw=on_stdout_raw,on_stderr_raw=on_stderr_raw))
    final = None

    def line(output):
        nonlocal final
        value = decode_object(output)
        if final is not None:
            raise CommandError("driver output followed its final result")
        if value.get("kind") == "driver_event":
            on_event(value)
        else:
            final = value

    await text_command(argv, request, timeout, on_line=line,on_stderr=on_stderr,
        on_stdout_raw=on_stdout_raw,on_stderr_raw=on_stderr_raw)
    if final is None:
        raise CommandError("driver produced no final result")
    return final

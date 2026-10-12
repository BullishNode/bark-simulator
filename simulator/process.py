from __future__ import annotations

import asyncio
import json
import os
import signal
from collections.abc import Callable

MAX_RESPONSE_BYTES = 2 * 1024 * 1024


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
                       on_line: Callable[[str], None] | None = None) -> str:
    """No shell, bounded output/time, and cleanup only of this child's session."""
    if not argv:
        raise ValueError("empty command")
    proc = await asyncio.create_subprocess_exec(*argv, stdin=asyncio.subprocess.PIPE,
                                               stdout=asyncio.subprocess.PIPE,
                                               stderr=asyncio.subprocess.DEVNULL, start_new_session=True)

    async def exchange():
        if request is not None:
            proc.stdin.write((json.dumps(request, allow_nan=False) + "\n").encode())
            await proc.stdin.drain()
        proc.stdin.close()
        output = bytearray()
        pending = bytearray()
        while True:
            chunk = await proc.stdout.read(65536)
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > MAX_RESPONSE_BYTES:
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


async def json_command(argv: list[str], request: dict | None = None, timeout: int = 120,
                       on_event: Callable[[dict], None] | None = None) -> dict:
    if on_event is None:
        return decode_object(await text_command(argv, request, timeout))
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

    await text_command(argv, request, timeout, on_line=line)
    if final is None:
        raise CommandError("driver produced no final result")
    return final

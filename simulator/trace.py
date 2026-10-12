"""Append-only public diagnostics, partitioned by UTC capture day.

Each partition has its own hash chain. Rotation closes the old connection;
retention moves closed partitions to an archive without deleting evidence or
changing the financial journal. Call capture() for untrusted diagnostics and
append() when rejection should propagate to the caller.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re
import sqlite3
import threading
import time
from decimal import Decimal
from pathlib import Path

from .model import InvariantError, canonical, integer, public_payload, timestamp

SCHEMA_VERSION = 1
ZERO_HASH = '0' * 64
MAX_RECORD_BYTES = 16 * 1024 * 1024
SCHEMA = '''
CREATE TABLE IF NOT EXISTS trace(seq INTEGER PRIMARY KEY, utc REAL NOT NULL,
 schema_version INTEGER NOT NULL, kind TEXT NOT NULL, actor TEXT, action_id TEXT,
 payload TEXT NOT NULL, raw BLOB, previous_hash TEXT NOT NULL, hash TEXT NOT NULL UNIQUE);
CREATE INDEX IF NOT EXISTS trace_actor ON trace(actor,utc,seq);
CREATE INDEX IF NOT EXISTS trace_action ON trace(action_id,seq);
CREATE INDEX IF NOT EXISTS trace_kind ON trace(kind,seq);
CREATE TRIGGER IF NOT EXISTS trace_no_update BEFORE UPDATE ON trace
 BEGIN SELECT RAISE(ABORT,'trace records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS trace_no_delete BEFORE DELETE ON trace
 BEGIN SELECT RAISE(ABORT,'trace records are append-only'); END;
'''


def normalized(value):
    """Preserve exact RPC decimals without converting them to binary floats."""
    if isinstance(value, Decimal): return str(value)
    if isinstance(value, dict): return {key: normalized(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)): return [normalized(item) for item in value]
    return value


def public_raw(raw):
    if raw is None: return None
    if isinstance(raw, str): raw = raw.encode()
    if not isinstance(raw, bytes): raise ValueError('raw evidence must be UTF-8 bytes')
    text = raw.decode('utf-8')
    public_payload(text)
    # Structured validation catches forbidden fields even when their values
    # cannot be recognized as private material by a text pattern.
    for line in text.splitlines():
        try: value = json.loads(line)
        except ValueError: continue
        public_payload(value)
    try: value = json.loads(text)
    except ValueError: pass
    else: public_payload(value)
    return raw


def record_hash(record):
    raw = record['raw']
    if raw is not None and not isinstance(raw, bytes):
        raise InvariantError('trace raw field is not a byte stream')
    return hashlib.sha256(canonical([record['seq'], record['utc'], record['schema_version'],
        record['kind'], record['actor'], record['action_id'], record['payload'],
        base64.b64encode(raw).decode() if raw is not None else None,
        record['previous_hash']]).encode()).hexdigest()


def partition_paths(root):
    root = Path(root)
    paths = [*root.glob('trace-*.sqlite'), *(root / 'trace-archive').glob('trace-*.sqlite')]
    names = set()
    for path in paths:
        if path.is_symlink() or re.fullmatch(r'trace-\d{4}-\d{2}-\d{2}\.sqlite', path.name) is None:
            raise ValueError('unsafe trace partition')
        dt.date.fromisoformat(path.name[6:16])
        if path.name in names: raise InvariantError('duplicate trace partition')
        names.add(path.name)
    return sorted(paths, key=lambda path: path.name)


def readonly(path):
    connection = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def verify_partition(path):
    connection = readonly(path); previous = ZERO_HASH; count = 0
    try:
        for sequence, row in enumerate(connection.execute('SELECT * FROM trace ORDER BY seq'), 1):
            if (row['seq'] != sequence or row['schema_version'] != SCHEMA_VERSION
                    or row['previous_hash'] != previous or row['hash'] != record_hash(row)):
                raise InvariantError('trace hash chain is damaged')
            timestamp(row['utc'], 'trace UTC')
            public_payload(json.loads(row['payload'])); public_raw(row['raw'])
            previous = row['hash']; count += 1
        return {'partition': Path(path).name, 'records': count, 'tip': previous}
    finally:
        connection.close()


def iter_records(root, *, actor=None, action_id=None, after=None, before=None):
    clauses = []; params = []
    for column, value in [('actor', actor), ('action_id', action_id)]:
        if value is not None: clauses.append(column + '=?'); params.append(value)
    for operator, value in [('>=', after), ('<=', before)]:
        if value is not None:
            timestamp(value, 'trace selection UTC'); clauses.append('utc' + operator + '?'); params.append(value)
    where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
    for path in partition_paths(root):
        connection = readonly(path)
        try:
            for row in connection.execute('SELECT * FROM trace' + where + ' ORDER BY seq', params):
                yield {**dict(row), 'partition': path.name, 'payload': json.loads(row['payload'])}
        finally:
            connection.close()


class TraceStore:
    def __init__(self, root, *, clock=time.time, retention_days=30, max_record_bytes=MAX_RECORD_BYTES):
        self.root = Path(root)
        if self.root.is_symlink(): raise ValueError('trace root cannot be a symlink')
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        integer(retention_days, 'trace hot retention days', 1)
        integer(max_record_bytes, 'trace record bound', 128)
        self.clock, self.retention_days, self.max_record_bytes = clock, retention_days, max_record_bytes
        self.connection = None; self.current_path = None
        self.lock = threading.RLock()
        paths = partition_paths(self.root)
        self.latest_day = paths[-1].name[6:16] if paths else None

    def close(self):
        with self.lock:
            if self.connection is not None:
                self.connection.close(); self.connection = None

    def _open(self, day):
        if self.latest_day is not None and day < self.latest_day:
            raise ValueError('capture cannot append to an older UTC partition')
        if self.current_path is not None and self.current_path.name == 'trace-' + day + '.sqlite' and self.connection is not None:
            return
        self.close()
        path = self.root / ('trace-' + day + '.sqlite')
        if path.is_symlink(): raise ValueError('trace partition cannot be a symlink')
        if path.exists(): verify_partition(path)
        self.connection = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute('PRAGMA journal_mode=WAL')
        self.connection.execute('PRAGMA synchronous=FULL')
        self.connection.executescript(SCHEMA)
        path.chmod(0o600)
        self.current_path = path; self.latest_day = day

    def append(self, kind, payload, *, actor=None, action_id=None, raw=None):
        metadata = {'kind': kind, 'actor': actor, 'action_id': action_id}
        if not isinstance(kind, str) or re.fullmatch(r'[a-z][a-z0-9_.-]{0,79}', kind) is None:
            raise ValueError('invalid trace kind')
        public_payload(metadata)
        payload = normalized(payload); public_payload(payload)
        serialized = canonical(payload); raw = public_raw(raw)
        if len(serialized.encode()) + len(raw or b'') > self.max_record_bytes:
            raise ValueError('trace record exceeds its byte bound')
        with self.lock:
            at = timestamp(self.clock(), 'trace UTC')
            day = dt.datetime.fromtimestamp(at, dt.timezone.utc).date().isoformat()
            self._open(day)
            connection = self.connection
            connection.execute('BEGIN IMMEDIATE')
            try:
                last = connection.execute('SELECT seq,hash FROM trace ORDER BY seq DESC LIMIT 1').fetchone()
                sequence, previous = (last['seq'] + 1, last['hash']) if last else (1, ZERO_HASH)
                record = {'seq': sequence, 'utc': at, 'schema_version': SCHEMA_VERSION, **metadata,
                          'payload': serialized, 'raw': raw, 'previous_hash': previous}
                digest = record_hash(record)
                connection.execute('INSERT INTO trace VALUES (?,?,?,?,?,?,?,?,?,?)',
                    (sequence, at, SCHEMA_VERSION, kind, actor, action_id, serialized, raw, previous, digest))
                connection.execute('COMMIT')
            except BaseException:
                connection.execute('ROLLBACK'); raise
            return {'partition': self.current_path.name, 'seq': sequence, 'hash': digest}

    def capture(self, kind, payload, *, actor=None, action_id=None, raw=None):
        try:
            if isinstance(payload, dict) and payload.get('truncated') is True:
                raise ValueError('truncated raw diagnostics cannot be checked completely')
            return self.append(kind, payload, actor=actor, action_id=action_id, raw=raw)
        except (ValueError, TypeError, UnicodeError):
            # Do not retain secret bytes, their digest, an exception message, or
            # unchecked identifiers when substituting a public redaction marker.
            try: public_payload({'kind': kind, 'actor': actor, 'action_id': action_id})
            except ValueError: kind, actor, action_id = 'redacted', None, None
            if not isinstance(kind, str) or re.fullmatch(r'[a-z][a-z0-9_.-]{0,79}', kind) is None:
                kind = 'redacted'
            return self.append(kind, {'redacted': True, 'reason': 'rejected'}, actor=actor, action_id=action_id)

    def records(self, **selection): return iter_records(self.root, **selection)

    def verify(self):
        with self.lock:
            partitions = [verify_partition(path) for path in partition_paths(self.root)]
        return {'schema_version': SCHEMA_VERSION, 'records': sum(p['records'] for p in partitions),
                'partitions': partitions}

    def archive(self):
        with self.lock:
            day = dt.datetime.fromtimestamp(timestamp(self.clock(), 'trace UTC'), dt.timezone.utc).date()
            cutoff = day - dt.timedelta(days=self.retention_days - 1)
            archive = self.root / 'trace-archive'
            if archive.is_symlink(): raise ValueError('trace archive cannot be a symlink')
            moved = []
            for path in partition_paths(self.root):
                if path.parent != self.root or path == self.current_path: continue
                if dt.date.fromisoformat(path.name[6:16]) >= cutoff: continue
                verify_partition(path)
                checkpoint = sqlite3.connect(path)
                try:
                    busy, _, _ = checkpoint.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
                    if busy: raise ValueError('trace archive partition has an active reader')
                finally: checkpoint.close()
                archive.mkdir(mode=0o700, exist_ok=True)
                target = archive / path.name
                if target.exists(): raise InvariantError('trace archive destination already exists')
                path.rename(target); moved.append(target.name)
            return moved

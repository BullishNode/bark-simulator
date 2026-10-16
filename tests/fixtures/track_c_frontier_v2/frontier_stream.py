"""One read-only PG snapshot, fixed public projections, verified finite stream.

No connection/credential/SQL/host dispatch API is exposed. The installed wrapper
must supply a fresh dedicated autocommit connection and authenticate bindings.
The existing ops allowlist is unchanged; this source is not installed or qualified.
"""
import hashlib
import json
from pathlib import Path
import time

PROJECTION_SHA256 = 'e1aadef2a87159b9bb51ff86691189e12382b759910cfe55b5a37b2540b7c24e'
PROTOCOL = 'track_c_closed_frontier_v2'
ZERO = '0' * 64
LIMIT_FIELDS = {'max_total_rows', 'max_total_bytes', 'max_page_rows', 'max_page_bytes',
                'max_pages', 'deadline_ms', 'statement_timeout_ms'}
IDENTITY_FIELDS = {'snapshot', 'backend_pid', 'database', 'observed_at', 'read_only', 'isolation'}
BINDING_FIELDS = {'observer_sha256', 'schema_sha256', 'deployment_sha256', 'genesis', 'server_pubkey', 'network', 'database'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def projections():
    raw = Path(__file__).with_name('public-projections.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROJECTION_SHA256:
        raise ValueError('fixed projection source differs')
    value = strict_json(raw)
    if len(value['tables']) != 19:
        raise ValueError('incomplete fixed table projection')
    return value['tables']


def declaration(value):
    # Hard resource ceilings are proposed source bounds, not run authorization.
    ceilings = {'max_total_rows': 1_000_000, 'max_total_bytes': 256 * 1024 * 1024,
                'max_page_rows': 1000, 'max_page_bytes': 1024 * 1024,
                'max_pages': 10000, 'deadline_ms': 180000, 'statement_timeout_ms': 8000}
    if set(value) != LIMIT_FIELDS:
        raise ValueError('explicit complete resource declaration required')
    for key, maximum in ceilings.items():
        if type(value[key]) is not int or not 0 < value[key] <= maximum:
            raise ValueError('invalid declared finite resource bound')
    if value['statement_timeout_ms'] > value['deadline_ms'] or value['max_page_bytes'] > value['max_total_bytes']:
        raise ValueError('inconsistent declared resource bounds')
    return dict(value)


def binding(value):
    if set(value) != BINDING_FIELDS or any(not isinstance(v, str) or not v for v in value.values()):
        raise ValueError('complete authenticated public source binding required')
    for key in ['observer_sha256', 'schema_sha256', 'deployment_sha256', 'genesis']:
        if len(value[key]) != 64 or any(c not in '0123456789abcdef' for c in value[key]):
            raise ValueError('invalid public source digest')
    if (len(value['server_pubkey']) != 66 or value['server_pubkey'][:2] not in ['02', '03']
            or any(c not in '0123456789abcdef' for c in value['server_pubkey'])):
        raise ValueError('invalid public server key')
    return dict(value)


def check_identity(value, expected=None):
    if (not isinstance(value, dict) or set(value) != IDENTITY_FIELDS
            or not isinstance(value['snapshot'], str) or not value['snapshot']
            or type(value['backend_pid']) is not int or value['backend_pid'] <= 0
            or not isinstance(value['database'], str) or not value['database']
            or not isinstance(value['observed_at'], str) or not value['observed_at']
            or value['read_only'] != 'on' or value['isolation'] != 'repeatable read'):
        raise ValueError('actual PG snapshot/settings missing')
    if expected is not None and value != expected:
        raise ValueError('mixed database transaction/snapshot')


IDENTITY_SQL = ("SELECT jsonb_build_object('snapshot',pg_current_snapshot()::text,"
                "'backend_pid',pg_backend_pid(),'database',current_database(),"
                "'observed_at',transaction_timestamp()::text,"
                "'read_only',current_setting('transaction_read_only'),"
                "'isolation',current_setting('transaction_isolation'))")


def query_one(cursor, sql):
    cursor.execute(sql)
    row = cursor.fetchone()
    if row is None or len(row) != 1:
        raise ValueError('invalid fixed PG response')
    value = row[0]
    return strict_json(value) if isinstance(value, (str, bytes)) else value


def check_row(table, row, schema):
    if not isinstance(row, dict) or set(row) != set(schema[table]['fields']):
        raise ValueError('unexpected public projection fields')
    if table == 'journal_carriers':
        items = row['fee_inputs']
        if not isinstance(items, list) or any(not isinstance(i, dict) or set(i) != {'outpoint', 'value_sat', 'script_pubkey'} for i in items):
            raise ValueError('unexpected public fee-input fields')


def produce(connection, limits, source, emit, clock=time.monotonic):
    """Emit NDJSON bytes through emit(bytes). Exactly one dedicated PG connection.

    A native DB-API connection adapter is required at integration. This helper
    opens no connection, takes no SQL or cursor from a caller and is not an ops
    endpoint. Source binding is supplied only by an independently authenticated
    installed wrapper, not claimed as PG/chain ownership evidence here.
    """
    limits, source, schema = declaration(limits), binding(source), projections()
    if getattr(connection, 'autocommit', None) is not True:
        raise ValueError('fresh dedicated autocommit PG connection required')
    deadline = clock() + limits['deadline_ms'] / 1000
    previous, sequence, wire_bytes, pages, seen = ZERO, 0, 0, 0, {t: 0 for t in schema}

    def remaining():
        if clock() >= deadline:
            raise ValueError('whole snapshot deadline exceeded')

    def send(kind, **payload):
        nonlocal previous, sequence, wire_bytes
        remaining()
        value = {'kind': kind, 'sequence': sequence, 'previous_sha256': previous, **payload}
        value['sha256'] = digest(value)
        raw = canonical(value) + b'\n'
        if len(raw) > limits['max_page_bytes'] or wire_bytes + len(raw) > limits['max_total_bytes']:
            raise ValueError('stream byte declaration exhausted')
        emit(raw)
        wire_bytes += len(raw)
        previous, sequence = value['sha256'], sequence + 1

    cursor = connection.cursor()
    try:
        cursor.execute('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
        cursor.execute("SET LOCAL statement_timeout = '%dms'" % limits['statement_timeout_ms'])
        cursor.execute("SET LOCAL idle_in_transaction_session_timeout = '%dms'" % limits['deadline_ms'])
        identity = query_one(cursor, IDENTITY_SQL)
        check_identity(identity)
        if identity['database'] != source['database']:
            raise ValueError('actual database differs from source binding')
        # All exact table counts, including zero tables, are from this snapshot.
        fields = ["'%s',(SELECT count(*) FROM %s)" % (t, s['table']) for t, s in schema.items()]
        counts = query_one(cursor, 'SELECT jsonb_build_object(' + ','.join(fields) + ')')
        if (set(counts) != set(schema) or any(type(n) is not int or n < 0 for n in counts.values())
                or sum(counts.values()) > limits['max_total_rows']):
            raise ValueError('complete snapshot exceeds declared row bound')
        send('header', protocol=PROTOCOL, declaration=limits, binding=source,
             projection_sha256=PROJECTION_SHA256, identity=identity, counts=counts)
        for number, (table, spec) in enumerate(schema.items()):
            # Identifier and SQL text come solely from the hashed fixed source.
            name = 'frontier_%d' % number
            cursor.execute('DECLARE %s NO SCROLL CURSOR FOR SELECT row_to_json(q) FROM '
                           '(SELECT %s FROM %s ORDER BY %s) q' %
                           (name, spec['columns'], spec['table'], spec['order_by']))
            while seen[table] < counts[table]:
                remaining()
                if pages >= limits['max_pages']:
                    raise ValueError('page declaration exhausted')
                cursor.execute('FETCH FORWARD %d FROM %s' % (limits['max_page_rows'], name))
                rows = [r[0] if isinstance(r[0], dict) else strict_json(r[0]) for r in cursor.fetchall()]
                if not 0 < len(rows) <= limits['max_page_rows'] or seen[table] + len(rows) > counts[table]:
                    raise ValueError('truncated or excess complete table')
                for row in rows:
                    check_row(table, row, schema)
                check_identity(query_one(cursor, IDENTITY_SQL), identity)
                send('page', table=table, offset=seen[table], rows=rows, identity=identity)
                seen[table] += len(rows)
                pages += 1
            cursor.execute('FETCH FORWARD 1 FROM ' + name)
            if cursor.fetchall():
                raise ValueError('table count omitted trailing rows')
            cursor.execute('CLOSE ' + name)
        check_identity(query_one(cursor, IDENTITY_SQL), identity)
        cursor.execute('ROLLBACK')  # read-only snapshot closed before success footer.
        send('footer', counts=seen, pages=pages, rows=sum(seen.values()), body_bytes=wire_bytes,
             identity=identity, database_tables_complete=True, complete=False, qualified=False)
    finally:
        try:
            connection.rollback()
        finally:
            cursor.close()


def consume(lines, limits, source, producer_exit, clock=time.monotonic):
    """Release DB-only data only after footer, EOF and actual producer exit 0.

    lines must come from a separately bounded process pipe; producer_exit must
    be the wrapper's actual wait/status accessor, never a wire JSON assertion.
    Failed streams are discarded. Caller still verifies owner/chain/readiness.
    """
    limits, source, schema = declaration(limits), binding(source), projections()
    deadline = clock() + limits['deadline_ms'] / 1000
    previous, sequence, wire_bytes, pages = ZERO, 0, 0, 0
    header, footer = None, None
    rows = {name: [] for name in schema}
    order = list(schema)
    last_table = -1
    for raw in lines:
        if clock() >= deadline or footer is not None:
            raise ValueError('deadline or data after final footer')
        if not isinstance(raw, bytes) or not raw.endswith(b'\n') or len(raw) > limits['max_page_bytes']:
            raise ValueError('unbounded/truncated stream record')
        before_bytes = wire_bytes
        wire_bytes += len(raw)
        if wire_bytes > limits['max_total_bytes']:
            raise ValueError('whole stream byte bound exceeded')
        value = strict_json(raw)
        if not isinstance(value, dict) or value.get('sequence') != sequence or type(value.get('sequence')) is not int:
            raise ValueError('stream sequence gap/replay')
        claimed = value.pop('sha256', None)
        if value.get('previous_sha256') != previous or claimed != digest(value):
            raise ValueError('stream hash/source chain differs')
        previous, sequence = claimed, sequence + 1
        common = {'kind', 'sequence', 'previous_sha256'}
        if header is None:
            if set(value) != common | {'protocol', 'declaration', 'binding', 'projection_sha256', 'identity', 'counts'} or value['kind'] != 'header':
                raise ValueError('header required first')
            if value['protocol'] != PROTOCOL or value['declaration'] != limits or value['binding'] != source or value['projection_sha256'] != PROJECTION_SHA256:
                raise ValueError('wrong declared source/protocol')
            check_identity(value['identity'])
            if value['identity']['database'] != source['database'] or set(value['counts']) != set(schema):
                raise ValueError('incomplete source counts')
            if any(type(n) is not int or n < 0 for n in value['counts'].values()) or sum(value['counts'].values()) > limits['max_total_rows']:
                raise ValueError('whole source row bound exceeded')
            header = value
        elif value['kind'] == 'page':
            if set(value) != common | {'table', 'offset', 'rows', 'identity'}:
                raise ValueError('invalid page fields')
            table = value['table']
            if table not in schema or order.index(table) < last_table:
                raise ValueError('unknown/reordered table')
            last_table = order.index(table)
            check_identity(value['identity'], header['identity'])
            items = value['rows']
            if type(value['offset']) is not int or value['offset'] != len(rows[table]) or not isinstance(items, list) or not 0 < len(items) <= limits['max_page_rows']:
                raise ValueError('truncated/replayed/oversized page')
            if len(rows[table]) + len(items) > header['counts'][table] or pages >= limits['max_pages']:
                raise ValueError('page/count bound exceeded')
            for item in items:
                check_row(table, item, schema)
            rows[table].extend(items)
            pages += 1
        elif value['kind'] == 'footer':
            if set(value) != common | {'counts', 'pages', 'rows', 'body_bytes', 'identity', 'database_tables_complete', 'complete', 'qualified'}:
                raise ValueError('invalid final footer')
            check_identity(value['identity'], header['identity'])
            actual = {t: len(items) for t, items in rows.items()}
            if (not isinstance(value['counts'], dict)
                    or any(type(n) is not int for n in value['counts'].values())
                    or any(type(value[k]) is not int for k in ['pages', 'rows', 'body_bytes'])
                    or value['counts'] != actual or actual != header['counts'] or value['pages'] != pages
                    or value['rows'] != sum(actual.values()) or value['body_bytes'] != before_bytes
                    or value['database_tables_complete'] is not True or value['complete'] is not False or value['qualified'] is not False):
                raise ValueError('incomplete/overclaimed final snapshot')
            footer = value
        else:
            raise ValueError('unexpected stream phase')
    if header is None or footer is None or clock() >= deadline:
        raise ValueError('missing footer/EOF/successful producer exit')
    exit_code = producer_exit()
    if type(exit_code) is not int or exit_code != 0:
        raise ValueError('unsuccessful or missing actual producer exit')
    return {'kind': 'closed_frontier', 'schema_version': 2, 'rows': rows,
            'snapshot': header['identity']['snapshot'], 'observed_at': header['identity']['observed_at'],
            'database_identity': header['identity'], 'source_binding': source,
            'stream_final_sha256': previous, 'stream_bytes': wire_bytes,
            'read_only': True, 'inventory_consistent': True, 'database_tables_complete': True,
            'complete': False, 'qualified': False,
            'validation_scope': 'One complete bounded public PG snapshot only; independent authenticated owner, all signed versions, active chain, wallet assets and readiness still required'}

"""Pure synthetic controls; no database, network, deployment or workload credit."""
import copy
import re
import unittest
import frontier_stream as f

LIMITS = {'max_total_rows': 6000, 'max_total_bytes': 8 * 1024 * 1024,
          'max_page_rows': 127, 'max_page_bytes': 256 * 1024,
          'max_pages': 100, 'deadline_ms': 30000, 'statement_timeout_ms': 4000}
SOURCE = {'observer_sha256': '1' * 64, 'schema_sha256': '2' * 64,
          'deployment_sha256': '3' * 64, 'genesis': '4' * 64,
          'server_pubkey': '02' + '5' * 64, 'network': 'regtest', 'database': 'synthetic'}
IDENTITY = {'snapshot': '41:99:52', 'backend_pid': 123, 'database': 'synthetic',
            'observed_at': '2026-10-16 00:00:00+00', 'read_only': 'on', 'isolation': 'repeatable read'}


def dataset(count=2501):
    schema = f.projections()
    rows = {name: [] for name in schema}
    for n in range(count):
        row = {key: None for key in schema['coins']['fields']}
        row['vtxo_id'] = 'synthetic-%06d' % n
        rows['coins'].append(row)
    rows['links'] = [{key: 'synthetic' for key in schema['links']['fields']}]
    rows['journal_carriers'] = [{key: ([] if key == 'fee_inputs' else None)
                                 for key in schema['journal_carriers']['fields']}]
    return rows


class FakeConnection:
    """Only fixed SQL semantics needed to exercise complete-stream invariants."""
    autocommit = True

    def __init__(self, rows=None, counts=None, switch_identity_at=None):
        self.rows = dataset() if rows is None else rows
        self.counts = counts or {t: len(r) for t, r in self.rows.items()}
        self.switch_identity_at = switch_identity_at
        self.identities = 0
        self.executed = []
        self.rollbacks = 0
        self.closed = False
        self.positions = {}
        self.answer = []

    def cursor(self):
        return self

    def execute(self, sql):
        self.executed.append(sql)
        self.answer = []
        if sql == f.IDENTITY_SQL:
            self.identities += 1
            identity = dict(IDENTITY)
            if self.switch_identity_at and self.identities >= self.switch_identity_at:
                identity['snapshot'] = '42:100:53'
            self.answer = [(identity,)]
        elif sql.startswith('SELECT jsonb_build_object('):
            self.answer = [(self.counts,)]
        elif sql.startswith('DECLARE '):
            name = sql.split()[1]
            self.positions[name] = 0
        elif sql.startswith('FETCH '):
            match = re.fullmatch(r'FETCH FORWARD ([0-9]+) FROM frontier_([0-9]+)', sql)
            if not match:
                raise AssertionError(sql)
            limit, n = map(int, match.groups())
            table = list(f.projections())[n]
            name = 'frontier_%d' % n
            pos = self.positions[name]
            selected = self.rows[table][pos:pos + limit]
            self.positions[name] += len(selected)
            self.answer = [(row,) for row in selected]
        elif sql not in ['BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY', 'ROLLBACK'] and not sql.startswith(('SET LOCAL ', 'CLOSE ')):
            raise AssertionError('unexpected SQL: ' + sql)

    def fetchone(self):
        return self.answer[0] if self.answer else None

    def fetchall(self):
        return self.answer

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


def stream(db=None, limits=None):
    lines = []
    f.produce(db or FakeConnection(), limits or LIMITS, SOURCE, lines.append)
    return lines


def rewrite(lines, change):
    """Rehash attacker-controlled frames to exercise semantic, not just hash checks."""
    values = [f.strict_json(line) for line in lines]
    change(values)
    previous = f.ZERO
    result = []
    for n, value in enumerate(values):
        value.pop('sha256', None)
        value['sequence'] = n
        value['previous_sha256'] = previous
        if value['kind'] == 'footer':
            value['body_bytes'] = sum(map(len, result))
        value['sha256'] = f.digest(value)
        previous = value['sha256']
        result.append(f.canonical(value) + b'\n')
    return result


class CompleteFrontierControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lines = stream()

    def consume(self, lines, **kwargs):
        return f.consume(lines, LIMITS, SOURCE, kwargs.get('producer_exit', lambda: 0),
                         clock=kwargs.get('clock', lambda: 0))

    def test_one_transaction_above_old_cap_complete_all_fixed_tables(self):
        db = FakeConnection()
        lines = stream(db)
        result = self.consume(lines)
        self.assertEqual(2501, len(result['rows']['coins']))
        self.assertEqual(set(f.projections()), set(result['rows']))
        self.assertEqual(1, len(result['rows']['links']))
        self.assertEqual(1, len(result['rows']['journal_carriers']))
        self.assertEqual(1, db.executed.count('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY'))
        self.assertEqual(19, sum(s.startswith('DECLARE ') for s in db.executed))
        self.assertEqual(19, sum(s.startswith('CLOSE ') for s in db.executed))
        self.assertTrue(db.closed)
        self.assertTrue(result['database_tables_complete'])
        self.assertFalse(result['complete'])
        self.assertFalse(result['qualified'])

    def test_all_zero_tables_still_require_all_counts_and_footer(self):
        rows = {t: [] for t in f.projections()}
        result = self.consume(stream(FakeConnection(rows)))
        self.assertTrue(all(not items for items in result['rows'].values()))
        self.assertFalse(result['qualified'])

    def test_truncation_and_missing_page_rejected(self):
        for lines in [self.lines[:-1], self.lines[1:], self.lines[:2] + self.lines[3:],
                      rewrite(self.lines, lambda v: v.pop(1))]:
            with self.subTest(length=len(lines)), self.assertRaises(ValueError):
                self.consume(lines)

    def test_rehashed_mixed_snapshot_and_backend_rejected(self):
        for key, replacement in [('snapshot', '100:200:101'), ('backend_pid', 456)]:
            lines = rewrite(self.lines, lambda v: v[1]['identity'].__setitem__(key, replacement))
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'mixed'):
                self.consume(lines)

    def test_failed_or_unknown_actual_producer_exit_rejected(self):
        for code in [1, -9, None, False]:
            with self.subTest(code=code), self.assertRaises(ValueError):
                self.consume(self.lines, producer_exit=lambda: code)

    def test_rehashed_foreign_source_or_declaration_rejected(self):
        for key, value in [('binding', {**SOURCE, 'deployment_sha256': '9' * 64}),
                           ('declaration', {**LIMITS, 'max_page_rows': 128})]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.consume(rewrite(self.lines, lambda v: v[0].__setitem__(key, value)))

    def test_trailing_data_duplicate_keys_or_oversized_line_rejected(self):
        duplicate = self.lines[0].replace(b'"kind":"header"', b'"kind":"header","kind":"header"')
        for lines in [self.lines + self.lines[-1:], [duplicate] + self.lines[1:],
                      [b' ' * (LIMITS['max_page_bytes'] + 1) + b'\n']]:
            with self.assertRaises(ValueError):
                self.consume(lines)

    def test_boolean_footer_numbers_rejected(self):
        empty = stream(FakeConnection({t: [] for t in f.projections()}))
        with self.assertRaises(ValueError):
            self.consume(rewrite(empty, lambda v: v[-1].__setitem__('pages', False)))
        with self.assertRaises(ValueError):
            self.consume(rewrite(empty, lambda v: v[-1]['counts'].__setitem__('coins', False)))

    def test_actual_pg_identity_switch_aborts_without_footer(self):
        db = FakeConnection(switch_identity_at=2)
        emitted = []
        with self.assertRaisesRegex(ValueError, 'mixed'):
            f.produce(db, LIMITS, SOURCE, emitted.append)
        self.assertFalse(any(f.strict_json(line)['kind'] == 'footer' for line in emitted))
        self.assertTrue(db.closed)
        self.assertEqual(1, db.rollbacks)

    def test_actual_counts_truncated_or_extra_rows_abort(self):
        rows = dataset(3)
        for amount in [2, 4]:
            counts = {t: len(items) for t, items in rows.items()}
            counts['coins'] = amount
            with self.subTest(count=amount), self.assertRaises(ValueError):
                stream(FakeConnection(rows, counts))

    def test_row_page_byte_total_and_page_count_envelopes_fail_closed(self):
        for limits in [{**LIMITS, 'max_total_rows': 2000},
                       {**LIMITS, 'max_pages': 1},
                       {**LIMITS, 'max_page_bytes': 100},
                       {**LIMITS, 'max_total_bytes': 256 * 1024}]:
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                stream(limits=limits)

    def test_forbidden_field_rejected_before_page_emit(self):
        rows = dataset(1)
        rows['coins'][0]['signed_tx'] = 'forbidden synthetic field'
        emitted = []
        with self.assertRaisesRegex(ValueError, 'projection fields'):
            f.produce(FakeConnection(rows), LIMITS, SOURCE, emitted.append)
        self.assertEqual(['header'], [f.strict_json(line)['kind'] for line in emitted])

    def test_consumer_deadline_and_explicit_finite_declaration(self):
        ticks = iter([0, 31])
        with self.assertRaises(ValueError):
            self.consume(self.lines, clock=lambda: next(ticks))
        for limits in [{}, {**LIMITS, 'max_pages': True}, {**LIMITS, 'deadline_ms': 180001}]:
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                f.declaration(limits)
        with self.assertRaises(ValueError):
            f.binding({**SOURCE, 'server_pubkey': '02' + 'z' * 64})


if __name__ == '__main__':
    unittest.main(verbosity=2)

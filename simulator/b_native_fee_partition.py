"""Partition authenticated B schema2 fee authorizations; no publication verdict.

Input must come from the admitted protected runtime producer and its replay.
This reducer checks its public, same-file projection against native aggregates.
It does not authenticate signed package bytes, chain state, fee payment, input
ownership, readiness or publication. An unbound/failed/confirmed reservation
continues consuming its entire ceiling; a binding consumes no new allowance.
Native source: 5a6702018bedc37d4d27cec1205abe828ea14ee5,
server/src/watchman/ordinary_fee.rs parse_history/require_urgent_headroom.
"""
import re

from .ownership import EvidenceGap

MAX_MONEY = 21_000_000 * 100_000_000
MAX_RECORDS = 10_000  # admitted runtime producer public projection bound
MAX_BYTES = 2 * 1024 * 1024  # native complete journal bound


def _require(value, field):
    if not value:
        raise EvidenceGap('B native fee partition: ' + field)


def _integer(value, field, *, minimum=0, maximum=MAX_MONEY):
    _require(type(value) is int and minimum <= value <= maximum, field)
    return value


def _hash(value, field, *, nonzero=False):
    _require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value)
             and (not nonzero or value != '0'*64), field)
    return value


def partition_native_fee_authorizations(runtime):
    """Return separate ordinary/urgent attempts without granting money authority.

    This intentionally has no complete/qualified/confirmed/spent labels. Every
    reservation remains charged, including urgent attempts without a binding.
    Consumers must join exact signed publication, all inputs and current-chain
    dispositions separately before using either category for financial proof.
    """
    _require(type(runtime) is dict, 'runtime absent')
    budget = runtime.get('native_budget')
    _require(type(budget) is dict, 'native_budget absent')
    disk, ledger = budget.get('disk_budget'), budget.get('public_ledger')
    _require(type(disk) is dict and type(disk.get('schema_version')) is int
             and disk['schema_version'] == 2, 'schema2 required')
    _require(type(ledger) is dict and set(ledger) == {
        'budget_file_sha256', 'ordinary_reservations', 'urgent_reservations',
        'urgent_bindings', 'record_count'}, 'exact public ledger fields required')
    files = budget.get('files')
    _require(type(files) is dict and type(files.get('ordinary-fee-budget')) is dict,
             'same-file budget identity absent')
    actual = files['ordinary-fee-budget']
    identity = _hash(ledger['budget_file_sha256'], 'ledger hash malformed')
    _require(identity == actual.get('sha256') == disk.get('budget_file_sha256'),
             'ledger/disk/held-file hash differs')
    length = _integer(actual.get('bytes'), 'held-file bytes', maximum=MAX_BYTES)
    _require(type(disk.get('budget_file_bytes')) is int
             and disk['budget_file_bytes'] == length, 'disk/held-file bytes differ')
    count = _integer(ledger['record_count'], 'record count', maximum=MAX_RECORDS)
    ordinary, urgent, bindings = (ledger[name] for name in
        ('ordinary_reservations', 'urgent_reservations', 'urgent_bindings'))
    _require(all(type(rows) is list for rows in (ordinary, urgent, bindings)),
             'ledger row lists required')
    _require(len(ordinary)+len(urgent)+len(bindings) == count,
             'record inventory differs')
    # Every record, including zero-charge p bindings, has a unique actual line.
    ordered = {}
    categories = ((ordinary, {'line', 'ceiling_sat'}, 'ordinary'),
                  (urgent, {'line', 'attempt_index', 'ceiling_sat'}, 'urgent'),
                  (bindings, {'line', 'attempt_index', 'binding_sha256'}, 'binding'))
    for rows, keys, kind in categories:
        previous = 0
        for row in rows:
            _require(type(row) is dict and set(row) == keys, kind+' exact fields')
            line = _integer(row['line'], kind+' line', minimum=1, maximum=MAX_RECORDS)
            _require(line > previous and line not in ordered, 'duplicate/unordered ledger line')
            previous = line
            ordered[line] = (kind, row)
    _require(set(ordered) == set(range(1, count+1)), 'missing ledger line')
    _require((count == 0) == (length == 0), 'empty journal identity differs')
    ordinary_rows, urgent_rows, bound = [], [], {}
    for line in range(1, count+1):
        kind, row = ordered[line]
        if kind in ('ordinary', 'urgent'):
            ceiling = _integer(row['ceiling_sat'], kind+' ceiling', minimum=1)
            if kind == 'ordinary':
                ordinary_rows.append({'attempt_index': len(ordinary_rows)+1,
                                      'line': line, 'ceiling_sat': ceiling})
            else:
                index = _integer(row['attempt_index'], 'urgent attempt index', minimum=1,
                                 maximum=MAX_RECORDS)
                _require(index == len(urgent_rows)+1, 'urgent indices not sequential')
                urgent_rows.append({'attempt_index': index, 'line': line,
                                    'ceiling_sat': ceiling})
        else:
            index = _integer(row['attempt_index'], 'binding index', minimum=1,
                             maximum=MAX_RECORDS)
            _require(index <= len(urgent_rows) and index not in bound,
                     'binding lacks unique prior urgent reservation')
            bound[index] = {'attempt_index': index, 'line': line,
                'binding_sha256': _hash(row['binding_sha256'], 'binding hash', nonzero=True)}
    ordinary_sum = sum(row['ceiling_sat'] for row in ordinary_rows)
    urgent_sum = sum(row['ceiling_sat'] for row in urgent_rows)
    expected = {'ordinary_attempt_count': len(ordinary_rows),
                'urgent_attempt_count': len(urgent_rows), 'urgent_binding_count': len(bound),
                'attempt_count': len(ordinary_rows)+len(urgent_rows),
                'urgent_reserved_ceiling_sum_sat': urgent_sum,
                'reserved_ceiling_sum_sat': ordinary_sum+urgent_sum}
    for field, value in expected.items():
        _require(type(disk.get(field)) is int and disk[field] == value,
                 field+' differs from full ledger partition')
    native = _integer(disk.get('opening_native_spent_sat'), 'native opening')
    external = _integer(disk.get('opening_external_spent_sat'), 'external opening')
    future = _integer(disk.get('external_future_reserved_sat'), 'external future partition')
    allowance = _integer(disk.get('ordinary_budget_sat'), 'lifetime allowance', minimum=1)
    urgent_limit = _integer(disk.get('urgent_reserve_sat'), 'urgent sublimit', minimum=1)
    opening = native+external+future
    charged = opening+ordinary_sum+urgent_sum
    _require(charged <= allowance <= MAX_MONEY and urgent_sum <= urgent_limit,
             'lifetime/urgent sublimit exhausted')
    urgent_remaining = urgent_limit-urgent_sum
    _require(charged+urgent_remaining <= allowance,
             'ordinary history consumed protected urgent headroom')
    for field, value in {'opening_charge_sat': opening, 'total_charged_sat': charged,
                         'remaining_ordinary_allowance_sat': allowance-charged}.items():
        _require(type(disk.get(field)) is int and disk[field] == value,
                 field+' opening/full-ceiling arithmetic differs')
    return {'budget_file_sha256': identity, 'record_count': count,
            'ordinary_attempts': ordinary_rows, 'urgent_attempts': urgent_rows,
            'urgent_bindings': [bound[index] for index in sorted(bound)],
            'unbound_urgent_attempts': [row['attempt_index'] for row in urgent_rows
                                      if row['attempt_index'] not in bound],
            'ordinary_reserved_sat': ordinary_sum, 'urgent_reserved_sat': urgent_sum,
            'opening_charge_sat': opening, 'total_charged_sat': charged,
            'remaining_lifetime_sat': allowance-charged,
            'remaining_urgent_sat': urgent_remaining,
            'remaining_discretionary_sat': allowance-charged-urgent_remaining}

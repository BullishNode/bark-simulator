"""Prospective C Watch grant geometry, without new capital or spending rights.

The existing bank transaction and once-only funding state remain authoritative.
Two separate 50k outputs replace a prospective single 100k output ONLY after an
explicit pre-funding declaration. This is no observed liquidity/readiness proof.
"""
import hashlib
import json

from .architecture import DIRECT_PER_KEY, profile
from .final_campaign import _source_event
from .model import canonical, public_payload

KEY = 'direct_per_key_initial_watch_geometry'
EVENT = 'direct_per_key_initial_watch_geometry_declared'


def _digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def declaration(store):
    encoded = store.get_meta(KEY)
    rows = store.db.execute('SELECT sequence FROM event WHERE kind=?', (EVENT,)).fetchall()
    if encoded is None:
        if rows: raise ValueError('original Watch geometry metadata missing')
        return None
    if profile(store) != DIRECT_PER_KEY or len(rows) != 1:
        raise ValueError('unique original C Watch geometry required')
    _, value = _source_event(store, rows[0][0])
    from .c_pilot import declaration as pilot_declaration
    pilot = pilot_declaration(store)
    if (canonical(value) != encoded or value != {
            'schema': 'c-initial-watch-geometry-v1', 'pilot_sha256': _digest(pilot),
            'pins': pilot['pins'], 'boundary_id': pilot['boundary_id'],
            'member_id': 'watchman', 'amounts_sat': [50000, 50000],
            'descriptor_index': 0, 'child_indexes': [0, 1],
            'total_operator_grant_sat': 100000,
            'ordinary_budget_sat': 60000, 'urgent_budget_sat': 40000,
            'financial_readiness': False, 'new_spending_authority': False}):
        raise ValueError('original C Watch geometry or pilot changed')
    return {**value, 'source_sequence': rows[0][0]}


def declare(store):
    """Append one exact plan before all funding; never mutate old declarations."""
    if profile(store) != DIRECT_PER_KEY:
        raise ValueError('Watch geometry is C-only')
    from .c_pilot import declaration as pilot_declaration
    pilot = pilot_declaration(store)
    value = {'schema': 'c-initial-watch-geometry-v1', 'pilot_sha256': _digest(pilot),
        'pins': pilot['pins'], 'boundary_id': pilot['boundary_id'],
        'member_id': 'watchman', 'amounts_sat': [50000, 50000],
        'descriptor_index': 0, 'child_indexes': [0, 1],
        'total_operator_grant_sat': 100000,
        'ordinary_budget_sat': 60000, 'urgent_budget_sat': 40000,
        'financial_readiness': False, 'new_spending_authority': False}
    public_payload(value)
    with store.transaction():
        if declaration(store) is not None:
            return False
        if not store.get_meta('paused'):
            raise ValueError('pause before prospective Watch geometry')
        if any(store.get_meta(key) is not None for key in (
                'finite_initial_funding_plan', 'fixture_funding_plan',
                'conserved_treasury_boundary', 'financial_operating_envelope')):
            raise ValueError('preserve existing financial declaration; no Watch replan')
        if store.db.execute("SELECT 1 FROM action WHERE operation!='create' OR state!='completed' OR actual_fee_sat IS NOT 0 OR fee_reservation_sat IS NOT 0 LIMIT 1").fetchone():
            raise ValueError('only original completed fee-zero creates may precede geometry')
        if store.db.execute("SELECT 1 FROM event WHERE kind IN ('fixture_funding_intent','fixture_funding_prepare_intent','fixture_funding_prepared','fixture_funding_broadcast_intent','financial_cost_verified') LIMIT 1").fetchone():
            raise ValueError('existing monetary history forbids Watch geometry')
        if store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='funding_batch'").fetchone():
            if store.db.execute('SELECT 1 FROM funding_batch LIMIT 1').fetchone():
                raise ValueError('existing funding batch retained; no Watch replan')
        store.db.execute('INSERT INTO meta VALUES (?,?)', (KEY, canonical(value)))
        store._event(EVENT, value)
    return True


def expand_recipients(store, recipients, addresses):
    """Use only independently derived scripts from the actual owning descriptor."""
    geometry = declaration(store)
    if geometry is None:
        return recipients
    result = []
    for row in recipients:
        if row['member_id'] != 'watchman':
            result.append(row)
            continue
        if (row['role'], row['amount_sat'], row['descriptor_index'], row['child_index']) != ('operator', 100000, 0, 0):
            raise ValueError('original exact Watch grant source required')
        for child in geometry['child_indexes']:
            address, script = addresses[('watchman', 0, child)]
            result.append({**row, 'address': address, 'script': script,
                           'child_index': child, 'amount_sat': 50000})
    from .finite_funding import funding_policy
    validate_recipients(store, result, funding_policy(store)['amounts'])
    return result


def validate_recipients(store, recipients, amounts):
    """Exact per-member sums and physical geometry; no duplicate output credit."""
    geometry = declaration(store)
    if not isinstance(recipients, list) or len(recipients) != len(amounts) + (1 if geometry else 0):
        raise ValueError('finite funding recipient geometry differs')
    totals = {}; groups = {}
    for row in recipients:
        member = row['member_id']; amount = row['amount_sat']
        if member not in amounts or type(amount) is not int or amount <= 0:
            raise ValueError('exact positive declared recipient amount required')
        totals[member] = totals.get(member, 0) + amount
        groups.setdefault(member, []).append(row)
    if totals != amounts:
        raise ValueError('finite recipient totals changed principal or operator grants')
    for member, rows in groups.items():
        if geometry and member == 'watchman':
            if (len(rows) != 2 or any(row['amount_sat'] != 50000 or row['descriptor_index'] != 0
                    or row['role'] != 'operator' for row in rows)
                    or {row['child_index'] for row in rows} != {0, 1}):
                raise ValueError('exact two distinct 50k owning Watch children required')
        elif len(rows) != 1:
            raise ValueError('only declared Watch outputs may share a member')
    if len({r['address'] for r in recipients}) != len(recipients) or len({r['script'] for r in recipients}) != len(recipients):
        raise ValueError('distinct independently derived funding outputs required')
    return geometry

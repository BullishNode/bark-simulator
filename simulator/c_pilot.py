"""Explicit Track C pilot policy within the common simulator admission path.

Declarations describe limits. They never establish an observed bank balance,
loaded runtime, accepted key link, or completed operation.
"""
import json
import re

from .architecture import DIRECT_PER_KEY, profile
from .final_campaign import _pins, _source_event
from .model import canonical, public_payload

KEY = 'direct_per_key_bounded_pilot'
CUSTOMERS = {'actor-01', 'actor-02'}
GRANTS = {'actor-01': 25000, 'actor-02': 0}
FIXED = {'schema_version': 1, 'architecture_profile': DIRECT_PER_KEY,
         'sender': 'actor-01', 'recipient': 'actor-02', 'grants_sat': GRANTS,
         'board_amount_sat': 20000, 'arkoor_amount_sat': 2000,
         'funding_max_miner_fee_sat': 1000, 'board_max_miner_fee_sat': 1000,
         'ordinary_fee_budget_sat': 60000, 'urgent_fee_budget_sat': 40000,
         'board_confirmations': 3, 'ordinary_lifetime_blocks': 48,
         'pool_lifetime_blocks': 48}


def validate(value):
    fields = set(FIXED) | {'id', 'pins', 'boundary_id', 'bank_opening_sat',
                           'board_action_id', 'arkoor_action_id'}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('complete explicit C bounded pilot declaration required')
    public_payload(value); _pins(value['pins'])
    for key, expected in FIXED.items():
        if value[key] != expected or isinstance(expected, int) and type(value[key]) is not int:
            raise ValueError('C pilot fixed scope differs: '+key)
    if (set(value['grants_sat']) != CUSTOMERS
            or any(type(amount) is not int for amount in value['grants_sat'].values())
            or type(value['bank_opening_sat']) is not int
            or not 126000 <= value['bank_opening_sat'] <= 900000):
        raise ValueError('C pilot actual declared opening cannot cover principal and protected budgets')
    for key in ('id', 'boundary_id', 'board_action_id', 'arkoor_action_id'):
        if not isinstance(value[key], str) or re.fullmatch('[a-zA-Z0-9:_-]{1,100}', value[key]) is None:
            raise ValueError('bounded original C pilot identifiers required')
    if value['board_action_id'] == value['arkoor_action_id']:
        raise ValueError('C pilot distinct original monetary action IDs required')
    return value


def declaration(store):
    if profile(store) != DIRECT_PER_KEY:
        raise ValueError('C pilot requires the actual direct_per_key namespace')
    encoded = store.get_meta(KEY)
    if encoded is None:
        raise ValueError('explicit C bounded pilot declaration missing')
    value = validate(json.loads(encoded))
    rows = store.db.execute("SELECT sequence FROM event WHERE kind='direct_per_key_bounded_pilot_declared'").fetchall()
    if len(rows) != 1 or _source_event(store, rows[0][0])[1] != value:
        raise ValueError('C pilot differs from its immutable original declaration')
    return value


def declare(store, value):
    validate(value)
    if profile(store) != DIRECT_PER_KEY:
        raise ValueError('C pilot requires the actual direct_per_key namespace')
    with store.transaction():
        if store.get_meta(KEY) is not None:
            if declaration(store) != value:
                raise ValueError('C bounded pilot declaration is immutable')
            return False
        if (not store.get_meta('paused')
                or store.db.execute("SELECT 1 FROM action WHERE operation NOT IN ('create','sync','snapshot','address') OR state IN ('dispatched','outcome_unknown') LIMIT 1").fetchone()
                or store.db.execute("SELECT 1 FROM event WHERE kind IN ('fixture_funding_intent','financial_cost_verified') LIMIT 1").fetchone()):
            raise ValueError('pause C pilot before any monetary or uncertain work')
        store.db.execute('INSERT INTO meta VALUES (?,?)', (KEY, canonical(value)))
        store._event('direct_per_key_bounded_pilot_declared', value)
    return True


def funding_policy(store):
    """Only the source policy varies; Core signing/once-only state stays common."""
    value = declaration(store)
    return {'customers': CUSTOMERS, 'amounts': {'actor-01': 25000},
            'opening_sat': value['bank_opening_sat'], 'principal_sat': 25000,
            'maximum_fee_sat': 1000, 'maximum_rate_sat_kvb': 20000,
            'ordinary_budget_sat': 60000, 'urgent_budget_sat': 40000,
            'grant_sat': 25000, 'board_sat': 20000, 'board_fee_reserve_sat': 1000,
            'pilot_id': value['id'], 'pins': value['pins'], 'boundary_id': value['boundary_id']}


def board_policy(store=None):
    """Phase policy only; all native dispatch and monetary checks stay shared."""
    if store is not None and profile(store)==DIRECT_PER_KEY:
        pilot=declaration(store)
        return {'actors':['actor-01','actor-02'],'board_actors':['actor-01'],
            'maximum_fee_sat':1000,'grants':pilot['grants_sat'],'opening_sat':pilot['bank_opening_sat'],
            'urgent_budget_sat':40000,'board_action_id':pilot['board_action_id']}
    actors=['actor-01','actor-02','actor-04']
    return {'actors':actors,'board_actors':actors,'maximum_fee_sat':4000,
        'grants':{actor:50000 for actor in actors},'opening_sat':665454,'urgent_budget_sat':15000}

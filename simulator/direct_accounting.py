"""Independent direct-claim arithmetic; never proves ownership or chain validity.

Caller supplies independently verified source partition, destination dust policy
and operator scripts. Returned measurements cannot qualify settlement on their
own. They do not infer allocations from aggregated transaction outputs.
"""
from .model import InvariantError, integer, transaction_fee

FLAT_FEE_SAT = 1000


def expected_outputs(leaves):
    groups = {}
    seen = set()
    for leaf in leaves:
        identity = leaf['id']
        if identity in seen:
            raise InvariantError('same source leaf counted twice')
        seen.add(identity)
        gross = integer(leaf['gross_sat'], 'source gross', 1)
        dust = integer(leaf['dust_sat'], 'actual script dust threshold', 1)
        script = leaf['script']
        if not isinstance(script,str) or not script:
            raise ValueError('destination script missing')
        group = groups.setdefault(script, {'gross_sat':0,'dust_sat':dust,'ids':[]})
        if group['dust_sat'] != dust:
            raise InvariantError('inconsistent relay threshold for one destination')
        group['gross_sat'] += gross
        group['ids'].append(identity)
    expected = {}
    forfeits = 0
    for script, group in groups.items():
        # Whole gross is terminal forfeit. No actual output means no flat charge.
        if group['gross_sat'] < FLAT_FEE_SAT + group['dust_sat']:
            forfeits += group['gross_sat']
        else:
            expected[script] = group['gross_sat'] - FLAT_FEE_SAT
    return {'outputs':expected, 'gross_sat':sum(g['gross_sat'] for g in groups.values()),
            'flat_fee_sat':FLAT_FEE_SAT*len(expected), 'forfeit_sat':forfeits}


def claim_accounts(leaves, tx, operator_input_sat, operator_scripts):
    """Conserve verified physical sources once, distinguishing fees from revenue."""
    expected = expected_outputs(leaves)
    own_input = integer(operator_input_sat, 'operator-owned backing and supplemental fee inputs')
    mining_fee = transaction_fee(tx)
    if sum(i['amount_sat'] for i in tx['inputs']) != expected['gross_sat'] + own_input:
        raise InvariantError('physical inputs do not equal independently classified source partition')
    if set(expected['outputs']) & set(operator_scripts):
        raise InvariantError('customer and operator destination classifications overlap')
    actual = {}
    operator_change = 0
    for output in tx['outputs']:
        script = output['script']
        amount = integer(output['amount_sat'], 'chain output')
        if script in expected['outputs']:
            if script in actual:
                raise InvariantError('one destination has multiple charged recipient outputs')
            actual[script] = amount
        elif script in operator_scripts:
            operator_change += amount
        else:
            raise InvariantError('unknown output ownership; cannot reconcile claim')
    if actual != expected['outputs']:
        raise InvariantError('recipient outputs differ from grouped flat-fee and dust policy')
    net = sum(actual.values())
    if expected['gross_sat'] != net + expected['flat_fee_sat'] + expected['forfeit_sat']:
        raise InvariantError('customer dispositions do not conserve gross')
    delta = operator_change - own_input
    if delta != expected['flat_fee_sat'] + expected['forfeit_sat'] - mining_fee:
        raise InvariantError('operator capital change does not reconcile transaction costs')
    return {**expected,'recipient_net_sat':net,'mining_fee_sat':mining_fee,
            'operator_input_sat':own_input,'operator_change_sat':operator_change,
            'operator_capital_delta_sat':delta,
            'flat_fee_surplus_sat':max(expected['flat_fee_sat']-mining_fee,0),
            'mining_shortfall_after_flat_fees_sat':max(mining_fee-expected['flat_fee_sat'],0),
            'scope':'amounts only; ownership, authorization, backing paths, winning carrier and seed recovery require separate evidence'}

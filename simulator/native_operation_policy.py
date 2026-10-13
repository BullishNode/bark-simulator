"""Pure supervisor checks for explicit native operation requests."""
import re

def _u64(value):
    if type(value) is not int or not 0<=value<2**64:raise ValueError('unsigned bounded integer required')
    return value

def exact_inputs(ids):
    if not isinstance(ids,list) or not 1<=len(ids)<=16 or any(not isinstance(v,str) for v in ids) or len(set(ids))!=len(ids):raise ValueError('1–16 exact unique inputs required')
    for value in ids:
        if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{64}:[0-9]{1,10}',value) or int(value.split(':')[1])>2**32-1:raise ValueError('canonical native coin ID required')
    return list(ids)

def scheduled_height(tip,height,expiries,confirmations,exit_margin):
    values=[tip,height,confirmations,exit_margin,*expiries]
    if any(type(v) is not int or not 0<=v<2**32 for v in values):raise ValueError('bounded native heights/margins required')
    if not expiries or not confirmations or not exit_margin or height<=tip or height+confirmations+exit_margin>=min(expiries):raise ValueError('scheduled refresh would consume the security window')
    return height

def exit_budget(frozen,requested,reserved,next_fee):
    frozen=_u64(frozen);requested=_u64(requested);next_fee=_u64(next_fee)
    used=sum(_u64(fee) for fee in reserved)
    if not frozen or frozen!=requested or used+next_fee>frozen:raise ValueError('immutable lifetime exit fee cap exhausted or changed')
    return frozen-used

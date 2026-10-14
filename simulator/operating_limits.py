"""Explicit money limits before funding/pilot dispatch, with checked source evidence.

No budget, fee ceiling, channel or pool default is inferred. Urgent claims and
progression use separately declared limits; an expensive estimate never silently
raises a ceiling. This is a preflight, not another dispatcher or retry engine.
"""
import json
import time
from .model import InvariantError, canonical, integer, public_payload
from .final_campaign import _pins, _source_event
from .treasury import boundary, capture_assets
from .pool_readiness import ready as pool_ready
from .topology import ready as channel_ready

KEY='financial_operating_envelope'
PATHS={'round','pool','sweep','payout','claim','progression'}
BUDGETS={'ordinary','urgent'}


def validate(declaration,config):
    fields={'id','pins','boundary_id','capital_exposure_msat','fee_budgets_msat','fee_ceilings_sat_kvb',
            'per_action_fee_sat','grant_sat','board_sat','board_fee_reserve_sat','minimum_pool_sat',
            'minimum_channel_msat','fee_assets'}
    if set(declaration)!=fields:raise ValueError('complete explicit operating envelope required')
    _pins(declaration['pins']);public_payload(declaration)
    if not declaration['id'] or not declaration['boundary_id']:raise ValueError('immutable envelope/boundary identifiers required')
    for field in ('capital_exposure_msat','per_action_fee_sat','grant_sat','board_sat','board_fee_reserve_sat','minimum_pool_sat','minimum_channel_msat'):
        integer(declaration[field],field,1)
    if set(declaration['fee_budgets_msat'])!=BUDGETS or set(declaration['fee_ceilings_sat_kvb'])!=PATHS:
        raise ValueError('ordinary/urgent budgets and every real fee path required')
    for amount in [*declaration['fee_budgets_msat'].values(),*declaration['fee_ceilings_sat_kvb'].values()]:integer(amount,'explicit positive financial limit',1)
    if declaration['board_sat']+declaration['board_fee_reserve_sat']>declaration['grant_sat']:
        raise ValueError('declared grant cannot fund its board and fees')
    if config.board_amount_sat!=declaration['board_sat'] or config.action_fee_reserve_sat!=declaration['board_fee_reserve_sat']:
        raise ValueError('actual runtime board/reserve differs from financial declaration')
    assets=declaration['fee_assets']
    if not isinstance(assets,list) or not assets or len(set(assets))!=len(assets):
        raise ValueError('actual distinct confirmed fee-funding outpoints required')
    return declaration


def declare_envelope(store,declaration,config,inventory_sequences,chain):
    """Freeze affordable limits while paused, before a first funded live action."""
    validate(declaration,config);treasury=boundary(store)
    if declaration['boundary_id']!=treasury['id'] or declaration['pins']!=treasury['pins']:
        raise ValueError('operating envelope differs from declared actual treasury')
    assets=capture_assets(store,inventory_sequences,chain)
    funded=0
    for identifier in declaration['fee_assets']:
        asset=assets['assets'].get(identifier)
        if not asset or asset['role']!='operator' or identifier!=asset['backing_outpoint']:
            raise ValueError('fee funding must be actual confirmed operator chain funds')
        funded+=asset['amount_msat']
    if funded<sum(declaration['fee_budgets_msat'].values()):
        raise ValueError('ordinary plus urgent fee budgets not confirmed-funded')
    encoded=canonical(declaration)
    with store.transaction():
        previous=store.get_meta(KEY)
        if previous is not None:
            if previous!=encoded:raise ValueError('financial envelope immutable; use a fresh namespace')
            return False
        if not store.get_meta('paused'):raise ValueError('pause before declaring operating limits')
        if store.db.execute("SELECT 1 FROM event WHERE kind IN ('fixture_funding_intent','action_dispatched') LIMIT 1").fetchone():
            raise ValueError('operating limits required before funding or first pilot')
        store.db.execute('INSERT INTO meta VALUES (?,?)',(KEY,encoded))
        store._event('financial_operating_envelope_declared',{'declaration':declaration,'inventory_sequences':inventory_sequences,
            'tip_hash':assets['tip_hash'],'confirmed_fee_funding_msat':funded})
    return True


def envelope(store,config):
    value=store.get_meta(KEY)
    if value is None:raise ValueError('financial operating limits not declared')
    declaration=json.loads(value);validate(declaration,config)
    rows=store.db.execute("SELECT payload FROM event WHERE kind='financial_operating_envelope_declared'").fetchall()
    if len(rows)!=1 or json.loads(rows[0][0])['declaration']!=declaration:
        raise ValueError('financial limits differ from original declaration')
    return declaration


def fee_totals(store,pins,*,reserved_action_id=None):
    """Deduplicate original miner/router costs and hold each unfinished action once."""
    totals={'ordinary':0,'urgent':0};seen=set();covered_actions=set()
    for row in store.db.execute("SELECT sequence FROM event WHERE kind='financial_cost_verified'"):
        _,proof=_source_event(store,row[0])
        if proof.get('financial_pins')!=pins or proof.get('budget') not in BUDGETS:
            raise ValueError('cost source original financial context missing or wrong')
        identifier=proof['monetary_id']
        if identifier in seen:raise InvariantError('same actual miner/router cost counted twice')
        seen.add(identifier);totals[proof['budget']]+=integer(proof['amount_msat'],'actual miner/router cost')
        if proof.get('action_id'):
            if proof['action_id'] in covered_actions:raise InvariantError('same native client cost counted twice')
            covered_actions.add(proof['action_id'])
    for row in store.db.execute("SELECT id FROM action WHERE state='completed' AND actual_fee_sat>0"):
        if row['id'] not in covered_actions:
            raise ValueError('completed paid action lacks independently checked original cost')
    held=store.db.execute("SELECT COALESCE(SUM(fee_reservation_sat),0) FROM action WHERE state IN ('queued','dispatched','outcome_unknown') AND (? IS NULL OR id!=?)",(reserved_action_id,reserved_action_id)).fetchone()[0]*1000
    # Existing native client queue is ordinary. Urgent server claims/progression
    # must have their own checked original cost/held evidence in readiness.
    totals['ordinary']+=held
    return totals


def preflight(store,config,snapshot,*,operation='ordinary',amount_sat=0,maximum_fee_sat=0,now=None,reserved_action_id=None):
    """Reject stale, underfunded or unaffordable dispatch; return a declared hold."""
    declaration=envelope(store,config);now=time.time() if now is None else now
    if snapshot.get('financial_pins')!=declaration['pins']:raise ValueError('current actual financial pins differ')
    proof_sequence=snapshot.get('operating_readiness_sequence')
    if proof_sequence is None:raise ValueError('original checked operating readiness missing')
    event,proof=_source_event(store,proof_sequence)
    if (event['kind']!='financial_operating_readiness' or proof.get('financial_pins')!=declaration['pins']
            or proof.get('boundary_id')!=declaration['boundary_id'] or proof.get('tip_hash')!=snapshot.get('tip_hash')
            or proof.get('height')!=snapshot.get('height') or proof.get('complete') is not True
            or not 0<=now-proof.get('observed_at',-1)<=90):
        raise ValueError('actual fresh operating readiness not verified')
    if proof.get('effective_fee_ceilings_sat_kvb')!=declaration['fee_ceilings_sat_kvb']:
        raise ValueError('actual round/pool/sweep/payout/claim/progression ceilings differ')
    if integer(proof['capital_exposure_msat'],'actual exposure')>declaration['capital_exposure_msat']:
        raise ValueError('declared capital exposure exhausted')
    actual_funds=integer(proof['available_fee_funding_msat'],'actual unreserved fee funding')
    if reserved_action_id is not None:
        reserved=store.db.execute("SELECT fee_reservation_sat,state FROM action WHERE id=?",(reserved_action_id,)).fetchone()
        if reserved is None or reserved['state'] not in {'queued','dispatched','outcome_unknown'} or reserved['fee_reservation_sat']!=maximum_fee_sat:
            raise ValueError('original action fee reservation differs')
    used=fee_totals(store,declaration['pins'],reserved_action_id=reserved_action_id)
    remaining={key:declaration['fee_budgets_msat'][key]-used[key] for key in BUDGETS}
    if any(value<0 for value in remaining.values()):raise ValueError('cumulative actual financial costs exceed budget')
    urgent=operation in {'claim','progression'};budget='urgent' if urgent else 'ordinary'
    reserve=integer(maximum_fee_sat,'per-action fee reservation')*1000
    if maximum_fee_sat>declaration['per_action_fee_sat'] or reserve>remaining[budget]:
        raise ValueError('per-action or cumulative fee limit exhausted')
    if actual_funds<sum(remaining.values()):raise ValueError('remaining ordinary/urgent budgets no longer backed by available funds')
    estimate=integer(proof['estimated_fee_rate_sat_kvb'],'actual fee estimate',1)
    paths={operation} if urgent else {'round','pool','sweep','payout'}
    if any(estimate>declaration['fee_ceilings_sat_kvb'][path] for path in paths):
        return {'allowed':False,'reason':'fee estimate exceeds affordable declared ceiling','budget':budget,
                'urgent_claims_and_progression':'separate declared budget and path ceiling; never inherit ordinary approval'}
    if operation in {'invoice','pay_invoice','external_lightning'}:
        minimum=max(integer(amount_sat,'Lightning amount',1),declaration['minimum_pool_sat'])
        if not pool_ready(snapshot,minimum) or not channel_ready(snapshot,declaration['minimum_channel_msat']):
            raise ValueError('positive actual eligible pool and bidirectional channel readiness required')
    return {'allowed':True,'budget':budget,'remaining_fee_msat':remaining,'financial_pins':declaration['pins']}

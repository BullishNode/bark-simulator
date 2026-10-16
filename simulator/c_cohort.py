"""C pilot preservation and finite future cohort allocation requirements.

This is a source reducer, never a creator, funder, dispatcher or normal-source
readiness producer. The shared normal hook belongs to its existing sole writer.
Original bootstrap, treasury, funding, fee policy and signed history stay intact.
"""
import hashlib
import json
import math
import re

from .architecture import DIRECT_PER_KEY, profile as architecture
from .final_campaign import _source_event
from .model import canonical, integer, public_payload

SEAL_KEY = 'direct_per_key_pilot_seal'
SEAL_EVENT = 'direct_per_key_pilot_sealed'
PROFILE_KEY = 'direct_per_key_normal_cohort_profile'
PROFILE_EVENT = 'direct_per_key_normal_cohort_profile_declared'
INITIAL = tuple(f'actor-{i:02}' for i in range(1, 13))
RAMP = tuple(f'actor-{i:02}' for i in range(13, 25))


def _digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def _quiescent(store):
    if architecture(store) != DIRECT_PER_KEY or not store.get_meta('paused'):
        raise ValueError('paused owned C namespace required')
    if store.db.execute("SELECT 1 FROM action WHERE state NOT IN ('completed','failed','expected_refusal','blocked','canceled') OR actual_fee_sat IS NULL LIMIT 1").fetchone():
        raise ValueError('all original actions and actual costs must be terminal')
    for table, states in (
        ('funding_batch', ('intent','prepared','broadcasting','broadcast','outcome_unknown')),
        ('actor_lease', ('active','outcome_unknown')),
        ('seed_recovery', ('preparing','prepare_unknown','broadcasting','outcome_unknown')),
        ('noah_control', ('started','outcome_unknown'))):
        if store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone():
            if store.db.execute('SELECT 1 FROM '+table+' WHERE state IN ('+','.join('?' for _ in states)+') LIMIT 1',states).fetchone():
                raise ValueError('original in-flight controller remains: '+table)


def _checkpoint(store, checkpoint):
    previous='0'*64;count=0
    if set(checkpoint) != {'sequence','hash'}:
        raise ValueError('exact original event checkpoint required')
    integer(checkpoint['sequence'],'pilot checkpoint',1)
    if checkpoint['sequence']>10000:raise ValueError('pilot checkpoint exceeds bounded history')
    for row in store.db.execute('SELECT sequence FROM event WHERE sequence<=? ORDER BY sequence',(checkpoint['sequence'],)):
        event,_=_source_event(store,row['sequence']);count+=1
        if event['sequence']!=count or event['previous_hash']!=previous:
            raise ValueError('original pilot event chain differs')
        previous=event['hash']
    if count!=checkpoint['sequence'] or previous!=checkpoint['hash']:
        raise ValueError('original pilot checkpoint differs')


def seal(store):
    encoded=store.get_meta(SEAL_KEY)
    rows=store.db.execute('SELECT sequence FROM event WHERE kind=?',(SEAL_EVENT,)).fetchall()
    if encoded is None:
        if rows:raise ValueError('pilot seal metadata missing over retained history')
        return None
    if len(rows)!=1:raise ValueError('unique original pilot seal required')
    _,value=_source_event(store,rows[0][0])
    if canonical(value)!=encoded:raise ValueError('pilot seal differs from original event')
    from .c_pilot import declaration
    from .identity_bootstrap import declaration as bootstrap, _root
    if (_digest(declaration(store))!=value['pilot_sha256']
            or _digest(bootstrap(store))!=value['bootstrap_sha256']
            or _root(value['wallet_root'])!=value['wallet_root_identity']):
        raise ValueError('original pilot, bootstrap or wallet root changed')
    _checkpoint(store,value['checkpoint'])
    for action_id,digest in value['actions'].items():
        row=store.db.execute('SELECT * FROM action WHERE id=?',(action_id,)).fetchone()
        if row is None or _digest(dict(row))!=digest:
            raise ValueError('original sealed action changed or disappeared')
    for sequence,digest in value['cost_sources'].items():
        event,cost=_source_event(store,int(sequence))
        if event['kind']!='financial_cost_verified' or _digest(cost)!=digest:
            raise ValueError('original sealed fee source changed')
    return {**value,'seal_sequence':rows[0][0]}


def seal_pilot(store,config,chain,*,source_sequence):
    """Re-run the existing real pilot reducer; supplied complete flags do nothing."""
    old=seal(store)
    if old is not None:
        if old['source_sequence']!=source_sequence:raise ValueError('pilot seal immutable')
        return False
    _quiescent(store)
    if store.get_meta('final_financial_epoch') is not None:
        raise ValueError('pilot seal precedes final financial epoch')
    from .c_pilot import declaration
    from .identity_bootstrap import declaration as bootstrap, _root
    from .ordinary_arkoor import record_ordinary_journey
    from .board_adoption import _origin
    from .finite_funding import _retained
    from .operating_limits import fee_totals
    pilot=declaration(store);original=bootstrap(store)
    if original is None or set(original['declaration']['actors'])!={'actor-01','actor-02'}:
        raise ValueError('preserve original two-customer C bootstrap')
    # This invokes full signed/native/chain/frontier/accounting checks. It does
    # not use a caller's summary as a substitute for the genuine pilot journey.
    journey=record_ordinary_journey(store,config,chain,source_sequence=source_sequence)
    origin=_origin(store,chain)
    funding=origin['funding_plan'];batch='finite:'+funding['id']
    row=store.db.execute('SELECT * FROM funding_batch WHERE id=?',(batch,)).fetchone()
    if row is None or row['state']!='confirmed':raise ValueError('original confirmed finite funding required')
    retained=_retained(store,row,funding);actual=chain.transaction(row['txid'])
    if (actual.get('confirmations',0)<1 or actual.get('fee_sat')!=row['fee_sat']
            or actual.get('outputs')!=retained['outputs']
            or [{'outpoint':i['outpoint']} for i in actual['inputs']]!=retained['inputs']):
        raise ValueError('original finite funding independent chain ancestry differs')
    credits={r['member_id']:r['amount_sat'] for r in funding['recipients']}
    if credits!={'actor-01':25000,'watchman':100000}:
        raise ValueError('exact original 25k/100k funding credits required')
    tip=chain.identity()
    source_event,source=_source_event(store,source_sequence)
    if (tip.get('initialblockdownload') is not False or tip.get('chain')!='signet'
            or (tip['blocks'],tip['bestblockhash'])!=(source['height'],source['tip_hash'])
            or journey['financial_pins']!=pilot['pins']):
        raise ValueError('original pilot and independently observed source tip differ')
    costs={};monetary=set()
    for item in store.db.execute("SELECT sequence FROM event WHERE kind='financial_cost_verified'"):
        _,cost=_source_event(store,item[0])
        if cost['monetary_id'] in monetary:raise ValueError('duplicate original economic cost')
        monetary.add(cost['monetary_id']);costs[str(item[0])]=_digest(cost)
    fees=fee_totals(store,pilot['pins'])
    if fees!={'ordinary':(origin['funding_fee_sat']+origin['mining_fee_sat'])*1000,'urgent':0}:
        raise ValueError('original cumulative pilot fees differ')
    actions={row['id']:_digest(dict(row)) for row in store.db.execute('SELECT * FROM action ORDER BY id')}
    last=store.db.execute('SELECT sequence,hash FROM event ORDER BY sequence DESC LIMIT 1').fetchone()
    value={'source_sequence':source_sequence,'journey_sequence':journey['sequence'],
        'pilot_sha256':_digest(pilot),'bootstrap_sha256':_digest(original),'pins':pilot['pins'],
        'wallet_root':original['declaration']['wallet_root'],'wallet_root_identity':_root(original['declaration']['wallet_root']),
        'checkpoint':dict(last),'actions':actions,'cost_sources':costs,'used_fees_msat':fees,
        'funding_batch_id':batch,'funding_txid':row['txid'],'funding_confirmation_sequence':origin['funding_confirmation_sequence'],
        'funding_credits_sat':credits,'physical_total_sat':journey['physical_total_sat'],
        'height':source['height'],'tip_hash':source['tip_hash']}
    public_payload(value)
    with store.transaction():
        _quiescent(store)
        if store.get_meta(SEAL_KEY) is not None:raise ValueError('pilot seal concurrent writer')
        _checkpoint(store,value['checkpoint'])
        store.db.execute('INSERT INTO meta VALUES (?,?)',(SEAL_KEY,canonical(value)))
        store._event(SEAL_EVENT,value)
    return True


def cohort_profile(store):
    encoded=store.get_meta(PROFILE_KEY)
    rows=store.db.execute('SELECT sequence FROM event WHERE kind=?',(PROFILE_EVENT,)).fetchall()
    if encoded is None:
        if rows:raise ValueError('cohort profile metadata missing over retained history')
        return None
    if len(rows)!=1:raise ValueError('unique cohort profile required')
    _,value=_source_event(store,rows[0][0])
    if canonical(value)!=encoded:raise ValueError('cohort profile immutable source differs')
    original=seal(store)
    if original is None or value['seal_sequence']!=original['seal_sequence'] or value['pins']!=original['pins']:
        raise ValueError('cohort profile requires the unchanged original fee epoch and pilot seal')
    return value


def declare_profile(store,value):
    """Freeze prospective capital limits; no new identity or funding admission."""
    fields={'id','seal_sequence','pins','initial_actors','ramp_actors','grant_sat',
            'maximum_client_principal_sat','fee_budgets_sat','capital_exposure_sat'}
    if not isinstance(value,dict) or set(value)!=fields:raise ValueError('complete C cohort profile required')
    public_payload(value);original=seal(store)
    from .c_escrow import effective_opening_sat
    if (original is None or type(value['seal_sequence']) is not int
            or value['seal_sequence']!=original['seal_sequence'] or value['pins']!=original['pins']
            or value['initial_actors']!=list(INITIAL) or value['ramp_actors']!=list(RAMP)
            or type(value['grant_sat']) is not int or value['grant_sat']!=25000
            or type(value['maximum_client_principal_sat']) is not int or value['maximum_client_principal_sat']!=600000
            or value['fee_budgets_sat']!={'ordinary':60000,'urgent':40000}
            or any(type(v) is not int for v in value['fee_budgets_sat'].values())
            or type(value['capital_exposure_sat']) is not int or value['capital_exposure_sat']!=effective_opening_sat(store)):
        raise ValueError('exact preserved C cohort allocation or fee epoch differs')
    if not isinstance(value['id'],str) or re.fullmatch('[a-zA-Z0-9:_-]{1,100}',value['id']) is None:
        raise ValueError('bounded cohort profile ID required')
    from .operating_limits import fee_totals
    used=fee_totals(store,value['pins'])
    if any(used[k]>value['fee_budgets_sat'][k]*1000 for k in used):raise ValueError('original cumulative fee budget exhausted')
    with store.transaction():
        _quiescent(store)
        old=cohort_profile(store)
        if old is not None:
            if old!=value:raise ValueError('cohort profile immutable; no new ID reset')
            return False
        if store.get_meta('final_financial_epoch') is not None:raise ValueError('cohort allocation precedes final epoch')
        store.db.execute('INSERT INTO meta VALUES (?,?)',(PROFILE_KEY,canonical(value)))
        store._event(PROFILE_EVENT,value)
    return True


def cohort_request(store,phase):
    """Return finite requirements only. This never creates actors or actions."""
    value=cohort_profile(store)
    if value is None:raise ValueError('explicit C cohort profile missing')
    if phase=='initial':
        actors=INITIAL;new=INITIAL[2:]
    elif phase=='ramp':
        from .final_campaign import epoch
        final=epoch(store)
        if final is None or final['pins']!=value['pins']:raise ValueError('original frozen final financial epoch required')
        declarations=store.db.execute("SELECT sequence FROM event WHERE kind='final_financial_epoch_declared'").fetchall()
        if len(declarations)!=1:raise ValueError('unique original final epoch required')
        total=0.0
        for item in store.db.execute("SELECT sequence FROM event WHERE kind='qualified_campaign_active_interval' AND sequence>? ORDER BY sequence",(declarations[0][0],)):
            _,interval=_source_event(store,item[0]);delta=interval['seconds']
            if type(delta) not in (int,float) or not math.isfinite(delta) or not 0<delta<=180:
                raise ValueError('actual bounded qualified interval required')
            total+=delta;declared=interval.get('total_seconds')
            if (type(declared) not in (int,float) or not math.isfinite(declared)
                    or not math.isclose(declared,total,rel_tol=0,abs_tol=0.000001)):
                raise ValueError('qualified interval chain differs')
        counter=float(store.get_meta('qualified_campaign_active_seconds') or '0')
        if total<10800 or not math.isfinite(counter) or not math.isclose(total,counter,rel_tol=0,abs_tol=0.000001):
            raise ValueError('actual credited 10800 seconds required before new ramp identities')
        actors=RAMP;new=RAMP
    else:raise ValueError('only exact initial/ramp cohorts supported')
    original=seal(store);credits=original['funding_credits_sat']
    requirements={actor:max(0,value['grant_sat']-credits.get(actor,0)) for actor in actors}
    return {'profile_id':value['id'],'phase':phase,'actors':list(actors),'new_actors':list(new),
        'retained_actors':list(INITIAL[:2]) if phase=='initial' else [],
        'funding_requirements_sat':requirements,'retained_operator_credits_sat':{'watchman':credits['watchman']},
        'seal_sequence':value['seal_sequence'],
        'required_sources':['new absent-path once-only create intent under explicit cohort scope',
            'same-tip independent zeroasset Core source and original driver response',
            'authenticated native V4 immutable record and all original51 V1 key proofs per new actor',
            'actual complete normal economic/source, pool/LN/native signer and cumulative fee readiness']}

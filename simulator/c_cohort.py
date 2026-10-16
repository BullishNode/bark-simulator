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
    credits={}
    for recipient in funding['recipients']:
        amount=recipient['amount_sat']
        integer(amount,'retained funding credit',1)
        member=recipient['member_id']
        credits[member]=credits.get(member,0)+amount
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



def _no_money(store):
    """Prospective path only: no financial intent, signed state or budget debit."""
    if store.db.execute("SELECT 1 FROM action WHERE operation!='create' OR state!='completed' OR actual_fee_sat!=0 OR fee_reservation_sat!=0 LIMIT 1").fetchone():
        raise ValueError('pre-money opening permits completed zero-fee creates only')
    for table in ('funding_batch','owned_coin','movement_evidence'):
        if store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone():
            if store.db.execute('SELECT 1 FROM '+table+' LIMIT 1').fetchone():
                raise ValueError('preserved funded path required over existing '+table)
    if store.db.execute("SELECT 1 FROM event WHERE kind IN ('fixture_funding_intent','fixture_funding_prepared','fixture_funding_broadcast_intent','closed_cohort_funding_intent','financial_cost_verified','ark_transfer_verified','board_funded') LIMIT 1").fetchone():
        raise ValueError('pre-money opening cannot replace original financial history')
    if store.get_meta('final_financial_epoch') is not None or store.get_meta('qualified_campaign_active_seconds') not in (None,'0'):
        raise ValueError('pre-money opening cannot reset epoch or clock')


def seal_unfunded(store,config,chain):
    """Preserve actual original create01; no pilot payment detour is required.

    This requires the original independently verified zero-asset receipt and all
    51 native key acknowledgements. It never recreates, opens or funds a wallet.
    The source must match the independently observed current tip. A missing zero
    proof remains a hold, including the actual namespace before reconciliation.
    """
    previous=seal(store)
    if previous is not None:
        if previous.get('opening_kind')!='unfunded_initial12':
            raise ValueError('preserve existing funded opening')
        return False
    _quiescent(store);_no_money(store)
    from .c_pilot import declaration
    from .identity_bootstrap import declaration as bootstrap,_context,_root,_sole_writer
    pilot=declaration(store);original=bootstrap(store)
    if original is None or original['declaration']['actors']!=['actor-01','actor-02']:
        raise ValueError('original two-actor identity declaration required')
    _context(config,original['declaration'],store=store)
    root=original['declaration']['wallet_root'];_sole_writer(root)
    if _root(root)!=original['filesystem']:raise ValueError('original wallet root changed')
    actions=[dict(row) for row in store.db.execute('SELECT * FROM action ORDER BY id')]
    if len(actions)!=1 or actions[0]['id']!='c_create_01' or actions[0]['actor_id']!='actor-01':
        raise ValueError('exact once-completed original c_create_01 required')
    rows=store.db.execute("SELECT sequence FROM event WHERE kind='identity_bootstrap_zero_assets_verified' AND json_extract(payload,'$.actor')='actor-01'").fetchall()
    if len(rows)!=1:raise ValueError('original actor01 independent zero-asset proof required')
    event,zero=_source_event(store,rows[0][0])
    if (zero.get('action_id')!='c_create_01' or zero.get('bootstrap_id')!=original['declaration']['id']
            or zero.get('bootstrap_declaration_sha256')!=_digest(original['declaration'])
            or zero.get('financial_pins')!=pilot['pins'] or zero.get('complete') is not True
            or zero.get('zero_assets') is not True or zero.get('confirmed_assets_sat')!=0
            or zero.get('unconfirmed_assets_sat')!=0):
        raise ValueError('original actor01 zero source context differs')
    native_event,native=_source_event(store,zero.get('driver_response_sequence'))
    response=native.get('response',{})
    if (native_event['kind']!='driver_response' or native.get('action_id')!='c_create_01'
            or response.get('action_id')!='c_create_01' or response.get('status')!='ok'
            or response.get('actual_fee_sat')!=0 or json.loads(actions[0]['result'])!=response
            or _digest(response)!=zero.get('native_response_sha256')
            or native_event['hash']!=zero.get('source_event_hash')):
        raise ValueError('original completed create body differs')
    _verify_key_sources(store,'actor-01','c_create_01',response.get('data',{}),pilot['pins'])
    descriptors=zero.get('descriptors')
    if (not isinstance(descriptors,list) or len(descriptors)!=1
            or descriptors!=response['data'].get('onchain_inventory',{}).get('descriptors')
            or descriptors[0].get('keychain')!='external'):
        raise ValueError('original public owning descriptor source required')
    derived=chain.call('deriveaddresses',descriptors[0]['descriptor'],[0,0])
    if not isinstance(derived,list) or len(derived)!=1:
        raise ValueError('independent native external0 payout derivation required')
    address=chain.call('validateaddress',derived[0])
    if address.get('isvalid') is not True or address.get('scriptPubKey')!=response['data']['binding']['spk']:
        raise ValueError('original immutable payout differs from independent external0')
    from .owned_mempool import verify as verify_activity
    from .model import SIGNET_GENESIS
    verify_activity(store,zero.get('mempool_activity'),expected_context={
        'collector':'identity_bootstrap_zero_assets','actor':'actor-01','action_id':'c_create_01',
        'height':zero['height'],'tip_hash':zero['tip_hash'],'genesis':SIGNET_GENESIS,
        'native_response_sha256':zero['native_response_sha256'],
        'bootstrap_declaration_sha256':_digest(original['declaration'])})
    import time
    tip=chain.identity()
    if (tip.get('chain')!='signet' or tip.get('initialblockdownload') is not False
            or (tip['blocks'],tip['bestblockhash'])!=(zero['height'],zero['tip_hash'])
            or not 0<=time.time()-zero.get('observed_at',0)<=90):
        raise ValueError('current independently verified original actor01 zero source required')
    last=store.db.execute('SELECT sequence,hash FROM event ORDER BY sequence DESC LIMIT 1').fetchone()
    value={'opening_kind':'unfunded_initial12','source_sequence':event['sequence'],
        'pilot_sha256':_digest(pilot),'bootstrap_sha256':_digest(original),'pins':pilot['pins'],
        'wallet_root':root,'wallet_root_identity':_root(root),'checkpoint':dict(last),
        'actions':{row['id']:_digest(row) for row in actions},'cost_sources':{},
        'used_fees_msat':{'ordinary':0,'urgent':0},'funding_credits_sat':{'watchman':0},
        'pending_original_create_ids':{'actor-02':'c_create_02'},
        'height':zero['height'],'tip_hash':zero['tip_hash'],
        'scope':'original unfunded identity preservation only; no funding/readiness authority'}
    public_payload(value)
    with store.transaction():
        _quiescent(store);_no_money(store)
        if store.get_meta(SEAL_KEY) is not None:raise ValueError('opening concurrent writer')
        _checkpoint(store,value['checkpoint'])
        store.db.execute('INSERT INTO meta VALUES (?,?)',(SEAL_KEY,canonical(value)))
        store._event(SEAL_EVENT,value)
    return True


def validate_original_unfunded_create(store,action):
    """Keep original predeclared02 ID; existing01 is never admitted again."""
    if architecture(store)!=DIRECT_PER_KEY:return
    opening=seal(store)
    if opening is None or opening.get('opening_kind')!='unfunded_initial12':return
    if action is not None and (action.get('actor_id')!='actor-02' or action.get('id')!='c_create_02'):
        raise ValueError('preserve original pending c_create_02; never retry01')


def prospective_funding_policy(store):
    """Exact direct-initial12 contract for the root-owned collector integration.

    A declaration is no financial permission. Actual complete original12 source,
    immutable first funding plan and all ordinary preflight checks are required.
    """
    value=cohort_profile(store);opening=seal(store)
    if value is None or opening.get('opening_kind')!='unfunded_initial12':
        raise ValueError('explicit unfunded initial12 profile required')
    from .c_pilot import declaration
    from .c_escrow import effective_opening_sat
    pilot=declaration(store)
    return {'customers':set(INITIAL),'amounts':{**{actor:25000 for actor in INITIAL},'watchman':100000},
        'profile_id':value['id'],'pilot_id':pilot['id'],'boundary_id':pilot['boundary_id'],
        'opening_sat':effective_opening_sat(store),'urgent_isolation_qualified':False,
        'principal_sat':400000,'client_principal_sat':300000,
        'operator_fee_grants_sat':{'rounds':0,'watchman':100000},'fee_signer_member':'watchman',
        'ordinary_budget_sat':60000,'urgent_budget_sat':40000,'maximum_fee_sat':1000,
        'maximum_rate_sat_kvb':20000,'grant_sat':25000,'board_sat':20000,'board_fee_reserve_sat':1000,
        'pins':value['pins'],'opening_kind':'unfunded_initial12','seal_sequence':value['seal_sequence'],
        'required_source_actors':list(INITIAL),'retained_create_ids':{'actor-01':'c_create_01','actor-02':'c_create_02'},
        'scope':'source contract only; root finite-funding integration and complete12 source remain required'}


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


ENROLLMENT_EVENT = 'direct_per_key_cohort_enrollment_declared'
CREATE_EVENT = 'direct_per_key_cohort_create_intent'
ZERO_EVENT = 'direct_per_key_cohort_zero_assets_verified'


def enrollment(store,phase):
    key='direct_per_key_cohort_enrollment_'+phase
    encoded=store.get_meta(key)
    rows=store.db.execute('SELECT sequence FROM event WHERE kind=? AND json_extract(payload,\'$.phase\')=?',(ENROLLMENT_EVENT,phase)).fetchall()
    if encoded is None:
        if rows:raise ValueError('cohort enrollment metadata missing over original history')
        return None
    if phase not in ('initial','ramp') or len(rows)!=1:raise ValueError('unique exact cohort enrollment required')
    _,value=_source_event(store,rows[0][0]);selected=cohort_profile(store)
    if canonical(value)!=encoded or selected is None or value['profile_sha256']!=_digest(selected):
        raise ValueError('cohort enrollment original profile differs')
    if value['declaration']['actors']!=list(INITIAL[2:] if phase=='initial' else RAMP):
        raise ValueError('exact new cohort identities required')
    return {**value,'enrollment_sequence':rows[0][0]}


def enrollment_for_actor(store,actor):
    if architecture(store)!=DIRECT_PER_KEY:return None
    for phase in ('initial','ramp'):
        current=enrollment(store,phase)
        if current is not None and actor in current['declaration']['actors']:return current
    return None


def declare_enrollment(store,config,phase,*,identifier,actions):
    """Declare only new absent paths; the original root-empty API is untouched."""
    _quiescent(store);requirements=cohort_request(store,phase);selected=cohort_profile(store)
    from .identity_bootstrap import declaration as bootstrap,_context,_root,_sole_writer
    original=bootstrap(store);base=original['declaration'];root=base['wallet_root']
    _sole_writer(root)
    if _root(root)!=original['filesystem']:raise ValueError('original private wallet root identity changed')
    new=requirements['new_actors']
    if (not isinstance(identifier,str) or re.fullmatch('[a-zA-Z0-9:_-]{1,100}',identifier) is None
            or not isinstance(actions,dict) or set(actions)!=set(new)
            or len(set(actions.values()))!=len(new)
            or any(not isinstance(v,str) or re.fullmatch('[a-zA-Z0-9:_-]{1,100}',v) is None for v in actions.values())):
        raise ValueError('exact distinct new-cohort create IDs required')
    previous=enrollment(store,phase)
    if previous is not None:
        if previous['declaration']['id']!=identifier or previous['actions']!=actions:
            raise ValueError('cohort enrollment and create IDs immutable')
        return False
    opening=seal(store)
    if phase=='initial' and opening.get('opening_kind')=='unfunded_initial12':
        from .identity_bootstrap import pending
        if pending(store):raise ValueError('original01/02 zero-asset proofs required before extra10')
        rows=store.db.execute("SELECT sequence FROM event WHERE kind='identity_bootstrap_zero_assets_verified' AND json_extract(payload,'$.actor')='actor-02'").fetchall()
        if len(rows)!=1:raise ValueError('original c_create_02 zero source required')
        _,zero=_source_event(store,rows[0][0])
        if zero.get('action_id')!='c_create_02':raise ValueError('original02 create ID changed')
        _,native=_source_event(store,zero['driver_response_sequence'])
        _verify_key_sources(store,'actor-02','c_create_02',native['response'].get('data',{}),selected['pins'])
    if phase=='ramp' and not enrollment_complete(store,'initial'):
        raise ValueError('all initial new identities require original checked sources')
    from pathlib import Path
    allowed=set(INITIAL[:2] if phase=='initial' else INITIAL)
    children={item.name:item for item in Path(root).iterdir()}
    if set(children)!=(allowed|{'supervisor.lock'}) or any(item.is_symlink() for item in children.values()):
        raise ValueError('exact retained private wallet directories required before cohort')
    import stat,os
    if any(not stat.S_ISDIR(children[a].lstat().st_mode)
           or stat.S_IMODE(children[a].lstat().st_mode)!=0o700
           or children[a].lstat().st_uid!=os.getuid() for a in allowed):
        raise ValueError('retained actor paths must remain owned private directories')
    for actor,action_id in actions.items():
        if (Path(root)/actor).exists() or store.db.execute('SELECT 1 FROM action WHERE actor_id=? OR id=? LIMIT 1',(actor,action_id)).fetchone():
            raise ValueError('new cohort actor path or action already attempted')
        row=store.db.execute('SELECT details FROM actor WHERE id=?',(actor,)).fetchone()
        if row is not None and (json.loads(row[0]) or not store.ordinary_actor_available(actor)):
            raise ValueError('new actor must be fresh and unheld')
    value={**base,'id':identifier,'actors':list(new),'pins':selected['pins']}
    context=_context(config,value)
    proof={'phase':phase,'profile_sha256':_digest(selected),'declaration':value,
        'actions':actions,'filesystem':original['filesystem'],'context':context,
        'retained_actors':sorted(allowed)}
    with store.transaction():
        _quiescent(store)
        key='direct_per_key_cohort_enrollment_'+phase
        if store.get_meta(key) is not None:raise ValueError('cohort enrollment concurrent writer')
        for actor in new:
            if store.db.execute('SELECT 1 FROM actor WHERE id=?',(actor,)).fetchone() is None:
                store.db.execute("INSERT INTO actor VALUES (?, 'declared C cohort identity',1,'{}')",(actor,))
        store.db.execute('INSERT INTO meta VALUES (?,?)',(key,canonical(proof)))
        store._event(ENROLLMENT_EVENT,proof)
    return True


def _zero_sources(store,current):
    result={};value=current['declaration']
    for row in store.db.execute('SELECT sequence FROM event WHERE kind=? AND json_extract(payload,\'$.bootstrap_id\')=? ORDER BY sequence',(ZERO_EVENT,value['id'])):
        event,proof=_source_event(store,row[0]);actor=proof.get('actor')
        if (actor not in value['actors'] or proof.get('action_id')!=current['actions'][actor]
                or proof.get('bootstrap_declaration_sha256')!=_digest(value)
                or proof.get('financial_pins')!=value['pins'] or proof.get('zero_assets') is not True or proof.get('complete') is not True):
            raise ValueError('original cohort zero-asset context differs')
        action=store.db.execute('SELECT actor_id,operation,state,actual_fee_sat,result FROM action WHERE id=?',(proof['action_id'],)).fetchone()
        response_event,response=_source_event(store,proof.get('driver_response_sequence'))
        if (action is None or tuple(action)[:4]!=(actor,'create','completed',0)
                or json.loads(action['result'])!=response.get('response')
                or response_event['kind']!='driver_response' or response_event['hash']!=proof.get('source_event_hash')
                or response.get('action_id')!=proof['action_id'] or response['response'].get('status')!='ok'
                or response['response'].get('actual_fee_sat')!=0
                or _digest(response['response'])!=proof.get('native_response_sha256')):
            raise ValueError('cohort original completed native source differs')
        if (proof.get('confirmed_assets_sat')!=0 or proof.get('unconfirmed_assets_sat')!=0
                or proof.get('descriptor_range')!=[0,19]):
            raise ValueError('complete original independent zero-assets source required')
        from .owned_mempool import verify as verify_activity
        from .model import SIGNET_GENESIS
        verify_activity(store,proof.get('mempool_activity'),expected_context={
            'collector':'identity_bootstrap_zero_assets','actor':actor,'action_id':proof['action_id'],
            'height':proof['height'],'tip_hash':proof['tip_hash'],'genesis':SIGNET_GENESIS,
            'native_response_sha256':proof['native_response_sha256'],
            'bootstrap_declaration_sha256':_digest(value)})
        result[actor]=(event,proof)
    return result


def enrollment_complete(store,phase):
    current=enrollment(store,phase)
    if current is None:return False
    rows=store.db.execute("SELECT sequence FROM event WHERE kind='direct_per_key_cohort_identities_verified' AND json_extract(payload,'$.phase')=?",(phase,)).fetchall()
    if not rows:return False
    if len(rows)!=1:raise ValueError('unique original cohort identity closure required')
    _,proof=_source_event(store,rows[0][0])
    if (proof.get('enrollment_sequence')!=current['enrollment_sequence']
            or proof.get('profile_sha256')!=current['profile_sha256']
            or set(proof.get('sources',{}))!=set(current['declaration']['actors'])):
        raise ValueError('original cohort identity closure context differs')
    _zero_sources(store,current)  # Retain refusal of any malformed later source.
    for actor,reference in proof['sources'].items():
        event,source=_source_event(store,reference['sequence'])
        if (event['hash']!=reference['hash'] or event['kind']!=ZERO_EVENT
                or source.get('actor')!=actor or source.get('action_id')!=current['actions'][actor]
                or source.get('financial_pins')!=current['declaration']['pins']
                or (source.get('height'),source.get('tip_hash'))!=(proof['height'],proof['tip_hash'])):
            raise ValueError('original same-tip cohort proof source differs')
    return True


def finalize_enrollment(store,phase):
    # This is called only AFTER the existing independent Core/native verifier.
    # An owner may repeat readonly observation at a new tip; no create is retried.
    import time
    if enrollment_complete(store,phase):return False
    current=enrollment(store,phase)
    if current is None:raise ValueError('declared cohort required')
    sources=_zero_sources(store,current)
    if set(sources)!=set(current['declaration']['actors']):return False
    tips={(proof['height'],proof['tip_hash']) for _,proof in sources.values()}
    if len(tips)!=1 or any(not 0<=time.time()-proof.get('observed_at',0)<=90 for _,proof in sources.values()):
        return False  # Old receipts are retained; explicit readonly refresh needed.
    all_scripts=set()
    for _,source in sources.values():
        scripts=source['mempool_activity']['scripts']
        if len(scripts)!=20 or all_scripts.intersection(scripts):
            raise ValueError('independent new cohort wallet descriptor scripts required')
        all_scripts.update(scripts)
    height,tip=tips.pop()
    proof={'phase':phase,'enrollment_sequence':current['enrollment_sequence'],
        'profile_sha256':current['profile_sha256'],'height':height,'tip_hash':tip,
        'sources':{actor:{'sequence':event['sequence'],'hash':event['hash']} for actor,(event,_) in sources.items()},
        'scope':'new cohort independent zero-assets and native per-key identities only; no monetary readiness'}
    store.event('direct_per_key_cohort_identities_verified',proof)
    return True


def pending_enrollment(store):
    if architecture(store)!=DIRECT_PER_KEY:return None
    for phase in ('initial','ramp'):
        current=enrollment(store,phase)
        if current is not None and not enrollment_complete(store,phase):return current
    return None


def eligible_create(store,config,snapshot,action=None):
    current=pending_enrollment(store)
    if current is None:return False
    import os,time
    from pathlib import Path
    from .identity_bootstrap import _context,_root,_sole_writer
    value=current['declaration'];root=value['wallet_root'];_context(config,value);_sole_writer(root)
    if _root(root)!=current['filesystem']:raise ValueError('original cohort root identity changed')
    config.validate_identity(snapshot)
    if (snapshot.get('financial_pins')!=value['pins'] or snapshot.get('stable_tip') is not True
            or snapshot.get('initial_block_download') is not False or snapshot.get('server_status',{}).get('status')!='running'
            or not 0<=time.time()-snapshot.get('observed_at',0)<=90):
        raise ValueError('fresh exact cohort target source required')
    if store.db.execute("SELECT 1 FROM action WHERE state='outcome_unknown' LIMIT 1").fetchone():
        raise ValueError('cohort unknown outcome parked; never retry')
    verified=set(_zero_sources(store,current));intents=[]
    for row in store.db.execute('SELECT sequence FROM event WHERE kind=? AND json_extract(payload,\'$.bootstrap_id\')=?',(CREATE_EVENT,value['id'])):
        _,item=_source_event(store,row[0]);intents.append(item)
        if (item.get('actor') not in value['actors'] or item.get('action_id')!=current['actions'][item['actor']]
                or item.get('financial_pins')!=value['pins'] or item.get('actor_path_absent') is not True):
            raise ValueError('original cohort create intent differs')
    if len({item['actor'] for item in intents})!=len(intents):raise ValueError('cohort create repeated')
    allowed=set(current['retained_actors'])|{'supervisor.lock'}|{item['actor'] for item in intents}
    if any(path.name not in allowed or path.is_symlink() for path in Path(root).iterdir()):
        raise ValueError('cohort root contains unenumerated wallet')
    if any(item['actor'] not in verified for item in intents):raise ValueError('await original cohort zero-asset and key proofs')
    if action is None:
        if len(intents)==len(value['actors']):raise ValueError('cohort identities require explicit shared-tip source refresh')
        return True
    actor=action['actor_id']
    retained=store.db.execute('SELECT actor_id,operation,state,args,fee_reservation_sat FROM action WHERE id=?',(action['id'],)).fetchone()
    if (retained is None or retained['actor_id']!=actor or retained['operation']!='create'
            or retained['state'] not in ('queued','dispatched') or json.loads(retained['args'])!={}
            or retained['fee_reservation_sat']!=0):
        raise ValueError('original queued or dispatched zero-principal create required')
    if (actor not in value['actors'] or action['id']!=current['actions'][actor] or action['operation']!='create'
            or action['args'] or action['fee_reservation_sat']!=0 or actor in {item['actor'] for item in intents}
            or os.path.lexists(Path(root)/actor)):
        raise ValueError('cohort permits one exact absent-path zero-fee create only')
    if store.db.execute("SELECT 1 FROM action WHERE state='dispatched' AND id!=? LIMIT 1",(action['id'],)).fetchone():
        raise ValueError('cohort create requires existing sole writer')
    return True


def begin_create(store,config,snapshot,action):
    if not eligible_create(store,config,snapshot,action):raise ValueError('cohort bootstrap inactive')
    current=pending_enrollment(store);value=current['declaration']
    from .identity_bootstrap import _context,_root
    with store.transaction():
        store._event(CREATE_EVENT,{'bootstrap_id':value['id'],'financial_pins':value['pins'],
            'actor':action['actor_id'],'action_id':action['id'],'operation':'create','maximum_fee_sat':0,
            'actor_path_absent':True,'filesystem':_root(value['wallet_root']),'context':_context(config,value)})


def verify_created(store,config,chain,actor,action_id):
    current=enrollment_for_actor(store,actor)
    if current is None or current['actions'][actor]!=action_id:raise ValueError('exact original cohort create required')
    from .identity_bootstrap import _context,_root
    _context(config,current['declaration'])
    if _root(current['declaration']['wallet_root'])!=current['filesystem']:raise ValueError('cohort root changed')
    intents=store.db.execute('SELECT sequence FROM event WHERE kind=? AND json_extract(payload,\'$.action_id\')=?',(CREATE_EVENT,action_id)).fetchall()
    if len(intents)!=1:raise ValueError('original absent-path cohort create intent required')
    _,intent=_source_event(store,intents[0][0])
    if intent.get('actor')!=actor or intent.get('bootstrap_id')!=current['declaration']['id']:
        raise ValueError('cohort original intent identity differs')
    from .closed_cohort_sources import verify_bootstrap_zero_assets
    result=verify_bootstrap_zero_assets(store,config,chain,actor,action_id,bootstrap_declaration=current['declaration'])
    finalize_enrollment(store,current['phase'])
    return result


def verify_native_identity(store,actor,action_id,data):
    """Consume all native acknowledgements and already independently checked keys."""
    current=enrollment_for_actor(store,actor)
    if current is None or current['actions'][actor]!=action_id:raise ValueError('declared cohort identity required')
    return _verify_key_sources(store,actor,action_id,data,current['declaration']['pins'])


def _verify_key_sources(store,actor,action_id,data,pins):
    from .per_key import initial_origins,binding_matches,proof_matches
    origins=initial_origins(data);binding=data['binding']
    rows=store.db.execute("SELECT sequence FROM event WHERE kind='public_ownership_verified' AND json_extract(payload,'$.action_id')=?",(action_id,)).fetchall()
    if len(rows)!=1:raise ValueError('unique original native signature verification source required')
    _,proof_source=_source_event(store,rows[0][0])
    if (proof_source.get('actor')!=actor or proof_source.get('financial_pins')!=pins
            or proof_source.get('objects')!=51):raise ValueError('all original51 independent key proofs required')
    for origin in origins:
        row=store.db.execute('SELECT * FROM owner_key WHERE pubkey=?',(origin['user_pubkey'],)).fetchone()
        checked=json.loads(row['proof']) if row else {}
        if (row is None or row['actor']!=actor or row['mailbox']!=binding['mailbox_pk']
                or checked.get('financial_pins')!=pins or not proof_matches(checked,origin)
                or not binding_matches(checked.get('binding',{}),binding)):
            raise ValueError('cohort original independently checked key identity differs')
    record=store.db.execute('SELECT * FROM owner_record WHERE mailbox=?',(binding['mailbox_pk'],)).fetchone()
    if (record is None or record['actor']!=actor or record['record_version']!=4 or record['script']!=binding['spk']
            or not binding_matches(json.loads(record['proof']),binding)):
        raise ValueError('cohort original immutable native payout record differs')
    from .c_pilot import verify_public_key_rows
    return verify_public_key_rows(store,actor,origins,initial=True)

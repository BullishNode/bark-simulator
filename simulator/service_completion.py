"""Finite qualification ends while a funded service continues operating.

A report is not a verifier. This evaluator requires original terminal proofs,
complete obligation coverage and independently checked backing at the same tip.
Known, backed, time-bounded normal liabilities need not be zero at completion.
"""
import json,time
from .model import InvariantError,integer,timestamp,canonical,public_payload
from .final_campaign import epoch,_source_event
from .treasury import boundary,capture_assets

TERMINAL_PROOFS={'direct_payout_verified','seed_recovery_spend_verified','protocol_refusal_verified',
                 'terminal_forfeit_verified','user_exit_verified','lightning_terminal_verified',
                 'round_terminal_verified','maintenance_guard_verified','ark_transfer_verified'}
ORDINARY={'maturity','confirmation','recovery'}
KEY='service_completion_contract'

def declare_contract(store,contract):
    if set(contract)!={'pins','requirements','ordinary_bounds'} or set(contract['ordinary_bounds'])!=ORDINARY:
        raise ValueError('explicit finite cases and ordinary liability bounds required')
    from .final_campaign import _pins
    _pins(contract['pins']);public_payload(contract)
    requirements=contract['requirements']
    if not isinstance(requirements,list) or not requirements or len(requirements)>512 or len({r['id'] for r in requirements})!=len(requirements):
        raise ValueError('bounded unique finite cases required')
    for bounds in contract['ordinary_bounds'].values():
        if set(bounds)!={'blocks','seconds'} or bounds['blocks'] is None and bounds['seconds'] is None:
            raise ValueError('declare actual maximum maturity/confirmation/recovery bounds')
        for value in bounds.values():
            if value is not None:integer(value,'declared ordinary bound',1)
    encoded=canonical(contract)
    with store.transaction():
        old=store.get_meta(KEY)
        if old is not None:
            if old!=encoded:raise ValueError('completion contract immutable; preserve failed campaign')
            return False
        if not store.get_meta('paused'):raise ValueError('declare coverage and bounds before dispatch')
        if store.db.execute("SELECT 1 FROM event WHERE kind IN ('action_dispatched','fixture_funding_intent') LIMIT 1").fetchone():
            raise ValueError('finite coverage/bounds must precede campaign actions')
        store.db.execute('INSERT INTO meta VALUES (?,?)',(KEY,encoded))
        store._event('service_completion_contract_declared',contract)
    return True


def evaluate(store,snapshot,chain,*,now=None):
    """No dispatch, no closure by timeout, no retroactive interpretation of proofs."""
    encoded=store.get_meta(KEY)
    if encoded is None:raise ValueError('predeclared finite coverage and ordinary bounds missing')
    contract=json.loads(encoded);requirements=contract['requirements']
    original=store.db.execute("SELECT payload FROM event WHERE kind='service_completion_contract_declared'").fetchall()
    if len(original)!=1 or original[0][0]!=encoded:raise ValueError('completion requirements differ from original declaration')
    final=epoch(store)
    if final is None:raise ValueError('final financial epoch missing')
    declaration=boundary(store)
    if final['pins']!=contract['pins'] or final['pins']!=declaration['pins'] or snapshot.get('financial_pins')!=final['pins']:
        raise ValueError('completion financial epoch differs')
    if (not isinstance(requirements,list) or not requirements or len(requirements)>512
            or len({r['id'] for r in requirements})!=len(requirements)):
        raise ValueError('bounded substantive finite cases required')
    now=time.time() if now is None else timestamp(now,'completion time')
    terminal={};source_events={}
    for row in store.db.execute("SELECT sequence FROM event WHERE kind='finite_scenario_terminal'"):
        event,proof=_source_event(store,row[0]);identity=proof['id']
        if identity in terminal:raise InvariantError('finite scenario has conflicting or duplicated terminal outcomes')
        if proof.get('financial_pins')!=final['pins'] or event['observed_at']<final['started_at']:
            continue
        terminal[identity]=proof;source_events[identity]=event
    missing=[]
    for requirement in requirements:
        if set(requirement)!={'id','variant','outcome','proof_kinds'} or not requirement['variant']:
            raise ValueError('explicit threat/path/state variant and expected terminal outcome required')
        expected=set(requirement['proof_kinds'])
        if not expected or expected-TERMINAL_PROOFS:raise ValueError('applicable original terminal verifier required')
        proof=terminal.get(requirement['id'])
        if proof is None:missing.append(requirement['id']);continue
        if proof.get('variant')!=requirement['variant'] or proof.get('outcome')!=requirement['outcome']:
            raise ValueError('finite result differs from declared variant/outcome')
        kinds=set()
        for sequence in proof.get('evidence_sequences',[]):
            evidence,original=_source_event(store,sequence)
            if (evidence['kind'] not in expected or original.get('financial_pins')!=final['pins']
                    or evidence['observed_at']<final['started_at'] or evidence['sequence']>=source_events[requirement['id']]['sequence']):
                raise ValueError('finite outcome lacks original applicable final-build evidence')
            kinds.add(evidence['kind'])
        if kinds!=expected:raise ValueError('finite outcome missing required terminal proof')
    unknown=[]
    for table,states in [('action',('outcome_unknown',)),
                         ('funding_batch',('broadcasting','outcome_unknown')),
                         ('seed_recovery',('preparing','prepare_unknown','broadcasting','outcome_unknown')),
                         ('actor_lease',('active','outcome_unknown')),
                         ('noah_control',('started','outcome_unknown'))]:
        if store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone():
            if store.db.execute('SELECT 1 FROM '+table+' WHERE state IN ('+','.join('?' for _ in states)+') LIMIT 1',states).fetchone():unknown.append(table)
    sequence=snapshot.get('continuing_obligations_sequence')
    if sequence is None:raise ValueError('complete continuing-money coverage missing')
    event,coverage=_source_event(store,sequence)
    if (event['kind']!='continuing_obligations_verified' or coverage.get('complete') is not True
            or coverage.get('financial_pins')!=final['pins'] or coverage.get('tip_hash')!=snapshot.get('tip_hash')
            or coverage.get('height')!=snapshot.get('height') or coverage.get('unexplained_ids')!=[]
            or not 0<=now-coverage.get('observed_at',-1)<=90):
        raise ValueError('continuing campaign has unexplained or stale money coverage')
    # Continuing work may be in flight; it must have its original exact intent,
    # dispatch identity and a predeclared recovery bound. Unknown outcomes are
    # never made ordinary by listing them here.
    pending={};maximum=contract['ordinary_bounds']['recovery']['seconds']
    for work in coverage['pending_actions']:
        if set(work)!={'action_id','intent_sequence','dispatch_sequence','deadline_at'} or work['action_id'] in pending:
            raise ValueError('unique original bounded continuing action required')
        intent_event,intent=_source_event(store,work['intent_sequence'])
        dispatch_event,dispatch=_source_event(store,work['dispatch_sequence'])
        action=store.db.execute('SELECT * FROM action WHERE id=?',(work['action_id'],)).fetchone()
        deadline=timestamp(work['deadline_at'],'continuing action recovery bound')
        if (action is None or action['state']!='dispatched' or intent_event['kind']!='action_intent'
                or dispatch_event['kind']!='action_dispatched' or intent['action_id']!=action['id']
                or dispatch['action_id']!=action['id'] or intent.get('financial_pins')!=final['pins']
                or dispatch.get('financial_pins')!=final['pins'] or intent['actor']!=action['actor_id']
                or dispatch['actor']!=action['actor_id'] or intent['operation']!=action['operation']
                or canonical(intent['args'])!=action['args'] or deadline<now
                or maximum is None or deadline>action['created_at']+maximum):
            raise ValueError('continuing client action not original, identified and within recovery bound')
        pending[action['id']]=work
    unexplained_actions=[row['id'] for row in store.db.execute("SELECT id FROM action WHERE state='dispatched'") if row['id'] not in pending]
    if unexplained_actions and 'action' not in unknown:unknown.append('action')
    assets=capture_assets(store,coverage['inventory_sequences'],chain)
    if assets['tip_hash']!=snapshot.get('tip_hash'):raise ValueError('continuing backing tip differs')
    identifiers=set();allocations={};liabilities=[]
    for obligation in coverage['liabilities']:
        if set(obligation)!={'id','owner','borrower','amount_msat','state','deadline_height','deadline_at','created_height','created_at','backing','verification_sequence'}:
            raise ValueError('identified ordinary liability and explicit recovery/maturity bounds required')
        if obligation['id'] in identifiers:raise InvariantError('same ordinary liability counted twice')
        identifiers.add(obligation['id']);amount=integer(obligation['amount_msat'],'remaining ordinary obligation',1)
        if obligation['state'] not in ORDINARY or not obligation['owner'] or obligation['borrower'] not in {m['id'] for m in declaration['members']}:
            raise ValueError('unclassified ordinary liability')
        deadline_height=obligation['deadline_height'];deadline_at=obligation['deadline_at']
        bounds=contract['ordinary_bounds'][obligation['state']]
        if bounds['blocks'] is not None and (deadline_height is None or deadline_height>integer(obligation['created_height'],'original liability height')+bounds['blocks']):
            raise ValueError('ordinary liability extends predeclared block bound')
        if bounds['seconds'] is not None and (deadline_at is None or deadline_at>timestamp(obligation['created_at'],'original liability time')+bounds['seconds']):
            raise ValueError('ordinary liability extends predeclared time bound')
        if deadline_height is None and deadline_at is None:raise ValueError('ordinary liability has no declared maturity/confirmation/recovery bound')
        if deadline_height is not None and assets['height']>integer(deadline_height,'ordinary block deadline'):
            raise ValueError('ordinary liability exceeded declared block bound')
        if deadline_at is not None and now>timestamp(deadline_at,'ordinary wall bound'):
            raise ValueError('ordinary liability exceeded declared recovery time bound')
        original_event,original=_source_event(store,obligation['verification_sequence'])
        if original_event['kind']!='ordinary_liability_verified' or original.get('financial_pins')!=final['pins'] or original.get('liability')!={k:v for k,v in obligation.items() if k!='verification_sequence'}:
            raise ValueError('ordinary liability differs from original checked allocation/bounds')
        backed=0
        for backing in obligation['backing']:
            identifier=backing['asset_id'];part=integer(backing['amount_msat'],'ordinary backing allocation',1)
            asset=assets['assets'].get(identifier)
            if asset is None or asset['member']!=obligation['borrower']:raise ValueError('ordinary liability backing is not an actual asset of its borrower')
            allocations[identifier]=allocations.get(identifier,0)+part
            if allocations[identifier]>asset['amount_msat']:raise InvariantError('physical backing overallocated across liabilities')
            backed+=part
        if backed<amount:raise ValueError('ordinary liability insufficiently backed')
        liabilities.append(obligation)
    return {'complete':not missing and not unknown,'finite_cases_terminal':len(requirements)-len(missing),
            'missing_finite_cases':missing,'unknown_client_or_controller_actions':unknown,
            'unexplained_dispatched_action_ids':unexplained_actions,'known_bounded_client_actions':list(pending.values()),'ordinary_liabilities':liabilities,'ordinary_liability_msat':sum(o['amount_msat'] for o in liabilities),
            'remaining_assets_msat':assets['total_msat'],'unexplained_money':[],
            'criterion':'Every required finite scenario reached its evidenced terminal outcome; continuing money and actions explained, ordinary liabilities identified, backed and within bounds.'}

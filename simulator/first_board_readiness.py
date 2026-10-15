"""Admission for one declared first Board from a confirmed, empty cash cohort.

This does not account for a resulting Ark tree. Any existing Board attempt holds
this producer. The pinned client enforces a TOTAL fee ceiling, not a rate cap.
"""
import hashlib
import json
import re
import time

from .final_campaign import _pins, _source_event
from .model import canonical, btc_to_sat, public_payload
from .architecture import DIRECT_PER_KEY,profile

KEY = 'finite_first_board_plan'
ACTORS = ['actor-01', 'actor-02', 'actor-04']
BALANCES = ['spendable_sat','needs_refresh_sat','pending_lightning_send_sat',
    'claimable_lightning_receive_sat','pending_in_round_sat','pending_board_sat',
    'pending_arkoor_send_sat','pending_offboard_sat','pending_exit_sat']


def _policy(store=None):
    from .c_pilot import board_policy
    return board_policy(store)


def _digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def _validate_plan(value,store=None):
    policy=_policy(store)
    if (not isinstance(value,dict) or set(value)!={'id','pins','boundary_id','board_actions','amount_sat','maximum_fee_sat'}
            or not isinstance(value['id'],str) or re.fullmatch('[a-z0-9_-]{1,100}',value['id']) is None
            or not isinstance(value['boundary_id'],str) or not value['boundary_id']
            or not isinstance(value['board_actions'],dict) or set(value['board_actions'])!=set(policy['board_actors'])
            or any(not isinstance(action,str) or not 1<=len(action)<=128 for action in value['board_actions'].values())
            or len(set(value['board_actions'].values()))!=len(policy['board_actors'])
            or type(value['amount_sat']) is not int or value['amount_sat']!=20000
            or type(value['maximum_fee_sat']) is not int or value['maximum_fee_sat']!=policy['maximum_fee_sat']):
        raise ValueError('exact bounded three-actor Board declaration required')
    _pins(value['pins']);public_payload(value)
    if 'board_action_id' in policy and value['board_actions']!={'actor-01':policy['board_action_id']}:
        raise ValueError('C original pilot Board action ID differs')
    return value


def board_plan(store):
    encoded=store.get_meta(KEY)
    if encoded is None:raise ValueError('original first Board plan missing')
    value=_validate_plan(json.loads(encoded),store)
    rows=store.db.execute("SELECT sequence FROM event WHERE kind='finite_first_board_plan_declared'").fetchall()
    if len(rows)!=1 or _source_event(store,rows[0][0])[1]!=value:
        raise ValueError('first Board plan differs from immutable original')
    return value


def declare_first_board_plan(store,value):
    """Declare three fixed IDs while paused, before any Board intent exists."""
    from .identity_bootstrap import declaration
    _validate_plan(value,store);policy=_policy(store)
    with store.transaction():
        if store.get_meta(KEY) is not None:
            if board_plan(store)!=value:raise ValueError('first Board plan is immutable')
            return False
        original=declaration(store)
        if (not store.get_meta('paused') or original is None
                or original['declaration']['pins']!=value['pins']
                or set(original['declaration']['actors'])!=set(policy['actors'])
                or store.db.execute("SELECT 1 FROM action WHERE operation='board' OR state IN ('dispatched','outcome_unknown') LIMIT 1").fetchone()
                or any(store.db.execute('SELECT 1 FROM action WHERE id=?',(action,)).fetchone() for action in value['board_actions'].values())):
            raise ValueError('pause exact original cash cohort before any Board intent')
        store.db.execute('INSERT INTO meta VALUES (?,?)',(KEY,canonical(value)))
        store._event('finite_first_board_plan_declared',value)
    return True


def validate_board_action_scope(store,proof,*,operation,maximum_fee_sat,reserved_action_id):
    """Bind the sole Engine's actual reservation; a probe cannot dispatch."""
    if 'board_action_scope' not in proof:return
    plan=board_plan(store);scope=proof['board_action_scope'];policy=_policy(store);cap=policy['maximum_fee_sat']
    if (not isinstance(scope,dict) or set(scope)!={'plan_id','action_id','actor','operation','args','maximum_fee_sat'}
            or scope['plan_id']!=plan['id'] or scope['actor'] not in policy['board_actors']
            or scope['action_id']!=plan['board_actions'][scope['actor']]
            or scope['operation']!='board' or scope['args']!={'amount_sat':20000}
            or type(scope['maximum_fee_sat']) is not int or scope['maximum_fee_sat']!=cap
            or proof.get('operation_scope')!=['board'] or proof.get('financial_pins')!=plan['pins']
            or proof.get('boundary_id')!=plan['boundary_id'] or 'client_action_scope' in proof
            or operation!='board' or type(maximum_fee_sat) is not int or maximum_fee_sat!=cap):
        raise ValueError('first Board exact action scope differs')
    # This producer admits the first attempt only. Unknown, failed or completed
    # attempts retain the hold; no regenerated ID or second actor earns credit.
    rows=store.db.execute("SELECT * FROM action WHERE operation='board'").fetchall()
    if len(rows)>1:raise ValueError('first Board scope permits only one original attempt')
    for row in rows:
        if (row['id']!=scope['action_id'] or row['actor_id']!=scope['actor']
                or json.loads(row['args'])!=scope['args'] or row['fee_reservation_sat']!=cap
                or row['state'] not in ('queued','dispatched')):
            raise ValueError('first Board original reservation differs or already attempted')
    if store.db.execute("SELECT 1 FROM action WHERE state IN ('dispatched','outcome_unknown') AND id!=? LIMIT 1",(scope['action_id'],)).fetchone():
        raise ValueError('concurrent or uncertain action holds first Board')
    if store.db.execute("SELECT 1 FROM action WHERE operation!='board' AND (state!='completed' OR actual_fee_sat IS NOT 0 OR fee_reservation_sat!=0 OR operation NOT IN ('create','sync','snapshot','address')) LIMIT 1").fetchone():
        raise ValueError('unresolved or monetary work holds first Board')
    if reserved_action_id is None:return
    if reserved_action_id!=scope['action_id'] or len(rows)!=1 or rows[0]['state']!='dispatched':
        raise ValueError('first Board dispatched original action required')
    # Authenticate the durable original intent, not only a mutable action row.
    for kind in ('action_intent','action_dispatched'):
        events=store.db.execute("SELECT sequence FROM event WHERE kind=? AND json_extract(payload,'$.action_id')=?",(kind,reserved_action_id)).fetchall()
        if len(events)!=1:raise ValueError('first Board unique original intent/dispatch required')
        _,event=_source_event(store,events[0][0])
        if (event.get('financial_pins')!=plan['pins'] or event.get('actor')!=scope['actor']
                or kind=='action_intent' and (event.get('actor')!=scope['actor'] or event.get('operation')!='board'
                    or event.get('args')!=scope['args'] or event.get('fee_reservation_sat')!=cap)):
            raise ValueError('first Board original intent context differs')


def _native(store,action,after_sequence):
    from .final_campaign import _action_pins
    if (action['state']!='completed' or action['actual_fee_sat']!=0
            or action['fee_reservation_sat']!=0 or json.loads(action['args'])!={}):
        raise ValueError('completed original fee-free native observation required')
    _action_pins(store,action['id'],board_plan(store)['pins'])
    rows=store.db.execute("SELECT sequence FROM event WHERE kind='driver_response' AND json_extract(payload,'$.action_id')=?",(action['id'],)).fetchall()
    if len(rows)!=1 or rows[0][0]<=after_sequence:raise ValueError('unique native observation after confirmed funding required')
    event,payload=_source_event(store,rows[0][0]);response=payload.get('response')
    if (response!=json.loads(action['result']) or response.get('status')!='ok'
            or response.get('action_id')!=action['id'] or response.get('actual_fee_sat')!=0):
        raise ValueError('original native response differs')
    return event,response


def verify_synced_cash_snapshots(store,source):
    """Every actual post-sync snapshot must equal independent confirmed assets."""
    result={}
    policy=_policy(store)
    for actor in policy['actors']:
        grant=policy['grants'][actor]
        rows=store.db.execute("SELECT * FROM action WHERE actor_id=? AND operation IN ('sync','snapshot') ORDER BY updated_at,id",(actor,)).fetchall()
        syncs=[row for row in rows if row['operation']=='sync']
        snapshots=[row for row in rows if row['operation']=='snapshot']
        if not syncs or not snapshots:raise ValueError('all three actual syncs and subsequent snapshots required')
        sync_event,sync=_native(store,syncs[-1],source['funding_confirmation_sequence'])
        snapshot_event,snapshot=_native(store,snapshots[-1],sync_event['sequence'])
        from .fresh_cash_readiness import _fresh
        _fresh(snapshot_event['observed_at'])
        if snapshot_event['observed_at']>source['observed_at']:
            raise ValueError('independent cash closure must follow native snapshots')
        data=sync.get('data',{})
        if (data.get('receive_count_before')!=0 or data.get('receive_count_after')!=0
                or any(data.get(field,{}).get(key)!=[] for field in ('before_evidence','evidence') for key in ('coins','movements'))):
            raise ValueError('native sync contained monetary state')
        data=snapshot.get('data',{});frame=data.get('onchain_inventory',{})
        _,inventory=_source_event(store,source['inventory_sequences'][actor])
        member=next(member for member in source['members'] if member['id']==actor)
        expected={coin['outpoint']:coin for coin in inventory['utxos']}
        if (len(expected)!=(1 if grant else 0) or sum(coin['amount_sat'] for coin in expected.values())!=grant
                or data.get('vtxos')!=[] or any(data.get('evidence',{}).get(key)!=[] for key in ('coins','movements'))
                or not isinstance(data.get('balance'),dict) or set(data['balance'])!=set(BALANCES)
                or any(type(data['balance'][key]) is not int or data['balance'][key]!=0 for key in BALANCES)
                or frame.get('schema_version')!=1 or frame.get('complete') is not True
                or frame.get('read_only') is not True or frame.get('network')!='signet'
                or (frame.get('tip_height'),frame.get('tip_hash'))!=(source['height'],source['tip_hash'])
                or [row.get('descriptor') for row in frame.get('descriptors',[])]!=member['descriptors']
                or any(frame.get(key)!=[] for key in ('pending_transactions','pending_parents','unavailable_parent_txids'))
                or not isinstance(frame.get('utxos'),list) or len(frame['utxos'])!=len(expected)):
            raise ValueError('actual empty Ark and confirmed native cash snapshot required')
        onchain=data.get('onchain')
        expected_balance={'total_sat':grant,'trusted_spendable_sat':grant,'immature_sat':0,
            'trusted_pending_sat':0,'untrusted_pending_sat':0,'confirmed_sat':grant}
        if (not isinstance(onchain,dict) or onchain!=expected_balance
                or any(type(value) is not int for value in onchain.values())):
            raise ValueError('actual native customer trusted spendable cash required')
        for coin in frame['utxos']:
            actual=expected.get(coin.get('outpoint'))
            if (actual is None or coin.get('value_sat')!=actual['amount_sat'] or coin.get('script_pubkey')!=actual['script']
                    or coin.get('keychain')!='external' or coin.get('derivation_index')!=actual['child_index']
                    or type(coin.get('confirmations')) is not int or coin['confirmations']<1
                    or coin.get('coinbase') is not False or coin.get('mature') is not True):
                raise ValueError('native confirmed coin differs from independent Core source')
        result[actor]={'sync_action_id':syncs[-1]['id'],'sync_response_sequence':sync_event['sequence'],
            'snapshot_action_id':snapshots[-1]['id'],'snapshot_response_sequence':snapshot_event['sequence'],
            'snapshot_response_sha256':_digest(snapshot)}
    return result


def record_first_board_readiness(store,config,chain,*,cash_readiness_sequence,current_startup_path,actor):
    """No dispatch: admit one fixed first Board, holding every later operation."""
    from .fresh_cash_readiness import _fresh,_phase_history,_confirmed_funding,observe_empty_client_economics
    from .operating_limits import envelope,fee_totals
    from .treasury import capture_assets
    from .runtime_startup import _read
    plan=board_plan(store);policy=_policy(store);cap=policy['maximum_fee_sat']
    if actor not in policy['board_actors']:raise ValueError('declared first Board actor required')
    event,cash=_source_event(store,cash_readiness_sequence)
    if (event['kind']!='financial_operating_readiness' or cash.get('complete') is not True
            or cash.get('operation_scope')!=['sync','snapshot','address'] or cash.get('financial_pins')!=plan['pins']
            or cash.get('boundary_id')!=plan['boundary_id'] or 'board_action_scope' in cash):
        raise ValueError('original fresh cash financial readiness required')
    _fresh(cash['observed_at']);_phase_history(store,plan['pins'],policy['actors'])
    runtime_event,runtime=_source_event(store,cash['runtime_source_sequence'])
    _,current_sha=_read(current_startup_path)
    if (runtime_event['kind']!='owned_runtime_configuration_verified'
            or runtime.get('loaded_configuration_identity_verified') is not True
            or runtime.get('current_source_sha256')!=current_sha
            or runtime.get('product_commit')!=plan['pins']['product_commit']
            or runtime.get('schema_sha256')!=plan['pins']['schema_sha256']):
        raise ValueError('original loaded runtime proof required')
    _fresh(runtime['observed_at'])
    original,initial,funded,transaction,funding_sequence=_confirmed_funding(store,chain)
    source_event,source=_source_event(store,cash['finite_fresh_cash_source_sequence'])
    if (source_event['kind']!='finite_fresh_cash_sources_verified' or source.get('financial_pins')!=plan['pins']
            or source.get('boundary_id')!=plan['boundary_id'] or source.get('funding_confirmation_sequence')!=funding_sequence):
        raise ValueError('original confirmed cash source differs')
    _fresh(source['observed_at'])
    observations=verify_synced_cash_snapshots(store,source)
    assets=capture_assets(store,source['inventory_sequences'],chain);limits=envelope(store,config)
    if (assets['total_msat']!=(policy['opening_sat']-transaction['fee_sat'])*1000
            or (assets['height'],assets['tip_hash'])!=(source['height'],source['tip_hash'])
            or fee_totals(store,plan['pins'])!={'ordinary':transaction['fee_sat']*1000,'urgent':0}
            or limits['fee_budgets_msat']!={'ordinary':60000000,'urgent':policy['urgent_budget_sat']*1000}
            or limits.get('operation_fee_paths',{}).get('board')!=['sweep','payout']
            or transaction['fee_sat']+len(policy['board_actors'])*cap+(0 if profile(store)==DIRECT_PER_KEY else 3*10000)>60000
            or cash['available_fee_funding_msat']<(60000+policy['urgent_budget_sat'])*1000-transaction['fee_sat']*1000):
        raise ValueError('first Board conserved capital or protected cumulative fee budget differs')
    client_sequence=observe_empty_client_economics(store,config)
    quote=chain.call('estimatesmartfee',3)
    rate=btc_to_sat(quote['feerate'])
    if not 1<=rate<=20000:raise ValueError('actual target-three Board quote unavailable or above observed limit')
    tip=chain.identity()
    if tip.get('initialblockdownload') is not False or (tip['blocks'],tip['bestblockhash'])!=(source['height'],source['tip_hash']):
        raise ValueError('first Board independent tip changed')
    receipt={key:value for key,value in cash.items() if key!='client_action_scope'}
    receipt.update({'observed_at':time.time(),'operation_scope':['board'],
        'cash_readiness_sequence':cash_readiness_sequence,'client_economics_sequence':client_sequence,
        'native_synced_cash_observations':observations,
        'board_action_scope':{'plan_id':plan['id'],'action_id':plan['board_actions'][actor],
            'actor':actor,'operation':'board','args':{'amount_sat':20000},'maximum_fee_sat':cap},
        'board_fee_policy':{'hard_total_fee_sat':cap,'hard_client_rate_cap_enforced':False,
            'independent_target_blocks':3,'observed_rate_sat_kvb':rate,'observed_rate_limit_sat_kvb':20000,
            'native_quote_and_actual_cost_audit_required_after_response':True},
        'ordinary_fee_holds_sat':{'funding_actual':transaction['fee_sat'],'three_board_total_fees':12000,'three_expiry_carriers':30000},
        'urgent_ring_reserve_sat':policy['urgent_budget_sat'],
        'scope':'one exact first Board only; total client fee hard-capped, rate independently observed; all subsequent money requires new accounting'})
    _fresh(cash['observed_at']);_fresh(source['observed_at'])
    if profile(store)==DIRECT_PER_KEY:
        receipt['ordinary_fee_holds_sat']={'funding_actual':transaction['fee_sat'],'one_board_total_fee_cap':1000}
    validate_board_action_scope(store,receipt,operation='board',maximum_fee_sat=cap,reserved_action_id=None)
    public_payload(receipt);store.event('financial_operating_readiness',receipt)
    return {'operating_readiness_sequence':store.db.execute('SELECT max(sequence) FROM event').fetchone()[0],**receipt}

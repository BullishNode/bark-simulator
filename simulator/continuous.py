"""Restart-safe ordinary client traffic, explicitly partial scenario coverage.

Real outcome qualification is performed by separate recipes/oracles. This
scheduler circulates existing client principal, keeps external funding declared,
and never wakes an absent actor or retries uncertainty.
"""
import json,time
from .model import InvariantError,canonical,integer
from .raw_cases import next_case
from .recycling import plan as recycle_plan
from .renewal import queue_board as queue_owner_renewal
from .realism import Rng,hazard,_transaction
from .store import ActorHeld, CampaignPaused

# These are ordinary users becoming permanently silent, separate from protocol
# attackers. The next cohort repeats the same independently seeded profiles.
RECEIVE_ABSENCE = {'actor-03':'ark','actor-06':'lightning','actor-15':'ark','actor-18':'lightning'}
LIGHTNING_CANDIDATES = ('actor-06','actor-18','actor-08','actor-07','actor-02')

def online_lightning_candidates(store):
    candidates=[]
    for actor in LIGHTNING_CANDIDATES:
        if store.actor_namespace(actor)!='ordinary' or store.actor_held(actor):continue
        row=store.db.execute('SELECT online,details FROM actor WHERE id=?',(actor,)).fetchone()
        if row and row['online']:
            detail=json.loads(row['details'])
            if detail.get('created') and detail.get('ark_address'):
                candidates.append((actor,detail))
    return candidates

def arm_receive_absence(store,actor,rail,random_context=None):
    """Stop only after a real successful receive and independent signed outputs.

    A submitted payer request, invoice, HTLC grant or positive stale balance is
    insufficient. This proves the boundary, not the eventual expiry outcome.
    No wallet, server RPC or preimage is consulted by this function.
    """
    if not store.ordinary_actor_available(actor):return False
    row=store.db.execute('SELECT online,details FROM actor WHERE id=?',(actor,)).fetchone()
    if row is None or not row['online']:return False
    if rail=='lightning' and len(online_lightning_candidates(store))<=2:return False
    detail=json.loads(row['details'])
    if detail.get('needs_sync') or not detail.get('snapshot_at'):return False
    subsystem={'ark':'bark.arkoor','lightning':'bark.lightning_receive'}[rail]
    # Live rollout freezes already observed movements. Existing receipts do
    # not retroactively become a receive-once experiment after deployment.
    seen_key='random_absence_seen_movements' if random_context else 'receive_absence_seen_movements'
    seen=json.loads(store.get_meta(seen_key) or '{}').get(actor,[])
    for row in store.db.execute('SELECT payload FROM movement_evidence WHERE actor=? ORDER BY movement_id',(actor,)):
        movement=json.loads(row['payload'])
        if movement.get('id') in seen:continue
        if (movement.get('status')!='successful' or movement.get('subsystem')!=subsystem
                or movement.get('input_vtxos') or movement.get('effective_balance_sat',0)<=0):continue
        ids=movement.get('output_vtxos',[])
        if not ids:continue
        if len(ids)!=len(set(ids)):raise InvariantError('receive has duplicate signed outputs')
        if not set(ids).issubset(detail.get('coin_ids',[])):continue
        coins=[]
        for coin_id in ids:
            coin=store.db.execute('SELECT c.id,c.amount_sat,k.actor FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey WHERE c.id=?',(coin_id,)).fetchone()
            if coin is None:break
            if coin['actor']!=actor:raise InvariantError('receive disappearance proof belongs to another owner')
            state=store.db.execute("SELECT state FROM coin_observation WHERE coin_id=? AND state!='PublicProof' ORDER BY observed_at DESC LIMIT 1",(coin_id,)).fetchone()
            if state is None or state['state']!='Spendable':break
            coins.append(coin)
        if len(coins)!=len(ids):continue
        received=sum(integer(c['amount_sat'],'signed receive amount',1) for c in coins)
        if received!=movement['effective_balance_sat']:raise InvariantError('received signed outputs differ from successful movement')
        invoice_id=None
        if rail=='lightning':
            invoice=store.db.execute("SELECT id,args FROM action WHERE actor_id=? AND operation='invoice' AND state='completed' AND json_extract(result,'$.data.payment_hash')=?",(actor,movement.get('payment_hash'))).fetchall()
            if len(invoice)!=1:continue
            invoice_id=invoice[0]['id']
            gross=integer(json.loads(invoice[0]['args'])['amount_sat'],'frozen invoice amount',1)
            fee=integer(movement['offchain_fee_sat'],'receive fee')
            if gross!=received+fee:raise InvariantError('receive principal and fee differ from frozen invoice')
        profile={'rail':rail,'movement_id':movement['id'],'coin_ids':ids,'received_sat':received,
            'invoice_action_id':invoice_id,'armed_at':time.time(),'original_wallet_must_stay_closed':True,
            'trigger':'independently verified spendable outputs of successful receive','payout_verdict':'pending'}
        if random_context:profile.update(random_context)
        with _transaction(store):
            detail['permanent_absence']=profile
            store.db.execute('UPDATE actor SET online=0,details=? WHERE id=?',(canonical(detail),actor))
            store._event('random_absence_armed' if random_context else 'receive_then_disappear_armed',{'actor':actor,**profile,
                'scenario_verdict':'not_qualified','no_client_calls_after_boundary':True})
        return True
    return False

def absence_report(store):
    result=[]
    for row in store.db.execute('SELECT id,online,details FROM actor ORDER BY id'):
        profile=json.loads(row['details']).get('permanent_absence')
        if not profile:continue
        ids=profile['coin_ids'];paid=[]
        for coin_id in ids:
            settlement=store.db.execute('SELECT coin_id,txid,actor,amount_sat FROM checked_settlement WHERE coin_id=?',(coin_id,)).fetchone()
            if settlement:
                if settlement['actor']!=row['id']:raise InvariantError('absent recipient was paid as another owner')
                paid.append(dict(settlement))
        result.append({'actor':row['id'],'online':bool(row['online']),**profile,
            'payout_verdict':'confirmed_amounts_checked' if ids and len(paid)==len(ids) else 'pending',
            'checked_settlements':paid,'waiting_coin_ids':[coin for coin in ids if coin not in {p['coin_id'] for p in paid}],
            'security_qualification':'exact sweep path, whole source arbitration and seed-only recovery are separate required gates'})
    return result

def receive_fee_block(store,actor):
    row=store.db.execute("SELECT id,state,result,actual_fee_sat,updated_at FROM action WHERE actor_id=? AND operation='sync' ORDER BY created_at DESC LIMIT 1",(actor,)).fetchone()
    if row is None or row['state']!='blocked' or row['actual_fee_sat']!=0:return None
    data=json.loads(row['result'] or '{}').get('data',{})
    if data.get('blocked') is True and data.get('reason')=='pending receive fees exceed this sync reserve':return row
    return None

def lightning_recipient(store):
    # Losing an ordinary recipient must not end the entire workload. A new
    # invoice is created on another online independently seeded existing wallet.
    for peer,detail in online_lightning_candidates(store):
        if receive_fee_block(store,peer) is not None or detail.get('needs_sync'):continue
        if store.db.execute("SELECT 1 FROM action WHERE actor_id=? AND state IN ('dispatched','outcome_unknown')",(peer,)).fetchone():continue
        # A successful bounded pass still defers full sync/mailbox adoption.
        # Preserve that receiver and its original invoices while another online
        # peer handles new traffic; partial progress is not receive readiness.
        latest=store.db.execute("SELECT state,result FROM action WHERE actor_id=? AND operation='sync' ORDER BY created_at DESC LIMIT 1",(peer,)).fetchone()
        if latest and latest['state']=='completed':
            data=json.loads(latest['result'] or '{}').get('data',{})
            if data.get('bounded_receive_sync') is True or data.get('receive_count_after',0)!=0:continue
        return peer,detail
    return None,{}

def lightning_payer(store,config,exclude=None):
    now=time.time();candidates=[]
    for row in store.db.execute('SELECT id,details FROM actor WHERE online=1'):
        actor=row['id'];detail=json.loads(row['details']);stamp=detail.get('snapshot_at',0)
        if actor==exclude or actor in {'actor-03','actor-09','actor-10'} or not store.ordinary_actor_available(actor):continue
        if detail.get('needs_sync') or not detail.get('created') or not detail.get('ark_address'):continue
        if type(stamp) not in (int,float) or not 0<=now-stamp<=180:continue
        if store.db.execute("SELECT 1 FROM action WHERE actor_id=? AND state IN ('queued','dispatched','outcome_unknown')",(actor,)).fetchone():continue
        balance=integer(detail.get('registered_spendable_sat',0),'payer balance')
        if balance>=2000+config.action_fee_reserve_sat:candidates.append((balance,actor,detail))
    if not candidates:return None,{}
    _,actor,detail=sorted(candidates,key=lambda item:(-item[0],item[1]))[0]
    return actor,detail

def queue_lightning_pair(store,config,snapshot,decisions):
    """An invoice belongs to one ready payer; unused legacy invoices stay intact."""
    from .pool_readiness import ready as pool_ready
    if not snapshot.get('capabilities',{}).get('lightning_configured') or not pool_ready(snapshot,2000):return False
    for row in store.db.execute("SELECT * FROM action WHERE operation='invoice' AND state='completed' ORDER BY created_at,id"):
        args=json.loads(row['args']);payer=args.get('planned_payer_actor')
        if not payer:continue
        if store.db.execute("SELECT 1 FROM action WHERE operation='pay_invoice' AND json_extract(args,'$.recipient_invoice_action')=?",(row['id'],)).fetchone():continue
        if time.time()-row['updated_at']>120:continue
        actor=row['actor_id']
        if not store.online(actor) or not store.ordinary_actor_available(actor):continue
        if store.db.execute("SELECT 1 FROM action WHERE actor_id=? AND state IN ('queued','dispatched','outcome_unknown')",(actor,)).fetchone():continue
        selected,_=lightning_payer(store,config,exclude=actor)
        if selected!=payer:continue
        data=json.loads(row['result'] or '{}').get('data',{})
        if not data.get('invoice') or not data.get('payment_hash'):continue
        identity=f"continuous-{store.db.execute('SELECT COUNT(*) FROM action').fetchone()[0]+1:08}"
        store.queue(identity,payer,'H40','pay_invoice',{'invoice':data['invoice'],'amount_sat':2000,
            'recipient_actor':actor,'recipient_invoice_action':row['id']},config.action_fee_reserve_sat)
        decisions[payer]={'actor':payer,'rule_id':'ready_lightning_pair','outcome':'queued','operation':'pay_invoice','inputs':{'recipient_actor':actor,'invoice_action_id':row['id']}}
        return True
    actor,detail=lightning_recipient(store)
    if not actor or detail.get('needs_sync'):return False
    latest=store.db.execute("SELECT result FROM action WHERE actor_id=? AND operation='sync' AND state='completed' ORDER BY created_at DESC,id DESC LIMIT 1",(actor,)).fetchone()
    if latest and json.loads(latest['result'] or '{}').get('data',{}).get('receive_count_after',0)!=0:return False
    recent=store.db.execute("SELECT MAX(created_at) FROM action WHERE operation='invoice' AND state!='canceled'").fetchone()[0]
    if recent and time.time()-recent<1800:return False
    payer,_=lightning_payer(store,config,exclude=actor)
    if not payer:return False
    identity=f"continuous-{store.db.execute('SELECT COUNT(*) FROM action').fetchone()[0]+1:08}"
    if store.remaining_fee_budget()<3*config.action_fee_reserve_sat:return False
    store.queue(identity,actor,'H40','invoice',{'amount_sat':2000,'planned_payer_actor':payer},config.action_fee_reserve_sat)
    decisions[actor]={'actor':actor,'rule_id':'ready_lightning_invoice','outcome':'queued','operation':'invoice','inputs':{'planned_payer_actor':payer}}
    return True

def lightning_pair_hold(store,actor):
    # Preserve a ready pair through the short invoice-to-submission window.
    # This holds ordinary scheduling only; it never overrides actor leases.
    return store.db.execute("""SELECT 1 FROM action invoice WHERE invoice.operation='invoice'
        AND invoice.state IN ('queued','dispatched','completed') AND invoice.created_at>?
        AND (invoice.actor_id=? OR json_extract(invoice.args,'$.planned_payer_actor')=?)
        AND json_type(invoice.args,'$.planned_payer_actor')='text'
        AND NOT EXISTS(SELECT 1 FROM action pay WHERE pay.operation='pay_invoice'
            AND json_extract(pay.args,'$.recipient_invoice_action')=invoice.id
            AND pay.state NOT IN ('queued','dispatched','outcome_unknown')) LIMIT 1""",
        (time.time()-120,actor,actor)).fetchone() is not None

def schedule(store,config,snapshot):
    decisions={}
    try:
        rng=Rng.configured(store,config)
        if store.get_meta('paused'):return
        hazard(store,config,rng,arm_receive_absence,online_lightning_candidates)
        slots=getattr(config,'dispatch_per_tick',1) if rng else 1
        if type(slots) is not int or not 1<=slots<=3:raise ValueError('dispatch_per_tick must be 1–3')
        if rng:
            queued=sum(store.ordinary_actor_available(r[0]) for r in store.db.execute("SELECT DISTINCT a.actor_id FROM action a JOIN actor u ON u.id=a.actor_id WHERE a.state='queued' AND u.online=1 AND a.due_at<=? AND NOT EXISTS(SELECT 1 FROM action busy WHERE busy.actor_id=a.actor_id AND busy.state IN ('dispatched','outcome_unknown'))",(time.time(),)))
            slots=max(0,slots-queued)
        for _ in range(slots):_schedule(store,config,snapshot,decisions,rng)
    except (CampaignPaused, ActorHeld):
        # A pause or direct lease can commit after our initial guard. The
        # atomic queue fence wins; retain this process and preparation jobs.
        return
    finally:
        store.event('scheduler_tick',{'actors':list(decisions.values()),
            'pause':store.get_meta('paused'),
            'runnable_queue':store.has_runnable_queue(),
            'scope':'scheduling decisions only; a queued operation is not a verified outcome'})


def _schedule(store,config,snapshot,decisions,rng=None):
    if store.get_meta('paused'):return
    if rng is None and (store.has_runnable_queue() or any(store.actor_namespace(r[0])=='ordinary' for r in store.db.execute("SELECT actor_id FROM action WHERE state='dispatched'"))):return
    from .round_adoption import queue_confirmed
    round_decisions=[]
    round_decision=queue_confirmed(store,config,snapshot,decisions=round_decisions)
    for decision in round_decisions:
        key=('round-held:'+decision['inputs']['refresh_action_id']) if decision['outcome']=='held' else decision['actor']
        decisions[key]=decision
    if round_decision and round_decision['outcome']=='queued':return
    if queue_lightning_pair(store,config,snapshot,decisions):return
    actors=store.db.execute("SELECT a.* FROM actor a WHERE online=1 ORDER BY COALESCE((SELECT MAX(updated_at) FROM action WHERE actor_id=a.id),0),a.id").fetchall()
    for actor in actors:
        name=actor['id'];d=json.loads(actor['details'])
        if store.actor_namespace(name)!='ordinary':continue
        latest={row['operation']:row['latest'] for row in store.db.execute(
            "SELECT operation,MAX(updated_at) AS latest FROM action WHERE actor_id=? AND state='completed' GROUP BY operation",(name,))}
        if any(d.get('actor')==name and d.get('reason') in {'sdk_exitability_window','sdk_input_parameters_unknown','sdk_parameters_mismatch'} for d in decisions.values()):continue
        decisions[name]={'actor':name,'rule_id':'cadence','outcome':'held','inputs':{
            'spendable':d.get('registered_spendable_sat',0),'needs_refresh':d.get('needs_refresh_sat',0),
            'onchain':d.get('onchain_confirmed_sat',0),'needs_sync':bool(d.get('needs_sync')),
            'pending_in_round':d.get('pending_in_round_sat',0),'last_sync':latest.get('sync'),
            'last_board':latest.get('board'),'budget':store.remaining_fee_budget()}}
        def decide(rule,outcome='held'):
            decisions[name]['rule_id']=rule;decisions[name]['outcome']=outcome
        if store.actor_held(name):decide('private_actor_lease');continue
        if lightning_pair_hold(store,name):decide('planned_lightning_pair');continue
        busy=store.db.execute("SELECT state FROM action WHERE actor_id=? AND state IN ('dispatched','outcome_unknown') ORDER BY CASE state WHEN 'outcome_unknown' THEN 0 ELSE 1 END LIMIT 1",(name,)).fetchone()
        if busy:decide('unknown_outcome' if busy['state']=='outcome_unknown' else 'native_inflight');continue
        if rng and store.db.execute("SELECT 1 FROM action WHERE actor_id=? AND state='queued'",(name,)).fetchone():
            decide('queued_action');continue
        rail=RECEIVE_ABSENCE.get(name)
        if rail and arm_receive_absence(store,name,rail):decide('receive_absence','offline');continue
        history=store.db.execute('SELECT * FROM action WHERE actor_id=? ORDER BY created_at DESC',(name,)).fetchall()
        if any(x['state']=='outcome_unknown' for x in history):decide('unknown_outcome');continue
        def last(operation):return max((x['updated_at'] for x in history if x['operation']==operation and x['state']=='completed'),default=0)
        def due(rule,interval,anchor):
            return rng.due(name,rule,interval,anchor,time.time()) if rng else time.time()-anchor>interval
        def queue(scenario,operation,args=None,fee=0):
            sequence=store.db.execute('SELECT COUNT(*) FROM action').fetchone()[0]+1
            if store.remaining_fee_budget()<fee:decide('fee_budget');return False
            if operation=='sync' and args is None:
                from .receive_sync import sync_args
                args=sync_args(store,name)
            store.queue(f'continuous-{sequence:08}',name,scenario,operation,args or {},fee)
            decisions[name]['outcome']='queued';decisions[name]['operation']=operation
            return True
        if not d.get('created'):
            decide('create_wallet')
            if not history or all(x['state'] not in {'failed','blocked'} for x in history):queue('H01','create')
            return
        if not d.get('ark_address'):decide('advertise_address');queue('H07','address');return
        # Leave one real broadcast board unregistered. Its frozen public coin
        # candidate can be verified after confirmation without reopening Bark.
        # An accepted SDK request alone never certifies the H04 payout outcome.
        if name in {'actor-10','actor-22'} and d.get('board_submitted') and d.get('registered_spendable_sat',0)==0:
            boards=[x for x in history if x['operation']=='board' and x['state']=='completed']
            if len(boards)==1:
                board=boards[0]
                candidates=store.db.execute('SELECT id,verified FROM client_coin_candidate WHERE actor=? AND action_id=?',
                    (name,board['id'])).fetchall()
                pending_snapshots=[x for x in history if x['operation']=='snapshot' and x['state']=='completed'
                    and x['created_at']>=board['created_at']]
                pending=(json.loads(pending_snapshots[0]['result']).get('data',{}).get('balance',{}).get('pending_board_sat',0)>0
                    if pending_snapshots else not any(x['operation']=='sync' and x['state']=='completed'
                        and x['created_at']>board['created_at'] for x in history))
                if pending_snapshots and any(x['operation']=='sync' and x['state']=='completed'
                        and x['created_at']>pending_snapshots[0]['created_at'] for x in history):
                    pending=False # A later sync could have registered the board.
                if candidates and pending:
                    decide('pending_board_absence','offline')
                    with store.transaction():
                        store.db.execute('UPDATE actor SET online=0 WHERE id=?',(name,))
                        store._event('continuous_absence_armed',{'actor':name,'scenario':'H04','board_action_id':board['id'],
                            'coin_candidates':[x['id'] for x in candidates],
                            'independent_confirmation_pending':any(not x['verified'] for x in candidates),
                            'scenario_verdict':'not_qualified','original_wallet_must_stay_closed':True})
                    continue
        # Consume only already declared, externally journaled funding. No implicit top-up.
        if d.get('needs_sync'):
            decide('sync_debt')
            blocked=receive_fee_block(store,name)
            attempted=max(last('sync'),blocked['updated_at'] if blocked else 0)
            if blocked:
                decide('receive_sync_fee_hold')
                decisions[name]['inputs']['blocked_action_id']=blocked['id']
            if time.time()-attempted>120 and queue('H01','sync',fee=config.action_fee_reserve_sat):return
            continue
        # Always read after a mutation/sync, but don't let twelve serial
        # clients' periodic reads preempt every affordable money operation.
        # The native SDK rechecks inputs and fees before any submission.
        if not d.get('snapshot_at',0):
            decide('read_after_mutation')
            queue('H01','snapshot');return
        balance=d.get('registered_spendable_sat',0)
        if name in {'actor-09','actor-10','actor-21','actor-22'} and balance>0:
            decide('registered_absence','offline');store.set_online(name,False);store.event('continuous_absence_armed',{'actor':name,'scenario':'H03','coins':d.get('coin_ids',[])})
            continue
        if queue_owner_renewal(store,name,d,config):decide('declared_owner_renewal','queued');return
        if not d.get('board_submitted') and d.get('onchain_confirmed_sat',0)>=config.board_amount_sat+config.action_fee_reserve_sat:
            decide('initial_board')
            if queue('H01','board',{'amount_sat':config.board_amount_sat},config.action_fee_reserve_sat):return
            continue
        recycle=recycle_plan(store,name,d,config)
        if recycle and store.remaining_fee_budget()>=config.action_fee_reserve_sat:
            decide('recycle_owned_source','queued')
            # One database transaction freezes source ownership and the fresh
            # action ID. Lost replies cannot release or reuse this source.
            sequence=store.db.execute('SELECT COUNT(*) FROM action').fetchone()[0]+1
            action_id=f'continuous-{sequence:08}'
            with store.transaction():
                store.queue(action_id,name,'H35','board',recycle,config.action_fee_reserve_sat)
                store._event('recycle_intent',{'actor':name,'action_id':action_id,'source':recycle['recycle_source'],
                    'board_amount_sat':recycle['amount_sat'],'fee_reserve_sat':config.action_fee_reserve_sat,
                    'new_external_funding_sat':0,'grant_reused':False,'outcome':'pending confirmed input/fee proof'})
            return
        if d.get('board_submitted') and due('periodic_sync',600,last('sync')):
            decide('periodic_sync')
            if queue('H01','sync',fee=config.action_fee_reserve_sat):return
            continue
        # Refreshable coins cannot fund a send yet. Keep their native state as
        # a scheduling input and restore spendability before the dry-wallet gate.
        # Sync debt and the read after a mutation were handled above.
        refreshable=d.get('needs_refresh_sat',0)
        if refreshable>0:
            decide('refreshable_balance')
            operation='refresh_delegated' if name in {'actor-07','actor-08'} else 'refresh'
            if queue('H20' if operation.endswith('delegated') else 'H17',operation,fee=config.action_fee_reserve_sat):return
            continue
        # A dry wallet continues observation; it is not silently topped up.
        if balance<(1 if rng else 1000)+config.action_fee_reserve_sat:
            decide('dry_wallet')
            if due('snapshot',180,d.get('snapshot_at',0)):queue('H01','snapshot');return
            continue
        if name in {'actor-11','actor-12'} and time.time()-max((x['updated_at'] for x in history if x['operation'].startswith('raw_')),default=0)>900:
            decide('negative_probe_cadence')
            count=sum(x['operation'].startswith('raw_') for x in history)
            scenario,operation,args=next_case(store,name,count);queue(scenario,operation,args);return
        # Cooperative offboard is deliberately one-shot; reboarding needs a
        # separate new principal allocation/recipe rather than an endless fee loop.
        if name=='actor-04' and not last('offboard_all'):
            decide('one_shot_offboard')
            if queue('H33','offboard_all',fee=10000):return
            continue
        # Diverse amounts/peers are deterministic from durable action history.
        sends=sum(x['operation']=='send_arkoor' for x in history)
        if due('send_arkoor',600,last('send_arkoor')):
            decide('ark_payment_cadence')
            # Rotate through every advertised peer, including the Lightning
            # sender and new cohort. Otherwise its balance only falls and LN
            # traffic stops permanently even while other clients circulate funds.
            targets=[r['id'] for r in store.db.execute('SELECT id,online,details FROM actor ORDER BY id')
                     if r['id']!=name and store.actor_namespace(r['id'])=='ordinary' and not store.actor_held(r['id']) and json.loads(r['details']).get('ark_address')
                     and (not rng or r['online'] or r['id'] in {'actor-09','actor-10'})]
            if not targets:decide('no_advertised_peer');continue
            target=rng.recipient(name,targets) if rng else targets[(int(name[-2:])+sends)%len(targets)]
            if target is None:decide('no_selected_advertised_peer');continue
            row=store.db.execute('SELECT details FROM actor WHERE id=?',(target,)).fetchone();to=json.loads(row[0]) if row else {}
            if to.get('ark_address'):
                amount=rng.amount(name,balance,config.action_fee_reserve_sat) if rng else [500,1000,1500][sends%3]
                if balance>=amount+config.action_fee_reserve_sat:
                    if queue('H08' if target in {'actor-09','actor-10'} else 'H07','send_arkoor',{'destination':to['ark_address'],'amount_sat':amount,'recipient_actor':target},config.action_fee_reserve_sat):return
        if due('snapshot',180,d.get('snapshot_at',0)):
            decide('periodic_snapshot')
            queue('H01','snapshot');return

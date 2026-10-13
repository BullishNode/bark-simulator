"""Declared own confirmed receipt -> board cycles, never new funding credit.

Only independently checked collaborative exits or fallback outputs qualify.
The driver spends precisely the frozen source, and confirmed Core evidence
closes the cycle. Permanent absence and uncertain requests never recycle.
"""
import asyncio,json,time
from .model import InvariantError,integer,btc_to_sat,canonical

def sources(store):
    result={}
    for row in store.db.execute("SELECT payload FROM event WHERE kind='client_fee_reconciled'"):
        p=json.loads(row[0]);a=store.db.execute("SELECT actor_id,operation,result FROM action WHERE id=?",(p['action_id'],)).fetchone()
        if not a or a['operation']!='offboard_all' or not p.get('chain_transaction'):continue
        d=json.loads(a['result'])['data'];tx=p['chain_transaction']
        if tx.get('confirmations',0)<1:continue
        outputs=[o for o in tx['outputs'] if o['script']==d['destination_script']]
        if len(outputs)!=1 or outputs[0]['amount_sat']!=p['net_sat']:raise InvariantError('recycle exit differs from reconciled output')
        o=outputs[0];outpoint=tx['txid']+':'+str(o['vout'])
        result[outpoint]={'actor':a['actor_id'],'outpoint':outpoint,'script':o['script'],'amount_sat':o['amount_sat'],
            'kind':'confirmed_own_collaborative_exit','source_action_id':p['action_id']}
    for row in store.db.execute('SELECT actor,script,txid FROM checked_settlement GROUP BY actor,script,txid'):
        chain=store.db.execute('SELECT payload FROM chain_payout WHERE txid=?',(row['txid'],)).fetchone()
        if not chain:continue
        tx=json.loads(chain[0])
        if tx.get('confirmations',0)<1:continue
        outputs=[o for o in tx['outputs'] if o['script']==row['script']]
        if len(outputs)!=1:raise InvariantError('recycle fallback output is ambiguous')
        if not store.db.execute('SELECT 1 FROM owner_record WHERE actor=? AND script=?',(row['actor'],row['script'])).fetchone():raise InvariantError('recycle fallback script lacks owner binding')
        o=outputs[0];outpoint=tx['txid']+':'+str(o['vout'])
        result[outpoint]={'actor':row['actor'],'outpoint':outpoint,'script':o['script'],'amount_sat':o['amount_sat'],
            'kind':'confirmed_own_fallback','source_action_id':None}
    return result

def claimed(store,outpoint):
    return store.db.execute("SELECT 1 FROM event WHERE kind='recycle_intent' AND json_extract(payload,'$.source.outpoint')=?",(outpoint,)).fetchone() is not None

async def collect(store,chain,limit=2):
    candidates=[]
    for outpoint,source in sources(store).items():
        if not store.ordinary_actor_available(source['actor']):continue
        actor=store.db.execute('SELECT online,details FROM actor WHERE id=?',(source['actor'],)).fetchone()
        if not actor or not actor['online'] or json.loads(actor['details']).get('permanent_absence') or claimed(store,outpoint):continue
        candidates.append((outpoint,source))
    after=store.get_meta('recycle_source_cursor') or ''
    candidates=sorted(candidates);candidates=[x for x in candidates if x[0]>after]+[x for x in candidates if x[0]<=after]
    for outpoint,source in candidates[:limit]:
        try:
            await asyncio.to_thread(chain.identity)
            txid,vout=outpoint.split(':');utxo=await asyncio.to_thread(chain.call,'gettxout',txid,int(vout),True)
            if utxo and utxo.get('confirmations',0)>=1:
                if btc_to_sat(utxo['value'])!=source['amount_sat'] or utxo['scriptPubKey']['hex']!=source['script']:raise InvariantError('confirmed recycle source changed amount or destination')
                value={**source,'confirmations':utxo['confirmations'],'checked_at':time.time(),'status':'unspent'}
                previous=json.loads(store.get_meta('recycle_verified:'+outpoint) or 'null')
                unchanged=previous is not None and {k:v for k,v in previous.items() if k!='checked_at'}=={k:v for k,v in value.items() if k!='checked_at'}
                if not unchanged:store.event('recycle_source_unspent_verified',value)
                store.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)",('recycle_verified:'+outpoint,canonical(value)))
            else:
                # Invalidate the fresh cache immediately; old append-only
                # observations cannot override a newer spent/unavailable result.
                store.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)",('recycle_verified:'+outpoint,canonical({**source,'status':'unavailable_or_spent','checked_at':time.time()})))
        except InvariantError:raise
        except Exception:
            store.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)",('recycle_verified:'+outpoint,canonical({**source,'status':'unavailable','checked_at':time.time()})))
        store.db.execute("INSERT OR REPLACE INTO meta VALUES ('recycle_source_cursor',?)",(outpoint,))
    reconcile(store)

def board_cost_estimate(store,actor):
    rows=store.db.execute("""SELECT e.payload FROM event e JOIN action a
        ON a.id=json_extract(e.payload,'$.action_id')
        WHERE e.kind='client_fee_reconciled' AND a.actor_id=? AND a.operation='board'
        ORDER BY e.sequence DESC""",(actor,)).fetchall()
    for row in rows:
        value=json.loads(row[0])
        if value.get('chain_transaction',{}).get('confirmations',0)<1:continue
        service=integer(value['service_charge_sat'],'observed board service fee')
        mining=integer(value['mining_fee_sat'],'observed board mining fee')
        return {'fee_sat':service+mining,'service_sat':service,'mining_sat':mining,
                'source_action_id':value['action_id'],'basis':'confirmed native board cost'}
    # Independently audited v18 signet baseline, explicitly a planning estimate.
    # Native preparation requotes exact service/mining before any signing.
    return {'fee_sat':483,'service_sat':330,'mining_sat':153,
            'source_action_id':None,'basis':'audited campaign baseline; exact native quote still required'}


def plan(store,actor,detail,config):
    if not store.ordinary_actor_available(actor):return None
    if not detail.get('board_submitted') or detail.get('needs_sync') or detail.get('permanent_absence'):return None
    # Unknown wallet state remains held. Independently observed unrelated live
    # Ark coins do not prevent a source-only on-chain board.
    live=[]
    for coin in detail.get('coin_ids',[]):
        state=store.db.execute("SELECT state FROM coin_observation WHERE coin_id=? AND state!='PublicProof' ORDER BY observed_at DESC LIMIT 1",(coin,)).fetchone()
        if not state:return None
        if state[0] not in {'Spent','Exited','Offboarded'}:
            proof=store.db.execute('SELECT proof FROM owned_coin WHERE id=?',(coin,)).fetchone()
            if not proof:return None
            live.append(json.loads(proof[0]))
    sources_by_id={}
    for row in store.db.execute("SELECT payload FROM event WHERE kind='recycle_source_unspent_verified' AND json_extract(payload,'$.actor')=? ORDER BY sequence DESC",(actor,)):
        source=json.loads(row[0]);sources_by_id.setdefault(source['outpoint'],source)
    for row in store.db.execute("SELECT value FROM meta WHERE key LIKE 'recycle_verified:%'"):
        source=json.loads(row[0])
        if source['actor']==actor:sources_by_id[source['outpoint']]=source
    quote=board_cost_estimate(store,actor)
    for outpoint,source in sources_by_id.items():
        if source.get('status','unspent')!='unspent' or claimed(store,outpoint) or source.get('confirmations',0)<1 or not 0<=time.time()-source['checked_at']<=120:continue
        if any(outpoint in step.get('inputs',[]) for proof in live for step in proof.get('path',[])):continue
        available=min(integer(detail.get('onchain_confirmed_sat',0),'own confirmed balance'),integer(source['amount_sat'],'confirmed recycle source',1))
        amount=min(config.board_amount_sat,available-quote['fee_sat'])
        minimum_principal=1000+config.action_fee_reserve_sat
        if quote['fee_sat']>config.action_fee_reserve_sat or amount<minimum_principal:
            if not store.db.execute("SELECT 1 FROM event WHERE kind='recycle_fee_exhaustion' AND json_extract(payload,'$.outpoint')=?",(outpoint,)).fetchone():
                store.event('recycle_fee_exhaustion',{'actor':actor,'outpoint':outpoint,'confirmed_source_sat':source['amount_sat'],
                    'confirmed_wallet_sat':detail.get('onchain_confirmed_sat',0),'fee_reserve_sat':config.action_fee_reserve_sat,
                    'minimum_new_ark_principal_sat':minimum_principal,'fee_estimate':quote,
                    'source_remains_in_own_bip84_wallet':True,'funding_injected_sat':0,
                    'reason':'source minus estimated cost is below principal floor or quote exceeds hard fee ceiling; no source combining'})
            continue
        return {'amount_sat':amount,'minimum_ark_amount_sat':minimum_principal,'recycle_source':source,
                'recycle_autosize':True,'board_cap_sat':config.board_amount_sat,'recycle_fee_estimate':quote}
    return None

def reconcile(store):
    for row in store.db.execute("SELECT payload FROM event WHERE kind='recycle_intent'"):
        p=json.loads(row[0]);action=p['action_id']
        if store.db.execute("SELECT 1 FROM event WHERE kind='recycle_confirmed' AND json_extract(payload,'$.action_id')=?",(action,)).fetchone():continue
        fee=store.db.execute("SELECT payload FROM event WHERE kind='client_fee_reconciled' AND json_extract(payload,'$.action_id')=?",(action,)).fetchall()
        if not fee:continue
        if len(fee)!=1:raise InvariantError('recycle board has duplicate fee proofs')
        f=json.loads(fee[0][0]);tx=f['chain_transaction'];source=p['source']
        if tx.get('confirmations',0)<1:continue
        if len(tx['inputs'])!=1 or tx['inputs'][0]['outpoint']!=source['outpoint'] or tx['inputs'][0]['amount_sat']!=source['amount_sat'] or tx['inputs'][0]['script']!=source['script']:raise InvariantError('recycle board did not spend precisely its frozen own receipt')
        action_row=store.db.execute('SELECT args FROM action WHERE id=?',(action,)).fetchone()
        args=json.loads(action_row[0]) if action_row else {}
        funded=p['board_amount_sat']
        if args.get('recycle_autosize') is True:
            funded=integer(f['funded_amount_sat'],'independently reconciled exact board output',1)
            if funded>args['board_cap_sat']:raise InvariantError('recycle board exceeds frozen cap')
        principal=funded-f['service_charge_sat'];change=sum(o['amount_sat'] for o in tx['outputs'])-funded
        minimum=1000+p['fee_reserve_sat']
        if change<0 or f['service_charge_sat']+f['mining_fee_sat']>p['fee_reserve_sat'] or principal<minimum or source['amount_sat']!=principal+f['service_charge_sat']+f['mining_fee_sat']+change:raise InvariantError('recycle principal/fees/change do not conserve confirmed receipt')
        store.event('recycle_confirmed',{'actor':p['actor'],'action_id':action,'source':source,'board_txid':tx['txid'],
            'new_ark_principal_sat':principal,'service_fee_sat':f['service_charge_sat'],'mining_fee_sat':f['mining_fee_sat'],
            'own_onchain_change_sat':change,'external_injection_sat':0,'source_credit_count':1,
            'scope':'confirmed own receipt spent once, principal+service+mining+own change conserve; full operator treasury is separate'})

def report(store):
    return {kind:[json.loads(r[0]) for r in store.db.execute('SELECT payload FROM event WHERE kind=? ORDER BY sequence',(kind,))]
        for kind in ['recycle_intent','recycle_confirmed','recycle_fee_exhaustion']}

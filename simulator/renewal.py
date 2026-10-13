"""Separately declared owner allocations, never recycled capital.

Original initial/ramp grants are immutable. This uses one independently
confirmed new owner receipt, frozen recipients and one durable transaction.
Unknown broadcasts pause dispatch and are queried, never regenerated.
"""
import json,re,time
from decimal import Decimal
from .model import InvariantError,SIGNET_GENESIS,btc_to_sat,canonical,integer
from .funding import WalletRpc

TRANCHE='owner-renewal-2026-10-11-1'
TRAFFIC_TRANCHE='owner-renewal-2026-10-12-traffic-2'
PAUSE='owner renewal funding outcome uncertain'
REGTEST_GENESIS='0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206'

def eligible(store,config):
    result=[]
    for row in store.db.execute('SELECT id,online,details FROM actor ORDER BY id'):
        actor=row['id'];d=json.loads(row['details'])
        if not store.ordinary_actor_available(actor):continue
        if actor not in {f'actor-{i:02}' for i in range(1,13) if i not in (9,10)} or not row['online'] or d.get('permanent_absence'):continue
        if not d.get('created') or not d.get('board_submitted') or d.get('needs_sync') or not 0<=time.time()-d.get('snapshot_at',0)<=600:continue
        if d.get('registered_spendable_sat',0)>=1000+config.action_fee_reserve_sat or d.get('onchain_confirmed_sat',0)>=config.board_amount_sat+config.action_fee_reserve_sat:continue
        address=d.get('funding_address')
        prefix='bcrt1q' if getattr(config,'network','signet')=='regtest' else 'tb1q'
        if not isinstance(address,str) or not address.startswith(prefix):raise InvariantError('renewal actor lacks original verified funding address')
        result.append({'actor':actor,'address':address,'amount_sat':8000})
    if len({r['address'] for r in result})!=len(result):raise InvariantError('renewal funding addresses repeat')
    return result

def _key(name,tranche):
    if tranche not in {TRANCHE,TRAFFIC_TRANCHE}:raise InvariantError('undeclared owner allocation identity')
    return name if tranche==TRANCHE else name+':'+tranche

def _pause(tranche):return PAUSE if tranche==TRANCHE else PAUSE+' '+tranche

def _traffic_declaration(declaration):
    fields={'tranche_id','maximum_principal_sat','maximum_actor_grant_sat','maximum_mining_fee_sat','maximum_batches','funding_wallet','source','recipients'}
    if set(declaration)!=fields:raise InvariantError('owner allocation requires exact source, wallet and recipients')
    for name,expected in [('maximum_principal_sat',86800),('maximum_actor_grant_sat',13200),('maximum_mining_fee_sat',2000),('maximum_batches',1)]:
        if integer(declaration[name],name,1)!=expected:raise InvariantError('owner allocation fixed cap changed')
    if declaration['funding_wallet']!='abandon-simulator-funding':raise InvariantError('owner allocation funding wallet changed')
    source=declaration['source']
    if (not isinstance(source,dict) or set(source)!={'outpoint','script','amount_sat'}
            or not isinstance(source['outpoint'],str) or re.fullmatch(r'[0-9a-f]{64}:\d+',source['outpoint']) is None
            or not isinstance(source['script'],str) or re.fullmatch(r'(?:[0-9a-f]{2}){1,10000}',source['script']) is None):raise InvariantError('owner allocation source is malformed')
    index=source['outpoint'].split(':')[1]
    if str(int(index))!=index or int(index)>4294967295:raise InvariantError('owner source requires a canonical output index')
    integer(source['amount_sat'],'owner allocation source value',1)
    recipients=declaration['recipients'];allowed={f'actor-{i:02}' for i in (1,2,4,5,6,7,8,11,12)}
    if not isinstance(recipients,list) or not 1<=len(recipients)<=9:raise InvariantError('owner allocation needs bounded frozen recipients')
    for recipient in recipients:
        if not isinstance(recipient,dict) or set(recipient)!={'actor','address','amount_sat','minimum_ark_amount_sat'}:raise InvariantError('owner allocation recipient fields changed')
        actor=recipient['actor']
        if actor not in allowed or not isinstance(recipient['address'],str) or not recipient['address'].startswith(('tb1q','bcrt1q')):raise InvariantError('owner allocation includes an absent actor or unsupported destination')
        amount,minimum=(13200,12000) if actor=='actor-05' else (9200,8000)
        if integer(recipient['amount_sat'],'owner grant',1)!=amount or integer(recipient['minimum_ark_amount_sat'],'minimum Ark principal',1)!=minimum:raise InvariantError('owner allocation grant or net floor changed')
    if len({r['actor'] for r in recipients})!=len(recipients) or len({r['address'] for r in recipients})!=len(recipients):raise InvariantError('owner allocation recipients repeat')
    prefixes={r['address'].split('1',1)[0] for r in recipients}
    if len(prefixes)!=1:raise InvariantError('owner allocation mixes destination networks')
    total=sum(r['amount_sat'] for r in recipients)
    if total>86800 or source['amount_sat']<total+2000:raise InvariantError('one owner source cannot fund declared recipients and full mining cap')

def declare(store,declaration):
    tranche=declaration['tranche_id'];key=_key('owner_renewal_declaration',tranche)
    if tranche==TRANCHE:
        assert (declaration['maximum_principal_sat'],declaration['maximum_actor_grant_sat'],declaration['maximum_mining_fee_sat'],declaration['maximum_batches'])==(80000,8000,2000,1)
    else:_traffic_declaration(declaration)
    encoded=canonical(declaration);old=store.get_meta(key)
    if old is not None and old!=encoded:raise InvariantError('renewal declaration changed')
    if old is None:
        with store.transaction():
            store.db.execute('INSERT INTO meta VALUES (?,?)',(key,encoded))
            store._event('owner_renewal_declared',declaration)

def _declaration(store,tranche):
    raw=store.get_meta(_key('owner_renewal_declaration',tranche))
    if raw is None:return None
    declaration=json.loads(raw)
    if declaration.get('tranche_id')!=tranche:raise InvariantError('owner allocation identity changed')
    if tranche==TRAFFIC_TRANCHE:
        _traffic_declaration(declaration)
        rows=store.db.execute("SELECT payload FROM event WHERE kind='owner_renewal_declared' AND json_extract(payload,'$.tranche_id')=?",(tranche,)).fetchall()
        if len(rows)!=1 or json.loads(rows[0][0])!=declaration:raise InvariantError('owner allocation differs from its immutable declaration event')
    return declaration

def _present(store,actor,detail):
    if not store.ordinary_actor_available(actor):return False
    row=store.db.execute('SELECT online FROM actor WHERE id=?',(actor,)).fetchone()
    hazard=json.loads(store.get_meta('realism_hazards') or '{}').get(actor,{})
    return bool(row and row[0] and actor not in {'actor-03','actor-09','actor-10'} and not detail.get('permanent_absence')
        and not detail.get('scheduled_silence_profile') and not hazard.get('pending'))

def _traffic_recipients(store,config,declaration):
    if config.action_fee_reserve_sat!=2000 or config.funding_wallet!=declaration['funding_wallet']:raise InvariantError('owner allocation wallet or board fee ceiling changed')
    prefix='bcrt1q' if getattr(config,'network','signet')=='regtest' else 'tb1q'
    for recipient in declaration['recipients']:
        row=store.db.execute('SELECT details FROM actor WHERE id=?',(recipient['actor'],)).fetchone()
        if not row:return None
        detail=json.loads(row[0])
        if not _present(store,recipient['actor'],detail) or not detail.get('created'):return None
        if detail.get('funding_address')!=recipient['address'] or not recipient['address'].startswith(prefix):return None
        if store.db.execute("SELECT 1 FROM action WHERE actor_id=? AND (state IN ('dispatched','outcome_unknown') OR (state='queued' AND operation NOT IN ('snapshot','address')))",(recipient['actor'],)).fetchone():return None
    return declaration['recipients']

def _allocated(store,rpc,source,tranche):
    for row in store.db.execute("SELECT payload FROM event WHERE kind='owner_renewal_allocation_intent'"):
        prior=json.loads(row[0])
        if prior.get('tranche')!=tranche and prior.get('source',{}).get('outpoint')==source['outpoint']:return True
    for row in store.db.execute('SELECT id,raw_tx FROM funding_batch WHERE id!=?',(tranche,)):
        if not row['raw_tx']:continue
        tx=rpc.call('decoderawtransaction',row['raw_tx'],root=True)
        if any(i.get('txid','')+':'+str(i.get('vout'))==source['outpoint'] for i in tx['vin']):return True
    return False

def _traffic_source(store,rpc,declaration):
    source=declaration['source'];tranche=declaration['tranche_id']
    if getattr(rpc,'wallet',declaration['funding_wallet'])!=declaration['funding_wallet']:raise InvariantError('owner source RPC uses another funding wallet')
    if _allocated(store,rpc,source,tranche):return 'held_source_allocated'
    txid,index=source['outpoint'].split(':');index=int(index)
    rows=rpc.call('listunspent',1,9999999,[],False,{'maximumCount':10000})
    matches=[r for r in rows if r.get('txid')==txid and r.get('vout')==index]
    if len(matches)!=1:return 'held_source_unavailable'
    own=matches[0]
    if (type(own.get('confirmations')) is not int or own['confirmations']<1 or own.get('spendable') is not True
            or own.get('solvable') is not True or own.get('safe') is not True):return 'held_source_unavailable'
    if btc_to_sat(own['amount'])!=source['amount_sat'] or own['scriptPubKey']!=source['script']:raise InvariantError('frozen owner source differs from wallet unspent evidence')
    ownership=rpc.call('getaddressinfo',own['address'])
    if ownership.get('ismine') is not True:return 'held_source_ownership'
    if ownership.get('scriptPubKey')!=source['script']:raise InvariantError('wallet-owned source script changed')
    unspent=rpc.call('gettxout',txid,index,True,root=True)
    if not unspent or unspent.get('confirmations',0)<1:return 'held_source_unavailable'
    raw=rpc.call('getrawtransaction',txid,True,root=True)
    output=raw['vout'][index]
    if (raw.get('txid')!=txid or output.get('n')!=index or btc_to_sat(output['value'])!=source['amount_sat']
            or output['scriptPubKey']['hex']!=source['script'] or btc_to_sat(unspent['value'])!=source['amount_sat']
            or unspent['scriptPubKey']['hex']!=source['script']):raise InvariantError('owner source differs from exact confirmed chain output')
    return None

def _prepared(store,row,source,tranche):
    if tranche!=TRAFFIC_TRANCHE:return
    proof=store.db.execute("SELECT payload FROM event WHERE kind='owner_renewal_prepared' AND json_extract(payload,'$.tranche')=?",(tranche,)).fetchall()
    if len(proof)!=1:raise InvariantError('owner allocation lacks unique frozen prepared evidence')
    frozen=json.loads(proof[0][0])
    if (frozen.get('source')!=source or frozen.get('txid')!=row['txid'] or frozen.get('raw_tx')!=row['raw_tx']
            or frozen.get('fee_sat')!=row['fee_sat']):raise InvariantError('owner allocation prepared bytes or source changed')

def _validate_outputs(rpc,tx,recipients,source):
    txid,index=source['outpoint'].split(':')
    if len(tx['vin'])!=1 or tx['vin'][0].get('txid')!=txid or tx['vin'][0].get('vout')!=int(index):raise InvariantError('renewal did not spend precisely its declared owner injection')
    expected={r['address']:r['amount_sat'] for r in recipients};seen={};change=0;outputs={}
    for o in tx['vout']:
        address=o['scriptPubKey'].get('address');value=btc_to_sat(o['value'])
        if address in expected:
            if address in seen or value!=expected[address]:raise InvariantError('renewal recipient amount duplicated or changed')
            seen[address]=value;outputs[address]={'outpoint':tx['txid']+':'+str(o['n']),'script':o['scriptPubKey']['hex'],'amount_sat':value}
        else:
            if not address or not rpc.call('getaddressinfo',address).get('ismine'):raise InvariantError('renewal change belongs to someone else')
            change+=1
    if seen!=expected or change>1:raise InvariantError('renewal recipient set changed')
    fee=source['amount_sat']-sum(btc_to_sat(o['value']) for o in tx['vout'])
    if not 0<=fee<=2000:raise InvariantError('renewal actual mining fee outside fixed cap')
    return fee,outputs

def fund(store,rpc,config,tranche_id=TRANCHE):
    declaration=_declaration(store,tranche_id)
    if declaration is None:return {'state':'not_declared'}
    network=getattr(config,'network','signet')
    if network not in {'signet','regtest'}:raise InvariantError('renewal permits only signet or isolated regtest')
    genesis=SIGNET_GENESIS if network=='signet' else REGTEST_GENESIS
    if rpc.call('getblockhash',0,root=True)!=genesis:raise InvariantError('renewal chain mismatch')
    if rpc.call('getblockchaininfo',root=True)['initialblockdownload']:return {'state':'held_core_sync'}
    store.db.execute('CREATE TABLE IF NOT EXISTS funding_batch(id TEXT PRIMARY KEY,state TEXT NOT NULL,recipients TEXT NOT NULL,txid TEXT,raw_tx TEXT,fee_sat INTEGER,updated_at REAL NOT NULL)')
    old=store.db.execute('SELECT * FROM funding_batch WHERE id=?',(tranche_id,)).fetchone()
    if old and old['state'] in {'broadcasting','outcome_unknown','broadcast','confirmed'}:
        return reconcile(store,rpc,old)
    if store.get_meta('paused') or store.db.execute("SELECT 1 FROM action WHERE state IN ('dispatched','outcome_unknown')").fetchone():return {'state':'held_uncertainty'}
    if store.db.execute("SELECT 1 FROM funding_batch WHERE id!=? AND state IN ('broadcasting','outcome_unknown')",(tranche_id,)).fetchone():return {'state':'held_funding_uncertainty'}
    if old is None:
        recipients=_traffic_recipients(store,config,declaration) if tranche_id==TRAFFIC_TRANCHE else eligible(store,config)
        if recipients is None:return {'state':'held_recipient_change','broadcast':False}
        if not recipients:return {'state':'no_eligible_online_clients'}
        total=sum(r['amount_sat'] for r in recipients)
        if total>declaration['maximum_principal_sat']:raise InvariantError('renewal principal cap exceeded')
        if tranche_id==TRAFFIC_TRANCHE:
            held=_traffic_source(store,rpc,declaration)
            if held:return {'state':held,'broadcast':False}
            source=declaration['source']
        else:
            source=None
            for injection in declaration['sources']:
                # An independently recorded actual owner receipt is required;
                # unrelated old funding-wallet balances never qualify.
                receipt=store.db.execute("SELECT payload FROM event WHERE kind='external_owner_injection_observed' AND json_extract(payload,'$.txid')=?",(injection['txid'],)).fetchone()
                if not receipt:continue
                verified=json.loads(receipt[0])
                for output in injection['outputs']:
                    if output not in verified['owned_outputs']:raise InvariantError('renewal source differs from independently observed owner receipt')
                    txid,index=output['outpoint'].split(':');utxo=rpc.call('gettxout',txid,int(index),True,root=True)
                    if not utxo or utxo.get('confirmations',0)<1 or output['amount_sat']<total+2000:continue
                    if btc_to_sat(utxo['value'])!=output['amount_sat'] or utxo['scriptPubKey']['hex']!=output['script']:raise InvariantError('owner injection UTXO changed')
                    source=output;break
                if source:break
            if source is None:return {'state':'no_confirmed_unallocated_owner_receipt'}
        with store.transaction():
            store.db.execute("INSERT INTO funding_batch VALUES (?,'intent',?,NULL,NULL,NULL,?)",(tranche_id,canonical(recipients),time.time()))
            store.db.execute('INSERT INTO meta VALUES (?,?)',(_key('owner_renewal_funding_source',tranche_id),canonical(source)))
            store._event('owner_renewal_allocation_intent',{'tranche':tranche_id,'recipients':recipients,'source':source,'principal_sat':total,'maximum_fee_sat':2000,'classification':'new owner-funded test allocation','recycling_credit_sat':0,'traffic_credit_seconds':0,'original_initial_ramp_budgets_unchanged':True})
        old=store.db.execute('SELECT * FROM funding_batch WHERE id=?',(tranche_id,)).fetchone()
    source=json.loads(store.get_meta(_key('owner_renewal_funding_source',tranche_id)));recipients=json.loads(old['recipients'])
    if any(not store.ordinary_actor_available(r['actor']) for r in recipients):return {'state':'held_recipient_change','broadcast':False}
    if tranche_id==TRAFFIC_TRANCHE:
        if source!=declaration['source'] or recipients!=declaration['recipients']:raise InvariantError('frozen owner source or recipient set changed')
        if _traffic_recipients(store,config,declaration)!=recipients:return {'state':'held_recipient_change','broadcast':False}
        held=_traffic_source(store,rpc,declaration)
        if held:return {'state':held,'broadcast':False}
    else:
        eligible_actors={r['actor']:r for r in eligible(store,config)}
        if any(eligible_actors.get(r['actor'])!=r for r in recipients):return {'state':'held_recipient_change','broadcast':False}
    if old['state']=='intent':
        txid,index=source['outpoint'].split(':')
        outputs=[{r['address']:str(Decimal(r['amount_sat'])/100000000)} for r in recipients]
        prepared=rpc.call('walletcreatefundedpsbt',[{'txid':txid,'vout':int(index)}],outputs,0,{'fee_rate':'3','lockUnspents':False,'add_inputs':False})
        if btc_to_sat(prepared['fee'])>2000:return {'state':'held_fee_cap','broadcast':False}
        if tranche_id==TRAFFIC_TRANCHE:
            unsigned=rpc.call('decodepsbt',prepared['psbt'])['tx']
            fee,_=_validate_outputs(rpc,unsigned,recipients,source)
            if fee!=btc_to_sat(prepared['fee']):raise InvariantError('owner allocation unsigned fee changed before signing')
        if any(not store.ordinary_actor_available(r['actor']) for r in recipients):return {'state':'held_recipient_change','broadcast':False}
        signed=rpc.call('walletprocesspsbt',prepared['psbt']);final=rpc.call('finalizepsbt',signed['psbt'])
        if final.get('complete') is not True:return {'state':'held_incomplete_signature','broadcast':False}
        raw=final['hex'];tx=rpc.call('decoderawtransaction',raw,root=True);fee,_=_validate_outputs(rpc,tx,recipients,source)
        if fee!=btc_to_sat(prepared['fee']):raise InvariantError('renewal quoted fee differs from exact inputs and outputs')
        with store.transaction():
            store.db.execute("UPDATE funding_batch SET state='prepared',txid=?,raw_tx=?,fee_sat=?,updated_at=? WHERE id=?",(tx['txid'],raw,fee,time.time(),tranche_id))
            store._event('owner_renewal_prepared',{'tranche':tranche_id,'source':source,'txid':tx['txid'],'raw_tx':raw,'principal_sat':sum(r['amount_sat'] for r in recipients),'fee_sat':fee,'recycling_credit_sat':0})
        old=store.db.execute('SELECT * FROM funding_batch WHERE id=?',(tranche_id,)).fetchone()
    if tranche_id==TRAFFIC_TRANCHE:
        _prepared(store,old,source,tranche_id)
        if _traffic_recipients(store,config,declaration)!=recipients:return {'state':'held_recipient_change','broadcast':False}
        held=_traffic_source(store,rpc,declaration)
        if held:return {'state':held,'broadcast':False}
    if any(not store.ordinary_actor_available(r['actor']) for r in recipients):return {'state':'held_recipient_change','broadcast':False}
    with store.transaction():
        if any(not store.ordinary_actor_available(r['actor']) for r in recipients):return {'state':'held_recipient_change','broadcast':False}
        store.db.execute("UPDATE funding_batch SET state='broadcasting',updated_at=? WHERE id=?",(time.time(),tranche_id))
        store._event('owner_renewal_broadcast_intent',{'tranche':tranche_id,'txid':old['txid']})
    try:
        returned=rpc.call('sendrawtransaction',old['raw_tx'],root=True)
        if returned!=old['txid']:raise InvariantError('renewal broadcast returned another transaction')
        state='broadcast'
    except Exception:state='outcome_unknown'
    with store.transaction():
        store.db.execute('UPDATE funding_batch SET state=?,updated_at=? WHERE id=?',(state,time.time(),tranche_id))
        if state=='outcome_unknown':store.db.execute("INSERT OR REPLACE INTO meta VALUES ('paused',?)",(_pause(tranche_id),))
        store._event('owner_renewal_funding_result',{'tranche':tranche_id,'txid':old['txid'],'state':state,'fee_sat':old['fee_sat'],'retry_allowed':False})
    return {'state':state,'txid':old['txid'],'retry_allowed':False}

def reconcile(store,rpc,row):
    tranche_id=row['id'];declaration=_declaration(store,tranche_id)
    if tranche_id==TRAFFIC_TRANCHE:
        genesis=REGTEST_GENESIS if declaration['recipients'][0]['address'].startswith('bcrt1q') else SIGNET_GENESIS
        if rpc.call('getblockhash',0,root=True)!=genesis:raise InvariantError('owner allocation reconciliation chain changed')
    if row['state']=='confirmed':return {'state':'confirmed','txid':row['txid']}
    try:tx=rpc.call('getrawtransaction',row['txid'],True,root=True)
    except Exception:return {'state':'outcome_unknown','txid':row['txid'],'retry_allowed':False}
    source=json.loads(store.get_meta(_key('owner_renewal_funding_source',tranche_id)));recipients=json.loads(row['recipients'])
    if tranche_id==TRAFFIC_TRANCHE and (source!=declaration['source'] or recipients!=declaration['recipients']):raise InvariantError('frozen allocation differs during reconciliation')
    if tx['txid']!=row['txid']:raise InvariantError('renewal confirmation changed transaction')
    _prepared(store,row,source,tranche_id)
    fee,outputs=_validate_outputs(rpc,tx,recipients,source)
    if fee!=row['fee_sat']:raise InvariantError('renewal confirmed mining fee changed')
    state='confirmed' if tx.get('confirmations',0)>=1 else 'broadcast'
    with store.transaction():
        store.db.execute('UPDATE funding_batch SET state=?,updated_at=? WHERE id=?',(state,time.time(),tranche_id))
        if state=='confirmed':
            for r in recipients:
                actor=store.db.execute('SELECT online,details FROM actor WHERE id=?',(r['actor'],)).fetchone();d=json.loads(actor['details'])
                # A funded phone that disappeared meanwhile remains closed;
                # its grant stays in its own mnemonic-restorable BIP84 wallet.
                if actor['online'] and not d.get('permanent_absence'):
                    grant={**outputs[r['address']],'kind':'new_owner_funded_renewal','tranche':tranche_id,'confirmations':tx['confirmations']}
                    if tranche_id==TRAFFIC_TRANCHE:
                        if not _present(store,r['actor'],d):continue
                        d.setdefault('owner_renewal_sources',{})[tranche_id]=grant
                        d.update(needs_sync=True,snapshot_at=0)
                    else:d.update(owner_renewal_source=grant,needs_sync=True,snapshot_at=0)
                    store.db.execute('UPDATE actor SET details=? WHERE id=?',(canonical(d),r['actor']))
            store._event('owner_renewal_confirmed',{'tranche':tranche_id,'txid':row['txid'],'principal_sat':sum(r['amount_sat'] for r in recipients),'fee_sat':fee,'recipient_outputs':{r['actor']:outputs[r['address']] for r in recipients},'classification':'existing confirmed owner funds allocated to test clients' if tranche_id==TRAFFIC_TRANCHE else 'external owner injection allocated to test clients','recycling_credit_sat':0,'traffic_credit_seconds':0})
        if store.get_meta('paused')==_pause(tranche_id):store.db.execute("DELETE FROM meta WHERE key='paused'")
    return {'state':state,'txid':row['txid'],'retry_allowed':False}

def collect(store,config):
    if not config.funding_wallet:return
    rpc=None
    for tranche in (TRANCHE,TRAFFIC_TRANCHE):
        if not _declaration(store,tranche):continue
        row=store.db.execute('SELECT * FROM funding_batch WHERE id=?',(tranche,)).fetchone()
        if row and row['state'] in {'broadcast','broadcasting','outcome_unknown'}:
            if rpc is None:rpc=WalletRpc(config.funding_credential_file,config.funding_wallet,capture=store.trace_sample if store.trace is not None else None)
            reconcile(store,rpc,row)

def queue_board(store,actor,detail,config):
    traffic_source=detail.get('owner_renewal_sources',{}).get(TRAFFIC_TRANCHE)
    if traffic_source:return _queue_source_board(store,actor,detail,config,traffic_source)
    source=detail.get('owner_renewal_source')
    return _queue_source_board(store,actor,detail,config,source) if source else False

def _queue_source_board(store,actor,detail,config,source):
    if not store.ordinary_actor_available(actor):return False
    tranche=source.get('tranche')
    if source.get('kind')!='new_owner_funded_renewal' or tranche not in {TRANCHE,TRAFFIC_TRANCHE} or source.get('confirmations',0)<1:return False
    if tranche==TRAFFIC_TRANCHE:
        declaration=_declaration(store,tranche)
        if not declaration:raise InvariantError('owner grant has no immutable declaration')
        recipient=next((r for r in declaration['recipients'] if r['actor']==actor),None)
        if not recipient:raise InvariantError('owner grant actor differs from frozen allocation')
        if config.action_fee_reserve_sat!=2000 or config.funding_wallet!=declaration['funding_wallet']:raise InvariantError('owner board fee ceiling or funding wallet changed')
        current=store.db.execute('SELECT details FROM actor WHERE id=?',(actor,)).fetchone()
        if (not current or json.loads(current[0])!=detail or not _present(store,actor,detail) or detail.get('needs_sync')
                or not 0<=time.time()-detail.get('snapshot_at',0)<=600 or store.get_meta('paused')):return False
        if detail.get('funding_address')!=recipient['address'] or source['amount_sat']!=recipient['amount_sat']:raise InvariantError('owner board grant or destination changed')
        if store.db.execute("SELECT 1 FROM action WHERE actor_id=? AND state IN ('queued','dispatched','outcome_unknown')",(actor,)).fetchone():return False
    exists=store.db.execute("SELECT 1 FROM event WHERE kind='owner_renewal_board_intent' AND json_extract(payload,'$.actor')=? AND coalesce(json_extract(payload,'$.tranche'),json_extract(payload,'$.source.tranche'),?)=?",(actor,TRANCHE,tranche)).fetchone()
    if exists:return False
    proof=store.db.execute("SELECT payload FROM event WHERE kind='owner_renewal_confirmed' AND coalesce(json_extract(payload,'$.tranche'),?)=?",(TRANCHE,tranche)).fetchall()
    if len(proof)!=1:raise InvariantError('renewal board lacks unique confirmed funding proof')
    expected=json.loads(proof[0][0])['recipient_outputs'].get(actor)
    if expected!={k:source[k] for k in ('outpoint','script','amount_sat')}:raise InvariantError('renewal board source differs from confirmed actor grant')
    if tranche==TRAFFIC_TRANCHE:
        amount=source['amount_sat'];minimum=recipient['minimum_ark_amount_sat']
        args={'amount_sat':amount,'minimum_ark_amount_sat':minimum,'recycle_source':source,'recycle_autosize':True,'board_cap_sat':amount}
        action_id='owner-renewal-board-'+actor+'-'+tranche
    else:
        amount=min(config.board_amount_sat,source['amount_sat']-config.action_fee_reserve_sat);minimum=1000+config.action_fee_reserve_sat
        if amount<minimum:return False
        args={'amount_sat':amount,'minimum_ark_amount_sat':minimum,'recycle_source':source}
        action_id='owner-renewal-board-'+actor+'-1'
    if detail.get('onchain_confirmed_sat',0)<source['amount_sat'] or store.remaining_fee_budget()<config.action_fee_reserve_sat:return False
    with store.transaction():
        # This receipt-input guard grants no recycling or qualified traffic.
        store.queue(action_id,actor,'H01','board',args,config.action_fee_reserve_sat)
        store._event('owner_renewal_board_intent',{'actor':actor,'action_id':action_id,'tranche':tranche,'source':source,'board_amount_sat':amount,'minimum_ark_amount_sat':minimum,
            'classification':'new owner-funded allocation; not recycled receipt','recycling_credit_sat':0,'traffic_credit_seconds':0,'customer_traffic':False})
    return True

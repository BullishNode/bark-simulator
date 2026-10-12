"""One separately declared owner-funded renewal, never recycled capital.

Original initial/ramp grants are immutable. This uses one independently
confirmed new owner receipt, frozen recipients and one durable transaction.
Unknown broadcasts pause dispatch and are queried, never regenerated.
"""
import json,time
from decimal import Decimal
from .model import InvariantError,SIGNET_GENESIS,btc_to_sat,canonical,integer
from .funding import WalletRpc

TRANCHE='owner-renewal-2026-10-11-1'
PAUSE='owner renewal funding outcome uncertain'
REGTEST_GENESIS='0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206'

def eligible(store,config):
    result=[]
    for row in store.db.execute('SELECT id,online,details FROM actor ORDER BY id'):
        actor=row['id'];d=json.loads(row['details'])
        if actor not in {f'actor-{i:02}' for i in range(1,13) if i not in (9,10)} or not row['online'] or d.get('permanent_absence'):continue
        if not d.get('created') or not d.get('board_submitted') or d.get('needs_sync') or not 0<=time.time()-d.get('snapshot_at',0)<=600:continue
        if d.get('registered_spendable_sat',0)>=1000+config.action_fee_reserve_sat or d.get('onchain_confirmed_sat',0)>=config.board_amount_sat+config.action_fee_reserve_sat:continue
        address=d.get('funding_address')
        prefix='bcrt1q' if getattr(config,'network','signet')=='regtest' else 'tb1q'
        if not isinstance(address,str) or not address.startswith(prefix):raise InvariantError('renewal actor lacks original verified funding address')
        result.append({'actor':actor,'address':address,'amount_sat':8000})
    if len({r['address'] for r in result})!=len(result):raise InvariantError('renewal funding addresses repeat')
    return result

def declare(store,declaration):
    assert declaration['tranche_id']==TRANCHE
    assert (declaration['maximum_principal_sat'],declaration['maximum_actor_grant_sat'],declaration['maximum_mining_fee_sat'],declaration['maximum_batches'])==(80000,8000,2000,1)
    encoded=canonical(declaration);old=store.get_meta('owner_renewal_declaration')
    if old is not None and old!=encoded:raise InvariantError('renewal declaration changed')
    if old is None:
        with store.transaction():
            store.db.execute("INSERT INTO meta VALUES ('owner_renewal_declaration',?)",(encoded,))
            store._event('owner_renewal_declared',declaration)

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

def fund(store,rpc,config):
    declaration=json.loads(store.get_meta('owner_renewal_declaration') or 'null')
    if declaration is None:return {'state':'not_declared'}
    network=getattr(config,'network','signet')
    if network not in {'signet','regtest'}:raise InvariantError('renewal permits only signet or isolated regtest')
    genesis=SIGNET_GENESIS if network=='signet' else REGTEST_GENESIS
    if rpc.call('getblockhash',0,root=True)!=genesis:raise InvariantError('renewal chain mismatch')
    if rpc.call('getblockchaininfo',root=True)['initialblockdownload']:return {'state':'held_core_sync'}
    store.db.execute('CREATE TABLE IF NOT EXISTS funding_batch(id TEXT PRIMARY KEY,state TEXT NOT NULL,recipients TEXT NOT NULL,txid TEXT,raw_tx TEXT,fee_sat INTEGER,updated_at REAL NOT NULL)')
    old=store.db.execute('SELECT * FROM funding_batch WHERE id=?',(TRANCHE,)).fetchone()
    if old and old['state'] in {'broadcasting','outcome_unknown','broadcast','confirmed'}:
        return reconcile(store,rpc,old)
    if store.get_meta('paused') or store.db.execute("SELECT 1 FROM action WHERE state IN ('dispatched','outcome_unknown')").fetchone():return {'state':'held_uncertainty'}
    if store.db.execute("SELECT 1 FROM funding_batch WHERE id!=? AND state IN ('broadcasting','outcome_unknown')",(TRANCHE,)).fetchone():return {'state':'held_funding_uncertainty'}
    if old is None:
        recipients=eligible(store,config)
        if not recipients:return {'state':'no_eligible_online_clients'}
        total=sum(r['amount_sat'] for r in recipients)
        if total>80000:raise InvariantError('renewal principal cap exceeded')
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
            store.db.execute("INSERT INTO funding_batch VALUES (?,'intent',?,NULL,NULL,NULL,?)",(TRANCHE,canonical(recipients),time.time()))
            store.db.execute("INSERT INTO meta VALUES ('owner_renewal_funding_source',?)",(canonical(source),))
            store._event('owner_renewal_allocation_intent',{'tranche':TRANCHE,'recipients':recipients,'source':source,'principal_sat':total,'maximum_fee_sat':2000,'classification':'new owner-funded test allocation','recycling_credit_sat':0,'traffic_credit_seconds':0,'original_initial_ramp_budgets_unchanged':True})
        old=store.db.execute('SELECT * FROM funding_batch WHERE id=?',(TRANCHE,)).fetchone()
    source=json.loads(store.get_meta('owner_renewal_funding_source'));recipients=json.loads(old['recipients'])
    eligible_actors={r['actor']:r for r in eligible(store,config)}
    if any(eligible_actors.get(r['actor'])!=r for r in recipients):return {'state':'held_recipient_change','broadcast':False}
    if old['state']=='intent':
        txid,index=source['outpoint'].split(':')
        outputs=[{r['address']:str(Decimal(r['amount_sat'])/100000000)} for r in recipients]
        prepared=rpc.call('walletcreatefundedpsbt',[{'txid':txid,'vout':int(index)}],outputs,0,{'fee_rate':'3','lockUnspents':False,'add_inputs':False})
        if btc_to_sat(prepared['fee'])>2000:return {'state':'held_fee_cap','broadcast':False}
        signed=rpc.call('walletprocesspsbt',prepared['psbt']);final=rpc.call('finalizepsbt',signed['psbt'])
        if final.get('complete') is not True:return {'state':'held_incomplete_signature','broadcast':False}
        raw=final['hex'];tx=rpc.call('decoderawtransaction',raw,root=True);fee,_=_validate_outputs(rpc,tx,recipients,source)
        if fee!=btc_to_sat(prepared['fee']):raise InvariantError('renewal quoted fee differs from exact inputs and outputs')
        with store.transaction():
            store.db.execute("UPDATE funding_batch SET state='prepared',txid=?,raw_tx=?,fee_sat=?,updated_at=? WHERE id=?",(tx['txid'],raw,fee,time.time(),TRANCHE))
            store._event('owner_renewal_prepared',{'tranche':TRANCHE,'source':source,'txid':tx['txid'],'raw_tx':raw,'principal_sat':sum(r['amount_sat'] for r in recipients),'fee_sat':fee,'recycling_credit_sat':0})
        old=store.db.execute('SELECT * FROM funding_batch WHERE id=?',(TRANCHE,)).fetchone()
    with store.transaction():
        store.db.execute("UPDATE funding_batch SET state='broadcasting',updated_at=? WHERE id=?",(time.time(),TRANCHE))
        store._event('owner_renewal_broadcast_intent',{'tranche':TRANCHE,'txid':old['txid']})
    try:
        returned=rpc.call('sendrawtransaction',old['raw_tx'],root=True)
        if returned!=old['txid']:raise InvariantError('renewal broadcast returned another transaction')
        state='broadcast'
    except Exception:state='outcome_unknown'
    with store.transaction():
        store.db.execute('UPDATE funding_batch SET state=?,updated_at=? WHERE id=?',(state,time.time(),TRANCHE))
        if state=='outcome_unknown':store.db.execute("INSERT OR REPLACE INTO meta VALUES ('paused',?)",(PAUSE,))
        store._event('owner_renewal_funding_result',{'tranche':TRANCHE,'txid':old['txid'],'state':state,'fee_sat':old['fee_sat'],'retry_allowed':False})
    return {'state':state,'txid':old['txid'],'retry_allowed':False}

def reconcile(store,rpc,row):
    if row['state']=='confirmed':return {'state':'confirmed','txid':row['txid']}
    try:tx=rpc.call('getrawtransaction',row['txid'],True,root=True)
    except Exception:return {'state':'outcome_unknown','txid':row['txid'],'retry_allowed':False}
    source=json.loads(store.get_meta('owner_renewal_funding_source'));recipients=json.loads(row['recipients'])
    if tx['txid']!=row['txid']:raise InvariantError('renewal confirmation changed transaction')
    fee,outputs=_validate_outputs(rpc,tx,recipients,source)
    if fee!=row['fee_sat']:raise InvariantError('renewal confirmed mining fee changed')
    state='confirmed' if tx.get('confirmations',0)>=1 else 'broadcast'
    with store.transaction():
        store.db.execute('UPDATE funding_batch SET state=?,updated_at=? WHERE id=?',(state,time.time(),TRANCHE))
        if state=='confirmed':
            for r in recipients:
                actor=store.db.execute('SELECT online,details FROM actor WHERE id=?',(r['actor'],)).fetchone();d=json.loads(actor['details'])
                # A funded phone that disappeared meanwhile remains closed;
                # its grant stays in its own mnemonic-restorable BIP84 wallet.
                if actor['online'] and not d.get('permanent_absence'):
                    d.update(owner_renewal_source={**outputs[r['address']],'kind':'new_owner_funded_renewal','tranche':TRANCHE,'confirmations':tx['confirmations']},needs_sync=True,snapshot_at=0)
                    store.db.execute('UPDATE actor SET details=? WHERE id=?',(canonical(d),r['actor']))
            store._event('owner_renewal_confirmed',{'tranche':TRANCHE,'txid':row['txid'],'principal_sat':sum(r['amount_sat'] for r in recipients),'fee_sat':fee,'recipient_outputs':{r['actor']:outputs[r['address']] for r in recipients},'classification':'external owner injection allocated to test clients','recycling_credit_sat':0,'traffic_credit_seconds':0})
        if store.get_meta('paused')==PAUSE:store.db.execute("DELETE FROM meta WHERE key='paused'")
    return {'state':state,'txid':row['txid'],'retry_allowed':False}

def collect(store,config):
    if not store.get_meta('owner_renewal_declaration'):return
    if not config.funding_wallet:return
    row=store.db.execute('SELECT * FROM funding_batch WHERE id=?',(TRANCHE,)).fetchone()
    if row and row['state'] in {'broadcast','broadcasting','outcome_unknown'}:
        reconcile(store,WalletRpc(config.funding_credential_file,config.funding_wallet),row)

def queue_board(store,actor,detail,config):
    source=detail.get('owner_renewal_source')
    if not source or source.get('kind')!='new_owner_funded_renewal' or source.get('tranche')!=TRANCHE or source.get('confirmations',0)<1:return False
    if store.db.execute("SELECT 1 FROM event WHERE kind='owner_renewal_board_intent' AND json_extract(payload,'$.actor')=?",(actor,)).fetchone():return False
    proof=store.db.execute("SELECT payload FROM event WHERE kind='owner_renewal_confirmed'").fetchall()
    if len(proof)!=1:raise InvariantError('renewal board lacks unique confirmed funding proof')
    expected=json.loads(proof[0][0])['recipient_outputs'].get(actor)
    if expected!={k:source[k] for k in ('outpoint','script','amount_sat')}:raise InvariantError('renewal board source differs from confirmed actor grant')
    amount=min(config.board_amount_sat,source['amount_sat']-config.action_fee_reserve_sat)
    if detail.get('onchain_confirmed_sat',0)<source['amount_sat'] or amount<1000+config.action_fee_reserve_sat or store.remaining_fee_budget()<config.action_fee_reserve_sat:return False
    action_id='owner-renewal-board-'+actor+'-1'
    with store.transaction():
        # Reuse the native exact-own-receipt input guard. This field name does
        # not confer recycling credit: classification/ledger stay separate.
        store.queue(action_id,actor,'H01','board',{'amount_sat':amount,'minimum_ark_amount_sat':1000+config.action_fee_reserve_sat,'recycle_source':source},config.action_fee_reserve_sat)
        store._event('owner_renewal_board_intent',{'actor':actor,'action_id':action_id,'source':source,'board_amount_sat':amount,
            'classification':'new owner-funded allocation; not recycled receipt','recycling_credit_sat':0,'traffic_credit_seconds':0})
    return True

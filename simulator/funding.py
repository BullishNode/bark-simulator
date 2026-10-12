"""Declared fixture funding, durable transaction before broadcast; no backend treasury.

This is customer test-capital allocation, not operator equity or revenue. Core
wallet key material remains on the simulation host. An uncertain batch is never
replaced with a newly generated transaction.
"""
import argparse,base64,json,os,re,time,tomllib,urllib.request
from decimal import Decimal
from pathlib import Path
from .model import SIGNET_GENESIS,btc_to_sat,canonical,integer
from .store import Store
class WalletRpc:
    def __init__(self,token_file,wallet,*,capture=None):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,100}',wallet):raise ValueError('invalid fixture funding wallet name')
        self.token_file=token_file;self.wallet=wallet;self.capture=capture
    def call(self,method,*params,root=False):
        if method not in {'getblockhash','getblockchaininfo','getwalletinfo','getbalances','getaddressinfo','gettxout','walletcreatefundedpsbt','walletprocesspsbt','finalizepsbt','decoderawtransaction','sendrawtransaction','getrawtransaction','listunspent','decodepsbt'}:raise ValueError('unsupported funding RPC')
        token=base64.b64encode(Path(self.token_file).read_text().strip().encode()).decode()
        url='http://127.0.0.1:38332'+('' if root else '/wallet/'+self.wallet)
        req=urllib.request.Request(url,json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),{'Authorization':'Basic '+token,'Content-Type':'application/json'})
        raw=None
        try:
            with urllib.request.urlopen(req,timeout=30) as f:raw=f.read(16*1024*1024+1)
            if len(raw)>16*1024*1024:raw=None;raise ValueError('funding RPC response exceeds bound')
            r=json.loads(raw,parse_float=Decimal)
        except Exception as error:
            if self.capture:self.capture({'kind':'chain.rpc','payload':{'method':method,'params':list(params),'error':type(error).__name__,'consumer':'funding-wallet'},'raw':raw})
            raise
        if self.capture:
            from .trace import normalized
            self.capture({'kind':'chain.rpc','payload':{'method':method,'params':list(params),'result':normalized(r.get('result')),'error':normalized(r.get('error')),'consumer':'funding-wallet'},'raw':raw})
        if r.get('error'):raise ValueError('funding RPC unavailable/rejected')
        return r['result']

def fund(store,rpc,batch,amount_sat=8000,maximum_fee_sat=3000):
    if store.get_meta('paused'):raise ValueError('campaign paused; no new funding')
    integer(amount_sat,'client allocation',1);integer(maximum_fee_sat,'funding fee cap',1)
    if batch not in {'initial','ramp'}:raise ValueError('invalid cohort')
    if amount_sat!=8000 or maximum_fee_sat!=3000:raise ValueError('funding differs from the fixed 12+12 budget-adjusted declaration')
    if rpc.call('getblockhash',0,root=True)!=SIGNET_GENESIS:raise ValueError('funding chain mismatch')
    chain=rpc.call('getblockchaininfo',root=True)
    if chain['initialblockdownload']:raise ValueError('funding held until independent Core sync')
    declaration=canonical({'initial_principal_sat':96000,'ramp_principal_sat':96000,'maximum_total_funding_fee_sat':6000,'classification':'fixture customer grants'})
    with store.transaction():
        plan=store.get_meta('fixture_funding_plan')
        if plan is not None and plan!=declaration:raise ValueError('funding plan changed')
        if plan is None:
            opening=btc_to_sat(rpc.call('getbalances')['mine']['trusted'])
            store.db.execute("INSERT INTO meta VALUES ('fixture_funding_plan',?)",(declaration,))
            store._event('fixture_funding_declared',{'plan':json.loads(declaration),'opening_confirmed_funding_wallet_sat':opening,'future_inflows_must_be_recorded':True})
    store.db.execute('''CREATE TABLE IF NOT EXISTS funding_batch(id TEXT PRIMARY KEY, state TEXT NOT NULL, recipients TEXT NOT NULL, txid TEXT, raw_tx TEXT, fee_sat INTEGER, updated_at REAL NOT NULL)''')
    first,last=(1,12) if batch=='initial' else (13,24)
    if batch=='ramp' and store.get_meta('ramp_applied')!='true':raise ValueError('ramp has not occurred')
    recipients=[]
    for i in range(first,last+1):
        row=store.db.execute('SELECT details FROM actor WHERE id=?',(f'actor-{i:02}',)).fetchone()
        if row is None:raise ValueError('cohort actor not created')
        detail=json.loads(row[0]);addr=detail.get('funding_address')
        if not detail.get('created') or not isinstance(addr,str) or not addr.startswith('tb1q'):raise ValueError('cohort has no verified fresh funding addresses')
        recipients.append({'actor':f'actor-{i:02}','address':addr,'amount_sat':amount_sat})
    if len({r['address'] for r in recipients})!=12:raise ValueError('repeated funding address')
    encoded=canonical(recipients)
    old=store.db.execute('SELECT * FROM funding_batch WHERE id=?',(batch,)).fetchone()
    if old and old['recipients']!=encoded:raise ValueError('funding identity changed; batch cannot be regenerated')
    if old and old['state'] in {'broadcasting','outcome_unknown','broadcast','confirmed'}:
        try:
            tx=rpc.call('getrawtransaction',old['txid'],True,root=True)
            state='confirmed' if tx.get('confirmations',0)>0 else 'broadcast'
        except Exception:return {'batch':batch,'state':'outcome_unknown','txid':old['txid'],'retry_allowed':False}
        with store.transaction():
            store.db.execute('UPDATE funding_batch SET state=?,updated_at=? WHERE id=?',(state,time.time(),batch))
            if state=='confirmed' and old['state']!='confirmed':
                for recipient in recipients:
                    row=store.db.execute('SELECT details FROM actor WHERE id=?',(recipient['actor'],)).fetchone()
                    detail=json.loads(row[0]);detail['needs_sync']=True
                    store.db.execute('UPDATE actor SET details=? WHERE id=?',(canonical(detail),recipient['actor']))
                store._event('fixture_funding_confirmed',{'batch':batch,'txid':old['txid'],'principal_sat':sum(r['amount_sat'] for r in recipients),'fee_sat':old['fee_sat']})
        return {'batch':batch,'state':state,'txid':old['txid'],'fee_sat':old['fee_sat'],'retry_allowed':False}
    if old is None:
        with store.transaction():
            store.db.execute('INSERT INTO funding_batch VALUES (?,\'intent\',?,NULL,NULL,NULL,?)',(batch,encoded,time.time()))
            store._event('fixture_funding_intent',{'batch':batch,'recipients':recipients,'maximum_fee_sat':maximum_fee_sat,
                'classification':'fixture customer grants; not operator equity or server revenue'})
        old=store.db.execute('SELECT * FROM funding_batch WHERE id=?',(batch,)).fetchone()
    if old['state']=='intent':
        outputs=[{r['address']:str(Decimal(r['amount_sat'])/100000000)} for r in recipients]
        prepared=rpc.call('walletcreatefundedpsbt',[],outputs,0,{'fee_rate':'3','lockUnspents':False,'add_inputs':True})
        fee=btc_to_sat(prepared['fee'])
        if fee>maximum_fee_sat:raise ValueError('funding fee exceeds cap; no inputs locked or transaction broadcast')
        signed=rpc.call('walletprocesspsbt',prepared['psbt']);final=rpc.call('finalizepsbt',signed['psbt'])
        if final.get('complete') is not True:raise ValueError('funding signing incomplete; no broadcast')
        raw=final['hex'];decoded=rpc.call('decoderawtransaction',raw,root=True)
        expected={r['address']:r['amount_sat'] for r in recipients};seen={};change=0
        for o in decoded['vout']:
            addr=o['scriptPubKey'].get('address');value=btc_to_sat(o['value'])
            if addr in expected:
                if addr in seen or value!=expected[addr]:raise ValueError('funding output mismatch')
                seen[addr]=value
            else:
                if not addr or not rpc.call('getaddressinfo',addr).get('ismine'):raise ValueError('funding change not owned')
                change+=1
        if seen!=expected or change>1:raise ValueError('funding recipient set mismatch')
        with store.transaction():
            store.db.execute("UPDATE funding_batch SET state='prepared',txid=?,raw_tx=?,fee_sat=?,updated_at=? WHERE id=?",(decoded['txid'],raw,fee,time.time(),batch))
            store._event('fixture_funding_prepared',{'batch':batch,'txid':decoded['txid'],'raw_tx':raw,'principal_sat':sum(expected.values()),'fee_sat':fee})
        old=store.db.execute('SELECT * FROM funding_batch WHERE id=?',(batch,)).fetchone()
    with store.transaction():
        store.db.execute("UPDATE funding_batch SET state='broadcasting',updated_at=? WHERE id=?",(time.time(),batch))
        store._event('fixture_funding_broadcast_intent',{'batch':batch,'txid':old['txid']})
    try:
        actual=rpc.call('sendrawtransaction',old['raw_tx'],root=True)
        if actual!=old['txid']:raise ValueError('funding broadcast transaction mismatch')
        state='broadcast'
    except Exception:state='outcome_unknown'
    with store.transaction():
        store.db.execute('UPDATE funding_batch SET state=?,updated_at=? WHERE id=?',(state,time.time(),batch))
        store._event('fixture_funding_result',{'batch':batch,'state':state,'txid':old['txid'],'fee_sat':old['fee_sat']})
        if state=='broadcast':
            for recipient in recipients:
                row=store.db.execute('SELECT details FROM actor WHERE id=?',(recipient['actor'],)).fetchone();d=json.loads(row[0]);d['needs_sync']=True
                store.db.execute('UPDATE actor SET details=? WHERE id=?',(canonical(d),recipient['actor']))
    return {'batch':batch,'state':state,'txid':old['txid'],'fee_sat':old['fee_sat'],'retry_allowed':False}

def main():
    from .engine import Lease
    os.umask(0o077);p=argparse.ArgumentParser();p.add_argument('--config',type=Path,required=True);p.add_argument('--batch',choices=['initial','ramp'],required=True);a=p.parse_args()
    c=tomllib.loads(a.config.read_text());f=c['funding']
    with Lease(Path(c['runtime']['state_dir'])):
        store=Store(Path(c['runtime']['state_dir']),'live',c['runtime']['fee_budget_sat'])
        try:print(json.dumps(fund(store,WalletRpc(f['credential_file'],f['wallet']),a.batch)))
        finally:store.close()
if __name__=='__main__':main()

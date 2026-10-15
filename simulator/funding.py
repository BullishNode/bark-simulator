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
    def call(self,method,*params,root=False,timeout=30,max_response_bytes=16*1024*1024):
        if method not in {'getblockhash','getblockchaininfo','getwalletinfo','getbalances','getaddressinfo','gettxout','walletcreatefundedpsbt','walletprocesspsbt','finalizepsbt','decoderawtransaction','sendrawtransaction','getrawtransaction','listunspent','decodepsbt','listdescriptors','listlockunspent','listsinceblock'}:raise ValueError('unsupported funding RPC')
        if method=='listdescriptors' and (len(params)!=1 or params[0] is not False):raise ValueError('only explicitly public descriptors may be requested')
        token=base64.b64encode(Path(self.token_file).read_text().strip().encode()).decode()
        url='http://127.0.0.1:38332'+('' if root else '/wallet/'+self.wallet)
        req=urllib.request.Request(url,json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),{'Authorization':'Basic '+token,'Content-Type':'application/json'})
        if not 0<timeout<=30 or not 0<max_response_bytes<=16*1024*1024:raise ValueError('invalid funding RPC bounds')
        self.last_response_bytes=0
        raw=None
        try:
            with urllib.request.urlopen(req,timeout=timeout) as f:raw=f.read(max_response_bytes+1)
            self.last_response_bytes=len(raw)
            if len(raw)>max_response_bytes:raw=None;raise ValueError('funding RPC response exceeds bound')
            r=json.loads(raw,parse_float=Decimal)
        except Exception as error:
            if self.capture:self.capture({'kind':'chain.rpc','payload':{'method':method,'params':list(params),'error':type(error).__name__,'consumer':'funding-wallet'},'raw':raw})
            raise
        if self.capture:
            from .trace import normalized
            self.capture({'kind':'chain.rpc','payload':{'method':method,'params':list(params),'result':normalized(r.get('result')),'error':normalized(r.get('error')),'consumer':'funding-wallet'},'raw':raw})
        if r.get('error'):raise ValueError('funding RPC unavailable/rejected')
        return r['result']

def declare_plan(store,declaration):
    """Immutable fresh-campaign allocation; never rewrite an old R&D plan."""
    from .model import public_payload
    fields={'id','initial_clients','ramp_clients','grant_sat','batch_maximum_fee_sat',
            'maximum_total_principal_sat','maximum_total_fee_sat','fee_rate_sat_kvb'}
    if not isinstance(declaration,dict) or set(declaration)!=fields or not declaration['id']:
        raise ValueError('explicit complete funding declaration required')
    public_payload(declaration)
    for field in fields-{'id'}:integer(declaration[field],field,1)
    if declaration['initial_clients']!=12 or declaration['ramp_clients']!=12:
        raise ValueError('declared campaign requires twelve initial and twelve added clients')
    if 24*declaration['grant_sat']>declaration['maximum_total_principal_sat']:
        raise ValueError('declared grants exceed total principal cap')
    if 2*declaration['batch_maximum_fee_sat']>declaration['maximum_total_fee_sat']:
        raise ValueError('declared batch fee limits exceed total funding fee cap')
    encoded=canonical(declaration)
    with store.transaction():
        old=store.get_meta('fixture_funding_plan')
        if old is not None:
            if old!=encoded:raise ValueError('funding plan immutable; use fresh namespace')
            return False
        if not store.get_meta('paused'):raise ValueError('pause before declaring funding')
        if store.get_meta('mode')=='live':
            from .treasury import boundary
            from .operating_limits import KEY
            boundary(store)
            financial=store.get_meta(KEY)
            if financial is None or json.loads(financial)['grant_sat']!=declaration['grant_sat']:
                raise ValueError('live grants differ from actual financial envelope')
        if store.db.execute("SELECT 1 FROM event WHERE kind IN ('fixture_funding_intent','fixture_funding_broadcast_intent') LIMIT 1").fetchone():
            raise ValueError('funding must be declared before first allocation')
        store.db.execute("INSERT INTO meta VALUES ('fixture_funding_plan',?)",(encoded,))
        store._event('fixture_funding_declared',{'plan':declaration,'future_inflows_must_be_recorded':True})
    return True


def plan(store):
    encoded=store.get_meta('fixture_funding_plan')
    if encoded is None:raise ValueError('explicit immutable funding plan missing')
    declaration=json.loads(encoded)
    # An old plan cannot be silently treated as a new grant declaration.
    if set(declaration)!={'id','initial_clients','ramp_clients','grant_sat','batch_maximum_fee_sat',
                           'maximum_total_principal_sat','maximum_total_fee_sat','fee_rate_sat_kvb'}:
        raise ValueError('preserve old campaign; new funding requires fresh namespace')
    rows=store.db.execute("SELECT payload FROM event WHERE kind='fixture_funding_declared'").fetchall()
    if len(rows)!=1 or json.loads(rows[0][0]).get('plan')!=declaration:
        raise ValueError('funding plan differs from original immutable declaration')
    return declaration


def _funding_table(store):
    store.db.execute('''CREATE TABLE IF NOT EXISTS funding_batch(id TEXT PRIMARY KEY, state TEXT NOT NULL, recipients TEXT NOT NULL, txid TEXT, raw_tx TEXT, fee_sat INTEGER, updated_at REAL NOT NULL)''')


def _check_outputs(decoded,recipients,rpc):
    """Existing exact recipient and at-most-one owned-change check."""
    expected={r['address']:r['amount_sat'] for r in recipients};seen={};change=[]
    if len(expected)!=len(recipients):raise ValueError('repeated funding address')
    for output in decoded['vout']:
        address=output['scriptPubKey'].get('address');value=btc_to_sat(output['value'])
        if address in expected:
            if address in seen or value!=expected[address]:raise ValueError('funding output mismatch')
            seen[address]=value
        else:
            if not address or not rpc.call('getaddressinfo',address).get('ismine'):raise ValueError('funding change not owned')
            change.append(output)
    if seen!=expected or len(change)>1:raise ValueError('funding recipient set mismatch')
    return change


def fund(store,rpc,batch,amount_sat=None,maximum_fee_sat=None):
    if store.get_meta('paused'):raise ValueError('campaign paused; no new funding')
    declaration=plan(store)
    amount_sat=declaration['grant_sat'] if amount_sat is None else integer(amount_sat,'client allocation',1)
    maximum_fee_sat=declaration['batch_maximum_fee_sat'] if maximum_fee_sat is None else integer(maximum_fee_sat,'funding fee cap',1)
    if amount_sat!=declaration['grant_sat'] or maximum_fee_sat!=declaration['batch_maximum_fee_sat']:
        raise ValueError('requested grant or fee differs from immutable funding declaration')
    if batch not in {'initial','ramp'}:raise ValueError('invalid cohort')
    if rpc.call('getblockhash',0,root=True)!=SIGNET_GENESIS:raise ValueError('funding chain mismatch')
    chain=rpc.call('getblockchaininfo',root=True)
    if chain['initialblockdownload']:raise ValueError('funding held until independent Core sync')
    _funding_table(store)
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
    def available():
        if any(not store.ordinary_actor_available(r['actor']) for r in recipients):
            raise ValueError('funding recipients belong to an active private controller or namespace')
    available()
    if old is None:
        with store.transaction():
            store.db.execute('INSERT INTO funding_batch VALUES (?,\'intent\',?,NULL,NULL,NULL,?)',(batch,encoded,time.time()))
            store._event('fixture_funding_intent',{'batch':batch,'recipients':recipients,'maximum_fee_sat':maximum_fee_sat,
                'classification':'fixture customer grants; not operator equity or server revenue'})
        old=store.db.execute('SELECT * FROM funding_batch WHERE id=?',(batch,)).fetchone()
    if old['state']=='intent':
        available()
        outputs=[{r['address']:str(Decimal(r['amount_sat'])/100000000)} for r in recipients]
        prepared=rpc.call('walletcreatefundedpsbt',[],outputs,0,{'fee_rate':str(Decimal(declaration['fee_rate_sat_kvb'])/1000),'minconf':1,'lockUnspents':False,'add_inputs':True})
        fee=btc_to_sat(prepared['fee'])
        if fee>maximum_fee_sat:raise ValueError('funding fee exceeds cap; no inputs locked or transaction broadcast')
        available()
        signed=rpc.call('walletprocesspsbt',prepared['psbt']);final=rpc.call('finalizepsbt',signed['psbt'])
        if final.get('complete') is not True:raise ValueError('funding signing incomplete; no broadcast')
        raw=final['hex'];decoded=rpc.call('decoderawtransaction',raw,root=True)
        _check_outputs(decoded,recipients,rpc)
        with store.transaction():
            store.db.execute("UPDATE funding_batch SET state='prepared',txid=?,raw_tx=?,fee_sat=?,updated_at=? WHERE id=?",(decoded['txid'],raw,fee,time.time(),batch))
            store._event('fixture_funding_prepared',{'batch':batch,'txid':decoded['txid'],'raw_tx':raw,'principal_sat':sum(r['amount_sat'] for r in recipients),'fee_sat':fee})
        old=store.db.execute('SELECT * FROM funding_batch WHERE id=?',(batch,)).fetchone()
    available()
    with store.transaction():
        available()
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

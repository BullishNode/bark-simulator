"""Independent read-only Bitcoin evidence; exact satoshis, bounded RPC calls."""
from __future__ import annotations
import base64,json,urllib.request
from decimal import Decimal
from pathlib import Path
from .model import SIGNET_GENESIS,btc_to_sat,integer,transaction_fee
from .trace import normalized,public_raw
from .model import public_payload
class ChainReader:
    def __init__(self,url,credential,expected_genesis,*,capture=None,consumer='chain-reader'):
        if not url.startswith('http://127.0.0.1:'):raise ValueError('independent Core must be loopback')
        self.url,self.credential,self.expected=url,Path(credential),expected_genesis
        self.cache={}
        self.capture,self.consumer=capture,consumer
    def call(self,method,*args):
        if method not in {'getrawtransaction','getblockhash','getblockchaininfo','gettxout','getmempoolinfo','estimatesmartfee','getdescriptorinfo','deriveaddresses','validateaddress'}:raise ValueError('read-only RPC required')
        token=base64.b64encode(self.credential.read_text().strip().encode()).decode()
        req=urllib.request.Request(self.url,json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':args}).encode(),{'Authorization':'Basic '+token,'Content-Type':'application/json'})
        raw=None
        try:
            with urllib.request.urlopen(req,timeout=12) as f:raw=f.read(16*1024*1024+1)
            if len(raw)>16*1024*1024:raw=None;raise ValueError('Core response exceeds capture bound')
            r=json.loads(raw,parse_float=Decimal)
        except Exception as error:
            self._capture(method,args,None,type(error).__name__,raw)
            raise
        self._capture(method,args,r.get('result'),r.get('error'),raw)
        if r.get('error'):raise ValueError('independent chain evidence unavailable')
        return r['result']
    def _capture(self,method,args,result,error,raw):
        if self.capture is None:return
        payload={'method':method,'params':list(args),'result':normalized(result),
                 'error':normalized(error),'consumer':self.consumer}
        try:public_payload(payload);public_raw(raw)
        except (ValueError,UnicodeError):payload={'redacted':True,'method':method,'consumer':self.consumer};raw=None
        self.capture({'kind':'chain.rpc','payload':payload,'raw':raw})
    def identity(self):
        if self.call('getblockhash',0)!=self.expected:raise ValueError('chain genesis mismatch')
        return self.call('getblockchaininfo')
    def tx(self,txid):
        if not isinstance(txid,str) or len(txid)!=64 or any(c not in '0123456789abcdef' for c in txid):raise ValueError('invalid transaction id')
        r=self.call('getrawtransaction',txid,True)
        if r['txid']!=txid:raise ValueError('chain transaction mismatch')
        return r
    def transaction(self,txid):
        r=self.tx(txid);inputs=[]
        for i in r['vin']:
            if 'coinbase' in i:raise ValueError('coinbase is not a payout')
            previous=self.tx(i['txid'])['vout'][integer(i['vout'],'output index')]
            inputs.append({'outpoint':i['txid']+':'+str(i['vout']),'amount_sat':btc_to_sat(previous['value']), 'script':previous['scriptPubKey']['hex']})
        outputs=[{'vout':o['n'],'script':o['scriptPubKey']['hex'],'amount_sat':btc_to_sat(o['value'])} for o in r['vout']]
        tx={'txid':txid,'inputs':inputs,'outputs':outputs,'confirmations':r.get('confirmations',0),'blockhash':r.get('blockhash')}
        tx['fee_sat']=transaction_fee(tx)
        if self.capture is not None:
            self.capture({'kind':'chain.derived','payload':{'txid':txid,'derived':tx,'consumer':self.consumer},'raw':None})
        return tx

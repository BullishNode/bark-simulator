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
        self.last_capture=None
        self.capture,self.consumer=capture,consumer
    def call(self,method,*args,timeout=12,max_response_bytes=16*1024*1024):
        self.last_capture=None
        if method not in {'getrawtransaction','getblockhash','getblockchaininfo','gettxout','getmempoolinfo','estimatesmartfee','getdescriptorinfo','deriveaddresses','validateaddress','scantxoutset','getrawmempool','getdescriptoractivity'}:raise ValueError('read-only RPC required')
        if method=='getdescriptoractivity':
            from .owned_mempool import validate_arguments,MAX_RESPONSE_BYTES
            validate_arguments(args)
            if max_response_bytes>MAX_RESPONSE_BYTES:raise ValueError('owned-script activity response bound required')
        if method=='scantxoutset':
            if args==('status',):pass
            elif (len(args)!=2 or args[0]!='start' or not isinstance(args[1],list) or not 1<=len(args[1])<=16
                    or any(not isinstance(row,dict) or set(row)!={'desc','range'} or not isinstance(row['desc'],str)
                        or not row['desc'] or len(row['desc'])>4096 or not isinstance(row['range'],list)
                        or len(row['range'])!=2 or any(type(index) is not int for index in row['range'])
                        or row['range'][0]!=0 or not 19<=row['range'][1]<2000 for row in args[1])):
                raise ValueError('bounded public bootstrap descriptor scan required')
            if args!=('status',):public_payload(args[1])
        if method=='getrawmempool' and args!=(False,):raise ValueError('bounded transaction-id inventory required')
        token=base64.b64encode(self.credential.read_text().strip().encode()).decode()
        body=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':args}).encode()
        if method=='getdescriptoractivity':
            from .owned_mempool import MAX_REQUEST_BYTES
            if len(body)>MAX_REQUEST_BYTES:raise ValueError('owned script request exceeds byte bound')
        req=urllib.request.Request(self.url,body,{'Authorization':'Basic '+token,'Content-Type':'application/json'})
        maximum_timeout=120 if method=='scantxoutset' and args[0]=='start' else 12
        if not 0<timeout<=maximum_timeout or not 0<max_response_bytes<=16*1024*1024:raise ValueError('invalid Core response bounds')
        self.last_response_bytes=0
        raw=None
        try:
            with urllib.request.urlopen(req,timeout=timeout) as f:raw=f.read(max_response_bytes+1)
            self.last_response_bytes=len(raw)
            if len(raw)>max_response_bytes:raw=None;raise ValueError('Core response exceeds capture bound')
            if method=='getdescriptoractivity':
                from .owned_mempool import decode_reply
                r=decode_reply(raw)
            else:r=json.loads(raw,parse_float=Decimal)
        except Exception as error:
            # A malformed/nonempty activity reply is not a public projection:
            # never capture arbitrary event fields, RPC messages or raw bytes.
            self._capture(method,args,None,type(error).__name__,None if method=='getdescriptoractivity' else raw)
            raise
        self._capture(method,args,r.get('result'),r.get('error'),raw)
        if r.get('error'):raise ValueError('independent chain evidence unavailable')
        return r['result']
    def _capture(self,method,args,result,error,raw):
        if self.capture is None:return
        if method=='getrawtransaction':
            # Unparsed/error replies may contain witness or scriptSig bytes too.
            raw=None
            if error is None:
                try:result=public_transaction(result)
                except ValueError:result={'public_projection_gap':True,'signed_bytes_omitted':True}
            else:
                result={'public_projection_gap':True,'signed_bytes_omitted':True}
                # RPC message/data strings can contain opaque transaction bytes.
                if isinstance(error,dict):
                    code=error.get('code')
                    error={'code':code} if type(code) is int and -2**31<=code<2**31 else 'RPCError'
                elif not isinstance(error,str) or error not in {'JSONDecodeError','UnicodeDecodeError','ValueError','OSError',
                        'URLError','HTTPError','TimeoutError','ConnectionError','ConnectionResetError',
                        'RemoteDisconnected','IncompleteRead','BrokenPipeError'}:
                    error='ObservationError'
        payload={'method':method,'params':list(args),'result':normalized(result),
                 'error':normalized(error),'consumer':self.consumer}
        try:public_payload(payload);public_raw(raw)
        except (ValueError,UnicodeError):payload={'redacted':True,'method':method,'consumer':self.consumer};raw=None
        self.last_capture=self.capture({'kind':'chain.rpc','payload':payload,'raw':raw})
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


def public_transaction(value):
    """Keep exact bodies only when their scriptSigs are empty; omit witnesses.

    This changes observation capture only. The Core result returned privately
    to its caller is unchanged. Numeric witness sizes describe the original
    observation; stripped bodies alone do not re-prove witness weight.
    """
    from .bundle_audit import decode_transaction
    if isinstance(value,str):
        decoded=decode_transaction(value,public_body=True)
        if any(decoded['input_script_sig_sizes']):
            raise ValueError('nonempty scriptSig cannot enter public transaction evidence')
        return decoded['stripped_hex']
    if not isinstance(value,dict) or not isinstance(value.get('hex'),str):
        raise ValueError('raw transaction capture lacks a bounded exact body')
    decoded=decode_transaction(value['hex'],public_body=True)
    if any(decoded['input_script_sig_sizes']):
        raise ValueError('nonempty scriptSig cannot enter public transaction evidence')
    result={**value,'hex':decoded['stripped_hex'],'witness_redacted':decoded['witness_redacted'],
            'original_size':decoded['size'],'original_weight':decoded['weight']}
    result['vin']=[]
    vin=value.get('vin',[])
    if not isinstance(vin,list) or any(not isinstance(source,dict) for source in vin):
        raise ValueError('invalid public input metadata')
    for source in vin:
        if source.get('scriptSig') not in (None, {'asm':'','hex':''}):
            raise ValueError('reported scriptSig is not the checked empty script')
        entry={k:v for k,v in source.items() if k!='txinwitness'}
        if 'txinwitness' in source:
            if not isinstance(source['txinwitness'],list) or any(not isinstance(item,str) for item in source['txinwitness']):
                raise ValueError('invalid public witness metadata')
            entry['witness_item_sizes']=[len(bytes.fromhex(item)) for item in source['txinwitness']]
        result['vin'].append(entry)
    return result

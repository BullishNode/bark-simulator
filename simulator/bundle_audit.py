"""Offline raw-chain and optional native signature replay for public bundles.

The replay RPC serves only exported public evidence. Missing anchors remain
missing; it has no forwarding path, wallet operations, or Core credentials.
"""
from __future__ import annotations
import base64
import hashlib
import json
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from .model import InvariantError, canonical, public_payload, transaction_fee


def decode_transaction(encoded):
    """Decode canonical Bitcoin wire bytes and recompute the non-witness txid."""
    if not isinstance(encoded,str) or len(encoded)>32*1024*1024:
        raise ValueError('invalid raw transaction')
    try:raw=bytes.fromhex(encoded)
    except ValueError:raise ValueError('invalid raw transaction') from None
    offset=0
    def take(size):
        nonlocal offset
        if size<0 or offset+size>len(raw):raise ValueError('truncated transaction')
        value=raw[offset:offset+size];offset+=size;return value
    def compact():
        marker=take(1)[0]
        if marker<253:return marker,bytes([marker])
        width={253:2,254:4,255:8}[marker];data=take(width);value=int.from_bytes(data,'little')
        if value<({253:253,254:65536,255:4294967296}[marker]):raise ValueError('noncanonical compact size')
        return value,bytes([marker])+data
    version=take(4);witness=False
    if offset+2<=len(raw) and raw[offset]==0:
        if take(2)!=b'\x00\x01':raise ValueError('unsupported witness flags')
        witness=True
    count,prefix=compact()
    if not count or count>100000:raise ValueError('invalid input count')
    stripped=bytearray(version+prefix);inputs=[]
    for _ in range(count):
        point=take(36);size,prefix=compact();script=take(size);sequence=take(4)
        stripped.extend(point+prefix+script+sequence)
        inputs.append({'outpoint':point[:32][::-1].hex()+':'+str(int.from_bytes(point[32:],'little'))})
    count,prefix=compact()
    if count>100000:raise ValueError('invalid output count')
    stripped.extend(prefix);outputs=[]
    for index in range(count):
        amount=take(8);size,prefix=compact();script=take(size)
        value=int.from_bytes(amount,'little')
        if value>21000000*100000000:raise ValueError('invalid Bitcoin amount')
        stripped.extend(amount+prefix+script)
        outputs.append({'vout':index,'amount_sat':value,'script':script.hex()})
    if sum(o['amount_sat'] for o in outputs)>21000000*100000000:raise ValueError('invalid Bitcoin total')
    if witness:
        found=False
        for _ in inputs:
            count,_=compact()
            if count>100000:raise ValueError('invalid witness count')
            found |= count>0
            for _ in range(count):size,_=compact();take(size)
        if not found:raise ValueError('superfluous witness encoding')
    stripped.extend(take(4))
    if offset!=len(raw):raise ValueError('trailing transaction bytes')
    txid=hashlib.sha256(hashlib.sha256(stripped).digest()).digest()[::-1].hex()
    return {'txid':txid,'inputs':inputs,'outputs':outputs}


def archived_transactions(directory):
    transactions={}
    for path in sorted(Path(directory).glob('*.json')):
        row=json.loads(path.read_text())
        if row.get('method')!='getrawtransaction':continue
        params=row.get('params',[]);result=row.get('result')
        if not params or result is None:continue
        encoded=result.get('hex') if isinstance(result,dict) else result
        if not encoded:continue
        try:decoded=decode_transaction(encoded)
        except ValueError:raise InvariantError('archived Core raw transaction is invalid') from None
        if decoded['txid']!=params[0] or (isinstance(result,dict) and result.get('txid')!=decoded['txid']):
            raise InvariantError('archived Core raw transaction identity differs')
        raw_path=path.with_suffix('.raw')
        if raw_path.exists():
            original=json.loads(raw_path.read_bytes())
            if original.get('result')!=result:
                # Decimal strings in normalized metadata are compared through
                # exact JSON decimals rather than through binary floating point.
                from decimal import Decimal
                from .trace import normalized
                original=json.loads(raw_path.read_bytes(),parse_float=Decimal)
                if normalized(original.get('result'))!=result:
                    raise InvariantError('raw Core response differs from normalized evidence')
        old=transactions.get(decoded['txid'])
        if old and old['hex']!=encoded:raise InvariantError('competing raw transaction bytes')
        metadata=result if isinstance(result,dict) else {}
        candidate={'hex':encoded,'decoded':decoded,'info':metadata}
        if old is None or metadata.get('confirmations',0)>old['info'].get('confirmations',0):
            transactions[decoded['txid']]=candidate
    return transactions


def replay_chain_payout(tx,transactions):
    current=transactions.get(tx['txid'])
    if current is None:return {'raw_chain_reverified':False,'gaps':[{'kind':'missing_raw_payout','txid':tx['txid']}]}
    decoded=current['decoded'];inputs=[]
    for point in decoded['inputs']:
        txid,index=point['outpoint'].split(':');previous=transactions.get(txid)
        if previous is None:return {'raw_chain_reverified':False,'gaps':[{'kind':'missing_raw_payout_input','txid':txid}]}
        try:output=previous['decoded']['outputs'][int(index)]
        except IndexError:raise InvariantError('payout input references an absent output') from None
        inputs.append({'outpoint':point['outpoint'],'amount_sat':output['amount_sat'],'script':output['script']})
    replay={'inputs':inputs,'outputs':decoded['outputs']}
    if inputs!=tx['inputs'] or decoded['outputs']!=tx['outputs'] or transaction_fee(replay)!=tx['fee_sat']:
        raise InvariantError('payout accounting differs from exported raw transactions')
    if current['info'].get('confirmations',0)<1:
        return {'raw_chain_reverified':False,'gaps':[{'kind':'missing_payout_confirmation_metadata','txid':tx['txid']}]}
    return {'raw_chain_reverified':True,'gaps':[]}


class ReplayCore:
    """A loopback, read-only RPC fixture with no upstream connection."""
    def __init__(self,genesis,transactions):self.genesis,self.transactions=genesis,transactions
    def call(self,method,params):
        if method=='getblockhash' and params==[0]:return self.genesis
        if method=='getrawtransaction' and 1<=len(params)<=2:
            archived=self.transactions.get(params[0])
            if archived is None:raise ValueError('unarchived anchor')
            return archived['info'] if len(params)==2 and params[1] else archived['hex']
        raise ValueError('public archive RPC only')
    def __enter__(self):
        owner=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                try:
                    size=int(self.headers.get('Content-Length','0'))
                    if size<1 or size>65536:raise ValueError('bounded public RPC request required')
                    request=json.loads(self.rfile.read(size));result=owner.call(request['method'],request.get('params',[]))
                    response={'id':request.get('id'),'result':result,'error':None}
                except (ValueError,KeyError,TypeError):
                    response={'id':None,'result':None,'error':{'code':-32600,'message':'public archive evidence unavailable'}}
                encoded=canonical(response).encode();self.send_response(200)
                self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(encoded)))
                self.end_headers();self.wfile.write(encoded)
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.url='http://127.0.0.1:'+str(self.server.server_address[1])
        return self
    def __exit__(self,*args):self.server.shutdown();self.server.server_close();self.thread.join(timeout=5)


def verify_native_proofs(proofs,transactions,binary):
    """Re-run the public native verifier on exact exported signature requests."""
    gaps=[];verified=0
    for coin in proofs:
        requests=[request for request in coin.get('requests',[]) if isinstance(request,dict)
            and request.get('signed_vtxo')==coin.get('signed_vtxo')
            and request.get('key_link_attestation')
            and isinstance(request.get('binding'),dict) and request['binding'].get('record_attestation')]
        if not requests:
            gaps.append({'kind':'missing_raw_signature_request','coin_id':coin['id']});continue
        cached=coin['proof'];anchor=cached.get('chain_anchor','').split(':')[0]
        if anchor not in transactions:
            gaps.append({'kind':'missing_raw_backing_anchor','coin_id':coin['id']});continue
        request=requests[0];public_payload(request)
        with tempfile.TemporaryDirectory(prefix='public-proof-replay-') as temporary:
            cookie=Path(temporary)/'rpc-cookie';cookie.write_text('public-replay:unused');cookie.chmod(0o600)
            with ReplayCore(cached['genesis'],transactions) as core:
                command=[str(binary),core.url,str(cookie),cached['server_pubkey']]
                result=subprocess.run(command,input=canonical(request).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        if result.returncode or len(result.stdout)>2097152:raise InvariantError('exported native signature proof failed')
        proof=json.loads(result.stdout);public_payload(proof)
        if any(proof.get(key)!=cached.get(key) for key in ('id','user_pubkey','amount_sat','chain_anchor','genesis','server_pubkey','path')):
            raise InvariantError('fresh native proof differs from exported ownership')
        if proof.get('signed_path_valid') is not True or proof.get('anchor_confirmations',0)<1:
            raise InvariantError('fresh native proof lacks confirmed signed backing')
        bound=proof.get('binding',{})
        if any(bound.get(key)!=cached.get('binding',{}).get(key) for key in ('mailbox_pk','seq','spk')) or any(
                bound.get(key) is not True for key in ('record_signature_valid','key_link_signature_valid')):
            raise InvariantError('fresh native binding differs from exported owner')
        verified+=1
    return {'native_protocol_reverified':bool(proofs) and verified==len(proofs),'native_proofs_verified':verified,'gaps':gaps}

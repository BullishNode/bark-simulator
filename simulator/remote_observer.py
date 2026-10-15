"""Dedicated simulator VM observer: restricted bridge plus independent signet Core.

Never call client wallets to observe an absent actor. Money not yet attributed
remains unknown. Node outputs exclude preimages and private configuration.
"""
from __future__ import annotations
import argparse,asyncio,base64,json,os,re,time,urllib.request,threading
from decimal import Decimal
from pathlib import Path
from .model import SIGNET_GENESIS,btc_to_sat,integer,public_payload
from .trace import normalized,public_raw
from .process import json_command

def sample(node, method, params, result, *, raw=None):
    payload={'node':node,'method':method,'params':list(params),'result':normalized(result)}
    try:
        public_payload(payload);raw=public_raw(raw)
    except (ValueError,UnicodeError):payload={'node':node,'method':method,'redacted':True};raw=None
    return {'kind':'observer.sample.raw','payload':payload,
            'raw':raw.decode() if raw is not None else None}

async def public_command(command, *, node, method, request=None, timeout=12, capture=None):
    output=[]
    kwargs={'timeout':timeout}
    if capture is not None:kwargs['on_stdout_raw']=output.append
    try:
        result=await json_command(command,request,**kwargs) if request is not None else await json_command(command,**kwargs)
    except Exception as error:
        if capture is not None:
            raw=output[0]['raw'] if output and not output[0]['truncated'] else None
            record=sample(node,method,[] if request is None else [request],None,raw=raw)
            record['payload']['error']=type(error).__name__;capture(record)
        raise
    if capture is not None:
        raw=output[0]['raw'] if output and not output[0]['truncated'] else None
        capture(sample(node,method,[] if request is None else [request],result,raw=raw))
    return result


class Core:
    def __init__(self,cookie,capture=None):self.cookie,self.capture=cookie,capture
    def call(self,method,*args):
        if method not in {'getblockchaininfo','getblockhash','gettxout','getindexinfo','getmempoolinfo'}:raise ValueError('read-only Core operation required')
        auth=base64.b64encode(self.cookie.read_text().strip().encode()).decode()
        req=urllib.request.Request('http://127.0.0.1:38332',json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':args}).encode(),
            {'Authorization':'Basic '+auth,'Content-Type':'application/json'})
        raw=None
        try:
            with urllib.request.urlopen(req,timeout=8) as response:raw=response.read(16*1024*1024+1)
            if len(raw)>16*1024*1024:raw=None;raise ValueError('Core observer response exceeds bound')
            r=json.loads(raw,parse_float=Decimal)
        except Exception as error:
            if self.capture is not None:
                record=sample('independent-core',method,args,None,raw=raw)
                record['payload']['error']=type(error).__name__;self.capture(record)
            raise
        if self.capture is not None:self.capture(sample('independent-core',method,args,r.get('result'),raw=raw))
        if r.get('error'):raise ValueError('independent Core observation unavailable')
        return r['result']

def peer_channel(channel):
    allowed=['peer_id','channel_id','state','opener','funding_txid','funding_outnum','total_msat','to_us_msat','spendable_msat','receivable_msat']
    return {k:channel[k] for k in allowed if k in channel}

def own_output(output):
    allowed=['txid','output','amount_msat','status','blockheight','reserved']
    return {k:output[k] for k in allowed if k in output}


def timing_projection(remote,info,*,per_key=False):
    actual={k:info['data'][k] for k in ('vtxo_lifetime','required_board_confirmations','round_interval_secs')}
    if per_key:
        # C's direct route has no legacy retained-minimum/grace/sweep pipeline.
        # Missing disabled legacy fields must not prevent a true C observation.
        return {**actual,'payout_enabled':remote.get('direct_expiry_enabled') is True,
            'direct_expiry_enabled':remote.get('direct_expiry_enabled'),
            'legacy_payout_enabled':remote.get('timings',{}).get('enabled')}
    return {'payout_enabled':remote['timings']['enabled'],'min_payout_sat':remote['timings']['min_payout_sat'],
        'grace_blocks':remote['timings']['grace_blocks'],'sweep_min_confs':remote['timings']['sweep_min_confs'],**actual}

async def lightning(container,capture=None):
    base=['sudo','-n','docker','exec',container,'lightning-cli','--network=signet','--lightning-dir=/data/.lightning']
    try:
        info,funds,peers=await asyncio.gather(*(public_command(base+[method],node=container,method=method,capture=capture) for method in ['getinfo','listfunds','listpeerchannels']))
        if info['network']!='signet':raise ValueError('Lightning node network mismatch')
        return {'node_id':info['id'],'network':info['network'],'blockheight':info['blockheight'],
            'unspent_outputs':[own_output(o) for o in funds['outputs']],
            'channels':[peer_channel(c) for c in peers['channels']],
            'fully_synced':not info.get('warning_bitcoind_sync') and not info.get('warning_lightningd_sync')}
    except Exception as error:return {'unknown':True,'reason':type(error).__name__}

async def collect(args):
    start=time.time();samples=[];sample_lock=threading.Lock()
    def capture(record):
        with sample_lock:
            samples.append(record)
            if getattr(args,'trace_events',False):
                print(json.dumps({'kind':'driver_event','event':'observer_trace','data':record},allow_nan=False),flush=True)
    core=Core(args.core_cookie,capture=capture)
    per_key=getattr(args,'architecture_profile',None)=='direct_per_key'
    target=getattr(args,'target_ssh',None)
    if target is not None and re.fullmatch('[a-zA-Z0-9_-]+@[a-zA-Z0-9.-]+',target) is None:
        raise ValueError('explicit fixed SSH target identity required')
    if per_key and (not target or not getattr(args,'financial_context',None) or not getattr(args,'campaign_config',None)):
        raise ValueError('C requires explicit target and actual local financial configuration sources')
    ssh=['ssh','-T','-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=8',
         '-o','UserKnownHostsFile='+str(args.known_hosts),'-i',str(args.ssh_identity),target or 'abandon-observer@172.81.182.157']
    async def unavailable_lightning():
        return {'unknown':True,'reason':'C pilot has no declared funded Lightning route; full qualification remains held'}
    remote,info,before,genesis,internal,external=await asyncio.gather(
        public_command(ssh,node='target',method='snapshot',request={'kind':'snapshot'},timeout=25,capture=capture),
        public_command([str(args.driver)],node='public-server',method='info',request={'operation':'info','expected_server_pubkey':args.server_pubkey},timeout=20,capture=capture),
        asyncio.to_thread(core.call,'getblockchaininfo'),asyncio.to_thread(core.call,'getblockhash',0),
        unavailable_lightning() if per_key else lightning('abandon-simulation-lightning-internal-1',capture=capture),
        unavailable_lightning() if per_key else lightning('abandon-simulation-lightning-external-1',capture=capture))
    try:
        pool_status=await public_command(ssh,node='target',method='pool_status',request={'kind':'pool_status'},timeout=15,capture=capture)
    except Exception as error:pool_status={'complete':False,'reason':type(error).__name__}
    if genesis!=SIGNET_GENESIS or remote['genesis']!=SIGNET_GENESIS or remote['network']!='signet':raise ValueError('independent/target genesis mismatch')
    if info.get('status')!='ok' or info['data']['network']!='signet' or info['data']['server_pubkey']!=args.server_pubkey:raise ValueError('server handshake mismatch')
    wallet=remote.get('wallet')
    rounds=wallet.get('rounds') if isinstance(wallet,dict) else None
    points=rounds['confirmed_utxos'] if rounds is not None else None
    trusted=integer(rounds['trusted_balance'],'trusted rounds balance') if rounds is not None else None
    value=None;gap=None;owned_scripts=[]
    if points is None:gap=remote.get('wallet_scope') or 'read-only signer wallet inventory unavailable'
    elif len(points)>256 or len(points)!=len(set(points)):gap='inventory cap/duplicates; incremental chain inventory required'
    elif before['blocks']!=remote['height'] or before['bestblockhash']!=remote['tip_hash']:gap='independent and server chain tips differ'
    else:
        semaphore=asyncio.Semaphore(4)
        async def output(point):
            txid,index=point.split(':');integer(int(index),'outpoint index')
            if len(txid)!=64 or any(c not in '0123456789abcdef' for c in txid):raise ValueError('invalid inventory outpoint')
            async with semaphore:utxo=await asyncio.to_thread(core.call,'gettxout',txid,int(index),True)
            if not utxo or integer(utxo['confirmations'],'confirmations')<1:raise ValueError('inventory changed or unconfirmed')
            owned_scripts.append({'script':utxo['scriptPubKey']['hex'],'outpoint':point,'confirmations':utxo['confirmations'],
                'scope':'trusted rounds-wallet inventory, independent Core script/value'})
            return btc_to_sat(utxo['value'])
        try:
            async with asyncio.timeout(12):value=sum(await asyncio.gather(*(output(p) for p in points)))
        except Exception as error:gap=type(error).__name__
    try:await asyncio.to_thread(core.call,'getmempoolinfo')
    except Exception as error:capture({'kind':'observer.sample.raw','payload':{'node':'independent-core','method':'getmempoolinfo','error':type(error).__name__},'raw':None})
    ending=await asyncio.to_thread(core.call,'getblockchaininfo')
    stable=remote['stable_tip'] and before['bestblockhash']==ending['bestblockhash'] and ending['bestblockhash']==remote['tip_hash']
    if not stable:value=None;gap='tips changed or differ'
    result={'trace_samples':samples,'observed_at':start,'completed_at':time.time(),'height':remote['height'],'tip_hash':remote['tip_hash'],
        'identity':{'network':'signet','genesis':genesis,'container':remote['container'],'image_digest':remote['server_status']['image_digest'],'server_pubkey':info['data']['server_pubkey']},
        'stable_tip':stable,'initial_block_download':ending['initialblockdownload'] or remote['initial_block_download'],
        'server_status':remote['server_status'],'rounds_confirmed_sat':value,'confirmed_inventory_gap':gap,'rounds_owned_scripts':owned_scripts if stable else [],
        'rounds_trusted_sat':trusted,
        'timings':timing_projection(remote,info,per_key=per_key),
        'pool_status':pool_status,'lightning':{'operator':internal,'fixture_peer':external},'complete':False,
        'capabilities':{'lightning_configured':remote['lightning_configured'],'full_capital_attribution':False},
        'unknown_buckets':['customer liabilities and ownership graph','unique locked backing attribution','operator input reservations','watchman and realized fees'],
        'independent_chain':{'height':ending['blocks'],'headers':ending['headers'],'ibd':ending['initialblockdownload']}}
    if per_key:
        result.update(architecture_profile='direct_per_key',financial_pins=c_financial_pins(args,remote),
            runtime_transport='systemd',native_runtime=remote['native_runtime'])
    return result


def c_financial_pins(args,remote):
    """Bind root's reviewed build assertions to the actual local artifacts used.

    SDK provenance remains the reviewed immutable paired-build assertion; this
    function never discovers a source commit by inspecting an ELF or a manifest.
    """
    from .final_campaign import _pins
    from .runtime_startup import _read
    from .identity_bootstrap import _hash
    value,_=_read(args.financial_context)
    fields={'financial_pins','driver_config_path','driver_config_sha256','wallet_config_path','wallet_config_sha256'}
    if not isinstance(value,dict) or set(value)!=fields:raise ValueError('exact C public build/config context required')
    pins=value['financial_pins'];_pins(pins)
    if (remote.get('architecture_profile')!='direct_per_key' or remote.get('fallback_protocol')!=4
            or remote.get('runtime_transport')!='systemd' or remote.get('declared_financial_pins')!=pins
            or _hash(Path(args.driver))!=pins['driver_sha256']
            or _hash(Path(args.campaign_config))!=pins['configuration_sha256']):
        raise ValueError('actual C target/driver/campaign artifacts differ from reviewed context')
    actual=Path(os.environ.get('SIM_DRIVER_CONFIG',''))
    if (not actual.is_absolute() or str(actual)!=value['driver_config_path']
            or _hash(actual)!=value['driver_config_sha256']):
        raise ValueError('actual C native driver configuration differs')
    native,_=_read(actual)
    wallet=Path(value['wallet_config_path'])
    if (native.get('architecture_profile')!='direct_per_key' or native.get('network')!='signet'
            or native.get('wallet_config')!=str(wallet) or not wallet.is_absolute()
            or _hash(wallet)!=value['wallet_config_sha256']):
        raise ValueError('actual C native wallet configuration differs')
    daemons=remote.get('native_runtime',{})
    if set(daemons)!={'captaind','watchmand'} or any(
            row.get('running') is not True or pins['product_commit'] not in row.get('version','')
            for row in daemons.values()):raise ValueError('actual running C release version differs')
    return pins

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ['ssh-identity','known-hosts','core-cookie','driver']:p.add_argument('--'+key,type=Path,required=True)
    p.add_argument('--target-ssh');p.add_argument('--architecture-profile',choices=['direct_per_key'])
    p.add_argument('--financial-context',type=Path);p.add_argument('--campaign-config',type=Path)
    p.add_argument('--server-pubkey',required=True);p.add_argument('--trace-events',action='store_true');args=p.parse_args()
    print(json.dumps(asyncio.run(collect(args)),allow_nan=False))
if __name__=='__main__':main()

"""Actual UTXO-scan checkpoint plus complete bounded confirmed-block deltas.

A retained scan is never a fresh balance or zero proof. Each observation checks
its active-chain identity, applies every subsequent matching-script block event,
then rechecks every current coin and all matching-script mempool activity.
"""
import base64
import hashlib
import json
import os
import re
import urllib.request
from decimal import Decimal
from pathlib import Path

from .model import SIGNET_GENESIS,btc_to_sat,integer,canonical
from .owned_mempool import arguments,MAX_RESPONSE_BYTES
from .two_step_normal import digest,strict_json


def _read(path,maximum):
    path=Path(path);st=path.lstat()
    if path.is_symlink() or not path.is_file() or st.st_uid!=os.getuid() or st.st_mode&0o077 or not 0<=st.st_size<=maximum:
        raise ValueError('bounded private checkpoint original required')
    raw=path.read_bytes()
    if len(raw)!=st.st_size:raise ValueError('checkpoint original changed')
    return raw


def confirmed_activity(chain,blocks,scripts):
    """Separate confirmed-only method shape; existing mempool guard is unchanged."""
    if (not isinstance(blocks,list) or not 1<=len(blocks)<=144 or len(set(blocks))!=len(blocks)
            or any(not isinstance(value,str) or re.fullmatch('[0-9a-f]{64}',value) is None for value in blocks)):
        raise ValueError('bounded exact confirmed blockhash interval required')
    params=[blocks,arguments(set(scripts))[1],False]
    body=canonical({'jsonrpc':'2.0','id':1,'method':'getdescriptoractivity','params':params}).encode()
    if len(body)>512*1024 or not chain.url.startswith('http://127.0.0.1:'):
        raise ValueError('bounded owned confirmed activity request required')
    token=base64.b64encode(chain.credential.read_text().strip().encode()).decode()
    request=urllib.request.Request(chain.url,body,{'Content-Type':'application/json','Authorization':'Basic '+token})
    raw=None
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=12) as source:
            raw=source.read(2*1024*1024+1)
        if len(raw)>2*1024*1024:raw=None;raise ValueError('confirmed activity original exceeds bound')
        value=strict_json(raw,decimals=True)
        if (type(value.get('id')) is not int or value['id']!=1 or value.get('jsonrpc')!='2.0'
                or value.get('error') is not None or not isinstance(value.get('result'),dict)
                or set(value['result'])!={'activity'} or not isinstance(value['result']['activity'],list)
                or len(value['result']['activity'])>20000):
            raise ValueError('complete matching confirmed activity result required')
    except BaseException as error:
        chain._capture('getdescriptoractivity',tuple(params),None,type(error).__name__,raw)
        raise
    chain._capture('getdescriptoractivity',tuple(params),value['result'],None,raw)
    return value['result']


def apply_delta(coins,events,blocks,scripts,*,minimum_height):
    """Apply real receive/spend events; missing or ambiguous ancestry holds."""
    result={point:dict(value) for point,value in coins.items()};previous=minimum_height
    for row in events:
        height=integer(row['height'],'actual activity blockheight',1)
        if height<=minimum_height or height not in blocks or blocks[height]!=row['blockhash'] or height<previous:
            raise ValueError('confirmed activity interval/order/active block differs')
        previous=height;kind=row['type']
        if kind=='receive':
            point=row['txid']+':'+str(integer(row['vout'],'received output'));script=row['output_spk']['hex'];amount=btc_to_sat(row['amount'])
            if point in result or script not in scripts:raise ValueError('duplicate or foreign confirmed receive')
            result[point]={'script':script,'amount_sat':amount,'height':height}
        elif kind=='spend':
            point=row['prevout_txid']+':'+str(integer(row['prevout_vout'],'spent output'));coin=result.get(point)
            if coin is None or coin['script']!=row['prevout_spk']['hex'] or coin['amount_sat']!=btc_to_sat(row['amount']):
                raise ValueError('confirmed spend lacks exact checkpoint/received source')
            del result[point]
        else:raise ValueError('unknown matching-script confirmed activity kind')
    return result


def current_from_checkpoint(chain,members,actor_members,prepared,metadata,source_records,*,path,expected_sha256,prepared_sha256):
    from .private_source_package import relative
    raw=_read(path,4*1024*1024)
    if digest(raw)!=expected_sha256:raise ValueError('admitted descriptor checkpoint manifest differs')
    manifest=strict_json(raw);directory=Path(path).parent
    if (manifest['schema']!='actual-public-descriptor-checkpoint-v1' or manifest['genesis']!=SIGNET_GENESIS
            or manifest['prepared_sha256']!=prepared_sha256):
        raise ValueError('actual scan checkpoint source identity differs')
    if not 1<=len(manifest['files'])<=12000 or len(manifest['batches'])!=2:
        raise ValueError('bounded complete two-batch checkpoint required')
    originals={};size=0
    for name,entry in manifest['files'].items():
        relative(name);value=_read(directory/name,16*1024*1024);size+=len(value)
        if size>40*1024*1024 or entry!={'sha256':digest(value),'size_bytes':len(value)}:
            raise ValueError('actual checkpoint original content/aggregate differs')
        originals[name]=value
    scripts=strict_json(originals['scripts.json']);actors={row['actor']:row for row in prepared['actors']}
    windows={row['actor']:row for row in manifest['windows']}
    if set(actor_members)!=set(actors) or set(windows)!=set(actors) or len(windows)!=24 or not 1<=len(scripts)<=2000:
        raise ValueError('checkpoint must cover exact all24 public identities')
    initial=chain.identity();height=initial['blocks'];tip=initial['bestblockhash']
    if initial['chain']!='signet' or initial.get('initialblockdownload') is not False:
        raise ValueError('current synchronized independent signet required')
    result={}
    for actor,member_id in actor_members.items():
        window=windows[actor];native=metadata[actor];member=members[member_id];descriptor=actors[actor]['public_descriptor']
        if window['desc']!=descriptor or member['descriptors']!=[descriptor] or member['role']!='customer' or member['kind']!='wallet':
            raise ValueError('checkpoint descriptor differs from actual immutable member')
        interval=window['range']
        if interval[0]!=0 or type(interval[1]) is not int or not 19<=interval[1]<2000:raise ValueError('bounded scanned descriptor window required')
        rows={row['child_index']:script for script,row in scripts.items() if row['actor']==actor}
        if set(rows)!=set(range(interval[1]+1)):raise ValueError('checkpoint script window is incomplete')
        if native.get('wallet_database_exists') is False:
            proof=actors[actor];birth=proof['fresh_seed_birth_Core'];frontier=-1;reserved=[]
            if proof['created_utc'] is None or proof['native_wallet_opened'] is not False or birth is None or birth['chain']!='signet' or birth['blocks']>height:
                raise ValueError('absent existing wallet cannot become dormant-zero identity')
        else:
            frontier=integer(native['issued_frontier'],'actual current issued frontier')
            if (frontier>interval[1] or native['wallet']['descriptor']!=descriptor or native['wallet']['network']!='signet'
                    or len(native['last_revealed'])!=1 or native['last_revealed'][0]['last_revealed']!=frontier
                    or native['last_revealed'][0]['descriptor_id']!=hashlib.sha256(bytes.fromhex(rows[0])).hexdigest()):
                raise ValueError('current native issued frontier exceeds/mismatches actual scan coverage')
            reserved=[row['txid']+':'+str(integer(row['vout'],'actual locked output')) for row in native['locked_outpoints']]
        result[member_id]={'source_kind':'core_descriptor_scan','network':'signet','height':height,'tip_hash':tip,
            'public_descriptors':[descriptor],'pending_transactions':[],'reserved_outpoints':reserved,
            'discovery_gaps':[],'utxos':[],'issued_frontier':frontier,'scan_range':interval,'checkpoint_sha256':expected_sha256}
    points=set();covered=set()
    for batch in manifest['batches']:
        if not 1<=len(batch['windows'])<=16:raise ValueError('bounded scan batch required')
        batch_actors={row['actor'] for row in batch['windows']}
        if not batch_actors or covered&batch_actors or any(windows[row['actor']]!=row for row in batch['windows']):raise ValueError('scan batch membership repeated or substituted')
        covered|=batch_actors
        reply=strict_json(originals[batch['response']],decimals=True);request_name=batch['response'].replace('.response.','.request.')
        request=strict_json(originals[request_name]);expected=[{'desc':row['desc'],'range':row['range']} for row in batch['windows']]
        if (request!={'jsonrpc':'2.0','id':batch['request_id'],'method':'scantxoutset','params':['start',expected]}
                or type(reply.get('id')) is not int or reply['id']!=batch['request_id'] or reply.get('jsonrpc')!='2.0'
                or reply.get('error') is not None or reply['result'].get('success') is not True):
            raise ValueError('checkpoint lacks exact successful actual scan request/reply')
        scan=reply['result']
        if not isinstance(scan['unspents'],list) or len(scan['unspents'])>20000:raise ValueError('bounded actual scan output rows required')
        base=integer(batch['height'],'actual scan height',1)
        if (base>height or height-base>144 or scan['height']!=base or scan['bestblock']!=batch['tip_hash']
                or chain.call('getblockhash',base)!=batch['tip_hash']):raise ValueError('checkpoint reorged/stale or tip source differs')
        allowed={script:row for script,row in scripts.items() if row['actor'] in batch_actors};coins={}
        for row in scan['unspents']:
            point=row['txid']+':'+str(integer(row['vout'],'actual scan output'));script=row['scriptPubKey']
            if point in coins or script not in allowed:raise ValueError('checkpoint repeats or invents owned output')
            coins[point]={'script':script,'amount_sat':btc_to_sat(row['amount']),'height':integer(row['height'],'scan output height',1)}
        if btc_to_sat(scan['total_amount'])!=sum(v['amount_sat'] for v in coins.values()):raise ValueError('checkpoint total differs from actual scan rows')
        blocks={h:chain.call('getblockhash',h) for h in range(base+1,height+1)}
        if blocks:coins=apply_delta(coins,confirmed_activity(chain,list(blocks.values()),allowed)['activity'],blocks,allowed,minimum_height=base)
        for point,coin in coins.items():
            txid,index=point.rsplit(':',1);current=chain.call('gettxout',txid,int(index),False)
            if (point in points or current is None or current['bestblock']!=tip or current['confirmations']<1
                    or current['scriptPubKey']['hex']!=coin['script'] or btc_to_sat(current['value'])!=coin['amount_sat']
                    or height-current['confirmations']+1!=coin['height']):raise ValueError('checkpoint+delta differs from current confirmed Core output')
            points.add(point);owner=allowed[coin['script']];member=actor_members[owner['actor']]
            result[member]['utxos'].append({'outpoint':point,'amount_sat':coin['amount_sat'],'script':coin['script'],'descriptor_index':0,'child_index':owner['child_index']})
    if covered!=set(actors):raise ValueError('scan batches omit declared customer identity')
    if chain.call('getdescriptoractivity',*arguments(set(scripts)),max_response_bytes=MAX_RESPONSE_BYTES)!={'activity':[]}:
        raise ValueError('current matching-script mempool activity unresolved')
    final=chain.identity()
    if (final['chain'],final['blocks'],final['bestblockhash'],final['initialblockdownload'])!=('signet',height,tip,False):raise ValueError('independent chain changed during checkpoint delta')
    if not source_records:raise ValueError('fresh independent source originals required')
    for frame in result.values():frame['source_records']=[expected_sha256,*source_records]
    return result

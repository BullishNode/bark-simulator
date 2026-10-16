"""Current public-descriptor assets, bounded by actual issued-index provenance.

A UTXO scan establishes current assets only. It does not establish historical
costs, invoices, Ark ownership, reserved fee capital or a fresh wallet birthday.
"""
import time
import hashlib
from .model import SIGNET_GENESIS, btc_to_sat, integer
from .two_step_normal import digest


def scan_current(chain, members, actor_members, prepared, metadata, source_records):
    """Use explicitly authenticated seed-derivation and current public BDK rows.

    Caller retains all raw RPC replies through ChainReader.capture and supplies
    their hashes in source_records; no source-complete boolean is consumed.
    """
    started=time.monotonic();initial=chain.identity()
    if initial['chain']!='signet' or initial.get('initialblockdownload') is not False:
        raise ValueError('current synchronized signet identity required')
    height=initial['blocks'];tip=initial['bestblockhash'];scripts={};scans=[];result={}
    if prepared['genesis']!=SIGNET_GENESIS or prepared['wallets_opened']!=0 or prepared['financial_dispatches']!=0:
        raise ValueError('actual pure descriptor generation provenance differs')
    actors={row['actor']:row for row in prepared['actors']}
    if set(actor_members)!=set(actors) or len(actors)!=24:
        raise ValueError('all twenty-four declared customer identities required')
    for actor,member_id in actor_members.items():
        member=members[member_id];proof=actors[actor];native=metadata[actor]
        descriptor=proof['public_descriptor']
        if member['role']!='customer' or member['kind']!='wallet' or member['descriptors']!=[descriptor]:
            raise ValueError('pure-derived descriptor differs from immutable customer member')
        if native.get('wallet_database_exists') is False:
            fresh=proof['fresh_seed_birth_Core']
            if (proof['created_utc'] is None or proof['native_wallet_opened'] is not False
                    or fresh is None or fresh['chain']!='signet' or fresh['initialblockdownload'] is not False
                    or fresh['blocks']>height):
                raise ValueError('missing existing wallet is not a fresh dormant identity')
            frontier=-1;reserved=[]
        else:
            if native['wallet']['descriptor']!=descriptor or native['wallet']['network']!='signet':
                raise ValueError('current public BDK descriptor differs from pure seed derivation')
            frontier=integer(native['issued_frontier'],'actual issued descriptor frontier')
            reserved=[row['txid']+':'+str(integer(row['vout'],'actual locked output')) for row in native['locked_outpoints']]
        maximum=max(19,frontier)
        if maximum>=2000:raise ValueError('public descriptor issued frontier exceeds bounded source')
        details=chain.call('getdescriptorinfo',descriptor)
        if details.get('hasprivatekeys') is not False or details.get('descriptor')!=descriptor:
            raise ValueError('actual canonical public descriptor required')
        addresses=chain.call('deriveaddresses',descriptor,[0,maximum])
        if not isinstance(addresses,list) or len(addresses)!=maximum+1 or len(set(addresses))!=len(addresses):
            raise ValueError('actual public descriptor derivation window incomplete')
        for child,address in enumerate(addresses):
            value=chain.call('validateaddress',address)
            if value.get('isvalid') is not True or value.get('address')!=address:
                raise ValueError('actual derived public address invalid')
            script=value['scriptPubKey']
            if child==0 and frontier>=0 and (len(native['last_revealed'])!=1 or
                    native['last_revealed'][0]['descriptor_id']!=hashlib.sha256(bytes.fromhex(script)).hexdigest() or
                    native['last_revealed'][0]['last_revealed']!=frontier):
                raise ValueError('persisted issued frontier does not bind actual public descriptor script-zero hash')
            if script in scripts:raise ValueError('same public owning script assigned twice')
            scripts[script]={'member_id':member_id,'descriptor_index':0,'child_index':child}
        scans.append({'desc':descriptor,'range':[0,maximum]})
        result[member_id]={'source_kind':'core_descriptor_scan','network':'signet','height':height,'tip_hash':tip,
            'public_descriptors':[descriptor],'pending_transactions':[],'reserved_outpoints':reserved,
            'discovery_gaps':[],'utxos':[], 'issued_frontier':frontier,'scan_range':[0,maximum]}
    if len(scripts)>2000:raise ValueError('complete owned-script mempool window exceeds bound')
    # Each existing Core method guard limits a scan to sixteen descriptors.
    seen=set()
    for offset in range(0,len(scans),16):
        if time.monotonic()-started>150:raise ValueError('bounded descriptor source deadline exceeded')
        scan=chain.call('scantxoutset','start',scans[offset:offset+16],timeout=120)
        if (scan.get('success') is not True or scan.get('height')!=height or scan.get('bestblock')!=tip
                or not isinstance(scan.get('unspents'),list) or len(scan['unspents'])>20000):
            raise ValueError('current descriptor scan incomplete or tip changed')
        subtotal=0
        for row in scan['unspents']:
            point=row['txid']+':'+str(integer(row['vout'],'actual scanned output'))
            script=row['scriptPubKey'];owner=scripts.get(script)
            if owner is None or point in seen:raise ValueError('foreign or repeated descriptor scan output')
            seen.add(point);amount=btc_to_sat(row['amount']);subtotal+=amount
            coin=chain.call('gettxout',row['txid'],row['vout'],False)
            if (coin is None or coin['bestblock']!=tip or coin['scriptPubKey']['hex']!=script
                    or btc_to_sat(coin['value'])!=amount or coin.get('confirmations',0)<1
                    or row.get('height')!=height-coin['confirmations']+1):
                raise ValueError('descriptor scan differs from current confirmed Core coin')
            result[owner['member_id']]['utxos'].append({'outpoint':point,'amount_sat':amount,
                'script':script,'descriptor_index':0,'child_index':owner['child_index']})
        if btc_to_sat(scan['total_amount'])!=subtotal:raise ValueError('descriptor scan total differs from exact rows')
    from .owned_mempool import arguments, MAX_RESPONSE_BYTES
    mempool=chain.call('getdescriptoractivity',*arguments(set(scripts)),max_response_bytes=MAX_RESPONSE_BYTES)
    if mempool!={'activity':[]}:raise ValueError('current customer owned-script pending activity unresolved')
    final=chain.identity()
    if (final['chain']!='signet' or final.get('initialblockdownload') is not False
            or (final['blocks'],final['bestblockhash'])!=(height,tip)):
        raise ValueError('independent chain changed during customer discovery')
    if not source_records:raise ValueError('actual original Core source records required')
    for value in result.values():value['source_records']=list(source_records)
    return result

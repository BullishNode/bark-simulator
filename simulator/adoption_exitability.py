"""Narrow admission for the declared ordinary two-client adoption experiment.

A source-derived fee quote is a liquidity check, never a confirmation guarantee
or an executed exit. This path does not change SDK exit or claim margins.
"""
import hashlib
import json
import sqlite3
import tomllib
from collections import Counter
from pathlib import Path
from .model import btc_to_sat, integer
from .bundle_audit import decode_transaction
from .ownership import proof_matches_profile


async def collect_parameters(store,config,declaration):
    """Use the qualified pure decoder; do not open a client wallet or submit work."""
    from .round_adoption import _initialize,record_input_params
    from .process import json_command,public_command_capture
    command=getattr(config,'server_policy_command',())
    if len(command)!=1:raise ValueError('one qualified pure input decoder required')
    executable=Path(command[0])
    if not executable.is_absolute() or executable.is_symlink():raise ValueError('safe native decoder path required')
    with executable.open('rb') as stream:verifier_hash=hashlib.file_digest(stream,'sha256').hexdigest()
    _initialize(store)
    original={coin for ids in declaration['adoption']['exitability_policy']['original_coin_ids_by_actor'].values() for coin in ids}
    rows=[]
    for row in store.db.execute('SELECT c.*,k.actor FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey'):
        if row['actor'] not in declaration['actors']:continue
        current=store.db.execute('SELECT state FROM coin_observation WHERE coin_id=? ORDER BY observed_at DESC,action_id DESC LIMIT 1',(row['id'],)).fetchone()
        if current is None or (current['state'].casefold()=='spent' and row['id'] not in original):continue
        if not store.db.execute('SELECT 1 FROM round_input_params WHERE signed_hash=?',(row['signed_hash'],)).fetchone():rows.append(row)
    if len(rows)>16:raise ValueError('bounded original/client replacement parameter inventory required')
    for row in rows:
        request={'signed_vtxo':row['signed_vtxo'],'server_pubkey':declaration['server_pubkey']}
        response=await json_command(list(command),request,timeout=30,
            **public_command_capture(store,'adoption.input_decode',request))
        record_input_params(store,row['signed_vtxo'],response,declaration['server_pubkey'],verifier_hash)


def _submitted(store,declaration):
    """A completed original submission permits observations, never a replay."""
    from .round_adoption import _intent
    a=declaration['adoption'];previous=set(a['previous_action_ids'])
    rows=[row for row in store.db.execute("SELECT * FROM action WHERE operation='refresh_delegated'") if row['id'] not in previous]
    if not rows or (len(rows)==1 and rows[0]['state']=='queued'):return None
    if len(rows)!=1 or rows[0]['state']!='completed':raise ValueError('reconcile original refresh before further SDK progression')
    action=rows[0];intent=_intent(store,action)
    if (action['actor_id']!=a['actor'] or json.loads(action['args'])!={'input_vtxo_ids':a['input_coin_ids']}
            or sorted(intent['inputs'])!=sorted(a['input_coin_ids']) or action['fee_reservation_sat']>500
            or not json.loads(action['result'])['data'].get('round_state_id')):
        raise ValueError('original completed refresh intent differs')
    requests=store.db.execute("SELECT * FROM event WHERE kind='driver_request' AND json_extract(payload,'$.action_id')=?",(action['id'],)).fetchall()
    if len(requests)!=1:raise ValueError('original refresh request missing or ambiguous')
    request=json.loads(requests[0]['payload']);snapshot=store.db.execute('SELECT payload FROM snapshot WHERE id=?',(request['context']['snapshot_id'],)).fetchone()
    if snapshot is None:raise ValueError('original refresh admission snapshot missing')
    snapshot=json.loads(snapshot[0]);source=store.db.execute('SELECT * FROM event WHERE sequence=?',(snapshot['exploratory_readiness_sequence'],)).fetchone()
    if source is None or source['kind']!='exploratory_operating_readiness' or source['sequence']>=requests[0]['sequence']:
        raise ValueError('dated pre-submit exitability proof missing')
    proof=json.loads(source['payload']);clients=proof.get('adoption_exitability',{}).get('clients',{})
    if (proof['scope_id']!=declaration['id'] or proof['financial_pins']!=declaration['pins']
            or proof.get('ordinary_path_checked') is not True or proof.get('global_complete') is not False
            or proof['adoption_exitability'].get('minimum_original_headroom_blocks')!=24
            or proof['height']+24>=a['input_expiry_height']
            or (proof['height'],proof['tip_hash'])!=(request['context']['height'],request['context']['tip_hash'])
            or not 0<=requests[0]['observed_at']-proof['observed_at']<=90
            or set(clients)!=set(declaration['actors']) or any(v.get('allocation_native_known') is not True for v in clients.values())
            or request['request']['operation']!='refresh_delegated'
            or request['request']['action_id']!=action['id']
            or request['request']['args']!=json.loads(action['args'])
            or request['request']['maximum_fee_sat']!=action['fee_reservation_sat']
            or request['request']['expected_server_pubkey']!=declaration['server_pubkey']):
        raise ValueError('original refresh lacks its exact strict pre-submit admission')
    return {'action_id':action['id'],'proof_sequence':source['sequence'],'proof_hash':source['hash'],
        'replacement_outputs':[{'user_pubkey':key,'amount_sat':amount,'count':count}
            for (key,amount),count in sorted(intent['outputs'].items())]}


def check(store, chain, declaration, wallet_root, height):
    policy=declaration['adoption']['exitability_policy']
    if (set(policy)!={'minimum_original_headroom_blocks','wallet_configuration_sha256','fee_allocations','original_coin_ids_by_actor'}
            or policy['minimum_original_headroom_blocks']!=24
            or set(policy['fee_allocations'])!=set(declaration['actors']) or len(declaration['actors'])!=2
            or set(policy['original_coin_ids_by_actor'])!=set(declaration['actors'])
            or any(len(ids)!=2 or len(set(ids))!=2 for ids in policy['original_coin_ids_by_actor'].values())
            or sorted(policy['original_coin_ids_by_actor'][declaration['adoption']['actor']])
                !=sorted(declaration['adoption']['input_coin_ids'])):
        raise ValueError('exact two-client adoption exitability policy required')
    submitted=_submitted(store,declaration)
    root=Path(wallet_root).resolve();config=(root.parent/'config'/'wallet.toml').read_bytes()
    if hashlib.sha256(config).hexdigest()!=policy['wallet_configuration_sha256']:
        raise ValueError('actual client wallet configuration differs')
    settings=tomllib.loads(config.decode())
    if settings.get('vtxo_exit_margin')!=12 or settings.get('htlc_recv_claim_delta')!=18:
        raise ValueError('client exit and receive security margins must remain unchanged')
    rate=btc_to_sat(chain.call('estimatesmartfee',1,'CONSERVATIVE')['feerate']);rate_kwu=(rate+3)//4
    if rate<=0:raise ValueError('independent positive exit fee estimate required')
    clients={};all_cash_points=set()
    for actor in declaration['actors']:
        paths={};coins=[];stages=0;original=set(policy['original_coin_ids_by_actor'][actor]);seen_original=set();replacements=Counter()
        for row in store.db.execute('SELECT c.* FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey WHERE k.actor=?',(actor,)):
            current=store.db.execute('SELECT state FROM coin_observation WHERE coin_id=? ORDER BY observed_at DESC,action_id DESC LIMIT 1',(row['id'],)).fetchone()
            if current is None:raise ValueError('client holding state missing')
            state=current['state'].casefold()
            if row['id'] in original:seen_original.add(row['id'])
            if state=='spent':
                if row['id'] not in original:continue
                if submitted is None or actor!=declaration['adoption']['actor'] or row['id'] not in declaration['adoption']['input_coin_ids']:
                    raise ValueError('unrelated original client spend cannot be refresh progression')
            if submitted is not None and state=='spendable' and row['id'] not in original:
                allowed=Counter({(v['user_pubkey'],v['amount_sat']):v['count'] for v in submitted['replacement_outputs']})
                replacements[(row['pubkey'],row['amount_sat'])]+=1
                if actor!=declaration['adoption']['actor'] or replacements-allowed:
                    raise ValueError('new client holding differs from exact frozen replacement outputs')
            if state not in {'spendable','spent'}:
                from .round_adoption import _locked
                if (state!='locked' or submitted is None or actor!=declaration['adoption']['actor']
                        or row['id'] not in declaration['adoption']['input_coin_ids']
                        or _locked(store,actor,declaration['adoption']['input_coin_ids']) is None):
                    raise ValueError('unexpected conditional or pending client holding')
            proof=json.loads(row['proof']);path=proof.get('path',[])
            params=store.db.execute('SELECT proof FROM round_input_params WHERE signed_hash=?',(row['signed_hash'],)).fetchone()
            if params is None:raise ValueError('actual native decoded input exit parameters missing')
            params=json.loads(params[0])
            if (proof.get('signed_path_valid') is not True or proof.get('authorization_path_valid') is not True
                    or proof.get('conditional_steps')!=0 or proof.get('server_pubkey')!=declaration['server_pubkey']
                    or (submitted is None and proof.get('expiry_height')-height<=24)
                    or proof.get('id')!=row['id'] or proof.get('amount_sat')!=row['amount_sat']
                    or not proof_matches_profile(store,proof,{'user_pubkey':row['pubkey']})
                    or not 1<=len(path)<=3
                    or (params['id'],params['amount_sat'],params['expiry_height'],params['server_pubkey'],params['exit_delta'])
                        !=(row['id'],row['amount_sat'],proof['expiry_height'],declaration['server_pubkey'],12)
                    or params.get('candidate_user_pubkey')!=row['pubkey']
                    or params.get('client_owner_verified') is not False or params.get('chain_contract_verified') is not False):
                raise ValueError('ordinary signed path or original input headroom unqualified')
            previous=proof['chain_anchor'];anchor_txid,anchor_index=previous.rsplit(':',1)
            anchor=chain.call('gettxout',anchor_txid,int(anchor_index),True)
            if anchor is None or anchor['confirmations']<1:raise ValueError('ordinary exit anchor unavailable')
            for item in path:
                raw=bytes.fromhex(item['transaction']);decoded=decode_transaction(item['transaction'],public_body=True)
                # The admitted native ordinary paths have exactly one empty-script
                # input. Refuse every other wire shape rather than infer its timing.
                if (len(raw)<46 or raw[:5]!=b'\x03\x00\x00\x00\x01' or raw[41]!=0
                        or raw[42:46]!=bytes(4) or raw[-4:]!=bytes(4)
                        or decoded['txid']!=item['txid'] or decoded['inputs']!=[{'outpoint':previous}]):
                    raise ValueError('exit path has an unqualified lock, sequence or dependency')
                point=item['txid']+':'+str(item['output_index']);previous=point
                output=decoded['outputs'][item['output_index']]
                if (output['amount_sat'],output['script'])!=(item['output_amount_sat'],item['output_script']):
                    raise ValueError('signed exit output differs')
                paths[item['txid']]=raw
            if previous!=row['id'] or path[-1]['output_amount_sat']!=row['amount_sat']:
                raise ValueError('signed exit leaf identity differs')
            stages=max(stages,len(path));coins.append(row['id'])
        if (not coins or seen_original!=original or len(paths)>8
                or (submitted is None and (set(coins)!=original or len(paths)>4))):
            raise ValueError('bounded complete ordinary client paths required')
        # These are the pinned SDK's canonical child weight and 1.2 liquidity
        # margin. Actual wallet construction and market confirmation stay separate.
        # Add up to 43 WU for a P2WPKH funding witness over the SDK's P2TR
        # prediction, retaining its larger P2TR change output conservatively.
        quote=sum((rate_kwu*(len(raw)*4+68+609+43)+999)//1000 for raw in paths.values())
        quote=(quote*6+4)//5
        db=sqlite3.connect('file:'+str(root/actor/'db.sqlite')+'?mode=ro',uri=True);db.row_factory=sqlite3.Row
        try:
            db.execute('BEGIN');wallet=db.execute('SELECT descriptor,change_descriptor FROM bdk_wallet WHERE id=0').fetchone()
            locks={row['txid']+':'+str(row['vout']) for row in db.execute('SELECT txid,vout FROM bdk_wallet_locked_outpoints')}
            rows=[dict(row) for row in db.execute('SELECT txid,vout,value,hex(script) AS script FROM bdk_txouts ORDER BY txid,vout LIMIT 65')]
            native_txids={row[0] for row in db.execute('SELECT txid FROM bdk_txs ORDER BY txid LIMIT 129')}
            if wallet is None or len(rows)>64 or len(native_txids)>128:raise ValueError('bounded native fee wallet required')
            descriptors=dict(wallet)
        finally:db.close()
        owned=set()
        for descriptor in descriptors.values():
            if not descriptor:continue
            info=chain.call('getdescriptorinfo',descriptor)
            if info['hasprivatekeys'] is not False:raise ValueError('public fee wallet descriptor required')
            addresses=chain.call('deriveaddresses',info['descriptor'],[0,8])
            if len(addresses)!=9:raise ValueError('complete bounded descriptor derivation required')
            for address in addresses:
                owned.add(chain.call('validateaddress',address)['scriptPubKey'])
        allocation=policy['fee_allocations'][actor]
        if set(allocation)!={'txid','vout'}:raise ValueError('exact declared fee allocation required')
        allocation_native_known=(allocation['txid'] in native_txids and any(
            row['txid']==allocation['txid'] and row['vout']==allocation['vout'] for row in rows))
        tx=chain.tx(allocation['txid']);out=tx['vout'][integer(allocation['vout'],'fee allocation index')]
        if out['scriptPubKey']['hex'] not in owned or btc_to_sat(out['value'])!=20000:
            raise ValueError('declared 20000-sat allocation must derive from the native client wallet')
        rows.append({'txid':allocation['txid'],'vout':allocation['vout'],'value':btc_to_sat(out['value']),'script':out['scriptPubKey']['hex']})
        cash=0;seen=set()
        for row in rows:
            point=row['txid']+':'+str(row['vout'])
            if point in seen or point in locks:continue
            seen.add(point);coin=chain.call('gettxout',row['txid'],row['vout'],True)
            if coin is None:continue
            if coin['scriptPubKey']['hex'] not in owned:raise ValueError('fee output is not owned by client descriptor')
            if (btc_to_sat(coin['value'])!=row['value']
                    or coin['scriptPubKey']['hex']!=row['script'].lower()):raise ValueError('native fee output differs from chain')
            if coin['confirmations']>0:
                if point in all_cash_points:raise ValueError('same fee capital counted for both actors')
                all_cash_points.add(point);cash+=row['value']
        if cash<quote:raise ValueError('confirmed unreserved client exit fee cash insufficient')
        clients[actor]={'coin_ids':sorted(coins),'maximum_confirmation_stages':stages,'unique_parent_count':len(paths),
            'bip84_adjusted_1_2_margin_broadcast_quote_sat':quote,'confirmed_unreserved_fee_cash_sat':cash,
            'allocation_native_known':allocation_native_known}
    return {'minimum_original_headroom_blocks':24,'client_security_margins':{'M':12,'D':12,'C':18},
        'quote_sat_kvb':rate,'clients':clients,'confirmation_guarantee':False,'claim_drain_fee_calculated':False,
        'submitted_original_intent':submitted,
        'qualification_scope':'ordinary zero-delay signed paths and current confirmed fee liquidity only'}

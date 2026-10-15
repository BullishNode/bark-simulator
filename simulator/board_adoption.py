"""One original confirmed Board: cash/backing source and fee-free adoption only."""
import json
import hashlib
import os
import re
import sqlite3
import stat
import time
from pathlib import Path
from .final_campaign import _source_event, _action_pins
from .model import btc_to_sat, canonical, public_payload
from .fresh_cash_readiness import (_digest,_fresh,_empty_mempool,_current_operator_ranges,
    _operator_fee_funding,ECONOMIC_TABLES,METADATA_TABLES)

OPS=['sync','snapshot']


def _unique(store,kind,action_id,event_name=None):
    rows=store.db.execute("SELECT sequence FROM event WHERE kind=? AND json_extract(payload,'$.action_id')=?",(kind,action_id)).fetchall()
    values=[_source_event(store,row[0]) for row in rows]
    if event_name is not None:values=[item for item in values if item[1].get('event')==event_name]
    if len(values)!=1:raise ValueError('unique original Board '+kind+' source required')
    return values[0]


def _origin(store,chain):
    from .first_board_readiness import board_plan
    from .finite_funding import _plan
    plan=board_plan(store);action_id=plan['board_actions']['actor-01']
    boards=store.db.execute("SELECT * FROM action WHERE operation='board'").fetchall()
    if (len(boards)!=1 or boards[0]['id']!=action_id or boards[0]['actor_id']!='actor-01'
            or boards[0]['state']!='completed' or boards[0]['fee_reservation_sat']!=4000
            or json.loads(boards[0]['args'])!={'amount_sat':20000}):raise ValueError('one original completed actor-01 Board required')
    _action_pins(store,action_id,plan['pins'])
    response_event,reply=_unique(store,'driver_response',action_id);response=reply['response']
    result=json.loads(boards[0]['result']);resolution_proof=None
    if response.get('status')!='ok' or response.get('action_id')!=action_id:
        raise ValueError('original Board reply differs')
    if response!=result:
        # The existing read-only unknown-outcome resolver preserves the native
        # data and records its independently checked fee in a new wrapper. It
        # must have one authenticated original resolution event; a caller-made
        # wrapper or a repeated resolution never substitutes for that source.
        _,resolved=_unique(store,'unknown_outcome_resolved',action_id)
        resolution=result.get('resolution',{})
        resolution_proof=resolution.get('proof')
        if (result.get('action_id')!=action_id or result.get('status')!='ok'
                or result.get('data')!=response.get('data') or not isinstance(resolution_proof,dict)
                or resolved.get('actor')!='actor-01' or resolved.get('wallet_opened') is not False
                or resolved.get('monetary_request_retried') is not False
                or resolved.get('proof')!=resolution_proof
                or resolved.get('original_result')!=resolution.get('original_result')
                or resolution_proof.get('native_response_event_sequence')!=response_event['sequence']):
            raise ValueError('original Board positive resolution differs')
    data=response['data'];board=data['board'];ids=board['vtxos']
    if len(ids)!=1:raise ValueError('one original Board VTXO required')
    _,proposal=_unique(store,'driver_evidence',action_id,'board_proposal');proposal=proposal['data']
    _,quote=_unique(store,'driver_evidence',action_id,'board_fee_quote');quote=quote['data']
    _,runtime=_unique(store,'driver_evidence',action_id,'wallet_runtime_parameters');runtime=runtime['data']
    if (proposal.get('amount_sat')!=20000 or proposal.get('recycle_autosize') is not False
            or quote.get('source')!='SDK chain backend' or quote.get('used_fallback') is not False
            or quote.get('same_process') is not True or quote.get('regular_confirmation_target')!=3 or type(quote.get('fee_rate_sat_per_kwu')) is not int
            or not 1<=quote['fee_rate_sat_per_kwu']<=5000 or runtime.get('run_daemon') is not False
            or runtime.get('daemon_manual_sync') is not True or type(runtime.get('vtxo_exit_margin')) is not int
            or not 0<=runtime['vtxo_exit_margin']<=2000):raise ValueError('actual original Board quote/runtime differs')
    coin=store.db.execute('SELECT c.*,k.actor FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey WHERE c.id=?',(ids[0],)).fetchone()
    if coin is None or coin['actor']!='actor-01':raise ValueError('independent original signed Board ownership proof required')
    proof=json.loads(coin['proof']);anchor=proof['chain_anchor'];txid,index=anchor.rsplit(':',1)
    originals=[row for row in data.get('evidence',{}).get('coins',[]) if row.get('id')==ids[0]]
    if (len(originals)!=1 or originals[0].get('amount_sat')!=coin['amount_sat']
            or originals[0].get('user_pubkey')!=coin['pubkey']
            or hashlib.sha256(bytes.fromhex(originals[0]['signed_vtxo'])).hexdigest()!=coin['signed_hash']
            or data.get('fallback_script')!=proof.get('binding',{}).get('spk')
            or proposal.get('expiry_height')!=data.get('expiry_height')):
        raise ValueError('original native signed Board coin/fallback differs')
    if (proof.get('financial_pins')!=plan['pins'] or proof.get('authorization_path_valid') is not True
            or proof.get('signed_path_valid') is not True or proof.get('conditional_steps')!=0
            or proof.get('binding',{}).get('record_signature_valid') is not True
            or proof.get('binding',{}).get('account_child_verified') is not True
            or proposal['funding_txid']!=txid or data['expiry_height']!=proof['expiry_height']):
        raise ValueError('original ordinary Board signed path/binding differs')
    from .bundle_audit import decode_transaction
    decoded=decode_transaction(proposal['unsigned_funding_tx'],public_body=True)
    tx=chain.transaction(txid)
    if (tx.get('confirmations',0)<1 or decoded['txid']!=txid or decoded['outputs']!=tx['outputs']
            or [row['outpoint'] for row in decoded['inputs']]!=[row['outpoint'] for row in tx['inputs']]
            or len(tx['inputs'])!=1 or tx['inputs'][0]['amount_sat']!=50000 or len(tx['outputs'])!=2):
        raise ValueError('exact confirmed original50k Board funding required')
    outputs=[row for row in tx['outputs'] if row['vout']==int(index)]
    net=coin['amount_sat'];service=20000-net;miner=tx['fee_sat']
    if (len(outputs)!=1 or outputs[0]['amount_sat']!=20000 or board.get('amount')!=net or not 0<net<=20000
            or service!=data['sdk_service_fee_sat'] or service!=proposal['estimated_service_fee_sat']
            or miner!=data['planned_mining_fee_sat'] or miner!=proposal['planned_mining_fee_sat']
            or not 0<miner+service<=4000 or boards[0]['actual_fee_sat'] not in (None,miner+service)):
        raise ValueError('actual Board principal/miner/service amounts differ')
    if resolution_proof is not None:
        prior_tx=resolution_proof.get('chain_transaction',{})
        if (resolution_proof.get('actual_fee_sat')!=miner+service
                or result.get('actual_fee_sat')!=miner+service
                or any(prior_tx.get(key)!=tx.get(key) for key in ('txid','inputs','outputs','fee_sat','blockhash'))):
            raise ValueError('original resolved Board fee/confirmed transaction differs')
    raw=chain.tx(txid);weight=raw.get('weight');vsize=raw.get('vsize')
    if (type(weight) is not int or type(vsize) is not int or not decoded['weight']<=weight<=4000000
            or vsize!=(weight+3)//4 or not 1000*miner<=20000*vsize):
        raise ValueError('actual signed Board weight/rate exceeds observed ceiling')
    actual_rate={'weight_wu':weight,'vsize':vsize,'miner_fee_sat':miner,
        'actual_rate_sat_kvb_ceil':(1000*miner+vsize-1)//vsize,'independent_limit_sat_kvb':20000}
    funding=_plan(store)
    if funding['pins']!=plan['pins'] or funding['boundary_id']!=plan['boundary_id']:raise ValueError('original Board funding context differs')
    rows=store.db.execute("SELECT sequence FROM event WHERE kind='fixture_funding_confirmed' AND json_extract(payload,'$.batch')=?",('finite:'+funding['id'],)).fetchall()
    if len(rows)!=1:raise ValueError('original finite funding confirmation missing')
    _,funded=_source_event(store,rows[0][0]);actualfund=chain.transaction(funded['txid'])
    if (actualfund.get('confirmations',0)<1 or funded['financial_pins']!=plan['pins']
            or any(actualfund.get(key)!=funded['confirmed_transaction'].get(key) for key in ('inputs','outputs','fee_sat','blockhash'))):
        raise ValueError('independent original finite funding differs')
    return {'financial_pins':plan['pins'],'boundary_id':plan['boundary_id'],'board_action_id':action_id,
        'actor':'actor-01','native_response_sequence':response_event['sequence'],'native_response_sha256':_digest(response),
        'vtxo_id':ids[0],'net_liability_sat':net,'anchor':anchor,'anchor_output':outputs[0],
        'transaction':tx,'mining_fee_sat':miner,'service_charge_sat':service,'expiry_height':proof['expiry_height'],
        'exit_margin':runtime['vtxo_exit_margin'],'user_pubkey':coin['pubkey'],'binding':proof['binding'],
        'movement_id':board['movement_id'],'funding_fee_sat':actualfund['fee_sat'],'funding_plan':funding,'actual_rate':actual_rate,
        'funding_confirmation_sequence':rows[0][0]}


def _history(store,origin,reserved=None,*,allow_queued=False):
    queued=0
    for row in store.db.execute('SELECT * FROM action'):
        if row['id']==origin['board_action_id']:continue
        if reserved is not None and row['id']==reserved:continue
        if (allow_queued and row['state']=='queued' and row['actor_id']=='actor-01'
                and row['operation'] in OPS and row['fee_reservation_sat']==0 and json.loads(row['args'])=={}):
            queued+=1
            if queued>1:raise ValueError('only one serial adoption intent may wait')
            continue
        if (row['actor_id'] not in ('actor-01','actor-02','actor-04') or row['state']!='completed' or row['actual_fee_sat']!=0 or row['fee_reservation_sat']!=0
                or row['operation'] not in ('create','address','snapshot','sync') or json.loads(row['args'])!={}):
            raise ValueError('unrelated or unfinished action holds Board adoption')
    if store.db.execute("SELECT 1 FROM funding_batch WHERE state!='confirmed'").fetchone():raise ValueError('unknown funding holds Board adoption')


def _client_state(store,config,origin,height):
    from .identity_bootstrap import declaration,_context,_root,_sole_writer
    original=declaration(store);value=original['declaration'];_context(config,value,store=store);_sole_writer(value['wallet_root'])
    if (value['pins']!=origin['financial_pins'] or _root(value['wallet_root'])!=original['filesystem']
            or any(key.startswith('BARK_') for key in os.environ)):
        raise ValueError('original context/override-free Board adoption required')
    if origin['expiry_height']<=height+origin['exit_margin']+6:raise ValueError('Board near expiry; salvage path unavailable')
    results={}
    for actor in value['actors']:
        path=Path(value['wallet_root'])/actor/'db.sqlite'
        if any(stat.S_ISLNK(part.lstat().st_mode) for part in (path,*path.parents)):raise ValueError('client SQLite symlink')
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError('private actual client SQLite required')
        conn=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=2);conn.row_factory=sqlite3.Row
        conn.execute('PRAGMA query_only=ON');start=time.monotonic();conn.set_progress_handler(lambda:time.monotonic()-start>5,1000)
        try:
            conn.execute('BEGIN');tables={row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'bark_%'")}
            if conn.execute('SELECT max(value) FROM migrations').fetchone()[0]!=43 or not ECONOMIC_TABLES<=tables or len(tables)>64:raise ValueError('pinned economic schema required')
            counts={}
            allowed={'bark_vtxo','bark_vtxo_state','bark_wallet_action_checkpoint','bark_movements','bark_movements_output_vtxos'} if actor=='actor-01' else set()
            for table in sorted(tables):
                if re.fullmatch('bark_[a-z_]+',table) is None:raise ValueError('unknown economic table')
                count=conn.execute('SELECT count(*) FROM '+table).fetchone()[0];counts[table]=count
                if (table not in allowed|METADATA_TABLES and count!=0 or table in METADATA_TABLES and count>128
                        or table in allowed and count>4):raise ValueError('unrelated persisted monetary state holds adoption')
            if actor=='actor-01':
                rows=conn.execute('SELECT id,amount_sat,expiry_height FROM bark_vtxo').fetchall()
                if len(rows)!=1 or tuple(rows[0])!=(origin['vtxo_id'],origin['net_liability_sat'],origin['expiry_height']):raise ValueError('native Board coin differs')
                states=conn.execute('SELECT vtxo_id,state_kind FROM bark_vtxo_state ORDER BY id').fetchall()
                if not states or any(row['vtxo_id']!=origin['vtxo_id'] or row['state_kind'] not in ('Locked','Spendable') for row in states):raise ValueError('native Board state differs')
                movements=conn.execute('SELECT id,status,subsystem_name,effective_balance,offchain_fee FROM bark_movements').fetchall()
                if (len(movements)!=1 or str(movements[0]['id'])!=str(origin['movement_id']) or movements[0]['subsystem_name']!='bark.board'
                        or movements[0]['status'] not in ('pending','successful') or movements[0]['effective_balance']!=origin['net_liability_sat']
                        or movements[0]['offchain_fee']!=origin['service_charge_sat']):raise ValueError('native original Board movement differs')
                edges=conn.execute('SELECT movement_id,vtxo_id FROM bark_movements_output_vtxos').fetchall()
                if len(edges)!=1 or str(edges[0]['movement_id'])!=str(origin['movement_id']) or edges[0]['vtxo_id']!=origin['vtxo_id']:raise ValueError('native original Board movement edge differs')
                # Fixed JSON projection: never load/export the PSBT or private payload.
                checkpoints=conn.execute("SELECT id,json_extract(CAST(payload AS TEXT),'$.Board.id'),json_extract(CAST(payload AS TEXT),'$.Board.vtxo_id'),json_extract(CAST(payload AS TEXT),'$.Board.amount'),json_extract(CAST(payload AS TEXT),'$.Board.movement_id'),json_type(CAST(payload AS TEXT),'$.Board.progress.Confirming') FROM bark_wallet_action_checkpoint").fetchall()
                expected_id='board.'+origin['anchor'].replace(':','.')
                if (len(checkpoints)>1 or checkpoints and tuple(checkpoints[0])!=(expected_id,expected_id,origin['vtxo_id'],origin['net_liability_sat'],origin['movement_id'],'object')
                        or not checkpoints and (states[-1]['state_kind']!='Spendable' or movements[0]['status']!='successful')):
                    raise ValueError('only original Confirming Board checkpoint or completed adoption allowed')
                results[actor]={'counts':counts,'state':states[-1]['state_kind'],'checkpoint_count':len(checkpoints),'movement_status':movements[0]['status']}
            else:results[actor]={'counts':counts}
        finally:conn.close()
    return results


def _database(database,prior,origin):
    if (database.get('kind')!='closed_frontier' or database.get('database_tables_complete') is not True
            or database.get('inventory_consistent') is not True or database.get('read_only') is not True
            or set(database.get('rows',{}))!=set(prior['rows'])):raise ValueError('complete original nineteen-table frontier required')
    rows=database['rows'];allowed={'coins','pending_boards','links','journal_links','records','journal_records'}
    if any(items for name,items in rows.items() if name not in allowed):raise ValueError('unrelated server monetary frontier holds adoption')
    if any(rows[name]!=prior['rows'][name] for name in ('records','journal_records')):raise ValueError('immutable customer records changed')
    expected={'user_pubkey':origin['user_pubkey'],'mailbox_pk':origin['binding']['mailbox_pk'],'child_index':origin['binding']['child_index']}
    for name in ('links','journal_links'):
        if sorted(rows[name],key=canonical)!=sorted(prior['rows'][name]+([expected] if expected not in prior['rows'][name] else []),key=canonical):raise ValueError('original Board owner admission differs')
    coins={coin['vtxo_id']:coin for coin in rows['coins']}
    if len(coins)!=len(rows['coins']) or set(coins) not in ({origin['anchor']},{origin['anchor'],origin['vtxo_id']}):raise ValueError('one original Board frontier only')
    for point,coin in coins.items():
        anchor=point==origin['anchor']
        if (coin['anchor_point']!=origin['anchor'] or coin['amount']!=(20000 if anchor else origin['net_liability_sat'])
                or coin['expiry']!=origin['expiry_height'] or coin['policy_type']!=('expiry' if anchor else 'pubkey')
                or coin['spend_state']!=('spent' if anchor else 'spendable')
                or coin['oor_spent_txid']!=(origin['vtxo_id'].split(':')[0] if anchor else None)
                or any(coin.get(key) is not None for key in ('spent_in_round','offboarded_in','onchain_spent_txid','onchain_spent_height'))):raise ValueError('original Board server state differs')
    if (origin['vtxo_id'] not in coins and not rows['pending_boards']
            or rows['pending_boards'] not in ([],[{'vtxo_id':origin['vtxo_id'],'expiry':origin['expiry_height']}] )):raise ValueError('foreign pending Board')
    return {'registered':origin['vtxo_id'] in coins,'pending_board_retained':bool(rows['pending_boards'])}


async def collect_board_adoption_sources(store,config,chain,bank_rpc,*,cash_source_sequence,current_startup_path):
    return await _collect_backing_sources(store,config,chain,bank_rpc,
        cash_source_sequence=cash_source_sequence,current_startup_path=current_startup_path,
        history_validator=_history,client_validator=_client_state,database_validator=_database,
        source_kind='original_board_adoption_sources_verified')


async def _collect_backing_sources(store,config,chain,bank_rpc,*,cash_source_sequence,current_startup_path,
        history_validator,client_validator,database_validator,source_kind):
    """Observe six current cash wallets plus one separately verified Board anchor."""
    from .runtime_startup import _read
    from .funding_bank import collect_funding_bank_source
    from .process import json_command,public_command_capture
    from .model import SIGNET_GENESIS
    if (config.network!='signet' or config.expected_genesis!=SIGNET_GENESIS or not config.inventory_command
            or getattr(store,'trace',None) is None):raise ValueError('actual traced signet Board sources required')
    started=time.monotonic();origin=_origin(store,chain);history_validator(store,origin)
    event,cash=_source_event(store,cash_source_sequence)
    if (event['kind']!='finite_fresh_cash_sources_verified' or cash.get('financial_pins')!=origin['financial_pins']
            or cash.get('boundary_id')!=origin['boundary_id'] or cash.get('complete') is not True
            or cash.get('funding_confirmation_sequence')!=origin['funding_confirmation_sequence']
            or set(cash['actors'])!={'actor-01','actor-02','actor-04'}):raise ValueError('original pre-Board complete cash source required')
    before=chain.identity();tip=(before['blocks'],before['bestblockhash'])
    if before.get('chain')!='signet' or before.get('initialblockdownload') is not False:raise ValueError('synced independent signet required')
    client_validator(store,config,origin,tip[0]);current,current_sha=_read(current_startup_path)
    from .confirmed_scan import confirmed_scan
    specs=_current_operator_ranges(cash,current,tip)
    scripts,scans,scan,scan_provenance=confirmed_scan(store,config,chain,current,
        pins=origin['financial_pins'],boundary_id=origin['boundary_id'],members=cash['members'],specs=specs,tip=tip)
    expected={}
    for member,sequence in cash['inventory_sequences'].items():
        prior,inventory=_source_event(store,sequence)
        if prior['kind']!='treasury_inventory' or inventory['member_id']!=member or inventory['financial_pins']!=origin['financial_pins']:raise ValueError('original pre-Board cash inventory differs')
        for coin in inventory['utxos']:
            if coin['outpoint'] in expected:raise ValueError('duplicate original physical cash')
            expected[coin['outpoint']]={**coin,'member_id':member}
    transaction=origin['transaction'];spent=transaction['inputs'][0]['outpoint'];opening=expected.get(spent)
    if (opening is None or opening['member_id']!='actor-01' or opening['amount_sat']!=50000
            or transaction['inputs'][0]['script']!=opening['script']):raise ValueError('Board did not consume original declared customer50k')
    del expected[spent]
    for output in transaction['outputs']:
        point=transaction['txid']+':'+str(output['vout'])
        if point==origin['anchor']:continue
        owner=scripts.get(output['script'])
        if owner is None or owner['member_id']!='actor-01':raise ValueError('Board change not in original customer descriptor')
        expected[point]={**owner,'amount_sat':output['amount_sat'],'script':output['script']}
    observed={};total=0
    for coin in scan['unspents']:
        point=coin['txid']+':'+str(coin['vout']);amount=btc_to_sat(coin['amount']);total+=amount
        if point in observed or point not in expected or (amount,coin['scriptPubKey'])!=(expected[point]['amount_sat'],expected[point]['script']):raise ValueError('Board cash source has extra/missing/changed asset')
        observed[point]=expected[point]
    if len(observed)>2000 or set(observed)!=set(expected) or total!=btc_to_sat(scan['total_amount']):raise ValueError('complete Board cash footprint differs')
    anchor=origin['anchor_output'];physical={**observed,origin['anchor']:{'member_id':'original-board-backing','amount_sat':20000,'script':anchor['script']}}
    for point,coin in physical.items():
        txid,index=point.rsplit(':',1);actual=chain.call('gettxout',txid,int(index),True)
        if (actual is None or actual.get('confirmations',0)<1 or btc_to_sat(actual['value'])!=coin['amount_sat']
                or actual['scriptPubKey']['hex']!=coin['script']):raise ValueError('confirmed cash/Board backing unavailable or pending-spent')
    physical_total=sum(coin['amount_sat'] for coin in physical.values())
    if physical_total!=665454-origin['funding_fee_sat']-origin['mining_fee_sat']:raise ValueError('cash plus single physical Board anchor does not conserve capital')
    mempool=_empty_mempool(chain,set(scripts)|{anchor['script']},started)
    bankseq=collect_funding_bank_source(store,bank_rpc,chain);_,bank=_source_event(store,bankseq)
    expected_bank={point:coin for point,coin in observed.items() if coin['member_id']=='bank'}
    bank_points={row['txid']+':'+str(row['vout']):row for row in bank['listunspent']}
    if (bank['source_identity']['wallet_name']!=origin['funding_plan']['bank_wallet_name'] or (bank['height'],bank['tip_hash'])!=tip
            or set(bank_points)!=set(expected_bank) or any(bank.get(key)!=[] for key in ('pending_transactions','pending_parents','locked_coins','listlockunspent'))
            or btc_to_sat(bank['getbalances']['mine']['trusted'])!=sum(coin['amount_sat'] for coin in expected_bank.values())
            or btc_to_sat(bank['getbalances']['mine']['untrusted_pending'])!=0):raise ValueError('actual complete bank closing source differs')
    for point,coin in bank_points.items():
        if (btc_to_sat(coin['amount'])!=expected_bank[point]['amount_sat'] or coin['scriptPubKey']!=expected_bank[point]['script']
                or coin.get('spendable') is not True or coin.get('safe') is not True):raise ValueError('actual bank control differs')
    _,prior=_source_event(store,cash['database_source_sequence'])
    request={'kind':'closed_frontier'}
    database=await json_command(list(config.inventory_command),request,timeout=25,**public_command_capture(store,'board_adoption.closed_frontier',request))
    public_payload(database);server=database_validator(database,prior['response'],origin)
    native=client_validator(store,config,origin,tip[0]);history_validator(store,origin)
    ending=chain.identity()
    if (ending.get('initialblockdownload') is not False or (ending['blocks'],ending['bestblockhash'])!=tip or time.monotonic()-started>180):raise ValueError('Board source changed tip or exceeded180s')
    sequences={}
    with store.transaction():
        for member in cash['members']:
            coins=[{'outpoint':point,'amount_sat':coin['amount_sat'],'script':coin['script'],'descriptor_index':coin['descriptor_index'],'child_index':coin['child_index']}
                for point,coin in observed.items() if coin['member_id']==member['id']]
            store._event('treasury_inventory',{'member_id':member['id'],'identity':member['identity'],'financial_pins':origin['financial_pins'],
                'height':tip[0],'tip_hash':tip[1],'complete':True,'utxos':coins,'scope':'current descriptor cash only; original Board anchor separately counted exactly once'})
            sequences[member['id']]=store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
        source={'financial_pins':origin['financial_pins'],'boundary_id':origin['boundary_id'],'members':cash['members'],
            'height':tip[0],'tip_hash':tip[1],'observed_at':time.time(),'complete':True,'origin':origin,
            'cash_source_sequence':cash_source_sequence,'inventory_sequences':sequences,'descriptor_ranges':scans,
            'range_runtime_source_sha256':current_sha,'bank_source_sequence':bankseq,'database':database,'server':server,
            'confirmed_scan':scan_provenance,
            'native':native,'mempool':mempool,'physical_assets':physical,'physical_total_sat':physical_total,
            'net_liability_sat':origin['net_liability_sat'],'scope':'six cash wallets plus one signed original Board anchor; liability separate; source observation only'}
        public_payload(source);store._event(source_kind,source)
        sequence=store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
    return {'source_sequence':sequence,'source':source}


def validate_adoption_scope(store,config,proof,*,operation,maximum_fee_sat,reserved_action_id):
    scope=proof.get('board_adoption_scope')
    if (not isinstance(scope,dict) or set(scope)!={'actor','board_action_id','source_sequence','maximum_fee_sat','args'}
            or scope['actor']!='actor-01' or type(scope['maximum_fee_sat']) is not int or scope['maximum_fee_sat']!=0 or scope['args']!={}
            or proof.get('operation_scope')!=OPS or operation not in OPS or type(maximum_fee_sat) is not int or maximum_fee_sat!=0
            or 'client_action_scope' in proof or 'board_action_scope' in proof):raise ValueError('exact original Board adoption scope required')
    event,source=_source_event(store,scope['source_sequence']);origin=source['origin']
    if (event['kind']!='original_board_adoption_sources_verified' or origin['board_action_id']!=scope['board_action_id']
            or source['financial_pins']!=proof.get('financial_pins') or source['boundary_id']!=proof.get('boundary_id')
            or (source['height'],source['tip_hash'])!=(proof.get('height'),proof.get('tip_hash'))):raise ValueError('original Board adoption source context differs')
    _fresh(source['observed_at']);_history(store,origin,reserved_action_id,allow_queued=reserved_action_id is None)
    _client_state(store,config,origin,proof['height'])
    if reserved_action_id is not None:
        row=store.db.execute('SELECT * FROM action WHERE id=?',(reserved_action_id,)).fetchone()
        if (row is None or row['actor_id']!='actor-01' or row['operation']!=operation or row['state']!='dispatched'
                or row['fee_reservation_sat']!=0 or json.loads(row['args'])!={}):raise ValueError('original serial zero-fee adoption action required')
        _action_pins(store,reserved_action_id,proof['financial_pins'])


def record_board_adoption_readiness(store,config,chain,*,source_sequence,runtime_source_sequence,current_startup_path):
    _,source=_source_event(store,source_sequence)
    scope={'board_adoption_scope':{'actor':'actor-01','board_action_id':source['origin']['board_action_id'],
        'source_sequence':source_sequence,'maximum_fee_sat':0,'args':{}}}
    return _record_backing_readiness(store,config,chain,source_sequence=source_sequence,
        runtime_source_sequence=runtime_source_sequence,current_startup_path=current_startup_path,
        source_kind='original_board_adoption_sources_verified',history_validator=_history,
        client_validator=_client_state,allowed_operations=OPS,action_scope=scope,scope_validator=validate_adoption_scope,scope_description='only original confirmed Board adoption; no new principal/signing intent or Arkoor permission')


def _record_backing_readiness(store,config,chain,*,source_sequence,runtime_source_sequence,current_startup_path,
        source_kind,history_validator,client_validator,allowed_operations,action_scope,scope_validator,scope_description):
    from .runtime_startup import _read
    from .operating_limits import envelope,fee_totals
    from .treasury import boundary,capture_assets
    event,source=_source_event(store,source_sequence)
    if event['kind']!=source_kind or source.get('complete') is not True:raise ValueError('original complete Board adoption source required')
    _fresh(source['observed_at']);origin=_origin(store,chain)
    if origin!=source['origin']:raise ValueError('original Board source changed')
    history_validator(store,origin)
    from .target_epochs import verified_runtime_source
    current,current_sha=_read(current_startup_path)
    runtime=verified_runtime_source(store,runtime_source_sequence,
        origin_pins=origin['financial_pins'],current_source_sha256=current_sha)
    _fresh(runtime['observed_at']);limits=envelope(store,config);treasury=boundary(store)
    if (limits['pins']!=source['financial_pins'] or treasury['members']!=source['members'] or treasury['id']!=source['boundary_id']
            or runtime['effective_fee_ceilings_sat_kvb']!=limits['fee_ceilings_sat_kvb']
            or any(limits.get('operation_fee_paths',{}).get(operation)!=['sweep','payout'] for operation in allowed_operations)):
        raise ValueError('original immutable adoption envelope/membership differs')
    cash=capture_assets(store,source['inventory_sequences'],chain)
    anchor=source['physical_assets'][origin['anchor']];txid,index=origin['anchor'].rsplit(':',1)
    coin=chain.call('gettxout',txid,int(index),True)
    if (coin is None or coin.get('confirmations',0)<1 or btc_to_sat(coin['value'])!=20000 or coin['scriptPubKey']['hex']!=anchor['script']
            or cash['total_msat']+20000000!=source['physical_total_sat']*1000
            or (cash['height'],cash['tip_hash'])!=(source['height'],source['tip_hash'])):raise ValueError('current cash plus original signed anchor differs')
    available=_operator_fee_funding(store,source,cash,current)
    native=client_validator(store,config,origin,source['height'])
    # Only the miner fee leaves this operator+customer treasury. The existing
    # client fee reconciler retains the total customer charge; the service
    # component stays inside the physical Board anchor.
    cost={'monetary_id':'bitcoin-miner:'+origin['transaction']['txid'],'action_id':origin['board_action_id'],
        'financial_pins':origin['financial_pins'],'budget':'ordinary','amount_msat':origin['mining_fee_sat']*1000,
        'mining_fee_sat':origin['mining_fee_sat'],'service_charge_sat':origin['service_charge_sat'],
        'customer_total_fee_sat':origin['mining_fee_sat']+origin['service_charge_sat'],
        'service_charge_is_boundary_cost':False,'source_sequence':source_sequence,
        'scope':'one original Board miner cost; internal service transfer and total customer charge are separate metadata'}
    existing=store.db.execute("SELECT sequence FROM event WHERE kind='financial_cost_verified' AND json_extract(payload,'$.monetary_id')=?",(cost['monetary_id'],)).fetchall()
    if existing:
        if len(existing)!=1:raise ValueError('duplicate original Board financial cost')
        _,old=_source_event(store,existing[0][0])
        if any(old.get(key)!=value for key,value in cost.items() if key!='source_sequence'):raise ValueError('original Board financial cost changed')
    else:store.event('financial_cost_verified',cost)
    used=fee_totals(store,origin['financial_pins'])
    if used!={'ordinary':(origin['funding_fee_sat']+origin['mining_fee_sat'])*1000,'urgent':0}:
        raise ValueError('exact original funding and Board fee budget required')
    remaining={key:limits['fee_budgets_msat'][key]-used[key] for key in ('ordinary','urgent')}
    if min(remaining.values())<0 or available<sum(remaining.values()):raise ValueError('eligible operator cash cannot back remaining budgets')
    rate=btc_to_sat(chain.call('estimatesmartfee',6)['feerate'])
    if not 1<=rate<=min(limits['fee_ceilings_sat_kvb'][path] for path in ('sweep','payout')):raise ValueError('actual affordable fee estimate required')
    tip=chain.identity()
    if tip.get('initialblockdownload') is not False or (tip['blocks'],tip['bestblockhash'])!=(source['height'],source['tip_hash']):raise ValueError('adoption tip changed')
    _fresh(source['observed_at']);_fresh(runtime['observed_at'])
    receipt={'financial_pins':source['financial_pins'],'boundary_id':source['boundary_id'],'height':source['height'],'tip_hash':source['tip_hash'],
        'observed_at':time.time(),'complete':True,'operation_scope':allowed_operations,**action_scope,'effective_fee_ceilings_sat_kvb':limits['fee_ceilings_sat_kvb'],
        'capital_exposure_msat':source['physical_total_sat']*1000,'available_fee_funding_msat':available,'estimated_fee_rate_sat_kvb':rate,
        'net_liability_sat':origin['net_liability_sat'],'runtime_source_sequence':runtime_source_sequence,'native_economic_state':native,
        'pool_ready':False,'channel_route_ready':False,'scope':scope_description}
    scope_validator(store,config,receipt,operation=allowed_operations[0],maximum_fee_sat=0,reserved_action_id=None)
    public_payload(receipt);store.event('financial_operating_readiness',receipt)
    return {'operating_readiness_sequence':store.db.execute('SELECT max(sequence) FROM event').fetchone()[0],**receipt}

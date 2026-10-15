"""Narrow first-sync admission for a confirmed cash-only finite cohort.

SDK sync can drive persisted monetary actions. Empty economic state must be
observed independently; a stale customer BDK graph is never called fresh here.
"""
import hashlib
import json
import os
import re
import sqlite3
import stat
import time
from pathlib import Path

from .final_campaign import _source_event
from .identity_bootstrap import declaration
from .model import SIGNET_GENESIS, btc_to_sat, canonical, public_payload
from .architecture import DIRECT_PER_KEY,profile


def _policy(store):
    from .finite_funding_readiness import _policy as source_policy
    return source_policy(store)

OPERATIONS = ['sync', 'snapshot', 'address']
ECONOMIC_TABLES = {
    'bark_vtxo', 'bark_vtxo_state', 'bark_pending_board',
    'bark_wallet_action_checkpoint', 'bark_round_state',
    'bark_pending_lightning_receive', 'bark_lightning_send',
    'bark_settled_lightning_receive', 'bark_paid_invoice',
    'bark_exit_states', 'bark_exit_child_transactions', 'bark_movements',
    'bark_movements_sent_to', 'bark_movements_received_on',
    'bark_movements_input_vtxos', 'bark_movements_output_vtxos',
    'bark_movements_exited_vtxos',
}
METADATA_TABLES = {'bark_properties', 'bark_fallback_record',
                   'bark_vtxo_key', 'bark_mailbox_checkpoint'}


def validate_client_action_scope(store,proof,*,operation,maximum_fee_sat,reserved_action_id):
    """An optional source restriction only narrows the ordinary preflight."""
    if 'client_action_scope' not in proof:return
    scope=proof['client_action_scope']
    bootstrap=declaration(store)
    count=2 if profile(store)==DIRECT_PER_KEY else 3
    if (not isinstance(scope,dict) or set(scope)!={'actors','operations','maximum_fee_sat','args'}
            or not isinstance(scope['actors'],list) or len(scope['actors'])!=count
            or any(not isinstance(actor,str) for actor in scope['actors'])
            or len(set(scope['actors']))!=count or bootstrap is None
            or set(scope['actors'])!=set(bootstrap['declaration']['actors'])
            or proof.get('financial_pins')!=bootstrap['declaration']['pins']
            or scope['operations']!=OPERATIONS or proof.get('operation_scope')!=OPERATIONS
            or type(scope['maximum_fee_sat']) is not int or scope['maximum_fee_sat']!=0
            or scope['args']!={} or operation not in OPERATIONS or maximum_fee_sat!=0):
        raise ValueError('fresh-cash client action scope differs from original cohort')
    if reserved_action_id is None:return  # Readiness probe never invokes a wallet.
    row=store.db.execute('SELECT actor_id,operation,args,fee_reservation_sat,state FROM action WHERE id=?',
                        (reserved_action_id,)).fetchone()
    if (row is None or row['actor_id'] not in scope['actors'] or row['operation']!=operation
            or json.loads(row['args'])!={} or row['fee_reservation_sat']!=0 or row['state']!='dispatched'):
        raise ValueError('fresh-cash original native action context differs')


def observe_empty_client_economics(store,config):
    """Read counts from all three actual owning SQLite files, without payloads."""
    from .identity_bootstrap import _context,_root,_sole_writer
    original=declaration(store)
    if original is None:raise ValueError('original fresh cash bootstrap missing')
    value=original['declaration'];_context(config,value);_sole_writer(value['wallet_root'])
    if _root(value['wallet_root'])!=original['filesystem']:
        raise ValueError('fresh-cash wallet root identity changed')
    result={}
    for actor in value['actors']:
        path=Path(value['wallet_root'])/actor/'db.sqlite'
        for part in (path,*path.parents):
            if stat.S_ISLNK(part.lstat().st_mode):raise ValueError('fresh-cash client SQLite symlink refused')
        info=path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid()
                or stat.S_IMODE(info.st_mode)!=0o600):
            raise ValueError('actual private owning client SQLite required')
        started=time.monotonic()
        connection=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=2)
        connection.execute('PRAGMA query_only=ON')
        connection.set_progress_handler(lambda:time.monotonic()-started>5,1000)
        try:
            connection.execute('BEGIN')
            version=connection.execute('SELECT max(value) FROM migrations').fetchone()[0]
            tables={row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'bark_%'")}
            if version!=43 or not ECONOMIC_TABLES<=tables or len(tables)>64:
                raise ValueError('complete pinned client economic schema required')
            counts={}
            for table in sorted(tables):
                if re.fullmatch('bark_[a-z_]+',table) is None:raise ValueError('unknown client economic schema')
                count=connection.execute('SELECT count(*) FROM '+table).fetchone()[0]
                if table not in METADATA_TABLES and count!=0:
                    raise ValueError('fresh-cash client has existing monetary state')
                if table in METADATA_TABLES and count>128:
                    raise ValueError('client metadata footprint exceeds fresh cohort bound')
                counts[table]=count
            result[actor]={'schema_version':version,'table_counts':counts,'read_only':True,
                'device':info.st_dev,'inode':info.st_ino,'scope':'actual empty economic tables; onchain BDK freshness not inferred'}
        finally:connection.close()
    receipt={'financial_pins':value['pins'],'bootstrap_id':value['id'],
        'actors':value['actors'],'clients':result,'observed_at':time.time(),
        'complete':True,'scope':'empty persisted customer economic state only; not financial readiness'}
    public_payload(receipt);store.event('fresh_cash_client_economics_verified',receipt)
    return store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]


def _digest(value):return hashlib.sha256(canonical(value).encode()).hexdigest()


def _fresh(value):
    if type(value) not in (int,float) or not 0<=time.time()-value<=90:
        raise ValueError('fresh actual cash source required')


def _phase_history(store,pins,actors):
    if (store.db.execute("SELECT 1 FROM action WHERE state!='completed' OR actual_fee_sat IS NOT 0 "
            "OR fee_reservation_sat!=0 OR args!='{}' LIMIT 1").fetchone()
            or store.db.execute("SELECT 1 FROM funding_batch WHERE state!='confirmed' LIMIT 1").fetchone()):
        raise ValueError('fresh cash phase has unknown, paid or unfinished client/funding work')
    for row in store.db.execute('SELECT actor_id,operation,result FROM action'):
        if row['actor_id'] not in actors or row['operation'] not in ['create',*OPERATIONS]:
            raise ValueError('fresh cash phase has an unsupported original action')
        response=json.loads(row['result'])
        if response.get('status')!='ok' or response.get('actual_fee_sat')!=0:
            raise ValueError('original zero-fee native action required')
        data=response.get('data',{})
        if row['operation']=='sync':
            if (data.get('receive_count_before')!=0 or data.get('receive_count_after')!=0
                    or any(data.get(field,{}).get(key)!=[] for field in ('before_evidence','evidence') for key in ('coins','movements'))):
                raise ValueError('prior sync had monetary state or unresolved receives')
        if row['operation']=='snapshot' and (data.get('vtxos')!=[] or data.get('evidence',{}).get('coins')!=[]):
            raise ValueError('prior snapshot contained Ark ownership')
    original=declaration(store)
    if original is None or original['declaration']['pins']!=pins or set(original['declaration']['actors'])!=set(actors):
        raise ValueError('original cash-only three-customer bootstrap differs')


def _confirmed_funding(store,chain):
    from .finite_funding import _plan
    value=_plan(store);pins=value['pins'];batch='finite:'+value['id']
    rows=store.db.execute("SELECT sequence FROM event WHERE kind='fixture_funding_confirmed' "
        "AND json_extract(payload,'$.batch')=?",(batch,)).fetchall()
    if len(rows)!=1:raise ValueError('unique original confirmed finite funding required')
    _,funded=_source_event(store,rows[0][0])
    initial_event,initial=_source_event(store,value['finite_initial_source_sequence'])
    if (initial_event['kind']!='finite_initial_funding_sources_verified'
            or funded.get('financial_pins')!=pins or initial.get('financial_pins')!=pins
            or funded.get('boundary_id')!=value['boundary_id'] or initial.get('boundary_id')!=value['boundary_id']
            or funded.get('recipients')!=value['recipients'] or initial.get('funding_recipients')!=value['recipients']
            or funded.get('bank_source_sequence')!=value['bank_source_sequence']
            or funded.get('funding_plan_sha256')!=_digest(value['recipients'])
            or funded.get('finite_initial_source_sequence')!=value['finite_initial_source_sequence']):
        raise ValueError('original finite funding source/declaration differs')
    row=store.db.execute('SELECT state,txid,fee_sat FROM funding_batch WHERE id=?',(batch,)).fetchone()
    if row is None or tuple(row)!=( 'confirmed',funded['txid'],funded['fee_sat']):
        raise ValueError('original finite funding outcome is not confirmed')
    actual=chain.transaction(funded['txid']);old=funded.get('confirmed_transaction',{})
    if (actual.get('confirmations',0)<1 or any(actual.get(key)!=old.get(key) for key in ('txid','inputs','outputs','fee_sat','blockhash'))
            or actual['fee_sat']!=funded['fee_sat'] or not 0<actual['fee_sat']<=value['maximum_miner_fee_sat']):
        raise ValueError('independent confirmed finite funding transaction differs')
    costs=store.db.execute("SELECT sequence FROM event WHERE kind='financial_cost_verified'").fetchall()
    if len(costs)!=1:raise ValueError('fresh cash phase permits only the original funding miner cost')
    _,cost=_source_event(store,costs[0][0])
    if (cost.get('financial_pins')!=pins or cost.get('monetary_id')!='bitcoin-miner:'+funded['txid']
            or cost.get('amount_msat')!=actual['fee_sat']*1000 or cost.get('budget')!='ordinary'):
        raise ValueError('original exact finite funding cost differs')
    return value,initial,funded,actual,rows[0][0]


def _empty_mempool(chain,scripts,started):
    """Full current owned-output footprint; bounded fixed point, not truncation."""
    from .trace import normalized
    checked=set();bytes_read=outputs=0
    def current():
        ids=chain.call('getrawmempool',False)
        if (not isinstance(ids,list) or len(ids)>4096 or any(not isinstance(txid,str)
                or re.fullmatch('[0-9a-f]{64}',txid) is None for txid in ids) or len(set(ids))!=len(ids)):
            raise ValueError('complete cash mempool transaction bound exceeded')
        return set(ids)
    pending=current()
    for passes in range(1,9):
        if len(pending|checked)>4096:raise ValueError('cash unique mempool bound exceeded')
        for txid in sorted(pending-checked):
            if time.monotonic()-started>180:raise ValueError('cash source deadline exceeded')
            transaction=chain.tx(txid);bytes_read+=len(canonical(normalized(transaction)).encode())
            rows=transaction.get('vout')
            if not isinstance(rows,list):raise ValueError('complete cash mempool outputs required')
            outputs+=len(rows)
            if bytes_read>16*1024*1024 or outputs>50000:
                raise ValueError('cash mempool byte/output bound exceeded: '
                    f'observed_bytes={bytes_read}; maximum_bytes={16*1024*1024}; '
                    f'observed_outputs={outputs}; maximum_outputs=50000; '
                    f'observed_transactions={len(checked)+1}; maximum_unique_transactions=4096; maximum_seconds=180')
            for row in rows:
                script=row.get('scriptPubKey',{}).get('hex')
                if not isinstance(script,str) or script in scripts:raise ValueError('cash wallet has missing or unconfirmed output source')
            checked.add(txid)
        pending=current()
        if pending<=checked:return {'unique_checked':len(checked),'current_count':len(pending),
            'current_set_sha256':_digest(sorted(pending)),'passes':passes,'bytes':bytes_read,'outputs':outputs,
            'maximum_bytes':16*1024*1024,'maximum_outputs':50000,'maximum_unique_transactions':4096,
            'maximum_passes':8,'maximum_seconds':180}
    raise ValueError('complete cash mempool fixed point unavailable')


def _current_operator_ranges(initial,current,tip):
    """Extend only the exact owning descriptors from the actual public frontier."""
    specs={row['desc']:list(row['range']) for row in initial['descriptor_ranges']}
    for owner,field in (('rounds','rounds_inventory'),('watchman','watchman_inventory')):
        member=next(member for member in initial['members'] if member['id']==owner)
        frame=current.get(field,{}).get(owner)
        if (not isinstance(frame,dict) or frame.get('complete') is not True
                or frame.get('network')!='signet' or frame.get('wallet')!=owner
                or member['descriptors']!=[frame.get('public_descriptor')]
                or (frame.get('tip_height'),frame.get('tip_hash'))!=tip
                or type(frame.get('last_revealed_index')) is not int
                or not 0<=frame['last_revealed_index']<1980):
            raise ValueError('actual current bounded owning operator descriptor frontier required')
        descriptor=member['descriptors'][0]
        if descriptor not in specs:raise ValueError('owning operator descriptor differs from original boundary')
        specs[descriptor]=[0,max(specs[descriptor][1],frame['last_revealed_index']+20)]
    return specs


async def collect_fresh_cash_sources(store,config,chain,bank_rpc,*,current_startup_path):
    """Actual six-wallet closing assets after funding; no wallet synchronization."""
    from .funding_bank import collect_funding_bank_source
    from .process import json_command,public_command_capture
    started=time.monotonic()
    policy=_policy(store)
    if (config.network!='signet' or config.expected_genesis!=SIGNET_GENESIS or not config.inventory_command
            or getattr(store,'trace',None) is None):raise ValueError('traced actual signet cash sources required')
    plan,initial,funded,transaction,funding_sequence=_confirmed_funding(store,chain)
    members={member['id']:member for member in initial['members']}
    actors=sorted(member['id'] for member in members.values() if member['role']=='customer')
    if len(members)!=len(policy['customers'])+3 or set(members)!={'bank','rounds','watchman',*actors} or set(actors)!=policy['customers']:
        raise ValueError('exact six-member cash boundary required')
    _phase_history(store,plan['pins'],actors)
    before=chain.identity();tip=(before['blocks'],before['bestblockhash'])
    if before.get('chain')!='signet' or before.get('initialblockdownload') is not False:
        raise ValueError('independent synchronized signet cash source required')
    from .runtime_startup import _read
    range_runtime,range_runtime_sha256=_read(current_startup_path)
    specs=_current_operator_ranges(initial,range_runtime,tip)
    from .confirmed_scan import confirmed_scan
    scripts,scans,scan,scan_provenance=confirmed_scan(store,config,chain,range_runtime,
        pins=plan['pins'],boundary_id=plan['boundary_id'],members=list(members.values()),specs=specs,tip=tip)
    opening={}
    for member,sequence in initial['inventory_sequences'].items():
        event,inventory=_source_event(store,sequence)
        if event['kind']!='treasury_inventory' or inventory.get('member_id')!=member or inventory.get('financial_pins')!=plan['pins']:
            raise ValueError('original initial cash inventory differs')
        for coin in inventory['utxos']:opening[coin['outpoint']]={**coin,'member_id':member}
    inputs={row['outpoint'] for row in transaction['inputs']}
    if not inputs<=set(opening) or any(opening[point]['member_id']!='bank' for point in inputs):
        raise ValueError('confirmed funding consumed undeclared initial capital')
    expected={point:coin for point,coin in opening.items() if point not in inputs}
    recipients={row['script']:row for row in plan['recipients']};seen=set();change=0
    for output in transaction['outputs']:
        owner=scripts.get(output['script'])
        if owner is None:raise ValueError('confirmed funding has foreign output')
        recipient=recipients.get(output['script'])
        if recipient is not None:
            if (recipient['member_id'] in seen or recipient['member_id']!=owner['member_id']
                    or recipient['amount_sat']!=output['amount_sat']):raise ValueError('confirmed finite recipient differs')
            seen.add(recipient['member_id'])
        else:
            change+=1
            if owner['member_id']!='bank' or change>1:raise ValueError('finite funding change ownership differs')
        expected[funded['txid']+':'+str(output['vout'])]={**owner,'amount_sat':output['amount_sat'],'script':output['script']}
    if seen!={row['member_id'] for row in plan['recipients']} or sum(c['amount_sat'] for c in expected.values())!=policy['opening_sat']-transaction['fee_sat']:
        raise ValueError('exact finite cash conservation differs')
    observed={}
    rows=scan.get('unspents')
    if not isinstance(rows,list) or len(rows)>2000:raise ValueError('cash coin source bound exceeded')
    total=0
    for coin in rows:
        point=coin['txid']+':'+str(coin['vout']);amount=btc_to_sat(coin['amount']);total+=amount
        if point in observed or point not in expected or (amount,coin.get('scriptPubKey'))!=(expected[point]['amount_sat'],expected[point]['script']):
            raise ValueError('actual cash footprint contains missing, extra or changed capital')
        observed[point]=expected[point]
    if total!=btc_to_sat(scan['total_amount']):raise ValueError('complete cash scan total differs')
    if set(observed)!=set(expected):raise ValueError('complete cash scan omitted declared owned output')
    for point,coin in observed.items():
        txid,index=point.rsplit(':',1)
        actual=chain.call('gettxout',txid,int(index),True)
        if (actual is None or actual.get('confirmations',0)<1 or btc_to_sat(actual['value'])!=coin['amount_sat']
                or actual['scriptPubKey']['hex']!=coin['script']):raise ValueError('cash output unavailable or pending-spent')
    mempool=_empty_mempool(chain,set(scripts),started)
    bank_sequence=collect_funding_bank_source(store,bank_rpc,chain);_,bank=_source_event(store,bank_sequence)
    bank_points={row['txid']+':'+str(row['vout']):row for row in bank['listunspent']}
    expected_bank={point:coin for point,coin in observed.items() if coin['member_id']=='bank'}
    if (bank['source_identity']['wallet_name']!=plan['bank_wallet_name'] or (bank['height'],bank['tip_hash'])!=tip
            or set(bank_points)!=set(expected_bank) or any(bank.get(key)!=[] for key in
                ('pending_transactions','pending_parents','locked_coins','listlockunspent'))
            or btc_to_sat(bank['getbalances']['mine']['trusted'])!=sum(coin['amount_sat'] for coin in expected_bank.values())
            or btc_to_sat(bank['getbalances']['mine']['untrusted_pending'])!=0):
        raise ValueError('actual complete bank closing cash source differs')
    for point,coin in bank_points.items():
        if (btc_to_sat(coin['amount'])!=expected_bank[point]['amount_sat'] or coin['scriptPubKey']!=expected_bank[point]['script']
                or coin.get('spendable') is not True or coin.get('safe') is not True):raise ValueError('actual bank closing control differs')
    request={'kind':'closed_frontier'}
    database=await json_command(list(config.inventory_command),request,timeout=25,
        **public_command_capture(store,'fresh_cash.closed_frontier',request))
    public_payload(database)
    _,initial_db=_source_event(store,initial['database_source_sequence'])
    if (database.get('kind')!='closed_frontier' or database.get('schema_version')!=initial_db['response'].get('schema_version')
            or database.get('fallback_protocol')!=initial_db['response'].get('fallback_protocol')
            or database.get('complete')!=initial_db['response'].get('complete')
            or database.get('qualified')!=initial_db['response'].get('qualified')
            or database.get('database_tables_complete') is not True or database.get('inventory_consistent') is not True
            or database.get('read_only') is not True or database.get('rows')!=initial_db['response']['rows']):
        raise ValueError('cash-only monetary database frontier is no longer empty')
    store.event('closed_cohort_original_source',{'source_kind':'closed_frontier','response':database,
        'response_sha256':_digest(database),'financial_pins':plan['pins'],'observed_at':time.time()})
    database_sequence=store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
    client_sequence=observe_empty_client_economics(store,config)
    ending=chain.identity()
    if ending.get('initialblockdownload') is not False or (ending['blocks'],ending['bestblockhash'])!=tip or time.monotonic()-started>180:
        raise ValueError('fresh cash source changed chain or exceeded deadline')
    _phase_history(store,plan['pins'],actors)
    inventories={}
    with store.transaction():
        for member_id,member in members.items():
            coins=[{'outpoint':point,'amount_sat':coin['amount_sat'],'script':coin['script'],
                'descriptor_index':coin['descriptor_index'],'child_index':coin['child_index']}
                for point,coin in observed.items() if coin['member_id']==member_id]
            store._event('treasury_inventory',{'member_id':member_id,'identity':member['identity'],'financial_pins':plan['pins'],
                'height':tip[0],'tip_hash':tip[1],'complete':True,'utxos':coins,'scope':'actual finite confirmed cash-only footprint; no Ark liabilities'})
            inventories[member_id]=store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
        source={'financial_pins':plan['pins'],'boundary_id':plan['boundary_id'],'members':initial['members'],
            'actors':actors,'height':tip[0],'tip_hash':tip[1],'observed_at':time.time(),'complete':True,
            'funding_confirmation_sequence':funding_sequence,'finite_initial_source_sequence':plan['finite_initial_source_sequence'],
            'bank_source_sequence':bank_sequence,'client_economics_sequence':client_sequence,'inventory_sequences':inventories,
            'database_source_sequence':database_sequence,'database_response_sha256':_digest(database),
            'mempool':mempool,'descriptor_ranges':scans,'range_runtime_source_sha256':range_runtime_sha256,
            'confirmed_scan':scan_provenance,
            'total_sat':policy['opening_sat']-transaction['fee_sat'],
            'funding_fee_sat':transaction['fee_sat'],'operation_scope':OPERATIONS,
            'scope':'exact confirmed funding and empty persisted monetary state; customer BDK need not be synchronized'}
        public_payload(source);store._event('finite_fresh_cash_sources_verified',source)
        sequence=store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
    return {'source_sequence':sequence,'source':source}


def _operator_fee_funding(store,source,assets,current):
    available=0
    for owner,field in (('rounds','rounds_inventory'),('watchman','watchman_inventory')):
        frame=current.get(field,{}).get(owner)
        scanned={row['desc']:row['range'][1] for row in source.get('descriptor_ranges',[])}
        expected={point:coin for point,coin in assets['assets'].items() if coin['member']==owner}
        member=next(member for member in source['members'] if member['id']==owner)
        _,inventory=_source_event(store,source['inventory_sequences'][owner])
        owned_scripts={coin['outpoint']:coin['script'] for coin in inventory['utxos']}
        if (not isinstance(frame,dict) or frame.get('complete') is not True or frame.get('network')!='signet'
                or frame.get('wallet')!=owner or member['descriptors']!=[frame.get('public_descriptor')]
                or type(frame.get('last_revealed_index')) is not int
                or not 0<=frame['last_revealed_index']<=scanned.get(frame.get('public_descriptor'),-1)
                or (frame.get('tip_height'),frame.get('tip_hash'))!=(source['height'],source['tip_hash'])
                or any(frame.get(key)!=[] for key in ('reserved_outpoints','pending_transactions','pending_parents','unavailable_parent_txids'))
                or not isinstance(frame.get('utxos'),list) or len(frame['utxos'])!=len(expected)
                or {coin['outpoint'] for coin in frame['utxos']}!=set(expected)):
            raise ValueError('actual current unreserved operator cash inventory required')
        for coin in frame['utxos']:
            actual=expected[coin['outpoint']]
            if (type(coin.get('value_sat')) is not int or coin['value_sat']*1000!=actual['amount_msat']
                    or coin.get('script_pubkey')!=owned_scripts[coin['outpoint']]
                    or type(coin.get('confirmed_fee_eligible')) is not bool
                    or type(coin.get('trusted')) is not bool or type(coin.get('mature')) is not bool
                    or coin.get('reserved') is not False):
                raise ValueError('actual operator fee eligibility differs')
            # An untrusted rounds output remains conserved capital. Only the
            # actual native eligible subset backs fee budgets.
            if coin['confirmed_fee_eligible']:
                if coin['mature'] is not True or coin['trusted'] is not True:
                    raise ValueError('native fee eligibility contradicts maturity/trust')
                # The C direct-expiry signer is watchman. Bank capital and
                # rounds liquidity cannot stand in for actual signer funds.
                if profile(store)!=DIRECT_PER_KEY or owner=='watchman':
                    available+=actual['amount_msat']
    return available


def record_fresh_cash_readiness(store,config,chain,*,source_sequence,runtime_source_sequence,current_startup_path):
    """Admit only fee-free cash synchronization after actual source collection."""
    from .runtime_startup import _read
    from .treasury import boundary,capture_assets
    from .operating_limits import envelope,fee_totals
    policy=_policy(store)
    event,source=_source_event(store,source_sequence)
    if event['kind']!='finite_fresh_cash_sources_verified' or source.get('operation_scope')!=OPERATIONS:
        raise ValueError('original exact fresh-cash source required')
    _fresh(source['observed_at'])
    plan,initial,funded,transaction,funding_sequence=_confirmed_funding(store,chain)
    _phase_history(store,plan['pins'],source['actors'])
    if (source['financial_pins']!=plan['pins'] or source['boundary_id']!=plan['boundary_id']
            or source['funding_confirmation_sequence']!=funding_sequence or source['members']!=initial['members']):
        raise ValueError('fresh cash source has different financial context')
    runtime_event,runtime=_source_event(store,runtime_source_sequence)
    current,current_sha=_read(current_startup_path)
    if (runtime_event['kind']!='owned_runtime_configuration_verified'
            or runtime.get('loaded_configuration_identity_verified') is not True
            or runtime.get('current_source_sha256')!=current_sha
            or runtime.get('product_commit')!=plan['pins']['product_commit']
            or runtime.get('schema_sha256')!=plan['pins']['schema_sha256']):
        raise ValueError('actual same-process loaded cash configuration required')
    _fresh(runtime['observed_at'])
    limits=envelope(store,config);treasury=boundary(store)
    if (limits['pins']!=plan['pins'] or limits['boundary_id']!=plan['boundary_id']
            or treasury['members']!=source['members'] or treasury['id']!=source['boundary_id']
            or runtime.get('effective_fee_ceilings_sat_kvb')!=limits['fee_ceilings_sat_kvb']
            or any(limits.get('operation_fee_paths',{}).get(operation)!=['sweep','payout'] for operation in OPERATIONS)):
        raise ValueError('actual cash configuration or predeclared operation paths differ')
    assets=capture_assets(store,source['inventory_sequences'],chain)
    if ((assets['height'],assets['tip_hash'])!=(source['height'],source['tip_hash'])
            or assets['total_msat']!=(policy['opening_sat']-transaction['fee_sat'])*1000
            or fee_totals(store,plan['pins'])!={'ordinary':transaction['fee_sat']*1000,'urgent':0}):
        raise ValueError('cash closing conservation, tip or cumulative fees differ')
    available=_operator_fee_funding(store,source,assets,current)
    used=fee_totals(store,plan['pins'])
    remaining={key:limits['fee_budgets_msat'][key]-used[key] for key in ('ordinary','urgent')}
    if min(remaining.values())<0 or available<sum(remaining.values()):
        raise ValueError('actual eligible operator cash cannot back remaining fee budgets')
    # Re-read customer economics after the potentially slow descriptor scans.
    client_sequence=observe_empty_client_economics(store,config)
    estimate=chain.call('estimatesmartfee',6)
    rate=btc_to_sat(estimate['feerate'])
    if not 1<=rate<=min(limits['fee_ceilings_sat_kvb'][path] for path in ('sweep','payout')):
        raise ValueError('actual cash source fee estimate unavailable or above ceiling')
    current_tip=chain.identity()
    if (current_tip.get('initialblockdownload') is not False
            or (current_tip['blocks'],current_tip['bestblockhash'])!=(source['height'],source['tip_hash'])):
        raise ValueError('cash proof independent chain changed')
    _fresh(source['observed_at']);_fresh(runtime['observed_at'])
    receipt={'financial_pins':plan['pins'],'boundary_id':plan['boundary_id'],
        'height':source['height'],'tip_hash':source['tip_hash'],'observed_at':time.time(),'complete':True,
        'operation_scope':OPERATIONS,'client_action_scope':{'actors':source['actors'],'operations':OPERATIONS,
            'maximum_fee_sat':0,'args':{}},'finite_fresh_cash_source_sequence':source_sequence,
        'funding_confirmation_sequence':funding_sequence,'runtime_source_sequence':runtime_source_sequence,
        'client_economics_sequence':client_sequence,'effective_fee_ceilings_sat_kvb':limits['fee_ceilings_sat_kvb'],
        'capital_exposure_msat':assets['total_msat'],'available_fee_funding_msat':available,
        'estimated_fee_rate_sat_kvb':rate,'pool_ready':False,'channel_route_ready':False,
        'scope':'confirmed cash only and no persisted monetary intents; sync/snapshot/address only; no Board or Ark send admission'}
    if profile(store)==DIRECT_PER_KEY:
        receipt.update(fee_signer_member='watchman',actual_daemon_fee_liquidity_msat=available,
            bank_capital_counts_as_signer_liquidity=False,urgent_isolation_qualified=False,
            urgent_qualification_scope='C11 separate urgent selection/reservation proof OPEN; labels and aggregate budgets alone do not qualify it')
    validate_client_action_scope(store,receipt,operation='sync',maximum_fee_sat=0,reserved_action_id=None)
    store.event('financial_operating_readiness',receipt)
    return {'operating_readiness_sequence':store.db.execute('SELECT max(sequence) FROM event').fetchone()[0],**receipt}

"""Explicit short ordinary canary; never final financial qualification.

The source is the owning read-only native bridge, joined against independent
Core. A missing source is a hold. This path cannot authorize Lightning, exits,
refresh, hostile clients, final-qualified time, or an automatic fee increase.
"""
import hashlib
import json
import time
from datetime import datetime

from .model import SIGNET_GENESIS, InvariantError, btc_to_sat, canonical, integer
from .final_campaign import _pins
from .process import json_command, public_command_capture

KEY = 'exploratory_operating_scope'
ALLOWED = {'board', 'send_arkoor', 'sync', 'snapshot', 'address', 'create', 'progression'}
ZERO_TABLES = {'expiry_settlement','htlc_settlement','htlc_vtxo','offboards','sweep',
    'recovery_capital_release','recovery_receipt','recovery_source_hold',
    'lightning_invoice','lightning_payment_attempt','vtxo_pool'}


def scope(store):
    raw = store.get_meta(KEY+':continuation') or store.get_meta(KEY)
    if raw is None:
        return None
    value = json.loads(raw)
    rows = store.db.execute("SELECT payload FROM event WHERE kind='exploratory_operating_scope_declared' AND payload=?",(raw,)).fetchall()
    if len(rows) != 1 or canonical(value) != raw:
        raise InvariantError('exploratory scope differs from original declaration')
    closed = store.get_meta(KEY+':closed:'+hashlib.sha256(raw.encode()).hexdigest())
    if closed is not None:
        events=store.db.execute("SELECT payload FROM event WHERE kind='exploratory_operating_scope_closed' AND payload=?",(closed,)).fetchall()
        if len(events)!=1:raise InvariantError('scope closure differs from original event')
        return None
    if store.get_meta('final_financial_epoch') is not None:
        raise ValueError('exploratory authority cannot qualify a final financial epoch')
    return value


def declare(store, declaration):
    _pins(declaration['pins'])
    fields = {'id','pins','source_key','configuration_sha256','image_digest','container','server_pubkey',
        'actors','started_at','deadline','fee_ceiling_sat_kvb','per_action_fee_sat','fee_budget_sat',
        'capital_budget_sat','maximum_client_principal_sat','minimum_fee_cash_sat','funding_txids',
        'raw_estimate_above_cap_policy','qualified_seconds','binary_sha256','recovery_sweep_script','client_board_fee_ceiling_sat_kvb','board_amount_sat','ark_send_amount_sat','maximum_ark_transfers'}
    if set(declaration) != fields or declaration['qualified_seconds'] != 0:
        raise ValueError('complete explicit unqualified exploratory scope required')
    if not 0 < declaration['deadline']-declaration['started_at'] <= 1800:
        raise ValueError('exploratory scope is at most thirty minutes')
    if (not isinstance(declaration['actors'],list) or not 1 <= len(set(declaration['actors'])) <= 2
            or len(set(declaration['actors'])) != len(declaration['actors'])):
        raise ValueError('at most two distinct funded actors')
    if declaration['raw_estimate_above_cap_policy'] != 'nonurgent_capped_broadcast_pending_allowed':
        raise ValueError('explicit nonurgent capped broadcast policy required')
    for field in ('fee_ceiling_sat_kvb','per_action_fee_sat','fee_budget_sat','capital_budget_sat',
                  'maximum_client_principal_sat','minimum_fee_cash_sat','board_amount_sat','ark_send_amount_sat','maximum_ark_transfers'):
        integer(declaration[field],field,1)
    if declaration['client_board_fee_ceiling_sat_kvb'] is not None:
        integer(declaration['client_board_fee_ceiling_sat_kvb'],'client board rate ceiling',1)
    if not declaration['funding_txids'] or len(declaration['funding_txids']) > 8:
        raise ValueError('actual distinct funding sources required')
    encoded = canonical(declaration)
    with store.transaction():
        old = scope(store)
        if old is not None:
            if old != declaration:raise ValueError('exploratory scope immutable')
            return False
        if store.get_meta('qualified_campaign_active_seconds') not in (None,'0'):
            raise ValueError('preserve previous qualified clock; exploratory requires a fresh namespace')
        if store.db.execute('SELECT 1 FROM action LIMIT 1').fetchone():
            raise ValueError('preserve previous funded/action history; exploratory requires a fresh namespace')
        if not store.get_meta('paused') or store.db.execute("SELECT 1 FROM action WHERE state IN ('dispatched','outcome_unknown') LIMIT 1").fetchone():
            raise ValueError('declare while paused with zero in-flight and unknown')
        store.db.execute('INSERT INTO meta VALUES (?,?)',(KEY,encoded))
        store.db.execute("INSERT OR REPLACE INTO meta VALUES ('financial_qualification_required','true')")
        store.db.execute("INSERT OR IGNORE INTO meta VALUES ('qualified_campaign_active_seconds','0')")
        store._event('exploratory_operating_scope_declared',declaration)
    return True


def close(store,snapshot,reason,*,now=None):
    """Append closure; pending signed boards and every fee hold remain intact."""
    now=time.time() if now is None else now
    declaration=scope(store)
    if declaration is None:raise ValueError('no active exploratory scope to close')
    if not isinstance(reason,str) or not 1<=len(reason)<=500:raise ValueError('bounded closure reason required')
    with store.transaction():
        if not store.get_meta('paused') or store.db.execute("SELECT 1 FROM action WHERE state IN ('queued','dispatched','outcome_unknown') LIMIT 1").fetchone():
            raise ValueError('close while paused with zero queued, in-flight and unknown')
        row=store.db.execute("SELECT * FROM event WHERE sequence=?",(snapshot.get('exploratory_readiness_sequence'),)).fetchone()
        if row is None or row['kind']!='exploratory_operating_readiness':raise ValueError('fresh checked closure source required')
        proof=json.loads(row['payload'])
        if (proof['scope_id']!=declaration['id'] or proof['financial_pins']!=declaration['pins']
                or (proof['height'],proof['tip_hash'])!=(snapshot['height'],snapshot['tip_hash'])
                or not 0<=now-proof['observed_at']<=90 or proof['ordinary_path_checked'] is not True
                or proof['global_complete'] is not False):raise ValueError('fresh checked closure source required')
        held=store.db.execute("SELECT COALESCE(SUM(fee_reservation_sat),0) FROM action WHERE operation IN ('board','send_arkoor','sync') AND state IN ('queued','dispatched','outcome_unknown','completed')").fetchone()[0]
        if held+proof['operator_miner_fees_sat']>declaration['fee_budget_sat'] or proof['available_fee_funding_sat']<held:
            raise ValueError('preserve unresolved costs; closure cannot renew an exhausted budget')
        if store.get_meta('qualified_campaign_active_seconds') not in (None,'0'):
            raise ValueError('preserve unexpected positive qualified counter')
        declaration_hash=hashlib.sha256(canonical(declaration).encode()).hexdigest()
        closure={'declaration_sha256':declaration_hash,'scope_id':declaration['id'],'reason':reason,
            'source_sequence':row['sequence'],'source_event_hash':row['hash'],'source_height':proof['height'],
            'source_tip_hash':proof['tip_hash'],'source_observed_at':proof['observed_at'],
            'remaining_fee_budget_sat':declaration['fee_budget_sat']-held-proof['operator_miner_fees_sat'],
            'retained_fee_holds_sat':held,'operator_miner_fees_sat':proof['operator_miner_fees_sat'],
            'action_count':store.db.execute('SELECT COUNT(*) FROM action').fetchone()[0],
            'qualified_seconds':0,'closed_at':now,'pending_signed_liabilities_preserved':True}
        store.db.execute('INSERT INTO meta VALUES (?,?)',(KEY+':closed:'+declaration_hash,canonical(closure)))
        store._event('exploratory_operating_scope_closed',closure)
    return closure


def continue_scope(store,declaration,*,now=None):
    """An explicit reviewed continuation; original cumulative budgets/counts apply."""
    now=time.time() if now is None else now
    raw=store.get_meta(KEY+':continuation') or store.get_meta(KEY)
    if raw is None or scope(store) is not None:raise ValueError('close original scope before continuation')
    if store.get_meta('final_financial_epoch') is not None:raise ValueError('cannot continue after final financial epoch')
    previous=json.loads(raw);allowed={'id','started_at','deadline'}
    if set(declaration)!=set(previous) or any(declaration[k]!=v for k,v in previous.items() if k not in allowed):
        raise ValueError('continuation cannot change pins, actors, fees, capital or operation bounds')
    if (not isinstance(declaration['id'],str) or declaration['id']==previous['id']
            or not declaration['started_at']<=now<declaration['deadline']
            or not 0<declaration['deadline']-declaration['started_at']<=1800):
        raise ValueError('fresh distinct at-most-thirty-minute continuation required')
    encoded=canonical(declaration);oldhash=hashlib.sha256(raw.encode()).hexdigest()
    closed=json.loads(store.get_meta(KEY+':closed:'+oldhash))
    with store.transaction():
        if store.get_meta('qualified_campaign_active_seconds') not in (None,'0'):
            raise ValueError('preserve unexpected positive qualified counter')
        if (not store.get_meta('paused') or not 0<=now-closed['source_observed_at']<=90
                or store.db.execute("SELECT 1 FROM action WHERE state IN ('queued','dispatched','outcome_unknown') LIMIT 1").fetchone()
                or closed['action_count']!=store.db.execute('SELECT COUNT(*) FROM action').fetchone()[0]
                or closed['remaining_fee_budget_sat']<0):raise ValueError('fresh unchanged reconciled closure required')
        if store.db.execute("SELECT 1 FROM event WHERE kind='exploratory_operating_scope_declared' AND json_extract(payload,'$.id')=?",(declaration['id'],)).fetchone():
            raise ValueError('scope id already declared')
        store.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',(KEY+':continuation',encoded))
        store._event('exploratory_operating_scope_declared',declaration)
        store._event('exploratory_operating_scope_continued',{'previous_declaration_sha256':oldhash,
            'previous_closure_sha256':hashlib.sha256(canonical(closed).encode()).hexdigest(),
            'new_declaration_sha256':hashlib.sha256(encoded.encode()).hexdigest(),
            'retained_action_count':closed['action_count'],'retained_fee_holds_sat':closed['retained_fee_holds_sat'],
            'remaining_cumulative_fee_budget_sat':closed['remaining_fee_budget_sat'],'qualified_seconds':0})
    return True


def checked_source(declaration, packet, chain, *, now=None, client_board_proposals=None):
    """Check only the explicitly declared ordinary operating-path proof scope."""
    now = time.time() if now is None else now
    client_board_proposals = {} if client_board_proposals is None else client_board_proposals
    client_board_txids = set(client_board_proposals)
    start = datetime.fromisoformat(packet['observed_at']).timestamp()
    end = datetime.fromisoformat(packet['completed_at']).timestamp()
    if not start <= end <= now or now-start > 90:raise ValueError('stale owning source')
    if (packet['genesis'] != SIGNET_GENESIS or packet['network'] != 'signet'
            or packet['source_key'] != declaration['source_key']
            or packet['config_sha256'] != declaration['configuration_sha256']):
        raise ValueError('actual source/config/network differs')
    if packet.get('container_runtime_stable') is not True:
        raise ValueError('owning executable process changed during capture')
    if packet.get('binary_sha256') != declaration['binary_sha256']:
        raise ValueError('actual shipping executable hashes differ')
    info = packet['client_verified_server_info']
    if info['server_pubkey'] != declaration['server_pubkey'] or info['network'] != 'signet' or info['vtxo_lifetime'] != 48:
        raise ValueError('actual public server identity differs')
    inspected = packet['container_inspect']
    if (inspected['Image'] != declaration['image_digest'] or inspected['Name'].lstrip('/') != declaration['container']
            or inspected['State']['Running'] is not True or inspected['State']['OOMKilled']):
        raise ValueError('actual running image differs')
    independent = chain.identity(); height = independent['blocks']; tip = independent['bestblockhash']
    if independent.get('initialblockdownload') is not False or packet['stable_tip'] is not True:
        raise ValueError('stable synchronized chain required')
    for frame in (packet['core_before'],packet['core_after']):
        if (frame['blocks'],frame['bestblockhash'],frame['initialblockdownload']) != (height,tip,False):
            raise ValueError('independent same tip required')
    policy = packet['public_policy']
    if (policy['vtxo_lifetime'] != 48 or policy['required_board_confirmations'] != 3
            or policy['vtxo_exit_delta'] != 12 or policy['vtxopool']['vtxo_targets']
            or policy['expiry_payout']['enabled'] is not False
            or any(policy[field] != '0 sat' for field in ('max_ln_send_amount','max_ln_receive_amount','max_offboard_amount'))):
        raise ValueError('declared no-Lightning/no-exit/no-pool canary policy differs')
    # Exact running config bytes and source review bind this signed quiet-funding
    # ceiling. We do not claim that it caps urgent claims or CPFP child rates.
    cap = policy['fee_estimator']['max_fee_rate']
    if cap != str(declaration['fee_ceiling_sat_kvb']//1000)+'sat/vb' or declaration['fee_ceiling_sat_kvb'] % 1000:
        raise ValueError('actual quiet funding ceiling differs')
    counts = packet['postgres_public_table_counts']['tables']
    if packet['postgres_count_snapshot'] != 'REPEATABLE READ READ ONLY' or any(counts.get(name) != 0 for name in ZERO_TABLES):
        raise ValueError('conditional/exit/payout/recovery work present or unobserved')
    money = packet['postgres_financial_rows']
    reserve = packet['recovery_reserve']
    if (reserve['id'] != 'rounds' or reserve['sweep_spk'] != declaration['recovery_sweep_script']
            or reserve['fee_headroom_sat'] != 20000 or reserve['held_sat'] != 0
            or reserve['unknown_gross'] is not False or reserve['checkpoint_height'] > height
            or chain.call('getblockhash',reserve['checkpoint_height']) != reserve['checkpoint_hash']):
        raise ValueError('actual configured recovery reserve differs or has unknown obligations')

    if any(money.get(name) != 0 for name in ('conditional_count','exit_count','payout_count','recovery_hold_sat')):
        raise ValueError('unqualified urgent or retained obligation exposure')
    earliest = money['earliest_expiry_height']
    if earliest is None:
        if any(counts.get(name) != 0 for name in ('vtxo','round','pending_board','virtual_transaction')):
            raise ValueError('backing expiry missing')
    elif integer(earliest,'earliest expiry') <= height+30:
        raise ValueError('stop before expiry headroom reaches thirty blocks')
    if integer(money['customer_principal_sat'],'customer principal') > declaration['maximum_client_principal_sat']:
        raise ValueError('customer principal budget exceeded')
    fee_cash = 0; all_points = set(); physical_native_sat = 0
    for owner in ('rounds','watchman'):
        reply = packet[owner+'_inventory']
        if reply['exit'] != 0:raise ValueError('owning '+owner+' source unavailable')
        wallet = reply['data'][owner]
        if (wallet['complete'] is not True or wallet['network'] != 'signet'
                or (wallet['tip_height'],wallet['tip_hash']) != (height,tip)
                or wallet['unavailable_parent_txids']):
            raise ValueError('owning wallet frame incomplete or at different tip')
        info = chain.call('getdescriptorinfo',wallet['public_descriptor'])
        if info.get('hasprivatekeys') is not False or info['descriptor'] != wallet['public_descriptor']:
            raise ValueError('canonical public descriptor required')
        if len(wallet['utxos']) > 64 or len(wallet['pending_transactions']) > 64:
            raise ValueError('canary source exceeds bounded inventory')
        # Pending signed transactions and reservations cannot supply fee cash.
        pending = set()
        from .bundle_audit import decode_transaction
        for tx in wallet['pending_transactions']:
            decoded = decode_transaction(tx['transaction_body'],public_body=True)
            if decoded['txid'] != tx['txid']:raise InvariantError('pending transaction identity differs')
            pending.update(row['outpoint'] for row in decoded['inputs'])
        for row in wallet['utxos']:
            point = row['outpoint']
            if point in all_points:raise InvariantError('same physical coin counted twice')
            all_points.add(point); txid,index = point.rsplit(':',1)
            coin = chain.call('gettxout',txid,int(index),True)
            if coin is None:
                if point not in pending:raise ValueError('unknown chain or mempool spend')
                continue
            if btc_to_sat(coin['value']) != row['value_sat'] or coin['scriptPubKey']['hex'] != row['script_pubkey']:
                raise InvariantError('native inventory differs from independent chain')
            addresses = chain.call('deriveaddresses',wallet['public_descriptor'],[row['derivation_index'],row['derivation_index']])
            if len(addresses) != 1 or chain.call('validateaddress',addresses[0])['scriptPubKey'] != row['script_pubkey']:
                raise InvariantError('native output does not derive from actual wallet')
            if txid not in set(money['funding_txids']) | set(declaration['funding_txids']):
                raise ValueError('operator coin has undeclared funding origin')
            if coin['confirmations']>0:physical_native_sat += row['value_sat']
            if (row['confirmed_fee_eligible'] and coin['confirmations'] >= wallet['min_trusted_confirmations']
                    and point not in wallet['reserved_outpoints'] and point not in pending):fee_cash += row['value_sat']
    fee_cash = max(0,fee_cash-reserve['fee_headroom_sat']-money['recovery_hold_sat'])
    if fee_cash < declaration['minimum_fee_cash_sat']:raise ValueError('confirmed unreserved operator fee cash insufficient')
    if physical_native_sat+integer(money['customer_principal_sat'],'current client principal') > declaration['capital_budget_sat']:
        raise ValueError('capital exposure budget exceeded')
    txids = list(set(money['funding_txids']) | set(declaration['funding_txids']) | set(client_board_txids))
    if not isinstance(txids,list) or len(txids)>128 or len(set(txids)) != len(txids):raise ValueError('bounded distinct carrier inventory required')
    miner_fees = 0; client_miner_fees = 0; miner_by_txid = {}
    for txid in txids:
        tx = chain.transaction(txid);miner_fees += tx['fee_sat']
        miner_by_txid[txid] = tx['fee_sat']
        if txid in client_board_txids:client_miner_fees += tx['fee_sat']
        raw = chain.tx(txid)
        ceiling = declaration['client_board_fee_ceiling_sat_kvb'] if txid in client_board_txids else declaration['fee_ceiling_sat_kvb']
        if txid in client_board_proposals:
            proposal = client_board_proposals[txid]
            mining = integer(proposal['planned_mining_fee_sat'],'planned board miner fee')
            service = integer(proposal['estimated_service_fee_sat'],'planned board service fee')
            maximum = integer(proposal['maximum_fee_sat'],'original board fee hold',1)
            if tx['fee_sat'] != mining or mining+service > maximum or maximum > declaration['per_action_fee_sat']:
                raise ValueError('actual client board fee differs from native original affordable proposal')
        if ceiling is not None and tx['fee_sat']*1000 > ceiling*integer(raw['vsize'],'actual vsize',1):
            raise ValueError('actual signed carrier fee exceeds declared quiet ceiling')
    if miner_fees > declaration['fee_budget_sat']:raise ValueError('actual cumulative miner budget exceeded')
    ending = chain.identity()
    if (ending['blocks'],ending['bestblockhash']) != (height,tip):raise ValueError('tip changed during checks')
    estimate = chain.call('estimatesmartfee',1,'CONSERVATIVE')
    rate = btc_to_sat(estimate['feerate'])
    return {'scope_id':declaration['id'],'financial_pins':declaration['pins'],'height':height,'tip_hash':tip,
        'observed_at':start,'completed_at':time.time(),'ordinary_path_checked':True,'global_complete':False,
        'available_fee_funding_sat':fee_cash,'miner_fees_sat':miner_fees,
        'operator_miner_fees_sat':miner_fees-client_miner_fees,'client_board_miner_fees_sat':client_miner_fees,
        'miner_fee_by_txid':miner_by_txid,'earliest_expiry_height':earliest,
        'raw_estimate_sat_kvb':rate,'quiet_signed_ceiling_sat_kvb':declaration['fee_ceiling_sat_kvb'],
        'estimate_warning':rate>declaration['fee_ceiling_sat_kvb'],'qualified_seconds':0,
        'source_sha256':hashlib.sha256(canonical(packet).encode()).hexdigest()}


async def collect(store,config,chain,snapshot):
    declaration = scope(store)
    if declaration is None:return snapshot
    packet = await json_command(list(config.inventory_command),{'kind':'exploratory_readiness'},timeout=25,
        **public_command_capture(store,'exploratory.source',{'kind':'exploratory_readiness'}))
    command = list(config.driver_command)
    info = await json_command(command,{'operation':'info','action_id':'exploratory-info',
        'expected_server_pubkey':declaration['server_pubkey']},timeout=15,
        **public_command_capture(store,'exploratory.public-info',{'operation':'info'}))
    if info.get('status')!='ok':raise ValueError('actual public server info unavailable')
    packet['client_verified_server_info']=info['data']
    proposals=store.db.execute("SELECT payload FROM event WHERE kind='driver_evidence' AND json_extract(payload,'$.event')='board_proposal'").fetchall()
    client_proposals={}
    from .bundle_audit import decode_transaction
    from .chain import public_transaction
    for row in proposals:
        event=json.loads(row[0]);proposal=event['data']
        action=store.db.execute('SELECT * FROM action WHERE id=?',(event['action_id'],)).fetchone()
        if action is None or action['operation']!='board' or action['actor_id'] not in declaration['actors']:
            raise ValueError('client board carrier lacks original scoped action')
        args=json.loads(action['args'])
        if args.get('amount_sat')!=declaration['board_amount_sat'] or proposal['amount_sat']!=declaration['board_amount_sat']:
            raise ValueError('native board proposal differs from original amount')
        unsigned=decode_transaction(proposal['unsigned_funding_tx'],public_body=True)
        if unsigned['txid']!=proposal['funding_txid']:
            raise InvariantError('native board proposal transaction differs')
        original=public_transaction(chain.tx(proposal['funding_txid']))
        if original['hex']!=unsigned['stripped_hex']:
            raise InvariantError('actual client board differs from native unsigned proposal')
        client_proposals[proposal['funding_txid']]={**proposal,'maximum_fee_sat':action['fee_reservation_sat']}
    proof = checked_source(declaration,packet,chain,client_board_proposals=client_proposals)
    store.event('exploratory_operating_readiness',proof)
    snapshot['exploratory_readiness_sequence'] = store.db.execute('SELECT MAX(sequence) FROM event').fetchone()[0]
    return snapshot


def preflight(store,config,snapshot,*,operation='ordinary',amount_sat=0,maximum_fee_sat=0,now=None,reserved_action_id=None):
    declaration = scope(store);now=time.time() if now is None else now
    if not declaration['started_at'] <= now < declaration['deadline']:raise ValueError('exploratory thirty-minute window ended')
    if operation not in ALLOWED:raise ValueError('operation outside exploratory ordinary scope')
    if integer(maximum_fee_sat,'action reserve') > declaration['per_action_fee_sat']:raise ValueError('canary action fee limit exceeded')
    sequence = snapshot.get('exploratory_readiness_sequence')
    row = store.db.execute("SELECT kind,payload FROM event WHERE sequence=?",(sequence,)).fetchone()
    if row is None or row['kind'] != 'exploratory_operating_readiness':raise ValueError('checked exploratory readiness missing')
    proof = json.loads(row['payload'])
    if (proof['scope_id'] != declaration['id'] or proof['financial_pins'] != declaration['pins']
            or (proof['height'],proof['tip_hash']) != (snapshot['height'],snapshot['tip_hash'])
            or not 0<=now-proof['observed_at']<=90 or proof['ordinary_path_checked'] is not True
            or proof['global_complete'] is not False):raise ValueError('fresh scoped readiness required')
    if store.get_meta('qualified_campaign_active_seconds') not in (None,'0'):raise InvariantError('exploratory scope cannot earn qualified time')
    if reserved_action_id:
        action = store.db.execute('SELECT * FROM action WHERE id=?',(reserved_action_id,)).fetchone()
        if not action:raise ValueError('original action missing')
        admit(store,action['actor_id'],action['operation'],json.loads(action['args']),reserved_action_id)
        if operation=='progression' and action['operation']!='sync':raise ValueError('progression means existing ordinary sync only')
    held = store.db.execute("SELECT COALESCE(SUM(fee_reservation_sat),0) FROM action WHERE operation IN ('board','send_arkoor','sync') AND state IN ('queued','dispatched','outcome_unknown','completed')").fetchone()[0]
    if held+proof['operator_miner_fees_sat'] > declaration['fee_budget_sat']:raise ValueError('actual and unresolved canary fees exceed budget')
    if proof['available_fee_funding_sat'] < held:raise ValueError('canary reservations no longer funded')
    return {'allowed':True,'budget':'explicit_exploratory','qualified_seconds':0,'scope_id':declaration['id'],
            'estimate_warning':proof['estimate_warning'],'financial_pins':declaration['pins']}


def admit(store,actor,operation,args,action_id=None):
    declaration=scope(store)
    if declaration is None:return
    if actor not in declaration['actors'] or operation not in ALLOWED-{'progression'}:
        raise ValueError('actor or operation outside two-client canary')
    if operation=='create' and store.get_meta('unfunded_setup_import') is not None:
        raise ValueError('original native wallet already initialized; never recreate')
    if operation=='board':
        if args.get('amount_sat')!=declaration['board_amount_sat']:
            raise ValueError('board amount differs from immutable canary')
        previous=store.db.execute("SELECT 1 FROM action WHERE actor_id=? AND operation='board' AND id!=? AND state IN ('queued','dispatched','completed','outcome_unknown')",(actor,action_id or '')).fetchone()
        if previous:raise ValueError('one original board per canary actor')
    if operation=='send_arkoor':
        if args.get('amount_sat')!=declaration['ark_send_amount_sat']:
            raise ValueError('Ark amount differs from immutable canary')
        count=store.db.execute("SELECT COUNT(*) FROM action WHERE operation='send_arkoor' AND id!=? AND state IN ('queued','dispatched','completed','outcome_unknown')",(action_id or '',)).fetchone()[0]
        if count>=declaration['maximum_ark_transfers']:raise ValueError('finite canary Ark depth/work bound reached')
        recipient=args.get('recipient_actor')
        if recipient not in declaration['actors'] or recipient==actor:
            raise ValueError('recipient outside two-client canary')
        row=store.db.execute('SELECT details FROM actor WHERE id=?',(recipient,)).fetchone()
        if row is None or json.loads(row[0]).get('ark_address')!=args.get('destination'):
            raise ValueError('recipient address differs from original native enrollment')


async def import_unfunded_setup(store,config,directory):
    """Import genuine setup receipts, never fabricate engine action completion."""
    from pathlib import Path
    from .workload import record_actor_result
    from .ownership import verify_client_evidence,record_verified
    directory=Path(directory)
    result_path=directory/'result.json'
    result=json.loads(result_path.read_text())
    digest=hashlib.sha256(result_path.read_bytes()).hexdigest()
    previous=store.get_meta('unfunded_setup_import')
    if previous is not None:
        if previous!=digest:raise ValueError('original setup import immutable')
        return False
    if result['exit_code']!=0 or result['count']!=12 or result['financial_dispatches']!=0 or result['qualified_time_seconds']!=0:
        raise ValueError('complete actual zero-value setup required')
    if store.db.execute('SELECT 1 FROM action LIMIT 1').fetchone():raise ValueError('import original setup before funded queue')
    checked=[]
    for actor in [f'actor-{i:02}' for i in range(1,13)]:
        data={}
        for operation in ('create','address'):
            label=actor+'-'+operation
            raw=(directory/(label+'.stdout.log')).read_bytes()
            terminal=json.loads((directory/(label+'.terminal.json')).read_text())
            if terminal['exit_code']!=0 or terminal['stdout_sha256']!=hashlib.sha256(raw).hexdigest():
                raise ValueError('actual setup bytes/terminal differ')
            reply=json.loads(raw.splitlines()[-1])
            if reply['status']!='ok' or reply['actual_fee_sat']!=0 or reply['action_id']!='a-unfunded-'+operation+'-01-'+actor:
                raise ValueError('actual setup action identity differs')
            data[operation]=reply['data']
        proof=await verify_client_evidence(store,actor,'address',data['address'],config.proof_command)
        if proof is None or len(proof['objects'])!=1:raise ValueError('genuine independent public binding proof required')
        checked.append((actor,data,proof))
    with store.transaction():
        for actor,data,proof in checked:
            record_actor_result(store,actor,'create',data['create'])
            record_actor_result(store,actor,'address',data['address'])
            record_verified(store,actor,'original-unfunded-setup-'+actor,proof)
            store._event('unfunded_client_setup_imported',{'actor':actor,'original_setup_result_sha256':digest,
                'original_created_at':result['completed_utc'],'funding_address':data['create']['funding_address'],
                'advertised_address':data['address']['address'],'actual_public_binding_reverified':True,
                'engine_action_completion':False,'funded_dispatch':False,'qualified_seconds':0})
        store.db.execute("INSERT INTO meta VALUES ('unfunded_setup_import',?)",(digest,))
    return True

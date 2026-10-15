"""Public original-recipient observations; never wallet admission or recovery.

Only retained signed receipts, complete operator snapshots and independent Core
are read. Unknown successors/reservations remain gaps, never zero or paid.
"""
import hashlib
import json
import time

from . import ordinary_arkoor as ordinary,direct_settlements as direct
from .board_adoption import _origin,_digest
from .campaign import _signed_coin
from .final_campaign import _source_event,_recipient_pins
from .fresh_cash_readiness import _fresh,_current_operator_ranges,_empty_mempool,_operator_fee_funding
from .model import SIGNET_GENESIS,InvariantError,btc_to_sat,canonical,public_payload
from .ownership import EvidenceGap
from .public_treasury import confirmed_frontier,match_scanned_cash,check_named_bank,check_current_outputs

KIND='public_absent_recipient_observation'
TABLES={'coins','pending_boards','links','records','pool','lightning_nodes','htlcs','receives','payments',
    'participations','participation_inputs','participation_outputs','nursery','rounds'}|{'journal_'+name for name in direct.TABLES}


def _baseline(store,chain,sequence):
    event,journey=_source_event(store,sequence);plan=ordinary.plan(store)
    if (event['kind']!='ordinary_arkoor_journey_verified' or journey.get('financial_pins')!=plan['pins']
            or journey.get('plan_id')!=plan['id'] or journey.get('boundary_id')!=plan['boundary_id']
            or journey.get('amount_sat')!=plan['amount_sat'] or journey.get('action_id')!=plan['actions']['send']):
        raise ValueError('original completed signed ordinary journey required')
    actor=journey['recipient_actor'];absence=store.permanent_absence(actor)
    declarations=store.db.execute("SELECT sequence FROM event WHERE kind='actor_permanent_absence_declared' AND json_extract(payload,'$.actor')=?",(actor,)).fetchall()
    if absence is None or store.online(actor) or len(declarations)!=1 or declarations[0][0]<=sequence:
        raise ValueError('prospective durable original recipient absence required')
    absence_event,_=_source_event(store,declarations[0][0])
    if store.db.execute('SELECT 1 FROM action WHERE actor_id=? AND created_at>=?',(actor,absence_event['observed_at'])).fetchone():
        raise InvariantError('original absent identity has a later native intent')
    source_event,source=_source_event(store,journey['source_sequence']);origin=_origin(store,chain)
    old=source['origin']
    keys=('financial_pins','boundary_id','board_action_id','vtxo_id','anchor','anchor_output','net_liability_sat','service_charge_sat','funding_fee_sat','mining_fee_sat','expiry_height')
    if (source_event['kind']!=ordinary.KIND or source.get('complete') is not True or source.get('ordinary_step') is not None
            or source.get('financial_pins')!=plan['pins'] or any(origin[key]!=old[key] for key in keys)
            or any(origin['transaction'][key]!=old['transaction'][key] for key in ('txid','inputs','outputs','fee_sat','blockhash'))
            or ordinary._history(store,origin)[0] is not None):raise ValueError('retained complete ordinary source/origin differs')
    transfer_event,transfer=_source_event(store,journey['ark_transfer_sequence'])
    recipient=source['server']['recipient_coins'];leaf_ids=recipient+source['server']['change_coins']
    if (transfer_event['kind']!='ark_transfer_verified' or transfer.get('action_id')!=journey['action_id']
            or transfer.get('recipient_actor')!=actor or transfer.get('amount_sat')!=journey['amount_sat']
            or {coin['coin_id'] for coin in transfer['receipts']}!=set(recipient)
            or len(set(leaf_ids))!=len(leaf_ids)):raise ValueError('original independent recipient receipt differs')
    _recipient_pins(store,actor,recipient,plan['pins']);leaves={}
    for point in leaf_ids:
        owner=actor if point in recipient else journey['sender_actor'];signed=_signed_coin(store,point,owner)
        if signed is None:raise ValueError('retained independently signed current leaf missing')
        row,proof=signed
        if (proof.get('authorization_path_valid') is not True or proof.get('conditional_steps')!=0
                or proof.get('chain_anchor')!=origin['anchor']):raise ValueError('unsupported original ordinary signed source')
        step='receiver_snapshot' if owner==actor else 'sender_snapshot'
        action=store.db.execute('SELECT * FROM action WHERE id=?',(plan['actions'][step],)).fetchone()
        _,snapshot=ordinary._response(store,action)
        originals=[coin for coin in snapshot.get('evidence',{}).get('coins',[]) if coin.get('id')==point]
        if (len(originals)!=1 or originals[0].get('amount_sat')!=row['amount_sat'] or originals[0].get('user_pubkey')!=row['pubkey']
                or hashlib.sha256(bytes.fromhex(originals[0]['signed_vtxo'])).hexdigest()!=row['signed_hash']
                or hashlib.sha256(bytes.fromhex(row['signed_vtxo'])).hexdigest()!=row['signed_hash']):
            raise InvariantError('retained signed object differs from original authenticated native snapshot')
        leaves[point]={'actor':owner,'pubkey':row['pubkey'],'amount_sat':row['amount_sat'],'script':proof['binding']['spk']}
    if (sum(leaf['amount_sat'] for leaf in leaves.values())!=origin['net_liability_sat']
            or source['physical_total_sat']!=665454-origin['funding_fee_sat']-origin['mining_fee_sat']
            or sum(coin['amount_sat'] for coin in source['physical_assets'].values())!=source['physical_total_sat']
            or source['physical_assets'].get(origin['anchor'],{}).get('amount_sat')!=20000):
        raise ValueError('original complete physical/liability conservation differs')
    return event,journey,source,origin,leaves,declarations[0][0]


def _journal(database,baseline):
    public_payload(database);rows=database.get('rows',{})
    if (database.get('kind')!='closed_frontier' or database.get('database_tables_complete') is not True
            or database.get('inventory_consistent') is not True or database.get('read_only') is not True
            or set(rows)!=TABLES or set(baseline['rows'])!=TABLES
            or any(not isinstance(items,list) for items in rows.values()) or sum(map(len,rows.values()))>2000
            or len(canonical(database).encode())>2*1024*1024):raise ValueError('whole bounded current nineteen-table public frontier required')
    allowed={'coins','pending_boards','links','records','nursery'}|{'journal_'+name for name in direct.TABLES}
    if any(items for name,items in rows.items() if name not in allowed):raise EvidenceGap('unsupported LN/pool/round or conditional public frontier')
    for name in ('records','links','journal_records','journal_links'):
        if sorted(rows[name],key=canonical)!=sorted(baseline['rows'][name],key=canonical):raise InvariantError('original public owner record/link changed')
    value={'kind':'direct_journal','schema_version':1,'fallback_protocol':3,'binding_scope':'owners_referenced_by_allocations',
        'journal_complete':True,'inventory_consistent':True,'complete':False,'qualified':False,
        'rows':{name:rows['journal_'+name] for name in direct.TABLES}}
    # The original complete SQL frame is retained; the public direct view's
    # documented record scope is exactly the owners referenced by allocations.
    keys={row['owner_pubkey'] for row in value['rows']['allocations'] if row['owner_pubkey'] is not None}
    value['rows']['links']=[row for row in value['rows']['links'] if row['user_pubkey'] in keys]
    mailboxes={row['mailbox_pk'] for row in value['rows']['links']}
    value['rows']['records']=[row for row in value['rows']['records'] if row['mailbox_pk'] in mailboxes]
    return direct.frame(value)


def _terminal_groups(store,chain,journal,leaves,scripts,tip):
    direct.initialize(store)
    for previous in store.db.execute('SELECT kind,id FROM direct_journal_object'):
        key=direct.TABLES[previous['kind']]
        current={row[key] if key else canonical([row['txid'],row['allocation_id']]) for row in journal['rows'][previous['kind']]}
        if previous['id'] not in current:raise EvidenceGap('whole current direct frontier omits retained known history')
    direct.record(store,journal);transactions={};checked=[];pending=[]
    for txid in sorted(row['txid'] for row in journal['rows']['carriers']):
        try:transactions[txid]=chain.transaction(txid)
        except Exception as error:raise EvidenceGap('retained carrier outcome unknown: '+type(error).__name__) from error
    for row in journal['rows']['allocations']:
        if row['disposition']=='operator':continue
        if row['id'] not in leaves:raise EvidenceGap('allocation is outside original independently signed leaf frontier')
    for carrier in journal['rows']['carriers']:
        for item in carrier['fee_inputs']:
            if scripts.get(item['script_pubkey'],{}).get('member_id') not in {'rounds','watchman'}:
                raise EvidenceGap('supplemental input is not an independently owned operator wallet script')
    for script,owner in scripts.items():
        if owner['member_id'] not in {'rounds','watchman'}:continue
        store.db.execute('INSERT OR IGNORE INTO operator_script VALUES (?,?)',(script,canonical({**owner,'scope':'current full independently derived original operator descriptor coverage'})))
    for freeze in sorted({row['freeze_set'] for row in journal['rows']['allocations']}):
        ids={row['id'] for row in journal['rows']['allocations'] if row['freeze_set']==freeze}
        versions={row['txid'] for row in journal['rows']['mappings'] if row['allocation_id'] in ids}
        if not any(transactions[txid].get('confirmations',0)>0 for txid in versions):
            pending.append(freeze);continue
        result=direct.check_group(store,journal,freeze,transactions);tx=transactions[result['txid']]
        winner=next(row for row in journal['rows']['carriers'] if row['txid']==result['txid'])
        height=tip[0]-tx['confirmations']+1
        if (not 0<=height<=tip[0] or winner['confirmed_height']!=height
                or chain.call('getblockhash',height)!=tx['blockhash']):raise EvidenceGap('actual bestchain carrier height/block membership differs')
        from .bundle_audit import decode_transaction
        raw=chain.tx(tx['txid']);body=decode_transaction(raw['hex'],public_body=True)
        if (body['txid']!=tx['txid'] or body['outputs']!=tx['outputs']
                or [coin['outpoint'] for coin in body['inputs']]!=[coin['outpoint'] for coin in tx['inputs']]
                or raw.get('weight')!=body['weight'] or raw.get('vsize')!=body['vsize']):raise EvidenceGap('actual signed carrier body/weight differs')
        public={key:value for key,value in result.items() if key!='owners'}
        old=store.db.execute('SELECT state,payload FROM direct_check WHERE freeze_set=?',(freeze,)).fetchone()
        if old is None or old['state']!='confirmed_checked' or json.loads(old['payload'])!=public:
            direct.commit_checked(store,result,tx)
        checked.append({'result':result,'transaction':tx,'height':height,'signed_weight_wu':body['weight'],
            'fee_rate_sat_kvb_ceil':(tx['fee_sat']*1000+body['vsize']-1)//body['vsize']})
    return sorted(checked,key=lambda item:(item['height'],item['transaction']['txid'])),pending


def _current_graph(database,baseline,groups):
    old={row['vtxo_id']:row for row in baseline['rows']['coins']};new={row['vtxo_id']:row for row in database['rows']['coins']}
    if len(new)!=len(database['rows']['coins']) or set(old)!=set(new):raise EvidenceGap('whole current graph has extra or missing original coin')
    retirement={}
    for group in groups:
        for point in group['result']['retirement_ids']:
            if point in retirement:raise InvariantError('original physical retirement is duplicated')
            retirement[point]=(group['transaction']['txid'],group['height'])
    for point,row in new.items():
        before=old[point];mutable={'onchain_spent_txid','onchain_spent_height','frontier_at'}
        if {k:v for k,v in row.items() if k not in mutable}!={k:v for k,v in before.items() if k not in mutable}:
            raise EvidenceGap('current public ordinary source changed beyond checked onchain retirement')
        actual=(row.get('onchain_spent_txid'),row.get('onchain_spent_height'))
        if actual!=retirement.get(point,(None,None)):raise EvidenceGap('public source retirement lacks exact checked confirmed spender')
    if not set(retirement)<=set(new):raise EvidenceGap('checked retirement missing from whole public graph')
    pending=database['rows']['pending_boards'];original=baseline['rows']['pending_boards']
    if pending!=original and not (not pending and retirement):raise EvidenceGap('pending Board closure is not independently accounted')
    versions={row['txid'] for row in database['rows']['journal_carriers']}
    if any(row.get('txid') not in versions for row in database['rows']['nursery']):raise EvidenceGap('unrelated nursery source requires its own physical transition proof')


def _record_miner_costs(store,pins,groups):
    total=0
    for group in groups:
        result,tx=group['result'],group['transaction'];total+=tx['fee_sat']
        events=store.db.execute("SELECT sequence FROM event WHERE kind='direct_payment_checked' AND json_extract(payload,'$.freeze_set')=? ORDER BY sequence DESC LIMIT 1",(result['freeze_set'],)).fetchone()
        if events is None:raise ValueError('original public direct check missing')
        _,check=_source_event(store,events[0])
        if check!={key:value for key,value in result.items() if key!='owners'}:raise InvariantError('original direct payment check differs')
        cost={'monetary_id':'bitcoin-miner:'+tx['txid'],'financial_pins':pins,'budget':'ordinary','amount_msat':tx['fee_sat']*1000,
            'mining_fee_sat':tx['fee_sat'],'direct_payment_sequence':events[0],
            'scope':'actual independently confirmed direct carrier miner cost only; customer flat charges and internal service remain inside treasury'}
        prior=store.db.execute("SELECT sequence FROM event WHERE kind='financial_cost_verified' AND json_extract(payload,'$.monetary_id')=?",(cost['monetary_id'],)).fetchall()
        if prior:
            if len(prior)!=1:raise InvariantError('actual direct miner cost recorded twice')
            _,old=_source_event(store,prior[0][0])
            if any(old.get(key)!=value for key,value in cost.items() if key!='direct_payment_sequence'):raise InvariantError('original direct miner cost changed')
            old_event,old_check=_source_event(store,old['direct_payment_sequence'])
            if (old_event['kind']!='direct_payment_checked' or any(old_check.get(key)!=result.get(key)
                    for key in ('txid','freeze_set','accounting','physical_inputs'))):raise InvariantError('original miner cost lost its checked payment provenance')
        else:store.event('financial_cost_verified',cost)
    return total


async def collect_public_absence_sources(store,config,chain,bank_rpc,*,journey_sequence,runtime_source_sequence,current_startup_path):
    """Observe the original signed journey across expiry without client access.

    The result never is financial_operating_readiness. Partial current facts may
    be retried read-only; they confer no spend, sync, recovery or retry authority.
    """
    from .runtime_startup import _read
    from .target_epochs import verified_runtime_source
    from .treasury import boundary
    from .operating_limits import envelope,fee_totals
    from .confirmed_scan import confirmed_scan
    from .funding_bank import collect_funding_bank_source
    from .process import json_command,public_command_capture
    if config.network!='signet' or config.expected_genesis!=SIGNET_GENESIS or not config.inventory_command or store.trace is None:
        raise ValueError('actual traced public operator/Core signet source required')
    started=time.monotonic();event,journey,baseline,origin,leaves,absence_sequence=_baseline(store,chain,journey_sequence)
    current,current_sha=_read(current_startup_path)
    runtime=verified_runtime_source(store,runtime_source_sequence,origin_pins=origin['financial_pins'],current_source_sha256=current_sha)
    limits=envelope(store,config);treasury=boundary(store)
    if (treasury['id']!=baseline['boundary_id'] or treasury['pins']!=baseline['financial_pins'] or treasury['members']!=baseline['members']
            or limits['boundary_id']!=treasury['id'] or limits['pins']!=treasury['pins']
            or runtime['effective_fee_ceilings_sat_kvb']!=limits['fee_ceilings_sat_kvb']):raise ValueError('original whole treasury/current runtime boundary differs')
    before=chain.identity();tip=(before['blocks'],before['bestblockhash'])
    if before.get('chain')!='signet' or before.get('initialblockdownload') is not False:raise ValueError('actual synced independent signet required')
    source={'financial_pins':origin['financial_pins'],'boundary_id':treasury['id'],'members':treasury['members'],
        'journey_sequence':journey_sequence,'journey_event_hash':event['hash'],'absence_sequence':absence_sequence,
        'runtime_source_sequence':runtime_source_sequence,'current_runtime_sha256':current_sha,
        'actual_product_commit':runtime['product_commit'],'financial_pins_scope':'preserved_origin_and_budget_lineage',
        'execution_release':runtime.get('execution_release'),'deployment_epoch_id':runtime.get('deployment_epoch_id'),
        'height':tip[0],'tip_hash':tip[1],'complete':False,'qualified':False,'physical_complete':False,'liabilities_complete':False,
        'fee_inventory_complete':False,'eligible_fee_funding_msat':None,'gaps':[],
        'scope':'public confirmed physical treasury and original signed liability observation only; no admission, wallet access, native dispatch, recovery or final campaign credit'}
    try:
        specs=_current_operator_ranges(baseline,current,tip)
        scripts,ranges,scan,provenance=confirmed_scan(store,config,chain,current,pins=origin['financial_pins'],
            boundary_id=treasury['id'],members=treasury['members'],specs=specs,tip=tip)
        source.update(descriptor_ranges=ranges,confirmed_scan=provenance)
        for leaf in leaves.values():
            if scripts.get(leaf['script'],{}).get('member_id')!=leaf['actor']:raise EvidenceGap('original signed fallback is outside actual owning customer descriptor coverage')
        request={'kind':'closed_frontier'}
        database=await json_command(list(config.inventory_command),request,timeout=25,**public_command_capture(store,'public_absence.closed_frontier',request))
        journal=_journal(database,baseline['database']);store.event('public_absence_database_source',{'response':database,'response_sha256':_digest(database)})
        source['database_source_sequence']=store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
        groups,pending=_terminal_groups(store,chain,journal,leaves,scripts,tip);_current_graph(database,baseline['database'],groups)
        fees=_record_miner_costs(store,origin['financial_pins'],groups)
        physical=confirmed_frontier(baseline['physical_assets'],[group['transaction'] for group in groups],scripts)
        for group in groups:
            for coin in group['transaction']['inputs']:
                txid,index=coin['outpoint'].rsplit(':',1)
                if chain.call('gettxout',txid,int(index),False) is not None:raise EvidenceGap('confirmed physical root and successor are both reported unspent')
        expected={point:coin for point,coin in physical.items() if coin['script'] in scripts}
        observed=match_scanned_cash(scan,expected)
        check_current_outputs(chain,physical,started)
        source.update(physical_assets=physical,physical_total_sat=sum(coin['amount_sat'] for coin in physical.values()),physical_complete=True)
        source['capital_exposure_msat']=source['physical_total_sat']*1000
        if source['capital_exposure_msat']>limits['capital_exposure_msat']:source['gaps'].append('actual physical capital exceeds original declared exposure ceiling')
        dispositions={point:{**leaf,'state':'unsettled','payout_sat':0,'flat_fee_sat':0,'forfeited_sat':0} for point,leaf in leaves.items()}
        for group in groups:
            for allocation,owner in group['result']['owners']:
                expected_leaf=leaves[allocation['id']]
                if owner['actor']!=expected_leaf['actor'] or allocation['gross_sat']!=expected_leaf['amount_sat']:raise InvariantError('checked disposition differs from original signed leaf owner')
                dispositions[allocation['id']]={**expected_leaf,'state':'confirmed_pay' if allocation['disposition']=='pay' else 'confirmed_forfeit',
                    'payout_sat':allocation['payout_sat'],'flat_fee_sat':allocation['fee_sat'],'forfeited_sat':allocation['forfeited_sat'],'txid':group['transaction']['txid']}
        if groups and any(leaf['state']=='unsettled' for leaf in dispositions.values()):raise EvidenceGap('confirmed backing consumption leaves an unclassified original liability')
        source.update(liabilities=list(dispositions.values()),liabilities_complete=True,
            outstanding_liability_sat=sum(leaf['amount_sat'] for leaf in dispositions.values() if leaf['state']=='unsettled'),
            pending_freeze_sets=pending,checked_carriers=[{'txid':group['transaction']['txid'],'height':group['height'],
                'signed_weight_wu':group['signed_weight_wu'],'fee_rate_sat_kvb_ceil':group['fee_rate_sat_kvb_ceil'],
                'accounting':group['result']['accounting']} for group in groups],
            direct_miner_fee_sat=fees,internal_service_sat=origin['service_charge_sat'])
        source['mempool']=_empty_mempool(chain,set(scripts)|{coin['script'] for coin in physical.values()},started)
        bankseq=collect_funding_bank_source(store,bank_rpc,chain);_,bank=_source_event(store,bankseq)
        check_named_bank(bank,origin['funding_plan']['bank_wallet_name'],observed,tip);source['bank_source_sequence']=bankseq
        sequences={}
        for member in treasury['members']:
            coins=[{'outpoint':point,**{key:coin[key] for key in ('amount_sat','script','descriptor_index','child_index')}} for point,coin in observed.items() if coin['member_id']==member['id']]
            store.event('treasury_inventory',{'member_id':member['id'],'identity':member['identity'],'financial_pins':origin['financial_pins'],
                'height':tip[0],'tip_hash':tip[1],'complete':True,'utxos':coins,'scope':'whole current public descriptor cash; physical backing and liabilities separately classified'})
            sequences[member['id']]=store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
        source['inventory_sequences']=sequences
        cash={'assets':{point:{'member':coin['member_id'],'amount_msat':coin['amount_sat']*1000} for point,coin in observed.items()}}
        try:
            source['eligible_fee_funding_msat']=_operator_fee_funding(store,source,cash,current);source['fee_inventory_complete']=True
        except ValueError as error:source['gaps'].append('owning fee inventory/reservations: '+str(error))
        used=fee_totals(store,origin['financial_pins']);source['budget_used_msat']=used
        source['budget_remaining_msat']={key:limits['fee_budgets_msat'][key]-used[key] for key in ('ordinary','urgent')}
        if used!={'ordinary':(origin['funding_fee_sat']+origin['mining_fee_sat']+fees)*1000,'urgent':0}:raise EvidenceGap('financial cost ledger has another unaccounted monetary source')
        if min(source['budget_remaining_msat'].values())<0:raise InvariantError('actual cumulative ordinary/urgent budget exceeded')
        eligible=source['eligible_fee_funding_msat']
        source['remaining_fee_budget_backed']=None if eligible is None else eligible>=sum(source['budget_remaining_msat'].values())
        if source['remaining_fee_budget_backed'] is False:source['gaps'].append('actual eligible operator capital does not back remaining declared fee budgets')
        source['estimated_fee_rate_sat_kvb']=btc_to_sat(chain.call('estimatesmartfee',6)['feerate'])
        ceiling=min(runtime['effective_fee_ceilings_sat_kvb'][key] for key in ('sweep','payout'))
        if not 0<source['estimated_fee_rate_sat_kvb']<=ceiling:source['gaps'].append('actual estimate is outside declared ordinary sweep/payout ceiling')
        if any(group['transaction']['fee_sat']>runtime['direct_carrier_max_miner_fee_sat'] for group in groups):source['gaps'].append('actual confirmed carrier exceeded loaded absolute miner ceiling')
        if any(group['fee_rate_sat_kvb_ceil']>ceiling for group in groups):source['gaps'].append('actual signed carrier exceeded loaded ordinary fee-rate ceiling')
        ending=await json_command(list(config.inventory_command),request,timeout=25,**public_command_capture(store,'public_absence.closed_frontier_end',request))
        _journal(ending,baseline['database'])
        if ending.get('rows')!=database['rows']:raise EvidenceGap('whole current database frontier changed during observation')
        store.event('public_absence_database_source',{'response':ending,'response_sha256':_digest(ending),'phase':'end'})
        source['database_end_source_sequence']=store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
        _,current_end_sha=_read(current_startup_path)
        if current_end_sha!=current_sha:raise EvidenceGap('actual loaded runtime source changed during observation')
        check_current_outputs(chain,physical,started)
        _fresh(runtime['observed_at'])
        if time.monotonic()-started>180:raise EvidenceGap('whole public source deadline exceeded')
        end=chain.identity()
        if end.get('initialblockdownload') is not False or (end['blocks'],end['bestblockhash'])!=tip:raise EvidenceGap('independent confirmed tip changed during observation')
        source['observation_complete']=not source['gaps']
    except InvariantError:raise
    except (ValueError,KeyError) as error:
        source.update(observation_complete=False,physical_complete=False,liabilities_complete=False,
            fee_inventory_complete=False,eligible_fee_funding_msat=None,remaining_fee_budget_backed=None)
        source['gaps'].append(str(error))
    source['observed_at']=time.time();public_payload(source)
    if len(canonical(source).encode())>4*1024*1024:raise ValueError('whole public observation receipt exceeds byte bound')
    store.event(KIND,source);sequence=store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
    return {'source_sequence':sequence,'source':source}

"""C direct-carrier fee reservations and confirmed costs from original bytes.

The admitted collector supplies an authenticated whole private filesystem/RR cut.
This reducer neither discovers files nor authenticates a transport. It uses the
shared transaction decoder and existing append-only money join. C's decimal
reservation ledger is not A's epoch ledger and a reservation is never payment.
"""
import hashlib
import json
import re
import time

from .bundle_audit import decode_transaction
from .final_campaign import _pins, _source_event
from .model import SIGNET_GENESIS, canonical, integer, public_payload

MAX_BYTES = 16 * 1024 * 1024
MAX_ROWS = 10000
# Native identity.json uses bitcoin::constants::ChainHash Display (BOLT order),
# distinct from the RPC genesis BlockHash displayed by independent Core.
NATIVE_SIGNET_CHAIN_HASH = 'f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _id(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError('canonical original SHA/transaction identity required')
    return value


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise ValueError('duplicate private fee JSON field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite private source')))


def _raw(value, maximum=MAX_BYTES):
    if not isinstance(value, str) or len(value)>maximum*2 or re.fullmatch('(?:[0-9a-f]{2})*',value) is None:
        raise ValueError('bounded exact private native source bytes required')
    return bytes.fromhex(value)


def _native_vec(values):
    # Exact serde_json Vec<String> encoding in direct_delivery.rs:69.
    return json.dumps(values, ensure_ascii=False, separators=(',', ':')).encode()


def _observation(source, pins, height, tip):
    observation = source.get('source_observation')
    if (not isinstance(observation, dict) or observation.get('architecture_profile')!='direct_per_key'
            or observation.get('financial_pins')!=pins or not isinstance(observation.get('id'),str)
            or not observation['id'] or observation.get('height')!=height or observation.get('tip_hash')!=tip
            or type(observation.get('started_at')) not in (int,float)
            or not 0<=time.time()-observation['started_at']<=90):
        raise ValueError('current normal source observation identity/tip/pins required')
    return observation


def collect_cost_records(store, chain, *, config, private_cut, source_event, source,
                         expected_history_identity, expected_policy_sha256,
                         expected_server_pubkey, maximum_carrier_fee_sat=20000):
    """Return the unchanged shared money-join ABI plus conservative held exposure.

    private_cut exact fields: schema_version/root_identity/identity_hex/policy_hex/
    budget_hex/history_hex/records/allocation_witnesses/carrier_witnesses. The last
    two maps contain EXACT original PostgreSQL jsonb witness strings, in the same
    authenticated RR cut as source['database']; never caller-reencoded JSON.
    Missing private coverage holds even if a public DB row says confirmed.
    """
    store.verify_event_chain(); parent, original = _source_event(store,source_event['sequence'])
    if parent['hash']!=source_event['hash'] or parent['kind']!='normal_financial_source' or original!=source:
        raise ValueError('original normal source event differs')
    pins=_pins(source.get('financial_pins'))
    from . import frontier_source
    if frontier_source.schema(config)!=2 or type(source.get('database_source_sequence'))is not int:
        raise ValueError('explicit schema2 original protected source required')
    frontier_source.verify_source(store,config,source,pins)
    original_database_event,_=_source_event(store,source['database_source_sequence'])
    if not isinstance(private_cut,bytes) or len(private_cut)>MAX_BYTES or digest(private_cut)!=source.get('private_native_fee_sha256'):
        raise ValueError('whole authenticated private fee cut missing or changed')
    cut=_json(private_cut)
    if not isinstance(expected_history_identity,dict) or set(expected_history_identity)!={'device','inode','uid','mode'}:
        raise ValueError('independently admitted filesystem history identity required')
    for key in ('device','inode','uid','mode'):integer(expected_history_identity[key],'history '+key)
    if not 0<integer(maximum_carrier_fee_sat,'native carrier cap')<=20000 or source.get('direct_carrier_max_miner_fee_sat')!=maximum_carrier_fee_sat:
        raise ValueError('original native carrier ceiling missing or raised')
    if (set(cut)!={'schema_version','root_identity','identity_hex','policy_hex','budget_hex','history_hex',
                  'records','allocation_witnesses','carrier_witnesses','database_snapshot'}
            or type(cut['schema_version']) is not int or cut['schema_version']!=1
            or cut['root_identity']!=expected_history_identity
            or source.get('native_history_root_identity')!=expected_history_identity):
        raise ValueError('native independent history root differs')
    policy_raw=_raw(cut['policy_hex'],65536);policy=_json(policy_raw)
    if (digest(policy_raw)!=_id(expected_policy_sha256)
            or source.get('native_fee_policy_sha256')!=expected_policy_sha256
            or set(policy)!={'urgent_reserve_sat','ordinary_budget_sat'}
            or integer(policy['urgent_reserve_sat'],'urgent floor',40000)<40000
            or not 0<integer(policy['ordinary_budget_sat'],'ordinary budget')<=60000):
        raise ValueError('immutable live native ordinary policy differs')
    identity=_json(_raw(cut['identity_hex'],65536))
    if type(identity.get('version'))is not int or identity!={'version':1,'genesis':NATIVE_SIGNET_CHAIN_HASH,'server_pubkey':expected_server_pubkey}:
        raise ValueError('independent native history network/server identity differs')
    ledger=_raw(cut['budget_hex'],2*1024*1024)
    if ledger and not ledger.endswith(b'\n'):raise ValueError('torn native reservation history')
    entries=[]
    for raw in ledger.splitlines():
        if not re.fullmatch(b'[1-9][0-9]*',raw):raise ValueError('noncanonical native reservation')
        amount=int(raw)
        if amount>policy['ordinary_budget_sat']:raise ValueError('native reservation exceeds immutable policy')
        entries.append(amount)
    charged=sum(entries)
    if charged>policy['ordinary_budget_sat']:raise ValueError('native cumulative ordinary budget exceeded')
    index_bytes=_raw(cut['history_hex'],MAX_ROWS*65)
    if index_bytes and not index_bytes.endswith(b'\n'):raise ValueError('torn independent carrier history')
    ids=index_bytes.decode('ascii').splitlines()
    if len(ids)>MAX_ROWS or len(ids)!=len(set(ids)):raise ValueError('duplicate/bounded independent carrier index required')
    for txid in ids:_id(txid)
    records=cut['records'];witnesses=cut['carrier_witnesses'];allocations=cut['allocation_witnesses']
    if (not isinstance(records,dict) or not isinstance(witnesses,dict) or not isinstance(allocations,dict)
            or set(records)!=set(ids) or set(witnesses)!=set(ids)):
        raise ValueError('whole private witness/index coverage differs')
    database=source.get('database')
    if (not isinstance(database,dict) or database.get('architecture_profile')!='direct_per_key'
            or database.get('database_tables_complete') is not True or database.get('inventory_consistent') is not True
            or database.get('read_only') is not True or database.get('complete') is not False
            or database.get('qualified') is not False or database.get('fallback_protocol')!=4
            or database.get('declared_financial_pins')!=pins or cut['database_snapshot']!=database.get('snapshot')):
        raise ValueError('original protected whole public PG frame required')
    rows=database['rows'];carriers=rows['journal_carriers']
    if (not isinstance(carriers,list) or len(carriers)>MAX_ROWS or len({v['txid']for v in carriers})!=len(carriers)
            or {v['txid']for v in carriers}!=set(ids)):
        raise ValueError('private history and whole PG carrier membership differ')
    if len(ids)>len(entries):raise ValueError('signed carrier lacks its native construction reservation')
    public={v['txid']:v for v in carriers};groups={v['freeze_set']for v in rows['journal_allocations']}
    if set(allocations)!=groups:raise ValueError('whole private allocation group coverage differs')
    before=chain.identity();height=integer(before['blocks'],'source height');tip=_id(before['bestblockhash'])
    if before.get('initialblockdownload') is not False or chain.call('getblockhash',0)!=SIGNET_GENESIS:
        raise ValueError('independent synchronized official Signet chain required')
    observation=_observation(source,pins,height,tip)
    if not observation['started_at']<=original_database_event['observed_at']<=time.time():
        raise ValueError('current invocation must collect new original protected database source')
    previous=store.db.execute("SELECT sequence FROM event WHERE kind='normal_financial_source_cost_join' AND json_extract(payload,'$.money_evidence_hashes.native_fee.history_identity') IS NOT NULL ORDER BY sequence DESC LIMIT 1").fetchone()
    if previous:
        _,old=_source_event(store,previous[0]);prior=old['money_evidence_hashes']['native_fee']
        if (prior['history_identity']!=expected_history_identity or prior['policy_sha256']!=expected_policy_sha256
                or entries[:len(prior['ordinary_reservations_sat'])]!=prior['ordinary_reservations_sat']
                or ids[:len(prior['history_txids'])]!=prior['history_txids']
                or any(digest(_raw(records.get(k,'')))!=v for k,v in prior['record_sha256'].items())):
            raise ValueError('native fee/history rollback or original replacement')
    by_tx={};existing_ids=set()
    for row in store.db.execute("SELECT sequence FROM event WHERE kind='financial_cost_verified'"):
        _,cost=_source_event(store,row[0]);ident=cost['monetary_id']
        txid=cost.get('txid')
        if txid is None and isinstance(ident,str) and ident.startswith(('miner:','bitcoin-miner:')):txid=ident.split(':',1)[1]
        if txid is None:continue
        _id(txid)
        if txid in by_tx or ident in existing_ids:raise ValueError('same physical miner transaction already costed twice')
        if cost.get('direct_payment_sequence')is not None and txid not in records:
            raise ValueError('original direct miner cost lost its retained private witness')
        by_tx[txid]=cost;existing_ids.add(ident)
    costs=[];reused=[];zeros={};pending={};record_hashes={};evidence={};confirmed_total=0;signed_total=0;freeze_for={}
    started=time.monotonic();cache={};bytes_seen=0
    def read(txid):
        nonlocal bytes_seen
        if len(cache)>=512 or time.monotonic()-started>20:raise ValueError('native miner Core proof bound exceeded')
        if txid not in cache:
            value=chain.tx(_id(txid));raw=_raw(value['hex']);decoded=decode_transaction(raw.hex())
            bytes_seen+=len(raw)
            if bytes_seen>MAX_BYTES or decoded['txid']!=txid or value.get('txid')!=txid:raise ValueError('independent Core original transaction differs')
            cache[txid]=(value,raw,decoded)
        return cache[txid]
    for txid in ids:
        raw_record=_raw(records[txid]);record_hashes[txid]=digest(raw_record);record=_json(raw_record)
        if set(record)!={'freeze_set','tx','allocation_hash','carrier_hash'}:raise ValueError('native DirectRecord fields differ')
        freeze=record['freeze_set'];freeze_for[txid]=freeze
        original_allocations=allocations.get(freeze)
        if not isinstance(original_allocations,list) or not original_allocations or any(not isinstance(v,str)for v in original_allocations):raise ValueError('original ordered allocation witnesses missing')
        public_allocations=sorted([v for v in rows['journal_allocations']if v['freeze_set']==freeze],key=lambda v:v['id'])
        private_allocations=[_json(v)for v in original_allocations]
        if len(private_allocations)!=len(public_allocations):raise ValueError('private/public allocation membership differs')
        for private,allocation in zip(private_allocations,public_allocations):
            if set(private)!={'id','owner','spk','disposition','gross','fee','payout','forfeited','source','evidence','retirement'}:
                raise ValueError('original private allocation witness fields differ')
            expected={'id':allocation['id'],'owner':None if allocation['owner_pubkey']is None else '\\x'+allocation['owner_pubkey'],
                'spk':None if allocation['spk']is None else '\\x'+allocation['spk'],'disposition':allocation['disposition'],
                'gross':allocation['gross_sat'],'fee':allocation['fee_sat'],'payout':allocation['payout_sat'],
                'forfeited':allocation['forfeited_sat'],'source':allocation['source'],'retirement':allocation['retirement_ids']}
            if any(private.get(k)!=v for k,v in expected.items()):raise ValueError('private/public allocation economics or owner differs')
        if digest(_native_vec(original_allocations))!=record['allocation_hash'] or digest(witnesses[txid].encode())!=record['carrier_hash']:
            raise ValueError('independent native witness differs from original PG allocation/carrier hash')
        c=_json(witnesses[txid]);row=public[txid]
        if (set(c)!={'generation','backing','fee_inputs','miner','subsidy','mappings'}
                or c.get('generation')!=row['generation'] or c.get('backing')!=row['backing_ids']
                or c.get('fee_inputs')!=row['fee_inputs'] or c.get('miner')!=row['miner_fee_sat']
                or c.get('subsidy')!=row['funding_subsidy_sat']):raise ValueError('private PG carrier differs from public source')
        actual_mapping=sorted([{'id':v['allocation_id'],'vout':v['vout']}for v in rows['journal_mappings']if v['txid']==txid],key=lambda v:v['id'])
        if c.get('mappings')!=actual_mapping:raise ValueError('private/public carrier allocation mappings differ')
        if not isinstance(record['tx'],list) or any(type(v)is not int or not 0<=v<=255 for v in record['tx']):raise ValueError('exact private native signed bytes required')
        signed=bytes(record['tx']);decoded=decode_transaction(signed.hex(),public_body=True)
        if not decoded['witness_redacted']:raise ValueError('native signed SegWit witness missing')
        if decoded['txid']!=txid:raise ValueError('signed native witness transaction identity differs')
        fee=integer(row['miner_fee_sat'],'native signed fee')
        if fee>maximum_carrier_fee_sat:raise ValueError('native signed carrier exceeds immutable miner cap')
        signed_total+=fee
        # All signed versions remain reserved. Unknown RPC/missing parents HOLD,
        # never a typed absence manufactured from a generic exception.
        actual,actual_raw,tx=read(txid)
        if actual_raw!=signed:raise ValueError('independent confirmed/native witness bytes differ')
        confirmations=integer(actual.get('confirmations',0),'actual confirmations')
        if not confirmations:
            if txid in by_tx:raise ValueError('previously costed carrier is no longer confirmed; reconciliation required')
            pending[txid]={'txid':txid,'reason':'retained signed carrier not independently confirmed','budget':'ordinary'};continue
        block=_id(actual.get('blockhash'));block_height=height-confirmations+1
        if block_height<0 or chain.call('getblockhash',block_height)!=block:raise ValueError('carrier not confirmed on independent active chain')
        gross=0;points=set()
        for point in tx['inputs']:
            ident=point['outpoint']
            if ident in points:raise ValueError('duplicate miner input')
            points.add(ident);parent_id,index=ident.rsplit(':',1);_,_,parent_tx=read(parent_id)
            if int(index)>=len(parent_tx['outputs']):raise ValueError('original miner prevout missing')
            gross+=parent_tx['outputs'][int(index)]['amount_sat']
        measured=gross-sum(o['amount_sat']for o in tx['outputs'])
        if measured<0 or measured!=fee:raise ValueError('native miner fee differs from independently measured parents')
        backing=row['backing_ids'];fee_inputs=row['fee_inputs']
        if (not isinstance(backing,list) or not isinstance(fee_inputs,list) or len(backing)!=len(set(backing))
                or any(not isinstance(v,dict) or set(v)!={'outpoint','value_sat','script_pubkey'}for v in fee_inputs)):
            raise ValueError('complete exact carrier physical-input metadata required')
        expected=backing+[v['outpoint']for v in fee_inputs]
        if len(expected)!=len(set(expected)) or set(expected)!=points:raise ValueError('native carrier physical input partition differs')
        for value in fee_inputs:
            parent_id,index=value['outpoint'].rsplit(':',1);_,_,original_parent=read(parent_id)
            output=original_parent['outputs'][int(index)]
            if output['amount_sat']!=integer(value['value_sat'],'native fee prevout') or output['script']!=value['script_pubkey']:
                raise ValueError('native fee input metadata differs from actual Core parent')
        checks=store.db.execute("SELECT sequence FROM event WHERE kind='direct_payment_checked' AND json_extract(payload,'$.txid')=? ORDER BY sequence",(txid,)).fetchall()
        if not checks:raise ValueError('original direct ownership/liability payment check missing')
        checked_event,checked=_source_event(store,checks[0][0])
        if (checked.get('freeze_set')!=freeze or checked.get('physical_inputs')!=sorted(points)
                or set(checked.get('carrier_versions',[]))!={k for k in ids if _json(_raw(records[k]))['freeze_set']==freeze}):
            raise ValueError('confirmed carrier lost original whole-group liability/physical-input proof')
        if row.get('confirmed_height')!=block_height or row.get('confirmed_block')!=block:raise ValueError('PG confirmation differs from independent Core')
        confirmed_total+=fee;evidence[txid]={'record_sha256':record_hashes[txid],'signed_raw_sha256':digest(signed),'blockhash':block,'direct_payment_sequence':checked_event['sequence']}
        old=by_tx.get(txid)
        if old:
            if old.get('financial_pins')!=pins or old.get('budget')!='ordinary' or old.get('amount_msat')!=fee*1000:raise ValueError('original miner cost context/amount differs')
            if not fee:raise ValueError('zero carrier already booked as positive miner expense')
            reused.append(old['monetary_id'])
        elif fee:
            payer=source.get('direct_carrier_cost_member');members=source.get('members',[])
            matches=[v for v in members if v.get('id')==payer and v.get('role')=='operator' and v.get('kind')in('wallet','ark_backing')]
            if len(matches)!=1:raise ValueError('actual declared operator miner-cost member missing or ambiguous')
            member=matches[0];member_event,proof=_source_event(store,member['verification_sequence'])
            if (member_event['kind']!='treasury_member_verified' or proof.get('financial_pins')!=pins
                    or proof.get('genesis')!=SIGNET_GENESIS or proof.get('member')!={k:v for k,v in member.items()if k!='verification_sequence'}):
                raise ValueError('original operator miner-cost member source differs')
            costs.append({'monetary_id':'miner:'+txid,'kind':'miner_cost','txid':txid,'amount_msat':fee*1000,'budget':'ordinary',
                          'source':payer,'destination':'miners','financial_pins':pins})
        else:zeros[txid]={'txid':txid,'fee_sat':0,'raw_sha256':digest(signed),'blockhash':block,'budget':'ordinary'}
    if set(freeze_for.values())!=groups:raise ValueError('frozen allocation liabilities lack retained complete carrier coverage')
    if signed_total>charged or confirmed_total>charged:raise ValueError('native ordinary ledger does not cover retained signed fees')
    end=chain.identity()
    if (end['blocks'],end['bestblockhash'])!=(height,tip):raise ValueError('independent chain changed during native fee source')
    native={'history_identity':expected_history_identity,'policy_sha256':expected_policy_sha256,'ordinary_reservations_sat':entries,
            'ordinary_booked_sat':charged,'ordinary_confirmed_cost_sat':confirmed_total,'ordinary_held_sat':charged-confirmed_total,
            'ordinary_total_sat':policy['ordinary_budget_sat'],'ordinary_remaining_sat':policy['ordinary_budget_sat']-charged,
            'urgent_protected_floor_sat':policy['urgent_reserve_sat'],'urgent_fee_cost_coverage':None,
            'history_txids':ids,'record_sha256':record_hashes,'ledger_sha256':digest(ledger),'index_sha256':digest(index_bytes),
            'scope':'Direct-carrier reservation exposure only; no pool/router/urgent-cost or aggregate readiness coverage'}
    return {'cost_records':costs,'flow_records':[],'zero_fee_carriers':zeros,'pending_carriers':pending,'reused_cost_ids':reused,
            'reused_flow_ids':[],'client_service_charges':[], 'evidence_hashes':{'private_native_fee_sha256':digest(private_cut),
            'carrier_sources':evidence,'source_observation':observation,'native_fee':native},'native_fee':native}


def journal_cost_records(store, result, source_event, source):
    """Use A's existing journal join unchanged; absence is an integration HOLD."""
    try:
        from .normal_money_join import journal_money_sources
    except ModuleNotFoundError as error:
        if error.name!='simulator.normal_money_join':raise
        from .ownership import EvidenceGap
        raise EvidenceGap('existing shared money importer is not installed; retain source-only HOLD') from None
    # Only the pure, original-byte reducer above supplies result. This function
    # creates no normal readiness event or authority to call the shared Engine.
    return journal_money_sources(store,result,source_event,source,helper_sha256=digest(__file_bytes()))


def __file_bytes():
    from pathlib import Path
    return Path(__file__).read_bytes()

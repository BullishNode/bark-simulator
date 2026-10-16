"""The closed cohort's initial five-output funding prerequisite, from actual sources.

This is deliberately restricted to the empty monetary frontier before funding.
It does not qualify any Board, transfer, claim, refresh, round or progression.
The existing Engine and once-only funding adapter retain dispatch authority.
"""
from . import frontier_source
import hashlib
import json
import stat
import time
from pathlib import Path

from .final_campaign import _source_event
from .funding_bank import collect_funding_bank_source
from .identity_bootstrap import declaration, require_only_verified_creates, _root
from .model import SIGNET_GENESIS, btc_to_sat, canonical, integer, public_payload
from .process import json_command, public_command_capture
from .runtime_startup import _read
from .trace import normalized
from .architecture import DIRECT_PER_KEY, profile

CUSTOMERS={'actor-01','actor-02','actor-04'}
TABLES={'coins','pending_boards','links','records','pool','lightning_nodes','htlcs','receives','payments',
    'participations','participation_inputs','participation_outputs','journal_allocations','journal_carriers',
    'journal_mappings','journal_records','journal_links','nursery','rounds'}
OPENING_SAT=665454
PRINCIPAL_SAT=325000
FUNDING_FEE_SAT=10000
MAX_RATE_SAT_KVB=20000


def _policy(store):
    if profile(store)==DIRECT_PER_KEY:
        from .c_pilot import funding_policy
        return funding_policy(store)
    return {'customers':CUSTOMERS,'opening_sat':OPENING_SAT,'principal_sat':PRINCIPAL_SAT,
        'maximum_fee_sat':FUNDING_FEE_SAT,'maximum_rate_sat_kvb':MAX_RATE_SAT_KVB,
        'amounts':{'rounds':100000,'watchman':75000,**{actor:50000 for actor in CUSTOMERS}},
        'ordinary_budget_sat':60000,'urgent_budget_sat':15000,'grant_sat':50000,
        'board_sat':20000,'board_fee_reserve_sat':4000}


def _c_records_links(store, customer_data, pins):
    from .per_key import initial_origins, record_envelope, proof_matches, binding_matches
    records=[];links=[]
    for actor,data in sorted(customer_data.items()):
        binding=data['binding'];wire=record_envelope(binding)
        records.append({'mailbox_pk':binding['mailbox_pk'],'spk':binding['spk'],'mailbox_sig':wire[-64:].hex()})
        origins=initial_origins(data)
        for origin in origins:
            row=store.db.execute('SELECT * FROM owner_key WHERE pubkey=?',(origin['user_pubkey'],)).fetchone()
            checked=json.loads(row['proof']) if row else {}
            if (not row or row['actor']!=actor or checked.get('financial_pins')!=pins
                    or not proof_matches(checked,origin) or not binding_matches(checked.get('binding',{}),binding)):
                raise ValueError('original independently verified C creation link required')
            raw=bytes.fromhex(origin['key_link_attestation'])
            links.append({'user_pubkey':origin['user_pubkey'],'mailbox_pk':binding['mailbox_pk'],
                'sig':raw[-64:].hex(),'recovery_index':int.from_bytes(raw[35:39],'little')})
        from .c_pilot import verify_public_key_rows
        verify_public_key_rows(store,actor,origins,initial=True)
    if len({r['mailbox_pk'] for r in records})!=2 or len({r['spk'] for r in records})!=2 or len({l['user_pubkey'] for l in links})!=102:
        raise ValueError('two distinct C identities and 102 original unique links required')
    return sorted(records,key=lambda r:r['mailbox_pk']),sorted(links,key=lambda r:r['user_pubkey'])


def _digest(value):return hashlib.sha256(canonical(value).encode()).hexdigest()


def _fresh(value,name):
    if not isinstance(value,(int,float)) or isinstance(value,bool) or not 0<=time.time()-value<=90:
        raise ValueError('fresh '+name+' source required')


def _record(binding):
    """Compare every public signed-record byte to the original native record."""
    raw=bytes.fromhex(binding['fallback_record'])
    if len(raw)<2 or raw[0]!=3 or not 22<=raw[1]<=42 or len(raw)!=2+raw[1]+78+128:
        raise ValueError('pinned public record encoding required')
    end=2+raw[1]
    if raw[2:end].hex()!=binding['spk']:raise ValueError('native binding script differs')
    return {'mailbox_pk':binding['mailbox_pk'],'spk':raw[2:end].hex(),'account_xpub':raw[end:end+78].hex(),
        'mailbox_sig':raw[end+78:end+142].hex(),'account_sig':raw[end+142:].hex()}


def _initial(store,pins):
    require_only_verified_creates(store,pins)
    if store.db.execute("SELECT 1 FROM event WHERE kind IN ('fixture_funding_intent','fixture_funding_prepared','fixture_funding_broadcast_intent','closed_cohort_funding_intent','closed_cohort_funding_prepared','closed_cohort_funding_broadcast_intent','financial_cost_verified') LIMIT 1").fetchone():
        raise ValueError('initial-only source refuses any funding or paid history')
    if store.db.execute("SELECT 1 FROM action WHERE operation!='create' OR state!='completed' OR actual_fee_sat!=0 OR fee_reservation_sat!=0 LIMIT 1").fetchone():
        raise ValueError('only the original zero-fee creates may precede initial funding')


def _empty_owner(frame,owner,tip):
    if (not isinstance(frame,dict) or frame.get('wallet')!=owner or frame.get('network')!='signet'
            or frame.get('complete') is not True or (frame.get('tip_height'),frame.get('tip_hash'))!=tip
            or any(frame.get(field)!=[] for field in ('utxos','pending_transactions','pending_parents','unavailable_parent_txids','reserved_outpoints'))):
        raise ValueError('complete current empty owning '+owner+' wallet required')
    frontier=frame.get('last_revealed_index')
    if type(frontier) is not int or not 0<=frontier<1980:raise ValueError('bounded already-revealed owning wallet frontier required')
    return {'descriptors':[frame['public_descriptor']],'ranges':[frontier+20],'recipient_index':0}


async def collect_initial_funding_sources(store,config,chain,bank_rpc,*,runtime_source_sequence,current_startup_path,boundary_id):
    """Read actual sources and emit six verified members/inventories, without funding.

    Root must validate the exact startup capture first. The named bank collector
    is refreshed after expensive independent scans. No supplied complete labels
    or manually assembled monetary frames are accepted as source substitutes.
    """
    started=time.monotonic()
    policy=_policy(store);customers=policy['customers'];per_key=profile(store)==DIRECT_PER_KEY
    def remaining(limit):
        value=min(limit,180-(time.monotonic()-started))
        if value<=0:raise ValueError('initial funding source deadline exceeded')
        return value
    proof=declaration(store)
    if proof is None or set(proof['declaration']['actors'])!=customers:
        raise ValueError('exact fresh three-customer bootstrap required')
    pins=proof['declaration']['pins'];_initial(store,pins)
    if per_key and (policy['pins']!=pins or policy['boundary_id']!=boundary_id):
        raise ValueError('C pilot identity/treasury context differs')
    wallet_root=Path(proof['declaration']['wallet_root'])
    if str(config.wallet_root)!=str(wallet_root) or _root(str(wallet_root))!=proof['filesystem']:
        raise ValueError('original private cohort root identity changed')
    children={child.name:child for child in wallet_root.iterdir()}
    if set(children)-({'supervisor.lock'}|customers) or not customers<=set(children):
        raise ValueError('cohort root contains missing or unenumerated wallets')
    for actor in customers:
        info=children[actor].lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o700 or info.st_uid!=proof['filesystem']['uid']:
            raise ValueError('actual private customer directory required')
    if not config.inventory_command or chain is None or config.network!='signet' or config.expected_genesis!=SIGNET_GENESIS:
        raise ValueError('actual readonly bridge and independent signet required')
    if getattr(store,'trace',None) is None:raise ValueError('original source trace capture required')
    runtime_event,runtime=_source_event(store,runtime_source_sequence)
    current,current_sha=_read(current_startup_path)
    if (runtime_event['kind']!='owned_runtime_configuration_verified' or runtime.get('loaded_configuration_identity_verified') is not True
            or runtime.get('product_commit')!=pins['product_commit'] or runtime.get('schema_sha256')!=pins['schema_sha256']
            or runtime.get('current_source_sha256')!=current_sha):
        raise ValueError('original exact loaded runtime source required')
    _fresh(runtime['observed_at'],'runtime')
    before=chain.identity();tip=(before['blocks'],before['bestblockhash'])
    if before.get('chain')!='signet' or before.get('initialblockdownload') is not False:
        raise ValueError('synchronized independent signet required')
    bank_sequence=collect_funding_bank_source(store,bank_rpc,chain,timeout_seconds=remaining(30))
    _,bank=_source_event(store,bank_sequence)
    _fresh(bank['completed_at'],'bank')
    if (bank.get('height'),bank.get('tip_hash'))!=tip:raise ValueError('bank source tip differs')
    if (bank.get('pending_transactions')!=[] or bank.get('pending_parents')!=[] or bank.get('locked_coins')!=[]
            or bank.get('listlockunspent')!=[] or bank.get('listsinceblock',{}).get('transactions')!=[]):
        raise ValueError('initial named bank must have no pending transactions or locks')
    bank_coins=bank['listunspent']
    if not bank_coins or sum(btc_to_sat(coin['amount']) for coin in bank_coins)!=policy['opening_sat']:
        raise ValueError('exact included bank opening balance required')
    if any(type(coin.get('confirmations')) is not int or coin['confirmations']<1 or coin.get('spendable') is not True or coin.get('solvable') is not True or coin.get('safe') is not True for coin in bank_coins):
        raise ValueError('all bank coins must be confirmed, safe and controlled')
    if btc_to_sat(bank['getbalances']['mine']['trusted'])!=policy['opening_sat'] or btc_to_sat(bank['getbalances']['mine']['untrusted_pending'])!=0:
        raise ValueError('complete bank balance differs from initial assets')
    wallet_specs={};bank_descriptors=[];bank_ranges=[]
    for row in bank['listdescriptors']['descriptors']:
        frontier=row.get('next_index')
        if type(frontier) is not int or not 0<=frontier<1980 or not isinstance(row.get('range'),list) or row['range'][0]!=0:
            raise ValueError('bounded standard named bank descriptor frontier required')
        bank_descriptors.append(row['desc']);bank_ranges.append(frontier+20)
    if not 1<=len(bank_descriptors)<=12 or len(set(bank_descriptors))!=len(bank_descriptors):
        raise ValueError('complete bounded named bank descriptor set required')
    wallet_specs['bank']={'descriptors':bank_descriptors,'ranges':bank_ranges}
    for owner,field in (('rounds','rounds_inventory'),('watchman','watchman_inventory')):
        wallet_specs[owner]=_empty_owner(current.get(field,{}).get(owner),owner,tip)
    customer_data={};customer_sequences={}
    for actor in sorted(customers):
        rows=store.db.execute("SELECT sequence FROM event WHERE kind='identity_bootstrap_zero_assets_verified' AND json_extract(payload,'$.actor')=?",(actor,)).fetchall()
        if len(rows)!=1:raise ValueError('unique original customer bootstrap proof required')
        _,zero=_source_event(store,rows[0][0]);_,native=_source_event(store,zero['driver_response_sequence'])
        data=native['response']['data'];frame=data['onchain_inventory'];descriptors=frame.get('descriptors')
        if (frame.get('complete') is not True or frame.get('network')!='signet' or not isinstance(descriptors,list)
                or len(descriptors)!=1 or descriptors[0].get('keychain')!='external'
                or type(descriptors[0].get('last_revealed_index')) is not int or not 0<=descriptors[0]['last_revealed_index']<=1
                or any(frame.get(field)!=[] for field in ('utxos','pending_transactions','pending_parents','unavailable_parent_txids'))):
            raise ValueError('original fresh native customer descriptor and empty graph required')
        customer_data[actor]=data;customer_sequences[actor]=rows[0][0]
        wallet_specs[actor]={'descriptors':[descriptors[0]['descriptor']],'ranges':[20],'funding_address':data['funding_address']}
    addresses={};scripts={};scans=[]
    for member_id,spec in wallet_specs.items():
        for descriptor_index,(descriptor,last) in enumerate(zip(spec['descriptors'],spec['ranges'])):
            info=chain.call('getdescriptorinfo',descriptor)
            if (info.get('hasprivatekeys') is not False or info.get('isrange') is not True
                    or info.get('issolvable') is not True or info.get('descriptor')!=descriptor):
                raise ValueError('canonical public owning descriptor required')
            derived=chain.call('deriveaddresses',descriptor,[0,last])
            if not isinstance(derived,list) or len(derived)!=last+1:raise ValueError('complete bounded owning derivation required')
            if len(scripts)+len(derived)>2000:raise ValueError('aggregate owning derivation exceeds 2000 scripts')
            for child,address in enumerate(derived):
                if time.monotonic()-started>180:raise ValueError('initial funding source deadline exceeded')
                checked=chain.call('validateaddress',address);script=checked.get('scriptPubKey')
                if checked.get('isvalid') is not True or not isinstance(script,str) or not script or script in scripts:
                    raise ValueError('unique independently derived wallet script required')
                scripts[script]={'member_id':member_id,'descriptor_index':descriptor_index,'child_index':child,'address':address}
                addresses[(member_id,descriptor_index,child)]=(address,script)
            scans.append({'desc':descriptor,'range':[0,last]})
    confirmed={};scan_observations=[]
    for offset in range(0,len(scans),12):
        if chain.call('scantxoutset','status') is not None:raise ValueError('existing Core scan still running; defer without abort')
        result=chain.call('scantxoutset','start',scans[offset:offset+12],timeout=remaining(120))
        if result.get('success') is not True or (result.get('height'),result.get('bestblock'))!=tip:
            raise ValueError('complete owning descriptor scan at exact tip required')
        rows=result.get('unspents')
        if not isinstance(rows,list) or len(rows)>2000:raise ValueError('bounded complete descriptor coin scan required')
        total=0
        for coin in rows:
            point=coin['txid']+':'+str(integer(coin['vout'],'scan output'))
            if point in confirmed or coin.get('scriptPubKey') not in scripts:raise ValueError('overlapping or foreign scanned coin')
            total+=btc_to_sat(coin['amount']);confirmed[point]=coin
        if total!=btc_to_sat(result['total_amount']):raise ValueError('complete scan balance differs')
        scan_observations.append({'descriptors':scans[offset:offset+12],'response':normalized(result)})
    bank_points={coin['txid']+':'+str(coin['vout']):coin for coin in bank_coins}
    if set(confirmed)!=set(bank_points):raise ValueError('initial six-wallet assets differ from exact bank opening')
    inventories={member_id:[] for member_id in wallet_specs}
    for point,coin in confirmed.items():
        original=bank_points[point];position=scripts[coin['scriptPubKey']]
        if position['member_id']!='bank' or coin['scriptPubKey']!=original['scriptPubKey'] or btc_to_sat(coin['amount'])!=btc_to_sat(original['amount']):
            raise ValueError('actual bank coin ownership or amount differs')
        inventories['bank'].append({'outpoint':point,'amount_sat':btc_to_sat(coin['amount']),'script':coin['scriptPubKey'],
            'descriptor_index':position['descriptor_index'],'child_index':position['child_index']})
    from .owned_mempool import collect as collect_owned_activity,collector_context
    mempool_activity = collect_owned_activity(store, chain, set(scripts), started,
        context=collector_context('finite_initial_funding',{'financial_pins':pins,'boundary_id':boundary_id,'height':tip[0],'tip_hash':tip[1],'descriptor_ranges':scans}))
    refreshed_bank_sequence=collect_funding_bank_source(store,bank_rpc,chain,timeout_seconds=remaining(30))
    _,fresh_bank=_source_event(store,refreshed_bank_sequence)
    for field in ('source_identity','getwalletinfo','listdescriptors','listunspent','listlockunspent','listsinceblock','getbalances','locked_coins','pending_transactions','pending_parents'):
        if bank[field]!=fresh_bank[field]:raise ValueError('bank changed during initial funding observation')
    request={'kind':'closed_frontier'}
    database=(await frontier_source.collect(store,config,pins,timeout=remaining(25))
        if frontier_source.schema(config)==2 else await json_command(list(config.inventory_command),request,timeout=remaining(25),
        **public_command_capture(store,'finite_initial.closed_frontier',request)))
    frontier_source.verify_frame(store,config,database,pins)
    public_payload(database)
    store.event('closed_cohort_original_source',{'source_kind':'closed_frontier','response':database,
        'response_sha256':_digest(database),'financial_pins':pins,'observed_at':time.time()})
    database_sequence=store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
    rows=database.get('rows')
    if (database.get('kind')!='closed_frontier' or database.get('schema_version')!=frontier_source.schema(config) or database.get('fallback_protocol')!=(4 if per_key else 3)
            or per_key and database.get('architecture_profile')!=DIRECT_PER_KEY
            or database.get('complete') is not False or database.get('qualified') is not False
            or database.get('database_tables_complete') is not True
            or database.get('inventory_consistent') is not True or database.get('read_only') is not True
            or not isinstance(rows,dict) or set(rows)!=TABLES or any(not isinstance(value,list) for value in rows.values())):
        raise ValueError('complete original nineteen-table frontier required')
    expected_records=sorted((_record(customer_data[actor]['binding']) for actor in customers),key=lambda row:row['mailbox_pk']) if not per_key else []
    expected_links=[]
    if per_key:expected_records,expected_links=_c_records_links(store,customer_data,pins)
    if len({row['mailbox_pk'] for row in expected_records})!=len(customers):raise ValueError('distinct original customer bindings required')
    for table,records in rows.items():
        if table in {'records','journal_records'}:
            if sorted(records,key=lambda row:row['mailbox_pk'])!=expected_records:raise ValueError('exact original three customer database bindings required')
        elif per_key and table in {'links','journal_links'}:
            if sorted(records,key=lambda row:row['user_pubkey'])!=expected_links:raise ValueError('exact original 51 C links per customer required')
        elif records:raise ValueError('initial funding refuses existing monetary or unsupported database frontier')
    estimate=chain.call('estimatesmartfee',6)
    rate=btc_to_sat(estimate['feerate'])
    if not 1<=rate<=policy['maximum_rate_sat_kvb']:raise ValueError('actual funding fee estimate exceeds finite ceiling or unavailable')
    ending=chain.identity()
    if ending.get('initialblockdownload') is not False or (ending['blocks'],ending['bestblockhash'])!=tip:
        raise ValueError('chain changed during initial funding observation')
    if time.monotonic()-started>180:raise ValueError('initial funding source deadline exceeded')
    _initial(store,pins)
    recipients=[]
    recipient_amounts = sorted(policy['amounts'].items()) if per_key else [('rounds',100000),('watchman',75000),*[(actor,50000) for actor in sorted(CUSTOMERS)]]
    for member_id,amount in recipient_amounts:
        spec=wallet_specs[member_id]
        if member_id in customers:
            found=[(key,value) for key,value in addresses.items() if key[0]==member_id and value[0]==spec['funding_address']]
            if len(found)!=1:raise ValueError('original customer funding address not in owning descriptor')
            (_,descriptor_index,child),(address,script)=found[0]
        else:
            descriptor_index=0;child=spec['recipient_index'];address,script=addresses[(member_id,0,child)]
        recipients.append({'member_id':member_id,'role':'customer' if member_id in customers else 'operator',
            'address':address,'script':script,'amount_sat':amount,'descriptor_index':descriptor_index,'child_index':child})
    members=[];inventory_sequences={}
    with store.transaction():
        store._event('finite_initial_funding_core_inventory',{'height':tip[0],'tip_hash':tip[1],
            'scans':scan_observations,'fee_estimate_target':6,'fee_estimate':normalized(estimate),
            'financial_pins':pins,'observed_at':time.time()})
        core_inventory_sequence=store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
        store._event('finite_initial_funding_owned_mempool_activity',{'height':tip[0],'tip_hash':tip[1],
            'activity_source':mempool_activity,'financial_pins':pins,'observed_at':time.time()})
        mempool_sequence=store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
        for member_id,spec in wallet_specs.items():
            identity=('core-wallet:'+bank['source_identity']['wallet_name']) if member_id=='bank' else 'bdk-wallet:'+_digest(spec['descriptors'])
            member={'id':member_id,'kind':'wallet','role':'customer' if member_id in customers else 'operator',
                'identity':identity,'descriptors':spec['descriptors']}
            store._event('treasury_member_verified',{'member':member,'financial_pins':pins,'genesis':SIGNET_GENESIS,
                'source_scope':'actual initial named bank or pinned native owning wallet plus independent descriptor/mempool scan',
                'runtime_source_sequence':runtime_source_sequence,'bank_source_sequence':refreshed_bank_sequence,
                'customer_source_sequences':customer_sequences})
            sequence=store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
            members.append({**member,'verification_sequence':sequence})
            store._event('treasury_inventory',{'member_id':member_id,'identity':identity,'financial_pins':pins,
                'height':tip[0],'tip_hash':tip[1],'complete':True,'utxos':inventories[member_id],
                'scope':'complete initial confirmed descriptor footprint and no pending assets; fresh sole-writer cohort only'})
            inventory_sequences[member_id]=store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
        source={'financial_pins':pins,'boundary_id':boundary_id,'genesis':SIGNET_GENESIS,'height':tip[0],'tip_hash':tip[1],
            'observed_at':time.time(),'bank_member_id':'bank','bank_wallet_name':bank['source_identity']['wallet_name'],
            'bank_source_sequence':refreshed_bank_sequence,'database_source_sequence':database_sequence,
            'runtime_source_sequence':runtime_source_sequence,'customer_source_sequences':customer_sequences,
            'owned_mempool_activity_source_sequence':mempool_sequence,
            'mempool_activity':mempool_activity,
            'core_inventory_source_sequence':core_inventory_sequence,
            'opening_total_sat':policy['opening_sat'],'opening_liabilities_sat':0,'funding_recipients':recipients,
            'funding_plan_sha256':_digest(recipients),'principal_sat':policy['principal_sat'],
            'maximum_funding_fee_sat':policy['maximum_fee_sat'],'maximum_fee_rate_sat_kvb':policy['maximum_rate_sat_kvb'],
            'estimated_fee_rate_sat_kvb':rate,'inventory_sequences':inventory_sequences,'members':members,
            'descriptor_ranges':scans,'ordinary_fee_holds_sat':{'funding':10000,'three_boards':12000,'three_normal_expiry_carriers':30000},
            'urgent_fee_reserve_sat':policy['urgent_budget_sat'],'operation_scope':['funding'],
            'scope':'only initial funding of six fully enumerated owned wallets; all monetary database rows absent; no subsequent wallet operation admission'}
        if per_key:
            source.update(architecture_profile=DIRECT_PER_KEY,c_pilot_id=policy['pilot_id'],
                client_principal_sat=policy['client_principal_sat'],
                operator_fee_grants_sat=policy['operator_fee_grants_sat'],
                fee_signer_member=policy['fee_signer_member'],
                actual_daemon_fee_liquidity_msat=0,urgent_isolation_qualified=False,
                ordinary_fee_holds_sat={'funding':1000,'one_board':1000},
                scope='C initial Core-bank funding only: exact 25000-sat sender and 100000-sat watchman outputs; recipient/rounds zero; actual signer liquidity must be independently observed after confirmation; urgent separation/C11 and full qualification open')
        public_payload(source);store._event('finite_initial_funding_sources_verified',source)
        sequence=store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
    return {'source_sequence':sequence,'source':source,
        'boundary_declaration':{'id':boundary_id,'genesis':SIGNET_GENESIS,'pins':pins,'members':members,
            'excluded':[]},'inventory_sequences':inventory_sequences}


def record_initial_funding_readiness(store,config,chain,source_sequence):
    """After the ordinary boundary/envelope declarations, admit funding alone."""
    from .operating_limits import envelope,fee_totals
    from .treasury import boundary,capture_assets
    policy=_policy(store);per_key=profile(store)==DIRECT_PER_KEY
    event,source=_source_event(store,source_sequence)
    if event['kind']!='finite_initial_funding_sources_verified' or source.get('operation_scope')!=['funding']:
        raise ValueError('original initial-only funding source required')
    if per_key and (source.get('architecture_profile')!=DIRECT_PER_KEY
            or source.get('c_pilot_id')!=policy['pilot_id'] or source.get('opening_total_sat')!=policy['opening_sat']):
        raise ValueError('original C bounded pilot source required')
    frontier_source.verify_source(store,config,source,source['financial_pins'])
    from .owned_mempool import verify_source as verify_owned_source
    verify_owned_source(store,source,'finite_initial_funding',fresh=True)
    _fresh(source['observed_at'],'initial funding');_initial(store,source['financial_pins'])
    limits=envelope(store,config);treasury=boundary(store)
    if (limits['pins']!=source['financial_pins'] or limits['boundary_id']!=source['boundary_id']
            or treasury['members']!=source['members'] or treasury['id']!=source['boundary_id']
            or limits.get('operation_fee_paths',{}).get('funding')!=['sweep','payout']
            or limits['fee_ceilings_sat_kvb']!={'round':None,'pool':None,'sweep':20000,'payout':20000,'claim':None,'progression':None}
            or limits['fee_budgets_msat']!={'ordinary':policy['ordinary_budget_sat']*1000,'urgent':policy['urgent_budget_sat']*1000}
            or limits['capital_exposure_msat']<policy['opening_sat']*1000 or limits['per_action_fee_sat']!=policy['maximum_fee_sat']
            or limits['grant_sat']!=policy['grant_sat'] or limits['board_sat']!=policy['board_sat'] or limits['board_fee_reserve_sat']!=policy['board_fee_reserve_sat']):
        raise ValueError('exact prospectively affordable initial funding envelope required')
    assets=capture_assets(store,source['inventory_sequences'],chain)
    if (assets['total_msat']!=policy['opening_sat']*1000 or (assets['height'],assets['tip_hash'])!=(source['height'],source['tip_hash'])
            or fee_totals(store,source['financial_pins'])!={'ordinary':0,'urgent':0}):
        raise ValueError('actual opening assets, tip or prior financial costs differ')
    receipt={'financial_pins':source['financial_pins'],'boundary_id':source['boundary_id'],
        'height':source['height'],'tip_hash':source['tip_hash'],'observed_at':time.time(),'complete':True,
        'operation_scope':['funding'],'finite_initial_source_sequence':source_sequence,
        'bank_source_sequence':source['bank_source_sequence'],'funding_plan_sha256':source['funding_plan_sha256'],
        'effective_fee_ceilings_sat_kvb':limits['fee_ceilings_sat_kvb'],'capital_exposure_msat':policy['opening_sat']*1000,
        'available_fee_funding_msat':(policy['opening_sat']-policy['principal_sat']-policy['maximum_fee_sat'])*1000,
        'estimated_fee_rate_sat_kvb':source['estimated_fee_rate_sat_kvb'],
        'ordinary_fee_holds_sat':source['ordinary_fee_holds_sat'],'urgent_fee_reserve_sat':policy['urgent_budget_sat'],
        'pool_ready':False,'channel_route_ready':False,
        'scope':'complete only for the initial once-only five-output funding prerequisite; subsequent monetary state requires new source qualification'}
    if per_key:receipt.update(architecture_profile=DIRECT_PER_KEY,c_pilot_id=policy['pilot_id'],
        # Core bank is the real signer for THIS funding operation only. The
        # internal watchman allocation remains operator capital, not principal
        # leaving the treasury or already-observed daemon spending authority.
        available_fee_funding_msat=(policy['opening_sat']-policy['client_principal_sat']-policy['maximum_fee_sat'])*1000,
        funding_total_transfer_sat=policy['principal_sat'],client_principal_sat=policy['client_principal_sat'],
        operator_fee_grants_sat=policy['operator_fee_grants_sat'],
        fee_signer_member='bank',actual_daemon_fee_liquidity_msat=0,
        urgent_isolation_qualified=False,
        scope='C once-only Core-bank batch: sender25000/watchman100000; postfunding Board requires true confirmed/trusted watchman liquidity; urgent separation/C11 and full qualification open')
    store.event('financial_operating_readiness',receipt)
    return {'operating_readiness_sequence':store.db.execute('SELECT max(sequence) FROM event').fetchone()[0],**receipt}

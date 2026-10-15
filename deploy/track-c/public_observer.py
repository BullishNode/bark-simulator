"""Bounded public SQL/wallet validators ported from B's declared checkpoint.

This module has no deployment addresses, credentials, shell dispatch or monetary
admission. The C wrapper supplies fixed read-only ops after authenticating its
root-owned deployment declaration. Signature/chain validation stays independent.
"""
import json,os,re,selectors,subprocess,time
from decimal import Decimal
MAX_BYTES=2*1024*1024
FINANCIAL_ROW_LIMIT=2000
FINANCIAL_TABLES={'coins','pending_boards','links','records','pool','lightning_nodes','htlcs','receives','payments','participations','participation_inputs','participation_outputs'}
READ_DEADLINE=None
DEPLOY=None

def ops(*args):
    raise ValueError('declared C native ops transport not installed')

def run(argv,timeout=20):
    remaining=timeout if READ_DEADLINE is None else min(timeout,READ_DEADLINE-time.monotonic())
    if remaining<=0:raise ValueError('financial observation deadline exceeded')
    deadline=time.monotonic()+remaining;data=bytearray()
    with subprocess.Popen(argv,cwd=DEPLOY,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL) as child:
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout,selectors.EVENT_READ)
                while True:
                    remaining=deadline-time.monotonic()
                    if remaining<=0 or not selector.select(remaining):raise ValueError('bridge deadline exceeded')
                    chunk=os.read(child.stdout.fileno(),min(4096,MAX_BYTES+1-len(data)))
                    if not chunk:break
                    data.extend(chunk)
                    if len(data)>MAX_BYTES:raise ValueError('bridge output bound exceeded')
            child.wait(timeout=max(0.001,deadline-time.monotonic()))
            if child.returncode!=0:raise subprocess.CalledProcessError(child.returncode,argv)
        finally:
            if child.poll() is None:child.kill();child.wait(timeout=5)
    return data.decode()

def request(raw):
    if len(raw)>4096:raise ValueError('request bound exceeded')
    value=json.loads(raw)
    if not isinstance(value,dict):raise ValueError('invalid bridge request')
    if value.get('kind') in {'financial_readiness','claimant_inventory','direct_journal','closed_frontier'}:
        if set(value)!={'kind'}:raise ValueError('financial operation takes no arguments')
        return value['kind'],None
    if value.get('kind')=='rounds_descriptor':
        if set(value)!={'kind'}:raise ValueError('descriptor takes no arguments')
        return 'rounds_descriptor',None
    if value.get('kind')=='logs':
        if set(value)-{'kind','service','seconds','tail','max_bytes'}:raise ValueError('invalid logs request')
        if value.get('service') not in {'captaind','watchmand'}:raise ValueError('unsupported log service')
        for field,default,lower,upper in [('seconds',300,1,86400),('tail',200,1,1000),('max_bytes',65536,4096,262144)]:
            value.setdefault(field,default)
            if type(value[field]) is not int or not lower<=value[field]<=upper:raise ValueError('log request bound')
        return 'logs',value
    if value.get('kind')=='binding_check':
        if set(value)!={'kind','mailboxes','keys'}:raise ValueError('invalid binding request')
        for field,limit in [('mailboxes',2),('keys',32)]:
            items=value[field]
            if not isinstance(items,list) or len(items)>limit or len(set(items))!=len(items):raise ValueError('binding request bound')
            if any(not isinstance(item,str) or not re.fullmatch(r'(02|03)[0-9a-f]{64}',item) for item in items):raise ValueError('invalid public key')
        if not value['mailboxes']:raise ValueError('protected mailbox required')
        return 'binding_check',value
    if set(value)-{'kind','after'}:raise ValueError('invalid bridge request')
    kind=value.get('kind','snapshot');after=value.get('after','')
    if kind not in {'snapshot','settlements','coins','pending','links','records','nursery'}:raise ValueError('unsupported bridge operation')
    if not isinstance(after,str) or not re.fullmatch(r'[a-zA-Z0-9:_-]{0,128}',after):raise ValueError('invalid cursor')
    if kind=='snapshot' and after:raise ValueError('snapshot takes no cursor')
    return kind,after

def page(kind,after):
    # Lexicographic cyclic inventories: the caller restarts from '' after each
    # complete scan. Never assert a complete consistent database snapshot across
    # separate calls, and never use this cursor as a once-only commit watermark.
    tables={
      'settlements':("s.id", "expiry_settlement s", "s.id,s.txid,s.fee_sat,encode(s.spk,'hex') AS spk,s.created_at, (SELECT COUNT(*) FROM expiry_settlement z WHERE z.txid=s.txid) AS tx_settlement_count, "
         "(SELECT coalesce(jsonb_agg(q),'[]'::jsonb) FROM (SELECT h.spend_state,h.policy_type,h.oor_spent_txid,h.spent_in_round,h.offboarded_in,h.confirmed_height,h.onchain_spent_txid FROM vtxo_history h WHERE h.vtxo_id=s.id AND h.history_created_at=s.created_at) q) AS pre_commit_rows, "
         "EXISTS (SELECT 1 FROM pending_board p WHERE p.vtxo_id=s.id) AS board_reserved, "
         "(SELECT jsonb_build_object('payment_hash',h.payment_hash,'direction',h.direction,'htlc_expiry',h.htlc_expiry,'offchain_resolution',h.offchain_resolution,'chain_resolution',h.chain_resolution, "
         "'collection_recorded',EXISTS (SELECT 1 FROM htlc_settlement z WHERE z.payment_hash=h.payment_hash AND z.created_at<=s.created_at), "
         "'subscription_settled',EXISTS (SELECT 1 FROM lightning_htlc_subscription r WHERE r.payment_hash=h.payment_hash AND r.status='settled')) FROM htlc_vtxo h JOIN vtxo v ON v.id=h.id WHERE v.vtxo_id=s.id) AS htlc"),
      'coins':("v.vtxo_id","vtxo v","v.vtxo_id,v.id,v.amount,v.expiry,v.spend_state,v.policy_type,encode(v.policy,'hex') AS policy,v.anchor_point,v.onchain_spent_txid,v.onchain_spent_height,v.confirmed_height,v.oor_spent_txid,v.spent_in_round,v.offboarded_in"),
      'pending':("p.vtxo_id","pending_board p","p.vtxo_id,p.id,p.expiry"),
      'links':("encode(l.user_pubkey,'hex')","key_link l","encode(l.user_pubkey,'hex') AS user_pubkey,encode(l.mailbox_pk,'hex') AS mailbox_pk,encode(l.sig,'hex') AS sig,l.recovery_index"),
      'records':("encode(r.mailbox_pk,'hex')","fallback_record r","encode(r.mailbox_pk,'hex') AS mailbox_pk,encode(r.spk,'hex') AS spk,encode(r.mailbox_sig,'hex') AS mailbox_sig"),
      'nursery':("n.txid","nursery_tx n","n.txid,n.kind,n.confirmed_at_height,n.abandoned_at")}
    key,table,columns=tables[kind]
    # Cursor whitelist contains no quotes/operators. All table/column names fixed.
    sql=f"BEGIN READ ONLY; SET LOCAL statement_timeout='8s'; SELECT coalesce(jsonb_agg(t),'[]'::jsonb) FROM (SELECT {columns} FROM {table} WHERE {key} > '{after}' ORDER BY {key} LIMIT 101) t; COMMIT;"
    lines=ops('sql',sql).splitlines()
    arrays=[line for line in lines if line.startswith('[')]
    if len(arrays)!=1:raise ValueError('unrecognized bridge database response')
    rows=json.loads(arrays[0]);more=len(rows)>100;rows=rows[:100]
    field={'settlements':'id','coins':'vtxo_id','pending':'vtxo_id','links':'user_pubkey','records':'mailbox_pk','nursery':'txid'}[kind]
    return {'kind':kind,'fallback_protocol':4,'architecture_profile':'direct_per_key','rows':rows,'next':rows[-1][field] if more else None,'inventory_consistent':False,
        'validation_scope':'trusted server claims; independently verify chain, backing, signatures and rightful ownership'}

def claimant_sql(closed=False):
    # Complete bounded candidate tables in ONE snapshot, including spent logical
    # ancestors whose physical backing remains. These are not summed liabilities:
    # delegated predecessors/replacements and internal HTLCs need arbitration.
    tables={
        'coins':("vtxo", "vtxo_id", "vtxo_id,amount,expiry,spend_state,policy_type,encode(policy,'hex') AS policy,anchor_point,vtxo_txid,oor_spent_txid,spent_in_round,offboarded_in,frontier_at,confirmed_height", "onchain_spent_txid IS NULL"),
        'pending_boards':("pending_board", "vtxo_id", "vtxo_id,expiry", "true"),
        'links':("key_link", "user_pubkey", "encode(user_pubkey,'hex') AS user_pubkey,encode(mailbox_pk,'hex') AS mailbox_pk,encode(sig,'hex') AS sig,recovery_index", "true"),
        'records':("fallback_record", "mailbox_pk", "encode(mailbox_pk,'hex') AS mailbox_pk,encode(spk,'hex') AS spk,encode(mailbox_sig,'hex') AS mailbox_sig", "true"),
        'pool':("vtxo_pool", "id", "id,vtxo_id,expiry_height,amount", "spent_at IS NULL"),
        'lightning_nodes':("lightning_node", "id", "id,encode(pubkey,'hex') AS pubkey", "true"),
        'htlcs':("htlc_vtxo h", "h.id", "h.id,h.payment_hash,h.htlc_expiry,h.direction,h.offchain_resolution,h.chain_resolution,h.chain_resolution_height,EXISTS (SELECT 1 FROM htlc_settlement s WHERE s.payment_hash=h.payment_hash) AS collection_recorded", "EXISTS (SELECT 1 FROM vtxo v WHERE v.id=h.id AND v.onchain_spent_txid IS NULL)"),
        'receives':("lightning_htlc_subscription s", "s.id", "s.id,s.lightning_node_id,s.payment_hash,s.status,s.lowest_incoming_htlc_expiry,s.accepted_at,s.final_amount_msat,s.receiver_mailbox_id", "s.status NOT IN ('settled','canceled') OR EXISTS (SELECT 1 FROM vtxo v WHERE v.lightning_htlc_subscription_id=s.id AND v.onchain_spent_txid IS NULL)"),
        'payments':("lightning_payment_attempt p", "p.id", "p.id,p.lightning_node_id,p.payment_hash,p.status,p.amount_msat,p.final_amount_msat,p.sender_mailbox_id,p.lightning_htlc_subscription_id,p.block_height,p.user_fee_sat,p.invoice_expires_at", "p.status NOT IN ('succeeded','failed') OR EXISTS (SELECT 1 FROM lightning_payment_attempt_htlc_vtxo a JOIN vtxo v ON v.vtxo_id=a.vtxo_id WHERE a.lightning_payment_attempt_id=p.id AND v.onchain_spent_txid IS NULL)"),
        'participations':("round_participation p", "p.id", "p.id,p.round_id,p.created_at,p.forfeited_at,p.scheduled_height,(p.unlock_preimage IS NOT NULL) AS unlock_available", "p.forfeited_at IS NULL OR EXISTS (SELECT 1 FROM vtxo v WHERE v.spent_in_round=p.id AND v.onchain_spent_txid IS NULL)"),
        'participation_inputs':("round_part_input i", "i.participation_id,i.vtxo_id", "i.participation_id,i.vtxo_id,(i.signed_forfeit_tx IS NOT NULL) AS forfeit_signed", "EXISTS (SELECT 1 FROM round_participation p WHERE p.id=i.participation_id AND (p.forfeited_at IS NULL OR EXISTS (SELECT 1 FROM vtxo v WHERE v.spent_in_round=p.id AND v.onchain_spent_txid IS NULL)))"),
        'participation_outputs':("round_part_output o", "o.participation_id,o.policy,o.amount", "o.participation_id,encode(o.policy,'hex') AS policy,o.amount,o.unblinded_mailbox_id", "EXISTS (SELECT 1 FROM round_participation p WHERE p.id=o.participation_id AND (p.forfeited_at IS NULL OR EXISTS (SELECT 1 FROM vtxo v WHERE v.spent_in_round=p.id AND v.onchain_spent_txid IS NULL)))"),
    }
    if closed:
        # Closed-cohort admission needs historical ancestors and proof that
        # prohibited paths have no rows, not a convenient active-only prefix.
        tables={name:(table,key,columns,'true') for name,(table,key,columns,where) in tables.items()}
        table,key,columns,_=tables['coins']
        tables['coins']=(table,key,columns+',onchain_spent_height,onchain_spent_txid','true')
        for name,(table,key,columns) in DIRECT_JOURNAL_COLUMNS.items():
            tables['journal_'+name]=(table,key,columns,'true')
        tables['nursery']=('nursery_tx','id','id,txid,confirm_target_height,confirmed_at_height,abandoned_at,created_at,updated_at,kind','true')
        tables['rounds']=('public.round','id','id,seq,funding_txid,expiry,swept_at,created_at','true')
    fields=[]
    for name,(table,key,columns,where) in tables.items():
        fields.append("'"+name+"',(SELECT coalesce(jsonb_agg(q),'[]'::jsonb) FROM (SELECT "+columns+" FROM "+table+" WHERE "+where+" ORDER BY "+key+" LIMIT "+str(FINANCIAL_ROW_LIMIT+1)+") q)")
    payload="jsonb_build_object("+','.join(fields)+")"
    if closed:payload="jsonb_build_object('snapshot',pg_current_snapshot()::text,'observed_at',transaction_timestamp(),'rows',"+payload+")"
    return "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout='8s'; SELECT "+payload+"; COMMIT;"

def closed_frontier():
    lines=[line for line in ops('sql',claimant_sql(closed=True)).splitlines() if line.startswith('{')]
    if len(lines)!=1:raise ValueError('invalid closed frontier database response')
    frame=json.loads(lines[0])
    expected=FINANCIAL_TABLES|{'journal_'+name for name in DIRECT_JOURNAL_COLUMNS}|{'nursery','rounds'}
    if (not isinstance(frame,dict) or set(frame)!={'snapshot','observed_at','rows'}
            or not isinstance(frame['snapshot'],str) or not frame['snapshot']
            or not isinstance(frame['rows'],dict) or set(frame['rows'])!=expected):
        raise ValueError('incomplete closed frontier frame')
    rows=frame['rows']
    if (any(not isinstance(items,list) or len(items)>FINANCIAL_ROW_LIMIT for items in rows.values())
            or sum(map(len,rows.values()))>FINANCIAL_ROW_LIMIT):
        raise ValueError('whole closed frontier exceeds row budget')
    fields={
        'coins':'vtxo_id amount expiry spend_state policy_type policy anchor_point vtxo_txid oor_spent_txid spent_in_round offboarded_in frontier_at confirmed_height onchain_spent_height onchain_spent_txid',
        'pending_boards':'vtxo_id expiry', 'links':'user_pubkey mailbox_pk sig recovery_index',
        'records':'mailbox_pk spk mailbox_sig',
        'pool':'id vtxo_id expiry_height amount', 'lightning_nodes':'id pubkey',
        'htlcs':'id payment_hash htlc_expiry direction offchain_resolution chain_resolution chain_resolution_height collection_recorded',
        'receives':'id lightning_node_id payment_hash status lowest_incoming_htlc_expiry accepted_at final_amount_msat receiver_mailbox_id',
        'payments':'id lightning_node_id payment_hash status amount_msat final_amount_msat sender_mailbox_id lightning_htlc_subscription_id block_height user_fee_sat invoice_expires_at',
        'participations':'id round_id created_at forfeited_at scheduled_height unlock_available',
        'participation_inputs':'participation_id vtxo_id forfeit_signed',
        'participation_outputs':'participation_id policy amount unblinded_mailbox_id',
        'nursery':'id txid confirm_target_height confirmed_at_height abandoned_at created_at updated_at kind',
        'rounds':'id seq funding_txid expiry swept_at created_at'}
    allowed={name:set(value.split()) for name,value in fields.items()}
    allowed.update({'journal_'+name:value for name,value in DIRECT_JOURNAL_FIELDS.items()})
    for name,items in rows.items():
        for item in items:
            if not isinstance(item,dict) or set(item)!=allowed[name]:raise ValueError('unexpected closed frontier fields')
            if name=='journal_carriers':
                inputs=item['fee_inputs']
                if not isinstance(inputs,list) or any(not isinstance(i,dict) or set(i)!={'outpoint','value_sat','script_pubkey'} for i in inputs):
                    raise ValueError('unexpected closed frontier fee input fields')
    result={'kind':'closed_frontier','schema_version':1,'fallback_protocol':4,'architecture_profile':'direct_per_key',**frame,
        'read_only':True,'inventory_consistent':True,'database_tables_complete':True,
        'row_limit_total':FINANCIAL_ROW_LIMIT,'complete':False,'qualified':False,
        'validation_scope':'exhaustive bounded public database frontier and retained journal in one snapshot; no signed bytes, resolved ownership, chain validity, wallet completeness or operating readiness claim'}
    if len(json.dumps(result,allow_nan=False).encode())>MAX_BYTES:raise ValueError('whole closed frontier exceeds byte budget')
    return result

def claimant_inventory():
    lines=[line for line in ops('sql',claimant_sql()).splitlines() if line.startswith('{')]
    if len(lines)!=1:raise ValueError('invalid financial database response')
    result=json.loads(lines[0])
    if not isinstance(result,dict) or set(result)!=FINANCIAL_TABLES or any(not isinstance(rows,list) for rows in result.values()):
        raise ValueError('invalid financial inventory shape')
    truncated=[name for name,rows in result.items() if len(rows)>FINANCIAL_ROW_LIMIT]
    if any(len(rows)>FINANCIAL_ROW_LIMIT+1 for rows in result.values()):raise ValueError('financial row bound exceeded')
    return {'kind':'claimant_inventory','fallback_protocol':4,'architecture_profile':'direct_per_key',
        'rows':{name:rows[:FINANCIAL_ROW_LIMIT] for name,rows in result.items()},
        'row_limit_per_table':FINANCIAL_ROW_LIMIT,'truncated_tables':sorted(truncated),
        'inventory_consistent':True,'candidate_tables_complete':not truncated,
        'complete':False,'liability_accounting_complete':False,
        'validation_scope':'one database candidate snapshot, NOT a resolved claimant ledger or physical asset inventory; decode policies to exclude padding; independently arbitrate predecessors, HTLCs and backing membership'}

DIRECT_JOURNAL_COLUMNS={
    'allocations':('expiry_allocation','id',
        "id,freeze_set,encode(owner_pubkey,'hex') AS owner_pubkey,encode(spk,'hex') AS spk,disposition,gross_sat,fee_sat,payout_sat,forfeited_sat,source,retirement_ids,frozen_at"),
    'carriers':('expiry_carrier','generation',
        'txid,generation,backing_ids,fee_inputs,miner_fee_sat,funding_subsidy_sat,created_at,confirmed_height,confirmed_block'),
    'mappings':('expiry_carrier_allocation','txid,allocation_id','txid,allocation_id,vout'),
    'records':('fallback_record','mailbox_pk',
        "encode(mailbox_pk,'hex') AS mailbox_pk,encode(spk,'hex') AS spk,encode(mailbox_sig,'hex') AS mailbox_sig"),
    'links':('key_link','user_pubkey',
        "encode(user_pubkey,'hex') AS user_pubkey,encode(mailbox_pk,'hex') AS mailbox_pk,encode(sig,'hex') AS sig,recovery_index"),
}

DIRECT_JOURNAL_FIELDS={
    'allocations':{'id','freeze_set','owner_pubkey','spk','disposition','gross_sat','fee_sat','payout_sat','forfeited_sat','source','retirement_ids','frozen_at'},
    'carriers':{'txid','generation','backing_ids','fee_inputs','miner_fee_sat','funding_subsidy_sat','created_at','confirmed_height','confirmed_block'},
    'mappings':{'txid','allocation_id','vout'},
    'records':{'mailbox_pk','spk','mailbox_sig'},
    'links':{'user_pubkey','mailbox_pk','sig','recovery_index'},
}

def direct_journal_sql():
    fields=[]
    for name,(table,key,columns) in DIRECT_JOURNAL_COLUMNS.items():
        # Lookahead keys of unrelated active wallets do not belong to this
        # settlement journal. Keep every allocation/carrier generation, and
        # authenticate precisely the owners referenced by those allocations.
        where=''
        if name=='links':
            where=' WHERE EXISTS (SELECT 1 FROM expiry_allocation a WHERE a.owner_pubkey=key_link.user_pubkey)'
        elif name=='records':
            where=' WHERE EXISTS (SELECT 1 FROM key_link l JOIN expiry_allocation a ON a.owner_pubkey=l.user_pubkey WHERE l.mailbox_pk=fallback_record.mailbox_pk)'
        fields.append("'"+name+"',(SELECT coalesce(jsonb_agg(q),'[]'::jsonb) FROM (SELECT "+columns+
            " FROM "+table+where+" ORDER BY "+key+" LIMIT "+str(FINANCIAL_ROW_LIMIT+1)+") q)")
    return ("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout='8s'; "
        "SELECT jsonb_build_object('snapshot',pg_current_snapshot()::text,'observed_at',transaction_timestamp(),"
        "'rows',jsonb_build_object("+','.join(fields)+")); COMMIT;")

def direct_journal():
    lines=[line for line in ops('sql',direct_journal_sql()).splitlines() if line.startswith('{')]
    if len(lines)!=1:raise ValueError('invalid direct journal database response')
    frame=json.loads(lines[0])
    if not isinstance(frame,dict) or set(frame)!={'snapshot','observed_at','rows'}:
        raise ValueError('invalid direct journal frame')
    rows=frame['rows']
    if not isinstance(rows,dict) or set(rows)!=set(DIRECT_JOURNAL_COLUMNS):
        raise ValueError('incomplete direct journal tables')
    # A partial page is never delivered as an apparently complete journal. A
    # larger deployment needs a separately qualified consistent paging source.
    for name,items in rows.items():
        if not isinstance(items,list) or len(items)>FINANCIAL_ROW_LIMIT:
            raise ValueError('complete direct journal exceeds row budget')
        for item in items:
            if not isinstance(item,dict) or set(item)!=DIRECT_JOURNAL_FIELDS[name]:
                raise ValueError('unexpected direct journal fields')
            if name=='carriers':
                inputs=item['fee_inputs']
                if not isinstance(inputs,list) or any(not isinstance(i,dict) or set(i)!={'outpoint','value_sat','script_pubkey'} for i in inputs):
                    raise ValueError('unexpected direct fee input fields')
    result={'kind':'direct_journal','schema_version':1,'fallback_protocol':4,'architecture_profile':'direct_per_key',**frame,
        'binding_scope':'owners_referenced_by_allocations',
        'row_limit_per_table':FINANCIAL_ROW_LIMIT,'journal_complete':True,'inventory_consistent':True,
        'complete':False,'qualified':False,
        'validation_scope':'one complete bounded read-only journal snapshot; frozen allocations and claimed confirmation fields are not payments; independently verify ownership, all carrier versions, active-chain spends, outputs, fees and treasury'}
    if len(json.dumps(result,allow_nan=False).encode())>MAX_BYTES:
        raise ValueError('complete direct journal exceeds byte budget')
    return result

def fee_rate_sat_kvb(value):
    if value is None:return None
    if not isinstance(value,str):raise ValueError('explicit fee rate unit required')
    match=re.fullmatch(r'([0-9]+(?:\.[0-9]+)?)\s*sat/(kvb|vb)',value)
    if not match:raise ValueError('unsupported fee rate unit')
    number=Decimal(match[1])*(1000 if match[2]=='vb' else 1)
    if number!=number.to_integral_value() or not 0<number<=10**9:raise ValueError('fee rate out of bound')
    return int(number)

WALLET_FIELDS={'wallet','network','public_descriptor','tip_height','tip_hash',
    'min_trusted_confirmations','utxos','complete','reserved_outpoints','last_revealed_index',
    'pending_transactions','pending_parents','unavailable_parent_txids','pending_transaction_scope'}

UTXO_FIELDS={'outpoint','value_sat','script_pubkey','keychain','derivation_index',
    'confirmed_height_upper_bound','confirmation_block_hash','unconfirmed_first_seen','unconfirmed_last_seen',
    'coinbase','confirmations','mature','trusted','reserved','transaction_eligible','confirmed_fee_eligible',
    'confirming_descendant_txid','confirmation_time'}

def bounded_integer(value,upper,nullable=False):
    if nullable and value is None:return
    if type(value) is not int or not 0<=value<=upper:raise ValueError('invalid public wallet integer')

def public_hash(value,nullable=False):
    if nullable and value is None:return
    if not isinstance(value,str) or not re.fullmatch(r'[0-9a-f]{64}',value):raise ValueError('invalid public wallet hash')

def public_outpoint(value):
    if not isinstance(value,str) or not re.fullmatch(r'[0-9a-f]{64}:(0|[1-9][0-9]{0,9})',value):
        raise ValueError('invalid public wallet outpoint')
    bounded_integer(int(value.split(':')[1]),2**32-1)

def wallet_transaction(row):
    if not isinstance(row,dict) or set(row)!={'txid','transaction_body','signed_weight_wu','encoding'}:
        raise ValueError('invalid public wallet transaction fields')
    public_hash(row['txid']);bounded_integer(row['signed_weight_wu'],4_000_000)
    body=row['transaction_body']
    if row['encoding']!='bitcoin-stripped-body-v1' or not isinstance(body,str) or not re.fullmatch(r'(?:[0-9a-f]{2}){10,1048576}',body):
        raise ValueError('invalid public wallet body encoding')
    # Reuse Core's decoder. Never export its response or private error text.
    # A stripped body does not independently prove the original signed weight.
    tx=json.loads(ops('cli','decoderawtransaction',body))
    weight=2*len(body)
    if (not isinstance(tx,dict) or tx.get('txid')!=row['txid'] or tx.get('hash')!=row['txid'] or tx.get('weight')!=weight
            or not weight<=row['signed_weight_wu']<=4_000_000):
        raise ValueError('public wallet body identity or weight differs')
    inputs=tx.get('vin')
    if not isinstance(inputs,list) or not inputs:raise ValueError('public wallet body has no inputs')
    points=set()
    for item in inputs:
        if not isinstance(item,dict) or not isinstance(item.get('scriptSig'),dict) or item['scriptSig'].get('hex')!='' or item.get('txinwitness'):
            raise ValueError('private or unsafe wallet input refused')
        public_hash(item.get('txid'));bounded_integer(item.get('vout'),2**32-1)
        point=(item['txid'],item['vout'])
        if point in points:raise ValueError('duplicate public wallet input')
        points.add(point)
    return {txid for txid,_ in points}

def validate_wallet_frame(value,owner,network):
    # Reject unknown fields, especially private additions, instead of exporting
    # or silently sanitizing a partial source as a complete wallet snapshot.
    if not isinstance(value,dict) or set(value)!={'rounds','watchman','complete','missing_sources'} or value['complete'] is not False:
        raise ValueError('invalid owning-wallet response')
    opposite='watchman' if owner=='rounds' else 'rounds'
    expected=('watchmand owns its wallet; inventory unavailable from captaind' if owner=='rounds' else
        'captaind owns its rounds wallet; collect its separate source without assuming global atomicity')
    if value[opposite] is not None or value['missing_sources']!=[expected]:raise ValueError('invalid separate-owner scope')
    wallet=value[owner]
    if not isinstance(wallet,dict) or set(wallet)!=WALLET_FIELDS or wallet['wallet']!=owner or wallet['network']!=network or type(wallet['complete']) is not bool:
        raise ValueError('incomplete or incompatible owning-wallet snapshot')
    if wallet['pending_transaction_scope']!='canonical_wallet_graph_only':raise ValueError('unknown wallet graph scope')
    descriptor=wallet['public_descriptor']
    if not isinstance(descriptor,str) or len(descriptor)>1024 or not re.fullmatch(r'[a-zA-Z0-9\[\]/(),#*<>;\x27]+',descriptor):
        raise ValueError('invalid public descriptor')
    if re.search(r'xprv|tprv|(?:^|[^1-9A-HJ-NP-Za-km-z])[59cKL][1-9A-HJ-NP-Za-km-z]{50,51}(?:[^1-9A-HJ-NP-Za-km-z]|$)',descriptor):
        raise ValueError('private descriptor refused')
    bounded_integer(wallet['tip_height'],2**32-1);public_hash(wallet['tip_hash'])
    bounded_integer(wallet['min_trusted_confirmations'],2**32-1)
    if wallet['min_trusted_confirmations']==0:raise ValueError('invalid wallet trust threshold')
    bounded_integer(wallet['last_revealed_index'],2**32-1,True)
    rows=wallet['utxos'];reserved=wallet['reserved_outpoints']
    pending=wallet['pending_transactions'];parents=wallet['pending_parents'];unavailable=wallet['unavailable_parent_txids']
    collections=(rows,reserved,pending,parents,unavailable)
    if any(not isinstance(c,list) for c in collections) or sum(map(len,collections))>FINANCIAL_ROW_LIMIT:
        raise ValueError('owning-wallet aggregate row budget exceeded')
    for txid in unavailable:public_hash(txid)
    if len(set(unavailable))!=len(unavailable) or wallet['complete']!=(not bool(unavailable)):
        raise ValueError('invalid missing wallet parent declaration')
    # Check every row's field whitelist before any body reaches Core.
    for row in pending+parents:
        if not isinstance(row,dict) or set(row)!={'txid','transaction_body','signed_weight_wu','encoding'}:
            raise ValueError('invalid public wallet transaction fields')
        public_hash(row['txid'])
    parent_ids=set();needed=set();pending_ids=set()
    for row in pending:
        if row['txid'] in pending_ids:raise ValueError('duplicate pending transaction')
        pending_ids.add(row['txid']);needed.update(wallet_transaction(row))
    for row in parents:
        if row['txid'] in parent_ids:raise ValueError('duplicate wallet parent')
        parent_ids.add(row['txid']);wallet_transaction(row)
    if parent_ids & set(unavailable) or parent_ids | set(unavailable)!=needed:
        raise ValueError('wallet immediate-parent coverage differs')
    for point in reserved:public_outpoint(point)
    if len(set(reserved))!=len(reserved):raise ValueError('duplicate wallet reservation')
    seen=set()
    for row in rows:
        if not isinstance(row,dict) or set(row)!=UTXO_FIELDS:raise ValueError('invalid public UTXO fields')
        public_outpoint(row['outpoint'])
        if row['outpoint'] in seen:raise ValueError('duplicate wallet UTXO')
        seen.add(row['outpoint'])
        bounded_integer(row['value_sat'],21_000_000*100_000_000)
        bounded_integer(row['derivation_index'],2**32-1);bounded_integer(row['confirmations'],2**32-1)
        if row['keychain'] not in {'external','internal'} or not isinstance(row['script_pubkey'],str) or not re.fullmatch(r'(?:[0-9a-f]{2}){1,10000}',row['script_pubkey']):
            raise ValueError('invalid public UTXO script or keychain')
        for key in ('coinbase','mature','trusted','reserved','transaction_eligible','confirmed_fee_eligible'):
            if type(row[key]) is not bool:raise ValueError('invalid public UTXO boolean')
        height=row['confirmed_height_upper_bound'];bounded_integer(height,wallet['tip_height'],True)
        public_hash(row['confirming_descendant_txid'],True)
        for key in ('confirmation_time','unconfirmed_first_seen','unconfirmed_last_seen'):bounded_integer(row[key],2**64-1,True)
        if height is None:
            if row['confirmations']!=0 or any(row[key] is not None for key in ('confirmation_block_hash','confirming_descendant_txid','confirmation_time')):
                raise ValueError('invalid unconfirmed wallet position')
        else:
            public_hash(row['confirmation_block_hash'])
            if row['confirmation_time'] is None or row['confirmations']!=wallet['tip_height']-height+1 or row['unconfirmed_first_seen'] is not None or row['unconfirmed_last_seen'] is not None:
                raise ValueError('invalid confirmed wallet position')
        mature=not row['coinbase'] or row['confirmations']>=100
        eligible=row['trusted'] and mature and not row['reserved']
        if row['reserved']!=(row['outpoint'] in reserved) or row['mature']!=mature or row['transaction_eligible']!=eligible or row['confirmed_fee_eligible']!=(eligible and height is not None):
            raise ValueError('inconsistent public wallet eligibility')
    return value

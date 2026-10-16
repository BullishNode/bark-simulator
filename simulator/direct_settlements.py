"""Direct-carrier observations and independent limited-source reconciliation.

A complete DB journal is only a candidate inventory. Actual Core inputs/outputs,
original public authorization proofs, immutable owner records and operator script
ownership remain separate requirements. Complex Lightning/delegated arbitration
is held until its independent source-specific evidence adapter exists.
"""
import asyncio
import hashlib
import json
import re
import time
from .model import InvariantError,canonical,integer,public_payload
from .ownership import EvidenceGap,expiry_owner
from .direct_accounting import claim_accounts,FLAT_FEE_SAT
from .negative_checks import record_bytes
from .process import json_command,public_command_capture
from .architecture import profile, DIRECT_PER_KEY

TABLES={'allocations':'id','carriers':'txid','mappings':None,'records':'mailbox_pk','links':'user_pubkey'}
FIELDS={
    'allocations':{'id','freeze_set','owner_pubkey','spk','disposition','gross_sat','fee_sat','payout_sat','forfeited_sat','source','retirement_ids','frozen_at'},
    'carriers':{'txid','generation','backing_ids','fee_inputs','miner_fee_sat','funding_subsidy_sat','created_at','confirmed_height','confirmed_block'},
    'mappings':{'txid','allocation_id','vout'},
    'records':{'mailbox_pk','spk','account_xpub','mailbox_sig','account_sig'},
    'links':{'user_pubkey','mailbox_pk','child_index'},
}
SCHEMA='''
CREATE TABLE IF NOT EXISTS direct_journal_frame(digest TEXT PRIMARY KEY,payload TEXT NOT NULL,observed_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS direct_journal_object(kind TEXT NOT NULL,id TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(kind,id));
CREATE TABLE IF NOT EXISTS direct_check(freeze_set TEXT PRIMARY KEY,state TEXT NOT NULL,payload TEXT NOT NULL,observed_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS direct_consumption(outpoint TEXT PRIMARY KEY,freeze_set TEXT NOT NULL,txid TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS direct_retirement(id TEXT PRIMARY KEY,freeze_set TEXT NOT NULL,txid TEXT NOT NULL);
'''

def initialize(store):store.db.executescript(SCHEMA)

def frame(value, *, architecture=None):
    public_payload(value)
    per_key = architecture == DIRECT_PER_KEY
    fields = {**FIELDS, **({'records':{'mailbox_pk','spk','mailbox_sig'},
        'links':{'user_pubkey','mailbox_pk','sig','recovery_index'}} if per_key else {})}
    if (not isinstance(value,dict) or value.get('kind')!='direct_journal' or value.get('schema_version')!=1
            or type(value.get('fallback_protocol')) is not int or value.get('fallback_protocol')!=(4 if per_key else 3)
            or per_key and value.get('architecture_profile') != DIRECT_PER_KEY
            or value.get('binding_scope')!='owners_referenced_by_allocations'
            or value.get('journal_complete') is not True
            or value.get('inventory_consistent') is not True or value.get('complete') is not False
            or value.get('qualified') is not False or set(value.get('rows',{}))!=set(TABLES)):
        raise EvidenceGap('complete bounded profile-matched direct journal candidate snapshot required')
    if len(canonical(value).encode())>2_097_152:raise EvidenceGap('direct journal exceeds whole-frame bound')
    for table,key in TABLES.items():
        rows=value['rows'][table]
        if not isinstance(rows,list) or len(rows)>2000:raise EvidenceGap('direct journal table exceeds whole-frame bound')
        if any(not isinstance(r,dict) or set(r)!=fields[table] for r in rows):raise EvidenceGap('unknown or private direct journal row field refused')
        identities=[r[key] if key else (r['txid'],r['allocation_id']) for r in rows]
        if len(set(identities))!=len(identities):raise InvariantError('duplicated direct journal identity')
    allocations={r['id']:r for r in value['rows']['allocations']}
    carriers={r['txid']:r for r in value['rows']['carriers']}
    generations=[integer(r['generation'],'carrier generation',1) for r in carriers.values()]
    if len(set(generations))!=len(generations):raise InvariantError('carrier generation duplicated')
    for mapping in value['rows']['mappings']:
        if mapping['allocation_id'] not in allocations or mapping['txid'] not in carriers:
            raise EvidenceGap('carrier allocation mapping is incomplete')
        if mapping['vout'] is not None:integer(mapping['vout'],'carrier output index')
    for carrier in carriers.values():
        attached=[allocations[m['allocation_id']] for m in value['rows']['mappings'] if m['txid']==carrier['txid']]
        if not attached or len({r['freeze_set'] for r in attached})!=1:raise EvidenceGap('carrier freeze-set mapping incomplete')
        freeze=attached[0]['freeze_set']
        if {r['id'] for r in attached}!={r['id'] for r in allocations.values() if r['freeze_set']==freeze}:
            raise EvidenceGap('carrier does not map the complete frozen group')
    return value

def record(store,value):
    initialize(store);frame(value,architecture=profile(store));payload=canonical(value);digest=hashlib.sha256(payload.encode()).hexdigest()
    with store.transaction():
        for kind,key in TABLES.items():
            for row in value['rows'][kind]:
                ident=row[key] if key else canonical([row['txid'],row['allocation_id']]);old=store.db.execute('SELECT payload FROM direct_journal_object WHERE kind=? AND id=?',(kind,ident)).fetchone()
                if old:
                    prior=json.loads(old[0]);following=dict(row)
                    if kind=='carriers':
                        for mutable in ('confirmed_height','confirmed_block'):
                            prior.pop(mutable,None);following.pop(mutable,None)
                    if prior!=following:raise InvariantError('immutable direct journal object changed')
                store.db.execute('INSERT OR REPLACE INTO direct_journal_object VALUES(?,?,?)',(kind,ident,canonical(row)))
        store.db.execute('INSERT OR IGNORE INTO direct_journal_frame VALUES(?,?,?)',(digest,payload,time.time()))
        store._event('direct_journal_observed',{'digest':digest,'counts':{k:len(v) for k,v in value['rows'].items()},
            'journal_complete':True,'qualified':False,'scope':'bounded consistent DB candidates; frozen is not paid'})
    return digest

def script_dust(script):
    # Exact pinned bitcoin crate default dust relay policy, not a fee estimate.
    if script.startswith('0014') and len(script)==44:return 294
    if (script.startswith('5120') or script.startswith('0020')) and len(script)==68:return 330
    if script.startswith('76a914') and script.endswith('88ac') and len(script)==50:return 546
    if script.startswith('a914') and script.endswith('87') and len(script)==46:return 540
    raise EvidenceGap('destination dust policy is not independently supported')

def _native_vtxo_order(ident):
    # Native VtxoId derives Ord on [u8;36]: internal txid bytes, then vout LE.
    # Displayed txids reverse those hash bytes; text/numeric vout order differs.
    match=re.fullmatch(r'([0-9a-fA-F]{64}):([0-9]+)',ident)
    if match is None:raise ValueError('invalid direct allocation VTXO id')
    return bytes.fromhex(match[1])[::-1]+int(match[2]).to_bytes(4,'little')

def _proof(store,ident):
    row=store.db.execute('SELECT proof FROM owned_coin WHERE id=?',(ident,)).fetchone()
    if row is None:raise EvidenceGap('original independently verified source coin absent')
    proof=json.loads(row[0])
    if proof.get('proof_encoding')!='ark-public-authorization-v1' or proof.get('authorization_path_valid') is not True:
        raise EvidenceGap('new route needs original public authorization proof, not historical credit')
    if proof.get('conditional_steps')!=0:raise EvidenceGap('undisclosed hashlock needs separate terminal source evidence')
    return proof

def check_group(store,value,freeze,transactions):
    frame(value,architecture=profile(store));rows=value['rows'];allocs=[r for r in rows['allocations'] if r['freeze_set']==freeze]
    per_key = profile(store) == DIRECT_PER_KEY
    if not allocs:raise EvidenceGap('frozen group absent')
    versions=[r for r in rows['carriers'] if any(m['txid']==r['txid'] and m['allocation_id'] in {a['id'] for a in allocs} for m in rows['mappings'])]
    confirmed=[c for c in versions if transactions.get(c['txid'],{}).get('confirmations',0)>0]
    if not confirmed:raise EvidenceGap('frozen or mempool carrier is not a terminal payment')
    if len(confirmed)!=1:raise InvariantError('one logical group has multiple confirmed carrier winners')
    winner=confirmed[0];tx=transactions[winner['txid']]
    if (winner['confirmed_height'] is None or winner['confirmed_block']!=tx.get('blockhash')):
        raise EvidenceGap('winning Core confirmation and durable journal marker differ')
    return _check_candidate(store,rows,allocs,versions,winner,tx,freeze,per_key,
        'confirmed direct payment of independently proved ordinary sources; no delegated/Lightning terminal evidence or seed recovery inferred')


def check_pending_candidate(store,value,freeze,txid,tx):
    """Same exact source/accounting check, WITHOUT payment/retirement credit.

    Caller must independently prove current mempool membership or a confirmed
    conflicting winner. An unavailable Core version is never assumed pending.
    """
    frame(value,architecture=profile(store));rows=value['rows']
    allocs=[r for r in rows['allocations'] if r['freeze_set']==freeze]
    ids={r['id'] for r in allocs}
    versions=[r for r in rows['carriers'] if any(m['txid']==r['txid'] and m['allocation_id'] in ids for m in rows['mappings'])]
    winner=next((r for r in versions if r['txid']==txid),None)
    if (not allocs or winner is None or tx.get('txid')!=txid or tx.get('confirmations',0)!=0
            or winner['confirmed_height'] is not None or winner['confirmed_block'] is not None):
        raise EvidenceGap('pending candidate is not exact unconfirmed source')
    return _check_candidate(store,rows,allocs,versions,winner,tx,freeze,profile(store)==DIRECT_PER_KEY,
        'checked ordinary unconfirmed candidate; original gross remains owed; no payment or retirement credit')


def _check_candidate(store,rows,allocs,versions,winner,tx,freeze,per_key,scope):
    mapping={m['allocation_id']:m['vout'] for m in rows['mappings'] if m['txid']==winner['txid']}
    leaves=[];owners=[];proofs={};retired=set();operator_gross=0
    for row in allocs:
        for field in ('gross_sat','fee_sat','payout_sat','forfeited_sat'):integer(row[field],field)
        if row['disposition']=='operator':
            if any(row[f] for f in ('fee_sat','payout_sat','forfeited_sat')):raise InvariantError('operator principal is not a customer disposition')
            continue
        if row['gross_sat']!=row['fee_sat']+row['payout_sat']+row['forfeited_sat']:
            raise InvariantError('allocation dispositions do not conserve principal')
        if row['source'] not in {'registered','pending-board'}:
            raise EvidenceGap('source-specific delegated/Lightning/unregistered arbitration adapter incomplete')
        proof=_proof(store,row['id']);proofs[row['id']]=proof
        owner=expiry_owner(store,row['id'],'pending-board' if row['source']=='pending-board' else 'spendable')
        if (owner['pubkey'],owner['amount_sat'])!=(row['owner_pubkey'],row['gross_sat']):
            raise InvariantError('frozen allocation differs from independently verified owner/principal')
        own=store.db.execute('SELECT script,proof FROM owner_record WHERE actor=? AND mailbox=?',(owner['actor'],owner['mailbox'])).fetchone()
        if own is None:raise EvidenceGap('immutable owned record missing')
        record_row=next((r for r in rows['records'] if r['mailbox_pk']==owner['mailbox']),None)
        link=next((r for r in rows['links'] if r['user_pubkey']==row['owner_pubkey']),None)
        if per_key:
            from .per_key import record_bytes as c_record_bytes, link_bytes, proof_matches
            try:
                matched = (record_row is not None and link is not None and own['script']==row['spk']
                    and c_record_bytes(record_row)==json.loads(own['proof'])['fallback_record']
                    and link['mailbox_pk']==owner['mailbox']
                    and link_bytes(link)==proof['binding']['key_link_attestation']
                    and proof_matches(proof,{'user_pubkey':row['owner_pubkey'],
                        'key_link_attestation':link_bytes(link)}))
            except (ValueError,KeyError,TypeError):
                matched = False
            if not matched:raise EvidenceGap('exact retained immutable record/per-key signature not matched')
        elif (record_row is None or link is None or own['script']!=row['spk']
                or record_bytes(record_row)!=json.loads(own['proof'])['fallback_record']
                or (link['mailbox_pk'],link['child_index'])!=(owner['mailbox'],proof['binding']['child_index'])):
            raise EvidenceGap('exact immutable record/account-child admission not matched')
        leaves.append({'id':row['id'],'gross_sat':row['gross_sat'],'script':row['spk'],'dust_sat':script_dust(row['spk'])})
        owners.append((row,owner))
        if not isinstance(row['retirement_ids'],list) or not row['retirement_ids']:raise EvidenceGap('source retirement closure missing')
        if not set(row['retirement_ids'])<=set(proof['ancestor_ids']):raise EvidenceGap('retirement includes unauthenticated source')
        retired.update(row['retirement_ids'])
    for row in allocs:
        if row['disposition']!='operator':continue
        if row['source']!='transition-fee-anchor':raise EvidenceGap('operator backing classification needs a separate public source proof')
        matches=[o for p in proofs.values() for step in p['path'] for o in step.get('outputs',[])
                 if f"{step['txid']}:{o['vout']}"==row['id'] and o['script_pubkey']=='51024e73' and o['value_sat']==row['gross_sat']]
        if not matches:raise EvidenceGap('operator P2A principal is not proved by exact public source transaction')
        if row['owner_pubkey'] is not None or mapping[row['id']] is not None:raise InvariantError('operator source mistaken for a customer payout')
        operator_gross+=row['gross_sat']
    expected_inputs=set();known_source_points=set()
    for ident in winner['backing_ids']:
        candidates=[p for p in proofs.values() if ident in p['ancestor_ids']]
        if not candidates:raise EvidenceGap('physical backing root lacks independent original proof')
        # backing_ids are the actual physical rooted VTXO outpoints, not
        # an arbitrary ancestor that could authorize a different input set.
        known_source_points.add(ident)
    actual_points={i['outpoint'] for i in tx['inputs']}
    if len(actual_points)!=len(tx['inputs']):raise InvariantError('carrier repeats a physical input')
    supplemental=winner['fee_inputs'];operator_scripts={r[0] for r in store.db.execute('SELECT script FROM operator_script')}
    for item in supplemental:
        point=item['outpoint'];matches=[i for i in tx['inputs'] if i['outpoint']==point]
        if len(matches)!=1 or (matches[0]['amount_sat'],matches[0]['script'])!=(item['value_sat'],item['script_pubkey']):
            raise InvariantError('declared fee input differs from actual prevout')
        if item['script_pubkey'] not in operator_scripts:raise EvidenceGap('fee input owning-wallet descriptor unverified')
        expected_inputs.add(point)
    if not (actual_points-expected_inputs) or (actual_points-expected_inputs)!=known_source_points:
        raise EvidenceGap('carrier inputs do not consume independently proved backing roots')
    customer_scripts={leaf['script'] for leaf in leaves}
    if any(o['script'] not in customer_scripts|operator_scripts for o in tx['outputs']):
        raise EvidenceGap('operator surplus or fee-wallet change owning descriptor unverified')
    account=claim_accounts(leaves,tx,operator_gross+sum(i['value_sat'] for i in supplemental),operator_scripts)
    if account['mining_fee_sat']!=winner['miner_fee_sat']:raise InvariantError('actual miner fee differs from durable carrier')
    if winner['funding_subsidy_sat']!=max(account['mining_fee_sat']-account['flat_fee_sat']-account['forfeit_sat']-operator_gross,0):
        raise InvariantError('carrier subsidy differs from independently classified funding')
    grouped={}
    for row,_ in owners:grouped.setdefault(row['spk'],[]).append(row)
    for script,group in grouped.items():
        gross=sum(r['gross_sat'] for r in group);paid=gross>=FLAT_FEE_SAT+script_dust(script)
        remaining=FLAT_FEE_SAT if paid else 0
        output=[o for o in tx['outputs'] if o['script']==script]
        for row in sorted(group,key=lambda r:_native_vtxo_order(r['id'])):
            charge=min(row['gross_sat'],remaining);remaining-=charge
            expected=(charge,row['gross_sat']-charge,0) if paid else (0,0,row['gross_sat'])
            if (row['fee_sat'],row['payout_sat'],row['forfeited_sat'])!=expected:raise InvariantError('stable flat-fee allocation differs from policy')
            if row['disposition']!=('pay' if paid else 'forfeit'):raise InvariantError('frozen customer disposition differs from actual grouped policy')
            if mapping[row['id']]!=(output[0]['vout'] if paid and len(output)==1 else None):raise InvariantError('exact winning output mapping differs')
        if remaining:raise InvariantError('incomplete flat-fee allocation')
    return {'txid':winner['txid'],'freeze_set':freeze,'owners':owners,'retirement_ids':sorted(retired),
        'physical_inputs':sorted(actual_points),'accounting':account,'carrier_versions':sorted(c['txid'] for c in versions),
        'scope':scope}


def commit_checked(store,result,tx):
    initialize(store)
    with store.transaction():
        for table,identities in [('direct_consumption',result['physical_inputs']),('direct_retirement',result['retirement_ids'])]:
            key='outpoint' if table=='direct_consumption' else 'id'
            for identity in identities:
                old=store.db.execute(f'SELECT freeze_set,txid FROM {table} WHERE {key}=?',(identity,)).fetchone()
                if old and tuple(old)!=(result['freeze_set'],result['txid']):raise InvariantError('same backing or entitlement paid by another frozen group')
                store.db.execute(f'INSERT OR IGNORE INTO {table} VALUES(?,?,?)',(identity,result['freeze_set'],result['txid']))
        store.db.execute('INSERT OR REPLACE INTO chain_payout VALUES(?,?)',(result['txid'],canonical(tx)))
        for row,owner in result['owners']:
            old=store.db.execute('SELECT txid FROM checked_settlement WHERE coin_id=?',(row['id'],)).fetchone()
            if old and old['txid']!=result['txid']:raise InvariantError('same logical customer allocation paid twice')
            evidence={**row,'actor':owner['actor'],'route':'direct','accounting':result['accounting'],
                'carrier_versions':result['carrier_versions'],'scope':result['scope']}
            store.db.execute('INSERT OR REPLACE INTO checked_settlement VALUES(?,?,?,?,?,?)',
                (row['id'],result['txid'],owner['actor'],row['spk'],row['payout_sat'],canonical(evidence)))
        public={k:v for k,v in result.items() if k!='owners'}
        store.db.execute('INSERT OR REPLACE INTO direct_check VALUES(?,?,?,?)',(result['freeze_set'],'confirmed_checked',canonical(public),time.time()))
        store._event('direct_payment_checked',public)

async def collect(store,config,chain,limit=2):
    if not config.inventory_command:return 0
    request={'kind':'direct_journal'}
    observed=await json_command(list(config.inventory_command),request,timeout=25,
        **public_command_capture(store,'direct.journal',request))
    record(store,observed)
    groups=sorted({a['freeze_set'] for a in observed['rows']['allocations']})
    after=store.get_meta('direct_check_cursor') or ''
    groups=[g for g in groups if g>after]+[g for g in groups if g<=after]
    checked=0
    for freeze in groups[:limit]:
        try:
            ids={a['id'] for a in observed['rows']['allocations'] if a['freeze_set']==freeze}
            versions={m['txid'] for m in observed['rows']['mappings'] if m['allocation_id'] in ids}
            transactions={}
            for txid in versions:
                try:transactions[txid]=await asyncio.to_thread(chain.transaction,txid)
                except Exception as error:
                    # Existing ChainReader errors do not establish authoritative
                    # absence or a mutually conflicting signed input set.
                    raise EvidenceGap('carrier version outcome unknown: '+type(error).__name__) from error
            result=check_group(store,observed,freeze,transactions)
            commit_checked(store,result,transactions[result['txid']]);checked+=1
        except InvariantError:raise
        except (EvidenceGap,ValueError,KeyError) as error:
            state={'reason':str(error),'frozen_is_paid':False,'qualified':False}
            store.db.execute('INSERT OR REPLACE INTO direct_check VALUES(?,?,?,?)',(freeze,'pending',canonical(state),time.time()))
        store.db.execute("INSERT OR REPLACE INTO meta VALUES('direct_check_cursor',?)",(freeze,))
    return checked

"""Public typed native-owner snapshot joins, never a private publication proof.

The admitted protected producer must bind the actual CLI/source/process/FLOCK.
This module consumes native serde projection; it does NOT decode its f/g/r/p
journal or reconstruct Rust family/prevout hashes. Reservations never become
costs, income, wallet ownership or input-release permission here.
"""
import re
from .ownership import EvidenceGap
from .two_step_normal import digest, strict_json

MAX_BYTES = 2*1024*1024
MAX_ROWS = 4096
MAX_MONEY = 21_000_000*100_000_000
FIELDS = {'schema','policy_sha256','opening_sha256','journal_sha256','journal_device',
    'journal_inode','journal_bytes','policy','opening','charged_sat','remaining_total_sat',
    'urgent_remaining_sat','discretionary_remaining_sat','direct_attempt_count',
    'direct_reserved_sat','funding_reserved_sat','round_reserved_sat','pool_reserved_sat',
    'urgent_reserved_sat','funding','urgent','resolutions'}
POLICY = {'urgent_reserve_sat','ordinary_budget_sat','external_future_reserved_sat','opening_sha256'}
OPENING = {'version','network','genesis','server_pubkey','history_prefix_bytes',
    'history_prefix_sha256','native_spent_sat','external_spent_sat','accounting_receipt_sha256'}
FUNDING = {'index','purpose','family_sha256','generation','unsigned_body_sha256',
    'prevouts_sha256','txid','signed_wtxid','ceiling_sat'}


def need(value, field):
    if not value: raise EvidenceGap('B native owner snapshot: '+field)


def number(value, field, minimum=0, maximum=MAX_MONEY):
    need(type(value) is int and minimum <= value <= maximum, field)
    return value


def hashed(value, field):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None,field)
    return value


def rows(value, field):
    need(type(value) is list and len(value)<=MAX_ROWS,field)
    return value


def owner_snapshot(raw, runtime, *, expected_product_commit):
    """Check a complete native typed projection against protected actual files.

    expected_product_commit is an independently source-admitted final pin, never
    selected by the response. The protected runtime verifier runs BEFORE this
    reducer. Returned categories are authorizations only, including every failed,
    unsigned and old attempt. No absent SQL/package is replaced with an empty cut.
    """
    need(type(expected_product_commit) is str and re.fullmatch('[0-9a-f]{40}',expected_product_commit),
         'independent final native source absent')
    need(type(runtime) is dict and runtime.get('product_commit')==expected_product_commit
        and runtime.get('execution_release',{}).get('product_commit')==expected_product_commit,
        'actual protected native source differs')
    need(type(raw) is bytes and 0<len(raw)<=MAX_BYTES+1,'bounded original native snapshot absent')
    # The native projection is at most2MiB; its actual CLI appends one LF.
    payload=raw[:-1] if raw.endswith(b'\n') else raw
    need(0<len(payload)<=MAX_BYTES,'native projection exceeds payload bound')
    snapshot=strict_json(payload)
    need(type(snapshot) is dict and set(snapshot)==FIELDS and type(snapshot['schema']) is int
        and snapshot['schema']==1,'exact native schema1 required')
    budget=runtime.get('native_budget',{});files=budget.get('files',{});lock=budget.get('lock',{})
    for kind,field in [('ordinary-fee-budget','journal_sha256'),
                       ('ordinary-fee-policy.json','policy_sha256'),
                       ('ordinary-fee-opening.json','opening_sha256')]:
        need(type(files.get(kind)) is dict and files[kind].get('sha256')==hashed(snapshot[field],field),
            'same protected file hash differs '+kind)
    journal=files['ordinary-fee-budget']
    need(number(snapshot['journal_bytes'],'journal length',maximum=MAX_BYTES)==journal.get('bytes')
        and number(snapshot['journal_device'],'journal device',maximum=2**64-1)==journal.get('device')==lock.get('device')
        and number(snapshot['journal_inode'],'journal inode',minimum=1,maximum=2**64-1)==journal.get('inode')==lock.get('inode'),
        'same active FLOCK journal identity differs')
    policy=snapshot['policy'];opening=snapshot['opening']
    need(type(policy) is dict and set(policy)==POLICY and type(opening) is dict and set(opening)==OPENING,
         'exact native policy/opening fields required')
    cap=runtime.get('public_configuration',{}).get('captaind',{});watch=runtime.get('public_configuration',{}).get('watchmand',{})
    need(cap.get('ordinary_fee_policy')==policy==watch.get('direct_expiry',{}).get('ordinary_fee_policy'),
        'same loaded paired policy differs')
    allowance=number(policy['ordinary_budget_sat'],'ordinary lifetime',minimum=1)
    urgent_limit=number(policy['urgent_reserve_sat'],'urgent sublimit',minimum=1,maximum=allowance)
    future=number(policy['external_future_reserved_sat'],'fixed future partition',maximum=allowance)
    need(type(opening['version']) is int and opening['version']==1
        and opening['network']==cap.get('network')==watch.get('network')
        and opening['network'] in {'signet','regtest'},'opening chain/version differs')
    hashed(opening['genesis'],'opening genesis');hashed(opening['history_prefix_sha256'],'opening prefix')
    need(type(opening['server_pubkey']) is str and re.fullmatch('(02|03)[0-9a-f]{64}',opening['server_pubkey']),
        'opening server differs')
    prefix=number(opening['history_prefix_bytes'],'opening prefix bytes',maximum=650000)
    need(prefix%65==0,'opening prefix framing differs')
    native=number(opening['native_spent_sat'],'native opening');external=number(opening['external_spent_sat'],'external opening')
    if policy['opening_sha256'] is None:
        need(native==external==prefix==0 and opening['history_prefix_sha256']==digest(b'')
            and opening['accounting_receipt_sha256'] is None,'fresh opening contains historical money')
    else:
        need(hashed(policy['opening_sha256'],'adopted opening')==snapshot['opening_sha256']
            and prefix>0 and native>0 and hashed(opening['accounting_receipt_sha256'],'original accounting receipt')!='0'*64,
            'adopted history source differs')
    direct_count=number(snapshot['direct_attempt_count'],'direct count',maximum=10000)
    direct=number(snapshot['direct_reserved_sat'],'direct ceilings')
    need((direct_count==0)==(direct==0) and direct>=direct_count,'direct count/ceilings differ')
    funding=rows(snapshot['funding'],'funding row bound');urgent=rows(snapshot['urgent'],'urgent row bound')
    resolutions=rows(snapshot['resolutions'],'resolution row bound')
    indices={};families={};sums={'round':0,'pool':0};previous=0
    for row in funding:
        need(type(row) is dict and set(row)==FUNDING,'exact funding projection fields required')
        index=number(row['index'],'funding index',minimum=1,maximum=10000)
        need(index>previous and index<=direct_count+len(funding),'funding indices differ');previous=index
        need(row['purpose'] in sums,'unknown funding purpose')
        generation=number(row['generation'],'funding generation',maximum=2**32-1)
        need(row['purpose']!='pool' or generation==0,'pool generation differs')
        for field in ('family_sha256','unsigned_body_sha256','prevouts_sha256','txid'):hashed(row[field],field)
        if row['signed_wtxid'] is not None:hashed(row['signed_wtxid'],'signed funding witness identity')
        family=families.setdefault(row['family_sha256'],[])
        need(all(old['purpose']==row['purpose'] and old['generation']!=generation for old in family),
            'funding family purpose/generation conflicts')
        need(row['signed_wtxid'] is None or all(old['signed_wtxid'] is None for old in family),
            'competing signed family')
        family.append(row);indices[index]=row
        sums[row['purpose']]+=number(row['ceiling_sat'],'funding full ceiling',minimum=1)
    urgent_sum=0
    for i,row in enumerate(urgent,1):
        need(type(row) is dict and set(row)=={'index','ceiling_sat','source_binding_sha256','transactions'}
            and type(row['index']) is int and row['index']==i,'urgent complete sequential identities differ')
        urgent_sum+=number(row['ceiling_sat'],'urgent full ceiling',minimum=1)
        txs=rows(row['transactions'],'urgent transaction list')
        need(len(txs)<=2,'urgent package member bound')
        if row['source_binding_sha256'] is None:need(not txs,'unbound urgent has signed members')
        else:
            need(hashed(row['source_binding_sha256'],'urgent source binding')!='0'*64 and txs,
                 'urgent binding lacks exact signed members')
        ids=set()
        for tx in txs:
            need(type(tx) is dict and set(tx)=={'txid','wtxid'},'urgent public identity fields differ')
            hashed(tx['txid'],'urgent txid');hashed(tx['wtxid'],'urgent wtxid')
            need(tx['txid'] not in ids,'urgent duplicate member');ids.add(tx['txid'])
    previous=0
    for row in resolutions:
        need(type(row) is dict and set(row)=={'winner_index','block_height','block_hash'},'resolution fields differ')
        index=number(row['winner_index'],'resolution winner',minimum=1,maximum=10000)
        winner=indices.get(index)
        need(index>previous and winner and winner['purpose']=='round' and winner['signed_wtxid'] is not None,
            'resolution lacks original signed Round winner');previous=index
        number(row['block_height'],'resolution block height',minimum=1,maximum=2**32-1)
        need(hashed(row['block_hash'],'resolution block')!='0'*64,'resolution zero block')
    funding_sum=sums['round']+sums['pool'];opening_charge=native+external+future
    charged=opening_charge+direct+funding_sum+urgent_sum
    need(charged<=allowance and urgent_sum<=urgent_limit,'lifetime/urgent authorization exhausted')
    expected={'round_reserved_sat':sums['round'],'pool_reserved_sat':sums['pool'],
        'funding_reserved_sat':funding_sum,'urgent_reserved_sat':urgent_sum,
        'charged_sat':charged,'remaining_total_sat':allowance-charged,
        'urgent_remaining_sat':urgent_limit-urgent_sum,
        'discretionary_remaining_sat':allowance-charged-(urgent_limit-urgent_sum)}
    need(expected['discretionary_remaining_sat']>=0,'ordinary consumed urgent headroom')
    for field,value in expected.items():need(type(snapshot[field]) is int and snapshot[field]==value,field+' arithmetic differs')
    need((snapshot['journal_bytes']==0)==(not direct_count and not funding and not urgent),
        'empty journal inventory differs')
    return {'snapshot_sha256':digest(raw),'network':opening['network'],'genesis':opening['genesis'],
        'server_pubkey':opening['server_pubkey'],'policy_sha256':snapshot['policy_sha256'],
        'opening_sha256':snapshot['opening_sha256'],'journal_sha256':snapshot['journal_sha256'],
        'opening_charge_sat':opening_charge,'direct_attempt_count':direct_count,'direct_reserved_sat':direct,
        **expected,'funding':funding,'urgent':urgent,'resolutions':resolutions}


def current_resolution_anchors(partition,chain,*,tip):
    """Check canonical signed-winning chain observations; does not release inputs.

    Whole SQL family/input ownership and native private validation are separately
    required. A signed/mempool reservation is never a confirmed resolution.
    """
    def stable():
        actual=chain.identity()
        need((actual.get('blocks'),actual.get('bestblockhash'))==tip
            and actual.get('initialblockdownload') is False and actual.get('chain')==partition['network']
            and chain.call('getblockhash',0)==partition['genesis'],'independent current tip changed')
    stable();funding={r['index']:r for r in partition['funding']};result=[]
    for resolution in partition['resolutions']:
        row=funding[resolution['winner_index']];height=resolution['block_height']
        need(height<=tip[0] and chain.call('getblockhash',height)==resolution['block_hash'],
            'resolution block is not canonical')
        tx=chain.call('getrawtransaction',row['txid'],True)
        need(type(tx) is dict and tx.get('txid')==row['txid'] and tx.get('hash')==row['signed_wtxid']
            and tx.get('blockhash')==resolution['block_hash'] and type(tx.get('confirmations')) is int
            and tx['confirmations']==tip[0]-height+1,'actual signed confirmed winner differs')
        result.append({**resolution,'txid':row['txid'],'wtxid':row['signed_wtxid'],
            'confirmations':tx['confirmations']})
    stable();return result


def require_publication_sources(partition):
    """Never activate new domains from the safe snapshot or startup check alone."""
    need(not partition['funding'] and not partition['resolutions'],
         'fresh source-bound native V79/V80 private proof required')
    need(not partition['urgent'],'fresh source-bound complete urgent nursery/package proof required')

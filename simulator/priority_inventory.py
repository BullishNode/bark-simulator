"""Bounded public inventory discovery for existing online pending rounds.

These independent cyclic cursors accelerate observation without changing the
normal inventory rotation, waking a client, or authorizing a money operation.
Pages are trusted server claims, never a consistent commit watermark or a
signature, ownership, confirmation-header-chain or traffic verdict.
"""
from __future__ import annotations
import asyncio,json,math,re,time
from .model import InvariantError,canonical,integer,public_payload
from .ownership import record_server_page
from .padding import collect as collect_decoder
from .process import json_command,public_command_capture

PAGE_BUDGET=4
TIME_BUDGET=12
DECODE_LIMIT=16
FIELD={'coins':'vtxo_id','nursery':'txid'}
PATTERN={'coins':re.compile('[0-9a-f]{64}:[0-9]+'), 'nursery':re.compile('[0-9a-f]{64}')}


def interests(store):
    """Consult only the journal; permanently absent actors never enable a scan."""
    result=[]
    for row in store.db.execute("""SELECT a.id,a.details,m.movement_id,m.payload FROM actor a
        JOIN movement_evidence m ON m.actor=a.id WHERE a.online=1
        AND json_extract(m.payload,'$.subsystem')='bark.round'
        AND json_extract(m.payload,'$.status')='pending' ORDER BY a.id,m.movement_id"""):
        if json.loads(row['details']).get('permanent_absence'):continue
        movement=json.loads(row['payload']);inputs=movement.get('input_vtxos')
        if not isinstance(inputs,list) or not inputs:continue
        if len(inputs)>1024 or any(not isinstance(value,str) or len(value)>128 for value in inputs):
            raise ValueError('bounded pending round identities required')
        result.append({'actor':row['id'],'movement_id':row['movement_id'],'input_coin_ids':inputs})
        if len(result)>128:raise ValueError('bounded pending round scan interest required')
    public_payload(result)
    return result


def _checkpoint(store,kind):
    saved=store.get_meta('round_priority_cursor_'+kind)
    if saved is None:return {'schema_version':1,'after':'','generation':0}
    value=json.loads(saved)
    if (set(value)!={'schema_version','after','generation'} or value['schema_version']!=1
            or not isinstance(value['after'],str) or value['after'] and PATTERN[kind].fullmatch(value['after']) is None):
        raise ValueError('invalid durable priority inventory checkpoint')
    integer(value['generation'],'priority inventory scan generation')
    return value


def _validate(kind,after,page):
    public_payload(page)
    if not isinstance(page,dict) or page.get('kind')!=kind or page.get('inventory_consistent') is not False:
        raise ValueError('matching inconsistent public inventory page required')
    rows=page.get('rows')
    if not isinstance(rows,list) or len(rows)>100:raise ValueError('priority inventory page cap')
    identities=[]
    for row in rows:
        if not isinstance(row,dict):raise ValueError('public inventory row required')
        identity=row.get(FIELD[kind])
        if not isinstance(identity,str) or PATTERN[kind].fullmatch(identity) is None:raise ValueError('public inventory identity required')
        identities.append(identity)
    if identities!=sorted(set(identities)) or any(value<=after for value in identities):
        raise ValueError('inventory page must advance its declared lexical cursor')
    following=page.get('next')
    if following is not None and (not identities or following!=identities[-1]):
        raise ValueError('public inventory continuation differs from last row')
    return following


async def collect(store,config,*,fetch=None,decode=None,normal_page=None,
                  page_budget=PAGE_BUDGET,time_budget=TIME_BUDGET):
    """At most one nursery page and remaining coin pages, under one deadline.

    A known normal page can advance this cursor without another RPC. Scan ends
    wrap explicitly in the journal and stop that lane for the current call.
    Failed/timeout responses cannot advance the durable cursor; committed
    earlier pages survive. New interests never reset a cursor.
    """
    integer(page_budget,'priority inventory page budget',2)
    if page_budget>8:raise ValueError('priority inventory page budget exceeds eight')
    if type(time_budget) not in (int,float) or not math.isfinite(time_budget) or not 0<time_budget<=25:
        raise ValueError('bounded priority inventory deadline required')
    stats={'status':'idle','pages':0,'requests':0,'read_only':True,'traffic_credit':False,
        'page_budget':page_budget,'time_budget_seconds':time_budget,'decoder_limit':DECODE_LIMIT}
    if not getattr(config,'inventory_command',()):return stats
    fetch=json_command if fetch is None else fetch
    decode=collect_decoder if decode is None else decode
    started=time.monotonic();normal_used=False
    try:
        interested=interests(store)
        if not interested:return stats
        stats['status']='observed';stats['interest']=interested
        with store.transaction():
            encoded=canonical(interested)
            if store.get_meta('round_priority_inventory_interest')!=encoded:
                store.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',('round_priority_inventory_interest',encoded))
                store._event('round_priority_inventory_interest',{'rounds':interested,'cursor_reset':False,'read_only':True})
        async with asyncio.timeout(time_budget):
            for kind,limit in [('nursery',1),('coins',page_budget-1)]:
                for _ in range(limit):
                    # A disappearance during another read never triggers further calls.
                    if time.monotonic()-started>=time_budget:raise TimeoutError('priority inventory deadline reached')
                    interested=interests(store)
                    if not interested:break
                    checkpoint=_checkpoint(store,kind);request={'kind':kind,'after':checkpoint['after']}
                    reused=bool(not normal_used and normal_page and normal_page.get('request')==request)
                    context={'request':request,'generation':checkpoint['generation'],'rounds':interested,'read_only':True}
                    if reused:
                        response=normal_page['response'];normal_used=True
                    else:
                        store.event('round_priority_inventory_request',context)
                        stats['requests']+=1
                        response=await fetch(list(config.inventory_command),request,
                            timeout=max(.001,time_budget-(time.monotonic()-started)),
                            **public_command_capture(store,'inventory.priority',request))
                    following=_validate(kind,checkpoint['after'],response)
                    ended=following is None
                    next_checkpoint={'schema_version':1,'after':following or '',
                        'generation':checkpoint['generation']+int(ended)}
                    # record_server_page shares this transaction; cursor and item
                    # histories either both commit or both roll back.
                    with store.transaction():
                        if not reused:record_server_page(store,response)
                        store.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',
                            ('round_priority_cursor_'+kind,canonical(next_checkpoint)))
                        store._event('round_priority_inventory_page',{
                            **context,'kind':kind,'rows':len(response['rows']),
                            'row_ids':[row[FIELD[kind]] for row in response['rows']],
                            'next_cursor':next_checkpoint['after'],'generation':next_checkpoint['generation'],
                            'scan_finished':ended,'reused_normal_page':reused,'inventory_consistent':False,
                            'traffic_credit':False})
                    stats['pages']+=1
                    if ended:break
            if stats['pages'] and interests(store) and getattr(config,'server_policy_command',()):
                # The decoder prioritizes unclaimed/newly observed rows. It is
                # pure public SDK decoding, not an original client wallet call.
                await decode(store,config.server_policy_command,config.expected_server_pubkey,limit=DECODE_LIMIT)
    except InvariantError:raise
    except (ValueError,KeyError,TypeError,RuntimeError,TimeoutError) as error:
        stats['status']='held';stats['gap']=type(error).__name__
        store.event('round_priority_inventory_gap',{
            'reason':type(error).__name__,'pages_committed':stats['pages'],'requests':stats['requests'],
            'read_only':True,'traffic_credit':False,'cursor_reset':False,
            'scope':'public discovery gap; independent normal rotation continues'})
    return stats

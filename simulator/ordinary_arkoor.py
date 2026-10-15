"""One ordinary, fee-guarded 2000-sat payment from the adopted pilot Board.

This is a finite source producer, never a dispatcher. Unknown or unsupported
states hold; the original campaign collector alone supplies recipient credit.
"""
import hashlib
import json
import os
import re
import sqlite3
import stat
import time
from pathlib import Path

from .final_campaign import _pins, _source_event, _action_pins
from .model import canonical, public_payload
from .fresh_cash_readiness import _fresh, ECONOMIC_TABLES, METADATA_TABLES
from . import board_adoption as backing
from .campaign import _signed_coin, _receipt_origin, collect_ark_receipts
from .ownership import proof_matches_profile, binding_matches

KEY='finite_ordinary_arkoor_plan'
KIND='ordinary_arkoor_sources_verified'
STEPS=('address','send','receiver_sync','receiver_snapshot','sender_snapshot')


def _shape(value):
    if (not isinstance(value,dict) or set(value)!={'id','pins','boundary_id','board_action_id','actions','amount_sat','maximum_fee_sat'}
            or not isinstance(value['id'],str) or re.fullmatch('[a-z0-9_-]{1,100}',value['id']) is None
            or not isinstance(value['boundary_id'],str) or not value['boundary_id']
            or not isinstance(value['board_action_id'],str) or not value['board_action_id']
            or not isinstance(value['actions'],dict) or set(value['actions'])!=set(STEPS)
            or any(not isinstance(item,str) or not 1<=len(item)<=128 for item in value['actions'].values())
            or len(set(value['actions'].values()))!=len(STEPS) or value['board_action_id'] in value['actions'].values()
            or type(value['amount_sat']) is not int or value['amount_sat']!=2000
            or type(value['maximum_fee_sat']) is not int or value['maximum_fee_sat']!=0):
        raise ValueError('exact once-only ordinary 2000-sat declaration required')
    _pins(value['pins']);public_payload(value)
    return value


def plan(store):
    encoded=store.get_meta(KEY)
    if encoded is None:raise ValueError('ordinary Arkoor plan missing')
    value=_shape(json.loads(encoded));rows=store.db.execute("SELECT sequence FROM event WHERE kind='finite_ordinary_arkoor_plan_declared'").fetchall()
    if len(rows)!=1 or _source_event(store,rows[0][0])[1]!=value:raise ValueError('ordinary plan differs from original')
    return value


def declare_ordinary_arkoor(store,value):
    _shape(value)
    with store.transaction():
        if store.get_meta(KEY) is not None:
            if plan(store)!=value:raise ValueError('ordinary plan immutable')
            return False
        from .first_board_readiness import board_plan
        original=board_plan(store)
        if (not store.get_meta('paused') or value['pins']!=original['pins'] or value['boundary_id']!=original['boundary_id']
                or value['board_action_id']!=original['board_actions']['actor-01']
                or store.db.execute("SELECT 1 FROM action WHERE operation='send_arkoor' OR state IN ('queued','dispatched','outcome_unknown')").fetchone()
                or any(store.db.execute('SELECT 1 FROM action WHERE id=?',(identity,)).fetchone() for identity in value['actions'].values())):
            raise ValueError('pause adopted original Board before declaring ordinary journey')
        store.db.execute('INSERT INTO meta VALUES (?,?)',(KEY,canonical(value)));store._event('finite_ordinary_arkoor_plan_declared',value)
    return True


def _response(store,row):
    _action_pins(store,row['id'],plan(store)['pins'])
    event,payload=backing._unique(store,'driver_response',row['id']);reply=payload['response']
    requested,frame=backing._unique(store,'driver_request',row['id']);request=frame.get('request',{})
    dispatched,_=backing._unique(store,'action_dispatched',row['id'])
    if (request.get('action_id')!=row['id'] or request.get('operation')!=row['operation']
            or request.get('args')!=json.loads(row['args']) or type(request.get('maximum_fee_sat')) is not int
            or request['maximum_fee_sat']!=0 or not dispatched['sequence']<requested['sequence']<event['sequence']):raise ValueError('original native zero-fee guarded request required')
    if (row['state']!='completed' or row['actual_fee_sat']!=0 or reply.get('status')!='ok'
            or reply.get('action_id')!=row['id'] or reply!=json.loads(row['result'])):
        raise ValueError('original completed zero-fee native response required')
    data=reply.get('data',{})
    if row['operation']=='sync' and (data.get('receive_count_before')!=0 or data.get('receive_count_after')!=0):raise ValueError('ordinary sync must prove no Lightning receives')
    return event,data


def _destination(store,value):
    row=store.db.execute('SELECT * FROM action WHERE id=?',(value['actions']['address'],)).fetchone()
    if row is None:return None
    if row['actor_id']!='actor-02' or row['operation']!='address' or json.loads(row['args'])!={} or row['fee_reservation_sat']!=0:
        raise ValueError('original recipient address action differs')
    if row['state']!='completed':return None
    event,data=_response(store,row)
    key=store.db.execute('SELECT * FROM owner_key WHERE pubkey=?',(data.get('user_pubkey'),)).fetchone()
    if key is None or key['actor']!='actor-02':raise ValueError('recipient native ownership proof missing')
    proof=json.loads(key['proof'])
    if (proof.get('financial_pins')!=value['pins'] or not proof_matches_profile(store,proof,data)
            or not binding_matches(proof.get('binding',{}),data.get('binding',{}))
            or proof['binding']['mailbox_pk']!=key['mailbox']
            or not isinstance(data.get('address'),str) or not 1<=len(data['address'])<=4096):
        raise ValueError('recipient account-child proof differs')
    verified,verification=backing._unique(store,'public_ownership_verified',row['id'])
    if (verification.get('financial_pins')!=value['pins'] or verification.get('actor')!='actor-02' or verified['sequence']<=event['sequence']):raise ValueError('original recipient proof ordering differs')
    return {'address':data['address'],'user_pubkey':data['user_pubkey'],'binding':proof['binding'],
        'response_sequence':event['sequence'],'response_sha256':backing._digest(json.loads(row['result']))}


def _expected(value,step,destination):
    actor='actor-01' if step in ('send','sender_snapshot') else 'actor-02'
    operation={'send':'send_arkoor','receiver_sync':'sync','receiver_snapshot':'snapshot','sender_snapshot':'snapshot','address':'address'}[step]
    args={'destination':destination['address'],'recipient_actor':'actor-02','amount_sat':2000} if step=='send' and destination else {}
    return actor,operation,args


def _legacy_observation(store,row,board,pins):
    """Authenticate old zero-fee observations without assigning missing pins.

    The shared collector separately requires the original complete post-sync
    empty-ecosystem/cash baseline used before this Board. These historical
    replies establish chronology only; they never become qualified reads.
    """
    frames=[]
    for kind in ('action_intent','action_dispatched','driver_request','driver_response'):
        event,payload=backing._unique(store,kind,row['id']);frames.append((event,payload))
        if (not row['created_at']<board['created_at'] or not row['updated_at']<board['created_at']
                or not event['observed_at']<board['created_at']
                or 'financial_pins' in payload and payload['financial_pins']!=pins):raise ValueError('legacy observation must precede original Board with matching optional pins')
    intent,dispatch,request,response=[item[1] for item in frames]
    if ([item[0]['sequence'] for item in frames]!=sorted(item[0]['sequence'] for item in frames)
            or intent.get('actor')!=row['actor_id'] or dispatch.get('actor')!=row['actor_id']
            or intent.get('operation')!=row['operation'] or intent.get('args')!={} or intent.get('fee_reservation_sat')!=0):raise ValueError('legacy original intent/dispatch differs')
    native=request.get('request',{});reply=response.get('response',{})
    if (native.get('action_id')!=row['id'] or native.get('operation')!=row['operation'] or native.get('args')!={}
            or native.get('maximum_fee_sat')!=0 or reply!=json.loads(row['result']) or reply.get('action_id')!=row['id']
            or reply.get('status')!='ok' or reply.get('actual_fee_sat')!=0):raise ValueError('legacy original native zero-fee reply differs')
    data=reply.get('data',{})
    if (data.get('vtxos',[])!=[] or any(data.get(frame,{}).get(field,[])!=[] for frame in ('before_evidence','evidence') for field in ('coins','movements'))
            or 'balance' in data and (not isinstance(data['balance'],dict) or any(type(amount) is not int or amount!=0 for amount in data['balance'].values()))
            or row['operation']=='sync' and (data.get('receive_count_before')!=0 or data.get('receive_count_after')!=0)):
        raise ValueError('legacy observation contains monetary evidence')


def _history(store,origin,reserved=None,allow_queued=False):
    value=plan(store)
    if (origin['board_action_id']!=value['board_action_id'] or origin['financial_pins']!=value['pins']
            or origin['boundary_id']!=value['boundary_id']):raise ValueError('ordinary original Board context differs')
    destination=_destination(store,value);pending=[];next_step=None
    for step in STEPS:
        row=store.db.execute('SELECT * FROM action WHERE id=?',(value['actions'][step],)).fetchone()
        if row is None:
            if next_step is None:next_step=step
            continue
        actor,operation,args=_expected(value,step,destination)
        if (next_step is not None or row['actor_id']!=actor or row['operation']!=operation
                or json.loads(row['args'])!=args or row['fee_reservation_sat']!=0
                or step=='send' and destination is None):raise ValueError('ordinary serial action context differs')
        if row['state']=='queued':
            _,intent=backing._unique(store,'action_intent',row['id'])
            if (intent.get('financial_pins')!=value['pins'] or intent.get('actor')!=actor or intent.get('operation')!=operation or intent.get('args')!=args or intent.get('fee_reservation_sat')!=0):raise ValueError('original queued ordinary intent differs')
        else:_action_pins(store,row['id'],value['pins'])
        if row['state']!='completed':
            if row['id']!=reserved and not (allow_queued and row['state']=='queued'):raise ValueError('ordinary unknown/nonterminal action holds')
            pending.append(step);next_step=step
        else:_response(store,row)
    if len(pending)>1:raise ValueError('only one ordinary action may be active')
    declared=set(value['actions'].values())|{origin['board_action_id']}
    for row in store.db.execute('SELECT * FROM action'):
        if row['id'] in declared:continue
        if (row['actor_id'] not in ('actor-01','actor-02','actor-04') or row['state']!='completed'
                or row['operation'] not in ('create','address','sync','snapshot') or row['fee_reservation_sat']!=0
                or row['actual_fee_sat']!=0 or json.loads(row['args'])!={}):raise ValueError('unrelated or second monetary action holds ordinary journey')
        board=store.db.execute('SELECT * FROM action WHERE id=?',(origin['board_action_id'],)).fetchone()
        if board is not None and row['created_at']<board['created_at']:
            _legacy_observation(store,row,board,value['pins'])
        else:
            if row['operation']=='create':raise ValueError('post-Board identity creation is unavailable')
            _action_pins(store,row['id'],value['pins'])
    if store.db.execute("SELECT 1 FROM funding_batch WHERE state!='confirmed'").fetchone():raise ValueError('unresolved funding holds ordinary journey')
    return next_step,destination


def _send(store,origin):
    value=plan(store);row=store.db.execute('SELECT * FROM action WHERE id=?',(value['actions']['send'],)).fetchone()
    if row is None or row['state'] in ('queued','dispatched'):return None
    event,data=_response(store,row);proposal_event,frame=backing._unique(store,'driver_evidence',row['id'],'arkoor_request');proposal=frame['data']
    if frame.get('financial_pins',value['pins'])!=value['pins'] or proposal_event['sequence']>=event['sequence']:raise ValueError('original quote ordering/context differs')
    destination=_destination(store,value)
    if (data.get('submitted')!='send_arkoor' or data.get('amount_sat')!=2000 or data.get('estimated_fee_sat')!=0 or data.get('actual_fee_sat')!=0
            or proposal.get('destination')!=destination['address'] or proposal.get('amount_sat')!=2000
            or proposal.get('estimated_fee_sat')!=0 or proposal.get('input_vtxo_ids')!=[origin['vtxo_id']]):
        raise ValueError('actual pinned native zero-fee quote and single original input required')
    movements=[item for item in data.get('evidence',{}).get('movements',[]) if item.get('subsystem')=='bark.arkoor']
    if (len(movements)!=1 or movements[0].get('status')!='successful' or movements[0].get('input_vtxos')!=[origin['vtxo_id']]
            or movements[0].get('effective_balance_sat')!=-2000 or movements[0].get('offchain_fee_sat')!=0):raise ValueError('successful original sender movement required')
    changes={}
    for coin in data.get('evidence',{}).get('coins',[]):
        if coin['id']==origin['vtxo_id']:continue
        signed=_signed_coin(store,coin['id'],'actor-01')
        if signed is None:raise ValueError('native signed sender change proof missing')
        owned,proof=signed
        if (coin.get('amount_sat')!=owned['amount_sat'] or coin.get('user_pubkey')!=owned['pubkey']
                or coin.get('expiry_height')!=origin['expiry_height']
                or hashlib.sha256(bytes.fromhex(coin['signed_vtxo'])).hexdigest()!=owned['signed_hash']):raise ValueError('original native change bytes differ')
        if (proof.get('financial_pins')!=value['pins'] or proof.get('conditional_steps')!=0
                or proof.get('chain_anchor')!=origin['anchor'] or proof.get('expiry_height')!=origin['expiry_height']
                or _receipt_origin(proof,{origin['vtxo_id']}) is None or coin['id'] in changes):raise ValueError('ordinary change path differs')
        changes[coin['id']]={'amount_sat':owned['amount_sat'],'user_pubkey':owned['pubkey'],'proof':proof}
    if (not 1<=len(changes)<=8 or set(movements[0].get('output_vtxos',[]))!=set(changes)
            or sum(item['amount_sat'] for item in changes.values())!=origin['net_liability_sat']-2000):raise ValueError('exact signed sender change conservation required')
    return {'action_id':row['id'],'response_sequence':event['sequence'],'response_sha256':backing._digest(json.loads(row['result'])),
        'movement_id':str(movements[0]['id']),'changes':changes,'destination':destination}


def _server(database,prior,origin,store):
    send=_send(store,origin)
    if send is None:
        result=backing._database(database,prior,origin)
        if result['registered'] is not True:raise ValueError('original Board must be registered before ordinary journey')
        return result
    if (database.get('kind')!='closed_frontier' or database.get('database_tables_complete') is not True
            or database.get('inventory_consistent') is not True or database.get('read_only') is not True
            or set(database.get('rows',{}))!=set(prior['rows'])):raise ValueError('complete original server frontier required')
    rows=database['rows'];allowed={'coins','pending_boards','links','journal_links','records','journal_records'}
    if any(items for name,items in rows.items() if name not in allowed):raise ValueError('unrelated monetary server frontier')
    if any(rows[name]!=prior['rows'][name] for name in ('records','journal_records')):raise ValueError('original immutable records changed')
    points={coin['vtxo_id']:coin for coin in rows['coins']}
    if len(points)!=len(rows['coins']) or not 4<=len(points)<=24 or origin['anchor'] not in points or origin['vtxo_id'] not in points:raise ValueError('bounded original ordinary graph required')
    root=points[origin['anchor']]
    if (root['amount']!=20000 or root['policy_type']!='expiry' or root['spend_state']!='spent'
            or root['oor_spent_txid']!=origin['vtxo_id'].split(':')[0] or root['anchor_point']!=origin['anchor']
            or root['expiry']!=origin['expiry_height'] or any(root.get(key) is not None for key in ('spent_in_round','offboarded_in','onchain_spent_txid','onchain_spent_height'))):raise ValueError('original physical Board root differs')
    original=points[origin['vtxo_id']]
    if original['amount']!=origin['net_liability_sat'] or original.get('policy')!='00'+origin['user_pubkey']:raise ValueError('original signed ordinary input differs')
    pending=[origin['vtxo_id']];visited={origin['anchor']};leaves={};branches=set()
    while pending:
        point=pending.pop()
        if point in visited or point not in points:raise ValueError('cycle/shared or missing ordinary graph node')
        visited.add(point);coin=points[point]
        if (coin['anchor_point']!=origin['anchor'] or coin['expiry']!=origin['expiry_height']
                or coin['policy_type'] not in ('pubkey','checkpoint') or type(coin['amount']) is not int or coin['amount']<=0
                or any(coin.get(key) is not None for key in ('spent_in_round','offboarded_in','onchain_spent_txid','onchain_spent_height'))):raise ValueError('nonordinary or foreign-root server node')
        txid=coin.get('oor_spent_txid')
        if txid is None:
            if coin['spend_state']!='spendable' or coin['policy_type']!='pubkey':raise ValueError('unregistered or conditional ordinary leaf')
            leaves[point]=coin
        else:
            if coin['spend_state']!='spent' or txid in branches:raise ValueError('ordinary single-parent branch required')
            branches.add(txid);children=[identity for identity in points if identity.split(':')[0]==txid]
            if not children or sum(points[child]['amount'] for child in children)!=coin['amount']:raise ValueError('ordinary branch does not conserve liability')
            pending.extend(children)
    if visited!=set(points) or sum(coin['amount'] for coin in leaves.values())!=origin['net_liability_sat']:raise ValueError('ordinary physical root counted once; complete leaf liability required')
    recipient={point:coin for point,coin in leaves.items() if point not in send['changes']}
    if len(recipient)!=1 or sum(coin['amount'] for coin in recipient.values())!=2000:raise ValueError('one exact recipient leaf required')
    key=send['destination']['user_pubkey']
    for point,coin in leaves.items():
        expected=send['changes'].get(point,{'amount_sat':2000,'user_pubkey':key})
        if coin['amount']!=expected['amount_sat'] or coin.get('policy')!='00'+expected['user_pubkey']:raise ValueError('actual leaf owner/policy differs')
    keys={origin['user_pubkey']:origin['binding'],key:send['destination']['binding']}
    keys.update({item['user_pubkey']:item['proof']['binding'] for item in send['changes'].values()})
    expected_links=[{'user_pubkey':pubkey,'mailbox_pk':bound['mailbox_pk'],'child_index':bound['child_index']} for pubkey,bound in keys.items()]
    for name in ('links','journal_links'):
        expected=list(prior['rows'][name])+[link for link in expected_links if link not in prior['rows'][name]]
        if sorted(rows[name],key=canonical)!=sorted(expected,key=canonical):raise ValueError('ordinary native owner links differ')
    if rows['pending_boards'] not in ([],[{'vtxo_id':origin['vtxo_id'],'expiry':origin['expiry_height']}]):raise ValueError('foreign pending Board')
    return {'recipient_coins':list(recipient),'change_coins':list(send['changes']),'liability_sat':origin['net_liability_sat'],'physical_anchor_count':1}


def _native(store,config,origin,height):
    send=_send(store,origin)
    if send is None:
        result=backing._client_state(store,config,origin,height)
        if (result['actor-01']['state']!='Spendable' or result['actor-01']['checkpoint_count']!=0
                or result['actor-01']['movement_status']!='successful'):raise ValueError('original Board must be fully adopted before ordinary journey')
        return result
    from .identity_bootstrap import declaration,_context,_root,_sole_writer
    original=declaration(store);value=original['declaration'];_context(config,value);_sole_writer(value['wallet_root'])
    if (value['pins']!=origin['financial_pins'] or _root(value['wallet_root'])!=original['filesystem']
            or any(key.startswith('BARK_') for key in os.environ)):raise ValueError('same private sole-writer native context required')
    if origin['expiry_height']<=height+origin['exit_margin']+6:raise ValueError('ordinary Board near expiry')
    result={}
    for actor in value['actors']:
        path=Path(value['wallet_root'])/actor/'db.sqlite'
        if any(stat.S_ISLNK(part.lstat().st_mode) for part in (path,*path.parents)):raise ValueError('native SQLite symlink')
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError('actual private native SQLite required')
        conn=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=2);conn.row_factory=sqlite3.Row
        conn.execute('PRAGMA query_only=ON');started=time.monotonic();conn.set_progress_handler(lambda:time.monotonic()-started>5,1000)
        try:
            conn.execute('BEGIN');tables={row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'bark_%'")}
            if conn.execute('SELECT max(value) FROM migrations').fetchone()[0]!=43 or not ECONOMIC_TABLES<=tables or len(tables)>64:raise ValueError('pinned complete native schema required')
            allowed={'bark_vtxo','bark_vtxo_state','bark_movements','bark_movements_output_vtxos',
                'bark_movements_input_vtxos','bark_movements_sent_to','bark_movements_received_on'} if actor!='actor-04' else set()
            counts={}
            for table in sorted(tables):
                if re.fullmatch('bark_[a-z_]+',table) is None:raise ValueError('unknown native economic table')
                count=conn.execute('SELECT count(*) FROM '+table).fetchone()[0];counts[table]=count
                if (table not in allowed|METADATA_TABLES and count!=0 or table in METADATA_TABLES and count>128
                        or table in allowed and count>64):raise ValueError('unrelated native monetary state or checkpoint')
            if actor=='actor-04':result[actor]={'counts':counts};continue
            coins={row['id']:dict(row) for row in conn.execute('SELECT id,amount_sat,expiry_height FROM bark_vtxo')}
            expected={point:item['amount_sat'] for point,item in send['changes'].items()} if actor=='actor-01' else {}
            if actor=='actor-01':expected[origin['vtxo_id']]=origin['net_liability_sat']
            else:
                for point,coin in coins.items():
                    signed=_signed_coin(store,point,actor)
                    if signed is None:raise ValueError('recipient native coin lacks independent signed proof')
                    owned,proof=signed
                    if (proof.get('financial_pins')!=plan(store)['pins'] or proof.get('conditional_steps')!=0
                            or proof.get('chain_anchor')!=origin['anchor'] or proof.get('expiry_height')!=origin['expiry_height']
                            or owned['pubkey']!=send['destination']['user_pubkey'] or _receipt_origin(proof,{origin['vtxo_id']}) is None):raise ValueError('recipient ordinary signed path differs')
                    expected[point]=owned['amount_sat']
                if expected and (len(expected)!=1 or sum(expected.values())!=2000):raise ValueError('recipient signed amount differs')
            if set(coins)!=set(expected) or any((coin['amount_sat'],coin['expiry_height'])!=(expected[point],origin['expiry_height']) for point,coin in coins.items()):raise ValueError('native ordinary coins differ')
            states={}
            for row in conn.execute('SELECT vtxo_id,state_kind FROM bark_vtxo_state ORDER BY id'):
                if row['vtxo_id'] not in expected or row['state_kind'] not in ('Locked','Spendable','Spent'):raise ValueError('native ordinary state differs')
                states[row['vtxo_id']]=row['state_kind']
            wanted={point:('Spent' if point==origin['vtxo_id'] else 'Spendable') for point in expected}
            if states!=wanted:raise ValueError('native ordinary terminal state differs')
            movements=[dict(row) for row in conn.execute('SELECT id,status,subsystem_name,effective_balance,offchain_fee FROM bark_movements')]
            required=[(str(origin['movement_id']),'bark.board',origin['net_liability_sat'],origin['service_charge_sat']),
                (send['movement_id'],'bark.arkoor',-2000,0)] if actor=='actor-01' else []
            if actor=='actor-02' and expected:
                if len(movements)!=1:raise ValueError('one recipient adoption movement required')
                required=[(str(movements[0]['id']),'bark.arkoor',2000,0)]
            observed=[(str(row['id']),row['subsystem_name'],row['effective_balance'],row['offchain_fee']) for row in movements]
            if sorted(observed)!=sorted(required) or any(row['status']!='successful' for row in movements):raise ValueError('native ordinary movement differs')
            edges={(str(row[0]),row[1]) for row in conn.execute('SELECT movement_id,vtxo_id FROM bark_movements_output_vtxos')}
            wanted_edges={(str(origin['movement_id']),origin['vtxo_id'])}|{(send['movement_id'],point) for point in send['changes']} if actor=='actor-01' else ({(required[0][0],point) for point in expected} if expected else set())
            inputs={(str(row[0]),row[1]) for row in conn.execute('SELECT movement_id,vtxo_id FROM bark_movements_input_vtxos')}
            if edges!=wanted_edges or inputs!=({(send['movement_id'],origin['vtxo_id'])} if actor=='actor-01' else set()):raise ValueError('native ordinary movement edges differ')
            result[actor]={'counts':counts,'states':states,'spendable_sat':sum(expected[point] for point in expected if states[point]=='Spendable'),
                'recipient_adopted':bool(expected) if actor=='actor-02' else False}
        finally:conn.close()
    return result


async def collect_ordinary_sources(store,config,chain,bank_rpc,*,cash_source_sequence,current_startup_path):
    value=plan(store);before_step,_=_history(store,backing._origin(store,chain),allow_queued=True)
    source=await backing._collect_backing_sources(store,config,chain,bank_rpc,
        cash_source_sequence=cash_source_sequence,current_startup_path=current_startup_path,
        history_validator=lambda store,origin:_history(store,origin,allow_queued=True),client_validator=_native,
        database_validator=lambda database,prior,origin:_server(database,prior,origin,store),source_kind='ordinary_arkoor_backing_sources_verified')
    # No receipt is emitted until all fixed native adoption steps have completed.
    after_step,_=_history(store,source['source']['origin'],allow_queued=True)
    if after_step!=before_step:raise ValueError('ordinary phase changed during source observation')
    public={**source['source'],'backing_source_sequence':source['source_sequence'],'ordinary_plan_id':value['id'],'ordinary_step':after_step}
    store.event(KIND,public)
    return {'source_sequence':store.db.execute('SELECT max(sequence) FROM event').fetchone()[0],'source':public}


def validate_ordinary_scope(store,config,proof,*,operation,maximum_fee_sat,reserved_action_id):
    value=plan(store);scope=proof.get('ordinary_arkoor_scope')
    if (not isinstance(scope,dict) or set(scope)!={'plan_id','step','action_id','source_sequence'} or scope['plan_id']!=value['id']
            or scope['step'] not in STEPS or scope['action_id']!=value['actions'][scope['step']]
            or any(key in proof for key in ('board_adoption_scope','board_action_scope','client_action_scope'))
            or type(maximum_fee_sat) is not int or maximum_fee_sat!=0):raise ValueError('exact ordinary action scope required')
    event,source=_source_event(store,scope['source_sequence']);origin=source['origin']
    if (event['kind']!=KIND or source.get('complete') is not True or source.get('ordinary_plan_id')!=value['id']
            or source.get('ordinary_step')!=scope['step'] or proof.get('financial_pins')!=value['pins']
            or source['financial_pins']!=value['pins'] or source['boundary_id']!=value['boundary_id']
            or proof.get('boundary_id')!=value['boundary_id'] or (proof.get('height'),proof.get('tip_hash'))!=(source['height'],source['tip_hash'])):
        raise ValueError('original ordinary source context differs')
    _fresh(source['observed_at']);step,destination=_history(store,origin,reserved_action_id,allow_queued=reserved_action_id is None)
    if step!=scope['step']:raise ValueError('ordinary scope consumed or wrong serial step')
    actor,expected_operation,args=_expected(value,step,destination)
    if operation!=expected_operation or proof.get('operation_scope')!=[operation]:raise ValueError('ordinary operation differs')
    _native(store,config,origin,source['height'])
    if reserved_action_id is not None:
        row=store.db.execute('SELECT * FROM action WHERE id=?',(reserved_action_id,)).fetchone()
        if (reserved_action_id!=scope['action_id'] or row is None or row['actor_id']!=actor or row['operation']!=operation
                or row['state']!='dispatched' or json.loads(row['args'])!=args or row['fee_reservation_sat']!=0):raise ValueError('original exact ordinary dispatched action required')
        _action_pins(store,reserved_action_id,value['pins'])
    if step=='send':
        if not store.online('actor-02') or not store.ordinary_actor_available('actor-02'):raise ValueError('ordinary recipient must be online and available')
        if store.db.execute("SELECT 1 FROM action WHERE actor_id='actor-02' AND state IN ('queued','dispatched','outcome_unknown')").fetchone():raise ValueError('ordinary recipient has unresolved action')


def record_ordinary_readiness(store,config,chain,*,source_sequence,runtime_source_sequence,current_startup_path):
    _,source=_source_event(store,source_sequence);value=plan(store)
    step,destination=_history(store,source['origin'],allow_queued=True)
    if step is None:raise ValueError('ordinary plan complete; no further action admitted')
    _,operation,_=_expected(value,step,destination)
    scope={'ordinary_arkoor_scope':{'plan_id':value['id'],'step':step,'action_id':value['actions'][step],'source_sequence':source_sequence}}
    receipt=backing._record_backing_readiness(store,config,chain,source_sequence=source_sequence,
        runtime_source_sequence=runtime_source_sequence,current_startup_path=current_startup_path,source_kind=KIND,
        history_validator=lambda store,origin:_history(store,origin,allow_queued=True),client_validator=_native,
        allowed_operations=[operation],action_scope=scope,scope_validator=validate_ordinary_scope,
        scope_description='one exact serial ordinary journey action; pinned native zero-fee guard before signing; no further sends or unsupported rails')
    return receipt


def record_ordinary_journey(store,config,chain,*,source_sequence):
    """Require actual sender/recipient observations and the existing receipt ledger."""
    event,source=_source_event(store,source_sequence);value=plan(store)
    if (event['kind']!=KIND or source.get('complete') is not True or source.get('ordinary_plan_id')!=value['id']
            or source.get('ordinary_step') is not None or source.get('financial_pins')!=value['pins']
            or source.get('boundary_id')!=value['boundary_id']):raise ValueError('actual complete ordinary source required')
    _fresh(source['observed_at']);origin=backing._origin(store,chain)
    if source['origin']!=origin or _history(store,origin)[0] is not None:raise ValueError('all original ordinary steps must complete at unchanged origin')
    native=_native(store,config,origin,source['height']);send=_send(store,origin)
    if (native['actor-01']['spendable_sat']!=origin['net_liability_sat']-2000
            or native['actor-02']['spendable_sat']!=2000 or native['actor-02']['recipient_adopted'] is not True
            or source['server'].get('physical_anchor_count')!=1 or source['server'].get('liability_sat')!=origin['net_liability_sat']):raise ValueError('actual adopted ordinary conservation required')
    physical=source['physical_assets']
    if (source['physical_total_sat']!=665454-origin['funding_fee_sat']-origin['mining_fee_sat']
            or sum(item['amount_sat'] for item in physical.values())!=source['physical_total_sat']
            or physical.get(origin['anchor'],{}).get('amount_sat')!=20000):raise ValueError('complete physical capital and single anchor conservation required')
    txid,index=origin['anchor'].rsplit(':',1);actual=chain.call('gettxout',txid,int(index),True)
    from .model import btc_to_sat
    if (actual is None or actual.get('confirmations',0)<1 or btc_to_sat(actual['value'])!=20000
            or actual.get('scriptPubKey',{}).get('hex')!=physical[origin['anchor']]['script']):raise ValueError('actual original backing unavailable')
    for actor,step in (('actor-01','sender_snapshot'),('actor-02','receiver_snapshot')):
        row=store.db.execute('SELECT * FROM action WHERE id=?',(value['actions'][step],)).fetchone()
        snapshot_event,data=_response(store,row);coins=data.get('evidence',{}).get('coins',[])
        expected=native[actor]['states']
        if len(coins)!=len(expected) or {coin.get('id') for coin in coins}!=set(expected):raise ValueError('actual final native snapshot inventory required')
        for coin in coins:
            signed=_signed_coin(store,coin['id'],actor)
            if (signed is None or coin.get('state')!=expected[coin['id']] or coin.get('amount_sat')!=signed[0]['amount_sat']
                    or coin.get('user_pubkey')!=signed[0]['pubkey']
                    or hashlib.sha256(bytes.fromhex(coin['signed_vtxo'])).hexdigest()!=signed[0]['signed_hash']):raise ValueError('actual final native signed snapshot differs')
        if snapshot_event['sequence']<=send['response_sequence']:raise ValueError('original snapshots must follow send')
    tip=chain.identity()
    if (tip.get('initialblockdownload') is not False or (tip['blocks'],tip['bestblockhash'])!=(source['height'],source['tip_hash'])):raise ValueError('ordinary terminal tip changed')
    collect_ark_receipts(store)
    receipt_event,receipt=backing._unique(store,'ark_transfer_verified',value['actions']['send'])
    if (receipt['sender_actor']!='actor-01' or receipt['recipient_actor']!='actor-02' or receipt['amount_sat']!=2000
            or receipt['input_coin_ids']!=[origin['vtxo_id']] or receipt['destination']!=send['destination']['address']
            or {item['coin_id'] for item in receipt['receipts']}!=set(source['server']['recipient_coins'])):raise ValueError('original signed recipient receipt differs')
    from .final_campaign import _recipient_pins
    _recipient_pins(store,'actor-02',source['server']['recipient_coins'],value['pins'])
    result={'financial_pins':value['pins'],'boundary_id':value['boundary_id'],'plan_id':value['id'],
        'action_id':send['action_id'],'source_sequence':source_sequence,'ark_transfer_sequence':receipt_event['sequence'],
        'sender_actor':'actor-01','recipient_actor':'actor-02','amount_sat':2000,'miner_fee_sat':0,'internal_service_fee_sat':0,
        'sender_change_sat':origin['net_liability_sat']-2000,'net_liability_sat':origin['net_liability_sat'],
        'original_board_internal_service_sat':origin['service_charge_sat'],
        'physical_anchor':origin['anchor'],'physical_anchor_sat':20000,'physical_anchor_count':1,
        'physical_total_sat':source['physical_total_sat'],'observed_at':source['observed_at'],
        'scope':'one original ordinary signed transfer and actual adopted children; no full campaign or conditional/LN/exit qualification'}
    rows=store.db.execute("SELECT sequence FROM event WHERE kind='ordinary_arkoor_journey_verified'").fetchall()
    if rows:
        if len(rows)!=1:raise ValueError('ambiguous ordinary journey receipt')
        _,old=_source_event(store,rows[0][0])
        if any(old.get(key)!=result[key] for key in result if key not in ('source_sequence','observed_at')):raise ValueError('ordinary receipt changed')
        return {'sequence':rows[0][0],**old}
    public_payload(result);store.event('ordinary_arkoor_journey_verified',result)
    return {'sequence':store.db.execute('SELECT max(sequence) FROM event').fetchone()[0],**result}

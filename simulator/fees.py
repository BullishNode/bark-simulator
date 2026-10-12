"""Reconcile customer costs from frozen intents, signed coins and confirmed Core.

Service charges and mining fees are kept separate. Unsupported or incomplete
operation evidence remains reserved, including uncertain broadcasts.
"""
import asyncio, json
from .model import InvariantError, canonical, integer
from .ownership import EvidenceGap

def _proposal(store, action, kind):
    rows = store.db.execute("""SELECT payload FROM event WHERE kind='driver_evidence'
        AND json_extract(payload,'$.action_id')=? AND json_extract(payload,'$.event')=?""",
        (action['id'], kind)).fetchall()
    if len(rows) != 1:
        raise EvidenceGap('cost lacks a unique frozen proposal')
    return json.loads(rows[0]['payload'])['data']

def _owned(store, actor, ids):
    if len(ids) != len(set(ids)):
        raise InvariantError('duplicate coin in cost evidence')
    coins = []
    for coin_id in ids:
        coin = store.db.execute('''SELECT c.*,k.actor FROM owned_coin c
            JOIN owner_key k ON k.pubkey=c.pubkey WHERE c.id=?''', (coin_id,)).fetchone()
        if coin is None:
            raise EvidenceGap('cost awaits independent signed coin verification')
        if coin['actor'] != actor:
            raise InvariantError('cost evidence belongs to a different owner')
        integer(coin['amount_sat'], 'signed coin amount', 1)
        coins.append(coin)
    return coins

def movement_fee(store, action):
    """Close successful round/send costs using frozen intents and signed values.

    Failed/pending sends remain reserved: neither silence nor a local failed
    movement proves the terminal refund charge. No client is opened here.
    """
    operation, actor = action['operation'], action['actor_id']
    data = json.loads(action['result'])['data']
    if operation in {'refresh','refresh_delegated'}:
        proposal = _proposal(store, action, 'refresh_proposal')
        participation = proposal['participation']
        input_ids = []
        for signed in participation['inputs']:
            rows = store.db.execute('SELECT id FROM owned_coin WHERE signed_vtxo=?', (signed,)).fetchall()
            if len(rows) != 1:
                raise EvidenceGap('frozen refresh input awaits unique signed proof')
            input_ids.append(rows[0]['id'])
        subsystem, payment_hash = 'bark.round', None
    elif operation == 'pay_invoice':
        if (data.get('payment_state') != 'succeeded'
                or data.get('payment_status_verified') is not True):
            raise EvidenceGap('send lacks independently verified terminal success')
        proposal = _proposal(store, action, 'lightning_proposal')
        payment_hash = proposal['payment_hash']
        if data.get('payment_hash') != payment_hash:
            raise InvariantError('send cost differs from frozen payment hash')
        input_ids = proposal['input_vtxo_ids']
        subsystem = 'bark.lightning_send'
    else:
        raise EvidenceGap('unsupported movement cost')
    if not input_ids:
        raise EvidenceGap('movement has no signed principal inputs')
    inputs = _owned(store, actor, input_ids)
    candidates = []
    for row in store.db.execute('SELECT payload FROM movement_evidence WHERE actor=?', (actor,)):
        movement = json.loads(row['payload'])
        if (movement['subsystem'] == subsystem and movement['status'] == 'successful'
                and movement.get('payment_hash') == payment_hash
                and sorted(movement['input_vtxos']) == sorted(input_ids)):
            candidates.append(movement)
    if not candidates:
        raise EvidenceGap('successful matching movement not observed yet')
    if len(candidates) != 1:
        raise InvariantError('multiple successful movements consume the same cost inputs')
    movement = candidates[0]
    claimed = store.db.execute("""SELECT json_extract(payload,'$.action_id') FROM event
        WHERE kind='client_fee_reconciled' AND json_extract(payload,'$.actor')=?
        AND json_extract(payload,'$.movement_id')=?""", (actor,movement['id'])).fetchall()
    if any(row[0] != action['id'] for row in claimed):
        raise InvariantError('successful movement already assigned to another action')
    outputs = _owned(store, actor, movement['output_vtxos'])
    gross = sum(c['amount_sat'] for c in inputs)
    net = sum(c['amount_sat'] for c in outputs)
    if operation in {'refresh','refresh_delegated'}:
        expected = []
        for output in participation['outputs']:
            policy = output['policy']
            if not isinstance(policy,str) or len(policy)!=68 or not policy.startswith('00'):
                raise EvidenceGap('refresh output policy not a supported pubkey encoding')
            expected.append((policy[2:],integer(output['amount'],'frozen round amount',1)))
        if sorted(expected) != sorted((c['pubkey'],c['amount_sat']) for c in outputs):
            raise InvariantError('successful round outputs differ from frozen keys or amounts')
        cost = gross - net
        if cost != proposal['committed_fee_sat'] or cost != data['committed_fee_sat']:
            raise InvariantError('round cost differs from frozen charge')
        transferred = 0
    else:
        transferred = integer(proposal['amount_sat'],'frozen Lightning amount',1)
        cost = gross - net - transferred
        if cost > integer(proposal['fee_ceiling_sat'],'frozen send fee ceiling'):
            raise InvariantError('actual send cost exceeds frozen ceiling')
        if data.get('committed_fee_sat') is not None and cost != data['committed_fee_sat']:
            raise InvariantError('send cost differs from SDK checkpoint charge')
    if (cost < 0 or cost != movement['offchain_fee_sat']
            or cost > action['fee_reservation_sat']):
        raise InvariantError('movement cost does not conserve signed values or exceeds reserve')
    return {'actor':actor,'movement_id':movement['id'],'input_coin_ids':input_ids,
        'output_coin_ids':movement['output_vtxos'],'signed_input_sat':gross,
        'signed_output_sat':net,'transferred_sat':transferred,'actual_fee_sat':cost,
        'scope':'customer charge from frozen intent and independently verified signed coin values; no operator mining fee attributed'}

def receive_fee(store,action):
    """Assign only newly completed receives inside a frozen sync boundary.

    Invoice-time prices are estimates; actual claims obey the sync reservation.
    Every claim must match its original invoice and independently owned signed
    outputs. Partial/unproven claims retain the whole reservation. No absent
    wallet is opened and the same movement cannot be charged twice.
    """
    actor=action['actor_id'];data=json.loads(action['result'])['data']
    count=integer(data['receive_count_before'],'pending receive count')
    if not count or data['receive_count_after']!=0:raise EvidenceGap('receive claims not completely resolved')
    before={m['id'] for m in data['before_evidence']['movements'] if m.get('status')=='successful'}
    after=[m for m in data['evidence']['movements'] if m.get('subsystem')=='bark.lightning_receive'
        and m.get('status')=='successful' and m['id'] not in before]
    if len(after)!=count:raise EvidenceGap('sync boundary does not prove every claim completion')
    if len({m['id'] for m in after})!=len(after):raise InvariantError('receive sync repeats a movement')
    total=0;claims=[]
    for movement in after:
        observed=store.db.execute('SELECT payload FROM movement_evidence WHERE actor=? AND movement_id=?',(actor,movement['id'])).fetchone()
        if observed is None:raise EvidenceGap('receive movement awaits independent inventory')
        if canonical(json.loads(observed[0]))!=canonical(movement):raise EvidenceGap('receive movement is not the independently recorded completed boundary')
        if movement['input_vtxos']:raise InvariantError('receive movement unexpectedly consumes customer inputs')
        outputs=_owned(store,actor,movement['output_vtxos'])
        if not outputs:raise EvidenceGap('receive lacks signed output proof')
        net=sum(c['amount_sat'] for c in outputs)
        if net!=movement['effective_balance_sat']:raise InvariantError('receive signed value differs from movement')
        invoices=store.db.execute("""SELECT id,args,result FROM action WHERE actor_id=? AND operation='invoice'
            AND state='completed' AND json_extract(result,'$.data.payment_hash')=?""",(actor,movement.get('payment_hash'))).fetchall()
        if len(invoices)!=1:raise EvidenceGap('receive lacks unique frozen invoice')
        invoice=invoices[0];principal=integer(json.loads(invoice['args'])['amount_sat'],'frozen invoice principal',1)
        fee=principal-net;ceiling=integer(json.loads(invoice['result'])['data']['estimated_claim_fee_sat'],'frozen receive quote')
        if fee<0 or fee!=movement['offchain_fee_sat']:raise InvariantError('receive principal or charge differs from frozen invoice')
        for row in store.db.execute("SELECT payload FROM event WHERE kind='client_fee_reconciled' AND json_extract(payload,'$.actor')=?",(actor,)):
            prior=json.loads(row[0])
            if movement['id'] in prior.get('receive_movement_ids',[]) and prior['action_id']!=action['id']:
                raise InvariantError('receive claim assigned to another sync')
        total+=fee;claims.append({'movement_id':movement['id'],'invoice_action_id':invoice['id'],'payment_hash':movement['payment_hash'],
            'principal_sat':principal,'signed_output_sat':net,'service_charge_sat':fee,'invoice_estimated_charge_sat':ceiling,'invoice_estimate_variance_sat':fee-ceiling,'output_coin_ids':movement['output_vtxos']})
    if total>action['fee_reservation_sat']:raise InvariantError('receive charges exceed sync fee reservation')
    return {'actor':actor,'receive_movement_ids':[c['movement_id'] for c in claims],'claims':claims,'actual_fee_sat':total,
        'scope':'new completed claims between frozen native sync boundaries; original invoice and signed ownership/value proof; no operator fee attribution'}

def board_fee(store, action, tx):
    data=json.loads(action['result'])['data'];board=data['board']
    ids=board['vtxos']
    if len(ids)!=1:raise EvidenceGap('multi-output board fee qualification not implemented')
    coin=store.db.execute('SELECT c.*,k.actor FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey WHERE c.id=?',(ids[0],)).fetchone()
    if coin is None:raise EvidenceGap('board lacks independent signed ownership proof')
    if coin['actor']!=action['actor_id']:raise InvariantError('board fee evidence belongs to another actor')
    proof=json.loads(coin['proof']);txid,index=proof['chain_anchor'].split(':')
    if tx['txid']!=txid:raise InvariantError('board fee transaction differs from signed anchor')
    if tx.get('confirmations',0)<1:raise EvidenceGap('board funding is not confirmed')
    outputs=[o for o in tx['outputs'] if o['vout']==int(index)]
    if len(outputs)!=1:raise InvariantError('board anchor output missing')
    funded=integer(json.loads(action['args'])['amount_sat'],'board funded amount',1)
    if outputs[0]['amount_sat']!=funded:raise InvariantError('actual board funding differs from request')
    service=funded-coin['amount_sat']
    if service<0 or service!=data['sdk_service_fee_sat']:raise InvariantError('signed board service charge differs from SDK result')
    mining=integer(tx['fee_sat'],'actual board mining fee')
    total=service+mining
    if total>action['fee_reservation_sat']:raise InvariantError('actual board cost exceeds declared reserve')
    return {'txid':txid,'coin_id':ids[0],'mining_fee_sat':mining,'service_charge_sat':service,'actual_fee_sat':total,
        'scope':'confirmed Core input/output fee and signed board amount; service charge is not a mining fee'}

def offboard_fee(store,action,tx):
    data=json.loads(action['result'])['data']
    rows=store.db.execute("SELECT payload FROM event WHERE kind='driver_evidence' AND json_extract(payload,'$.action_id')=? AND json_extract(payload,'$.event')='offboard_proposal'",(action['id'],)).fetchall()
    if len(rows)!=1:raise EvidenceGap('offboard has no unique frozen proposal')
    proposal=json.loads(rows[0]['payload'])['data']
    if tx.get('confirmations',0)<1:raise EvidenceGap('offboard is not confirmed')
    if tx['txid']!=data.get('txid'):raise InvariantError('offboard confirmation has another transaction id')
    if proposal['action_id']!=data['offboard_action_id'] or proposal['destination_script']!=data['destination_script']:
        raise InvariantError('offboard outcome differs from frozen intent')
    ids=proposal['input_vtxo_ids']
    if not ids or len(ids)!=len(set(ids)):raise InvariantError('offboard inputs are empty or duplicated')
    gross=0
    for coin_id in ids:
        coin=store.db.execute('SELECT c.amount_sat,k.actor FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey WHERE c.id=?',(coin_id,)).fetchone()
        if coin is None:raise EvidenceGap('offboard input has no signed ownership proof')
        if coin['actor']!=action['actor_id']:raise InvariantError('offboard input belongs to another actor')
        gross+=integer(coin['amount_sat'],'signed offboard principal',1)
    net=integer(proposal['net_sat'],'offboard net',1)
    fee=gross-net
    if fee<0 or fee!=proposal['committed_fee_sat'] or fee!=data['committed_fee_sat']:
        raise InvariantError('offboard principal and fee do not conserve the frozen amount')
    if fee>action['fee_reservation_sat']:raise InvariantError('offboard fee exceeds declared reserve')
    outputs=[o for o in tx['outputs'] if o['script']==proposal['destination_script']]
    if len(outputs)!=1 or outputs[0]['amount_sat']!=net:raise InvariantError('offboard did not pay its intended net output')
    return {'txid':tx['txid'],'coin_ids':ids,'signed_principal_sat':gross,'net_sat':net,'actual_fee_sat':fee,
        'confirmed_transaction_mining_fee_sat':integer(tx['fee_sat'],'collaborative transaction mining fee'),
        'scope':'customer charge from signed inputs minus frozen confirmed output; whole transaction mining fee is reported separately, without assigning it all to this customer'}

async def collect(store,chain,limit=4):
    rows=store.db.execute("SELECT * FROM action WHERE operation='board' AND state='completed' AND actual_fee_sat IS NULL ORDER BY id").fetchall()
    after=store.get_meta('board_fee_cursor') or ''
    rows=[r for r in rows if r['id']>after]+[r for r in rows if r['id']<=after]
    for action in rows[:limit]:
        try:
            ids=json.loads(action['result'])['data']['board']['vtxos']
            if len(ids)!=1:raise EvidenceGap('unsupported multi-output board')
            coin=store.db.execute('SELECT proof FROM owned_coin WHERE id=?',(ids[0],)).fetchone()
            if coin is None:raise EvidenceGap('signed board not verified yet')
            txid=json.loads(coin['proof'])['chain_anchor'].split(':')[0]
            await asyncio.to_thread(chain.identity)
            tx=await asyncio.to_thread(chain.transaction,txid)
            evidence=board_fee(store,action,tx)
            with store.transaction():
                store.db.execute('UPDATE action SET actual_fee_sat=? WHERE id=? AND actual_fee_sat IS NULL',(evidence['actual_fee_sat'],action['id']))
                store._event('client_fee_reconciled',{'action_id':action['id'],**evidence,'chain_transaction':tx})
        except InvariantError:raise
        except (EvidenceGap,KeyError,TypeError,ValueError):pass
        except Exception:pass # Transport failures never release the reservation.
        store.db.execute("INSERT OR REPLACE INTO meta VALUES ('board_fee_cursor',?)",(action['id'],))
    rows=store.db.execute("SELECT * FROM action WHERE operation='offboard_all' AND state='completed' AND actual_fee_sat IS NULL ORDER BY id").fetchall()
    after=store.get_meta('offboard_fee_cursor') or ''
    rows=[r for r in rows if r['id']>after]+[r for r in rows if r['id']<=after]
    for action in rows[:limit]:
        try:
            txid=json.loads(action['result'])['data'].get('txid')
            if not txid:raise EvidenceGap('offboard transaction outcome is still unknown')
            await asyncio.to_thread(chain.identity)
            tx=await asyncio.to_thread(chain.transaction,txid)
            evidence=offboard_fee(store,action,tx)
            with store.transaction():
                store.db.execute('UPDATE action SET actual_fee_sat=? WHERE id=? AND actual_fee_sat IS NULL',(evidence['actual_fee_sat'],action['id']))
                store._event('client_fee_reconciled',{'action_id':action['id'],**evidence,'chain_transaction':tx})
        except InvariantError:raise
        except (EvidenceGap,KeyError,TypeError,ValueError):pass
        except Exception:pass
        store.db.execute("INSERT OR REPLACE INTO meta VALUES ('offboard_fee_cursor',?)",(action['id'],))
    rows=store.db.execute("""SELECT * FROM action WHERE operation IN
        ('refresh','refresh_delegated','pay_invoice','sync') AND state='completed'
        AND actual_fee_sat IS NULL ORDER BY id""").fetchall()
    after=store.get_meta('movement_fee_cursor') or ''
    rows=[r for r in rows if r['id']>after]+[r for r in rows if r['id']<=after]
    for action in rows[:limit]:
        try:
            evidence=receive_fee(store,action) if action['operation']=='sync' else movement_fee(store,action)
            with store.transaction():
                changed=store.db.execute('UPDATE action SET actual_fee_sat=? WHERE id=? AND actual_fee_sat IS NULL',
                    (evidence['actual_fee_sat'],action['id'])).rowcount
                if changed:
                    store._event('client_fee_reconciled',{'action_id':action['id'],**evidence})
        except InvariantError:raise
        except (EvidenceGap,KeyError,TypeError,ValueError):pass
        store.db.execute("INSERT OR REPLACE INTO meta VALUES ('movement_fee_cursor',?)",(action['id'],))

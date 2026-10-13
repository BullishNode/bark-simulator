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
    if operation in {'refresh','refresh_delegated','refresh_scheduled'}:
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
    if operation in {'refresh','refresh_delegated','refresh_scheduled'}:
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

def _receive_hashes(data):
    """Optional public native pending identities; never infer a missing half."""
    fields = ('receive_payment_hashes_before', 'receive_payment_hashes_after')
    if not any(field in data for field in fields):return None
    result = []
    for field, count_field in zip(fields, ('receive_count_before','receive_count_after')):
        hashes = data[field]
        if (not isinstance(hashes,list) or any(not isinstance(h,str) or len(h)!=64
                or any(c not in '0123456789abcdef' for c in h) for h in hashes)
                or len(set(hashes)) != len(hashes) or len(hashes) != data[count_field]):
            raise EvidenceGap('pending receive identities do not match native count')
        result.append(set(hashes))
    return result

def receive_fee(store,action):
    """Assign only newly completed receives inside a frozen sync boundary.

    Invoice-time prices are estimates; actual claims obey the sync reservation.
    Every claim must match its original invoice and independently owned signed
    outputs. Partial/unproven claims retain the whole reservation. No absent
    wallet is opened and the same movement cannot be charged twice.
    """
    actor=action['actor_id'];data=json.loads(action['result'])['data']
    count=integer(data['receive_count_before'],'pending receive count')
    hashes = _receive_hashes(data)
    args=json.loads(action['args']);target=args.get('receive_payment_hash')
    if target is not None:
        intents=store.db.execute("SELECT payload FROM event WHERE kind='action_intent' AND json_extract(payload,'$.action_id')=?",(action['id'],)).fetchall()
        if len(intents)!=1 or json.loads(intents[0][0]).get('args')!=args:
            raise InvariantError('targeted receive differs from frozen action intent')
        if (not isinstance(target,str) or len(target)!=64
                or any(c not in '0123456789abcdef' for c in target)):
            raise InvariantError('frozen receive target is malformed')
        if (data.get('bounded_receive_sync') is not True or hashes is None
                or ('target_receive_terminal' in data and data['target_receive_terminal'] is not True)
                or data.get('receive_canceled_payment_hashes',[])!=[]
                or data.get('selected_receive_payment_hashes')!=[target]
                or target not in hashes[0] or hashes[1]!=hashes[0]-{target}):
            raise EvidenceGap('targeted receive boundary is unresolved or changed unrelated checkpoints')
        before_history=_sync_movements(data['before_evidence'])
        after_history=_sync_movements(data['evidence'])
        if any(m.get('payment_hash')!=target and canonical(after_history.get(identity))!=canonical(m)
                for identity,m in before_history.items()):
            raise EvidenceGap('targeted receive changed unrelated movement history')
        if any(identity not in before_history and m.get('payment_hash')!=target
                for identity,m in after_history.items()):
            raise EvidenceGap('targeted receive has an unrelated new movement')
        count=1
    elif not count or data['receive_count_after']!=0:
        raise EvidenceGap('receive claims not completely resolved')
    before={m['id'] for m in data['before_evidence']['movements'] if m.get('status')=='successful'}
    after=[m for m in data['evidence']['movements'] if m.get('subsystem')=='bark.lightning_receive'
        and m.get('status')=='successful' and m['id'] not in before]
    if len(after)!=count:raise EvidenceGap('sync boundary does not prove every claim completion')
    if len({m['id'] for m in after})!=len(after):raise InvariantError('receive sync repeats a movement')
    expected_hashes={target} if target is not None else hashes[0] if hashes is not None else None
    if expected_hashes is not None and expected_hashes!={m['payment_hash'] for m in after}:
        raise EvidenceGap('successful claims differ from native pending identities')
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
        invoice=invoices[0]
        if target is not None and args.get('recipient_invoice_action',invoice['id'])!=invoice['id']:
            raise InvariantError('receive target differs from frozen recipient invoice')
        principal=integer(json.loads(invoice['args'])['amount_sat'],'frozen invoice principal',1)
        fee=principal-net;ceiling=integer(json.loads(invoice['result'])['data']['estimated_claim_fee_sat'],'frozen receive quote')
        if fee<0 or fee!=movement['offchain_fee_sat']:raise InvariantError('receive principal or charge differs from frozen invoice')
        for row in store.db.execute("SELECT payload FROM event WHERE kind='client_fee_reconciled' AND json_extract(payload,'$.actor')=?",(actor,)):
            prior=json.loads(row[0])
            assigned=prior.get('claims',[])
            if prior['action_id']!=action['id'] and (movement['id'] in prior.get('receive_movement_ids',[])
                    or any(c.get('payment_hash')==movement['payment_hash']
                        or c.get('invoice_action_id')==invoice['id']
                        or set(c.get('output_coin_ids',[])) & set(movement['output_vtxos']) for c in assigned)):
                raise InvariantError('receive claim assigned to another sync')
        total+=fee;claims.append({'movement_id':movement['id'],'invoice_action_id':invoice['id'],'payment_hash':movement['payment_hash'],
            'principal_sat':principal,'signed_output_sat':net,'service_charge_sat':fee,'invoice_estimated_charge_sat':ceiling,'invoice_estimate_variance_sat':fee-ceiling,'output_coin_ids':movement['output_vtxos']})
    if total>action['fee_reservation_sat']:raise InvariantError('receive charges exceed sync fee reservation')
    return {'actor':actor,'receive_movement_ids':[c['movement_id'] for c in claims],'claims':claims,'actual_fee_sat':total,
        'scope':'new completed claims between frozen native sync boundaries; original invoice and signed ownership/value proof; no operator fee attribution'}

def _sync_movements(boundary):
    movements = boundary['movements']
    by_id = {movement['id']: movement for movement in movements}
    if len(by_id) != len(movements):
        raise EvidenceGap('sync history has ambiguous movement ids')
    return by_id

def _pending_sync_release(store, action):
    """Prove an earlier unchanged sync made no receive claim of its own.

    Native history omits unclaimed invoices (the empty-invoice fixture has an
    empty history with one pending receive). Infer their hashes only when all
    prior invoice outcomes are known and their unmatched count exactly equals
    the native count. Later signed claim reconciliation must prove every hash;
    a changed history, an intervening invoice or ambiguity keeps the reserve.
    """
    actor = action['actor_id']
    data = json.loads(action['result'])['data']
    count = integer(data['receive_count_before'], 'pending receive count')
    if not count:raise EvidenceGap('earlier sync had no pending receive')
    if integer(data['receive_count_after'], 'pending receive count') != count:
        raise EvidenceGap('earlier sync changed pending receive count')
    before = _sync_movements(data['before_evidence'])
    after = _sync_movements(data['evidence'])
    if canonical(before) != canonical(after):
        raise EvidenceGap('earlier sync changed its movement history')
    native_hashes = _receive_hashes(data)
    if native_hashes is not None and native_hashes[0] != native_hashes[1]:
        raise EvidenceGap('earlier sync changed its pending receive identities')
    # Count-only legacy evidence especially needs the complete unchanged public
    # inventory. Keep the same conservative gate for explicit native identities.
    coins_before = data['before_evidence']['coins']
    coins_after = data['evidence']['coins']
    if (not isinstance(coins_before,list) or not isinstance(coins_after,list)
            or len({c['id'] for c in coins_before}) != len(coins_before)
            or canonical(sorted(coins_before,key=lambda c:c['id']))
                != canonical(sorted(coins_after,key=lambda c:c['id']))):
        raise EvidenceGap('sync changed or lacks complete coin inventory')
    completed_hashes = set()
    for movement in before.values():
        if movement['subsystem'] == 'bark.lightning_receive':
            if movement['status'] not in {'successful', 'pending'}:
                raise EvidenceGap('earlier receive history is unresolved')
            if movement['status'] == 'successful':
                completed_hashes.add(movement['payment_hash'])
    invoices = store.db.execute("""SELECT * FROM action WHERE actor_id=?
        AND operation='invoice' AND created_at<=? ORDER BY created_at,id""",
        (actor, action['created_at'])).fetchall()
    hashes = set()
    for invoice in invoices:
        if invoice['state'] != 'completed' or invoice['updated_at'] > action['created_at']:
            raise EvidenceGap('earlier invoice outcome is not frozen')
        payment_hash = json.loads(invoice['result'])['data']['payment_hash']
        if not isinstance(payment_hash, str) or len(payment_hash) != 64:
            raise EvidenceGap('invoice lacks a payment hash')
        if payment_hash in hashes:
            raise EvidenceGap('earlier invoices have ambiguous payment hashes')
        hashes.add(payment_hash)
    pending = native_hashes[0] if native_hashes is not None else hashes - completed_hashes
    if len(pending) != count:
        raise EvidenceGap('invoice history does not identify every pending receive')
    if not pending <= hashes:
        raise EvidenceGap('pending receive lacks earlier frozen invoice')
    for movement in before.values():
        if (movement['subsystem'] == 'bark.lightning_receive'
                and movement['status'] == 'pending' and movement['payment_hash'] not in pending):
            raise EvidenceGap('pending movement lacks a frozen invoice')
    proofs = store.db.execute("""SELECT * FROM action WHERE actor_id=?
        AND operation='sync' AND state='completed' AND actual_fee_sat IS NOT NULL
        AND created_at>? ORDER BY created_at,id""", (actor, action['updated_at'])).fetchall()
    for proof in proofs:
        # An invoice may not appear in movement history until it is claimed.
        # New invoices would make count-only pending identity ambiguous.
        if native_hashes is None and store.db.execute("""SELECT 1 FROM action WHERE actor_id=? AND operation='invoice'
                AND created_at>? AND created_at<=? LIMIT 1""",
                (actor, action['created_at'], proof['created_at'])).fetchone():
            continue
        try:
            evidence = receive_fee(store, proof)
            reconciled = store.db.execute("""SELECT payload FROM event
                WHERE kind='client_fee_reconciled' AND json_extract(payload,'$.action_id')=?""",
                (proof['id'],)).fetchall()
            if (len(reconciled) != 1 or proof['actual_fee_sat'] != evidence['actual_fee_sat']
                    or canonical(json.loads(reconciled[0][0])) != canonical({'action_id':proof['id'], **evidence})):
                continue
            claims = {claim['payment_hash']:claim for claim in evidence['claims']}
            if len(claims) != len(evidence['claims']) or not pending <= claims.keys():
                continue
            proof_before = _sync_movements(json.loads(proof['result'])['data']['before_evidence'])
            if any(coin_id not in proof_before or canonical(movement) != canonical(proof_before[coin_id])
                    for coin_id,movement in before.items()):
                continue
            if any(movement['subsystem'] == 'bark.lightning_receive' and movement['status'] == 'pending'
                    and claims[movement['payment_hash']]['movement_id'] != movement['id']
                    for movement in before.values()):
                continue
            return {'actor':actor,'proving_action_id':proof['id'],
                'receive_movement_ids':sorted(claims[h]['movement_id'] for h in pending),
                'payment_hashes':sorted(pending),'released_reservation_sat':action['fee_reservation_sat'],
                'actual_fee_sat':0,
                'scope':'unchanged earlier native sync; every unambiguous pending invoice proved by later independently reconciled claims; claim fees stay on proving action'}
        except (EvidenceGap,KeyError,TypeError,ValueError):
            continue
    raise EvidenceGap('no later independently reconciled sync proves all pending claims')

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
    args=json.loads(action['args'])
    funded=integer(args['amount_sat'],'board funded amount',1)
    proposal=None
    if args.get('recycle_autosize') is True:
        proposal=_proposal(store,action,'board_proposal')
        funded=integer(proposal['amount_sat'],'exact frozen board output',1)
        if proposal.get('recycle_autosize') is not True or proposal['funding_txid']!=txid:
            raise InvariantError('auto board differs from frozen exact quote')
        source=args['recycle_source']
        if (len(tx['inputs'])!=1 or any(tx['inputs'][0].get(k)!=source[k]
                for k in ('outpoint','amount_sat','script'))):
            raise InvariantError('auto board consumed other than its frozen receipt')
        if funded>integer(args['board_cap_sat'],'board output cap',1):
            raise InvariantError('auto board exceeds frozen cap')
        if coin['amount_sat']<integer(args['minimum_ark_amount_sat'],'minimum Ark principal',1):
            raise InvariantError('auto board creates below-floor Ark principal')
    if outputs[0]['amount_sat']!=funded:raise InvariantError('actual board funding differs from request')
    service=funded-coin['amount_sat']
    if service<0 or service!=data['sdk_service_fee_sat']:raise InvariantError('signed board service charge differs from SDK result')
    mining=integer(tx['fee_sat'],'actual board mining fee')
    if proposal and (service!=proposal['estimated_service_fee_sat'] or mining!=proposal['planned_mining_fee_sat']):
        raise InvariantError('confirmed auto board costs differ from pre-sign exact quote')
    total=service+mining
    if total>action['fee_reservation_sat']:raise InvariantError('actual board cost exceeds declared reserve')
    return {'txid':txid,'coin_id':ids[0],'funded_amount_sat':funded,'mining_fee_sat':mining,'service_charge_sat':service,'actual_fee_sat':total,
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
        ('refresh','refresh_delegated','refresh_scheduled','pay_invoice','sync') AND state='completed'
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
    # Also revisit older reservations whose proving sync was reconciled before
    # this release (or before a crash). Do not reassign its once-only claim cost.
    for action in rows[:limit]:
        if action['operation'] != 'sync':continue
        try:
            evidence = _pending_sync_release(store, action)
            with store.transaction():
                changed = store.db.execute("""UPDATE action SET actual_fee_sat=0
                    WHERE id=? AND state='completed' AND actual_fee_sat IS NULL""", (action['id'],)).rowcount
                if changed:
                    store._event('fee_reservation_released', {'action_id':action['id'], **evidence})
        except InvariantError:raise
        except (EvidenceGap,KeyError,TypeError,ValueError):pass

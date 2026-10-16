"""First normal financial opening after preserved, closed exploratory work.

This binds independently qualified opening evidence; it is not a producer of
financial readiness. Incomplete inventories, costs or liabilities stay blocked.
Original declarations, actions, expiry contracts and fee limits are never edited.
"""
import hashlib
import json
import time

from .model import canonical, integer, public_payload
from .final_campaign import _pins, _source_event

KEY = 'preserved_financial_opening'


def _digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def history(store):
    """The exact terminal history carried into a first financial opening."""
    from .exploratory import KEY as exploratory_key, scope
    from .target_epochs import declaration_hashes
    if not store.get_meta('paused') or scope(store) is not None:
        raise ValueError('closed exploratory scopes and paused dispatch required')
    if store.get_meta('qualified_campaign_active_seconds') not in (None, '0'):
        raise ValueError('preserve previous qualified time')
    if store.get_meta('final_financial_epoch') is not None:
        raise ValueError('opening must precede a final financial epoch')
    actions = [dict(row) for row in store.db.execute('SELECT * FROM action ORDER BY id')]
    if not actions or len(actions) > 10000:
        raise ValueError('bounded original exploratory action history required')
    if any(row['state'] not in {'completed', 'failed', 'expected_refusal', 'blocked', 'canceled'}
           or row['actual_fee_sat'] is None for row in actions):
        raise ValueError('all original outcomes and costs must be reconciled')
    for row in actions:
        from .unknown_outcomes import _intent
        _intent(store,row)
        if row['state']=='completed':
            terminals=store.db.execute("SELECT sequence FROM event WHERE kind='action_result' AND json_extract(payload,'$.action_id')=? AND json_extract(payload,'$.state')='completed'",(row['id'],)).fetchall()
            if len(terminals)!=1:raise ValueError('original completed terminal event missing or ambiguous')
            _,terminal=_source_event(store,terminals[0]['sequence'])
            if canonical(terminal['result'])!=row['result']:
                raise ValueError('original action result differs from preserved terminal event')
            if row['actual_fee_sat']==0 and terminal['actual_fee_sat']!=0:
                raise ValueError('zero cost requires original terminal evidence')
        if row['operation'] not in {'board','send_arkoor','sync','snapshot','address'}:
            raise ValueError('unsupported historical economic operation needs its own source reconciliation')
        if row['state']=='failed':
            from .campaign import _proven_no_cosign_request
            from .fees import _proposal
            if row['operation']!='send_arkoor' or _proven_no_cosign_request(store,row['id'],_proposal(store,row,'arkoor_request')) is None:
                raise ValueError('generic failed outcome is not an opening proof')
        elif row['state']!='completed':
            raise ValueError('unqualified historical refusals require independent disposition')
    for table, states in [('actor_lease', ('active', 'outcome_unknown')),
                          ('funding_batch', ('broadcasting', 'outcome_unknown')),
                          ('seed_recovery', ('preparing', 'prepare_unknown', 'broadcasting', 'outcome_unknown')),
                          ('noah_control', ('started', 'outcome_unknown'))]:
        if store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
            if store.db.execute('SELECT 1 FROM '+table+' WHERE state IN ('+','.join('?' for _ in states)+')', states).fetchone():
                raise ValueError('unresolved original controller: '+table)
    declarations = []
    for event in store.db.execute("SELECT sequence FROM event WHERE kind='exploratory_operating_scope_declared' ORDER BY sequence"):
        row, declaration = _source_event(store, event['sequence'])
        encoded = canonical(declaration); digest = hashlib.sha256(encoded.encode()).hexdigest()
        closure_raw = store.get_meta(exploratory_key+':closed:'+digest)
        closures = store.db.execute("SELECT sequence FROM event WHERE kind='exploratory_operating_scope_closed' AND payload=?", (closure_raw,)).fetchall()
        if closure_raw is None or len(closures) != 1:
            raise ValueError('every original exploratory scope needs its preserved closure')
        closure_event, closure = _source_event(store, closures[0]['sequence'])
        if (closure['declaration_sha256'] != digest or closure['scope_id'] != declaration['id']
                or closure_event['sequence'] <= row['sequence'] or closure['qualified_seconds'] != 0):
            raise ValueError('original exploratory closure changed')
        declarations.append({'id': declaration['id'], 'declaration_sha256': digest,
                             'closure_sha256': hashlib.sha256(closure_raw.encode()).hexdigest()})
    if not declarations:
        raise ValueError('preserved exploratory history required')
    store.verify_event_chain()
    return {'action_ids': [row['id'] for row in actions], 'action_rows_sha256': _digest(actions),
            'action_client_fees_sat': sum(row['actual_fee_sat'] for row in actions if row['state'] != 'canceled'),
            'original_fee_budget_sat': integer(int(store.get_meta('fee_budget_sat')), 'original fee budget'),
            'original_declaration_hashes': declaration_hashes(store), 'closed_scopes': declarations}


def _superseded_ark_input(store, original):
    from .campaign import _receipt_origin, _signed_coin
    from .fees import _proposal
    matches=[]
    for event in store.db.execute("SELECT sequence FROM event WHERE kind='ark_transfer_verified'"):
        _,credit=_source_event(store,event['sequence'])
        if original['id'] not in credit.get('input_coin_ids',[]):continue
        action=store.db.execute('SELECT * FROM action WHERE id=?',(credit['action_id'],)).fetchone()
        if (action is None or action['state']!='completed' or action['operation']!='send_arkoor'
                or action['actor_id']!=original['actor'] or action['actual_fee_sat']!=0):
            raise ValueError('historical spent input lacks its authenticated successful send')
        proposal=_proposal(store,action,'arkoor_request')
        if proposal['input_vtxo_ids']!=[original['id']] or credit['input_coin_ids']!=[original['id']]:
            raise ValueError('unsupported historical multi-input supersession')
        children=[]
        for coin in store.db.execute('SELECT c.id,k.actor FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey'):
            state=store.db.execute('SELECT state FROM coin_observation WHERE coin_id=? ORDER BY observed_at DESC,action_id DESC LIMIT 1',(coin['id'],)).fetchone()
            if state is None:continue
            if state['state'].casefold()=='spent':
                later=[json.loads(r[0]) for r in store.db.execute("SELECT payload FROM event WHERE kind='ark_transfer_verified'")]
                if any(coin['id'] in v.get('input_coin_ids',[]) for v in later):continue
            signed=_signed_coin(store,coin['id'],coin['actor'])
            if signed and _receipt_origin(signed[1],{original['id']}) is not None:
                children.append(signed[0])
        if sum(v['amount_sat'] for v in children)!=original['amount_sat']:
            raise ValueError('original spent principal lacks conserved signed replacement rights')
        matches.append(credit['action_id'])
    if len(matches)>1:raise ValueError('ambiguous historical spent-input allocation')
    return bool(matches)


def _current_claims(store):
    """Retain every independently owned current right, including locked rights."""
    from .ownership import proof_matches_profile
    from .architecture import profile, DIRECT_PER_KEY
    claims = []
    for row in store.db.execute('SELECT c.*,k.actor FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey ORDER BY c.id'):
        observed = store.db.execute('SELECT state,action_id FROM coin_observation WHERE coin_id=? ORDER BY observed_at DESC,action_id DESC LIMIT 1', (row['id'],)).fetchone()
        if observed is None:
            raise ValueError('known ownership has no current state evidence')
        if observed['state'].casefold() == 'spent' and _superseded_ark_input(store,row):
            continue
        # SDK expiry may also use Spent. Only a positively proved economic
        # supersession removes a right; expired/unpaid rights remain liabilities.
        proof = json.loads(row['proof'])
        bound = proof.get('binding', {})
        origin = ({'user_pubkey': row['pubkey'], 'key_link_attestation': bound.get('key_link_attestation')}
            if profile(store) == DIRECT_PER_KEY else
            {'user_pubkey': row['pubkey'], 'child_index': bound.get('child_index'),
             'blinded_mailbox_id': bound.get('blinded_mailbox_id')})
        if (not proof_matches_profile(store, proof, origin)
                or proof.get('signed_path_valid') is not True or proof.get('id') != row['id']
                or proof.get('amount_sat') != row['amount_sat']):
            raise ValueError('original retained right lacks signed ownership')
        claims.append({'coin_id': row['id'], 'actor': row['actor'], 'amount_sat': row['amount_sat'],
                       'signed_hash': row['signed_hash'], 'state': observed['state'],
                       'observation_action_id': observed['action_id']})
    return claims


def _original_cost(store, sequence):
    """Retained routing records replay their own old source, never current pins."""
    event, cost = _source_event(store, sequence)
    if cost.get('kind') == 'router_cost':
        from .cln_router_cost import verify_cost
        verify_cost(store, cost)
        return event, cost
    return _original_miner_cost(store, sequence)


def _original_miner_cost(store, sequence):
    """Decode retained source representations without mutating the old event.

    The caller still verifies original provenance, confirmed fee, unique txid,
    action charges, and internal service classification. This is no new cost.
    """
    import re
    event, cost = _source_event(store, sequence)
    if event['kind'] != 'financial_cost_verified':
        raise ValueError('original verified financial cost event required')
    monetary_id = cost.get('monetary_id')
    legacy = re.fullmatch(r'bitcoin-miner:([0-9a-f]{64})', monetary_id or '')
    if legacy is not None:
        txid = legacy[1]
        if cost.get('kind', 'miner_cost') != 'miner_cost' or cost.get('txid', txid) != txid:
            raise ValueError('legacy miner identity conflicts with original record')
        cost = {**cost, 'kind': 'miner_cost', 'txid': txid, 'monetary_id': 'miner:' + txid}
    return event, cost


def validate(store, opening, boundary_declaration, inventory_sequences, chain, *, now=None):
    """Require the normal producer's original complete opening reconciliation.

    The complete readiness frame must already be independently qualified by its
    producer. Matching its name or this declaration alone grants no dispatch.
    The normal preflight, including all urgent paths, still runs on every call.
    """
    from .target_epochs import active_identity
    from .treasury import _capture_assets
    now = time.time() if now is None else now
    fields = {'id', 'pins', 'target_epoch_id', 'boundary_sha256', 'envelope_sha256',
              'history', 'readiness_sequence', 'new_client_fee_budget_sat'}
    if not isinstance(opening, dict) or set(opening) != fields:
        raise ValueError('complete explicit preserved financial opening required')
    public_payload(opening); _pins(opening['pins'])
    if (not isinstance(opening['id'], str) or not 1 <= len(opening['id']) <= 100
            or opening['history'] != history(store)
            or opening['boundary_sha256'] != _digest(boundary_declaration)
            or opening['pins'] != boundary_declaration['pins']):
        raise ValueError('opening differs from original history or new boundary')
    integer(opening['new_client_fee_budget_sat'], 'explicit new client budget', 1)
    rows = store.db.execute("SELECT sequence FROM event WHERE kind='target_epoch_declared' ORDER BY sequence DESC LIMIT 1").fetchall()
    if len(rows) != 1:
        raise ValueError('verified deployment epoch required before financial opening')
    _, epoch = _source_event(store, rows[0]['sequence'])
    if (epoch['id'] != opening['target_epoch_id'] or epoch['identity'] != active_identity(store)
            or epoch['sdk_commit'] != opening['pins']['sdk_commit']
            or epoch['native_hashes']['bark-sim-driver'] != opening['pins']['driver_sha256']):
        raise ValueError('opening SDK, driver or target epoch differs')
    source, proof = _source_event(store, opening['readiness_sequence'])
    if (source['kind'] != 'financial_operating_readiness' or proof.get('complete') is not True
            or proof.get('financial_pins') != opening['pins']
            or proof.get('boundary_id') != boundary_declaration['id']
            or not 0 <= now-proof.get('observed_at', -1) <= 90):
        raise ValueError('fresh independently qualified normal opening source required')
    reconciliation = proof.get('preserved_history_opening')
    if (not isinstance(reconciliation, dict) or set(reconciliation) != {
            'history', 'inventory_sequences', 'retained_client_rights', 'pending_liabilities',
            'historical_cost_sequences', 'historical_flow_sequences'}
            or reconciliation['history'] != opening['history']
            or reconciliation['inventory_sequences'] != inventory_sequences
            or reconciliation['retained_client_rights'] != _current_claims(store)):
        raise ValueError('complete exact historical rights, costs and inventories required')
    # These are the producer's independently checked exhaustive liabilities and
    # original monetary sources, not zero values inferred from absent fields.
    for name in ('pending_liabilities', 'historical_cost_sequences', 'historical_flow_sequences'):
        if not isinstance(reconciliation[name], list):
            raise ValueError('explicit complete historical financial sources required')
    if not reconciliation['historical_cost_sequences'] or not reconciliation['historical_flow_sequences']:
        raise ValueError('original costs and funding flows cannot be omitted')
    liabilities=reconciliation['pending_liabilities']
    if any(not isinstance(v,dict) or set(v)!={'id','borrower','amount_msat','source_sequence'} for v in liabilities):
        raise ValueError('exact pending liability identities and original sources required')
    if len({v['id'] for v in liabilities})!=len(liabilities):
        raise ValueError('duplicate pending liability')
    members={v['id'] for v in boundary_declaration['members']}
    for liability in liabilities:
        integer(liability['amount_msat'],'pending liability',1)
        event,obligation=_source_event(store,liability['source_sequence'])
        if (event['kind']!='treasury_liability_verified' or obligation!=
                {k:v for k,v in liability.items() if k!='source_sequence'}
                or liability['borrower'] not in members):
            raise ValueError('pending liability original source differs')
    costs = set();cost_actions=set();cost_txids=set();client_costs=[]
    for sequence in reconciliation['historical_cost_sequences']:
        event, cost = _original_cost(store, sequence)
        if cost.get('kind') == 'router_cost':
            if event['kind'] != 'financial_cost_verified' or cost['monetary_id'] in costs:
                raise ValueError('unique retained original router cost required')
            costs.add(cost['monetary_id'])
            continue
        if (event['kind'] != 'financial_cost_verified' or cost.get('monetary_id') in costs
                or cost.get('kind')!='miner_cost' or cost.get('txid') in cost_txids
                or cost.get('monetary_id')!='miner:'+str(cost.get('txid'))):
            raise ValueError('unique original independently verified monetary costs required')
        original_tx=chain.transaction(cost['txid'])
        if original_tx.get('txid')!=cost['txid'] or original_tx.get('confirmations',0)<1 or original_tx['fee_sat']*1000!=cost['amount_msat']:
            raise ValueError('historical external miner cost differs from confirmed Core')
        cost_txids.add(cost['txid'])
        if cost.get('action_id'):cost_actions.add(cost['action_id'])
        integer(cost['amount_msat'],'historical external cost',1)
        costs.add(cost['monetary_id'])
    from .fees import board_fee
    for action in store.db.execute("SELECT * FROM action WHERE actual_fee_sat>0"):
        if action['operation']!='board':raise ValueError('historical paid operation lacks an admitted cost decoder')
        data=json.loads(action['result'])['data']; coin=store.db.execute('SELECT proof FROM owned_coin WHERE id=?',(data['board']['vtxos'][0],)).fetchone()
        txid=json.loads(coin['proof'])['chain_anchor'].split(':')[0]
        verified=board_fee(store,action,chain.transaction(txid))
        events=store.db.execute("SELECT sequence FROM event WHERE kind='client_fee_reconciled' AND json_extract(payload,'$.action_id')=?",(action['id'],)).fetchall()
        if len(events)!=1 or action['id'] not in cost_actions or verified['actual_fee_sat']!=action['actual_fee_sat']:
            raise ValueError('historical client charge and independent original cost incomplete')
        _,fee=_source_event(store,events[0]['sequence'])
        if any(fee.get(k)!=v for k,v in verified.items()):raise ValueError('original client fee source changed')
        matching=[_original_miner_cost(store,v)[1] for v in reconciliation['historical_cost_sequences'] if _original_miner_cost(store,v)[1].get('action_id')==action['id']]
        if (len(matching)!=1 or matching[0]['txid']!=txid or matching[0]['amount_msat']!=verified['mining_fee_sat']*1000):
            raise ValueError('service charge cannot be classified as an external miner cost')
        client_costs.append({'action_id':action['id'],**verified})
    flows=set()
    for sequence in reconciliation['historical_flow_sequences']:
        event, flow = _source_event(store, sequence)
        if event['kind'] != 'treasury_flow_verified' or not flow.get('monetary_id') or flow['monetary_id'] in flows:
            raise ValueError('original independently verified unique funding flows required')
        integer(flow['amount_msat'],'historical funding flow',1);flows.add(flow['monetary_id'])
    assets = _capture_assets(store, boundary_declaration, inventory_sequences, chain)
    if (assets['height'], assets['tip_hash']) != (proof.get('height'), proof.get('tip_hash')):
        raise ValueError('opening source and independent inventories differ in tip')
    if integer(proof['capital_exposure_msat'], 'opening capital exposure') < assets['total_msat']:
        raise ValueError('opening capital omits physical assets')
    return {'declaration': opening, 'inventory_sequences': inventory_sequences,
            'source_event_hash': source['hash'], 'opening_assets': assets,
            'retained_client_rights': reconciliation['retained_client_rights'],
            'pending_liabilities': reconciliation['pending_liabilities'],
            'historical_client_costs':client_costs,
            'historical_miner_cost_msat':sum(_source_event(store,v)[1]['amount_msat'] for v in reconciliation['historical_cost_sequences'] if _source_event(store,v)[1].get('kind')!='router_cost')}


def recorded(store):
    raw = store.get_meta(KEY)
    if raw is None:
        return None
    rows = store.db.execute("SELECT sequence FROM event WHERE kind='preserved_financial_opening_declared'").fetchall()
    if len(rows) != 1:
        raise ValueError('financial opening declaration event missing or duplicated')
    _, proof = _source_event(store, rows[0]['sequence'])
    if canonical(proof) != raw:
        raise ValueError('financial opening differs from preserved event')
    history=proof['declaration']['history'];ids=history['action_ids']
    actions=[dict(r) for r in store.db.execute('SELECT * FROM action ORDER BY id') if r['id'] in set(ids)]
    if len(actions)!=len(ids) or _digest(actions)!=history['action_rows_sha256']:
        raise ValueError('preserved opening action history changed')
    from .target_epochs import declaration_hashes
    current=declaration_hashes(store)
    if any(current.get(k)!=v for k,v in history['original_declaration_hashes'].items()):
        raise ValueError('original opening declarations changed')
    return proof


def client_budget(store):
    """A separately funded new budget never edits or renews an old declaration."""
    proof = recorded(store)
    if proof is None:
        return None
    opening = proof['declaration']
    # The envelope must have separately admitted this exact opening and funded
    # its ordinary and urgent limits before the queue can use its client budget.
    raw = store.get_meta('financial_operating_envelope')
    if raw is None or _digest(json.loads(raw)) != opening['envelope_sha256']:
        raise ValueError('explicit opening envelope has not been admitted')
    previous = set(opening['history']['action_ids'])
    used = sum((row['actual_fee_sat'] if row['actual_fee_sat'] is not None else row['fee_reservation_sat'])
               for row in store.db.execute('SELECT * FROM action')
               if row['id'] not in previous and row['state'] != 'canceled')
    return opening['new_client_fee_budget_sat']-used

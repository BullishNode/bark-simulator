"""Track delegated refresh intents without opening any client wallet.

Signed successors and paginated server observations establish an observed
replacement, not final expiry arbitration. Fees close only through the existing
independent movement checker or complete checked chain payouts. Originals and
successors remain in the public evidence graph; this module never deletes them.
"""
from __future__ import annotations

import hashlib
import json
import time
from collections import Counter
from contextlib import nullcontext

from .fees import movement_fee
from .model import InvariantError, canonical, integer
from .ownership import EvidenceGap

SCHEMA = """
CREATE TABLE IF NOT EXISTS delegated_entitlement(
 action_id TEXT PRIMARY KEY REFERENCES action(id),
 actor_id TEXT NOT NULL REFERENCES actor(id),
 input_coin_ids TEXT NOT NULL, expected_outputs TEXT NOT NULL,
 round_txid TEXT, server_round_id INTEGER, replacement_ids TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('submitted','replaced','paid')),
 proposal_digest TEXT NOT NULL, proposal_event_sequence INTEGER NOT NULL REFERENCES event(sequence),
 evidence TEXT NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL);
CREATE INDEX IF NOT EXISTS delegated_entitlement_state ON delegated_entitlement(state,updated_at);
CREATE INDEX IF NOT EXISTS delegated_refresh_proposal_lookup
 ON event(json_extract(payload,'$.action_id'))
 WHERE kind='driver_evidence' AND json_extract(payload,'$.event')='refresh_proposal';
"""


def initialize(store):
    store.db.executescript(SCHEMA)


def _hash(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def _frozen(store, action):
    rows = store.db.execute("""SELECT sequence,payload FROM event WHERE kind='driver_evidence'
        AND json_extract(payload,'$.action_id')=? AND json_extract(payload,'$.event')='refresh_proposal'""",
        (action['id'],)).fetchall()
    if len(rows) != 1:
        raise EvidenceGap('delegated refresh lacks a unique frozen proposal')
    proposal = json.loads(rows[0]['payload'])['data']
    participation = proposal['participation']
    inputs = participation['inputs']
    if not inputs or len(set(inputs)) != len(inputs):
        raise InvariantError('delegated refresh has empty or duplicate frozen inputs')
    fee = integer(proposal['committed_fee_sat'], 'frozen refresh charge')
    if fee > action['fee_reservation_sat']:
        raise InvariantError('delegated refresh quote exceeds its reserve')
    outputs = []
    for output in participation['outputs']:
        policy = output['policy']
        if (not isinstance(policy,str) or len(policy)!=68 or not policy.startswith(('0002','0003'))
                or any(c not in '0123456789abcdef' for c in policy)):
            raise EvidenceGap('delegated refresh output is not a supported public-key policy')
        outputs.append({'pubkey':policy[2:], 'amount_sat':integer(output['amount'],'frozen refresh output',1)})
    if not outputs:
        raise EvidenceGap('delegated refresh lacks frozen replacement outputs')
    data = json.loads(action['result'] or '{}').get('data',{})
    if 'committed_fee_sat' in data and data['committed_fee_sat'] != fee:
        raise InvariantError('delegated refresh result changed its frozen charge')
    return proposal, rows[0]['sequence'], outputs, fee


def _coin(store, coin_id, actor):
    coin = store.db.execute("""SELECT c.*,k.actor,k.mailbox FROM owned_coin c
        JOIN owner_key k ON k.pubkey=c.pubkey WHERE c.id=?""", (coin_id,)).fetchone()
    if coin is None:
        raise EvidenceGap('delegated coin awaits independent signed ownership')
    if coin['actor'] != actor:
        raise InvariantError('delegated coin belongs to another actor')
    proof = json.loads(coin['proof'])
    if (proof.get('id'),proof.get('user_pubkey'),proof.get('amount_sat')) != (coin['id'],coin['pubkey'],coin['amount_sat']):
        raise InvariantError('delegated signed coin identity or value changed')
    binding = proof.get('binding') or {}
    if (proof.get('signed_path_valid') is not True or proof.get('anchor_confirmations',0)<1
            or binding.get('record_signature_valid') is not True
            or binding.get('account_child_verified') is not True):
        raise EvidenceGap('delegated coin signature or backing proof is incomplete')
    if (binding.get('mailbox_pk') != coin['mailbox'] or not store.db.execute("""SELECT 1 FROM owner_record
            WHERE actor=? AND mailbox=? AND account_xpub=? AND script=?""",
            (actor,coin['mailbox'],binding.get('account_xpub'),binding.get('spk'))).fetchone()):
        raise EvidenceGap('delegated coin lacks its verified owner record')
    if hashlib.sha256(bytes.fromhex(coin['signed_vtxo'])).hexdigest() != coin['signed_hash']:
        raise InvariantError('delegated signed coin bytes differ from their proof digest')
    return coin, proof


def _inputs(store, actor, proposal, outputs, fee):
    coins = []
    for signed in proposal['participation']['inputs']:
        ids = store.db.execute('SELECT id FROM owned_coin WHERE signed_vtxo=?',(signed,)).fetchall()
        if len(ids) != 1:
            raise EvidenceGap('delegated input awaits unique independent signed proof')
        coin,_ = _coin(store,ids[0]['id'],actor)
        coins.append(coin)
    gross = sum(c['amount_sat'] for c in coins)
    if gross != sum(o['amount_sat'] for o in outputs) + fee:
        raise InvariantError('delegated frozen input/output principal and charge do not conserve')
    return coins, gross


def _record(store, action):
    if (action['operation'] not in {'refresh_delegated','refresh_scheduled'} or action['state'] not in
            {'completed','dispatched','outcome_unknown'}):
        return None
    data = json.loads(action['result'] or '{}').get('data',{})
    if data.get('no_inputs') is True:
        return None
    proposal,sequence,outputs,fee = _frozen(store,action)
    evidence = {'input_ownership_verified':False,'input_principal_sat':None,
        'expected_replacement_sat':sum(o['amount_sat'] for o in outputs),'committed_fee_sat':fee,
        'scope':'frozen submitted intent; replacement and expiry arbitration are not yet proved'}
    ids = []
    try:
        inputs,gross = _inputs(store,action['actor_id'],proposal,outputs,fee)
        ids = [c['id'] for c in inputs]
        evidence.update(input_ownership_verified=True,input_principal_sat=gross)
    except EvidenceGap as error:
        evidence['gap'] = str(error)
    previous = store.db.execute('SELECT * FROM delegated_entitlement WHERE action_id=?',(action['id'],)).fetchone()
    if previous:
        if previous['proposal_digest'] != _hash(proposal) or previous['actor_id'] != action['actor_id']:
            raise InvariantError('delegated frozen intent or owner changed')
        return previous
    at = time.time()
    store.db.execute("INSERT INTO delegated_entitlement VALUES (?,?,?,?,NULL,NULL,?,'submitted',?,?,?,?,?)",
        (action['id'],action['actor_id'],canonical(ids),canonical(outputs),canonical([]),
         _hash(proposal),sequence,canonical(evidence),at,at))
    store._event('delegated_entitlement_submitted',{'action_id':action['id'],'actor':action['actor_id'],
        'input_coin_ids':ids,'expected_outputs':outputs,'proposal_event_sequence':sequence,
        'proposal_digest':_hash(proposal),**evidence})
    return store.db.execute('SELECT * FROM delegated_entitlement WHERE action_id=?',(action['id'],)).fetchone()


def record_submitted(store, action_id):
    """Completion hook: accounting gaps never turn a valid SDK reply unknown."""
    action = store.db.execute('SELECT * FROM action WHERE id=?',(action_id,)).fetchone()
    if action is None or action['operation'] not in {'refresh_delegated','refresh_scheduled'}:return
    with (nullcontext() if store.db.in_transaction else store.transaction()):
        try:
            _record(store,action)
        except InvariantError as error:
            store._event('ownership_incident',{'action_id':action_id,'reason':str(error)})
            store.db.execute("INSERT OR REPLACE INTO meta VALUES ('paused','delegated ownership contradiction')")
        except (EvidenceGap,KeyError,TypeError,ValueError) as error:
            store._event('delegated_entitlement_pending',{'action_id':action_id,'reason':str(error)})


def _server_coin(store, coin, action, active_output=False):
    row = store.db.execute("SELECT * FROM server_item WHERE kind='coins' AND id=?",(coin['id'],)).fetchone()
    if row is None or row['observed_at'] < action['updated_at']:
        raise EvidenceGap('delegated round awaits a later public server coin observation')
    value = json.loads(row['payload'])
    if value.get('vtxo_id') != coin['id'] or value.get('signed_vtxo') != coin['signed_vtxo']:
        raise EvidenceGap('delegated public inventory differs from the independently signed coin')
    if value.get('policy_type') != 'pubkey':
        raise EvidenceGap('delegated inventory policy is not the frozen public-key policy')
    if active_output and value.get('spend_state') not in {'unclaimed','spendable'}:
        raise EvidenceGap('delegated signed replacement is not an active server output')
    return value, _hash(value)


def _replacements(store, action, inputs, outputs):
    rounds, mapped_anchors, input_digests = set(), set(), {}
    for coin in inputs:
        value,hashed = _server_coin(store,coin,action)
        round_id = value.get('spent_in_round')
        if type(round_id) is not int or round_id < 1 or value.get('spend_state') != 'spent':
            raise EvidenceGap('delegated input has no observed round spend')
        if value.get('offboarded_in') is not None:
            raise EvidenceGap('delegated input also names an offboard spend')
        rounds.add(round_id);input_digests[coin['id']] = hashed
        mapped = value.get('spent_in_round_txid')
        if mapped is not None:
            if not isinstance(mapped,str) or len(mapped)!=64 or any(c not in '0123456789abcdef' for c in mapped):
                raise EvidenceGap('delegated server round funding identity is malformed')
            mapped_anchors.add(mapped)
    if len(rounds) != 1:
        raise EvidenceGap('delegated inputs name different server rounds')
    expected = Counter((o['pubkey'],o['amount_sat']) for o in outputs)
    for pubkey,amount in expected:
        if store.db.execute("""SELECT 1 FROM delegated_entitlement e JOIN json_each(e.expected_outputs) output
            WHERE e.action_id<>? AND e.state IN ('submitted','replaced')
            AND json_extract(output.value,'$.pubkey')=? AND json_extract(output.value,'$.amount_sat')=? LIMIT 1""",
            (action['id'],pubkey,amount)).fetchone():
            raise EvidenceGap('delegated output key/value is shared by another unresolved intent')
    found, anchors, output_digests, signed_hashes, direct_round_outputs = [], set(), {}, {}, True
    for (pubkey,amount),count in expected.items():
        candidates = store.db.execute('SELECT id FROM owned_coin WHERE pubkey=? AND amount_sat=? ORDER BY id',
                                      (pubkey,amount)).fetchall()
        matching = []
        for candidate in candidates:
            coin,proof = _coin(store,candidate['id'],action['actor_id'])
            if coin['id'] in {c['id'] for c in inputs}:
                raise EvidenceGap('delegated replacement reuses an original coin')
            try:
                value,hashed = _server_coin(store,coin,action,active_output=True)
            except EvidenceGap:
                continue
            from .padding import classification
            if classification(store, value) == 'round_padding':
                continue
            earliest = store.db.execute('SELECT MIN(observed_at) FROM coin_observation WHERE coin_id=?',
                                        (coin['id'],)).fetchone()[0]
            if earliest is None or earliest <= action['created_at']:
                continue
            if proof.get('expiry_height') != value.get('expiry'):
                raise EvidenceGap('delegated replacement expiry differs from signed proof')
            anchor = proof.get('chain_anchor','').split(':')
            if len(anchor)!=2 or len(anchor[0])!=64 or any(c not in '0123456789abcdef' for c in anchor[0]):
                raise EvidenceGap('delegated replacement has no proven round funding anchor')
            anchors.add(anchor[0]);output_digests[coin['id']] = hashed;signed_hashes[coin['id']] = coin['signed_hash']
            direct_round_outputs = direct_round_outputs and type(proof.get('arkoor_transition_count')) is int and proof['arkoor_transition_count']==0
            matching.append(coin)
        if len(matching) != count:
            raise EvidenceGap('delegated replacement set is missing, partial or ambiguous')
        found.extend(matching)
    if len(anchors) != 1:
        raise EvidenceGap('delegated replacement proofs name different funding transactions')
    anchor = next(iter(anchors))
    if mapped_anchors and mapped_anchors != {anchor}:
        raise EvidenceGap('delegated server round funding identity contradicts the signed successor anchor')
    association = None
    if len(mapped_anchors)==1 and anchor in mapped_anchors and direct_round_outputs:
        # Every input must carry the mapping; a partially upgraded page is not
        # a complete round association, even if another input supplied its ID.
        if all(json.loads(store.db.execute("SELECT payload FROM server_item WHERE kind='coins' AND id=?",
                 (coin['id'],)).fetchone()[0]).get('spent_in_round_txid')==anchor for coin in inputs):
            association = 'server round-ID/funding-txid mapping and independently decoded no-arkoor successor path'
    if association is None:
        try:
            movement = movement_fee(store,action)
            if set(movement['output_coin_ids'])=={coin['id'] for coin in found}:
                association = 'successful independently recorded SDK round movement tied to frozen inputs and signed outputs'
        except InvariantError:raise
        except (EvidenceGap,KeyError,TypeError,ValueError):pass
    if association is None:
        raise EvidenceGap('delegated successors lack an explicit round funding/direct-leaf association or completed matching SDK movement')
    return [c['id'] for c in found], anchor, next(iter(rounds)), {
        'input_inventory_digests':input_digests,'replacement_inventory_digests':output_digests,
        'replacement_signed_hashes':signed_hashes,'inventory_consistent':False,
        'round_mapping_scope':association+'; numeric server round ID is not a txid',
        'scope':'observed signed replacement and trusted server round spend; cancellation and final expiry arbitration remain separate'}


def _settled(store, ids, actor, original=False):
    checked = []
    for coin_id in ids:
        coin,_ = _coin(store,coin_id,actor)
        row = store.db.execute("""SELECT s.*,tx.payload chain,ck.state check_state FROM checked_settlement s
            JOIN chain_payout tx ON tx.txid=s.txid JOIN settlement_check ck ON ck.txid=s.txid
            WHERE s.coin_id=?""",(coin_id,)).fetchone()
        if row is None:continue
        if row['actor'] != actor or row['amount_sat'] != coin['amount_sat']:
            raise InvariantError('delegated checked payout has another owner or principal')
        if row['check_state'] != 'amounts_checked' or json.loads(row['chain']).get('confirmations',0)<1:
            continue
        evidence = json.loads(row['evidence']);source = evidence['row'];owner = evidence['owner']
        if (source['id'] != coin_id or source['txid'] != row['txid']
                or owner['actor'] != actor or owner['amount_sat'] != coin['amount_sat']
                or owner['pubkey'] != coin['pubkey'] or owner['mailbox'] != coin['mailbox']
                or source['spk'] != row['script']):
            raise InvariantError('delegated payout proof changed its signed owner')
        if not store.db.execute('SELECT 1 FROM owner_record WHERE actor=? AND mailbox=? AND script=?',
                                (actor,coin['mailbox'],row['script'])).fetchone():
            raise EvidenceGap('delegated checked payout lacks its signed owner destination')
        if original:
            pre = source.get('pre_commit_rows',[])
            if not pre or any(p.get('spend_state')!='spendable' or p.get('spent_in_round') is not None
                    or p.get('oor_spent_txid') is not None or p.get('offboarded_in') is not None for p in pre):
                continue
        checked.append({'coin_id':coin_id,'txid':row['txid'],'gross_sat':row['amount_sat']})
    return checked


def _cancelled(store, action, row, inputs, replacements):
    """A positive server rollback invalidates an observed successor only.

    This never releases a fee or proves payout eligibility. Paginated evidence
    stays explicit; an absent row or an ordinarily spent successor is no proof.
    """
    if not replacements:return False
    try:
        for coin in inputs:
            value,_ = _server_coin(store,coin,action)
            if (value.get('spend_state')!='spendable' or value.get('spent_in_round') is not None
                    or value.get('oor_spent_txid') is not None or value.get('offboarded_in') is not None):
                return False
        for coin_id in replacements:
            coin,_ = _coin(store,coin_id,row['actor_id'])
            value,_ = _server_coin(store,coin,action)
            if (value.get('spend_state')!='spent' or value.get('spent_in_round') is not None
                    or value.get('oor_spent_txid') is not None or value.get('offboarded_in') is not None
                    or value.get('confirmed_height') is not None):
                return False
        return True
    except EvidenceGap:return False


def _change(store, row, state, inputs, replacements, round_txid, server_round_id, evidence):
    fields = {'state':state,'input_coin_ids':canonical(inputs),'replacement_ids':canonical(replacements),
        'round_txid':round_txid,'server_round_id':server_round_id,'evidence':canonical(evidence)}
    if all(row[key]==value for key,value in fields.items()):return
    store.db.execute("""UPDATE delegated_entitlement SET state=?,input_coin_ids=?,replacement_ids=?,
        round_txid=?,server_round_id=?,evidence=?,updated_at=? WHERE action_id=?""",
        (state,fields['input_coin_ids'],fields['replacement_ids'],round_txid,server_round_id,
         fields['evidence'],time.time(),row['action_id']))
    store._event('delegated_entitlement_changed',{'action_id':row['action_id'],'actor':row['actor_id'],
        'previous_state':row['state'],'state':state,'input_coin_ids':inputs,'replacement_ids':replacements,
        'round_txid':round_txid,'server_round_id':server_round_id,**evidence})


def _close_fee(store, action, evidence):
    cost = integer(evidence['actual_fee_sat'],'delegated actual charge')
    if cost > action['fee_reservation_sat']:
        raise InvariantError('delegated actual charge exceeds its frozen reserve')
    current = store.db.execute('SELECT actual_fee_sat,state FROM action WHERE id=?',(action['id'],)).fetchone()
    if current['actual_fee_sat'] is not None:
        if current['actual_fee_sat'] != cost:
            raise InvariantError('delegated paid source contradicts its already reconciled charge')
        return
    if current['state'] != 'completed':return
    if store.db.execute("SELECT 1 FROM event WHERE kind='client_fee_reconciled' AND json_extract(payload,'$.action_id')=?",
                        (action['id'],)).fetchone():
        raise InvariantError('delegated fee proof exists without its atomic charge update')
    changed = store.db.execute('UPDATE action SET actual_fee_sat=? WHERE id=? AND actual_fee_sat IS NULL',
                              (cost,action['id'])).rowcount
    if changed:store._event('client_fee_reconciled',{'action_id':action['id'],**evidence})


def _reconcile(store, action, row):
    proposal,sequence,outputs,fee = _frozen(store,action)
    if _hash(proposal) != row['proposal_digest'] or action['actor_id'] != row['actor_id']:
        raise InvariantError('delegated frozen proposal or owner changed')
    inputs,gross = _inputs(store,row['actor_id'],proposal,outputs,fee)
    input_ids = [c['id'] for c in inputs]
    evidence = json.loads(row['evidence'])
    evidence.update(input_ownership_verified=True,input_principal_sat=gross)
    evidence.pop('gap',None)
    replacements = json.loads(row['replacement_ids'])
    round_txid,server_round_id,state = row['round_txid'],row['server_round_id'],row['state']
    if state != 'paid':
        if _cancelled(store,action,row,inputs,replacements):
            evidence['cancelled_replacement'] = {'replacement_ids':replacements,
                'round_txid':round_txid,'server_round_id':server_round_id}
            replacements,round_txid,server_round_id,state = [],None,None,'submitted'
            evidence['scope'] = 'server reports originals restored and successors retired; fee and payout qualification remain reserved'
        try:
            observed,txid,round_id,proof = _replacements(store,action,inputs,outputs)
            if replacements and (set(observed)!=set(replacements) or txid!=round_txid or round_id!=server_round_id):
                raise InvariantError('delegated observed replacement set changed')
            replacements,round_txid,server_round_id,state = observed,txid,round_id,'replaced'
            evidence.update(proof)
        except EvidenceGap as error:
            evidence['gap'] = str(error)
    # A successful independent movement can close the charge even if server
    # inventory is incomplete. It never opens a wallet or proves final expiry.
    movement = None
    if action['state']=='completed':
        try:
            movement = movement_fee(store,action)
            for coin_id in movement['output_coin_ids']:
                _coin(store,coin_id,row['actor_id'])
            _close_fee(store,action,movement)
        except InvariantError:raise
        except (EvidenceGap,KeyError,TypeError,ValueError):pass
    original_paid = _settled(store,input_ids,row['actor_id'],original=True)
    replacement_paid = _settled(store,replacements,row['actor_id']) if replacements else []
    if original_paid and replacement_paid:
        raise InvariantError('delegated originals and successors both received checked payouts')
    if original_paid and movement:
        raise InvariantError('delegated original payout contradicts independently completed successors')
    originals_complete = original_paid if len(original_paid)==len(input_ids) else None
    replacements_complete = replacement_paid if replacements and len(replacement_paid)==len(replacements) else None
    paid,source,cost = (originals_complete,'original',0) if originals_complete else (replacements_complete,'replacement',fee)
    if paid:
        state = 'paid'
        evidence.update(payout_source=source,checked_payouts=paid,
            scope='complete checked chain payouts for one frozen principal source; payout fees remain separate')
        _close_fee(store,action,{'actor':row['actor_id'],'actual_fee_sat':cost,
            'input_coin_ids':input_ids,'output_coin_ids':input_ids if source=='original' else replacements,
            'checked_payouts':paid,'payout_source':source,
            'scope':'customer refresh charge from frozen signed principal and complete checked payouts; recipient/operator payout fees not assigned to this refresh'})
    _change(store,row,state,input_ids,replacements,round_txid,server_round_id,evidence)


def collect(store, limit=4):
    """Advance persisted evidence only. Unknown/dispatched actions retain fees."""
    rows = store.db.execute("""SELECT * FROM action WHERE operation IN ('refresh_delegated','refresh_scheduled')
        AND state IN ('completed','dispatched','outcome_unknown') ORDER BY id""").fetchall()
    after = store.get_meta('delegated_entitlement_cursor') or ''
    rows = [r for r in rows if r['id']>after] + [r for r in rows if r['id']<=after]
    for action in rows[:limit]:
        with store.transaction():
            try:
                row = _record(store,action)
                if row is not None:_reconcile(store,action,row)
            except InvariantError:raise
            except (EvidenceGap,KeyError,TypeError,ValueError) as error:
                row = store.db.execute('SELECT * FROM delegated_entitlement WHERE action_id=?',(action['id'],)).fetchone()
                if row:
                    evidence = json.loads(row['evidence']);evidence['gap'] = str(error)
                    _change(store,row,row['state'],json.loads(row['input_coin_ids']),json.loads(row['replacement_ids']),
                            row['round_txid'],row['server_round_id'],evidence)
            store.db.execute("INSERT OR REPLACE INTO meta VALUES ('delegated_entitlement_cursor',?)",(action['id'],))


def unclaimed_expired_report(store, height, limit=1000):
    """Public inventory candidates, with honest partial-snapshot/ownership scope."""
    integer(height,'report height')
    count = store.db.execute("SELECT count(*) FROM server_item WHERE kind='coins'").fetchone()[0]
    rows = store.db.execute("""SELECT id,payload,observed_at FROM server_item WHERE kind='coins'
        AND json_extract(payload,'$.policy_type')='pubkey' AND json_extract(payload,'$.spend_state')='unclaimed'
        AND json_extract(payload,'$.expiry')<? ORDER BY id""",(height,))
    from .padding import classification
    candidates,total = [],0
    for row in rows:
        value = json.loads(row['payload'])
        if classification(store, value) == 'round_padding':
            continue
        total += 1
        if len(candidates)>=limit:continue
        coin = store.db.execute("""SELECT c.*,k.actor FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey
            WHERE c.id=?""",(row['id'],)).fetchone()
        value = json.loads(row['payload'])
        linked = [r[0] for r in store.db.execute("""SELECT e.action_id FROM delegated_entitlement e
            JOIN json_each(e.replacement_ids) ids ON ids.value=? ORDER BY e.action_id""",(row['id'],))]
        proved = False
        if coin and coin['signed_vtxo']==value.get('signed_vtxo'):
            try:_coin(store,coin['id'],coin['actor']);proved=True
            except (EvidenceGap,KeyError,TypeError,ValueError):pass
        candidates.append({'coin_id':row['id'],'expiry_height':value['expiry'],'observed_at':row['observed_at'],
            'delegated_action_ids':linked,'actor':coin['actor'] if proved else None,
            'signed_amount_sat':coin['amount_sat'] if proved else None,'independent_ownership_verified':proved,
            'association_scope':'frozen delegated proposal and independently signed successors' if linked else
                'unclaimed public-key inventory candidate; delegated association not proved'})
    return {'height':height,'status':'partial_inventory' if count else 'no_inventory',
        'inventory_consistent':False,'inventory_coin_rows':count,'expired_unclaimed_public_key_rows':total,
        'rows':candidates,'detail_limit':limit,'truncated':total>len(candidates),
        'scope':'saved/current trusted paginated server observations, positively SDK-decoded protocol padding excluded; no complete snapshot or payout qualification; unknown ownership/amounts remain unknown'}

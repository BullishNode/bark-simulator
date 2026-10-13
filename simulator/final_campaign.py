"""Final-build campaign evidence; no wallet calls, funding or dispatch.

A namespace has one immutable final financial epoch. Earlier traffic stays
exploratory. Callers supply independently observed pins and checked original
proof events; declarations or actor rows alone cannot qualify operation.
"""
from __future__ import annotations

import hashlib
import json
import re
from .model import canonical, integer, public_payload, timestamp

RAILS = ('ark', 'internal_lightning', 'external_lightning')
PIN_LENGTHS = {'product_commit':40, 'sdk_commit':40, 'driver_sha256':64,
               'configuration_sha256':64, 'schema_sha256':64}
EPOCH_KEY = 'final_financial_epoch'
SCHEMA = '''CREATE TABLE IF NOT EXISTS final_traffic(
 source_sequence INTEGER PRIMARY KEY, rail TEXT NOT NULL, action_id TEXT NOT NULL,
 verified_at REAL NOT NULL, proof TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS final_traffic_recent ON final_traffic(rail,verified_at);'''


def _pins(value):
    if not isinstance(value, dict) or set(value) != set(PIN_LENGTHS):
        raise ValueError('complete financial product/SDK/driver/config/schema pins required')
    for key, length in PIN_LENGTHS.items():
        if not isinstance(value[key], str) or re.fullmatch('[0-9a-f]{'+str(length)+'}', value[key]) is None:
            raise ValueError('invalid financial pin: '+key)
    return value


def _declaration(value):
    if not isinstance(value, dict) or set(value) != {'id','pins','started_at','windows_seconds','minimum_observations'}:
        raise ValueError('complete final financial epoch required')
    if not isinstance(value['id'], str) or re.fullmatch('[a-z0-9][a-z0-9_-]{0,99}', value['id']) is None:
        raise ValueError('bounded financial epoch identifier required')
    _pins(value['pins']); timestamp(value['started_at'], 'epoch start')
    for field in ('windows_seconds','minimum_observations'):
        if not isinstance(value[field],dict) or set(value[field]) != set(RAILS):
            raise ValueError('declare Ark, internal and external Lightning requirements')
        for rail, number in value[field].items():
            integer(number, field+' '+rail, 1)
            if number > (86400 if field == 'windows_seconds' else 1000):
                raise ValueError('campaign evidence bound exceeded')
    public_payload(value)
    return value


def epoch(store):
    encoded = store.get_meta(EPOCH_KEY)
    if encoded is None:
        return None
    value = _declaration(json.loads(encoded))
    events = store.db.execute("SELECT payload FROM event WHERE kind='final_financial_epoch_declared'").fetchall()
    if len(events) != 1 or events[0][0] != canonical(value):
        raise ValueError('financial epoch differs from immutable declaration event')
    return value


def declare_epoch(store, declaration):
    """Lead records a preverified declaration while paused; never repins live work."""
    _declaration(declaration)
    with store.transaction():
        previous = store.get_meta(EPOCH_KEY)
        if previous is not None:
            current = epoch(store)
            if current != declaration:
                raise ValueError('financial epoch immutable; preserve it and use a fresh namespace')
            return False
        if not store.get_meta('paused'):
            raise ValueError('pause dispatch before declaring a final financial epoch')
        if store.db.execute("SELECT 1 FROM action WHERE state IN ('dispatched','outcome_unknown') LIMIT 1").fetchone():
            raise ValueError('reconcile dispatched and unknown actions before final epoch')
        for table,states in [('funding_batch',('broadcasting','outcome_unknown')),
                             ('seed_recovery',('preparing','prepare_unknown','broadcasting','outcome_unknown')),
                             ('actor_lease',('active','outcome_unknown')),
                             ('noah_control',('started','outcome_unknown'))]:
            if store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone():
                placeholders=','.join('?' for _ in states)
                if store.db.execute('SELECT 1 FROM '+table+' WHERE state IN ('+placeholders+') LIMIT 1',states).fetchone():
                    raise ValueError('reconcile in-flight controller before final epoch: '+table)
        if store.get_meta('ramp_applied') == 'true':
            raise ValueError('preserve exploratory ramp; use a fresh namespace for final cohort')
        ordinary = [r[0] for r in store.db.execute('SELECT id FROM actor') if store.actor_namespace(r[0]) == 'ordinary']
        if set(ordinary) != {f'actor-{i:02}' for i in range(1,13)}:
            raise ValueError('final epoch requires its declared initial twelve-client cohort')
        old = store.get_meta('qualified_campaign_active_seconds') or '0'
        store.db.execute("INSERT INTO meta VALUES ('exploratory_active_seconds',?)", (old,))
        store.db.execute("INSERT OR REPLACE INTO meta VALUES ('qualified_campaign_active_seconds','0')")
        store.db.execute('INSERT INTO meta VALUES (?,?)', (EPOCH_KEY,canonical(declaration)))
        # DDL must not use executescript inside the enclosing transaction.
        store.db.execute(SCHEMA.split(';')[0])
        store.db.execute(SCHEMA.split(';')[1])
        store._event('final_financial_epoch_declared', declaration)
    return True


def pins_match(store, observed_pins):
    value = epoch(store)
    if value is None or observed_pins is None:
        return False
    return _pins(observed_pins) == value['pins']


def _source_event(store, sequence):
    integer(sequence, 'source event sequence', 1)
    event = store.db.execute('SELECT * FROM event WHERE sequence=?',(sequence,)).fetchone()
    if event is None:
        raise ValueError('original checked proof event missing')
    frame = canonical([event['sequence'],event['observed_at'],event['kind'],event['payload'],event['previous_hash']])
    if hashlib.sha256(frame.encode()).hexdigest() != event['hash']:
        raise ValueError('original checked event frame changed')
    return event, json.loads(event['payload'])


def record_traffic(store, rail, action_id, source_sequence, observed_pins):
    """Bind an existing checked outcome to its original time, never import time.

    Internal receives require the independently reconciled signed claim; a payer
    status alone is insufficient. External observations require the controlled
    peer verifier's terminal outcome, not an arbitrary pay_invoice ACK.
    """
    if rail not in RAILS or not pins_match(store,observed_pins):
        raise ValueError('financial epoch/rail/pins differ')
    declaration = epoch(store)
    event, proof = _source_event(store, source_sequence)
    action = store.db.execute('SELECT * FROM action WHERE id=?',(action_id,)).fetchone()
    if action is None or action['state'] != 'completed':
        raise ValueError('traffic action is not a completed original action')
    if action['created_at'] < declaration['started_at'] or action['updated_at'] < declaration['started_at']:
        raise ValueError('exploratory action cannot earn final credit')
    if proof.get('action_id') != action_id:
        raise ValueError('proof action differs from original intent')
    if rail == 'ark':
        if event['kind'] != 'ark_transfer_verified' or action['operation'] != 'send_arkoor':
            raise ValueError('signed Ark receipt proof required')
        verified_at = timestamp(proof['verified_at'],'original receipt observation')
    elif rail == 'internal_lightning':
        if event['kind'] != 'client_fee_reconciled' or action['operation'] != 'sync':
            raise ValueError('signed internal receive claim proof required')
        claims = proof.get('claims',[])
        if not claims or len(claims) > 64:
            raise ValueError('bounded independently reconciled receive claims required')
        for claim in claims:
            senders = store.db.execute("""SELECT actor_id,args,created_at,updated_at FROM action WHERE operation='pay_invoice'
                AND state='completed' AND json_extract(result,'$.data.payment_hash')=?
                AND json_extract(result,'$.data.payment_status_verified')=1
                AND json_extract(result,'$.data.payment_state')='succeeded'""",(claim['payment_hash'],)).fetchall()
            if (len(senders) != 1 or senders[0]['actor_id'] == action['actor_id']
                    or senders[0]['created_at'] < declaration['started_at']):
                raise ValueError('receive lacks a unique successful internal payer')
            intended = json.loads(senders[0]['args'])
            if (intended.get('recipient_actor') != action['actor_id']
                    or intended.get('recipient_invoice_action') != claim['invoice_action_id']):
                raise ValueError('internal recipient differs from frozen payer intent')
            invoice = store.db.execute("SELECT actor_id,result,created_at FROM action WHERE id=? AND operation='invoice' AND state='completed'",(claim['invoice_action_id'],)).fetchone()
            if (invoice is None or invoice['actor_id'] != action['actor_id']
                    or invoice['created_at'] < declaration['started_at']
                    or json.loads(invoice['result'])['data']['payment_hash'] != claim['payment_hash']):
                raise ValueError('receive invoice differs from intended original hash')
        verified_at = event['observed_at']
    else:
        if (event['kind'] != 'controlled_peer_payment_verified' or proof.get('state') != 'succeeded'
                or proof.get('payment_hash') != json.loads(action['result'])['data'].get('payment_hash')
                or proof.get('direction') not in {'send','receive'}
                or proof.get('peer_outcome_checked') is not True
                or not isinstance(proof.get('peer_pubkey'),str)
                or re.fullmatch('(02|03)[0-9a-f]{64}',proof['peer_pubkey']) is None):
            raise ValueError('independently checked controlled external peer outcome required')
        verified_at = timestamp(proof['verified_at'],'original peer observation')
    if not declaration['started_at'] <= verified_at <= event['observed_at']:
        raise ValueError('proof time outside final epoch or later than source event')
    frame = {'epoch_id':declaration['id'],'pins':declaration['pins'],'rail':rail,
             'action_id':action_id,'source_sequence':source_sequence,'source_hash':event['hash'],'verified_at':verified_at,
             'participants':sorted({action['actor_id']} | ({proof['recipient_actor']} if rail == 'ark' and isinstance(proof.get('recipient_actor'),str) else set()))}
    encoded = canonical(frame)
    with store.transaction():
        previous = store.db.execute('SELECT proof FROM final_traffic WHERE source_sequence=?',(source_sequence,)).fetchone()
        if previous:
            if previous[0] != encoded:
                raise ValueError('traffic proof was assigned to another rail or action')
            return False
        store.db.execute('INSERT INTO final_traffic VALUES (?,?,?,?,?)',(source_sequence,rail,action_id,verified_at,encoded))
        store._event('final_traffic_verified',frame)
    return True


def traffic_ready(store, now, observed_pins):
    if not pins_match(store,observed_pins):
        return False
    declaration = epoch(store)
    if now < declaration['started_at']:
        return False
    for rail in RAILS:
        count = store.db.execute("SELECT COUNT(DISTINCT action_id) FROM final_traffic WHERE rail=? AND verified_at>=? AND verified_at<=?",
            (rail,max(declaration['started_at'],now-declaration['windows_seconds'][rail]),now)).fetchone()[0]
        if count < declaration['minimum_observations'][rail]:
            return False
    return True


def ramp_status(store):
    """Rows/funding ACKs are preparation. Checked funding and boards prove ramp."""
    declaration = epoch(store)
    if declaration is None:
        return {'state':'exploratory','qualified':False}
    row = store.db.execute("SELECT * FROM event WHERE kind='final_ramp_verified' ORDER BY sequence DESC LIMIT 1").fetchone()
    if row is None:
        return {'state':'prepared' if store.get_meta('ramp_applied') == 'true' else 'not_started','qualified':False}
    _,proof = _source_event(store,row['sequence'])
    matches = proof.get('epoch_id') == declaration['id'] and proof.get('pins') == declaration['pins']
    return {**proof,'state':'qualified' if matches else 'unqualified','qualified':matches}


def verify_ramp(store, chain, observed_pins):
    """Read-only Core and already checked boards; no wallet opening or funding."""
    if not pins_match(store,observed_pins) or store.get_meta('ramp_applied') != 'true':
        raise ValueError('final epoch pins or prepared ramp missing')
    declaration = epoch(store)
    if ramp_status(store).get('qualified'):
        return False
    if float(store.get_meta('qualified_campaign_active_seconds') or '0') < 10800:
        raise ValueError('three qualified hours required before ramp')
    exists = store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='funding_batch'").fetchone()
    funding = store.db.execute("SELECT * FROM funding_batch WHERE id='ramp'").fetchone() if exists else None
    if funding is None or funding['state'] != 'confirmed':
        raise ValueError('original ramp funding has not confirmed')
    recipients = json.loads(funding['recipients'])
    actors = {f'actor-{i:02}' for i in range(13,25)}
    if len(recipients) != 12 or {r['actor'] for r in recipients} != actors or len({r['address'] for r in recipients}) != 12:
        raise ValueError('ramp requires twelve distinct funded identities')
    chain.identity()
    tx = chain.transaction(funding['txid'])
    if tx['confirmations'] < 1 or tx['fee_sat'] != funding['fee_sat']:
        raise ValueError('ramp funding is not independently confirmed with exact fee')
    receipts = []
    from .campaign import _signed_coin
    for recipient in recipients:
        address = chain.call('validateaddress',recipient['address'])
        outputs = [o for o in tx['outputs'] if o['script'] == address.get('scriptPubKey')]
        if len(outputs) != 1 or outputs[0]['amount_sat'] != recipient['amount_sat']:
            raise ValueError('ramp recipient funding differs from actual chain output')
        action = store.db.execute("SELECT * FROM action WHERE actor_id=? AND operation='board' AND state='completed' AND created_at>=? ORDER BY created_at",
                                 (recipient['actor'],declaration['started_at'])).fetchall()
        boards = []
        for board in action:
            coins = store.db.execute("SELECT coin_id FROM coin_observation WHERE action_id=?",(board['id'],)).fetchall()
            signed = [_signed_coin(store,c[0],recipient['actor']) for c in coins]
            if signed and all(c is not None for c in signed):
                boards.append({'action_id':board['id'],'coin_ids':[c[0]['id'] for c in signed]})
        if not boards:
            raise ValueError('ramp actor lacks independently signed confirmed board evidence')
        receipts.append({'actor':recipient['actor'],'funding_vout':outputs[0]['vout'],'boards':boards})
    participating_rails = set()
    for observation in store.db.execute('SELECT rail,verified_at,proof FROM final_traffic WHERE verified_at>=?',(funding['updated_at'],)):
        if set(json.loads(observation['proof']).get('participants',[])) & actors:
            participating_rails.add(observation['rail'])
    if 'ark' not in participating_rails or not participating_rails.intersection({'internal_lightning','external_lightning'}):
        raise ValueError('funded ramp requires real post-funding Ark and Lightning activity involving added clients')
    proof = {'epoch_id':declaration['id'],'pins':declaration['pins'],'funding_txid':tx['txid'],
             'funding_fee_sat':tx['fee_sat'],'actors':receipts,'total_clients':24}
    encoded = canonical(proof)
    with store.transaction():
        prior = store.db.execute("SELECT payload FROM event WHERE kind='final_ramp_verified'").fetchone()
        if prior:
            if prior[0] != encoded:
                raise ValueError('verified ramp evidence changed')
            return False
        store._event('final_ramp_verified',proof)
    return True


def collect_traffic(store, observed_pins, limit=32):
    """Bounded fair retry of existing proof events, never a monetary operation."""
    if not pins_match(store,observed_pins):
        return 0
    integer(limit,'final traffic batch',1)
    if limit > 64:
        raise ValueError('final traffic batch exceeds bound')
    after=int(store.get_meta('final_traffic_cursor') or '0')
    query="""SELECT e.sequence,e.kind,e.payload FROM event e
        WHERE e.kind IN ('ark_transfer_verified','client_fee_reconciled','controlled_peer_payment_verified')
        AND e.observed_at>=? AND NOT EXISTS(SELECT 1 FROM final_traffic t WHERE t.source_sequence=e.sequence)"""
    start=epoch(store)['started_at']
    rows=store.db.execute(query+' AND e.sequence>? ORDER BY e.sequence LIMIT ?',(start,after,limit)).fetchall()
    if len(rows)<limit:
        rows+=store.db.execute(query+' AND e.sequence<=? ORDER BY e.sequence LIMIT ?',(start,after,limit-len(rows))).fetchall()
    accepted=0
    kinds={'ark_transfer_verified':'ark','client_fee_reconciled':'internal_lightning',
           'controlled_peer_payment_verified':'external_lightning'}
    for row in rows:
        proof=json.loads(row['payload'])
        try:
            accepted+=int(record_traffic(store,kinds[row['kind']],proof['action_id'],row['sequence'],observed_pins))
        except (ValueError,KeyError):
            # Missing recipient or peer evidence remains unqualified. A later
            # original proof may resolve it; no invoice/payment is retried.
            pass
        store.db.execute("INSERT OR REPLACE INTO meta VALUES ('final_traffic_cursor',?)",(str(row['sequence']),))
    return accepted

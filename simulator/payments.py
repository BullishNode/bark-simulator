"""Observe initiated Lightning sends without reopening absent clients or retrying.

The native adapter validates the preimage against the frozen payment hash.
Success is payment evidence only; fee reserves remain until separate accounting
proves the customer charge. A timeout never implies failure or authorizes refund.
"""
import json
import time

from .model import InvariantError, canonical, public_payload
from .ownership import EvidenceGap
from .process import json_command, public_command_capture


def payment_hash(store, action):
    data = json.loads(action['result'])['data']
    value = data.get('payment_hash')
    if not isinstance(value, str) or len(value) != 64:
        raise EvidenceGap('initiated payment lacks a valid hash')
    try:
        if len(bytes.fromhex(value)) != 32:
            raise ValueError()
    except ValueError:
        raise EvidenceGap('initiated payment hash is malformed') from None
    proposals = store.db.execute("""SELECT payload FROM event
        WHERE kind='driver_evidence' AND json_extract(payload,'$.action_id')=?
        AND json_extract(payload,'$.event')='lightning_proposal'""", (action['id'],)).fetchall()
    if len(proposals) != 1:
        raise EvidenceGap('payment has no unique frozen proposal')
    proposal = json.loads(proposals[0]['payload'])['data']
    if proposal.get('payment_hash') != value:
        raise InvariantError('payment result differs from its frozen hash')
    return value


def record_status(store, action, expected_hash, response, query_id):
    public_payload(response)
    if response.get('action_id') != query_id:
        raise InvariantError('payment observation has another query identity')
    if response.get('status') == 'incident':
        raise InvariantError('native payment status failed its protocol checks')
    if response.get('status') != 'ok':
        raise EvidenceGap('payment status is unavailable')
    data = response.get('data', {})
    if (data.get('payment_hash') != expected_hash or data.get('read_only') is not True
            or type(response.get('actual_fee_sat')) is not int or response['actual_fee_sat'] != 0):
        raise InvariantError('payment observation identity or read-only cost differs')
    state = data.get('state')
    if state not in {'pending', 'failed', 'succeeded'}:
        raise InvariantError('payment observation has an unsupported state')
    if data.get('success_preimage_hash_valid') is not (state == 'succeeded'):
        raise InvariantError('payment success lacks native preimage verification')
    result = json.loads(action['result'])
    previous = result['data'].get('payment_state')
    if previous in {'failed', 'succeeded'} and previous != state:
        raise InvariantError('terminal payment evidence changed')
    if previous == state and result['data'].get('payment_status_verified') is True:
        return
    result['data'].update(payment_state=state, payment_status_verified=True, paid=state == 'succeeded')
    with store.transaction():
        # Preserve the initiation, actor state and fee reservation. Only the first
        # observed success changes the customer-activity timestamp.
        store.db.execute('UPDATE action SET result=?,updated_at=? WHERE id=?',
            (canonical(result), time.time() if state == 'succeeded' else action['updated_at'], action['id']))
        store._event('lightning_payment_outcome', {'action_id': action['id'],
            'payment_hash': expected_hash, 'state': state, 'response': response,
            'fee_reservation_released': False, 'absent_wallet_opened': False})


async def collect(store, driver_command, server_pubkey, limit=2):
    rows = store.db.execute("""SELECT * FROM action WHERE operation='pay_invoice'
        AND state='completed' AND json_extract(result,'$.data.initiated')=1
        AND COALESCE(json_extract(result,'$.data.payment_state'),'pending')='pending'
        ORDER BY id""").fetchall()
    after = store.get_meta('payment_status_cursor') or ''
    rows = [r for r in rows if r['id'] > after] + [r for r in rows if r['id'] <= after]
    for action in rows[:limit]:
        try:
            value = payment_hash(store, action)
            query_id = 'payment-status:' + action['id']
            request = {'operation': 'lightning_payment_status', 'action_id': query_id,
                'actor_dir': None, 'expected_server_pubkey': server_pubkey,
                'maximum_fee_sat': 0, 'args': {'payment_hash': value}}
            response = await json_command(list(driver_command), request, timeout=15, **public_command_capture(store,'payment.status',request,action_id=action['id']))
            record_status(store, action, value, response, query_id)
        except InvariantError:
            raise
        except Exception as error:
            store.event('lightning_payment_evidence_pending', {'action_id': action['id'],
                'reason': type(error).__name__, 'refund_authorized': False})
        finally:
            store.db.execute("INSERT OR REPLACE INTO meta VALUES ('payment_status_cursor',?)", (action['id'],))

"""Rotate bounded polls of existing receive checkpoints without retrying sends."""
import json


def sync_args(store, actor):
    row = store.db.execute("""SELECT state,result FROM action WHERE actor_id=?
        AND operation='sync' ORDER BY created_at DESC,id DESC LIMIT 1""", (actor,)).fetchone()
    if row is None or row['state'] != 'completed' or not row['result']:
        return {}
    data = json.loads(row['result']).get('data', {})
    if data.get('bounded_receive_sync') is not True:
        return {}
    before = data.get('receive_payment_hashes_before')
    selected = data.get('selected_receive_payment_hashes')
    def hashes(value, bound):
        return (isinstance(value, list) and 0 < len(value) <= bound
                and all(isinstance(h, str) and len(h) == 64
                        and all(c in '0123456789abcdef' for c in h) for h in value)
                and len(set(value)) == len(value))
    if not hashes(before, 1024) or not hashes(selected, 32) or not set(selected) <= set(before):
        return {}
    return {'receive_sync_start_after': selected[-1]}


def queue_payment_receiver(store, config, payment, payment_hash):
    """One exact-hash action alongside the frozen payer proposal; no replay."""
    from .model import InvariantError
    actor=payment['args'].get('recipient_actor')
    invoice_id=payment['args'].get('recipient_invoice_action')
    if not actor or not invoice_id:return None
    invoice=store.db.execute("SELECT actor_id,state,result FROM action WHERE id=? AND operation='invoice'",(invoice_id,)).fetchone()
    if (invoice is None or invoice['actor_id']!=actor or invoice['state']!='completed'
            or json.loads(invoice['result'] or '{}').get('data',{}).get('payment_hash')!=payment_hash):
        raise InvariantError('receiver hash differs from the original frozen invoice')
    action_id='receive-drive:'+payment['id']
    if store.db.execute('SELECT 1 FROM action WHERE id=?',(action_id,)).fetchone():return None
    if not store.online(actor) or not store.ordinary_actor_available(actor):return None
    if store.db.execute("SELECT 1 FROM action WHERE actor_id=? AND state IN ('queued','dispatched','outcome_unknown')",(actor,)).fetchone():return None
    store.queue(action_id,actor,'H40','sync',{'receive_payment_hash':payment_hash,
        'payer_action_id':payment['id'],'recipient_invoice_action':invoice_id},config.action_fee_reserve_sat)
    return store.claim({'sync'},action_id=action_id)

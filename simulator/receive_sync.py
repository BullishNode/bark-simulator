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

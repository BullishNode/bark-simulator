"""Explicit SDK rotation after a checked payout; no new address on retry."""
import hashlib,json,re
from contextlib import nullcontext
from .model import canonical,public_payload
from .ownership import EvidenceGap


def queue_rotation(store,config,actor,new_script):
    if getattr(config,'network',None)!='signet':raise EvidenceGap('explicit signet declaration required')
    if actor in {'actor-03','actor-09','actor-10'}:raise EvidenceGap('original absent wallet must remain closed')
    user=store.db.execute('SELECT online,details FROM actor WHERE id=?',(actor,)).fetchone()
    if user is None or not user['online'] or json.loads(user['details']).get('permanent_absence'):
        raise EvidenceGap('rotation requires an online non-absent actor')
    if store.get_meta('paused'):raise EvidenceGap('campaign paused')
    if not isinstance(new_script,str) or re.fullmatch(r'(0014[0-9a-f]{40}|0020[0-9a-f]{64}|5120[0-9a-f]{64}|76a914[0-9a-f]{40}88ac|a914[0-9a-f]{40}87)',new_script) is None:
        raise ValueError('declared standard fallback script required')
    record=store.db.execute('SELECT * FROM owner_record WHERE actor=? ORDER BY seq DESC LIMIT 1',(actor,)).fetchone()
    if record is None:raise EvidenceGap('independently verified original signed record missing')
    if record['script']==new_script:raise EvidenceGap('rotation must declare another owned destination')
    payouts=[dict(r) for r in store.db.execute('SELECT coin_id,txid,actor,script,amount_sat FROM checked_settlement WHERE actor=? AND script=? ORDER BY coin_id',(actor,record['script']))]
    if not payouts:raise EvidenceGap('rotation requires a checked payout to the original destination')
    intent={'schema_version':1,'actor':actor,'server_pubkey':config.expected_server_pubkey,'network':'signet',
        'mailbox':record['mailbox'],'old_script':record['script'],'old_sequence':record['seq'],
        'new_script':new_script,'checked_original_payouts':payouts,'maximum_fee_sat':0,
        'sdk_must_verify_owned_script':True,'automatic_retry':False,'production_qualified':False}
    public_payload(intent);digest=hashlib.sha256(canonical(intent).encode()).hexdigest();identity='fallback-rotate-'+digest
    old=store.db.execute('SELECT id,args FROM action WHERE id=?',(identity,)).fetchone()
    if old:return {'action_id':identity,'intent_hash':digest}
    if store.db.execute("SELECT 1 FROM action WHERE actor_id=? AND state IN ('queued','dispatched','outcome_unknown')",(actor,)).fetchone():
        raise EvidenceGap('owner has a busy or unknown action')
    with (nullcontext() if store.db.in_transaction else store.transaction()):
        store.queue(identity,actor,'H29','fallback_rotate',{'rotation_intent':intent,'intent_hash':digest},0)
        store._event('fallback_rotation_intent',{'action_id':identity,'intent_hash':digest,**intent})
    return {'action_id':identity,'intent_hash':digest}

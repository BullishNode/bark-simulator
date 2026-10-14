"""Explicit immutable-record check after a payout; no destination rotation."""
import hashlib,json
from .model import canonical,public_payload
from .ownership import EvidenceGap

def queue_check(store,config,actor):
    if getattr(config,'network',None)!='signet':raise EvidenceGap('explicit signet declaration required')
    if actor in {'actor-03','actor-09','actor-10'}:raise EvidenceGap('original absent wallet must remain closed')
    user=store.db.execute('SELECT online,details FROM actor WHERE id=?',(actor,)).fetchone()
    if user is None or not user['online'] or json.loads(user['details']).get('permanent_absence'):
        raise EvidenceGap('record check requires an online non-absent owner')
    if store.get_meta('paused'):raise EvidenceGap('campaign paused')
    record=store.db.execute('SELECT * FROM owner_record WHERE actor=?',(actor,)).fetchone()
    if record is None:raise EvidenceGap('independently verified immutable record missing')
    raw=json.loads(record['proof']).get('fallback_record')
    if not isinstance(raw,str) or not raw:raise EvidenceGap('exact authenticated canonical record required')
    payouts=[dict(r) for r in store.db.execute('SELECT coin_id,txid,actor,script,amount_sat FROM checked_settlement WHERE actor=? AND script=? AND amount_sat>0 ORDER BY coin_id LIMIT 16',(actor,record['script']))]
    if not payouts:raise EvidenceGap('record check requires a checked payout to index0')
    terms={'actor':actor,'server_pubkey':config.expected_server_pubkey,'fallback_record':raw,'account_xpub':record['account_xpub'],'fallback_script':record['script'],'checked_payouts':payouts}
    public_payload(terms);digest=hashlib.sha256(canonical(terms).encode()).hexdigest();identity='immutable-check-'+digest
    if store.db.execute('SELECT 1 FROM action WHERE id=?',(identity,)).fetchone():return {'action_id':identity,'intent_hash':digest}
    if store.db.execute("SELECT 1 FROM action WHERE actor_id=? AND state IN ('queued','dispatched','outcome_unknown')",(actor,)).fetchone():raise EvidenceGap('owner has a busy or unknown action')
    store.queue(identity,actor,'H29','fallback_record_check',{'fallback_record':raw,'phase':'start'},0)
    store.event('immutable_record_check_intent',{'action_id':identity,'intent_hash':digest,**terms})
    return {'action_id':identity,'intent_hash':digest}

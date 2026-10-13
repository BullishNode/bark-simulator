"""Positive pool evidence for new Lightning work, never a coin reservation."""
import time

def ready(snapshot, amount_sat):
    if type(amount_sat) is not int or amount_sat<=0:return False
    status=snapshot.get('pool_status') or {}
    identity=snapshot.get('identity') or {}
    observed=status.get('observed_at');pool=status.get('pool') or {}
    margin=status.get('pool_pre_expiry_blocks');expiry=pool.get('minimum_eligible_expiry_height')
    height=snapshot.get('height')
    return (status.get('schema_version')==1 and status.get('complete') is True
        and status.get('stable_tip') is True and type(observed) in (int,float)
        and 0<=time.time()-observed<=90
        and status.get('genesis')==identity.get('genesis') and bool(identity.get('genesis'))
        and status.get('server_pubkey')==identity.get('server_pubkey') and bool(identity.get('server_pubkey'))
        and type(height) is int and status.get('height')==height
        and status.get('tip_hash')==snapshot.get('tip_hash') and bool(snapshot.get('tip_hash'))
        and type(margin) is int and margin>=0 and type(expiry) is int and expiry>height+margin
        and type(pool.get('confirmed_eligible_count')) is int and pool['confirmed_eligible_count']>0
        and type(pool.get('confirmed_eligible_amount_sat')) is int and pool['confirmed_eligible_amount_sat']>=amount_sat)

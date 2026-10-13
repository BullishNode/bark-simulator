"""Private enrollment requests bound to independently declared phone identities."""
from pathlib import Path
from .noah import _actor
import re

SDK_COMMIT='8f2286ee7e1631b0ceccd1631ec3b728a1bb0a52'

def enrollment_request(*,identifier,actor,wallet,phone,chain,k1,expiry):
    if not isinstance(identifier,str) or not re.fullmatch('[A-Za-z0-9_-]{1,100}',identifier):raise ValueError('explicit setup identity required')
    if (not isinstance(actor,str) or _actor(actor)!=actor
            or phone.get('actor')!=actor):raise ValueError('new declared phone identity differs')
    wallet=Path(wallet)
    if (not wallet.is_absolute() or wallet.name!=actor or not wallet.is_dir()
            or any(p.is_symlink() for p in (wallet,*wallet.parents))):raise ValueError('new phone wallet path differs')
    if chain.get('network')!='signet' or chain.get('phone_sdk_commit')!=SDK_COMMIT:raise ValueError('independently qualified signet SDK required')
    for key in ('auth_pubkey','mailbox_id'):
        if not isinstance(phone.get(key),str) or not re.fullmatch('(02|03)[0-9a-f]{64}',phone[key]):raise ValueError('declared public phone key differs')
    if not isinstance(chain.get('server_pubkey'),str) or not re.fullmatch('(02|03)[0-9a-f]{64}',chain['server_pubkey']):raise ValueError('server identity differs')
    if not isinstance(phone.get('ark_address'),str) or not 1<=len(phone['ark_address'])<=4096:raise ValueError('declared Ark destination required')
    script=phone.get('fallback_script')
    if not isinstance(script,str) or not re.fullmatch('(0014[0-9a-f]{40}|0020[0-9a-f]{64}|5120[0-9a-f]{64})',script):raise ValueError('declared owned witness fallback required')
    if not isinstance(k1,str) or not re.fullmatch('[0-9a-f]{64}_[0-9]{1,20}',k1):raise ValueError('original issued challenge required')
    if type(expiry) is not int or not 0<expiry<2**63:raise ValueError('bounded mailbox expiry required')
    return {'protocol':'noah-private-v1','operation':'enrollment_material','actor':actor,'action_id':identifier,
        'wallet_path':str(wallet),'k1':k1,'expiry_unix':expiry,'expected_sdk_commit':SDK_COMMIT,
        'expected_server_pubkey':chain['server_pubkey'],'expected_ark_address':phone['ark_address'],
        'expected_fallback_script':script,'expected_auth_pubkey':phone['auth_pubkey'],'expected_mailbox_id':phone['mailbox_id']}

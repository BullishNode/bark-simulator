"""Synthetic account metadata for pipeline tests, never cryptographic/live proof.

These factories model the native verifier's new output contract. Tests of the
native signatures use real Rust keys; qualification never imports this module.
"""
def coin(value):
    return {'child_index':0,'blinded_mailbox_id':'02'+'11'*32,**{k:v for k,v in value.items() if k!='key_link_attestation'}}
def binding(value):
    result={k:v for k,v in value.items() if k not in {'seq','record_attestation','key_link_signature_valid'}}
    return {'account_xpub':'synthetic-account','fallback_record':'03'+'11'*230,**result}
def proof(value):
    result=dict(value);bound=binding(value.get('binding',{}))
    result['binding']={'record_signature_valid':True,'account_child_verified':True,
        'child_index':0,'blinded_mailbox_id':'02'+'11'*32,'policy_pubkey_full':value.get('user_pubkey'),**bound}
    return result

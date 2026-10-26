"""Current public proof envelopes. Only the pinned native SDK verifies signatures."""
OPERATIONS = frozenset({'create','snapshot','address','sync','board','send_arkoor','refresh','refresh_delegated','offboard_all'})
SDK_COMMIT = '8b356f8ae966e206204301b169f1d1169520d554'


def binding_matches(bound, source):
    return (not any(k in bound or k in source for k in ('account_xpub', 'seq', 'account_child_verified'))
            and all(isinstance(bound.get(k), str) and bound[k] and bound[k] == source.get(k)
                    for k in ('mailbox_pk', 'spk', 'fallback_record', 'server_mailbox_pubkey')))


def record_envelope(binding):
    if not binding_matches(binding, binding):
        raise ValueError('current SDK registration required')
    # Opaque SDK encoding: Python does not decode protocol records or signatures.
    for field in ('mailbox_pk', 'spk', 'fallback_record', 'server_mailbox_pubkey'):
        value = binding[field]
        if len(value) > 512 or len(value) % 2 or any(c not in '0123456789abcdef' for c in value):
            raise ValueError('bounded public encoding required')
    return binding


def proof_matches(proof, source):
    bound = proof.get('binding', {})
    return (bound.get('record_signature_valid') is True
            and bound.get('owner_link_signature_valid') is True
            and bound.get('record_version') == 4
            and bound.get('policy_pubkey_full') == source.get('user_pubkey') == proof.get('user_pubkey')
            and binding_matches(bound, bound)
            and isinstance(bound.get('owner_link'), str) and bool(bound['owner_link'])
            and ('owner_link' not in source or source['owner_link'] == bound['owner_link']))

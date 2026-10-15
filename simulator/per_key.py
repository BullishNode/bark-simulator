"""Canonical C public envelopes; signature validation belongs to the native verifier.

These shape checks never establish ownership, funded backing or a payment.
The record is immutable; the optional signed index is recovery metadata only.
"""
import re


def raw_hex(value, length=None):
    if (not isinstance(value, str) or not value or len(value) % 2
            or re.fullmatch('[0-9a-f]+', value) is None
            or length is not None and len(value) != length * 2):
        raise ValueError('noncanonical public per-key encoding')
    return bytes.fromhex(value)


def record_bytes(record):
    if set(record) != {'mailbox_pk', 'spk', 'mailbox_sig'}:
        raise ValueError('C record requires immutable mailbox/script signature only')
    mailbox = raw_hex(record['mailbox_pk'], 33)
    if mailbox[0] not in (2, 3):
        raise ValueError('compressed mailbox required')
    script = raw_hex(record['spk'])
    if not 22 <= len(script) <= 42:
        raise ValueError('bounded address script required')
    signature = raw_hex(record['mailbox_sig'], 64)
    return (b'\x04' + bytes([len(script)]) + script + signature).hex()


def link_bytes(link):
    if set(link) != {'user_pubkey', 'mailbox_pk', 'sig', 'recovery_index'}:
        raise ValueError('complete retained per-key signature required')
    key = raw_hex(link['user_pubkey'], 33)
    mailbox = raw_hex(link['mailbox_pk'], 33)
    if key[0] not in (2, 3) or mailbox[0] not in (2, 3):
        raise ValueError('compressed public identities required')
    index = link['recovery_index']
    if index is None:
        hint = b'\x00'
    elif type(index) is int and 0 <= index < 2**31:
        hint = b'\x01' + index.to_bytes(4, 'little')
    else:
        raise ValueError('invalid optional signed recovery index')
    return (b'\x01' + key + hint + raw_hex(link['sig'], 64)).hex()


def binding_matches(bound, source):
    return (not any(k in bound or k in source for k in ('account_xpub', 'account_child_verified', 'seq'))
        and all(isinstance(bound.get(k), str) and bound[k] and bound[k] == source.get(k)
                for k in ('mailbox_pk', 'spk', 'fallback_record')))


def proof_matches(proof, source):
    bound = proof.get('binding', {})
    if (bound.get('record_signature_valid') is not True
            or bound.get('key_link_signature_valid') is not True
            or type(bound.get('record_version')) is not int or bound['record_version'] != 4
            or type(bound.get('key_link_version')) is not int or bound['key_link_version'] != 1
            or any(k in bound for k in ('account_xpub', 'account_child_verified', 'seq'))
            or proof.get('user_pubkey') != source.get('user_pubkey')
            or bound.get('policy_pubkey_full') != source.get('user_pubkey')):
        return False
    try:
        encoded = raw_hex(bound.get('key_link_attestation'))
        key = raw_hex(source['user_pubkey'], 33)
        if len(encoded) not in (99, 103) or encoded[:34] != b'\x01' + key:
            return False
        marker = encoded[34]
        index = None if marker == 0 and len(encoded) == 99 else (
            int.from_bytes(encoded[35:39], 'little') if marker == 1 and len(encoded) == 103 else -1)
        if index is not None and not 0 <= index < 2**31:
            return False
        if bound.get('recovery_index') != index:
            return False
        if 'key_link_attestation' in source and source['key_link_attestation'] != encoded.hex():
            return False
        record = raw_hex(bound.get('fallback_record'))
        script = raw_hex(bound.get('spk'))
        if record != b'\x04' + bytes([len(script)]) + script + record[-64:]:
            return False
        raw_hex(bound.get('mailbox_pk'), 33)
    except (ValueError, KeyError, TypeError, OverflowError):
        return False
    return True

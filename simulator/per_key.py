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


def record_envelope(binding):
    """Check canonical public shape only, without claiming a valid signature."""
    script = raw_hex(binding['spk'])
    record = raw_hex(binding['fallback_record'])
    mailbox = raw_hex(binding['mailbox_pk'],33)
    if (not 22 <= len(script) <= 42 or mailbox[0] not in (2,3)
            or len(record) != 2 + len(script) + 64
            or record[:2] != b'\x04' + bytes([len(script)])
            or record[2:2+len(script)] != script):
        raise ValueError('canonical V4 public record required')
    return record


def initial_origins(data):
    """The pinned native create exports existing indices, never new addresses."""
    binding = data.get('binding', {})
    record_envelope(binding)
    rows = data.get('initial_key_links')
    if not isinstance(rows, list) or len(rows) != 51:
        raise ValueError('exact 51 original C key acknowledgements required')
    return prefix_origins(binding,rows,50)


def prefix_origins(binding,rows,maximum):
    record_envelope(binding)
    if not isinstance(rows,list) or len(rows)!=maximum+1:
        raise ValueError('complete original native key prefix required')
    keys = set()
    for index, row in enumerate(rows):
        if (not isinstance(row, dict) or set(row) != {'native_index','origin'}
                or type(row['native_index']) is not int or row['native_index'] != index):
            raise ValueError('ordered original C indices 0 through 50 required')
        origin = row['origin']
        if (not isinstance(origin, dict) or set(origin) != {'user_pubkey','key_link_attestation','binding'}
                or not binding_matches(binding, origin['binding'])):
            raise ValueError('initial C acknowledgement binding differs')
        key = raw_hex(origin['user_pubkey'], 33)
        wire = raw_hex(origin['key_link_attestation'], 103)
        if (key[0] not in (2,3) or origin['user_pubkey'] in keys
                or wire[:35] != b'\x01' + key + b'\x01'
                or int.from_bytes(wire[35:39], 'little') != index):
            raise ValueError('initial C key or signed native recovery index differs')
        keys.add(origin['user_pubkey'])
    return [row['origin'] for row in rows]


def retained_origins(frame):
    fields={'schema_version','scope','last_issued_index','maximum_index','binding','rows'}
    if (not isinstance(frame,dict) or set(frame)!=fields or type(frame['schema_version']) is not int
            or frame['schema_version']!=1 or frame['scope']!='fresh_synced_native_prefix'
            or type(frame['last_issued_index']) is not int or not 0<=frame['last_issued_index']<78
            or type(frame['maximum_index']) is not int or frame['maximum_index']!=frame['last_issued_index']+50):
        raise ValueError('bounded original fresh synced C prefix required')
    return prefix_origins(frame['binding'],frame['rows'],frame['maximum_index'])


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
        record_envelope(bound)
    except (ValueError, KeyError, TypeError, OverflowError):
        return False
    return True

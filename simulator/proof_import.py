"""Import declared public coin bundles without opening any original wallet.

[proofs] bundles = ["/absolute/path/public-proof-bundle.json"]
Bundle v1: {schema_version: 1, actor: "actor-09", identity: {network,
genesis, server_pubkey}, coins: [{id, user_pubkey, amount_sat, expiry_height,
signed_vtxo, key_link_attestation, binding: {mailbox_pk, seq, spk,
record_attestation}}]}. Native audit summaries alone are not input proofs.

Imports prove signatures and confirmed backing, never live spendability,
customer traffic, payout arbitration, or seed recovery. Native validation runs
on every not-yet-imported bundle even when an ownership proof is cached.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path

from .model import InvariantError, canonical, integer, public_payload
from .ownership import EvidenceGap, record_candidates, record_verified
from .process import json_command, public_command_capture

MAX_BYTES = 2_097_152
MAX_COINS = 16


def _public(value):
    public_payload(value)
    if isinstance(value, dict):
        for item in value.values(): _public(item)
    elif isinstance(value, list):
        for item in value: _public(item)
    elif isinstance(value, str):
        words = value.split()
        if (re.search(r'\b(?:xprv|tprv|__cookie__:)', value)
                or (len(words) in (12, 24) and all(re.fullmatch('[a-z]+', w) for w in words))):
            raise ValueError('secret-shaped value is forbidden in public evidence')


def declared_paths(values, wallet_root):
    if not isinstance(values, (list, tuple)) or len(values) > 64:
        raise ValueError('proof bundles must be a bounded local path array')
    paths = []
    wallet_root = Path(wallet_root).absolute()
    for value in values:
        if not isinstance(value, (str, Path)):
            raise ValueError('proof bundle path must be local')
        raw = str(value)
        path = Path(raw).expanduser()
        if ('://' in raw or not path.is_absolute() or '..' in path.parts
                or path.suffix != '.json' or path.is_relative_to(wallet_root)):
            raise ValueError('proof bundle requires an absolute public JSON path outside wallets')
        if path in paths:
            raise ValueError('duplicate proof bundle declaration')
        paths.append(path)
    return tuple(paths)


def _read(path):
    """Do not follow any symlink or block on special files, including parents."""
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            following = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=descriptor)
            os.close(descriptor); descriptor = following
        following = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                            dir_fd=descriptor)
        with os.fdopen(following, 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_BYTES:
                raise ValueError('public bundle must be a bounded regular file')
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError('public bundle exceeds input bound')
        return json.loads(raw)
    finally:
        os.close(descriptor)


def _hex(value, size=None):
    if (not isinstance(value, str) or not value or len(value) % 2
            or re.fullmatch('[0-9a-f]+', value) is None
            or (size is not None and len(value) != size)):
        raise EvidenceGap('public encoding is missing or malformed')


def _bundle(store, config, value):
    _public(value)
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'actor', 'identity', 'coins'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1):
        raise EvidenceGap('complete raw public proof bundle is required')
    expected = {'network': config.network, 'genesis': config.expected_genesis,
                'server_pubkey': config.expected_server_pubkey}
    if value['identity'] != expected:
        raise EvidenceGap('public proof target differs from declared identity')
    bound = store.get_meta('target_identity')
    if bound is not None and any(json.loads(bound).get(k) != v for k, v in expected.items()):
        raise InvariantError('proof config differs from frozen target identity')
    actor = value['actor']
    if not isinstance(actor, str) or re.fullmatch(r'actor-\d{2}', actor) is None:
        raise EvidenceGap('public proof actor is invalid')
    row = store.db.execute('SELECT details FROM actor WHERE id=?', (actor,)).fetchone()
    if row is None:
        raise EvidenceGap('public proof actor is undeclared')
    details = json.loads(row[0])
    mailboxes = {r[0] for r in store.db.execute('SELECT DISTINCT mailbox FROM owner_key WHERE actor=?', (actor,))}
    for field in ('binding', 'advertised_key_proof'):
        binding = details.get(field, {})
        if field == 'advertised_key_proof': binding = binding.get('binding', {})
        if binding.get('mailbox_pk'): mailboxes.add(binding['mailbox_pk'])
    if len(mailboxes) != 1:
        raise EvidenceGap('public proof requires an unambiguous previously recorded actor mailbox')
    coins = value['coins']
    if not isinstance(coins, list) or not 1 <= len(coins) <= MAX_COINS:
        raise EvidenceGap('public proof bundle needs bounded complete coins')
    ids = []
    for coin in coins:
        fields = {'id', 'user_pubkey', 'amount_sat', 'expiry_height', 'signed_vtxo',
                  'key_link_attestation', 'binding'}
        if not isinstance(coin, dict) or set(coin) != fields:
            raise EvidenceGap('raw coin signatures and binding are required')
        if not isinstance(coin['id'], str) or re.fullmatch(r'[0-9a-f]{64}:\d+', coin['id']) is None:
            raise EvidenceGap('public coin identity is malformed')
        ids.append(coin['id'])
        integer(coin['amount_sat'], 'public principal', 1)
        integer(coin['expiry_height'], 'public expiry', 1)
        _hex(coin['signed_vtxo']); _hex(coin['key_link_attestation'], 128)
        _hex(coin['user_pubkey'], 66)
        if coin['user_pubkey'][:2] not in {'02', '03'}:
            raise EvidenceGap('public coin key is malformed')
        binding = coin['binding']
        if not isinstance(binding, dict) or set(binding) != {'mailbox_pk', 'seq', 'spk', 'record_attestation'}:
            raise EvidenceGap('raw signed owner record is required')
        if binding['mailbox_pk'] not in mailboxes:
            raise EvidenceGap('public coin mailbox does not belong to declared actor')
        _hex(binding['mailbox_pk'], 66); _hex(binding['spk'], 44)
        if not binding['spk'].startswith('0014'):
            raise EvidenceGap('public record is not the supported BIP84 destination')
        integer(binding['seq'], 'public record sequence')
        _hex(binding['record_attestation'], 128)
    if len(ids) != len(set(ids)):
        raise EvidenceGap('duplicate coin in public proof bundle')
    return actor, coins


def _checked(config, coin, proof):
    _public(proof)
    bound = proof.get('binding', {})
    integer(proof.get('amount_sat'), 'native public principal', 1)
    integer(proof.get('expiry_height'), 'native public expiry', 1)
    integer(bound.get('seq'), 'native owner sequence')
    if (any(proof.get(k) != coin[k] for k in ('id', 'user_pubkey', 'amount_sat', 'expiry_height'))
            or proof.get('genesis') != config.expected_genesis
            or proof.get('server_pubkey') != config.expected_server_pubkey
            or proof.get('signed_path_valid') is not True
            or type(proof.get('anchor_confirmations')) is not int or proof['anchor_confirmations'] < 1
            or any(bound.get(k) != coin['binding'][k] for k in ('mailbox_pk', 'seq', 'spk'))
            or bound.get('record_signature_valid') is not True
            or bound.get('key_link_signature_valid') is not True):
        raise EvidenceGap('native public proof does not validate the exact declared coin and owner')
    return {'kind': 'coin', 'coin': {**coin, 'state': 'PublicProof'}, 'proof': proof,
        'signed_hash': hashlib.sha256(bytes.fromhex(coin['signed_vtxo'])).hexdigest(),
        'request_binding': coin['binding']}


def _pending(store, source_id, reason):
    key = 'public_proof_pending_' + source_id
    if store.get_meta(key) == reason:
        return
    with store.transaction():
        store.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', (key, reason))
        store._event('public_proof_import_pending', {'source_id': source_id, 'reason': reason,
                     'original_wallet_opened': False})


async def collect(store, config, *, paths=None, limit=2):
    """Retry declared incomplete public evidence; commit complete bundles atomically."""
    paths = config.proof_bundles if paths is None else paths
    if not paths:
        return 0
    integer(limit, 'public import batch', 1)
    after = int(store.get_meta('public_proof_import_cursor') or '0') % len(paths)
    ordered = list(paths[after:]) + list(paths[:after])
    imported = 0
    for raw_path in ordered[:limit]:
        source_id = hashlib.sha256(str(raw_path).encode()).hexdigest()
        try:
            path = declared_paths([raw_path], config.wallet_root)[0]
            value = _read(path)
            actor, coins = _bundle(store, config, value)
            content_hash = hashlib.sha256(canonical(value).encode()).hexdigest()
            identity = 'public-proof-import-' + content_hash
            existing = store.db.execute('SELECT * FROM action WHERE id=?', (identity,)).fetchone()
            if existing is not None:
                if (existing['operation'] != 'public_proof_import' or existing['state'] != 'completed'
                        or existing['actor_id'] != actor
                        or json.loads(existing['args']).get('content_sha256') != content_hash):
                    raise InvariantError('public import identity has a conflicting action')
                store.db.execute('DELETE FROM meta WHERE key=?', ('public_proof_pending_' + source_id,))
                continue
            if not config.proof_command:
                raise EvidenceGap('independent native verifier is not configured')
            objects = []
            for coin in coins:
                proof = await json_command(list(config.proof_command), coin, timeout=30, **public_command_capture(store,'proof.import',coin,actor=actor,action_id=identity))
                objects.append(_checked(config, coin, proof))
            with store.transaction():
                at = time.time()
                store.db.execute("""INSERT INTO action VALUES (?,?,NULL,?,?,'completed',?,0,0,?,?,?)""",
                    (identity, actor, 'public_proof_import', canonical({'content_sha256': content_hash}),
                     at, canonical({'data': {'public_proof_import': True, 'coin_ids': [c['id'] for c in coins]}}), at, at))
                # No actor-state mutation, movement evidence, or live-spendability
                # claim. Retain the exact public signatures for later independent audit.
                for item in objects:
                    old = store.db.execute('SELECT * FROM owned_coin WHERE id=?', (item['coin']['id'],)).fetchone()
                    if old and (old['pubkey'], old['amount_sat'], old['signed_vtxo']) != (
                            item['coin']['user_pubkey'], item['coin']['amount_sat'], item['coin']['signed_vtxo']):
                        raise InvariantError('import contradicts an immutable signed coin')
                    record_candidates(store, actor, identity, {'evidence': {
                        'binding': item['request_binding'], 'coins': [item['coin']]}})
                record_verified(store, actor, identity, {'objects': objects, 'movements': []})
                store._event('public_proof_imported', {'action_id': identity, 'actor': actor,
                    'content_sha256': content_hash, 'coin_ids': [c['id'] for c in coins],
                    'original_wallet_opened': False, 'customer_traffic': False,
                    'scope': 'public signatures and confirmed backing; arbitration, sweep and recovery separate'})
                store.db.execute('DELETE FROM meta WHERE key=?', ('public_proof_pending_' + source_id,))
            imported += 1
        except InvariantError:
            raise
        except Exception as error:
            # Never expose a pathname, signature, native stderr, or secret value
            # in a failure record. Missing pieces and rejected proofs remain pending.
            reason = str(error) if isinstance(error, EvidenceGap) else type(error).__name__
            _pending(store, source_id, reason)
    store.db.execute("INSERT OR REPLACE INTO meta VALUES ('public_proof_import_cursor',?)",
                     (str((after + min(limit, len(paths))) % len(paths)),))
    return imported

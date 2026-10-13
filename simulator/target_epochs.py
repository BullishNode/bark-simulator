"""Explicit verified deployment epochs inside the original campaign.

The owner supplies a declaration only after independent qualification. Receipt
hashes identify that evidence; this module does not turn their presence into a
server qualification or permit automatic pin changes. Existing target metadata,
wallets, declarations, signed coin expiries and financial rows are never edited.
"""
from __future__ import annotations

import hashlib
import json
import re
import time

from .model import SIGNET_GENESIS, canonical, integer, public_payload, timestamp

IMMUTABLE_META = ('mode', 'fee_budget_sat', 'wallet_root', 'target_identity',
                  'fixture_funding_plan', 'owner_renewal_declaration',
                  'owner_renewal_funding_source',
                  'seed_recovery_declaration', 'campaign_seed', 'campaign_realism',
                  'ramp_plan', 'realism_started_at')
IMMUTABLE_FAMILIES = ('owner_renewal_declaration:', 'owner_renewal_funding_source:')
RECEIPTS = {'upgrade_completion', 'independent_identity', 'sdk_qualification',
            'simulator_release', 'nursery_reconciliation'}
NATIVE = {'bark-sim-driver', 'vtxo-proof', 'seed-restore'}
IDENTITY_FIELDS = {'network', 'genesis', 'container', 'image_digest', 'server_pubkey'}
FIELDS = {'id', 'previous_identity', 'identity', 'observed_at', 'sdk_commit',
          'native_hashes', 'receipt_hashes', 'ordinary_lifetime_blocks',
          'pool_lifetime_blocks', 'recovery_guard_verified',
          'pending_server_payouts_preserved', 'declaration_hashes'}
SCHEMA = '''CREATE TABLE IF NOT EXISTS target_epoch(
 sequence INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE,
 declaration TEXT NOT NULL, identity TEXT NOT NULL)'''


def declaration_hashes(store):
    return {key: hashlib.sha256(value.encode()).hexdigest()
            for key, value in store.db.execute('SELECT key,value FROM meta')
            if key in IMMUTABLE_META or key.startswith(IMMUTABLE_FAMILIES)}


def active_identity(store):
    # Registry rows are a view of the append-only financial history. Dropping
    # or editing that view must never authorize an undeclared image or rollback.
    original = store.get_meta('target_identity')
    original_event = store.db.execute("SELECT payload FROM event WHERE kind='target_manifest' ORDER BY sequence LIMIT 1").fetchone()
    if original_event and original != original_event[0]:
        raise ValueError('original target metadata differs from preserved manifest evidence')
    declarations = [row[0] for row in store.db.execute("SELECT payload FROM event WHERE kind='target_epoch_declared' ORDER BY sequence")]
    table = store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='target_epoch'").fetchone()
    rows = list(store.db.execute('SELECT sequence,id,declaration,identity FROM target_epoch ORDER BY sequence')) if table else []
    if len(rows) != len(declarations):
        raise ValueError('target epoch registry differs from preserved declaration evidence')
    current = json.loads(original) if original is not None else None
    for sequence, (row, encoded) in enumerate(zip(rows, declarations), 1):
        declaration = json.loads(encoded)
        if (row[0] != sequence or row[1] != declaration['id'] or row[2] != encoded
                or row[3] != canonical(declaration['identity'])
                or declaration['previous_identity'] != current):
            raise ValueError('target epoch registry or predecessor has changed')
        current = declaration['identity']
    return current


def _identity(value):
    if not isinstance(value, dict) or set(value) != IDENTITY_FIELDS:
        raise ValueError('epoch requires the exact declared target identity')
    if value['network'] != 'signet' or value['genesis'] != SIGNET_GENESIS:
        raise ValueError('new deployment epochs require official signet')
    if not isinstance(value['container'], str) or not value['container']:
        raise ValueError('epoch requires the existing target container')
    for field, pattern in [('image_digest', r'sha256:[0-9a-f]{64}'),
                           ('server_pubkey', r'0[23][0-9a-f]{64}')]:
        if not isinstance(value[field], str) or re.fullmatch(pattern, value[field]) is None:
            raise ValueError('epoch target pin is malformed')


def _hashes(value, required, *, key_pattern=r'[a-zA-Z0-9_-]{1,100}'):
    if (not isinstance(value, dict) or not required.issubset(value)
            or any(not isinstance(key, str) or re.fullmatch(key_pattern, key) is None
                   or not isinstance(digest, str) or re.fullmatch(r'[0-9a-f]{64}', digest) is None
                   for key, digest in value.items())):
        raise ValueError('epoch requires qualified native pins and complete evidence hashes')


def _validate(declaration):
    public_payload(declaration)
    if not isinstance(declaration, dict) or set(declaration) != FIELDS:
        raise ValueError('epoch declaration has missing or unsupported fields')
    if not isinstance(declaration['id'], str) or re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,99}', declaration['id']) is None:
        raise ValueError('epoch requires a new immutable identifier')
    _identity(declaration['previous_identity'])
    _identity(declaration['identity'])
    for field in IDENTITY_FIELDS - {'image_digest'}:
        if declaration['previous_identity'][field] != declaration['identity'][field]:
            raise ValueError('an epoch cannot change signet, server key or target host')
    if not isinstance(declaration['sdk_commit'], str) or re.fullmatch(r'[0-9a-f]{40}', declaration['sdk_commit']) is None:
        raise ValueError('epoch requires the actually qualified SDK commit')
    _hashes(declaration['native_hashes'], NATIVE)
    _hashes(declaration['receipt_hashes'], RECEIPTS)
    for field in ('ordinary_lifetime_blocks', 'pool_lifetime_blocks'):
        if integer(declaration[field], field, 1) != 48:
            raise ValueError('post-upgrade ordinary and pool lifetimes must both be48')
    if declaration['recovery_guard_verified'] is not True or declaration['pending_server_payouts_preserved'] is not True:
        raise ValueError('independent guard and pending payout reconciliation are required')
    timestamp(declaration['observed_at'], 'epoch audit time')
    _hashes(declaration['declaration_hashes'], {'mode', 'fee_budget_sat', 'target_identity', 'wallet_root'},
            key_pattern=r'[a-zA-Z0-9_:-]{1,200}')


def declare(store, declaration):
    """Record an owner-qualified transition, without unpausing or changing pins."""
    _validate(declaration)
    encoded = canonical(declaration)
    with store.transaction():
        store.db.execute(SCHEMA)
        store.db.execute("CREATE INDEX IF NOT EXISTS target_epoch_event ON event(sequence) WHERE kind='target_epoch_declared'")
        current = active_identity(store)
        previous = store.db.execute('SELECT declaration FROM target_epoch WHERE id=?', (declaration['id'],)).fetchone()
        if previous:
            if previous[0] != encoded:
                raise ValueError('target epoch declaration is immutable')
            return False
        if not 0 <= time.time() - declaration['observed_at'] <= 600:
            raise ValueError('epoch requires a fresh independent audit')
        if not store.get_meta('paused'):
            raise ValueError('pause dispatch before declaring an epoch')
        if current != declaration['previous_identity']:
            raise ValueError('epoch predecessor differs from the active deployment')
        if declaration_hashes(store) != declaration['declaration_hashes']:
            raise ValueError('original campaign declarations changed during qualification')
        if store.db.execute("SELECT 1 FROM action WHERE state IN ('dispatched','outcome_unknown') LIMIT 1").fetchone():
            raise ValueError('reconcile in-flight and unknown client actions before an epoch')
        recovery = store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='seed_recovery'").fetchone()
        if recovery and store.db.execute("SELECT 1 FROM seed_recovery WHERE state IN ('preparing','prepare_unknown','broadcasting','outcome_unknown') LIMIT 1").fetchone():
            raise ValueError('reconcile seed preparations and recovery unknowns before an epoch')
        funding = store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='funding_batch'").fetchone()
        if funding and store.db.execute("SELECT 1 FROM funding_batch WHERE state IN ('broadcasting','outcome_unknown') LIMIT 1").fetchone():
            raise ValueError('reconcile funding broadcasts and unknowns before an epoch')
        if store.db.execute("SELECT 1 FROM actor_lease WHERE state IN ('active','outcome_unknown') LIMIT 1").fetchone():
            raise ValueError('reconcile direct client controller leases before an epoch')
        private = store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='noah_control'").fetchone()
        if private and store.db.execute("SELECT 1 FROM noah_control WHERE state IN ('started','outcome_unknown') LIMIT 1").fetchone():
            raise ValueError('reconcile private client controller actions before an epoch')
        for actor in ('actor-03', 'actor-09', 'actor-10'):
            row = store.db.execute('SELECT online FROM actor WHERE id=?', (actor,)).fetchone()
            if row is None or row[0] != 0:
                raise ValueError('original permanently absent clients must remain closed')
        store.db.execute('INSERT INTO target_epoch(id,declaration,identity) VALUES (?,?,?)',
                         (declaration['id'], encoded, canonical(declaration['identity'])))
        store._event('target_epoch_declared', declaration)
    return True

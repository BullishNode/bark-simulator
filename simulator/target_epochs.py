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
RUNTIME_META = ('zero_principal_identity_bootstrap', 'conserved_treasury_boundary',
                'financial_operating_envelope', 'finite_initial_funding_plan', 'finite_first_board_plan')
SERVER_COMMIT = '4d041f7f2f13ba0a5a95e540c70d6aba60f9bb50'
DEPLOY_COMMIT = 'c59a9907373c1dcae8bed96d4cfabcd31148e88b'
SERVER_IMAGE = 'sha256:da797d16bd5441e04cc3564540c166a2885c0b63588ec0b5c3773f17f3eae014'
ORIGIN_COMMIT = '5e5994d3ab6844a443cef1e9d19a9195ed785486'
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
LEGACY_SCHEMA = '''CREATE TABLE IF NOT EXISTS legacy_target_reconciliation(
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 declaration TEXT NOT NULL, event_sequence INTEGER NOT NULL, event_hash TEXT NOT NULL)'''
LEGACY_FIELDS = {'id', 'first_manifest_sequence', 'first_manifest_hash',
                 'first_manifest_identity', 'metadata_identity', 'metadata_sha256',
                 'observed_at', 'receipt_hashes', 'historical_transition_qualified'}


def declaration_hashes(store):
    return {key: hashlib.sha256(value.encode()).hexdigest()
            for key, value in store.db.execute('SELECT key,value FROM meta')
            if key in IMMUTABLE_META or key.startswith(IMMUTABLE_FAMILIES)}


def active_identity(store):
    # Registry rows are a view of the append-only financial history. Dropping
    # or editing that view must never authorize an undeclared image or rollback.
    original = store.get_meta('target_identity')
    original_event = store.db.execute("SELECT * FROM event WHERE kind='target_manifest' ORDER BY sequence LIMIT 1").fetchone()
    legacy = list(store.db.execute("SELECT * FROM event WHERE kind='legacy_target_identity_reconciled' ORDER BY sequence"))
    registry_exists = store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='legacy_target_reconciliation'").fetchone()
    registry = list(store.db.execute('SELECT * FROM legacy_target_reconciliation')) if registry_exists else []
    if len(registry) != len(legacy):
        raise ValueError('legacy target registry differs from preserved reconciliation evidence')
    if len(legacy) > 1:
        raise ValueError('legacy target reconciliation must be unique')
    if legacy:
        _event_frame(legacy[0])
        row = registry[0]
        if (row['singleton'] != 1 or row['declaration'] != legacy[0]['payload']
                or row['event_sequence'] != legacy[0]['sequence'] or row['event_hash'] != legacy[0]['hash']):
            raise ValueError('legacy target reconciliation registry changed')
        _legacy_binding(store, json.loads(legacy[0]['payload']))
    elif original_event and original != original_event['payload']:
        raise ValueError('original target metadata differs from preserved manifest evidence')
    epoch_events = list(store.db.execute("SELECT * FROM event WHERE kind='target_epoch_declared' ORDER BY sequence"))
    for event in epoch_events:_event_frame(event)
    declarations = [row['payload'] for row in epoch_events]
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


def _event_frame(row):
    expected = hashlib.sha256(canonical([row['sequence'], row['observed_at'],
        row['kind'], row['payload'], row['previous_hash']]).encode()).hexdigest()
    if expected != row['hash']:
        raise ValueError('preserved target reconciliation event frame changed')


def _legacy_binding(store, declaration):
    public_payload(declaration)
    if not isinstance(declaration, dict) or set(declaration) != LEGACY_FIELDS:
        raise ValueError('complete explicit legacy target reconciliation required')
    if not isinstance(declaration['id'], str) or re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,99}', declaration['id']) is None:
        raise ValueError('legacy reconciliation requires an immutable identifier')
    if declaration['historical_transition_qualified'] is not False:
        raise ValueError('reconciliation cannot qualify the historical image switch')
    _identity(declaration['first_manifest_identity'])
    _identity(declaration['metadata_identity'])
    for key in IDENTITY_FIELDS - {'image_digest'}:
        if declaration['first_manifest_identity'][key] != declaration['metadata_identity'][key]:
            raise ValueError('legacy reconciliation cannot change signet, server key or target host')
    _hashes(declaration['receipt_hashes'], {'before_upgrade_identity', 'preserved_campaign_history'})
    timestamp(declaration['observed_at'], 'legacy audit time')
    event = store.db.execute("SELECT * FROM event WHERE kind='target_manifest' ORDER BY sequence LIMIT 1").fetchone()
    if event is None:
        raise ValueError('legacy reconciliation requires the original target event')
    _event_frame(event)
    if (integer(declaration['first_manifest_sequence'], 'original target sequence', 1) != event['sequence']
            or declaration['first_manifest_hash'] != event['hash']
            or declaration['first_manifest_identity'] != json.loads(event['payload'])):
        raise ValueError('legacy reconciliation differs from the preserved original manifest')
    original = store.get_meta('target_identity')
    if (original is None or declaration['metadata_identity'] != json.loads(original)
            or declaration['metadata_sha256'] != hashlib.sha256(original.encode()).hexdigest()):
        raise ValueError('legacy reconciliation differs from the exact preserved metadata')
    if declaration['first_manifest_identity'] == declaration['metadata_identity']:
        raise ValueError('legacy reconciliation requires a recorded historical difference')


def reconcile_legacy_identity(store, declaration):
    """Acknowledge a qualified caller's observed legacy gap; change no old data.

    Receipt contents must be independently checked by the owner. This records
    the known pre-upgrade metadata as the baseline for future epochs, and never
    retrospectively qualifies or conceals the older image switch.
    """
    with store.transaction():
        _legacy_binding(store, declaration)
        existing = list(store.db.execute("SELECT * FROM event WHERE kind='legacy_target_identity_reconciled' ORDER BY sequence"))
        if existing:
            active_identity(store)
            if len(existing) != 1 or existing[0]['payload'] != canonical(declaration):
                raise ValueError('legacy target reconciliation is immutable')
            return False
        registry_exists = store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='legacy_target_reconciliation'").fetchone()
        if registry_exists and store.db.execute('SELECT 1 FROM legacy_target_reconciliation LIMIT 1').fetchone():
            raise ValueError('legacy target reconciliation event was removed')
        if store.db.execute("SELECT 1 FROM event WHERE kind='target_epoch_declared' LIMIT 1").fetchone():
            raise ValueError('legacy baseline must be reconciled before new epochs')
        if not 0 <= time.time() - declaration['observed_at'] <= 600:
            raise ValueError('legacy reconciliation requires a fresh independent audit')
        _require_quiescent(store)
        store.db.execute(LEGACY_SCHEMA)
        store._event('legacy_target_identity_reconciled', declaration)
        event = store.db.execute("SELECT sequence,hash FROM event WHERE kind='legacy_target_identity_reconciled'").fetchone()
        store.db.execute('INSERT INTO legacy_target_reconciliation VALUES (1,?,?,?)',
                         (canonical(declaration), event['sequence'], event['hash']))
    return True


def _require_quiescent(store):
    if not store.get_meta('paused'):
        raise ValueError('pause dispatch before declaring an epoch')
    if store.db.execute("SELECT 1 FROM action WHERE state IN ('dispatched','outcome_unknown') LIMIT 1").fetchone():
        raise ValueError('reconcile in-flight and unknown client actions before an epoch')
    for table, states in [('seed_recovery', ('preparing','prepare_unknown','broadcasting','outcome_unknown')),
                          ('funding_batch', ('broadcasting','outcome_unknown')),
                          ('actor_lease', ('active','outcome_unknown')),
                          ('noah_control', ('started','outcome_unknown'))]:
        exists = store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
        if exists and store.db.execute('SELECT 1 FROM '+table+' WHERE state IN ('+','.join('?' for _ in states)+') LIMIT 1', states).fetchone():
            raise ValueError('reconcile client state before an epoch: '+table)
    for actor in ('actor-03', 'actor-09', 'actor-10'):
        row = store.db.execute('SELECT online FROM actor WHERE id=?', (actor,)).fetchone()
        if row is None or row[0] != 0:
            raise ValueError('original permanently absent clients must remain closed')


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
    if not isinstance(declaration, dict) or set(declaration) not in (FIELDS, FIELDS | {'runtime_manifest'}):
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
            if 'runtime_manifest' in declaration:_validate_runtime_manifest(store,declaration)
            return False
        if not 0 <= time.time() - declaration['observed_at'] <= 600:
            raise ValueError('epoch requires a fresh independent audit')
        _require_quiescent(store)
        if current != declaration['previous_identity']:
            raise ValueError('epoch predecessor differs from the active deployment')
        if declaration_hashes(store) != declaration['declaration_hashes']:
            raise ValueError('original campaign declarations changed during qualification')
        if 'runtime_manifest' in declaration:
            _validate_runtime_manifest(store, declaration, declaring=True)
        elif active_runtime_manifest(store) is not None:
            raise ValueError('finite runtime manifest cannot be silently removed')
        store.db.execute('INSERT INTO target_epoch(id,declaration,identity) VALUES (?,?,?)',
                         (declaration['id'], encoded, canonical(declaration['identity'])))
        store._event('target_epoch_declared', declaration)
    return True



def runtime_declaration_hashes(store):
    """Additional finite-pilot account/budget declarations, never mutable telemetry."""
    return {key:hashlib.sha256(value.encode()).hexdigest()
        for key,value in store.db.execute('SELECT key,value FROM meta') if key in RUNTIME_META}


def _validate_runtime_manifest(store, declaration, *, declaring=False):
    from .final_campaign import _pins, _source_event
    manifest=declaration['runtime_manifest']
    fields={'scope','origin_financial_pins','execution_release','expected','startup_source_sha256',
        'previous_runtime_source_sequence','precutover_source_sequence','checkpoint','preserved_declaration_hashes'}
    if not isinstance(manifest,dict) or set(manifest)!=fields or manifest['scope']!='finite_exploratory':
        raise ValueError('exact finite exploratory runtime manifest required')
    if store.get_meta('financial_qualification_required') is None:
        raise ValueError('finite financial qualification mode required')
    if store.get_meta('final_financial_epoch') is not None:
        raise ValueError('finite exploratory deployment cannot qualify a final campaign')
    pins=_pins(manifest['origin_financial_pins']);release=manifest['execution_release'];expected=manifest['expected']
    if not isinstance(expected,dict) or 'schema_sha256' not in expected:raise ValueError('complete qualified runtime expectations required')
    _hashes({'schema':expected['schema_sha256']},{'schema'})
    if (pins['product_commit']!=ORIGIN_COMMIT or pins['sdk_commit']!=ORIGIN_COMMIT
            or declaration['sdk_commit']!=ORIGIN_COMMIT
            or declaration['native_hashes']['bark-sim-driver']!=pins['driver_sha256']
            or release!={'product_commit':SERVER_COMMIT,'deploy_commit':DEPLOY_COMMIT,'image_sha256':SERVER_IMAGE,
                'sdk_commit':ORIGIN_COMMIT,'driver_sha256':pins['driver_sha256'],
                'configuration_sha256':pins['configuration_sha256'],'schema_sha256':expected['schema_sha256']}
            or declaration['identity']['image_digest']!=SERVER_IMAGE):
        raise ValueError('only qualified4d server and unchanged5e native lineage permitted')
    if (not isinstance(expected,dict) or set(expected)!={'product_commit','image_sha256','schema_sha256',
            'database','containers','binary_sha256','config_sha256','config_paths'}
            or expected['product_commit']!=SERVER_COMMIT or expected['image_sha256']!=SERVER_IMAGE):
        raise ValueError('complete qualified runtime expectations required')
    _hashes({'startup':manifest['startup_source_sha256']}, {'startup'})
    if (set(manifest['preserved_declaration_hashes'])!=set(RUNTIME_META)
            or manifest['preserved_declaration_hashes']!=runtime_declaration_hashes(store)):
        raise ValueError('original finite account or financial declaration changed')
    bootstrap=store.get_meta('zero_principal_identity_bootstrap')
    if bootstrap is None:raise ValueError('original finite bootstrap required')
    from .identity_bootstrap import declaration as bootstrap_declaration
    bootstrap=bootstrap_declaration(store)['declaration']
    if (bootstrap['pins']!=pins or bootstrap['identity']!=declaration['previous_identity']
            or bootstrap['wallet_root']!=store.get_meta('wallet_root')):
        raise ValueError('original wallet/account/target lineage differs')
    event,prior=_source_event(store,manifest['previous_runtime_source_sequence'])
    if (event['kind']!='owned_runtime_configuration_verified' or prior.get('product_commit')!=ORIGIN_COMMIT
            or prior.get('loaded_configuration_identity_verified') is not True):
        raise ValueError('original verified5e runtime source required')
    for service in ('captaind','watchmand'):
        original=prior['daemons'][service]
        if (original['image_sha256']!=declaration['previous_identity']['image_digest']
                or expected['containers'].get(service)!=original['container']
                or expected['config_sha256'].get(service)!=original['config_sha256']
                or expected['config_paths'].get(service)!={'host':original['config_path'],
                    'container':original['config_mount']['destination']}
                or expected['database']!=original['public_loaded_config_provenance']['postgres_database']):
            raise ValueError('runtime transition cannot change accounts/database/config/containers')
    journey_event,journey=_source_event(store,manifest['precutover_source_sequence'])
    if (journey_event['kind']!='ordinary_arkoor_journey_verified' or journey.get('financial_pins')!=pins
            or journey.get('sender_actor')!='actor-01' or journey.get('recipient_actor')!='actor-02'
            or journey.get('amount_sat')!=2000 or journey.get('miner_fee_sat')!=0 or journey.get('internal_service_fee_sat')!=0):
        raise ValueError('original verified finite2k journey required before cutover')
    transfer_event,transfer=_source_event(store,journey['ark_transfer_sequence'])
    from .final_campaign import _action_pins
    _action_pins(store,journey['action_id'],pins)
    action=store.db.execute('SELECT state,operation FROM action WHERE id=?',(journey['action_id'],)).fetchone()
    if (transfer_event['kind']!='ark_transfer_verified' or transfer.get('action_id')!=journey['action_id']
            or action['state']!='completed' or action['operation']!='send_arkoor'):
        raise ValueError('original finite journey transfer source differs')
    checkpoint=manifest['checkpoint']
    if not isinstance(checkpoint,dict) or set(checkpoint)!={'sequence','hash'}:raise ValueError('retained journal checkpoint required')
    integer(checkpoint['sequence'],'journal checkpoint sequence',1)
    if checkpoint['sequence']>10000:raise ValueError('runtime checkpoint exceeds bounded pilot journal')
    previous='0'*64;count=0
    for row in store.db.execute('SELECT * FROM event WHERE sequence<=? ORDER BY sequence',(checkpoint['sequence'],)):
        count+=1;_event_frame(row)
        if row['sequence']!=count or row['previous_hash']!=previous:raise ValueError('retained journal prefix differs')
        previous=row['hash']
    if count!=checkpoint['sequence'] or previous!=checkpoint['hash'] or event['sequence']>count or journey_event['sequence']>count or transfer_event['sequence']>count:
        raise ValueError('retained journal checkpoint differs')
    if declaring:
        if store.db.execute("SELECT 1 FROM action WHERE state IN ('queued','dispatched','outcome_unknown') LIMIT 1").fetchone():
            raise ValueError('complete original actions before runtime cutover; no queued replay')
        if store.db.execute("SELECT 1 FROM event WHERE sequence>? AND kind IN ('action_intent','action_dispatched','financial_cost_verified')",(count,)).fetchone():
            raise ValueError('financial history advanced after runtime checkpoint')
    return manifest


def active_runtime_manifest(store):
    """Return the declared finite runtime transition, never infer compatibility."""
    if not store.db.execute("SELECT 1 FROM event WHERE kind='target_epoch_declared' AND json_type(payload,'$.runtime_manifest')='object' LIMIT 1").fetchone():return None
    active_identity(store)
    exists=store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='target_epoch'").fetchone()
    row=store.db.execute('SELECT id,declaration FROM target_epoch ORDER BY sequence DESC LIMIT 1').fetchone() if exists else None
    if row is None:return None
    declaration=json.loads(row['declaration'])
    if 'runtime_manifest' not in declaration:
        if store.db.execute("SELECT 1 FROM event WHERE kind='target_epoch_declared' AND json_type(payload,'$.runtime_manifest')='object'").fetchone():
            raise ValueError('finite runtime manifest cannot be silently removed')
        return None
    return {'deployment_epoch_id':row['id'],**_validate_runtime_manifest(store,declaration)}


def verified_execution_context(store, snapshot=None):
    """Authenticate fresh actual execution separately from old origin/budget pins."""
    from .final_campaign import _source_event
    manifest=active_runtime_manifest(store)
    if manifest is None:return None
    if snapshot is None:
        row=store.db.execute('SELECT payload FROM snapshot ORDER BY id DESC LIMIT 1').fetchone()
        snapshot=json.loads(row[0]) if row else {}
    if (not 0<=time.time()-snapshot.get('observed_at',-1)<=90
            or snapshot.get('financial_pins')!=manifest['origin_financial_pins']
            or snapshot.get('financial_pins_scope')!='preserved_origin_and_budget_lineage'
            or snapshot.get('execution_release')!=manifest['execution_release']
            or snapshot.get('deployment_epoch_id')!=manifest['deployment_epoch_id']
            or snapshot.get('identity')!=active_identity(store)):
        raise ValueError('actual fresh finite execution context required')
    sequence=snapshot.get('runtime_source_sequence');event,runtime=_source_event(store,sequence)
    if (event['kind']!='owned_runtime_configuration_verified' or runtime.get('loaded_configuration_identity_verified') is not True
            or runtime.get('deployment_epoch_id')!=manifest['deployment_epoch_id']
            or runtime.get('execution_release')!=manifest['execution_release']
            or runtime.get('origin_financial_pins')!=manifest['origin_financial_pins']
            or runtime.get('product_commit')!=manifest['execution_release']['product_commit']
            or runtime.get('schema_sha256')!=manifest['execution_release']['schema_sha256']
            or runtime.get('startup_source_sha256')!=manifest['startup_source_sha256']
            or not 0<=time.time()-runtime.get('observed_at',-1)<=90):
        raise ValueError('fresh declared runtime source required')
    return {'execution_release':manifest['execution_release'],'deployment_epoch_id':manifest['deployment_epoch_id'],
        'runtime_source_sequence':sequence,'financial_pins_scope':'preserved_origin_and_budget_lineage'}



def verified_runtime_source(store, sequence, *, origin_pins, current_source_sha256):
    """Readiness hook: current executable identity never replaces historical pins."""
    from .final_campaign import _source_event
    event,runtime=_source_event(store,sequence)
    manifest=active_runtime_manifest(store)
    if (event['kind']!='owned_runtime_configuration_verified' or runtime.get('loaded_configuration_identity_verified') is not True
            or runtime.get('current_source_sha256')!=current_source_sha256
            or not 0<=time.time()-runtime.get('observed_at',-1)<=90):
        raise ValueError('fresh authenticated loaded runtime source required')
    if manifest is None:
        if runtime.get('product_commit')!=origin_pins['product_commit'] or runtime.get('schema_sha256')!=origin_pins['schema_sha256']:
            raise ValueError('original loaded runtime identity differs')
    elif (origin_pins!=manifest['origin_financial_pins']
            or runtime.get('product_commit')!=manifest['execution_release']['product_commit']
            or runtime.get('schema_sha256')!=manifest['execution_release']['schema_sha256']
            or runtime.get('execution_release')!=manifest['execution_release']
            or runtime.get('deployment_epoch_id')!=manifest['deployment_epoch_id']
            or runtime.get('startup_source_sha256')!=manifest['startup_source_sha256']):
        raise ValueError('runtime differs from declared lineage and execution release')
    return runtime

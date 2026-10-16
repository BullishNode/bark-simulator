"""Admitted ordinary Arkoor frontier; no payment or round retirement inference."""
import hashlib
from pathlib import Path

from . import normal_lineage as lineage
from .bundle_audit import decode_transaction


SOURCE_SHA256 = 'c911161934c665a7034dee29cbcf84fd1a4ca5cf92a5797d36e8d874309b2b3e'
CONFIGURATION = {'schema_version': 1, 'scope': 'arkoor_only', 'source_sha256': SOURCE_SHA256}


def original_claims(store):
    """All retained ownership originals for root discovery, never a current frontier."""
    rows = store.db.execute('SELECT c.*,k.actor FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey ORDER BY c.id').fetchall()
    if len(rows) > lineage.MAX_COINS:
        raise ValueError('bounded complete ownership originals required')
    return [{'coin_id': row['id'], 'actor': row['actor'], 'amount_sat': row['amount_sat']} for row in rows]


def authenticate_frontier(store, tables, tools, *, server_pubkey, genesis,
                          native_source_sha256, observation_id, configuration):
    """Execute admitted tools on original Fulls, then reconcile exact original edges.

    The caller has already authenticated this nonce's SQL bytes and admission.
    No returned value is accepted as a readiness or source-authentication flag.
    """
    import re
    if (not isinstance(configuration, dict) or type(configuration.get('schema_version')) is not int
            or configuration != CONFIGURATION
            or hashlib.sha256(Path(lineage.__file__).read_bytes()).hexdigest() != SOURCE_SHA256
            or not isinstance(observation_id, str) or re.fullmatch('[0-9a-f]{32}', observation_id) is None):
        raise ValueError('admitted typed lineage source/observation differs')
    lineage.hash_id(native_source_sha256)
    # Forfeit validity alone cannot establish exhaustive signed-tree allocation.
    if any(tables[name] for name in ('round', 'round_participation', 'round_part_input', 'round_part_output')):
        raise ValueError('round lineage requires exhaustive signed-tree allocation and completed Full originals')
    originals = original_claims(store)
    if not originals:
        actions = store.db.execute("SELECT 1 FROM action WHERE state='completed' AND operation IN ('board','send_arkoor','refresh','refresh_delegated','refresh_scheduled') LIMIT 1").fetchone()
        if actions is not None:
            raise ValueError('completed original operation has no retained owned Full')
        return {'current_claim_ids': [], 'consumed_claim_ids': [], 'obligation_groups': [],
            'native_source_sha256': native_source_sha256, 'source_observation_id': observation_id,
            'claims': [], 'authenticated_coins': {}}
    coins = lineage.authenticate_owned_originals(store, tables, tools, genesis=genesis, server_pubkey=server_pubkey)
    origins, edges = lineage.edges_from_store(store, tables, coins, decode_transaction=decode_transaction)
    if any(edge['kind'] != 'arkoor' for edge in edges):
        raise ValueError('round retirement lacks exhaustive signed-tree proof')
    result = lineage.reduce_lineage(coins, origins, edges, native_source_sha256=native_source_sha256)
    claims = []
    rows = {row['vtxo_id']: row for row in tables['vtxo']}
    for identifier in result['current_claim_ids']:
        row = rows[identifier]
        if any(row.get(name) is not None for name in ('oor_spent_txid', 'spent_in_round', 'offboarded_in', 'onchain_spent_txid')):
            raise ValueError('current typed liability has unexplained native spend disposition')
        owned = store.db.execute('SELECT * FROM owned_coin WHERE id=?', (identifier,)).fetchone()
        state = store.db.execute('SELECT state,action_id FROM coin_observation WHERE coin_id=? ORDER BY observed_at DESC,action_id DESC LIMIT 1', (identifier,)).fetchone()
        if state is None:
            raise ValueError('typed current right lacks retained observation')
        claims.append({'coin_id': identifier, 'actor': coins[identifier]['actor'], 'amount_sat': owned['amount_sat'],
            'signed_hash': owned['signed_hash'], 'state': state['state'], 'observation_action_id': state['action_id']})
    store.verify_event_chain()
    return {**result, 'claims': claims, 'authenticated_coins': coins, 'source_observation_id': observation_id}


def public_frontier(value):
    """Hash-only native execution evidence, never original signed bytes."""
    fields = ('native_request_sha256', 'native_response_sha256', 'native_full_sha256',
        'native_policy_request_sha256', 'native_policy_response_sha256')
    return {**{key: value[key] for key in ('current_claim_ids', 'consumed_claim_ids', 'obligation_groups',
        'native_source_sha256', 'source_observation_id')},
        'coin_proof_hashes': {identifier: {key: coin[key] for key in fields}
            for identifier, coin in value['authenticated_coins'].items()}}


def board_descendants(value, identifier, claims, native):
    """Select one original obligation group, without inventing cross-origin shares."""
    groups = [group for group in value['obligation_groups'] if identifier in group['original_claim_ids']]
    if len(groups) != 1 or groups[0]['original_claim_ids'] != [identifier] or groups[0]['sdk_service_charge_sat'] != 0:
        raise ValueError('pending Board requires exact single-origin zero-service-charge lineage')
    group = groups[0]
    selected = {name: claim for name, claim in claims.items() if name in group['current_claim_ids']}
    if set(selected) != set(group['current_claim_ids']) or sum(row['amount_sat'] for row in selected.values()) != group['original_principal_sat']:
        raise ValueError('pending Board typed frontier omits current principal')
    if identifier not in group['current_claim_ids'] and identifier not in value['consumed_claim_ids']:
        raise ValueError('pending Board original has no authenticated immediate consumer')
    for name in group['current_claim_ids']:
        if native[name]['anchor_point'] != native[identifier]['anchor_point']:
            raise ValueError('pending Board descendant has foreign physical anchor')
    return selected


def opening_claims(store, proof, readiness_sequence, pins):
    """Bind the already executed frontier to its original qualified source chain.

    This is a declaration handoff, never a new producer or a supplied ID list.
    The independently qualified Collector has already rerun all supplied-byte
    native proofs and compared the source frontier under the same nonce/SQL cut.
    """
    import json
    from .final_campaign import _source_event
    from .architecture import profile, TWO_STEP
    from .normal_lineage import bind_coin
    from .two_step_normal import Collector, module_hash
    from .two_step_capture import SourceCapture
    value = proof.get('ordinary_lineage')
    if value is None:
        return None
    if (not isinstance(value, dict) or set(value) != {'current_claim_ids', 'consumed_claim_ids',
            'obligation_groups', 'native_source_sha256', 'source_observation_id', 'coin_proof_hashes'}
            or not isinstance(value['current_claim_ids'], list) or not isinstance(value['consumed_claim_ids'], list)
            or not isinstance(value['coin_proof_hashes'], dict)):
        raise ValueError('opening typed frontier exact qualified schema required')
    rows = store.db.execute('SELECT sequence FROM event WHERE hash=?', (proof.get('source_event_hash'),)).fetchall()
    if len(rows) != 1:
        raise ValueError('opening typed frontier original source missing')
    source_event, source = _source_event(store, rows[0]['sequence'])
    observation = proof.get('source_observation')
    if (profile(store) != TWO_STEP or not isinstance(value, dict)
            or source_event['kind'] != 'normal_financial_source' or source_event['sequence'] >= readiness_sequence
            or source.get('financial_pins') != pins or source.get('boundary_id') != proof.get('boundary_id')
            or not isinstance(observation, dict) or observation.get('architecture_profile') != TWO_STEP
            or source.get('source_observation') != observation
            or source.get('ordinary_lineage') != value
            or source.get('original_sha256') != proof.get('original_source_hashes')
            or value.get('native_source_sha256') != source.get('original_sha256', {}).get('native_sql')
            or value.get('source_observation_id') != observation.get('id')):
        raise ValueError('opening typed frontier is detached from authenticated observation/SQL')
    sequence = source.get('lineage_admission_sequence')
    if type(sequence) is not int or not 0 < sequence < source_event['sequence']:
        raise ValueError('opening typed frontier original admission missing')
    admission_event, admitted = _source_event(store, sequence)
    expected = {'ordinary_lineage': module_hash(authenticate_frontier), 'typed_lineage': module_hash(bind_coin),
        'adapter': module_hash(Collector.produce), 'capture': module_hash(SourceCapture.collect)}
    if (admission_event['kind'] != 'normal_financial_collector_qualified'
            or admitted.get('financial_pins') != pins or admitted.get('ordinary_lineage') != CONFIGURATION
            or any(admitted.get('component_sha256', {}).get(name) != digest for name, digest in expected.items())
            or any(admitted.get('capture_dependencies_sha256', {}).get(name) != expected[name]
                for name in ('ordinary_lineage', 'typed_lineage'))
            or not {'binding', 'policy'} <= set(admitted.get('proof_tool_sha256', {}))
            or set(admitted.get('proof_tool_sha256', {})) != set(admitted.get('proof_commands_sha256', {}))):
        raise ValueError('opening typed frontier collector/module/tool admission differs')
    for mapping in ('proof_tool_sha256', 'proof_commands_sha256'):
        for digest in admitted[mapping].values():
            lineage.hash_id(digest)
    owned = {row['id']: row for row in store.db.execute('SELECT c.*,k.actor FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey ORDER BY c.id')}
    current = lineage.ids(value['current_claim_ids']) if value['current_claim_ids'] else ()
    consumed = lineage.ids(value['consumed_claim_ids']) if value['consumed_claim_ids'] else ()
    if (set(current) & set(consumed) or set(current) | set(consumed) != set(owned)
            or set(value['coin_proof_hashes']) != set(owned)):
        raise ValueError('opening typed frontier omits or duplicates an original right')
    fields = {'native_request_sha256', 'native_response_sha256', 'native_full_sha256',
        'native_policy_request_sha256', 'native_policy_response_sha256'}
    for record in value['coin_proof_hashes'].values():
        if set(record) != fields:
            raise ValueError('opening typed frontier native original hashes incomplete')
        for digest in record.values():
            lineage.hash_id(digest)
    board_ids = []
    for action in store.db.execute("SELECT result FROM action WHERE operation='board' AND state='completed'"):
        board_ids.extend(json.loads(action['result'])['data']['board']['vtxos'])
    groups = value['obligation_groups']; origins = []; frontier = []
    if not isinstance(groups, list) or len(groups) > lineage.MAX_COINS:
        raise ValueError('bounded original obligation groups required')
    for group in groups:
        if (not isinstance(group, dict) or set(group) != {'original_claim_ids', 'current_claim_ids',
                'original_principal_sat', 'current_principal_sat', 'sdk_service_charge_sat', 'action_ids',
                'per_origin_fee_allocation'}
                or any(type(group[key]) is not int for key in ('original_principal_sat', 'current_principal_sat', 'sdk_service_charge_sat'))
                or group['per_origin_fee_allocation'] is not None):
            raise ValueError('opening typed frontier exact obligation schema required')
        original = lineage.ids(group['original_claim_ids']); leaves = lineage.ids(group['current_claim_ids'])
        if (set(original+leaves) - set(owned) or group['sdk_service_charge_sat'] != 0
                or group['original_principal_sat'] != sum(owned[name]['amount_sat'] for name in original)
                or group['current_principal_sat'] != sum(owned[name]['amount_sat'] for name in leaves)
                or group['original_principal_sat'] != group['current_principal_sat']):
            raise ValueError('opening typed frontier changes original unpaid principal')
        origins.extend(original); frontier.extend(leaves)
    if (sorted(origins) != sorted(board_ids) or len(set(origins)) != len(origins)
            or sorted(frontier) != sorted(current) or len(set(frontier)) != len(frontier)):
        raise ValueError('opening typed frontier original/current obligation coverage differs')
    result = []
    for identifier in current:
        row = owned[identifier]
        if hashlib.sha256(bytes.fromhex(row['signed_vtxo'])).hexdigest() != row['signed_hash']:
            raise ValueError('opening retained signed original bytes changed')
        state = store.db.execute('SELECT state,action_id FROM coin_observation WHERE coin_id=? ORDER BY observed_at DESC,action_id DESC LIMIT 1', (identifier,)).fetchone()
        if state is None:
            raise ValueError('opening retained original observation missing')
        result.append({'coin_id': identifier, 'actor': row['actor'], 'amount_sat': row['amount_sat'],
            'signed_hash': row['signed_hash'], 'state': state['state'], 'observation_action_id': state['action_id']})
    store.verify_event_chain()
    return result

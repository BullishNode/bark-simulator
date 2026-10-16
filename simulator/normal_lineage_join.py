"""Admitted ordinary Arkoor frontier; no payment or round retirement inference."""
import hashlib
from pathlib import Path

from . import normal_lineage as lineage
from .bundle_audit import decode_transaction


SOURCE_SHA256 = 'fa93fd02e4f144313e607d3d69ba5d56d513f56ddc39ae39a2cb15fd36543e6f'
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

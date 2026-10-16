"""Admitted ordinary Arkoor frontier; no payment or round retirement inference."""
import hashlib
from pathlib import Path

from . import normal_lineage as lineage
from .bundle_audit import decode_transaction


SOURCE_SHA256 = 'f20f7b9e6251855fd3fae542d2022c1db34456732c4d4f72c10819c26cb1e8a8'
CONFIGURATION = {'schema_version': 1, 'scope': 'arkoor_only', 'source_sha256': SOURCE_SHA256}
ROUND_CONFIGURATION = {**CONFIGURATION, 'scope': 'ordinary_completed_rounds'}


def round_executor(store, tools, sequence, *, native_source_sha256, observation_id):
    """Resolve immutable admission, then execute the existing pinned pure tool.

    A callback cannot select an executable or supply its own execution verdict.
    Exact source/nonce/SDK/argv/tool bindings come from the checked event and
    the installed command, and all private request/response bytes are retained
    by run_proof. This function never creates an admission event.
    """
    from .final_campaign import _source_event
    from .model import canonical
    from .two_step_normal import module_hash, run_proof
    import re
    if (type(sequence) is not int or sequence < 1 or not isinstance(observation_id, str)
            or re.fullmatch('[0-9a-f]{32}', observation_id) is None):
        raise ValueError('round proof requires exact admission and observation identity')
    lineage.hash_id(native_source_sha256)
    store.verify_event_chain()
    event, admitted = _source_event(store, sequence)
    tool = tools['policy']
    command_hash = hashlib.sha256(canonical(tool['command']).encode()).hexdigest()
    expected_components = {'ordinary_lineage': module_hash(authenticate_frontier),
        'typed_lineage': module_hash(lineage.bind_coin)}
    if (not isinstance(tool['command'], list) or len(tool['command']) != 1
            or event['kind'] != 'normal_financial_collector_qualified'
            or admitted.get('ordinary_lineage') != ROUND_CONFIGURATION
            or type(admitted.get('ordinary_lineage', {}).get('schema_version')) is not int
            or admitted.get('financial_pins', {}).get('sdk_commit') != lineage.NATIVE_COMPLETION_SDK
            or admitted.get('proof_tool_sha256', {}).get('policy') != tool['sha256']
            or admitted.get('proof_commands_sha256', {}).get('policy') != command_hash
            or any(admitted.get('component_sha256', {}).get(key) != value
                or admitted.get('capture_dependencies_sha256', {}).get(key) != value
                for key, value in expected_components.items())):
        raise ValueError('completed round tool/source/SDK admission differs')
    pins = {'tool_sha256': tool['sha256'], 'commands_sha256': command_hash,
        'admission_sha256': event['hash'], 'sdk_commit': lineage.NATIVE_COMPLETION_SDK,
        'source_observation_id': observation_id, 'source_sha256': native_source_sha256,
        'qualification_scope': 'admitted_native'}
    for key in ('tool_sha256', 'commands_sha256', 'admission_sha256', 'source_sha256'):
        lineage.hash_id(pins[key])

    def execute(request, *, expected):
        if expected != pins or expected['qualification_scope'] != 'admitted_native':
            raise ValueError('round execution cannot replace admission/source/nonce')
        current, body = _source_event(store, sequence)
        if current['hash'] != event['hash'] or body != admitted:
            raise ValueError('round original admission changed before execution')
        sent, received = run_proof(tool, request)
        store.verify_event_chain()
        return sent, received, dict(pins)

    return execute, pins


def require_round_evidence(value, tables, native_source_sha256):
    """Rejoin completed proof hashes to this SQL cut, never an export flag.

    Callers use the locally recomputed authenticate_frontier result. The same
    original tree/anchor, ALL participation membership and EVERY original
    forfeit execution must survive the handoff to a different reducer.
    """
    from .bundle_audit import decode_transaction
    if (not isinstance(value, dict) or value.get('native_source_sha256') != native_source_sha256
            or not isinstance(value.get('round_proof_evidence'), list)):
        raise ValueError('round allocations require a separate authenticated resolver')
    rounds = {row['funding_txid']: row for row in tables['round']}
    if len(rounds) != len(tables['round']):
        raise ValueError('duplicate native round funding')
    parts = {(row['round_id'], row['unlock_hash']): row for row in tables['round_participation']}
    if len(parts) != len(tables['round_participation']):
        raise ValueError('duplicate native participation identity')
    seen = set()
    for record in value['round_proof_evidence']:
        tree = record['native_tree_originals']; binding = tree['execution_binding']
        key = (tree['round_funding_txid'], tree['participation_unlock_hash'])
        if (key not in parts or key in seen or key[0] not in rounds
                or binding['qualification_scope'] != 'admitted_native'
                or binding['sdk_commit'] != lineage.NATIVE_COMPLETION_SDK
                or binding['source_sha256'] != native_source_sha256
                or binding['source_observation_id'] != value['source_observation_id']):
            raise ValueError('round proof source/nonce/SDK/participation differs')
        seen.add(key); row = rounds[key[0]]
        raw_tree = lineage.original_hex(row.get('signed_tree_hex'))
        raw_anchor = lineage.original_hex(row['funding_tx_hex'])
        if (type(row.get('signed_tree_bytes')) is not int or len(raw_tree) != row['signed_tree_bytes']
                or tree['signed_tree_sha256'] != lineage.sha(raw_tree)
                or tree['anchor_raw_sha256'] != lineage.sha(raw_anchor)
                or decode_transaction(raw_anchor.hex())['txid'] != key[0]):
            raise ValueError('round proof lost exact original tree/funding source')
        for name in ('request_sha256', 'response_sha256'):
            lineage.hash_id(tree[name])
        part = parts[key]
        inputs = [entry['vtxo_id'] for entry in tables['round_part_input'] if entry['participation_id'] == part['id']]
        proofs = record['native_forfeit_originals']
        if sorted(entry['input_id'] for entry in proofs) != sorted(inputs) or len(set(inputs)) != len(inputs):
            raise ValueError('round proof lost an original participation input')
        for proof in proofs:
            if proof['execution_binding'] != binding:
                raise ValueError('round forfeit and tree admission/source differ')
            lineage.hash_id(proof['request_sha256']); lineage.hash_id(proof['response_sha256'])
    if seen != set(parts) or {key[0] for key in seen} != set(rounds):
        raise ValueError('unmatched native round/participation remains an obligation')
    return value['round_proof_evidence']


def original_claims(store):
    """All retained ownership originals for root discovery, never a current frontier."""
    rows = store.db.execute('SELECT c.*,k.actor FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey ORDER BY c.id').fetchall()
    if len(rows) > lineage.MAX_COINS:
        raise ValueError('bounded complete ownership originals required')
    return [{'coin_id': row['id'], 'actor': row['actor'], 'amount_sat': row['amount_sat']} for row in rows]


def authenticate_frontier(store, tables, tools, *, server_pubkey, genesis,
                          native_source_sha256, observation_id, configuration,
                          admission_sequence=None):
    """Execute admitted tools on original Fulls, then reconcile exact original edges.

    The caller has already authenticated this nonce's SQL bytes and admission.
    No returned value is accepted as a readiness or source-authentication flag.
    """
    import re
    if (not isinstance(configuration, dict) or type(configuration.get('schema_version')) is not int
            or configuration not in (CONFIGURATION, ROUND_CONFIGURATION)
            or hashlib.sha256(Path(lineage.__file__).read_bytes()).hexdigest() != SOURCE_SHA256
            or not isinstance(observation_id, str) or re.fullmatch('[0-9a-f]{32}', observation_id) is None):
        raise ValueError('admitted typed lineage source/observation differs')
    lineage.hash_id(native_source_sha256)
    round_tables = ('round', 'round_participation', 'round_part_input', 'round_part_output')
    has_rounds = any(tables[name] for name in round_tables)
    executor = pins = None
    if has_rounds:
        if configuration != ROUND_CONFIGURATION or type(admission_sequence) is not int:
            raise ValueError('round lineage requires exhaustive signed-tree allocation and completed Full originals')
        for row in tables['round']:
            raw = lineage.original_hex(row.get('signed_tree_hex'))
            if type(row.get('signed_tree_bytes')) is not int or len(raw) != row['signed_tree_bytes']:
                raise ValueError('exact same-cut signed tree body/length required')
        executor, pins = round_executor(store, tools, admission_sequence,
            native_source_sha256=native_source_sha256, observation_id=observation_id)
    originals = original_claims(store)
    if not originals:
        if has_rounds:
            raise ValueError('native rounds require retained original owned Full attribution')
        actions = store.db.execute("SELECT 1 FROM action WHERE state='completed' AND operation IN ('board','send_arkoor','refresh','refresh_delegated','refresh_scheduled') LIMIT 1").fetchone()
        if actions is not None:
            raise ValueError('completed original operation has no retained owned Full')
        return {'current_claim_ids': [], 'consumed_claim_ids': [], 'obligation_groups': [],
            'native_source_sha256': native_source_sha256, 'source_observation_id': observation_id,
            'claims': [], 'authenticated_coins': {}}
    coins = lineage.authenticate_owned_originals(store, tables, tools, genesis=genesis, server_pubkey=server_pubkey)
    origins, edges = lineage.edges_from_store(store, tables, coins, decode_transaction=decode_transaction,
        round_proof_executor=executor, tree_proof_executor=executor, tree_proof_pins=pins)
    if any(edge['kind'] != 'arkoor' for edge in edges) and not has_rounds:
        raise ValueError('round retirement lacks exhaustive signed-tree proof')
    if has_rounds:
        covered = {edge['native_tree_originals']['round_funding_txid']
            for edge in edges if edge['kind'] == 'refresh'}
        if covered != {row['funding_txid'] for row in tables['round']}:
            raise ValueError('native round has no complete original client/forfeit/allocation join')
        participation_keys = [(row['round_id'], row['unlock_hash'])
            for row in tables['round_participation']]
        completed_keys = [(edge['native_tree_originals']['round_funding_txid'],
            edge['native_tree_originals']['participation_unlock_hash'])
            for edge in edges if edge['kind'] == 'refresh']
        if (len(set(participation_keys)) != len(participation_keys)
                or sorted(completed_keys) != sorted(participation_keys)):
            raise ValueError('every native participation needs its original completed allocation join')
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
    value = {**result, 'claims': claims, 'authenticated_coins': coins, 'source_observation_id': observation_id}
    if has_rounds:
        value['round_proof_evidence'] = [{'action_id': edge['action_id'],
            'native_forfeit_originals': edge['native_forfeit_originals'],
            'native_tree_originals': edge['native_tree_originals']}
            for edge in edges if edge['kind'] == 'refresh']
        require_round_evidence(value, tables, native_source_sha256)
    return value


def public_frontier(value):
    """Hash-only native execution evidence, never original signed bytes."""
    fields = ('native_request_sha256', 'native_response_sha256', 'native_full_sha256',
        'native_policy_request_sha256', 'native_policy_response_sha256')
    result = {**{key: value[key] for key in ('current_claim_ids', 'consumed_claim_ids', 'obligation_groups',
        'native_source_sha256', 'source_observation_id')},
        'coin_proof_hashes': {identifier: {key: coin[key] for key in fields}
            for identifier, coin in value['authenticated_coins'].items()}}
    if 'round_proof_evidence' in value:
        result['round_proof_evidence'] = value['round_proof_evidence']
    return result


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
            or admitted.get('financial_pins') != pins
            or admitted.get('ordinary_lineage') not in (CONFIGURATION, ROUND_CONFIGURATION)
            or type(admitted.get('ordinary_lineage', {}).get('schema_version')) is not int
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

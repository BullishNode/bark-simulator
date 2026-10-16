"""Append one evidenced financial overlay; never overwrite old declarations.

An admitted normal-source verifier owns exhaustive discovery and source replay.
This module additionally checks every declared member's independent assets,
original cumulative costs, flow conservation and unchanged budget limits. It
does not produce readiness, reset an epoch, fund a wallet, or dispatch clients.
"""
import hashlib
import inspect
import json
import os
from pathlib import Path
import stat
import time

from .final_campaign import _pins, _source_event
from .model import canonical, integer, public_payload

EVENT = 'preserved_treasury_upgrade_verified'


def _digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def _require_leases(store, config):
    """Observe the existing Linux flock leases; never acquire one as a proof."""
    wallet_root = store.get_meta('wallet_root')
    if wallet_root is None or Path(wallet_root) != Path(config.wallet_root).resolve():
        raise ValueError('original wallet-root binding required for upgrade lease')
    for root in (Path(store.root), Path(wallet_root)):
        lock = root / 'supervisor.lock'
        try:
            expected = lock.lstat()
        except FileNotFoundError:
            raise ValueError('existing state and wallet-root Lease required') from None
        if not stat.S_ISREG(expected.st_mode):
            raise ValueError('regular existing supervisor lease required')
        held = False
        for entry in Path('/proc/self/fdinfo').iterdir():
            try:
                actual = os.fstat(int(entry.name))
                if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
                    continue
                for line in entry.read_text().splitlines():
                    parts = line.split()
                    if len(parts) >= 9 and parts[0] == 'lock:' and parts[2:6] == [
                            'FLOCK', 'ADVISORY', 'WRITE', str(os.getpid())]:
                        held = True
            except (FileNotFoundError, OSError):
                continue
        if not held:
            raise ValueError('current process must hold both original state and wallet-root Lease')


def _context(store):
    tail = store.db.execute('SELECT sequence,hash FROM event ORDER BY sequence DESC LIMIT 1').fetchone()
    return {'event_tail': list(tail) if tail else None,
            'meta_sha256': _digest([list(row) for row in store.db.execute('SELECT * FROM meta ORDER BY key')]),
            'actions_sha256': _digest([dict(row) for row in store.db.execute('SELECT * FROM action ORDER BY id')])}


def _originals(store):
    originals = []
    for key, kind, nested in (
            ('conserved_treasury_boundary', 'treasury_boundary_declared', False),
            ('financial_operating_envelope', 'financial_operating_envelope_declared', True)):
        encoded = store.get_meta(key)
        rows = store.db.execute('SELECT sequence FROM event WHERE kind=?', (kind,)).fetchall()
        if encoded is None or len(rows) != 1:
            raise ValueError('unique original treasury and envelope required')
        event, proof = _source_event(store, rows[0][0])
        value = proof['declaration'] if nested else proof
        if canonical(value) != encoded:
            raise ValueError('original financial declaration was changed')
        originals.append((value, {'sequence': event['sequence'], 'hash': event['hash'],
                                  'sha256': _digest(value)}))
    return originals


def recorded(store):
    rows = store.db.execute('SELECT sequence FROM event WHERE kind=?', (EVENT,)).fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        raise ValueError('financial upgrade is once-only, not a resettable overlay')
    event, value = _source_event(store, rows[0][0])
    old_boundary, old_envelope = _originals(store)
    if (value['previous_boundary'] != old_boundary[1]
            or value['previous_envelope'] != old_envelope[1]):
        raise ValueError('financial upgrade lost original declaration identity')
    for source in value['sources']:
        original, _ = _source_event(store, source['sequence'])
        if original['hash'] != source['hash'] or original['sequence'] >= event['sequence']:
            raise ValueError('financial upgrade original source changed')
    return {**value, 'upgrade_sequence': event['sequence']}


def boundary(store, original):
    value = recorded(store)
    return original if value is None else value['boundary']


def envelope(store, original):
    value = recorded(store)
    return original if value is None else value['envelope']


def _cost_key(proof):
    identifier = proof.get('monetary_id')
    if not isinstance(identifier, str) or not identifier:
        raise ValueError('original monetary cost identity missing')
    if identifier.startswith(('bitcoin-miner:', 'miner:')):
        import re
        match = re.fullmatch(r'(?:bitcoin-miner|miner):([0-9a-f]{64})', identifier)
        if match is None:
            raise ValueError('invalid original miner transaction identity')
        return ('miner', match[1])
    return ('other', identifier)


def fee_totals(store, pins, *, reserved_action_id=None):
    value = recorded(store)
    if value is None:
        return None
    if pins != value['boundary']['pins']:
        raise ValueError('fee query differs from upgraded execution pins')
    old_pins = _originals(store)[0][0]['pins']
    old_costs = {row['sequence']: row['hash'] for row in value['costs']}
    totals = {'ordinary': 0, 'urgent': 0}
    seen = set()
    covered = set()
    for row in store.db.execute("SELECT sequence FROM event WHERE kind='financial_cost_verified'"):
        event, proof = _source_event(store, row[0])
        if event['sequence'] < value['upgrade_sequence']:
            if old_costs.get(event['sequence']) != event['hash'] or proof.get('financial_pins') != old_pins:
                raise ValueError('original cumulative cost history differs')
        elif proof.get('financial_pins') != pins:
            raise ValueError('new financial cost uses previous or foreign pins')
        if proof.get('budget') not in totals:
            raise ValueError('original cost lacks its budget classification')
        identity = _cost_key(proof)
        if identity in seen:
            raise ValueError('same actual cost counted twice across financial pins')
        seen.add(identity)
        totals[proof['budget']] += integer(proof['amount_msat'], 'actual cumulative cost')
        if proof.get('action_id'):
            if proof['action_id'] in covered:
                raise ValueError('same native client cost counted twice')
            covered.add(proof['action_id'])
    for row in store.db.execute("SELECT id FROM action WHERE state='completed' AND actual_fee_sat>0"):
        if row['id'] not in covered:
            raise ValueError('paid original action lacks its retained cost source')
    held = store.db.execute("SELECT COALESCE(SUM(fee_reservation_sat),0) FROM action WHERE state IN ('queued','dispatched','outcome_unknown') AND (? IS NULL OR id!=?)",
                            (reserved_action_id, reserved_action_id)).fetchone()[0]
    totals['ordinary'] += integer(held, 'existing client fee reservations') * 1000
    return totals


def _runtime(store, sequence, pins, config, *, now):
    event, proof = _source_event(store, sequence)
    release = proof.get('execution_release', {})
    if (event['kind'] != 'owned_runtime_configuration_verified'
            or proof.get('product_commit') != pins['product_commit']
            or proof.get('schema_sha256') != pins['schema_sha256']
            or proof.get('loaded_configuration_identity_verified') is not True
            or any(release.get(key) != pins[key] for key in pins)
            or release.get('image_sha256') != config.expected_image
            or set(proof.get('daemons', {})) != {'captaind', 'watchmand'}
            or type(proof.get('observed_at')) not in (int, float)
            or not 0 <= now - proof['observed_at'] <= 90):
        raise ValueError('authenticated final runtime/SDK/driver/config/schema source required')
    # The admitted existing runtime-source producer authenticates same-process
    # loaded config, startup/current file hashes, executable, mounts and guards.
    for name in ('startup_source_sha256', 'current_source_sha256'):
        import re
        if re.fullmatch('[0-9a-f]{64}', proof.get(name, '')) is None:
            raise ValueError('actual startup/current runtime source identities required')
    for daemon in proof['daemons'].values():
        if (type(daemon.get('pid')) is not int or daemon['pid'] <= 0
                or not isinstance(daemon.get('started_at'), str) or not daemon['started_at']
                or daemon.get('image_sha256') != config.expected_image
                or any(re.fullmatch('[0-9a-f]{64}', daemon.get(key, '')) is None
                       for key in ('binary_sha256', 'config_sha256'))):
            raise ValueError('actual paired running daemon artifact/config identities required')
    return event


def record_upgrade(store, config, chain, declaration, *, source_verifier=None):
    """Root calls under its existing sole Store lease while dispatch is paused.

    source_verifier is an explicitly installed, separately source-qualified
    Python dependency, never a command or flag selected by a source response.
    It replays exhaustive original/current physical membership, old rights and
    retirements, original flows, added preexisting assets and final runtime.
    Missing verifier or actual source coverage refuses before the overlay.
    """
    from .cln_router_cost import require_routing_reconciliation
    require_routing_reconciliation(store)
    if not callable(source_verifier):
        raise ValueError('admitted exhaustive normal-source verifier required')
    _require_leases(store, config)
    existing = recorded(store)
    if existing is not None:
        if existing['declaration_sha256'] != _digest(declaration):
            raise ValueError('financial upgrade immutable; no replacement or budget reset')
        return existing['upgrade_sequence']
    if set(declaration) != {'id', 'previous_boundary_sha256', 'previous_envelope_sha256', 'boundary', 'envelope'}:
        raise ValueError('exact explicit preserved financial upgrade required')
    public_payload(declaration)
    store.verify_event_chain()
    if (not store.get_meta('paused') or store.get_meta('final_financial_epoch') is not None
            or store.db.execute("SELECT 1 FROM action WHERE state IN ('queued','dispatched','outcome_unknown') LIMIT 1").fetchone()):
        raise ValueError('pause and reconcile every original client action before financial upgrade')
    from .exploratory import scope
    if scope(store) is not None:
        raise ValueError('close original exploratory scope without resetting its history')
    for table, states in (
            ('actor_lease', ('active', 'outcome_unknown')),
            ('funding_batch', ('broadcasting', 'outcome_unknown')),
            ('seed_recovery', ('preparing', 'prepare_unknown', 'broadcasting', 'outcome_unknown'))):
        if store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
            if store.db.execute('SELECT 1 FROM ' + table + ' WHERE state IN (' + ','.join('?' for _ in states) + ') LIMIT 1', states).fetchone():
                raise ValueError('unresolved original controller blocks upgrade: ' + table)
    from .treasury import _members, _capture_assets, reconcile_edge
    from .operating_limits import validate
    originals = _originals(store)
    old_boundary, old_envelope = (entry[0] for entry in originals)
    new_boundary, limits = declaration['boundary'], declaration['envelope']
    if (declaration['previous_boundary_sha256'] != originals[0][1]['sha256']
            or declaration['previous_envelope_sha256'] != originals[1][1]['sha256']):
        raise ValueError('explicit old declaration hashes differ')
    old_members = _members(old_boundary)
    members = _members(new_boundary)
    _pins(new_boundary['pins']); validate(limits, config)
    if getattr(config, 'expected_sdk_commit', None) != new_boundary['pins']['sdk_commit']:
        raise ValueError('actual configured SDK differs from proposed execution pins')
    if (new_boundary['id'] == old_boundary['id'] or limits['id'] == old_envelope['id']
            or limits['pins'] != new_boundary['pins'] or limits['boundary_id'] != new_boundary['id']
            or new_boundary['genesis'] != old_boundary['genesis']
            or new_boundary['excluded'] != old_boundary['excluded']
            or limits['fee_budgets_msat'] != old_envelope['fee_budgets_msat']):
        raise ValueError('new explicit identity required with original budgets/exclusions retained')
    for identity, old in old_members.items():
        if identity not in members or any(old[key] != members[identity][key]
                for key in ('id', 'kind', 'role', 'identity', 'descriptors')):
            raise ValueError('original member ownership cannot be removed or redirected')
    member_sources = set()
    for member in members.values():
        member_event, member_proof = _source_event(store, member['verification_sequence'])
        if (member_event['kind'] != 'treasury_member_verified'
                or member_proof.get('member') != {k: v for k, v in member.items() if k != 'verification_sequence'}
                or member_proof.get('genesis') != new_boundary['genesis']
                or member_proof.get('financial_pins') != new_boundary['pins']):
            raise ValueError('new execution membership lacks its original owning source')
        member_sources.add(member_event['sequence'])
        for descriptor in member['descriptors']:
            details = chain.call('getdescriptorinfo', descriptor)
            if details.get('hasprivatekeys') is not False or details.get('descriptor') != descriptor:
                raise ValueError('canonical public owning descriptor required')
    for path, rate in old_envelope['fee_ceilings_sat_kvb'].items():
        new = limits['fee_ceilings_sat_kvb'][path]
        if rate is not None and (new is None or new > rate):
            raise ValueError('upgrade cannot remove or raise existing fee ceilings')
    if limits['per_action_fee_sat'] > old_envelope['per_action_fee_sat']:
        raise ValueError('upgrade cannot raise the original per-action fee guard')
    for field in ('grant_sat', 'board_sat', 'board_fee_reserve_sat'):
        if limits[field] != old_envelope[field]:
            raise ValueError('original grant/Board policy requires a separate explicit authorized scope')
    for field in ('minimum_pool_sat', 'minimum_channel_msat'):
        if limits[field] < old_envelope[field]:
            raise ValueError('upgrade cannot weaken original pool/channel readiness guards')
    for operation, paths in old_envelope.get('operation_fee_paths', {}).items():
        if not set(paths) <= set(limits.get('operation_fee_paths', {}).get(operation, [])):
            raise ValueError('upgrade cannot drop original operation fee-path guards')
    before_context = _context(store)
    source_path = inspect.getsourcefile(source_verifier)
    if source_path is None:
        raise ValueError('admitted source verifier file identity unavailable')
    source_sha256 = hashlib.sha256(Path(source_path).read_bytes()).hexdigest()
    copied = json.loads(canonical(declaration))
    proof = source_verifier(store, config, chain, old_boundary, old_envelope,
                            copied['boundary'], copied['envelope'])
    store.verify_event_chain()
    _require_leases(store, config)
    if _context(store) != before_context:
        raise ValueError('source verifier must not rewrite financial context or append events')
    if not isinstance(proof, dict) or set(proof) != {
            'opening_assets', 'inventory_sequences', 'flow_sequences', 'liability_sequences',
            'runtime_source_sequence', 'source_sequences', 'cost_payers'}:
        raise ValueError('complete original source references required; labels are insufficient')
    if (not isinstance(proof['source_sequences'], list) or not proof['source_sequences']
            or len(proof['source_sequences']) > 10000
            or len(set(proof['source_sequences'])) != len(proof['source_sequences'])):
        raise ValueError('bounded distinct original opening/member/flow source references required')
    runtime = _runtime(store, proof['runtime_source_sequence'], new_boundary['pins'], config, now=time.time())
    closing = _capture_assets(store, new_boundary, proof['inventory_sequences'], chain)
    if closing['total_msat'] > limits['capital_exposure_msat']:
        raise ValueError('actual expanded treasury exceeds declared capital exposure')
    costs = []; flows = []; seen = set()
    from .financial_transition import _original_cost
    for row in store.db.execute("SELECT sequence FROM event WHERE kind='financial_cost_verified' ORDER BY sequence"):
        event, cost = _original_cost(store, row[0])
        if cost.get('financial_pins') != old_boundary['pins'] or cost.get('budget') not in {'ordinary', 'urgent'}:
            raise ValueError('original cost financial lineage differs')
        if cost.get('kind') != 'router_cost':
            tx = chain.transaction(cost['txid'])
            if (tx.get('txid') != cost['txid'] or tx.get('confirmations', 0) < 1
                    or tx['fee_sat'] * 1000 != cost['amount_msat']):
                raise ValueError('original miner cost differs from independent confirmed chain')
        identity = _cost_key(cost)
        if identity in seen:
            raise ValueError('same original miner cost counted twice')
        seen.add(identity)
        payer = proof['cost_payers'].get(event['sequence'])
        if payer not in members:
            raise ValueError('original cost needs its independently authenticated paying member')
        costs.append({'sequence': event['sequence'], 'hash': event['hash'], 'budget': cost['budget'],
                      'payer': payer,
                      'amount_msat': integer(cost['amount_msat'], 'retained actual miner fee')})
        if cost.get('kind') == 'router_cost' and payer != cost['source']:
            raise ValueError('retained router payer cannot be reassigned by upgrade')
        flows.append({'id': cost['monetary_id'], 'kind': cost['kind'], 'source': payer,
                      'destination': cost['destination'] if cost['kind']=='router_cost' else 'outside-bitcoin-miners',
                      'amount_msat': cost['amount_msat']})
    references = set(proof['source_sequences']) | set(proof['inventory_sequences'].values()) | member_sources | {runtime['sequence']}
    for sequence in proof['flow_sequences']:
        event, flow = _source_event(store, sequence)
        if event['kind'] != 'treasury_flow_verified' or set(flow) != {'id', 'kind', 'source', 'destination', 'amount_msat'}:
            raise ValueError('original independently qualified unique treasury flow required')
        flows.append(flow); references.add(sequence)
    liabilities = []
    for sequence in proof['liability_sequences']:
        event, liability = _source_event(store, sequence)
        if event['kind'] != 'treasury_liability_verified' or set(liability) != {'id', 'borrower', 'amount_msat'}:
            raise ValueError('original independently qualified liability source required')
        liabilities.append(liability); references.add(sequence)
    # Independent asset capture and conservation remain mandatory even after
    # an admitted source verifier. Preexisting CLN belongs in opening assets,
    # not among flows; duplicated receipts or unexplained assets fail here.
    reconciliation = reconcile_edge(proof['opening_assets'], closing, flows, liabilities, members)
    funded = 0
    for point in limits['fee_assets']:
        asset = closing['assets'].get(point)
        if (asset is None or asset['role'] != 'operator' or asset['backing_outpoint'] != point
                or members[asset['member']]['kind'] != 'wallet'):
            raise ValueError('fee funding must be actual confirmed operator wallet inputs')
        funded += asset['amount_msat']
    if funded < sum(limits['fee_budgets_msat'].values()):
        raise ValueError('retained ordinary and urgent budgets lack confirmed fee funding')
    for budget, maximum in limits['fee_budgets_msat'].items():
        if sum(row['amount_msat'] for row in costs if row['budget'] == budget) > maximum:
            raise ValueError('retained cumulative fee budget already exhausted')
    references.update(row['sequence'] for row in costs)
    sources = [{'sequence': sequence, 'hash': _source_event(store, sequence)[0]['hash']}
               for sequence in sorted(references)]
    if hashlib.sha256(Path(source_path).read_bytes()).hexdigest() != source_sha256:
        raise ValueError('admitted source verifier bytes changed during verification')
    value = {'id': declaration['id'], 'declaration_sha256': _digest(declaration),
             'previous_boundary': originals[0][1], 'previous_envelope': originals[1][1],
             'boundary': new_boundary, 'envelope': limits, 'sources': sources, 'costs': costs,
             'reconciliation': reconciliation, 'closing_assets': closing,
             'source_verifier_sha256': source_sha256,
             'source_verifier': source_verifier.__module__ + '.' + source_verifier.__qualname__,
             'financial_readiness': False, 'dispatch_authority': False, 'fee_budget_reset': False}
    with store.transaction():
        if (recorded(store) is not None or _originals(store) != originals
                or _context(store) != before_context):
            raise ValueError('original financial state changed during upgrade verification')
        _require_leases(store, config)
        store.verify_event_chain()
        store._event(EVENT, value)
        sequence = store.db.execute('SELECT MAX(sequence) FROM event').fetchone()[0]
    return sequence

"""Public SDK classification of operator round padding and backing subsets.

Raw inventory is never rewritten. Decoding identifies the protocol marker;
confirmed backing and a fresh positive UTXO observation qualify locked value.
An absent UTXO is not evidence of a sweep. Padding is already included in tree
backing, so its attribution is never another term in the asset identity.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
from pathlib import Path

from .model import InvariantError, btc_to_sat, canonical, integer, public_payload
from .process import json_command
from .bundle_audit import decode_transaction

PADDING_PUBKEY = '02dfa52f6690299d2d6a08323083e290597b56fee125063e5f4e2957731639c42c'
PADDING_UNLOCK_HASH = 'deadbeef' * 8
PADDING_AMOUNT_SAT = 330
SCHEMA = '''
CREATE TABLE IF NOT EXISTS server_coin_classification(
 coin_id TEXT PRIMARY KEY,signed_hash TEXT NOT NULL,verifier_hash TEXT NOT NULL,
 server_pubkey TEXT NOT NULL,classification TEXT NOT NULL,proof TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tree_padding_contract(
 coin_id TEXT PRIMARY KEY,signed_hash TEXT NOT NULL,verifier_hash TEXT NOT NULL,
 anchor TEXT NOT NULL,proof TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tree_padding_backing(
 outpoint TEXT PRIMARY KEY,amount_sat INTEGER NOT NULL,script TEXT NOT NULL,proof TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tree_padding_sweep(txid TEXT PRIMARY KEY,height INTEGER NOT NULL,evidence TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS server_coin_decode_attempt(coin_id TEXT PRIMARY KEY,last_attempt REAL NOT NULL);
CREATE TABLE IF NOT EXISTS tree_padding_snapshot(snapshot_id INTEGER PRIMARY KEY,height INTEGER NOT NULL,payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tree_padding_anchor_observation(
 anchor TEXT PRIMARY KEY,height INTEGER NOT NULL,block_hash TEXT NOT NULL,
 observed_at REAL NOT NULL,evidence TEXT NOT NULL);
'''


def initialize(store):
    # executescript commits an enclosing entitlement transaction implicitly.
    for statement in SCHEMA.split(';'):
        if statement.strip():
            store.db.execute(statement)


def _signed_hash(row):
    value = row.get('signed_vtxo')
    if not isinstance(value, str) or len(value) > 2097152 or len(value) % 2:
        raise ValueError('invalid bounded serialized coin')
    return hashlib.sha256(bytes.fromhex(value)).hexdigest()


def _marker(proof):
    return (proof.get('policy') == 'pubkey'
            and proof.get('candidate_user_pubkey') == PADDING_PUBKEY
            and proof.get('unlock_hash') == PADDING_UNLOCK_HASH
            and proof.get('amount_sat') == PADDING_AMOUNT_SAT
            and type(proof.get('arkoor_transition_count')) is int
            and proof['arkoor_transition_count'] == 0)


def record_decoded(store, row, proof, server_pubkey, verifier_hash):
    """Accept only the pinned public decoder response, never server flags."""
    initialize(store)
    public_payload(proof)
    if (proof.get('schema_version') != 1 or proof.get('id') != row['vtxo_id']
            or proof.get('server_pubkey') != server_pubkey
            or proof.get('expiry_height') != row.get('expiry')
            or proof.get('client_owner_verified') is not False
            or proof.get('chain_contract_verified') is not False):
        raise InvariantError('public coin decoder identity or scope differs')
    integer(proof['amount_sat'], 'decoded coin amount', 1)
    integer(proof['arkoor_transition_count'], 'decoded arkoor transition count')
    marker = _marker(proof)
    if (type(proof.get('tree_padding')) is not bool or proof['tree_padding'] != marker
            or marker and row.get('policy_type') != 'pubkey'):
        raise InvariantError('public coin decoder padding marker differs')
    signed_hash = _signed_hash(row)
    classification = 'round_padding' if marker else 'other'
    previous = store.db.execute('SELECT * FROM server_coin_classification WHERE coin_id=?',
                                (row['vtxo_id'],)).fetchone()
    encoded = canonical({**proof, 'source_signed_vtxo': row['signed_vtxo']})
    values = (row['vtxo_id'], signed_hash, verifier_hash, server_pubkey, classification, encoded)
    if previous is not None and tuple(previous) == values:
        return
    with store.transaction():
        store.db.execute('INSERT OR REPLACE INTO server_coin_classification VALUES (?,?,?,?,?,?)', values)
        store._event('server_coin_classified', {'coin_id': row['vtxo_id'],
            'signed_hash': signed_hash, 'verifier_hash': verifier_hash,
            'classification': classification, 'sdk_commit': proof.get('sdk_commit'),
            'customer_ownership_verified': False, 'chain_backing_verified': False})


def classification(store, row):
    initialize(store)
    saved = store.db.execute('SELECT * FROM server_coin_classification WHERE coin_id=?',
                            (row.get('vtxo_id'),)).fetchone()
    if saved is None:
        return None
    try:
        if saved['signed_hash'] != _signed_hash(row):
            return None
        proof = json.loads(saved['proof'])
        if (proof.get('id') != row['vtxo_id'] or proof.get('expiry_height') != row.get('expiry')
                or proof.get('server_pubkey') != saved['server_pubkey']
                or proof.get('client_owner_verified') is not False):
            return None
        if saved['classification'] == 'round_padding' and (
                not _marker(proof) or row.get('policy_type') != 'pubkey'):
            return None
    except (KeyError, TypeError, ValueError):
        return None
    return saved['classification']


async def collect(store, command, server_pubkey, *, limit=8):
    """Bounded, resumable public decoding, independent of wallets and Core."""
    initialize(store)
    if not command:
        return
    integer(limit, 'public classification batch', 1)
    if limit > 32 or len(command) != 1:
        raise ValueError('bounded classification needs one pinned public executable')
    executable = Path(command[0])
    if not executable.is_absolute() or executable.is_symlink():
        raise ValueError('unsafe public classification executable')
    with executable.open('rb') as stream:
        verifier_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
    rows = []
    for saved in store.db.execute("SELECT payload,observed_at FROM server_item WHERE kind='coins' ORDER BY id"):
        row = json.loads(saved['payload'])
        old = store.db.execute('SELECT signed_hash,verifier_hash FROM server_coin_classification WHERE coin_id=?',
                               (row['vtxo_id'],)).fetchone()
        try:
            if old and (old['signed_hash'], old['verifier_hash']) == (_signed_hash(row), verifier_hash):
                continue
        except (ValueError, TypeError):
            pass
        attempt = store.db.execute('SELECT last_attempt FROM server_coin_decode_attempt WHERE coin_id=?', (row['vtxo_id'],)).fetchone()
        rows.append((row, saved['observed_at'], attempt[0] if attempt else 0))
    # Current unclaimed replacements precede spent history. Within each group,
    # new observations precede older ones, while failed decodes rotate fairly.
    rows.sort(key=lambda item: (item[0].get('spend_state') != 'unclaimed', item[2], -item[1], item[0]['vtxo_id']))
    for row, _, _ in rows[:limit]:
        try:
            request = {'signed_vtxo': row['signed_vtxo'], 'server_pubkey': server_pubkey}
            store.trace_capture('padding.decode', {'phase': 'request', 'request': request})
            response = await json_command(list(command), request, timeout=30,
                on_stdout_raw=_capture(store, 'padding.decode.stdout'),
                on_stderr_raw=_capture(store, 'padding.decode.stderr'))
            store.trace_capture('padding.decode', {'phase': 'response', 'response': response})
            record_decoded(store, row, response, server_pubkey, verifier_hash)
        except InvariantError:
            raise
        except (KeyError, TypeError, ValueError, RuntimeError, TimeoutError) as error:
            store.event('server_coin_classification_pending', {'coin_id': row['vtxo_id'],
                'reason': type(error).__name__, 'excluded_from_user_counts': False})
        store.db.execute('INSERT OR REPLACE INTO server_coin_decode_attempt VALUES (?,?)', (row['vtxo_id'], time.time()))


def _capture(store, kind):
    def capture(record):
        store.trace_capture(kind, {key: value for key, value in record.items() if key != 'raw'}, raw=record['raw'])
    return capture


def decoded_coin(store, row, *, server_pubkey=None):
    """Current serialized-byte-bound decoder evidence, with no ownership claim."""
    if classification(store, row) is None:
        return None
    saved = store.db.execute('SELECT * FROM server_coin_classification WHERE coin_id=?', (row['vtxo_id'],)).fetchone()
    if server_pubkey is not None and saved['server_pubkey'] != server_pubkey:
        return None
    return {**json.loads(saved['proof']), 'signed_hash': saved['signed_hash'],
            'verifier_hash': saved['verifier_hash'], 'scope': 'SDK decoding only; customer ownership, signatures, backing confirmation and spend status are unproved'}


def record_contract(store, request, proof, verifier_hash):
    """Check the exact raw anchor around a pinned native server-policy proof."""
    initialize(store)
    public_payload(request); public_payload(proof)
    raw = decode_transaction(request['anchor_raw'])
    txid, index = proof['chain_anchor'].split(':'); index = integer(int(index), 'padding anchor index')
    output = raw['outputs'][index]
    row = store.db.execute("SELECT payload FROM server_item WHERE kind='coins' AND id=?", (proof['id'],)).fetchone()
    if row is None:
        raise InvariantError('padding contract lacks its public inventory')
    row = json.loads(row[0]); decoded = decoded_coin(store, row, server_pubkey=request['server_pubkey'])
    if (not decoded or not _marker(proof) or proof.get('padding_backing_structure_verified') is not True
            or proof.get('chain_contract_verified') is not False or proof.get('signed_path_valid') is not False
            or proof.get('client_owner_verified') is not False or txid != raw['txid']
            or proof.get('server_pubkey') != request['server_pubkey']
            or decoded['verifier_hash'] != verifier_hash or _signed_hash(row) != _signed_hash(request)
            or any(proof.get(key) != decoded.get(key) for key in ('id', 'chain_anchor', 'expiry_height', 'amount_sat', 'policy', 'unlock_hash', 'candidate_user_pubkey', 'arkoor_transition_count'))
            or (proof.get('anchor_amount_sat'), proof.get('anchor_script')) != (output['amount_sat'], output['script'])
            or proof['amount_sat'] > output['amount_sat']):
        raise InvariantError('padding raw contract identity, marker or scope differs')
    old = store.db.execute('SELECT * FROM tree_padding_backing WHERE outpoint=?', (proof['chain_anchor'],)).fetchone()
    if old and (old['amount_sat'], old['script']) != (output['amount_sat'], output['script']):
        raise InvariantError('immutable padding backing differs')
    proof = {**proof, 'signed_hash': _signed_hash(request)}
    with store.transaction():
        store.db.execute('INSERT OR REPLACE INTO tree_padding_contract VALUES (?,?,?,?,?)',
            (proof['id'], proof['signed_hash'], verifier_hash, proof['chain_anchor'], canonical(proof)))
        store.db.execute('INSERT OR IGNORE INTO tree_padding_backing VALUES (?,?,?,?)',
            (proof['chain_anchor'], output['amount_sat'], output['script'], canonical(proof)))
        store._event('tree_padding_contract_verified', {'coin_id': proof['id'], 'anchor': proof['chain_anchor'],
            'signed_hash': proof['signed_hash'], 'verifier_hash': verifier_hash, 'customer_ownership_verified': False})


def record_sweep(store, transaction, raw_transactions):
    """A confirmed exact raw spend to already declared operator scripts only."""
    initialize(store)
    from .ownership import EvidenceGap
    public_payload(transaction)
    if type(transaction.get('confirmations')) is not int or transaction['confirmations'] < 1:
        raise EvidenceGap('padding sweep is not independently confirmed')
    height = integer(transaction['height'], 'padding sweep height')
    raw = decode_transaction(raw_transactions[transaction['txid']])
    if raw['txid'] != transaction['txid']:
        raise InvariantError('padding sweep raw identity differs')
    points = [item['outpoint'] for item in raw['inputs']]
    if len(points) != len(set(points)):
        raise InvariantError('padding sweep repeats an input')
    inputs = []
    for point in points:
        txid, index = point.split(':')
        parent = decode_transaction(raw_transactions[txid])
        if parent['txid'] != txid:
            raise InvariantError('padding sweep raw parent identity differs')
        value = parent['outputs'][integer(int(index), 'padding sweep parent index')]
        inputs.append({'outpoint': point, 'amount_sat': value['amount_sat'], 'script': value['script']})
    roles = {row[0] for row in store.db.execute('SELECT script FROM operator_script')}
    backing = {row['outpoint']: row for row in store.db.execute('SELECT * FROM tree_padding_backing')}
    if not any(point in backing for point in points):
        raise EvidenceGap('padding sweep does not spend a checked backing anchor')
    if any(item['outpoint'] not in backing and item['script'] not in roles for item in inputs):
        raise EvidenceGap('padding sweep input ownership is unverified')
    if any(output['amount_sat'] and output['script'] not in roles for output in raw['outputs']):
        raise EvidenceGap('padding sweep return script ownership is unverified')
    for item in inputs:
        owned = backing.get(item['outpoint'])
        if owned and (owned['amount_sat'], owned['script']) != (item['amount_sat'], item['script']):
            raise InvariantError('padding sweep spends a different backing value or script')
    if sum(item['amount_sat'] for item in inputs) < sum(item['amount_sat'] for item in raw['outputs']):
        raise InvariantError('padding sweep raw value does not conserve')
    evidence = {'raw_chain_verified': True, 'block_hash': transaction['blockhash'],
        'transaction': {'txid': transaction['txid'], 'inputs': inputs, 'outputs': raw['outputs']},
        'scope': 'independent Core confirmation and exact raw input/return ownership; no claim about net padding recovery or fee allocation'}
    old = store.db.execute('SELECT * FROM tree_padding_sweep WHERE txid=?', (transaction['txid'],)).fetchone()
    encoded = canonical(evidence)
    if old:
        if (old['height'], old['evidence']) != (height, encoded):
            raise InvariantError('immutable padding sweep changed')
        return
    with store.transaction():
        store.db.execute('INSERT INTO tree_padding_sweep VALUES (?,?,?)', (transaction['txid'], height, encoded))
        store._event('tree_padding_sweep_verified', {'txid': transaction['txid'], 'height': height,
            'customer_traffic': False, 'additive_asset': False})


def record_anchor_observation(store, anchor, tip, utxo):
    initialize(store)
    integer(tip['blocks'], 'padding observation height')
    public_payload(utxo)
    evidence = {'tip': tip, 'utxo': utxo, 'positive_unspent': False}
    if (tip.get('initialblockdownload') is False and isinstance(utxo, dict)
            and utxo.get('bestblock') == tip['bestblockhash']
            and type(utxo.get('confirmations')) is int and utxo['confirmations'] >= 1):
        evidence['positive_unspent'] = True
    with store.transaction():
        store.db.execute('INSERT OR REPLACE INTO tree_padding_anchor_observation VALUES (?,?,?,?,?)',
            (anchor, tip['blocks'], tip['bestblockhash'], time.time(), canonical(evidence)))
        store._event('tree_padding_backing_observed', {'anchor': anchor, 'height': tip['blocks'],
            'block_hash': tip['bestblockhash'], 'positive_unspent': evidence['positive_unspent'],
            'null_utxo_proves_sweep': False})


def capture_snapshot(store, snapshot_id, snapshot):
    """Keep padding attribution at its observation time, never backfill history."""
    initialize(store)
    integer(snapshot_id, 'padding snapshot id', 1)
    height = integer(snapshot['height'], 'padding snapshot height')
    existing = store.db.execute('SELECT payload FROM tree_padding_snapshot WHERE snapshot_id=?', (snapshot_id,)).fetchone()
    if existing:
        return json.loads(existing[0])
    result = report(store, height=height)
    if snapshot.get('stable_tip') is not True or snapshot.get('initial_block_download') is not False:
        result['tree_padding_locked_sat'] = None
        result['unknowns'].append({'bucket': 'padding_snapshot', 'reason': 'stable synced chain snapshot is missing'})
    with store.transaction():
        store.db.execute('INSERT INTO tree_padding_snapshot VALUES (?,?,?)', (snapshot_id, height, canonical(result)))
        store._event('tree_padding_snapshot', {'snapshot_id': snapshot_id, 'height': height,
            'tree_padding_locked_sat': result['tree_padding_locked_sat'], 'additive_asset': False})
    return result


def csv_values(store, snapshot_id):
    initialize(store)
    row = store.db.execute('SELECT payload FROM tree_padding_snapshot WHERE snapshot_id=?', (snapshot_id,)).fetchone()
    result = json.loads(row[0]) if row else {}
    return {key: result.get(key) for key in ('tree_padding_locked_sat', 'tree_padding_unclaimed', 'tree_padding_swept')}


async def collect_backing(store, chain, command, server_pubkey, *, limit=2):
    """Independently verify raw padding anchors and current positive UTXOs."""
    initialize(store)
    integer(limit, 'padding backing batch', 1)
    if limit > 32 or len(command) != 1:
        raise ValueError('padding backing needs one pinned executable and bounded batch')
    executable = Path(command[0])
    if not executable.is_absolute() or executable.is_symlink():
        raise ValueError('unsafe padding backing executable')
    with executable.open('rb') as stream:
        verifier_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
    rows = []
    for saved in store.db.execute("SELECT payload FROM server_item WHERE kind='coins' ORDER BY id"):
        row = json.loads(saved[0]); proof = decoded_coin(store, row, server_pubkey=server_pubkey)
        if proof and proof['verifier_hash'] == verifier_hash and proof['tree_padding']:
            rows.append((row, proof))
    cursor = store.get_meta('tree_padding_backing_cursor') or ''
    ordered = [r for r in rows if r[0]['vtxo_id'] > cursor] + [r for r in rows if r[0]['vtxo_id'] <= cursor]
    for row, decoded in ordered[:limit]:
        try:
            tip = await asyncio.to_thread(chain.identity)
            anchor = decoded['chain_anchor']; txid, index = anchor.split(':')
            transaction = await asyncio.to_thread(chain.tx, txid)
            if transaction.get('confirmations', 0) < 1:
                raise ValueError('padding backing anchor unconfirmed')
            existing = store.db.execute('SELECT signed_hash,verifier_hash FROM tree_padding_contract WHERE coin_id=?', (row['vtxo_id'],)).fetchone()
            if existing is None or (existing['signed_hash'], existing['verifier_hash']) != (decoded['signed_hash'], verifier_hash):
                request = {'signed_vtxo': row['signed_vtxo'], 'server_pubkey': server_pubkey, 'anchor_raw': transaction['hex']}
                store.trace_capture('padding.contract', {'phase': 'request', 'request': request})
                proof = await json_command(list(command), request, timeout=30,
                    on_stdout_raw=_capture(store, 'padding.contract.stdout'), on_stderr_raw=_capture(store, 'padding.contract.stderr'))
                store.trace_capture('padding.contract', {'phase': 'response', 'response': proof})
                record_contract(store, request, proof, verifier_hash)
            utxo = await asyncio.to_thread(chain.call, 'gettxout', txid, int(index), True)
            closing = await asyncio.to_thread(chain.identity)
            if (tip.get('bestblockhash'), tip.get('blocks')) != (closing.get('bestblockhash'), closing.get('blocks')):
                utxo = None
            record_anchor_observation(store, anchor, closing, utxo)
            hint = row.get('onchain_spent_txid')
            if not isinstance(hint, str):
                backing_row = store.db.execute("SELECT payload FROM server_item WHERE kind='coins' AND id=?", (anchor,)).fetchone()
                if backing_row:
                    hint = json.loads(backing_row['payload']).get('onchain_spent_txid')
            # A leaf or exact backing-row hint only selects a read-only query.
            # Exact raw inputs, confirmation and declared return ownership still
            # decide whether this is a sweep; neither server state nor null UTXO does.
            if isinstance(hint, str):
                spent = await asyncio.to_thread(chain.tx, hint)
                raw = decode_transaction(spent['hex'])
                wires = {hint: spent['hex']}
                for item in raw['inputs']:
                    parent_id = item['outpoint'].split(':')[0]
                    parent = await asyncio.to_thread(chain.tx, parent_id); wires[parent_id] = parent['hex']
                height = closing['blocks'] - spent.get('confirmations', 0) + 1
                block_hash = await asyncio.to_thread(chain.call, 'getblockhash', height)
                if block_hash != spent.get('blockhash'):
                    raise ValueError('padding sweep confirmation block differs')
                record_sweep(store, {**spent, 'height': height}, wires)
        except InvariantError:
            raise
        except (KeyError, TypeError, ValueError, RuntimeError, TimeoutError) as error:
            store.event('tree_padding_backing_pending', {'coin_id': row['vtxo_id'], 'reason': type(error).__name__, 'null_utxo_proves_sweep': False})
        store.db.execute("INSERT OR REPLACE INTO meta VALUES ('tree_padding_backing_cursor',?)", (row['vtxo_id'],))


def report(store, *, height=None):
    initialize(store)
    if height is None:
        snapshot = store.db.execute('SELECT payload FROM snapshot ORDER BY id DESC LIMIT 1').fetchone()
        height = json.loads(snapshot[0]).get('height') if snapshot else None
    counts = {'tree_padding_unclaimed': 0, 'tree_padding_expired_unclaimed': 0,
              'tree_padding_server_spent': 0, 'tree_padding_swept': 0,
              'unclassified_coin_rows': 0}
    rows = [json.loads(r[0]) for r in store.db.execute("SELECT payload FROM server_item WHERE kind='coins'")]
    unknowns, groups, proofs = [], {}, {}
    if not rows:
        unknowns.append({'bucket': 'padding_inventory', 'reason': 'no observed inventory'})
    for row in rows:
        kind = classification(store, row)
        if kind is None:
            counts['unclassified_coin_rows'] += 1
            continue
        if kind != 'round_padding':
            continue
        state = row.get('spend_state')
        if state == 'unclaimed':
            counts['tree_padding_unclaimed'] += 1
            if type(height) is int and row['expiry'] < height:
                counts['tree_padding_expired_unclaimed'] += 1
        elif state == 'spent':
            counts['tree_padding_server_spent'] += 1
        else:
            unknowns.append({'bucket': 'padding_state', 'coin_id': row['vtxo_id'],
                             'reason': 'padding has an unexpected server state'})
        saved = store.db.execute('SELECT * FROM tree_padding_contract WHERE coin_id=?',
                                 (row['vtxo_id'],)).fetchone()
        classified = store.db.execute('SELECT * FROM server_coin_classification WHERE coin_id=?',
                                      (row['vtxo_id'],)).fetchone()
        proof = json.loads(saved['proof']) if saved else {}
        if (not saved or saved['signed_hash'] != classified['signed_hash']
                or saved['verifier_hash'] != classified['verifier_hash']
                or proof.get('server_pubkey') != classified['server_pubkey']
                or proof.get('padding_backing_structure_verified') is not True
            or proof.get('chain_contract_verified') is not False or proof.get('signed_path_valid') is not False or not _marker(proof)):
            unknowns.append({'bucket': 'padding_backing', 'coin_id': row['vtxo_id'],
                             'reason': 'no matching independently checked backing contract'})
            continue
        anchor = saved['anchor']
        groups.setdefault(anchor, []).append(row)
        proofs[anchor] = proof
    if counts['unclassified_coin_rows']:
        unknowns.append({'bucket': 'padding_classification', 'reason': 'some observed coins lack matching SDK decoding'})
    locked, backing = 0, 0
    for anchor, group in groups.items():
        output = store.db.execute('SELECT * FROM tree_padding_backing WHERE outpoint=?', (anchor,)).fetchone()
        proof = proofs[anchor]
        if (output is None or (output['amount_sat'], output['script']) !=
                (proof.get('anchor_amount_sat'), proof.get('anchor_script'))):
            raise InvariantError('padding backing value or script differs')
        amount = len(group) * PADDING_AMOUNT_SAT
        if amount > output['amount_sat']:
            raise InvariantError('padding subset exceeds its backing output')
        spent = []
        for tx in store.db.execute("SELECT height,evidence FROM tree_padding_sweep"):
            evidence = json.loads(tx['evidence'])
            if evidence.get('raw_chain_verified') is not True or type(height) is not int or tx['height'] > height:
                continue
            for item in evidence.get('transaction', {}).get('inputs', []):
                if item.get('outpoint') == anchor:
                    if (item.get('amount_sat'), item.get('script')) != (output['amount_sat'], output['script']):
                        raise InvariantError('padding sweep input value or script differs')
                    spent.append(evidence)
        if len(spent) > 1:
            raise InvariantError('padding backing has competing confirmed sweep spends')
        if spent:
            counts['tree_padding_swept'] += len(group)
            continue
        observation = store.db.execute('SELECT * FROM tree_padding_anchor_observation WHERE anchor=?', (anchor,)).fetchone()
        observed = json.loads(observation['evidence']) if observation else {}
        utxo = observed.get('utxo')
        if (observation and observed.get('positive_unspent') is True and observation['height'] == height
                and 0 <= time.time() - observation['observed_at'] <= 90
                and all(row.get('spend_state') == 'unclaimed' for row in group)):
            if (btc_to_sat(utxo['value']), utxo['scriptPubKey']['hex']) != (output['amount_sat'], output['script']):
                raise InvariantError('current padding UTXO value or script differs')
            locked += amount
            backing += output['amount_sat']
        else:
            unknowns.append({'bucket': 'padding_spend_status', 'anchor': anchor,
                'reason': 'fresh positive UTXO or raw confirmed operator sweep is missing; null UTXO and server spent are insufficient'})
    return {**counts, 'height': height, 'known_tree_padding_locked_sat': locked,
        'tree_padding_locked_sat': None if unknowns else locked,
        'padding_backing_confirmed_sat': backing, 'unknowns': unknowns,
        'inventory_consistent': False, 'additive_asset': False,
        'scope': 'observed SDK-decoded protocol leaves; locked padding is a subset of existing backing, never extra assets; partial paginated inventory does not establish a complete operator balance'}

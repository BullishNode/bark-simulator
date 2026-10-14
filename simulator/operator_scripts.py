"""Prove historical rounds-wallet scripts using public Core derivation.

A declared descriptor needs an independently confirmed output already attributed
to the rounds wallet. Derivation alone cannot adopt another wallet's change.
Only addresses seen in confirmed transactions are validated as scripts; the
bounded address index also covers spent change without thousands of RPC calls.
"""
import asyncio
import hashlib
import json

from .model import InvariantError, canonical, integer, public_payload
from .ownership import EvidenceGap
from .proof_import import _read, declared_paths

SCHEMA = '''
CREATE TABLE IF NOT EXISTS operator_descriptor(
 id TEXT PRIMARY KEY, declaration TEXT NOT NULL, descriptor TEXT NOT NULL,
 first_index INTEGER NOT NULL, last_index INTEGER NOT NULL, next_index INTEGER NOT NULL,
 anchor_outpoint TEXT, anchor_script TEXT);
CREATE TABLE IF NOT EXISTS operator_descriptor_source(path TEXT PRIMARY KEY, id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS operator_address(
 descriptor_id TEXT NOT NULL, derivation_index INTEGER NOT NULL, address TEXT NOT NULL,
 PRIMARY KEY(descriptor_id,derivation_index), UNIQUE(descriptor_id,address));
CREATE INDEX IF NOT EXISTS operator_address_lookup ON operator_address(address);
'''


def declaration_paths(values, wallet_root):
    paths = declared_paths(values, wallet_root)
    if len(paths) > 8: raise ValueError('at most eight public operator descriptors may be declared')
    return paths


def initialize(store):
    store.db.executescript(SCHEMA)


def _declaration(config, value):
    public_payload(value)
    required = {'schema_version', 'identity', 'descriptor', 'first_index', 'last_index'}
    if not isinstance(value, dict) or set(value) != required or type(value['schema_version']) is not int or value['schema_version'] != 1:
        raise EvidenceGap('complete public operator descriptor declaration required')
    expected = {'network': config.network, 'genesis': config.expected_genesis,
                'server_pubkey': config.expected_server_pubkey}
    if value['identity'] != expected: raise EvidenceGap('operator descriptor target mismatch')
    descriptor = value['descriptor']
    if not isinstance(descriptor, str) or not descriptor or len(descriptor) > 4096:
        raise EvidenceGap('bounded public descriptor required')
    first = integer(value['first_index'], 'first derivation index')
    last = integer(value['last_index'], 'last derivation index')
    if last < first or last > 1_000_000: raise EvidenceGap('bounded descriptor range required')
    return canonical(value)


async def _register(store, config, chain, path):
    value = _read(path)
    encoded = _declaration(config, value)
    identity = store.get_meta('target_identity')
    if identity and any(json.loads(identity).get(k) != v for k, v in value['identity'].items()):
        raise InvariantError('operator descriptor differs from frozen target identity')
    digest = hashlib.sha256(encoded.encode()).hexdigest()
    previous = store.db.execute('SELECT id FROM operator_descriptor_source WHERE path=?', (str(path),)).fetchone()
    if previous and previous['id'] != digest:
        raise InvariantError('public operator descriptor declaration changed')
    if store.db.execute('SELECT 1 FROM operator_descriptor WHERE id=?', (digest,)).fetchone(): return digest
    info = await asyncio.to_thread(chain.call, 'getdescriptorinfo', value['descriptor'])
    if info.get('hasprivatekeys') is not False or info.get('isrange') is not True or info.get('issolvable') is not True:
        raise EvidenceGap('operator descriptor must be public, ranged and solvable')
    descriptor = info.get('descriptor')
    public_payload(descriptor)
    if not isinstance(descriptor, str) or not descriptor or len(descriptor) > 4096:
        raise EvidenceGap('Core did not return a bounded canonical descriptor')
    with store.transaction():
        store.db.execute('INSERT INTO operator_descriptor VALUES (?,?,?,?,?,?,NULL,NULL)',
                         (digest, encoded, descriptor, value['first_index'], value['last_index'], value['first_index']))
        store.db.execute('INSERT INTO operator_descriptor_source VALUES (?,?)', (str(path), digest))
        store._event('operator_descriptor_declared', {'descriptor_id': digest, **value})
    return digest


async def _derive(store, chain, digest, batch_size):
    row = store.db.execute('SELECT * FROM operator_descriptor WHERE id=?', (digest,)).fetchone()
    first = row['next_index']
    if first > row['last_index']: return
    last = min(row['last_index'], first + batch_size - 1)
    addresses = await asyncio.to_thread(chain.call, 'deriveaddresses', row['descriptor'], [first, last])
    if (not isinstance(addresses, list) or len(addresses) != last - first + 1
            or len(set(addresses)) != len(addresses)
            or any(not isinstance(a, str) or not a or len(a) > 128 for a in addresses)):
        raise EvidenceGap('Core derivation returned an incomplete or ambiguous range')
    public_payload(addresses)
    with store.transaction():
        store.db.executemany('INSERT INTO operator_address VALUES (?,?,?)',
                            [(digest, first + offset, address) for offset, address in enumerate(addresses)])
        store.db.execute('UPDATE operator_descriptor SET next_index=? WHERE id=?', (last + 1, digest))
        store._event('operator_descriptor_range_verified', {'descriptor_id': digest, 'first_index': first, 'last_index': last})


async def _confirmed_outputs(chain, txid):
    tx = await asyncio.to_thread(chain.tx, txid)
    if tx.get('txid') != txid: raise InvariantError('operator script transaction identity mismatch')
    if integer(tx.get('confirmations', 0), 'confirmations') < 1: return []
    return tx.get('vout', [])


async def _matching_script(chain, address, script):
    result = await asyncio.to_thread(chain.call, 'validateaddress', address)
    if result.get('isvalid') is not True or result.get('scriptPubKey') != script:
        raise InvariantError('independent derived address differs from confirmed script')


async def _anchor(store, chain, digest):
    row = store.db.execute('SELECT anchor_outpoint FROM operator_descriptor WHERE id=?', (digest,)).fetchone()
    if row['anchor_outpoint']: return
    anchors = store.db.execute('SELECT script,evidence FROM operator_script ORDER BY script').fetchall()
    for anchor in anchors[:256]:
        evidence = json.loads(anchor['evidence'])
        point = evidence.get('outpoint')
        if not isinstance(point, str) or ':' not in point or evidence.get('confirmations', 0) < 1: continue
        txid, index = point.rsplit(':', 1)
        if not index.isdecimal(): continue
        for output in await _confirmed_outputs(chain, txid):
            script = output.get('scriptPubKey', {})
            if output.get('n') != int(index) or script.get('hex') != anchor['script']: continue
            address = script.get('address')
            match = store.db.execute('SELECT 1 FROM operator_address WHERE descriptor_id=? AND address=?',
                                     (digest, address)).fetchone()
            if not match: continue
            await _matching_script(chain, address, anchor['script'])
            with store.transaction():
                store.db.execute('UPDATE operator_descriptor SET anchor_outpoint=?,anchor_script=? WHERE id=?',
                                 (point, anchor['script'], digest))
                store._event('operator_descriptor_anchored', {'descriptor_id': digest, 'outpoint': point,
                                                            'script': anchor['script']})
            return


async def _payout_changes(store, chain, digest, limit):
    descriptor = store.db.execute('SELECT * FROM operator_descriptor WHERE id=?', (digest,)).fetchone()
    if not descriptor['anchor_outpoint']: return
    txids = set()
    for row in store.db.execute("SELECT payload FROM server_item WHERE kind='settlements'"):
        value = json.loads(row[0]); txid = value['txid']
        checked = store.db.execute('SELECT state FROM settlement_check WHERE txid=?', (txid,)).fetchone()
        if not checked or checked['state'] != 'amounts_checked': txids.add(txid)
    # Direct carriers include independently owned surplus and possibly a
    # Watchman fee-wallet change output. Verify each against declared public
    # descriptors; never infer wallet ownership from an input's funding role.
    from .direct_settlements import initialize as initialize_direct
    initialize_direct(store)
    for saved in store.db.execute("SELECT payload FROM direct_journal_object WHERE kind='carriers'"):
        carrier=json.loads(saved[0])
        if carrier['confirmed_height'] is None:continue
        txids.add(carrier['txid'])
        txids.update(item['outpoint'].rsplit(':',1)[0] for item in carrier['fee_inputs'])
    cursor = store.get_meta('operator_script_cursor') or ''
    ordered = sorted(txids); ordered = [t for t in ordered if t > cursor] + [t for t in ordered if t <= cursor]
    for txid in ordered[:limit]:
        for output in await _confirmed_outputs(chain, txid):
            script = output.get('scriptPubKey', {})
            if not script.get('hex') or store.db.execute('SELECT 1 FROM operator_script WHERE script=?', (script['hex'],)).fetchone(): continue
            match = store.db.execute('SELECT derivation_index FROM operator_address WHERE descriptor_id=? AND address=?',
                                     (digest, script.get('address'))).fetchone()
            if not match: continue
            await _matching_script(chain, script['address'], script['hex'])
            proof = {'descriptor_id': digest, 'derivation_index': match[0], 'address': script['address'],
                     'anchor_outpoint': descriptor['anchor_outpoint'], 'txid': txid, 'vout': output['n'],
                     'scope': 'public Core derivation, independently confirmed chain script and declared owning-wallet anchor'}
            with store.transaction():
                store.db.execute('INSERT INTO operator_script VALUES (?,?)', (script['hex'], canonical(proof)))
                store._event('operator_script_verified', {'script': script['hex'], **proof})
        store.db.execute("INSERT OR REPLACE INTO meta VALUES ('operator_script_cursor',?)", (txid,))


async def collect(store, config, chain, *, batch_size=2048, limit=2):
    if not config.operator_descriptors: return
    initialize(store)
    integer(batch_size, 'descriptor batch size', 1)
    if batch_size > 4096: raise ValueError('descriptor derivation batch exceeds bound')
    await asyncio.to_thread(chain.identity)
    remote = None
    if getattr(config, 'operator_bridge_enabled', False):
        from .operator_bridge import observe, match
        try:
            remote, bridge_reference = await observe(store, config)
        except Exception as error:
            # Keep prior ownership evidence; a bridge failure cannot declare a
            # new descriptor or make an unverified change output ours.
            reason = str(error) if isinstance(error, EvidenceGap) else type(error).__name__
            state = canonical({'path': 'rounds_descriptor bridge', 'reason': reason})
            if store.get_meta('operator_descriptor_bridge_gap') != state:
                with store.transaction():
                    store.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', ('operator_descriptor_bridge_gap', state))
                    store._event('operator_descriptor_pending', json.loads(state))
            return
    for path in config.operator_descriptors:
        try:
            if remote is not None:
                value = _read(path)
                _declaration(config, value)
                match(value, remote)
            digest = await _register(store, config, chain, path)
            if remote is not None:
                store.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',
                                 ('operator_descriptor_bridge_evidence_' + digest, canonical(bridge_reference)))
            await _derive(store, chain, digest, batch_size)
            await _anchor(store, chain, digest)
            await _payout_changes(store, chain, digest, limit)
        except InvariantError: raise
        except Exception as error:
            reason = str(error) if isinstance(error, EvidenceGap) else type(error).__name__
            state = canonical({'path': str(path), 'reason': reason})
            key = 'operator_descriptor_gap_' + hashlib.sha256(str(path).encode()).hexdigest()
            if store.get_meta(key) != state:
                with store.transaction():
                    store.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', (key, state))
                    store._event('operator_descriptor_pending', json.loads(state))

"""C-only owning-wallet auxiliary source for an admitted normal factory.

The two fixed native RPCs already exist. This source opens no SDK wallet, signs
nothing, changes no service and emits no financial readiness. It authenticates
original responses, reuses the shared wallet/descriptor/treasury reducers, and
retains a narrow two-wallet source for the enclosing exhaustive collector.
"""
import asyncio
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import time

from .architecture import DIRECT_PER_KEY, profile
from .final_campaign import _pins, _source_event
from .model import SIGNET_GENESIS, btc_to_sat, canonical, integer, public_payload
from .process import decode_object, text_command

OWNERS = ('rounds', 'watchman')
KIND = 'c_native_owning_wallet_auxiliary_source'
RAW_KIND = 'c_native_owning_wallet.original'
VALIDATOR = Path(__file__).resolve().parent.parent/'deploy/track-c/public_observer.py'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _sha(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError('exact owning source hash required')
    return value


class FixedOwningReader:
    """Only root-admitted complete argv ending in the literal existing ops read.

    Commands are trusted constructor data, never observation/config/response
    fields. The existing process helper owns bounded stdout and its subprocess;
    the enclosing installed collector still owns the whole process deadline.
    """
    def __init__(self, commands, *, ops_sha256):
        if not isinstance(commands, dict) or set(commands) != set(OWNERS):
            raise ValueError('two fixed owning commands required')
        self.commands = {}
        for owner, command in commands.items():
            if (not isinstance(command, (list, tuple)) or not 3 <= len(command) <= 40
                    or any(not isinstance(v, str) or not v or '\0' in v for v in command)
                    or tuple(command[-2:]) != ('wallet-inventory', owner)):
                raise ValueError('literal fixed ops owning-wallet read required')
            self.commands[owner] = tuple(command)
        self.ops_sha256 = _sha(ops_sha256)

    def hashes(self):
        return {owner: digest(canonical(list(command)).encode()) for owner, command in self.commands.items()}

    async def read(self, owner, *, remaining):
        if owner not in OWNERS or not 0 < remaining <= 90:
            raise ValueError('bounded owning read required')
        value = await text_command(list(self.commands[owner]), timeout=min(12, remaining))
        return value.encode('utf8')


def _admission(store, sequence, reader, pins, runtime):
    event, admitted = _source_event(store, sequence)
    expected = {'financial_pins': pins, 'architecture_profile': DIRECT_PER_KEY,
        'producer_sha256': digest(Path(__file__).read_bytes()),
        'validator_sha256': digest(VALIDATOR.read_bytes()), 'ops_sha256': reader.ops_sha256,
        'commands_sha256': reader.hashes(), 'startup_source_sha256': runtime['startup_source_sha256']}
    if event['kind'] != 'c_native_owning_wallet_source_qualified' or admitted != expected:
        raise ValueError('independent installed owning source/command qualification required')
    return admitted


def _validator(expected_sha):
    raw = VALIDATOR.read_bytes()
    if digest(raw) != expected_sha:
        raise ValueError('existing public wallet validator differs')
    spec = importlib.util.spec_from_file_location('_c_admitted_public_wallet_validator', VALIDATOR)
    module = importlib.util.module_from_spec(spec)
    # Execute precisely the authenticated bytes, not a second file read.
    exec(compile(raw, str(VALIDATOR), 'exec'), module.__dict__)
    return module


def _tip(chain, observation):
    point = chain.identity()
    if (chain.call('getblockhash', 0) != SIGNET_GENESIS or point.get('chain') != 'signet'
            or point.get('initialblockdownload') is not False
            or (point.get('blocks'), point.get('bestblockhash')) != (observation['height'], observation['tip_hash'])):
        raise ValueError('owning source independent synchronized tip differs')
    return observation['height'], observation['tip_hash']


def _member(store, boundary, owner):
    from .treasury import _members
    members = _members(boundary)
    member = members.get(owner)
    if member is None or member['kind'] != 'wallet' or member['role'] != 'operator' or len(member['descriptors']) != 1:
        raise ValueError('exact declared operator owning wallet required')
    event, original = _source_event(store, member['verification_sequence'])
    if (event['kind'] != 'treasury_member_verified' or original.get('financial_pins') != boundary['pins']
            or original.get('genesis') != SIGNET_GENESIS
            or original.get('member') != {k:v for k,v in member.items() if k != 'verification_sequence'}):
        raise ValueError('original independent owning member proof differs')
    return member


def replay_original(store, reference, *, owner, phase, observation):
    from .trace import partition_paths, readonly, record_hash, SCHEMA_VERSION
    if not isinstance(reference, dict) or set(reference) != {'partition', 'seq', 'hash'}:
        raise ValueError('original owning TraceStore reference required')
    matches = [p for p in partition_paths(store.trace.root) if p.name == reference['partition']]
    if len(matches) != 1:
        raise ValueError('original owning trace missing')
    connection = readonly(matches[0])
    try:
        size = connection.execute('SELECT length(raw) FROM trace WHERE seq=?', (reference['seq'],)).fetchone()
        if size is None or type(size[0]) is not int or not 0 < size[0] <= 2*1024*1024:
            raise ValueError('bounded original owning bytes missing')
        row = connection.execute('SELECT * FROM trace WHERE seq=?', (reference['seq'],)).fetchone()
    finally:
        connection.close()
    if (row['schema_version'] != SCHEMA_VERSION or row['hash'] != reference['hash']
            or record_hash(row) != reference['hash'] or row['kind'] != RAW_KIND
            or json.loads(row['payload']) != {'owner':owner, 'phase':phase, 'source_observation':observation}
            or not isinstance(row['raw'], bytes)):
        raise ValueError('original owning trace scope/hash differs')
    return decode_object(row['raw'].decode()), row['raw']


async def collect(store, config, chain, observation, *, boundary, reader,
                  qualification_sequence, runtime_source_sequence, current_startup_path):
    """Return exact auxiliary inventory events; never a normal readiness ID.

    Root must qualify the installed fixed ops/source before its admission event.
    This function preserves real original bytes and checks independent Core and
    existing source reducers; an admission event is not itself wallet proof.
    Pending/reserved/unknown-parent cases are retained and held in this slice.
    """
    if (profile(store) != DIRECT_PER_KEY or not isinstance(reader, FixedOwningReader)
            or getattr(store, 'trace', None) is None or not isinstance(observation, dict)
            or set(observation) != {'id','started_at','architecture_profile','financial_pins','boundary_id','height','tip_hash'}
            or observation.get('architecture_profile') != DIRECT_PER_KEY
            or re.fullmatch('[0-9a-f]{32}', observation.get('id', '')) is None
            or type(observation.get('started_at')) not in (int, float)
            or not 0 <= time.time()-observation['started_at'] <= 90
            or type(observation.get('height')) is not int or observation['height'] < 0
            or re.fullmatch('[0-9a-f]{64}', observation.get('tip_hash', '')) is None
            or observation['financial_pins'] != _pins(boundary['pins']) or observation['boundary_id'] != boundary['id']):
        raise ValueError('fresh traced C owning source observation required')
    if store.db.execute("SELECT 1 FROM event WHERE kind=? AND json_extract(payload,'$.source_observation.id')=?", (KIND, observation['id'])).fetchone():
        raise ValueError('owning observation already collected; never refresh old source')
    original = canonical(observation)
    def remaining():
        value = 90-(time.time()-observation['started_at'])
        if not value > 0:
            raise ValueError('whole owning source observation deadline exceeded')
        return value
    from .runtime_startup import _read
    from .target_epochs import verified_runtime_source
    current, current_sha = _read(current_startup_path)
    verified_runtime_source(store, runtime_source_sequence, origin_pins=boundary['pins'], current_source_sha256=current_sha)
    runtime_event, runtime = _source_event(store, runtime_source_sequence)
    if (runtime_event['kind'] != 'owned_runtime_configuration_verified'
            or not observation['started_at'] <= runtime['observed_at'] <= time.time()
            or runtime.get('product_commit') != boundary['pins']['product_commit']
            or runtime.get('schema_sha256') != boundary['pins']['schema_sha256']
            or set(runtime.get('daemons', {})) != {'captaind','watchmand'}):
        raise ValueError('new actual owning runtime source required')
    admitted = _admission(store, qualification_sequence, reader, boundary['pins'], runtime)
    validator = _validator(admitted['validator_sha256'])
    def decode_public_body(*args):
        if len(args) != 3 or args[:2] != ('cli','decoderawtransaction'):
            raise ValueError('existing public validator permits only stripped-body decoding')
        from .trace import normalized
        return canonical(normalized(chain.call('decoderawtransaction', args[2])))
    validator.ops = decode_public_body
    members = [_member(store, boundary, owner) for owner in OWNERS]
    tip = _tip(chain, observation)
    captured = {}; references = {}; capture_times = {}; original_hashes = {}
    for phase in ('before', 'after'):
        for owner in OWNERS:
            started = time.time()
            raw = await reader.read(owner, remaining=remaining())
            completed = time.time(); remaining()
            if not isinstance(raw, bytes) or not 0 < len(raw) <= 2*1024*1024:
                raise ValueError('bounded literal owning response required')
            response = decode_object(raw.decode())
            validator.validate_wallet_frame(response, owner, 'signet')
            public_payload(response)
            reference = store.trace_capture(RAW_KIND, {'owner':owner,'phase':phase,'source_observation':observation}, raw=raw)
            check, stored_raw = replay_original(store, reference, owner=owner, phase=phase, observation=observation)
            if check != response or stored_raw != raw:
                raise ValueError('actual owning original capture differs')
            native = response[owner]
            member = next(v for v in members if v['id'] == owner)
            if (native['complete'] is not True or (native['tip_height'], native['tip_hash']) != tip
                    or member['descriptors'] != [native['public_descriptor']]
                    or any(native[k] for k in ('pending_transactions','pending_parents','unavailable_parent_txids','reserved_outpoints'))
                    or type(native['last_revealed_index']) is not int or not 0 <= native['last_revealed_index'] < 1980):
                raise ValueError('complete stable unreserved owning wallet scope required')
            captured[(phase,owner)] = response; references[phase+':'+owner] = reference
            original_hashes[phase+':'+owner] = digest(raw)
            capture_times[(phase,owner)] = (started, completed)
        if phase == 'before':
            specs = {captured[('before',owner)][owner]['public_descriptor']:[0,captured[('before',owner)][owner]['last_revealed_index']+20] for owner in OWNERS}
            if len(specs) != 2:
                raise ValueError('distinct independent owning descriptors required')
            from .confirmed_scan import confirmed_scan
            scripts, ranges, scanned, scan_provenance = confirmed_scan(store, config, chain, current,
                pins=boundary['pins'], boundary_id=boundary['id'], members=members, specs=specs, tip=tip)
            remaining()
            from .owned_mempool import collect as collect_activity, collector_context
            activity_context = collector_context('c_native_owning_wallet', {**observation,'descriptor_ranges':ranges})
            activity = collect_activity(store, chain, set(scripts), time.monotonic(), context=activity_context)
            remaining()
        _tip(chain, observation)
    for owner in OWNERS:
        if captured[('before',owner)] != captured[('after',owner)]:
            raise ValueError('actual owning wallet changed during independent observation')
    # Reuse the actual shared supplied-wallet reducer before admitting any asset
    # projection. Its coverage limitations remain explicit in the auxiliary.
    from .wallet_projection import reduce_wallet_projection
    projections = {}; inventories = {}; source_sequences = {}; reports = {}
    for owner in OWNERS:
        response = captured[('before',owner)]; native = response[owner]
        begin, end = capture_times[('before',owner)]
        facts = {'schema_version':1,'kind':'financial_facts','architecture_profile':DIRECT_PER_KEY,
            'network':'signet','genesis':SIGNET_GENESIS,'height':tip[0],'tip_hash':tip[1],
            'observed_at':begin,'completed_at':end,'financial_pins':boundary['pins'],
            'source_identity':{'product_commit':runtime['product_commit'],'schema_sha256':runtime['schema_sha256'],
                'bridge_sha256':admitted['ops_sha256'],
                'daemon_binary_hashes':{k:v['binary_sha256'] for k,v in runtime['daemons'].items()}},
            'sources':{owner+'_wallet':{'owner':owner,'observed_at':begin,'completed_at':end,'source':response}},
            'source_gaps':[]}
        member = next(v for v in members if v['id'] == owner)
        projection = reduce_wallet_projection(member, facts, chain, boundary['pins'], owner=owner)
        if not projection['projection_complete']:
            raise ValueError('owning wallet/Core projection retains gaps')
        expected = {row['outpoint']:row for row in projection['confirmed_tip_utxos']}
        actual = {row['txid']+':'+str(row['vout']):row for row in scanned['unspents'] if scripts[row['scriptPubKey']]['member_id'] == owner}
        if set(expected) != set(actual) or len(expected) != len(native['utxos']):
            raise ValueError('native owning inputs differ from exhaustive confirmed descriptor set')
        for point, row in expected.items():
            if (row['amount_sat'] != btc_to_sat(actual[point]['amount']) or row['script'] != actual[point]['scriptPubKey']
                    or row['child_index'] != scripts[row['script']]['child_index']):
                raise ValueError('actual owning descriptor amount/child differs')
        projections[owner] = projection
        inventories[owner] = [{k:row[k] for k in ('outpoint','amount_sat','script','descriptor_index','child_index')} for row in expected.values()]
        reports[owner] = native
    remaining(); _tip(chain, observation)
    if _read(current_startup_path)[1] != current_sha:
        raise ValueError('actual runtime source changed during owning observation')
    verified_runtime_source(store, runtime_source_sequence, origin_pins=boundary['pins'], current_source_sha256=current_sha)
    if canonical(observation) != original:
        raise ValueError('owning producer changed original source observation')
    # Component inventory events use the exact existing shared normal ABI.
    with store.transaction():
        for owner in OWNERS:
            member = next(v for v in members if v['id'] == owner)
            context = {'member_id':owner,'identity':member['identity'],'financial_pins':boundary['pins'],
                'height':tip[0],'tip_hash':tip[1],'observed_at':time.time()}
            body = {**context,'reported_utxos':inventories[owner],'reported_channels':[],
                'wallet_inventory':reports[owner], 'pending_transactions':[], 'reserved_outpoints':[],
                'discovery_gaps':[], 'source_kind':'actual_native_owning_wallet',
                'original_source_sha256':original_hashes['before:'+owner],
                'original_trace':references['before:'+owner], 'owning_projection':projections[owner]}
            public_payload(body); store._event('treasury_native_inventory_source', body)
            source_sequences[owner] = store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
            store._event('treasury_inventory', {**context,'utxos':inventories[owner],'complete':True,
                'scope':'independently scanned two owning wallets only; not complete treasury or readiness'})
            inventories[owner] = store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
        from .treasury import _capture_assets
        subset = {**boundary,'members':members}
        assets = _capture_assets(store, subset, inventories, chain)
        from .fresh_cash_readiness import _operator_fee_funding
        source = {'height':tip[0],'tip_hash':tip[1],'members':members,'inventory_sequences':inventories,'descriptor_ranges':ranges}
        current_owners = {'rounds_inventory':captured[('after','rounds')],'watchman_inventory':captured[('after','watchman')]}
        available = _operator_fee_funding(store, source, assets, current_owners)
        remaining(); _tip(chain, observation)
        result = {'source_observation':copy.deepcopy(observation),'financial_pins':boundary['pins'],
            'boundary_id':boundary['id'],'height':tip[0],'tip_hash':tip[1],'observed_at':time.time(),
            'runtime_source_sequence':runtime_source_sequence,'qualification_sequence':qualification_sequence,
            'inventory_sequences':inventories,'inventory_source_sequences':source_sequences,
            'original_traces':references,'original_source_hashes':original_hashes,
            'confirmed_scan':scan_provenance,'mempool_activity':activity,
            'actual_owning_wallet_assets':assets,'watchman_native_fee_eligible_msat':available,
            'complete':False,'financial_readiness':False,'qualified':False,
            'scope':'two native owning wallets only; no aggregate liabilities, CLN, pool/router budget or normal readiness'}
        public_payload(result); store._event(KIND, result)
        result['source_sequence'] = store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
    return result

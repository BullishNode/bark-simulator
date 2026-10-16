"""Private A source collector for an ordinary/recovered normal treasury.

The installed capture function and native tools require an independently reviewed
source admission. No observer reply selects code or grants completeness. Original
Fulls, witnesses and retained fee files remain private; only hashes and checked
money projections enter the Store. Unsupported native domains hold dispatch.
"""
import hashlib
import inspect
import json
import os
import subprocess
import time
import uuid
from decimal import Decimal
from pathlib import Path

from .architecture import profile
from .bundle_audit import decode_transaction
from .final_campaign import _source_event
from .financial_transition import _current_claims, _superseded_ark_input, history, recorded
from .model import SIGNET_GENESIS, btc_to_sat, canonical, integer, public_payload, timestamp
from .normal_native_fee import verify_native_fee_epoch
from .normal_recovered_backing import bind_native_claim, verify_recovered_backing
from .operating_limits import PATHS, fee_totals
from .target_epochs import active_identity
from .treasury import _capture_assets, _members, reconcile_edge

TABLES = frozenset(('vtxo', 'virtual_transaction', 'pending_board', 'fallback_record',
    'key_link', 'round', 'round_participation', 'round_part_input', 'round_part_output',
    'htlc_vtxo', 'htlc_settlement', 'lightning_invoice', 'lightning_htlc_subscription',
    'lightning_payment_attempt', 'lightning_payment_attempt_htlc_vtxo', 'offboards',
    'vtxo_pool', 'expiry_settlement', 'expiry_cancelled_participation', 'recovery_reserve',
    'recovery_source_hold', 'recovery_capital_release', 'recovery_receipt', 'nursery_tx',
    'sweep', 'lightning_node', 'ephemeral_tweak', 'wallet_changeset',
    'fee_allowance_policy', 'fee_allowance_candidate'))
SUPPORTED = frozenset(('vtxo', 'virtual_transaction', 'pending_board', 'fallback_record',
    'key_link', 'recovery_reserve', 'recovery_source_hold', 'recovery_receipt',
    'wallet_changeset', 'fee_allowance_policy', 'fee_allowance_candidate'))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw, *, decimals=False):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value: raise ValueError('duplicate private source field')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique, parse_float=Decimal if decimals else float)


def native_tables(raw, expected_sha256):
    """Exact bounded RR table cut; a missing table never means zero liabilities."""
    if not isinstance(raw, bytes) or len(raw) > 16*1024*1024 or digest(raw) != expected_sha256:
        raise ValueError('original private SQL hash or aggregate byte bound differs')
    lines = raw.decode().splitlines()
    if (lines[:2] != ['BEGIN', 'SET'] or lines[-1:] != ['COMMIT']
            or not (len(lines) == 4 or len(lines) == 5 and lines[2] == 'DO')):
        raise ValueError('original read-only transaction framing differs')
    frame = strict_json(lines[-2])
    if (frame['read_only'] != 'on' or frame['isolation'] != 'repeatable read'
            or set(frame['tables']) != TABLES):
        raise ValueError('all named native financial domains required in one RR cut')
    tables = {}
    for name, table in frame['tables'].items():
        rows = table['rows']
        if (not isinstance(rows, list) or integer(table['count'], 'native row count') != len(rows)
                or len(rows) >= 10000 or len(canonical(rows).encode()) > 8*1024*1024
                or any(not isinstance(row, dict) or len(canonical(row).encode()) > 2*1024*1024 for row in rows)):
            raise ValueError('native table coverage or bounded original rows differ')
        tables[name] = rows
    if any(tables[name] for name in TABLES-SUPPORTED):
        raise ValueError('native conditional/round/pool/pending domain needs its own resolver')
    return tables


def native_wallet(raw, wallet):
    """Select the owning frame from exact unmodified native CLI stdout bytes."""
    if wallet not in {'rounds','watchman'}: raise ValueError('named owning native wallet required')
    value = strict_json(raw)
    selected = value.get(wallet) if isinstance(value,dict) else None
    if not isinstance(selected,dict) or selected.get('wallet') != wallet:
        raise ValueError('actual native CLI owning wallet frame unavailable')
    return selected


def run_proof(tool, request):
    """Execute the admitted pure verifier and retain its exact private originals."""
    command = tool['command']; binary = Path(command[0]); parent = Path(tool['evidence_directory'])
    if (not binary.is_absolute() or binary.is_symlink() or not binary.is_file()
            or digest(binary.read_bytes()) != tool['sha256']):
        raise ValueError('qualified proof executable identity differs')
    if (not parent.is_absolute() or parent.is_symlink() or not parent.is_dir()
            or parent.stat().st_mode & 0o077):
        raise ValueError('private original proof directory required')
    directory = parent/uuid.uuid4().hex; directory.mkdir(mode=0o700)
    def save(name, raw):
        with os.fdopen(os.open(directory/name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600), 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    encoded = canonical(request).encode()
    if len(encoded) > 2*1024*1024: raise ValueError('private proof input exceeds bound')
    save('request.json', encoded)
    try:
        reply = subprocess.run(command, input=encoded, capture_output=True, timeout=12)
    except subprocess.TimeoutExpired as error:
        save('stdout', error.stdout or b''); save('stderr', error.stderr or b'')
        save('terminal.json', canonical({'timed_out':True, 'tool_sha256':tool['sha256']}).encode())
        raise ValueError('native private proof timed out') from error
    save('stdout', reply.stdout); save('stderr', reply.stderr)
    save('terminal.json', canonical({'timed_out':False, 'exit':reply.returncode, 'tool_sha256':tool['sha256']}).encode())
    if (reply.returncode or len(reply.stdout) > 2*1024*1024 or len(reply.stderr) > 65536
            or digest(binary.read_bytes()) != tool['sha256']):
        raise ValueError('native proof refused, changed or exceeded bounds')
    strict_json(reply.stdout)
    return encoded, reply.stdout


def authenticate_claims(store, tables, tools, server_pubkey):
    """Neither SQL spendable nor a provided signature verdict authenticates a Full."""
    claims = _current_claims(store)
    rows = {row['vtxo_id']:row for row in tables['vtxo']}
    if len(rows) != len(tables['vtxo']): raise ValueError('duplicate native VTXO source')
    virtuals = {row['txid']:row for row in tables['virtual_transaction']}
    if len(virtuals) != len(tables['virtual_transaction']): raise ValueError('duplicate native transaction')
    expected = {claim['coin_id'] for claim in claims}
    for identifier, row in rows.items():
        if row['policy_type'] != 'pubkey' or identifier in expected: continue
        old = store.db.execute('SELECT c.*,k.actor FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey WHERE c.id=?', (identifier,)).fetchone()
        if old is None or not _superseded_ark_input(store, old):
            raise ValueError('unattributed native ordinary right cannot be omitted')
    authenticated = []
    for claim in claims:
        row = rows.get(claim['coin_id'])
        if row is None: raise ValueError('retained customer right absent from native source')
        proof = json.loads(store.db.execute('SELECT proof FROM owned_coin WHERE id=?', (claim['coin_id'],)).fetchone()[0])
        if proof['server_pubkey'] != server_pubkey: raise ValueError('retained claim server differs')
        links = [v for v in tables['key_link'] if v['user_pubkey'] == proof['user_pubkey']]
        records = [] if len(links) != 1 else [v for v in tables['fallback_record'] if v['mailbox_pk'] == links[0]['mailbox_pk']]
        if len(links) != 1 or len(records) != 1: raise ValueError('unique native record and key-link required')
        link, record = links[0], records[0]; anchor = virtuals.get(row['anchor_point'].split(':')[0])
        if anchor is None or anchor['is_funding'] is not True:
            raise ValueError('original signed native anchor required')
        contract_request, contract_reply = run_proof(tools['policy'], {
            'signed_vtxo':row['signed_vtxo_hex'], 'anchor_raw':anchor['signed_transaction_hex'], 'server_pubkey':server_pubkey})
        binding_request, binding_reply = run_proof(tools['binding'], {
            'user_pubkey':proof['user_pubkey'], 'binding':{'mailbox_pk':record['mailbox_pk'],
                'spk':record['spk'], 'seq':record['seq'], 'record_attestation':record['sig']},
            'key_link_attestation':link['sig']})
        expected_claim = {**claim, 'chain_anchor':proof['chain_anchor'], 'user_pubkey':proof['user_pubkey'],
            'expiry_height':proof['expiry_height'], 'exit_delta':12, 'server_pubkey':server_pubkey, 'binding':proof['binding']}
        authenticated.append(bind_native_claim(expected_claim, row, contract_request, contract_reply,
            binding_request, binding_reply, genesis=SIGNET_GENESIS, server_pubkey=server_pubkey))
    return claims, authenticated


def source_members(store, boundary, inventory_sequences, source, *, now):
    members = _members(boundary)
    if (set(source['inventory_source_sequences']) != set(members)
            or set(inventory_sequences) != set(members) or set(source['member_source_hashes']) != set(members)):
        raise ValueError('every declared member needs original native discovery and inventory')
    for name, member in members.items():
        original_event, original = _source_event(store, source['inventory_source_sequences'][name])
        inventory_event, inventory = _source_event(store, inventory_sequences[name])
        member_event, identity = _source_event(store, member['verification_sequence'])
        if (member_event['kind'] != 'treasury_member_verified'
                or identity.get('member') != {k:v for k,v in member.items() if k != 'verification_sequence'}
                or identity.get('genesis') != SIGNET_GENESIS or identity.get('financial_pins') != boundary['pins']
                or original_event['kind'] != 'treasury_native_inventory_source' or inventory_event['kind'] != 'treasury_inventory'
                or original['member_id'] != name or original['identity'] != member['identity']
                or original['financial_pins'] != boundary['pins']
                or (original['height'], original['tip_hash']) != (source['height'], source['tip_hash'])
                or not 0 <= now-timestamp(original['observed_at'], 'member observed at') <= 90
                or original['reported_utxos'] != inventory['utxos']
                or original['reported_channels'] != inventory.get('channels', [])
                or any(not isinstance(original[k], list) for k in ('pending_transactions', 'reserved_outpoints', 'discovery_gaps'))
                or original['pending_transactions'] or original['discovery_gaps']
                or digest(canonical(original).encode()) != source['member_source_hashes'][name]):
            raise ValueError('exhaustive original member source identity/coverage unresolved')
    return members


def verify_cln_members(store, members, source, inventories, chain):
    """Compare both raw CLN endpoints and every cash/channel projection."""
    from .financial_components import inspect as inspect_components
    nodes = []
    for name, member in members.items():
        if member['kind'] != 'lightning_peer': continue
        _, native = _source_event(store, source['inventory_source_sequences'][name])
        _, inventory = _source_event(store, inventories[name])
        funds, peers = native['listfunds'], native['listpeerchannels']['channels']
        expected_cash = []
        for row in funds['outputs']:
            if row['status'] == 'spent': continue
            if row['status'] != 'confirmed' or integer(row['amount_msat'], 'owned CLN cash') % 1000:
                raise ValueError('pending CLN cash needs its own projection')
            expected_cash.append((row['txid']+':'+str(row['output']), row['amount_msat']//1000, row['scriptpubkey']))
        if sorted(expected_cash) != sorted((v['outpoint'], v['amount_sat'], v['script']) for v in inventory['utxos']):
            raise ValueError('CLN cash source/projection membership differs')
        expected_channels = [(v['funding_txid']+':'+str(v['funding_outnum']), v['channel_id'],
            v['peer_id'], v['to_us_msat']) for v in peers]
        if sorted(expected_channels) != sorted((v['funding_outpoint'], v['channel_id'],
                v['peer_identity'], v['owned_balance_msat']) for v in inventory['channels']):
            raise ValueError('full CLN owned channel source/projection differs')
        nodes.append({'id':name, 'source_sha256':source['member_source_hashes'][name],
            'getinfo':native['getinfo'], 'listfunds':funds, 'listpeerchannels':native['listpeerchannels']})
    if nodes:
        inspect_components([], nodes, [], chain, height=source['height'], tip_hash=source['tip_hash'],
            gaps=['Transport discovery and complete boundary checked by installed collector'])


def verify_fresh_backing(authenticated, tables, chain, *, height, server_pubkey):
    """Current native ordinary leaves backed by exact confirmed unspent roots.

    Native Full/path+per-key signatures were executed above. No expiry-based
    liability removal or reuse of an already-spent root is admitted here.
    """
    rows = {v['vtxo_id']:v for v in tables['vtxo']}; groups = {}
    for claim in authenticated:
        leaf = rows[claim['coin_id']]; point = claim['chain_anchor']; root = rows.get(point)
        if (root is None or root['policy_type'] != 'expiry' or root['anchor_point'] != point
                or root['server_pubkey'] != server_pubkey
                or any(leaf.get(k) is not None or root.get(k) is not None
                    for k in ('onchain_spent_txid','oor_spent_txid','spent_in_round','offboarded_in'))):
            raise ValueError('fresh ordinary claim has unresolved leaf/root disposition')
        txid, index = point.rsplit(':', 1); coin = chain.call('gettxout', txid, int(index), False)
        tx = chain.tx(txid); decoded = decode_transaction(tx['hex'])
        if (coin is None or coin.get('confirmations', 0) < 3 or tx.get('confirmations', 0) < 3
                or tx.get('blockhash') != chain.call('getblockhash', height-tx['confirmations']+1)
                or digest(bytes.fromhex(tx['hex'])) != claim['anchor_raw_sha256']
                or int(index) >= len(decoded['outputs'])
                or btc_to_sat(coin['value']) != root['amount']
                or decoded['outputs'][int(index)]['amount_sat'] != root['amount']
                or decoded['outputs'][int(index)]['script'] != coin['scriptPubKey']['hex']):
            raise ValueError('fresh signed native root differs from confirmed independent backing')
        group = groups.setdefault(point, {'root_sat':root['amount'], 'claim_sat':0})
        group['claim_sat'] += claim['amount_sat']
        if group['claim_sat'] > group['root_sat']: raise ValueError('customer claims exceed unique fresh backing')
    return groups


def verified_money(store, chain, source, *, opening=None):
    """All recorded flows/costs, checked once each; no historical fee re-debit."""
    sequences = {}
    for kind, field in [('treasury_flow_verified', 'flow_sequences'), ('financial_cost_verified', 'cost_sequences')]:
        expected = [row[0] for row in store.db.execute('SELECT sequence FROM event WHERE kind=? ORDER BY sequence', (kind,))]
        if source[field] != expected: raise ValueError('exhaustive original monetary event coverage differs')
        sequences[field] = expected
    old = set()
    if opening:
        _, original = _source_event(store, opening['declaration']['readiness_sequence'])
        for field, key in [('flow_sequences', 'historical_flow_sequences'), ('cost_sequences', 'historical_cost_sequences')]:
            old.update(original['preserved_history_opening'][key])
    flows = []; costs = {}; monetary = set()
    for sequence in sorted(sequences['flow_sequences']+sequences['cost_sequences']):
        event, value = _source_event(store, sequence); identifier = value['monetary_id']
        if identifier in monetary: raise ValueError('same original monetary item counted twice')
        monetary.add(identifier); integer(value['amount_msat'], 'original monetary amount', 1)
        if event['kind'] == 'financial_cost_verified':
            if value['kind'] != 'miner_cost' or identifier != 'miner:'+value['txid']:
                raise ValueError('unsupported external router cost needs its original decoder')
            actual = chain.transaction(value['txid'])
            if (actual['txid'] != value['txid'] or actual.get('confirmations', 0) < 1
                    or integer(actual['fee_sat'], 'actual miner fee')*1000 != value['amount_msat']):
                raise ValueError('original external miner cost differs from independent Core')
            costs[value['txid']] = value
        elif value['kind'] == 'injection':
            txid, index = value['outpoint'].rsplit(':', 1); actual = chain.tx(txid)
            rows = [v for v in actual['vout'] if v['n'] == int(index)]
            if (actual.get('confirmations', 0) < 1 or len(rows) != 1
                    or btc_to_sat(rows[0]['value'])*1000 != value['amount_msat']
                    or rows[0]['scriptPubKey']['hex'] != value['script']
                    or identifier != 'injection:'+value['outpoint']
                    or value['original_declaration_sha256'] not in source['injection_declaration_hashes']):
                raise ValueError('original injection declaration/raw output differs')
        elif value['kind'] != 'internal_transfer':
            raise ValueError('external receipt/payment requires its authenticated source resolver')
        if sequence not in old: flows.append({'id':identifier, **value})
    return flows, costs


def transaction_or_absent(store, chain, txid):
    """Only a fresh matched Core -5 permits an unbroadcast reservation state."""
    from .chain import CoreRpcError
    from .trace import partition_paths, readonly, record_hash, SCHEMA_VERSION
    started = time.time(); previous = getattr(chain,'last_capture',None)
    try:
        return chain.tx(txid)
    except CoreRpcError as error:
        reference = error.capture
        if (error.method != 'getrawtransaction' or error.params != (txid,True) or error.code != -5
                or reference is None or reference == previous or reference != getattr(chain,'last_capture',None)
                or getattr(store,'trace',None) is None or not isinstance(reference,dict)
                or set(reference) != {'partition','seq','hash'}):
            raise ValueError('native candidate absence lacks matching independent Core -5') from error
        paths = [path for path in partition_paths(store.trace.root) if path.name == reference['partition']]
        if len(paths) != 1: raise ValueError('original candidate absence trace missing') from error
        connection = readonly(paths[0])
        try:
            size = connection.execute('SELECT length(payload) FROM trace WHERE seq=?',(reference['seq'],)).fetchone()
            if size is None or not 0 < size[0] <= 4096: raise ValueError('bounded candidate absence trace required')
            row = connection.execute('SELECT * FROM trace WHERE seq=?',(reference['seq'],)).fetchone()
        finally:
            connection.close()
        payload = strict_json(row['payload'])
        if (row['schema_version'] != SCHEMA_VERSION or row['kind'] != 'chain.rpc' or row['raw'] is not None
                or record_hash(row) != reference['hash'] or row['hash'] != reference['hash']
                or not started <= row['utc'] <= time.time()
                or payload.get('method') != 'getrawtransaction' or payload.get('params') != [txid,True]
                or payload.get('error') != {'code':-5}):
            raise ValueError('original matching candidate absence trace differs') from error
        return None


def native_fee_exposure(tables, checked_fee, chain, costs, *, store=None):
    """Signed reservations may not be relabeled paid or charged as two expenses."""
    confirmed = {'ordinary':0, 'urgent':0}; actual_ids = set(); physical = set()
    for row in tables['fee_allowance_candidate']:
        candidate = strict_json(bytes.fromhex(row['candidate_bytes_hex']))
        tx = decode_transaction(bytes(candidate['raw']).hex()); physical.add(tx['txid'])
        actual = transaction_or_absent(store, chain, tx['txid'])
        if actual is None or actual.get('confirmations', 0) < 1: continue
        cost = costs.get(tx['txid'])
        if (cost is None or cost['amount_msat'] != row['fee_sat']*1000
                or cost['budget'] != ('urgent' if row['urgent'] else 'ordinary')):
            raise ValueError('confirmed native carrier lacks its exact once-only miner cost')
        # Distinct wtxids may represent the same chain transaction. Core names
        # the actual witness; only it is paid, while all reservations stay booked.
        if actual.get('hex') != bytes(candidate['raw']).hex(): continue
        if tx['txid'] in actual_ids: raise ValueError('same confirmed native carrier charged twice')
        actual_ids.add(tx['txid']); confirmed['urgent' if row['urgent'] else 'ordinary'] += row['fee_sat']
    result = {}
    for category in ('ordinary', 'urgent'):
        booked = checked_fee[category+'_booked_sat']
        if confirmed[category] > booked: raise ValueError('confirmed fee exceeds native booked source')
        result[category] = (booked-confirmed[category])*1000
    return result, physical


def fee_cash(store, boundary, envelope, assets, source, inventories, tables, fee, recovered, opening, chain):
    """Real owning unreserved UTXOs minus R+F once; never use reserved set as cash."""
    original_assets = assets if opening is None else opening['opening_assets']
    members = _members(boundary); eligible_members = set()
    for identifier in envelope['fee_assets']:
        asset = original_assets['assets'].get(identifier)
        if (asset is None or asset['role'] != 'operator' or asset['backing_outpoint'] != identifier
                or members[asset['member']]['kind'] != 'wallet'):
            raise ValueError('declared original fee funding is not operator owning cash')
        eligible_members.add(asset['member'])
    rounds = source['rounds_member_id']; watch = source['watchman_member_id']
    if rounds == watch or {rounds, watch}-eligible_members:
        raise ValueError('distinct owning rounds/watch fee members must be declared')
    reserved = set(fee['reserved_urgent_prevouts']); amounts = {name:0 for name in eligible_members}
    for row in tables['fee_allowance_candidate']:
        candidate = strict_json(bytes.fromhex(row['candidate_bytes_hex']))
        reserved.update(v['outpoint'] for v in decode_transaction(bytes(candidate['raw']).hex())['inputs'])
    owning = {}
    for name in eligible_members:
        _, original = _source_event(store, source['inventory_source_sequences'][name])
        native_reserved = original['reserved_outpoints']
        if not isinstance(native_reserved, list) or len(set(native_reserved)) != len(native_reserved):
            raise ValueError('exact native reserved input source required')
        reserved.update(native_reserved)
        wallet = original['wallet_inventory']
        if (wallet['network'] != 'signet' or (wallet['tip_height'],wallet['tip_hash']) != (source['height'],source['tip_hash'])
                or wallet['pending_transactions'] or wallet['unavailable_parent_txids']
                or set(wallet['reserved_outpoints']) != set(native_reserved)):
            raise ValueError('actual native fee wallet tip/pending/reserved source differs')
        rows = wallet['utxos']
        if not isinstance(rows, list) or len(rows) > 20000:
            raise ValueError('bounded literal owning fee-wallet inventory required')
        by_point = {row['outpoint']:row for row in rows}
        _, inventory = _source_event(store, inventories[name])
        if (len(by_point) != len(rows) or set(by_point) != {row['outpoint'] for row in inventory['utxos']}
                or len(inventory['utxos']) != len(rows)):
            raise ValueError('literal owning fee inventory/projection membership differs')
        owning[name] = (wallet, by_point)
    for name in eligible_members:
        _, inventory = _source_event(store, inventories[name])
        wallet, by_point = owning[name]
        for row in inventory['utxos']:
            point = row['outpoint']; txid, index = point.rsplit(':', 1)
            native = by_point[point]
            if (native['value_sat'] != row['amount_sat'] or native['script_pubkey'] != row['script']):
                raise ValueError('native fee wallet amount/script differs from projection')
            if (native['confirmed_fee_eligible'] is not True or native['mature'] is not True
                    or native['trusted'] is not True or native['reserved'] is not False):
                continue
            current = chain.call('gettxout', txid, int(index), True)
            if point in reserved or current is None: continue
            if (current.get('bestblock') != source['tip_hash']
                    or current.get('confirmations', 0) < integer(wallet['min_trusted_confirmations'], 'native cash min confirmations', 1)
                    or native['confirmations'] < wallet['min_trusted_confirmations']
                    or current.get('coinbase') is True and current['confirmations'] < 100
                    or btc_to_sat(current['value']) != row['amount_sat']
                    or current['scriptPubKey']['hex'] != row['script']):
                raise ValueError('actual unreserved fee cash differs from owning inventory')
            amounts[name] += row['amount_sat']*1000
    held = sum(integer(row['held_sat'], 'native held source') for row in tables['recovery_source_hold'])
    if len(tables['recovery_reserve']) != 1: raise ValueError('one actual native R/F policy required')
    reserve = tables['recovery_reserve'][0]; floor = integer(reserve['fee_headroom_sat'], 'native F', 1)
    if amounts[rounds] < (held+floor)*1000: raise ValueError('unreserved rounds cash does not preserve native R+F')
    if recovered and (held != recovered['source_holds_sat'] or floor != recovered['fee_headroom_sat']):
        raise ValueError('recovered liability encumbrance differs from owning R/F')
    amounts[rounds] -= (held+floor)*1000
    if amounts[watch] < fee['urgent_required_confirmed_sat']*1000:
        raise ValueError('actual unreserved watch liquidity below native urgent floor')
    return sum(amounts.values())


def private_history_hash(history_source):
    """Bind retained byte files without exporting their signed transactions."""
    projection = {}
    for name, value in history_source.items():
        if name == 'candidates':
            if not isinstance(value, dict): raise ValueError('private history candidates required')
            projection[name] = {key:digest(raw) for key,raw in value.items()}
        elif isinstance(value, bytes): projection[name] = digest(value)
        elif name == 'root_identity' and isinstance(value, str): projection[name] = value
        else: raise ValueError('unexpected retained private history field')
    return digest(canonical(projection).encode())


def module_hash(function):
    path = Path(inspect.getsourcefile(function)).resolve()
    return digest(path.read_bytes())


class Collector:
    """Explicit installed A callback; no observer-selected executable or plugin.

    ``capture`` returns source_sequence plus private buffers raw_sql/raw_policy/
    raw_core/raw_rounds_inventory, fee_history and inventory_sequences. Its new
    normal_financial_source event binds each buffer hash and this observation.
    Source admission binds the actual capture module, this module, helper modules,
    current executables, exact policy/history/opening identity and proof tools.
    Nothing in a capture response can install or change this admission.
    """
    def __init__(self, capture, admission_sequence, tools):
        self.capture = capture
        self.admission_sequence = admission_sequence
        self.tools = tools

    def admission(self, store, pins):
        event, value = _source_event(store, self.admission_sequence)
        from .financial_components import inspect as inspect_components
        hashes = {'adapter':digest(Path(__file__).read_bytes()), 'capture':module_hash(self.capture),
            'financial_components':module_hash(inspect_components),
            'native_fee':module_hash(verify_native_fee_epoch), 'recovered_backing':module_hash(bind_native_claim)}
        if (event['kind'] != 'normal_financial_collector_qualified' or value['financial_pins'] != pins
                or value['component_sha256'] != hashes
                or value['proof_tool_sha256'] != {name:tool['sha256'] for name,tool in self.tools.items()}
                or value['proof_commands_sha256'] != {name:digest(canonical(tool['command']).encode()) for name,tool in self.tools.items()}
                or set(self.tools) != {'policy', 'binding'}):
            raise ValueError('installed source collector/tool qualification differs')
        return value

    async def __call__(self, store, config, chain, snapshot, observation):
        from .treasury import boundary
        from .operating_limits import envelope
        opening = recorded(store)
        if opening is None: raise ValueError('first preserved financial opening must be admitted separately')
        return await self.produce(store, config, chain, snapshot, observation,
            boundary(store), envelope(store, config), opening=opening)

    async def prepare_opening(self, store, config, chain, snapshot, observation, boundary, envelope, declaration):
        """Verify first-opening evidence; does not declare epochs/budgets or resume."""
        if recorded(store) is not None: raise ValueError('first preserved opening already exists')
        return await self.produce(store, config, chain, snapshot, observation,
            boundary, envelope, opening_declaration=declaration)

    async def produce(self, store, config, chain, snapshot, observation, boundary, envelope, *, opening=None, opening_declaration=None):
        store.verify_event_chain()
        if profile(store) != 'two_step_per_key': raise ValueError('A collector cannot qualify another architecture')
        if (observation['financial_pins'] != boundary['pins'] or envelope['pins'] != boundary['pins']
                or observation['boundary_id'] != boundary['id'] or snapshot['financial_pins'] != boundary['pins']):
            raise ValueError('collector boundary/pins differ from immutable observation')
        admitted = self.admission(store, boundary['pins'])
        preserved = history(store) if opening is None else None
        start = chain.identity()
        if (chain.call('getblockhash', 0) != SIGNET_GENESIS or start['chain'] != 'signet'
                or start['initialblockdownload'] is not False
                or (start['blocks'], start['bestblockhash']) != (observation['height'], observation['tip_hash'])):
            raise ValueError('current independent normal source identity differs')
        first = store.db.execute('SELECT COALESCE(max(sequence),0) FROM event').fetchone()[0]
        captured = await self.capture(store, config, chain, snapshot, json.loads(canonical(observation)))
        source_event, source = _source_event(store, captured['source_sequence'])
        now = time.time()
        if (source_event['sequence'] <= first or source_event['kind'] != 'normal_financial_source'
                or source['source_observation'] != observation or source['financial_pins'] != boundary['pins']
                or source['boundary_id'] != boundary['id'] or source['identity'] != active_identity(store)
                or source['binary_sha256'] != admitted['binary_sha256']
                or not observation['started_at'] <= timestamp(source['observed_at'], 'source time') <= now
                or now-observation['started_at'] > 90
                or (source['height'], source['tip_hash']) != (start['blocks'], start['bestblockhash'])
                or source['rounds_member_id'] != admitted['rounds_member_id']
                or source['watchman_member_id'] != admitted['watchman_member_id']
                or source['injection_declaration_hashes'] != admitted['injection_declaration_hashes']):
            raise ValueError('fresh admitted authenticated native source required')
        originals = {'native_sql':captured['raw_sql'], 'policy':captured['raw_policy'],
            'core':captured['raw_core'], 'rounds_inventory':captured['raw_rounds_inventory']}
        if any(not isinstance(raw,bytes) or len(raw) > maximum for (name,raw),maximum in zip(
                originals.items(), (16*1024*1024,65536,64*1024*1024,8*1024*1024))):
            raise ValueError('private captured source byte bound exceeded')
        if (source['original_sha256'] != {key:digest(raw) for key,raw in originals.items()}
                or source['fee_history_sha256'] != private_history_hash(captured['fee_history'])
                or source['original_sha256']['policy'] != admitted['policy_sha256']):
            raise ValueError('authenticated original source buffer differs')
        tables = native_tables(originals['native_sql'], source['original_sha256']['native_sql'])
        if len(tables['recovery_reserve']) != 1:
            raise ValueError('one actual native recovery reserve required')
        reserve = tables['recovery_reserve'][0]
        if (reserve['id'] != 'rounds' or reserve['unknown_gross'] is not False
                or reserve['sweep_spk'] != admitted['recovery_sweep_script']
                or reserve['fee_headroom_sat'] != admitted['recovery_fee_headroom_sat']
                or (reserve['checkpoint_height'],reserve['checkpoint_hash']) != (source['height'],source['tip_hash'])
                or reserve['held_sat'] != sum(integer(v['held_sat'],'held recovery source') for v in tables['recovery_source_hold'])):
            raise ValueError('actual native R/F/configuration/checkpoint unresolved')
        core = strict_json(originals['core'], decimals=True)
        rounds = native_wallet(originals['rounds_inventory'], 'rounds')
        members = source_members(store, boundary, captured['inventory_sequences'], source, now=now)
        verify_cln_members(store, members, source, captured['inventory_sequences'], chain)
        assets = _capture_assets(store, boundary, captured['inventory_sequences'], chain)
        if (assets['height'], assets['tip_hash']) != (source['height'], source['tip_hash']):
            raise ValueError('native and independent treasury asset tips differ')
        claims, authenticated = authenticate_claims(store, tables, self.tools, source['identity']['server_pubkey'])
        holds = {row['id'] for row in tables['recovery_source_hold']}
        recovered_claims = [claim for claim in authenticated if claim['chain_anchor'] in holds]
        fresh_claims = [claim for claim in authenticated if claim['chain_anchor'] not in holds]
        fresh_backing = verify_fresh_backing(fresh_claims, tables, chain,
            height=source['height'], server_pubkey=source['identity']['server_pubkey'])
        recovered = None
        if recovered_claims or tables['recovery_receipt'] or holds:
            recovered = verify_recovered_backing(recovered_claims, tables, core, rounds,
                identity={'genesis':SIGNET_GENESIS, 'server_pubkey':source['identity']['server_pubkey'],
                    'tip_height':source['height'], 'tip_hash':source['tip_hash'],
                    'fee_headroom_sat':admitted['recovery_fee_headroom_sat']},
                source_hashes={key:source['original_sha256'][key] for key in ('native_sql','core','rounds_inventory')})
        liabilities = []
        for claim in authenticated:
            borrowers = [name for name, member in members.items()
                if member['kind'] == 'ark_backing' and member['identity'] == claim['server_pubkey']]
            if len(borrowers) != 1: raise ValueError('customer right needs one declared operator borrower')
            liabilities.append({'id':'coin:'+claim['coin_id'], 'borrower':borrowers[0], 'amount_msat':claim['amount_sat']*1000})
        supplied = []
        for item in source['pending_liabilities']:
            event, original = _source_event(store, item['source_sequence'])
            projection = {key:item[key] for key in ('id','borrower','amount_msat')}
            if event['kind'] != 'treasury_liability_verified' or original != projection:
                raise ValueError('original customer liability source differs')
            supplied.append(projection)
        if sorted(supplied, key=lambda v:v['id']) != sorted(liabilities, key=lambda v:v['id']):
            raise ValueError('every authenticated retained right must remain a liability')
        fee = verify_native_fee_epoch(originals['policy'], admitted['policy_sha256'],
            tables['fee_allowance_policy'], tables['fee_allowance_candidate'], chain,
            expected_genesis=SIGNET_GENESIS, expected_server_pubkey=source['identity']['server_pubkey'],
            expected_history_identity=admitted['fee_history_identity'],
            expected_opening_digest=admitted['native_opening_digest'], expected_epoch_id=admitted['native_epoch_id'],
            history=captured['fee_history'])
        limits = {name:fee['ordinary_signed_ceiling_sat_kvb'] for name in PATHS-{'claim','progression'}}
        limits.update({name:min(fee['urgent_child_signed_ceiling_sat_kvb'], fee['urgent_package_signed_ceiling_sat_kvb']) for name in ('claim','progression')})
        if limits != envelope['fee_ceilings_sat_kvb']: raise ValueError('envelope differs from actual signed native path ceilings')
        flows, costs = verified_money(store, chain, source, opening=opening)
        pending_fees, native_txids = native_fee_exposure(tables, fee, chain, costs, store=store)
        funding = {row['txid'] for row in tables['virtual_transaction'] if row['is_funding'] is True}
        if (funding | {row['id'] for row in tables['recovery_receipt']})-set(costs):
            raise ValueError('native physical funding/recovery carrier missing actual monetary cost')
        if recovered and any(costs.get(row['txid'], {}).get('amount_msat') != row['mining_fee_sat']*1000 for row in recovered['receipts']):
            raise ValueError('original recovery Sweep fee must be counted exactly once')
        edge = reconcile_edge({'total_msat':0} if opening is None else opening['opening_assets'],
            assets, flows, source['pending_liabilities'], members)
        available = fee_cash(store, boundary, envelope, assets, source, captured['inventory_sequences'],
            tables, fee, recovered, opening, chain)
        used = fee_totals(store, boundary['pins']) if opening else {'ordinary':0,'urgent':0}
        for category in ('ordinary','urgent'):
            if used[category]+pending_fees[category] > envelope['fee_budgets_msat'][category]:
                raise ValueError('outer new-cost budget exhausted by actual costs/held reservations')
        if available < sum(max(0,envelope['fee_budgets_msat'][key]-used[key]) for key in used):
            raise ValueError('actual unreserved fee cash does not back remaining outer budgets')
        quote = chain.call('estimatesmartfee', 1, 'CONSERVATIVE')
        estimate = btc_to_sat(quote['feerate'])
        if estimate < 1: raise ValueError('current source fee quote missing')
        ending = chain.identity()
        if (chain.call('getblockhash', 0) != SIGNET_GENESIS or ending['chain'] != 'signet'
                or ending['initialblockdownload'] is not False
                or (ending['blocks'],ending['bestblockhash']) != (start['blocks'],start['bestblockhash'])):
            raise ValueError('independent chain changed during full financial observation')
        proof = {'complete':True, 'source_observation':observation, 'financial_pins':boundary['pins'],
            'boundary_id':boundary['id'], 'height':assets['height'], 'tip_hash':assets['tip_hash'],
            'observed_at':time.time(), 'effective_fee_ceilings_sat_kvb':limits,
            'estimated_fee_rate_sat_kvb':estimate, 'capital_exposure_msat':assets['total_msat'],
            'available_fee_funding_msat':available, 'native_fee_reservations':fee,
            'pending_native_fee_exposure_msat':pending_fees, 'pending_liabilities':source['pending_liabilities'],
            'recovered_backing':recovered, 'fresh_backing':fresh_backing, 'treasury_reconciliation':edge,
            'source_event_hash':source_event['hash'], 'original_source_hashes':source['original_sha256']}
        if opening is None:
            if opening_declaration is None: raise ValueError('explicit first-opening declaration required')
            proof['preserved_history_opening'] = {'history':preserved,
                'inventory_sequences':captured['inventory_sequences'], 'retained_client_rights':claims,
                'pending_liabilities':source['pending_liabilities'],
                'historical_cost_sequences':source['cost_sequences'], 'historical_flow_sequences':source['flow_sequences']}
        public_payload(proof)
        if not 0 <= proof['observed_at']-timestamp(observation['started_at'],'normal observation start') <= 90:
            raise ValueError('full source verification exceeded fresh observation bound')
        with store.transaction():
            store.verify_event_chain()
            if opening is None and history(store) != preserved: raise ValueError('original history changed during opening verification')
            if opening is not None and recorded(store) != opening: raise ValueError('preserved financial opening changed')
            store._event('financial_operating_readiness', proof)
            sequence = store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
            if opening is None:
                from .financial_transition import validate
                validate(store, {**opening_declaration, 'readiness_sequence':sequence}, boundary,
                    captured['inventory_sequences'], chain, now=proof['observed_at'])
        return sequence

"""Project newly authenticated private A frames into the normal source journal.

Readers are explicitly installed Python dependencies, admitted by module and
configuration hashes. They perform bounded read-only transports and retain raw
originals privately. Neither an observer response nor a file's complete flag can
choose a reader, alter membership, or grant financial readiness.
"""
import json
import os
import re
import time
from pathlib import Path

from .final_campaign import _source_event
from .financial_transition import _current_claims
from .model import SIGNET_GENESIS, canonical, integer, public_payload, timestamp
from .treasury import _members
from .two_step_normal import digest, module_hash, native_tables, native_wallet, private_history_hash, strict_json

WALLET_FIELDS = ('wallet','network','tip_height','tip_hash','public_descriptor','last_revealed_index',
    'min_trusted_confirmations','pending_transactions','reserved_outpoints','unavailable_parent_txids')
UTXO_FIELDS = ('outpoint','value_sat','script_pubkey','derivation_index','keychain','coinbase',
    'confirmations','confirmed_fee_eligible','mature','reserved','trusted')


def wallet_projection(member, native, *, height, tip_hash):
    """Literal source fields, exact descriptor/index ownership, no SDK calls."""
    if (native['network'] != 'signet' or (native['tip_height'],native['tip_hash']) != (height,tip_hash)
            or len(member['descriptors']) != 1 or member['descriptors'][0] != native['public_descriptor']
            or native['pending_transactions'] or native['unavailable_parent_txids']):
        raise ValueError('owning wallet identity/descriptor/tip/pending source unresolved')
    if not isinstance(native['utxos'], list) or len(native['utxos']) > 20000:
        raise ValueError('bounded owning wallet row set required')
    report = {key:native[key] for key in WALLET_FIELDS}
    report['utxos'] = []; projection = []; seen = set()
    for original in native['utxos']:
        row = {key:original[key] for key in UTXO_FIELDS}; point = row['outpoint']
        if point in seen or row['keychain'] != 'external':
            raise ValueError('duplicate wallet point or undeclared keychain')
        seen.add(point); child = integer(row['derivation_index'], 'actual public child')
        if child >= 2**31: raise ValueError('ordinary public child required')
        integer(row['value_sat'],'owning native amount',1)
        report['utxos'].append(row)
        projection.append({'outpoint':point, 'amount_sat':row['value_sat'], 'script':row['script_pubkey'],
            'descriptor_index':0, 'child_index':child})
    public_payload(report); public_payload(projection)
    return report, projection


def cln_projection(member, raw, *, height):
    """Whitelist actual CLN public money fields; never journal PSBTs/preimages."""
    info = raw['getinfo']; funds = raw['listfunds']; peer_rows = raw['listpeerchannels']['channels']
    if (info['id'] != member['identity'] or info['network'] != 'signet' or info['blockheight'] != height
            or any(not isinstance(v,list) or len(v)>2000 for v in (funds['outputs'],funds['channels'],peer_rows))):
        raise ValueError('actual CLN identity/height/row coverage differs')
    outputs = []; cash = []; channels = []; peers = []
    for row in funds['outputs']:
        item = {key:row[key] for key in ('txid','output','amount_msat','scriptpubkey','status')}
        if row['status'] == 'spent': outputs.append(item); continue
        item['blockheight'] = row['blockheight']
        if row['status'] != 'confirmed' or integer(row['amount_msat'],'CLN cash') % 1000:
            raise ValueError('pending CLN cash requires a source resolver')
        outputs.append(item); cash.append({'outpoint':row['txid']+':'+str(integer(row['output'],'output')),
            'amount_sat':row['amount_msat']//1000, 'script':row['scriptpubkey']})
    fund_channels = [{key:row[key] for key in ('funding_txid','funding_output','state','our_amount_msat','amount_msat')}
        for row in funds['channels']]
    for row in peer_rows:
        if row['state'] != 'CHANNELD_NORMAL' or row['htlcs']:
            raise ValueError('non-normal or conditional channel needs its own resolver')
        peer = {key:row[key] for key in ('funding_txid','funding_outnum','state','channel_id','peer_id','to_us_msat','total_msat')}
        peer['htlcs'] = []; peers.append(peer)
        channels.append({'funding_outpoint':row['funding_txid']+':'+str(integer(row['funding_outnum'],'funding output')),
            'channel_id':row['channel_id'],'peer_identity':row['peer_id'],
            'owned_balance_msat':integer(row['to_us_msat'],'full owned balance')})
    native = {'getinfo':{key:info[key] for key in ('id','network','blockheight')},
        'listfunds':{'outputs':outputs,'channels':fund_channels}, 'listpeerchannels':{'channels':peers}}
    public_payload(native)
    return native, cash, channels


def public_wallet_projection(member, raw, *, height, tip_hash):
    """Non-fee wallets discovered by admitted Core/public-descriptor readers.

    This is not a native wallet-known fee-cash claim. The normal treasury still
    independently checks every output against its declared public descriptor.
    """
    if (member['role'] not in {'customer','funding_bank'}
            or raw['source_kind'] not in {'core_wallet_rpc','public_descriptor_activity','core_descriptor_scan'}
            or raw['network'] != 'signet' or (raw['height'],raw['tip_hash']) != (height,tip_hash)
            or raw['pending_transactions'] or raw['discovery_gaps']
            or raw['public_descriptors'] != member['descriptors']
            or not isinstance(raw['source_records'],list) or not raw['source_records']
            or any(not isinstance(value,str) or re.fullmatch('[0-9a-f]{64}',value) is None for value in raw['source_records'])
            or not isinstance(raw['utxos'],list) or len(raw['utxos'])>20000):
        raise ValueError('actual non-fee public wallet source/discovery unresolved')
    rows=[];seen=set()
    for row in raw['utxos']:
        point=row['outpoint'];index=integer(row['descriptor_index'],'public descriptor index')
        child=integer(row['child_index'],'public derivation child')
        if point in seen or index>=len(member['descriptors']) or child>=2**31:
            raise ValueError('duplicate point or undeclared public wallet derivation')
        seen.add(point);integer(row['amount_sat'],'public wallet amount',1)
        rows.append({key:row[key] for key in ('outpoint','amount_sat','script','descriptor_index','child_index')})
    return rows


class SourceCapture:
    """Journal frames from two admitted current-source readers, not saved flags.

    target_reader(observation) -> private TARGET package, retaining its actual
    manifest/runtime/source originals; member_reader(observation, members) ->
    exact non-target member frames. Readers return raw records, never Store
    sequences. The normal collector independently re-verifies every money join.
    """
    def __init__(self, target_reader, member_reader, admission_sequence, boundary, configuration, dependencies=None):
        self.target_reader = target_reader; self.member_reader = member_reader
        self.admission_sequence = admission_sequence; self.boundary = boundary
        self.configuration = configuration; self.dependencies = dependencies or {}
        if set(self.dependencies)&{'target_reader','member_reader'}:raise ValueError('reader dependency identity cannot be overridden')

    def admission(self, store, observation):
        event, value = _source_event(store, self.admission_sequence)
        dependencies = {'target_reader':module_hash(self.target_reader),'member_reader':module_hash(self.member_reader),
            **{name:module_hash(function) for name,function in self.dependencies.items()}}
        target_instance=self.target_reader.__self__;member_instance=self.member_reader.__self__
        actual_readers={'target':{'command':list(target_instance.command),
            'evidence_directory':str(target_instance.evidence_directory),'timeout':target_instance.timeout},
            'member':member_instance.configuration}
        if (event['kind'] != 'normal_financial_collector_qualified'
                or value['reader_configuration_sha256'] != digest(canonical(actual_readers).encode())
                or value['financial_pins'] != observation['financial_pins']
                or value['capture_dependencies_sha256'] != dependencies
                or value['capture_configuration_sha256'] != digest(canonical(self.configuration).encode())
                or self.configuration['boundary_sha256'] != digest(canonical(self.boundary).encode())):
            raise ValueError('installed actual source-reader qualification/configuration differs')
        return value

    async def collect(self, store, config, chain, snapshot, observation):
        admission = self.admission(store, observation); members = _members(self.boundary)
        if (observation['boundary_id'] != self.boundary['id'] or observation['financial_pins'] != self.boundary['pins']):
            raise ValueError('captured boundary differs from immutable observation')
        start = time.time()
        # GetArkInfo returns before any wallet is opened in the admitted driver.
        # The command/config hashes are checked locally, not trusted from output.
        if len(config.driver_command) != 1:
            raise ValueError('one actual admitted public-info executable required')
        executable = Path(config.driver_command[0]); driver_config = Path(os.environ.get('SIM_DRIVER_CONFIG',''))
        if (not executable.is_absolute() or executable.is_symlink()
                or digest(executable.read_bytes()) != observation['financial_pins']['driver_sha256']
                or not driver_config.is_absolute() or driver_config.is_symlink()
                or digest(driver_config.read_bytes()) != self.configuration['driver_config_sha256']):
            raise ValueError('actual info driver/config bytes differ from admitted source')
        from .process import json_command, public_command_capture
        request = {'actor_dir':None,'operation':'info','action_id':'normal-info-'+observation['id'],
            'args':{},'maximum_fee_sat':0,'expected_server_pubkey':snapshot['identity']['server_pubkey']}
        info = await json_command(list(config.driver_command),request,timeout=30,
            **public_command_capture(store,'normal.public_info',request))
        # The native response_fee() deliberately leaves info's fee null. This
        # source-audited no-wallet operation is not a financial fee receipt.
        if (info['action_id'] != request['action_id'] or info['status'] != 'ok' or info.get('actual_fee_sat') not in (None,0)
                or info['data']['network'] != 'signet'
                or info['data']['server_pubkey'] != snapshot['identity']['server_pubkey']
                or digest(executable.read_bytes()) != observation['financial_pins']['driver_sha256']
                or digest(driver_config.read_bytes()) != self.configuration['driver_config_sha256']):
            raise ValueError('actual independent public server identity differs')
        target = await self.target_reader(json.loads(canonical(observation)))
        # No parallel bank/Core/CLN calls before the owning TARGET cut completes.
        additional = await self.member_reader(json.loads(canonical(observation)), members, target)
        for package in (target, additional):
            manifest = package['manifest']
            if (digest(package['raw_manifest']) != package['manifest_sha256']
                    or strict_json(package['raw_manifest']) != manifest
                    or manifest['unresolved_sources']):
                raise ValueError('actual private manifest hash/source coverage differs')
            if (manifest['source_observation_id'] != observation['id']
                    or manifest['height'] != observation['height'] or manifest['tip_hash'] != observation['tip_hash']
                    or not start <= timestamp(manifest['started_at'],'source started') <=
                        timestamp(manifest['completed_at'],'source completed') <= time.time()):
                raise ValueError('actual source nonce/fresh tip/bracket differs')
        if (target['manifest']['source_program_sha256'] != admission['target_source_sha256']
                or additional['manifest']['source_program_sha256'] != admission['member_source_sha256']):
            raise ValueError('actual private source program differs from installed admission')
        original = {'native_sql':target['raw_sql'], 'policy':target['raw_policy'],
            'core':target['raw_core'], 'rounds_inventory':target['raw_rounds_inventory'],
            'watchman_inventory':target['raw_watchman_inventory'], 'runtime':target['raw_runtime']}
        if target['manifest']['original_sha256'] != {key:digest(raw) for key,raw in original.items()}:
            raise ValueError('private TARGET original content differs from authenticated manifest')
        if target['manifest']['fee_history_sha256'] != private_history_hash(target['fee_history']):
            raise ValueError('retained private fee history differs from authenticated manifest')
        runtime = strict_json(target['raw_runtime'])
        if (runtime['identity'] != snapshot['identity'] or runtime['binary_sha256'] != admission['binary_sha256']
                or runtime['configuration_sha256'] != observation['financial_pins']['configuration_sha256']
                or runtime['schema_sha256'] != observation['financial_pins']['schema_sha256']
                or runtime['container_runtime_stable'] is not True):
            raise ValueError('actual active runtime/policy/schema/source identity differs')
        tables = native_tables(target['raw_sql'],target['manifest']['original_sha256']['native_sql'])
        rounds = admission['rounds_member_id']; watch = admission['watchman_member_id']
        if rounds == watch or {rounds,watch}-set(members): raise ValueError('distinct actual native fee members required')
        if set(additional['members']) != set(members)-{rounds,watch}:
            raise ValueError('actual source missing a declared boundary member')
        member_hashes = {name:digest(frame['raw_original']) for name,frame in additional['members'].items()}
        if (additional['manifest']['original_sha256'] != member_hashes
                or any(frame['source_sha256'] != member_hashes[name] for name,frame in additional['members'].items())):
            raise ValueError('actual complete member package differs from original manifest')
        inventories = {}; sources = {}; hashes = {}; liabilities = []
        def event(kind, value):
            public_payload(value);store._event(kind,value)
            return store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
        # Source projections do not authorize anything. The enclosing normal
        # collector still checks the actual native proofs, Core, costs and cash.
        with store.transaction():
            for name, member in members.items():
                context = {'member_id':name,'identity':member['identity'],'financial_pins':self.boundary['pins'],
                    'height':observation['height'],'tip_hash':observation['tip_hash'],'observed_at':time.time()}
                body = {**context,'pending_transactions':[],'reserved_outpoints':[],'discovery_gaps':[]}
                channels = []
                if member['kind'] == 'wallet':
                    if name in {rounds,watch}:
                        raw = target['raw_rounds_inventory'] if name == rounds else target['raw_watchman_inventory']
                        source = native_wallet(raw, 'rounds' if name == rounds else 'watchman'); source_hash = digest(raw)
                        source_kind = 'actual_native_owning_wallet'
                    else:
                        frame = additional['members'][name]; raw = frame['raw_original']; source_hash = digest(raw)
                        if source_hash != frame['source_sha256']:raise ValueError('actual member raw original hash differs')
                        # The admitted reader must genuinely establish its complete
                        # public descriptor discovery; a source boolean is ignored.
                        original_frame = strict_json(raw)
                        if original_frame['discovery_gaps']:
                            raise ValueError('actual descriptor discovery remains incomplete')
                        source_kind = original_frame['source_kind']
                    if name in {rounds,watch}:
                        literal, utxos = wallet_projection(member, source,
                            height=observation['height'],tip_hash=observation['tip_hash'])
                        body.update(wallet_inventory=literal,reserved_outpoints=literal['reserved_outpoints'])
                    else:
                        utxos = public_wallet_projection(member, original_frame,
                            height=observation['height'],tip_hash=observation['tip_hash'])
                        body['reserved_outpoints'] = original_frame['reserved_outpoints']
                    body.update(original_source_sha256=source_hash,source_kind=source_kind)
                elif member['kind'] == 'lightning_peer':
                    frame = additional['members'][name]; raw = frame['raw_original']
                    if digest(raw) != frame['source_sha256']:raise ValueError('actual CLN original hash differs')
                    native, utxos, channels = cln_projection(member, strict_json(raw),
                        height=observation['height'])
                    body.update(native, original_source_sha256=digest(raw),source_kind='actual_cln_public_money_fields')
                    cash_source = event('treasury_cln_wallet_source', {**context,'genesis':SIGNET_GENESIS,
                        'member_verification_sequence':member['verification_sequence'],
                        'getinfo':native['getinfo'],'listfunds':native['listfunds']})
                    utxos = [{**row,'source_sequence':cash_source} for row in utxos]
                else:
                    frame = strict_json(additional['members'][name]['raw_original'])
                    if frame['source_kind'] != 'native_signed_ordinary_backing':
                        raise ValueError('Ark member needs actual signed backing source')
                    claims = _current_claims(store); root_points = set()
                    inside = {name}
                    for claim in claims:
                        owned = store.db.execute('SELECT proof FROM owned_coin WHERE id=?',(claim['coin_id'],)).fetchone()
                        if json.loads(owned['proof'])['server_pubkey'] != member['identity']:continue
                        customer = self.configuration['actor_member_ids'].get(claim['actor'])
                        if customer not in members or members[customer]['kind']!='wallet' or members[customer]['role']!='customer':
                            raise ValueError('owned Ark actor lacks its declared customer wallet member')
                        inside.add(customer)
                    rows = {row['vtxo_id']:row for row in tables['vtxo']}; utxos = []
                    for claim in claims:
                        owned = store.db.execute('SELECT proof FROM owned_coin WHERE id=?',(claim['coin_id'],)).fetchone()
                        proof = json.loads(owned['proof'])
                        if proof['server_pubkey'] != member['identity']:continue
                        point = proof['chain_anchor']; root = rows.get(point)
                        if root is None:raise ValueError('actual native original backing root missing')
                        if root['onchain_spent_txid'] is not None:continue
                        if point in root_points:continue
                        root_points.add(point)
                        actual = frame['roots'].get(point)
                        if actual is None:raise ValueError('actual source omitted unspent backing root')
                        sequence = event('treasury_backing_verified', {'outpoint':point,'script':actual['script'],
                            'financial_pins':self.boundary['pins'],'inside_members':sorted(inside),
                            'server_identity':member['identity'],'native_source_sha256':target['manifest']['original_sha256']['native_sql']})
                        utxos.append({'outpoint':point,'amount_sat':actual['amount_sat'],'script':actual['script'],
                            'verification_sequence':sequence})
                    if set(frame['roots']) != root_points:raise ValueError('extra or missing unspent backing attribution')
                    body.update(source_kind=frame['source_kind'],original_source_sha256=target['manifest']['original_sha256']['native_sql'])
                body.update(reported_utxos=utxos,reported_channels=channels)
                sources[name] = event('treasury_native_inventory_source',body)
                hashes[name] = digest(canonical(body).encode())
                inventories[name] = event('treasury_inventory', {**context,'complete':True,'utxos':utxos,'channels':channels})
            for claim in _current_claims(store):
                proof = json.loads(store.db.execute('SELECT proof FROM owned_coin WHERE id=?',(claim['coin_id'],)).fetchone()['proof'])
                borrowers = [name for name,member in members.items() if member['kind']=='ark_backing' and member['identity']==proof['server_pubkey']]
                if len(borrowers)!=1:raise ValueError('one declared borrower required for each retained right')
                liability = {'id':'coin:'+claim['coin_id'],'borrower':borrowers[0],'amount_msat':claim['amount_sat']*1000}
                sequence = event('treasury_liability_verified',liability)
                liabilities.append({**liability,'source_sequence':sequence})
            frame = {'source_observation':observation,'financial_pins':self.boundary['pins'],'boundary_id':self.boundary['id'],
                'height':observation['height'],'tip_hash':observation['tip_hash'],'observed_at':time.time(),
                'identity':runtime['identity'],'binary_sha256':runtime['binary_sha256'],
                'original_sha256':{key:target['manifest']['original_sha256'][key] for key in ('native_sql','policy','core','rounds_inventory')},
                'fee_history_sha256':target['manifest']['fee_history_sha256'],
                'inventory_source_sequences':sources,'member_source_hashes':hashes,
                'rounds_member_id':rounds,'watchman_member_id':watch,
                'injection_declaration_hashes':admission['injection_declaration_hashes'],
                'pending_liabilities':liabilities,
                'flow_sequences':[row[0] for row in store.db.execute("SELECT sequence FROM event WHERE kind='treasury_flow_verified' ORDER BY sequence")],
                'cost_sequences':[row[0] for row in store.db.execute("SELECT sequence FROM event WHERE kind='financial_cost_verified' ORDER BY sequence")],
                'target_manifest_sha256':target['manifest_sha256'],'member_manifest_sha256':additional['manifest_sha256']}
            frame['actual_public_server_info'] = info['data']
            source_sequence = event('normal_financial_source',frame)
        return {'source_sequence':source_sequence,'inventory_sequences':inventories,
            'raw_sql':target['raw_sql'],'raw_policy':target['raw_policy'],'raw_core':target['raw_core'],
            'raw_rounds_inventory':target['raw_rounds_inventory'],'fee_history':target['fee_history']}

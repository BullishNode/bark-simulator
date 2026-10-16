"""Independent descriptor/input ownership for admitted ordinary funding.

This source-only verifier returns records, never events, authority or readiness.
Its original source packages and prospective declarations must be independently
admitted. The existing collector's funding-import refusal remains unchanged.
"""
import re
import time
from pathlib import Path

from .bundle_audit import decode_transaction
from .final_campaign import _source_event
from .model import SIGNET_GENESIS, btc_to_sat, canonical, integer, public_payload
from .normal_member_source import bank_output_ownership
from .private_source_package import relative
from .treasury import _members
from .two_step_normal import digest, module_hash, strict_json

MAX_FILES = 12000
MAX_BYTES = 64 * 1024 * 1024


def _hash(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError('canonical funding/source hash required')
    return value


def _time(value):
    from datetime import datetime
    if not isinstance(value, str): raise ValueError('literal source UTC time required')
    parsed = datetime.fromisoformat(value)
    if parsed.utcoffset() is None: raise ValueError('source time needs timezone')
    return parsed.timestamp()


def _package(package, entry, qualified, chain, height):
    raw = package['manifest_bytes']; files = package['files']
    if (not isinstance(raw, bytes) or not 0 < len(raw) <= 4 * 1024 * 1024
            or digest(raw) != entry['bank_manifest_sha256'] or not isinstance(files, dict)
            or not 0 < len(files) <= MAX_FILES):
        raise ValueError('admitted original bank manifest missing or changed')
    manifest = strict_json(raw)
    if (manifest['source_program_sha256'] != qualified['bank_source_program_sha256']
            or manifest['unresolved_sources'] or set(files) != set(manifest['files'])
            or re.fullmatch('[0-9a-f]{32}', manifest['source_observation_id']) is None):
        raise ValueError('original bank source program/membership differs')
    total = 0
    for name, body in files.items():
        relative(name)
        if not isinstance(body, bytes) or len(body) > 2 * 1024 * 1024:
            raise ValueError('bank private source byte bound')
        total += len(body)
        if total > MAX_BYTES or manifest['files'][name] != {'sha256':digest(body), 'size_bytes':len(body)}:
            raise ValueError('original bank file hash/size differs')
    mapping = manifest['originals_map']
    if set(mapping) != {'bank', 'core', 'fixture_cln', 'runtime'}:
        raise ValueError('complete original member-source roles required')
    originals = {name:files[relative(path)] for name, path in mapping.items()}
    if manifest['original_sha256'] != {name:digest(body) for name,body in originals.items()}:
        raise ValueError('original bank role/source hash differs')
    source_height = integer(manifest['height'], 'archived bank source height')
    source_tip = _hash(manifest['tip_hash'])
    if source_height > height or chain.call('getblockhash', source_height) != source_tip:
        raise ValueError('original bank source is not on current active chain')
    if not 0 <= _time(manifest['started_at']) <= _time(manifest['completed_at']) <= time.time():
        raise ValueError('original bank source time bracket differs')
    core = strict_json(originals['core'], decimals=True)
    if (core['genesis'] != SIGNET_GENESIS or any(
            (v['chain'], v['blocks'], v['bestblockhash'], v['initialblockdownload'])
            != ('signet', source_height, source_tip, False) for v in (core['before'], core['after']))):
        raise ValueError('original bank source Core identity/brackets differ')
    bank = strict_json(originals['bank'], decimals=True)
    # Hashes bind the literal source, while these joins establish that the
    # aggregate actually contains the matching native RPC results.
    index = strict_json(files['rpc-original-index.private.json'])
    if not isinstance(index, list) or len(index) != manifest['rpc_count'] or len(index) > 512:
        raise ValueError('bounded original bank RPC index required')
    bank_calls = {}; core_calls = []; used = set()
    for row in index:
        if set(row) != {'method','params','request','response','response_sha256','source'}:
            raise ValueError('literal bank RPC index fields differ')
        request_path = relative(row['request']); response_path = relative(row['response'])
        if request_path in used or response_path in used:
            raise ValueError('same original bank RPC frame reused')
        used.update((request_path, response_path))
        request = strict_json(files[request_path]); response_raw = files[response_path]
        response = strict_json(response_raw, decimals=True)
        if (digest(response_raw) != row['response_sha256'] or request.get('jsonrpc') != '2.0'
                or response.get('jsonrpc') != '2.0' or 'id' not in request
                or type(request['id']) is not int or type(response.get('id')) is not int
                or request['id'] != response['id'] or response.get('error') is not None
                or 'result' not in response or request.get('method') != row['method']
                or canonical(request.get('params')) != canonical(row['params'])):
            raise ValueError('original bank RPC request/response envelope differs')
        key = (row['method'], canonical(row['params']))
        if row['source'] == 'bank_core':
            if key in bank_calls: raise ValueError('bank RPC method/arguments repeated')
            bank_calls[key] = response['result']
        elif row['source'] == 'core': core_calls.append((key, response['result']))
        elif row['source'] != 'fixture_cln': raise ValueError('unknown original source role')
    expected = {
        ('getwalletinfo','[]'):bank['getwalletinfo'], ('getbalances','[]'):bank['getbalances'],
        ('listdescriptors','[false]'):bank['listdescriptors'],
        ('listunspent',canonical([0,9999999,[],True,{'maximumCount':2001,'include_immature_coinbase':True}])):bank['listunspent'],
        ('listlockunspent','[]'):bank['listlockunspent'],
        ('listtransactions',canonical(['*',2001,0,True])):bank['listtransactions']}
    expected.update({('getaddressinfo',canonical([address])):result for address,result in bank['getaddressinfo'].items()})
    expected.update({('gettxout',canonical([point.rsplit(':',1)[0],int(point.rsplit(':',1)[1]),True])):result
        for point,result in bank['locked_gettxout'].items()})
    if (bank_calls != expected or core_calls != [
            (('getblockchaininfo','[]'),core['before']),
            (('getblockhash','[0]'),SIGNET_GENESIS),
            (('getblockchaininfo','[]'),core['after'])]):
        raise ValueError('literal native bank aggregate/RPC membership differs')
    info = bank['getwalletinfo']; balances = bank['getbalances']['mine']
    if (info.get('scanning') is not False or info.get('descriptors') is not True
            or type(info.get('txcount')) is not int or not 0 <= info['txcount'] <= 2000
            or len(bank['listunspent']) > 2000 or len(bank['listtransactions']) > 2000
            or bank['listlockunspent'] or bank['locked_gettxout']
            or balances['untrusted_pending'] != 0 or balances['immature'] != 0
            or any(type(v.get('confirmations')) is not int or v['confirmations'] < 1 for v in bank['listtransactions'])):
        raise ValueError('original bank source has unresolved locks/pending/discovery')
    return manifest, bank


class _Chain:
    def __init__(self, chain, height, tip):
        self.chain, self.height, self.tip = chain, integer(height,'current height'), _hash(tip)
        self.calls = 0; self.started = time.monotonic(); self.bytes = 0; self.transactions = {}
        self.stable()
    def call(self, method, *args):
        if method not in {'getblockhash','getdescriptorinfo','deriveaddresses','validateaddress'}:
            raise ValueError('funding verifier does not authorize this Core method')
        self.bound(); return self.chain.call(method,*args)
    def bound(self):
        self.calls += 1
        if self.calls > 1024 or self.bytes > MAX_BYTES or time.monotonic()-self.started > 60:
            raise ValueError('funding proof source resource bound')
    def stable(self):
        self.bound(); value = self.chain.identity()
        if (value['chain'] != 'signet' or value['initialblockdownload'] is not False
                or (value['blocks'],value['bestblockhash']) != (self.height,self.tip)
                or self.call('getblockhash',0) != SIGNET_GENESIS):
            raise ValueError('independent funding Core identity/tip differs')
    def tx(self, txid, *, confirmed=False):
        _hash(txid)
        if txid not in self.transactions:
            self.bound(); value = self.chain.tx(txid)
            decoded = decode_transaction(value['hex'],public_body=True)
            self.bytes += len(value['hex'])//2
            if value['txid'] != txid or decoded['txid'] != txid:
                raise ValueError('funding Core raw transaction identity differs')
            self.transactions[txid] = value,decoded
        value,decoded = self.transactions[txid]
        if confirmed:
            count = value.get('confirmations')
            if (type(count) is not int or not 1 <= count <= self.height+1
                    or self.call('getblockhash',self.height-count+1) != value.get('blockhash')):
                raise ValueError('funding carrier is not independently active confirmed')
        return value,decoded


def _script(chain, member, descriptor_index, child):
    index = integer(descriptor_index,'destination descriptor index'); child = integer(child,'destination child')
    if member['kind'] != 'wallet' or index >= len(member['descriptors']) or child >= 2**31:
        raise ValueError('declared ordinary destination descriptor/path required')
    descriptor = member['descriptors'][index]; info = chain.call('getdescriptorinfo',descriptor)
    if info.get('hasprivatekeys') is not False or info.get('descriptor') != descriptor:
        raise ValueError('canonical public destination descriptor required')
    addresses = chain.call('deriveaddresses',descriptor,[child,child])
    if not isinstance(addresses,list) or len(addresses) != 1: raise ValueError('one destination derivation required')
    result = chain.call('validateaddress',addresses[0])
    if result.get('isvalid') is not True: raise ValueError('destination address invalid')
    return result['scriptPubKey'], addresses[0]


def _bank_row(bank, member, chain, point):
    rows = [row for row in bank['listunspent'] if row['txid']+':'+str(row['vout']) == point]
    if len(rows) != 1: raise ValueError('funding point absent/duplicated in original bank inventory')
    row = rows[0]
    if (type(row.get('confirmations')) is not int or row['confirmations'] < 1
            or any(row.get(key) is not True for key in ('spendable','solvable','safe'))):
        raise ValueError('original bank funding input is not confirmed ordinary available cash')
    owned = bank_output_ownership(bank, member, chain, row)
    script,address = _script(chain,member,owned['descriptor_index'],owned['child_index'])
    if script != owned['script'] or address != row['address']:
        raise ValueError('actual bank script does not derive from declared descriptor')
    original,tx = chain.tx(row['txid'],confirmed=True); index = integer(row['vout'],'funding output index')
    if index >= len(tx['outputs']) or (tx['outputs'][index]['amount_sat'],tx['outputs'][index]['script']) != (owned['amount_sat'],owned['script']):
        raise ValueError('original bank amount/script differs from independent raw Core')
    return row,owned,original


def verify_funding_ownership(store, chain, *, qualification_sequence, boundary, packages, height, tip_hash):
    """Verify admitted original injection or prospective bank-transfer records.

    packages is declaration_sha256 -> {declaration_bytes, manifest_bytes,files}.
    A qualification binds originals and source programs; it does not prove
    ownership. Core derivation, literal source joins and actual bodies do that.
    """
    store.verify_event_chain(); event,qualified = _source_event(store,qualification_sequence)
    boundary_sha = digest(canonical(boundary).encode()); members = _members(boundary)
    if (boundary['genesis'] != SIGNET_GENESIS or event['kind'] != 'normal_funding_ownership_sources_qualified'
            or qualified['financial_pins'] != boundary['pins'] or qualified['boundary_sha256'] != boundary_sha
            or qualified['module_sha256'] != digest(Path(__file__).read_bytes())
            or qualified['bank_ownership_sha256'] != module_hash(bank_output_ownership)
            or not isinstance(packages,dict) or not 0 < len(packages) <= 32):
        raise ValueError('funding source/module/boundary qualification differs')
    for member in members.values():
        original,proof = _source_event(store,member['verification_sequence'])
        if (original['kind'] != 'treasury_member_verified'
                or proof.get('member') != {k:v for k,v in member.items() if k!='verification_sequence'}
                or proof.get('genesis') != SIGNET_GENESIS or proof.get('financial_pins') != boundary['pins']):
            raise ValueError('actual immutable funding member provenance differs')
    declarations = qualified['declarations']
    entries = {row['declaration_sha256']:row for row in declarations}
    if len(entries) != len(declarations) or set(entries) != set(packages):
        raise ValueError('exact admitted funding declaration membership required')
    bank_id = qualified['bank_member_id']; member = members[bank_id]
    if member['kind'] != 'wallet' or member['role'] != 'funding_bank':
        raise ValueError('funding source must be declared bank descriptor member')
    actual = _Chain(chain,height,tip_hash); costs = {}; flows = {}; zeros = {}; evidence = {}; physical = set(); input_uses = set()
    for sha,entry in entries.items():
        _hash(sha); package = packages[sha]; raw = package['declaration_bytes']
        if not isinstance(raw,bytes) or not 0 < len(raw) <= 65536 or digest(raw) != sha:
            raise ValueError('original immutable funding declaration differs')
        doc = strict_json(raw); manifest,bank = _package(package,entry,qualified,actual,height)
        txid = _hash(doc['txid']); value,tx = actual.tx(txid,confirmed=True)
        if doc['schema'] == 'track-a-supplemental-funding-declaration-v1':
            if (entry['kind'] != 'external_injection' or doc['track'] != 'A'
                    or any(v['outpoint'].startswith('0'*64+':') for v in tx['inputs'])
                    or doc['classification'] != 'EXTERNAL_INJECTION'
                    or type(doc['recycled_principal_sat']) is not int or doc['recycled_principal_sat'] != 0):
                raise ValueError('admitted original external injection classification differs')
            point = txid+':'+str(integer(doc['vout'],'injection output index'))
            if point in physical: raise ValueError('same physical funding output supplied twice')
            physical.add(point); native,owned,received = _bank_row(bank,member,actual,point)
            if manifest['height']-(height-received['confirmations']+1)+1 != native['confirmations']:
                raise ValueError('injection bank observation confirmation differs')
            if (integer(doc['amount_sat'],'injection amount',1) != owned['amount_sat']
                    or doc['script_pubkey'] != owned['script']
                    or doc['recipient_address'] != native['address']):
                raise ValueError('original injection amount/script/address differs from bank ownership')
            identifier = 'injection:'+point
            flows[identifier] = {'monetary_id':identifier,'kind':'injection','outpoint':point,
                'amount_msat':owned['amount_sat']*1000,'script':owned['script'],
                'original_declaration_sha256':sha,'source':'owner','destination':bank_id,'financial_pins':boundary['pins']}
        elif doc['schema'] == 'track-a-bank-transfer-intent-v1':
            if (entry['kind'] != 'bank_transfer' or doc['classification'] != 'INTERNAL_TRANSFER'
                    or doc['source_member'] != bank_id or type(doc['recycled_principal_sat']) is not int or doc['recycled_principal_sat'] != 0
                    or doc['signed_raw_sha256'] != digest(bytes.fromhex(value['hex']))):
                raise ValueError('original bank signed transfer identity differs')
            source_event,source = _source_event(store,entry['source_sequence'])
            prepared_event,prepared = _source_event(store,entry['prepared_sequence'])
            broadcast_event,broadcast = _source_event(store,entry['broadcast_sequence'])
            expected_source = {'financial_pins':boundary['pins'],'boundary_sha256':boundary_sha,'bank_member_id':bank_id,
                'manifest_sha256':entry['bank_manifest_sha256'],'source_program_sha256':qualified['bank_source_program_sha256'],
                'height':manifest['height'],'tip_hash':manifest['tip_hash'],'completed_at':manifest['completed_at']}
            expected_prepared = {'financial_pins':boundary['pins'],'boundary_sha256':boundary_sha,'bank_member_id':bank_id,
                'source_sequence':source_event['sequence'],'declaration_sha256':sha,'txid':txid,
                'signed_raw_sha256':doc['signed_raw_sha256'],'maximum_miner_fee_sat':doc['maximum_miner_fee_sat']}
            if (source_event['kind'] != 'normal_bank_source_captured' or source != expected_source
                    or prepared_event['kind'] != 'normal_bank_transfer_prepared' or prepared != expected_prepared
                    or broadcast_event['kind'] != 'normal_bank_transfer_broadcast_intent'
                    or broadcast != {'financial_pins':boundary['pins'],'prepared_sequence':prepared_event['sequence'],'txid':txid}
                    or not source_event['sequence'] < prepared_event['sequence'] < broadcast_event['sequence']
                    or not 0 <= source_event['observed_at']-_time(manifest['completed_at']) <= 90
                    or not 0 <= prepared_event['observed_at']-_time(manifest['completed_at']) <= 90
                    or not 0 <= broadcast_event['observed_at']-prepared_event['observed_at'] <= 90
                    or broadcast_event['observed_at'] > time.time()
                    or height-value['confirmations']+1 <= manifest['height']):
                raise ValueError('bank inventory/intent not authenticated before publication/confirmation')
            points = [v['outpoint'] for v in tx['inputs']]
            if not points or len(points) != len(set(points)) or points != doc['input_outpoints']:
                raise ValueError('exact unique original bank inputs required')
            gross = 0
            for point in points:
                if point in input_uses: raise ValueError('same bank input reused across declared transfers')
                input_uses.add(point); row,owned,parent = _bank_row(bank,member,actual,point)
                parent_height = height-parent['confirmations']+1
                original_confirmations = manifest['height']-parent_height+1
                if (original_confirmations != row['confirmations'] or original_confirmations < 1
                        or (any(v['outpoint'].startswith('0'*64+':') for v in decode_transaction(parent['hex'])['inputs']) and original_confirmations < 100)):
                    raise ValueError('bank input was not active confirmed/mature at original source')
                gross += owned['amount_sat']
            outputs = doc['outputs']
            if not isinstance(outputs,list) or len(outputs) != len(tx['outputs']) or not outputs:
                raise ValueError('all actual bank outputs need declared destination ownership')
            principal = 0
            for index,(output,original) in enumerate(zip(outputs,tx['outputs'])):
                destination = output['destination_member']
                if destination not in members or output['vout'] != index or type(output['vout']) is not int:
                    raise ValueError('bank destination member/output index differs')
                script,_ = _script(actual,members[destination],output['descriptor_index'],output['child_index'])
                amount = integer(output['amount_sat'],'actual bank output',1)
                if (output['script'],amount) != (original['script'],original['amount_sat']) or script != original['script']:
                    raise ValueError('bank output is not owned by declared destination descriptor')
                if destination == bank_id:
                    if output['kind'] != 'change': raise ValueError('bank change cannot be new transfer income')
                    continue
                if output['kind'] != 'transfer': raise ValueError('bank recipient output misclassified as change')
                principal += amount; point=txid+':'+str(index)
                if point in physical: raise ValueError('same physical funding output supplied twice')
                physical.add(point); identifier='internal:'+point
                flows[identifier]={'monetary_id':identifier,'kind':'internal_transfer','outpoint':point,
                    'amount_msat':amount*1000,'source':bank_id,'destination':destination,'financial_pins':boundary['pins']}
            fee = gross-sum(v['amount_sat'] for v in tx['outputs'])
            if not 0 <= fee <= integer(doc['maximum_miner_fee_sat'],'original bank miner cap') or principal < 1:
                raise ValueError('actual bank conservation/miner cap differs')
            if fee:
                costs['miner:'+txid]={'monetary_id':'miner:'+txid,'kind':'miner_cost','txid':txid,
                    'amount_msat':fee*1000,'budget':'ordinary','source':bank_id,'destination':'miners','financial_pins':boundary['pins']}
            else: zeros[txid]={'txid':txid,'fee_sat':0,'raw_sha256':digest(bytes.fromhex(value['hex'])),'blockhash':value['blockhash'],'budget':'ordinary'}
        else: raise ValueError('unsupported historical funding schema needs its actual ownership join')
        evidence[sha]={'bank_manifest_sha256':entry['bank_manifest_sha256'],'signed_core_raw_sha256':digest(bytes.fromhex(value['hex']))}
    verified_flows = dict(flows)
    reused = {}
    for field,kind,records in [('cost','financial_cost_verified',costs),('flow','treasury_flow_verified',flows)]:
        known={}; reused[field]=[]
        for row in store.db.execute('SELECT sequence FROM event WHERE kind=? ORDER BY sequence',(kind,)):
            _,body = _source_event(store,row[0]); identifier=body['monetary_id']
            if identifier in known: raise ValueError('historical funding monetary identity duplicated')
            known[identifier]=body
        for identifier in list(records):
            if identifier in known:
                expected=records[identifier]
                if any(known[identifier].get(k)!=v for k,v in expected.items() if k!='financial_pins'):
                    raise ValueError('original funding monetary record conflicts; never rewrite')
                reused[field].append(identifier)
                if field == 'flow': verified_flows[identifier] = known[identifier]
                del records[identifier]
    actual.stable(); store.verify_event_chain()
    result={'cost_records':list(costs.values()),'flow_records':list(flows.values()),'zero_fee_carriers':zeros,
        'pending_carriers':{},'client_service_charges':[],'verified_flow_records':verified_flows,'reused_cost_ids':sorted(reused['cost']),
        'reused_flow_ids':sorted(reused['flow']),'evidence_hashes':{'funding_ownership_sources':evidence,'qualification_sequence':event['sequence'],
            'qualification_hash':event['hash'],'funding_module_sha256':qualified['module_sha256'],
            'bank_ownership_module_sha256':qualified['bank_ownership_sha256']}}
    public_payload(result)
    return result

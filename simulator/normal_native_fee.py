"""Independently price A's exact retained native fee reservations.

The admitted collector authenticates the private source cut and filesystem
identity. This reducer checks original bytes; it does not establish exhaustive
wallet discovery, source qualification, available cash, or global readiness.
Reservations are exposure, not evidence that a miner has received that fee.
"""
import hashlib
import json
import re
import time

from .bundle_audit import decode_transaction
from .model import integer

MAX_MONEY = 2100000000000000
POLICY_FIELDS = {'epoch_id','genesis','server_pubkey','ordinary_sat','urgent_sat',
    'ordinary_sat_per_kwu','urgent_child_sat_per_kwu','urgent_package_sat_per_kwu',
    'urgent_max_candidate_sat','urgent_required_confirmed_sat',
    'watchman_descriptor_sha256','watchman_admin_address'}
CANDIDATE_FIELDS = {'epoch_id','path','raw','input_parents','package_parents','package_input_parents'}
URGENT = {'Claim','ProgressParent','ProgressChild'}
PATHS = URGENT | {'Round','Pool','Sweep','Payout','PayoutChild','Offboard'}


def _json(raw, maximum=4*1024*1024):
    if not isinstance(raw,bytes) or len(raw)>maximum:
        raise ValueError('private native fee source exceeds byte bound')
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise ValueError('duplicate native fee JSON field')
            result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=unique)


def _hex(raw, maximum=4*1024*1024):
    if (not isinstance(raw,str) or len(raw)>maximum*2 or len(raw)%2
            or re.fullmatch('[0-9a-f]*',raw) is None):
        raise ValueError('noncanonical private fee source hex')
    return bytes.fromhex(raw)


def _bytes(value):
    if (not isinstance(value,list) or len(value)>4*1024*1024
            or any(type(v) is not int or not 0<=v<=255 for v in value)):
        raise ValueError('bounded native byte vector required')
    return bytes(value)


def _amount(value,name):
    result=integer(value,name)
    if result>MAX_MONEY:raise ValueError('native fee amount exceeds money range')
    return result


def _id(raw):
    return hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()


def verify_native_fee_epoch(policy_bytes,expected_policy_sha256,policy_rows,candidate_rows,chain,*,
        expected_genesis,expected_server_pubkey,expected_history_identity,
        expected_opening_digest,expected_epoch_id,history):
    """Return original TOTAL/booked/remaining; never emit a readiness event.

    ``history`` contains privately captured root_identity, identity_bytes,
    index_bytes, candidates {wtxid: exact file bytes}, and, for an imported
    opening, opening_certificate_bytes and validated_digest_bytes. All paths,
    private bytes and Core authentication remain outside the returned projection.
    Missing, unknown-commit or racing source coverage fails closed.
    """
    deadline=time.monotonic()+20
    def bounded():
        if time.monotonic()>deadline:raise ValueError('native fee source verification deadline exceeded')
    if hashlib.sha256(policy_bytes).hexdigest()!=expected_policy_sha256:
        raise ValueError('external immutable native policy SHA differs')
    policy=_json(policy_bytes,65536)
    if (set(policy)!=POLICY_FIELDS or policy['genesis']!=expected_genesis
            or policy['server_pubkey']!=expected_server_pubkey
            or policy['epoch_id']!=expected_epoch_id):
        raise ValueError('native policy runtime identity differs')
    for name in ['ordinary_sat','urgent_sat','urgent_max_candidate_sat','urgent_required_confirmed_sat']:
        if not _amount(policy[name],name):raise ValueError('native fee allowance must be positive')
    for name in ['ordinary_sat_per_kwu','urgent_child_sat_per_kwu','urgent_package_sat_per_kwu']:
        integer(policy[name],name,1)
    if chain.call('getblockhash',0)!=expected_genesis:
        raise ValueError('independent native fee genesis differs')
    if (not isinstance(policy_rows,list) or len(policy_rows)!=1
            or policy_rows[0].get('id')!='active'
            or policy_rows[0].get('history_identity')!=expected_history_identity
            or policy_rows[0].get('opening_digest')!=expected_opening_digest):
        raise ValueError('native immutable policy/history/opening row differs')
    native_policy=_hex(policy_rows[0]['policy_bytes_hex'],65536)
    if _json(native_policy,65536)!=policy:
        raise ValueError('native stored policy differs from external TOTAL declaration')
    if (history.get('root_identity')!=expected_history_identity
            or history.get('identity_bytes')!=native_policy):
        raise ValueError('independent retained fee history identity differs')
    index=history.get('index_bytes')
    if (not isinstance(index,bytes) or len(index)>100000*65
            or index and not index.endswith(b'\n')):
        raise ValueError('missing, bounded or torn native fee index')
    ids=index.decode('ascii').splitlines()
    if any(re.fullmatch('[0-9a-f]{64}',v) is None for v in ids) or len(set(ids))!=len(ids):
        raise ValueError('native fee index duplicate or noncanonical identity')
    if not isinstance(candidate_rows,list) or len(candidate_rows)>100000:
        raise ValueError('native fee ledger row bound exceeded')
    originals=history.get('candidates')
    if not isinstance(originals,dict) or set(originals)!=set(ids):
        raise ValueError('independent original fee history/index coverage differs')
    parsed={};parent_cache={};total_bytes=0
    def transaction(value):
        raw=_bytes(value);return raw,decode_transaction(raw.hex())
    def source_parent(value):
        raw,decoded=transaction(value);txid=decoded['txid']
        bounded()
        if txid not in parent_cache:
            if len(parent_cache)>=512:raise ValueError('native fee independent parent call bound exceeded')
            actual=chain.tx(txid);bounded()
            if not isinstance(actual,dict) or _hex(actual.get('hex'))!=raw:
                raise ValueError('independent original fee parent bytes unavailable or differ')
            parent_cache[txid]=raw
        elif parent_cache[txid]!=raw:
            raise ValueError('conflicting witness bytes for native fee parent')
        return decoded
    def measured(decoded,parents):
        if not isinstance(parents,list) or len(parents)>4096:
            raise ValueError('bounded original fee parents required')
        sources={}
        for value in parents:
            parent=source_parent(value)
            if parent['txid'] in sources:raise ValueError('duplicate native fee parent')
            sources[parent['txid']]=parent
        points=[v['outpoint'] for v in decoded['inputs']]
        if not points or len(points)>4096 or len(set(points))!=len(points):
            raise ValueError('duplicate or unbounded native fee inputs')
        gross=0
        for point in points:
            txid,vout=point.rsplit(':',1)
            if txid not in sources:raise ValueError('original fee input parent missing')
            outputs=sources[txid]['outputs'];vout=int(vout)
            if vout>=len(outputs):raise ValueError('original fee prevout missing')
            gross+=outputs[vout]['amount_sat']
        fee=gross-sum(v['amount_sat'] for v in decoded['outputs'])
        return _amount(fee,'actual signed native candidate fee')
    booked={'ordinary':0,'urgent':0};reserved=set()
    for row in candidate_rows:
        bounded()
        raw=_hex(row['candidate_bytes_hex']);total_bytes+=len(raw)
        if total_bytes>64*1024*1024:raise ValueError('native fee ledger total byte bound exceeded')
        candidate=_json(raw)
        if (set(candidate)!=CANDIDATE_FIELDS or candidate['epoch_id']!=expected_epoch_id
                or candidate['path'] not in PATHS):
            raise ValueError('native candidate original epoch/path differs')
        signed,tx=transaction(candidate['raw']);identifier=_id(signed)
        if (identifier!=row['id'] or identifier in parsed or row['epoch_id']!=expected_epoch_id
                or originals.get(identifier)!=raw):
            raise ValueError('native candidate or independent original identity differs')
        fee=measured(tx,candidate['input_parents']);urgent=candidate['path'] in URGENT
        if type(row['urgent']) is not bool or row['urgent']!=urgent or _amount(row['fee_sat'],'native recorded fee')!=fee:
            raise ValueError('native candidate actual fee or original class differs')
        rate=policy['urgent_child_sat_per_kwu'] if urgent else policy['ordinary_sat_per_kwu']
        if fee>(rate*tx['weight']+999)//1000 or urgent and fee>policy['urgent_max_candidate_sat']:
            raise ValueError('actual signed native fee exceeds original ceiling')
        if candidate['path']!='ProgressChild' and (candidate['package_parents'] or candidate['package_input_parents']):
            raise ValueError('unexpected native fee package')
        parsed[identifier]=(candidate,tx,fee);booked['urgent' if urgent else 'ordinary']+=fee
        if urgent:reserved.update(v['outpoint'] for v in tx['inputs'])
    if set(parsed)!=set(ids):raise ValueError('native SQL and independent original fee coverage differs')
    for candidate,tx,fee in parsed.values():
        if candidate['path']!='ProgressChild':continue
        parents=candidate['package_parents']
        if not isinstance(parents,list) or not 1<=len(parents)<=64:raise ValueError('native progress package missing')
        seen=set();weight=tx['weight'];package_fee=fee
        for value in parents:
            raw,parent=transaction(value);identifier=_id(raw)
            if parent['txid'] in seen or not any(v['outpoint'].startswith(parent['txid']+':') for v in tx['inputs']):
                raise ValueError('duplicate or unrelated native progress parent')
            seen.add(parent['txid'])
            if identifier not in parsed or parsed[identifier][0]['raw']!=value:
                raise ValueError('native progress parent original reservation missing')
            parent_fee=measured(parent,candidate['package_input_parents'])
            if parent_fee!=parsed[identifier][2]:raise ValueError('native progress parent fee differs')
            package_fee+=parent_fee;weight+=parent['weight']
        if package_fee>(policy['urgent_package_sat_per_kwu']*weight+999)//1000:
            raise ValueError('actual native package fee exceeds original ceiling')
    remaining={}
    for category in ['ordinary','urgent']:
        remaining[category]=policy[category+'_sat']-booked[category]
        if remaining[category]<0:raise ValueError('native cumulative original allowance exhausted')
    imported=0
    if expected_opening_digest is not None:
        certificate=history.get('opening_certificate_bytes')
        if (not isinstance(certificate,bytes) or hashlib.sha256(certificate).hexdigest()!=expected_opening_digest
                or history.get('validated_digest_bytes')!=expected_opening_digest.encode()):
            raise ValueError('independent original native opening certificate missing')
        opening=_json(certificate)
        if (opening.get('version')!=1 or opening.get('genesis')!=expected_genesis
                or opening.get('server_pubkey')!=expected_server_pubkey
                or opening['policy_sha256']!=expected_policy_sha256 or opening['epoch_id']!=expected_epoch_id
                or opening['ordinary_total_sat']!=policy['ordinary_sat'] or opening['urgent_total_sat']!=policy['urgent_sat']):
            raise ValueError('native opening TOTAL identity differs')
        opening_ids=set()
        for candidate in opening['candidates']:
            signed,_=transaction(candidate['raw']);identifier=_id(signed)
            if identifier in opening_ids or identifier not in parsed or parsed[identifier][0]!=candidate or candidate['path']!='Sweep':
                raise ValueError('original native opening debit identity differs')
            opening_ids.add(identifier);imported+=parsed[identifier][2]
        if (not imported or opening['previously_booked_ordinary_sat']!=0 or opening['previously_booked_urgent_sat']!=0
                or opening['import_ordinary_sat']!=imported
                or opening['remaining_ordinary_sat']!=policy['ordinary_sat']-imported
                or opening['remaining_urgent_sat']!=policy['urgent_sat']):
            raise ValueError('native opening import/TOTAL/remainder differs')
    bounded()
    return {'policy_sha256':expected_policy_sha256,'epoch_id':expected_epoch_id,
        'ordinary_total_sat':policy['ordinary_sat'],'ordinary_booked_sat':booked['ordinary'],
        'ordinary_remaining_sat':remaining['ordinary'],'urgent_total_sat':policy['urgent_sat'],
        'urgent_booked_sat':booked['urgent'],'urgent_remaining_sat':remaining['urgent'],
        'original_opening_import_sat':imported,'candidate_ids':sorted(parsed),
        'urgent_required_confirmed_sat':policy['urgent_required_confirmed_sat'],
        'urgent_max_candidate_sat':policy['urgent_max_candidate_sat'],
        'watchman_descriptor_sha256':policy['watchman_descriptor_sha256'],
        'reserved_urgent_prevouts':sorted(reserved),'ordinary_signed_ceiling_sat_kvb':policy['ordinary_sat_per_kwu']*4,
        'urgent_child_signed_ceiling_sat_kvb':policy['urgent_child_sat_per_kwu']*4,
        'urgent_package_signed_ceiling_sat_kvb':policy['urgent_package_sat_per_kwu']*4,
        'scope':'Checked signed reservation exposure; not miner payment, available cash or financial readiness'}

"""Complete Core31 matching-script mempool evidence, never a global tx scan."""
import hashlib
import json
import re
import time
from decimal import Decimal

from .model import canonical, public_payload
from .trace import SCHEMA_VERSION, partition_paths, readonly, record_hash

METHOD = 'getdescriptoractivity'
SCHEMA = 'core31-owned-script-activity-v1'
MAX_RESPONSE_BYTES = 64 * 1024
MAX_REQUEST_BYTES = 512 * 1024
MAX_SCRIPTS = 2000


def _digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def arguments(scripts):
    if (not isinstance(scripts, (set, list, tuple)) or not 1 <= len(scripts) <= MAX_SCRIPTS
            or any(not isinstance(script, str) or re.fullmatch(r'(?:[0-9a-f]{2}){1,10000}', script) is None for script in scripts)
            or len(set(scripts)) != len(scripts)):
        raise ValueError('complete bounded unique owning script set required')
    args = ([], ['raw(' + script + ')' for script in sorted(scripts)], True)
    if len(canonical(args).encode()) > MAX_REQUEST_BYTES:
        raise ValueError('owned script request exceeds byte bound')
    return args


def validate_arguments(args):
    if (not isinstance(args, (tuple, list)) or len(args) != 3 or args[0] != []
            or args[2] is not True or not isinstance(args[1], list)
            or any(not isinstance(item, str) or not item.startswith('raw(') or not item.endswith(')') for item in args[1])):
        raise ValueError('fixed complete owned-script mempool RPC required')
    scripts = [item[4:-1] for item in args[1]]
    if tuple(args) != arguments(scripts):
        raise ValueError('canonical complete owned-script mempool arguments required')
    return scripts


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate Core activity JSON key')
        result[key] = value
    return result


def empty_result(value):
    if not isinstance(value, dict) or set(value) != {'activity'} or not isinstance(value['activity'], list):
        raise ValueError('complete Core owned-script activity reply required')
    if value['activity']:
        raise ValueError('owned wallet has unconfirmed assets or spends')
    return value


def decode_reply(raw):
    if not isinstance(raw,bytes) or not 0 < len(raw) <= MAX_RESPONSE_BYTES:
        raise ValueError('owned-script activity response exceeds byte bound')
    value=json.loads(raw,parse_float=Decimal,object_pairs_hook=unique_object)
    if (not isinstance(value,dict) or set(value)-{'result','error','id','jsonrpc'}
            or type(value.get('id')) is not int or value['id']!=1
            or value.get('jsonrpc','2.0')!='2.0' or value.get('error') is not None):
        raise ValueError('Core owned-script activity envelope unavailable')
    empty_result(value.get('result'))
    return value


def _raw_trace(store, reference, args):
    if (getattr(store, 'trace', None) is None or not isinstance(reference, dict)
            or set(reference) != {'partition', 'seq', 'hash'} or type(reference['seq']) is not int or reference['seq'] < 1):
        raise ValueError('original owned-script activity RPC trace required')
    matches = [path for path in partition_paths(store.trace.root) if path.name == reference['partition']]
    if len(matches) != 1:
        raise ValueError('original owned-script activity trace unavailable')
    conn = readonly(matches[0])
    try:
        sizes = conn.execute('SELECT length(raw),length(payload) FROM trace WHERE seq=?', (reference['seq'],)).fetchone()
        if sizes is None or sizes[0] is None or not 0 < sizes[0] <= MAX_RESPONSE_BYTES or sizes[1] > MAX_REQUEST_BYTES + MAX_RESPONSE_BYTES:
            raise ValueError('original owned-script activity raw trace unavailable or oversized')
        row = conn.execute('SELECT * FROM trace WHERE seq=?', (reference['seq'],)).fetchone()
    finally:
        conn.close()
    if (row['schema_version'] != SCHEMA_VERSION or row['hash'] != reference['hash']
            or record_hash(row) != reference['hash'] or row['kind'] != 'chain.rpc'):
        raise ValueError('original owned-script activity trace changed')
    payload = json.loads(row['payload'], object_pairs_hook=unique_object)
    raw = decode_reply(row['raw'])
    if (payload.get('method') != METHOD or payload.get('params') != list(args)
            or payload.get('error') is not None or payload.get('result') != {'activity': []}
            or not isinstance(raw, dict) or raw.get('error') is not None or raw.get('result') != {'activity': []}):
        raise ValueError('original owned-script activity raw response differs')
    return hashlib.sha256(row['raw']).hexdigest(), row['utc'], len(row['raw'])


def collector_context(kind, source):
    """Expected identity from the authenticated outer producer, never the reply."""
    result={'collector':kind,'financial_pins':source['financial_pins'],
        'boundary_id':source['boundary_id'],'height':source['height'],'tip_hash':source['tip_hash'],
        'descriptor_ranges_sha256':_digest(source['descriptor_ranges'])}
    if kind=='board_backing':
        result.update(anchor=source['origin']['anchor'],anchor_script=source['origin']['anchor_output']['script'])
    return result


def collect(store, chain, scripts, started, *, context):
    args = arguments(scripts)
    if not isinstance(context,dict) or not context or len(canonical(context).encode())>MAX_RESPONSE_BYTES:
        raise ValueError('bounded original owned-script collector context required')
    public_payload(context)
    remaining = 180 - (time.monotonic() - started)
    if remaining <= 0:
        raise ValueError('owned-script activity source deadline exceeded')
    result = chain.call(METHOD, *args, timeout=min(12, remaining), max_response_bytes=MAX_RESPONSE_BYTES)
    empty_result(result)
    if time.monotonic() - started > 180:
        raise ValueError('owned-script activity source deadline exceeded')
    reference = getattr(chain, 'last_capture', None)
    raw_sha, observed, response_bytes = _raw_trace(store, reference, args)
    if time.monotonic()-started>180:
        raise ValueError('owned-script activity source deadline exceeded')
    receipt = {'source_schema': SCHEMA, 'method': METHOD, 'blockhashes': [], 'include_mempool': True,
        'scripts': sorted(scripts), 'script_set_sha256': _digest(sorted(scripts)), 'script_count': len(scripts),
        'result': {'activity': []}, 'raw_trace': reference, 'raw_response_sha256': raw_sha,
        'response_bytes': response_bytes, 'maximum_response_bytes': MAX_RESPONSE_BYTES,
        'maximum_source_seconds': 180, 'observed_at': observed,'collector_context':context,
        'scope': 'complete matching Core mempool activity at RPC lock interval; no global transaction/body counts or confirmed balance claim'}
    public_payload(receipt)
    store.event('owned_script_mempool_activity_verified',receipt)
    row=store.db.execute('SELECT sequence,hash FROM event ORDER BY sequence DESC LIMIT 1').fetchone()
    return {**receipt,'source_sequence':row['sequence'],'source_event_hash':row['hash']}


def verify(store, receipt, *, expected_context):
    if (not isinstance(receipt, dict) or receipt.get('source_schema') != SCHEMA or receipt.get('method') != METHOD
            or receipt.get('blockhashes') != [] or receipt.get('include_mempool') is not True
            or receipt.get('maximum_response_bytes') != MAX_RESPONSE_BYTES
            or receipt.get('maximum_source_seconds') != 180):
        raise ValueError('original complete owned-script activity source required')
    from .final_campaign import _source_event
    event,original=_source_event(store,receipt.get('source_sequence'))
    if (event['kind']!='owned_script_mempool_activity_verified' or event['hash']!=receipt.get('source_event_hash')
            or original!={key:value for key,value in receipt.items() if key not in {'source_sequence','source_event_hash'}}
            or original.get('collector_context')!=expected_context):
        raise ValueError('original owned-script collector context differs')
    args = arguments(receipt.get('scripts'))
    if receipt['scripts']!=sorted(receipt['scripts']):
        raise ValueError('canonical owned-script activity inventory required')
    empty_result(receipt.get('result'))
    raw_sha, observed, size = _raw_trace(store, receipt.get('raw_trace'), args)
    if (receipt.get('script_set_sha256') != _digest(receipt['scripts']) or receipt.get('script_count') != len(receipt['scripts'])
            or receipt.get('raw_response_sha256') != raw_sha or receipt.get('observed_at') != observed
            or receipt.get('response_bytes') != size):
        raise ValueError('original owned-script activity provenance differs')
    return receipt


def verify_source(store,source,kind,*,fresh=False):
    """Bind a dynamic financial source to its original owning collector receipt."""
    field='mempool_activity' if kind=='finite_initial_funding' else 'mempool'
    receipt=verify(store,source.get(field),expected_context=collector_context(kind,source))
    if fresh and not 0<=time.time()-receipt['observed_at']<=90:
        raise ValueError('original owned-script activity source is stale')
    if kind=='finite_initial_funding':
        from .final_campaign import _source_event
        event,original=_source_event(store,source.get('owned_mempool_activity_source_sequence'))
        if (event['kind']!='finite_initial_funding_owned_mempool_activity' or original.get('activity_source')!=receipt
                or any(original.get(key)!=source.get(key) for key in ('height','tip_hash','financial_pins'))):
            raise ValueError('original initial owned-script activity source differs')
    return receipt

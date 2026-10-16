"""Source-only fixed command/schema contract; no installed dispatch or readiness."""
import hashlib
import importlib.util
from pathlib import Path
import re

ADAPTER_SHA256 = '5262ce15f749005bf89322786e9c0dc339173467dcd803c4f0564d0f43053e69'
COMMAND = 'closed-frontier-v2'
SIGNET_GENESIS = '00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6'
PIN_LENGTHS = {'product_commit': 40, 'sdk_commit': 40, 'driver_sha256': 64,
               'configuration_sha256': 64, 'schema_sha256': 64}


def adapter():
    path = Path(__file__).resolve().with_name('dbapi_adapter.py')
    if hashlib.sha256(path.read_bytes()).hexdigest() != ADAPTER_SHA256:
        raise ValueError('frozen adapter source differs')
    spec = importlib.util.spec_from_file_location('fixed_frontier_adapter_v2', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def expected_contract(value):
    """Assertions from protected, independently authenticated deployment config.

    This validator does not make an arbitrary declaration authoritative. The
    caller must retain the existing original runtime/config/genesis proof gates.
    """
    if not isinstance(value, dict) or set(value) != {'resource_declaration', 'source_binding', 'financial_pins', 'deployment_id'}:
        raise ValueError('explicit whole v2 source contract required')
    f = adapter().frontier()
    limits, source = f.declaration(value['resource_declaration']), f.binding(value['source_binding'])
    pins = value['financial_pins']
    if (not isinstance(pins, dict) or set(pins) != set(PIN_LENGTHS)
            or any(not isinstance(pins[k], str) or re.fullmatch('[0-9a-f]{%d}' % n, pins[k]) is None
                   for k, n in PIN_LENGTHS.items())):
        raise ValueError('exact product SDK driver config schema pins required')
    if source['network'] != 'signet' or source['genesis'] != SIGNET_GENESIS or source['schema_sha256'] != pins['schema_sha256']:
        raise ValueError('existing C signet/schema identity differs')
    if not isinstance(value['deployment_id'], str) or re.fullmatch('[a-zA-Z0-9_-]{1,100}', value['deployment_id']) is None:
        raise ValueError('bounded existing deployment identity required')
    return {'resource_declaration': limits, 'source_binding': source,
            'financial_pins': dict(pins), 'deployment_id': value['deployment_id']}


def request(expected):
    value = expected_contract(expected)
    return {'kind': COMMAND, 'resource_declaration': value['resource_declaration'],
            'source_binding': value['source_binding']}


def validate_request(raw, protected_expected):
    """Only the new fixed request; no SQL, host, credentials, cursors or files."""
    f = adapter().frontier()
    if not isinstance(raw, bytes) or len(raw) > 4096:
        raise ValueError('fixed public v2 request byte bound exceeded')
    value = f.strict_json(raw)
    if not isinstance(value, dict) or set(value) != {'kind', 'resource_declaration', 'source_binding'}:
        raise ValueError('fixed public v2 command fields required')
    f.declaration(value['resource_declaration'])
    f.binding(value['source_binding'])
    if value != request(protected_expected):
        raise ValueError('request differs from protected fixed v2 source contract')
    return value


def produce_command(raw_request, protected_expected, private_connection, emit):
    """Proposed restricted worker entry, only under the real process supervisor.

    Protected config and private role parameters must be supplied by reviewed
    installed code. This is not an ops endpoint and opens no ambient config.
    Output is the original NDJSON stream, never a schema1 aggregate alias.
    """
    command = validate_request(raw_request, protected_expected)
    adapter()._produce_worker({'connection': private_connection,
                               'declaration': command['resource_declaration'],
                               'binding': command['source_binding']}, emit)


def _reference(value):
    if (not isinstance(value, dict) or set(value) != {'partition', 'seq', 'hash'}
            or not isinstance(value['partition'], str) or not 1 <= len(value['partition']) <= 128
            or '/' in value['partition'] or '..' in value['partition']
            or type(value['seq']) is not int or value['seq'] < 1
            or not isinstance(value['hash'], str) or re.fullmatch('[0-9a-f]{64}', value['hash']) is None):
        raise ValueError('original hash-verified raw trace reference required')
    return dict(value)


def _frame(database, expected, receipt):
    return {**database, 'architecture_profile': 'direct_per_key', 'fallback_protocol': 4,
            'deployment_declaration_sha256': expected['source_binding']['deployment_sha256'],
            'deployment_id': expected['deployment_id'],
            'declared_financial_pins': expected['financial_pins'], 'frontier_stream_source': receipt}


def consume_original(lines, actual_exit, expected, public_validator, capture_line, load_original_line):
    """Validate full original stream before public capture or database admission.

    lines/actual_exit MUST come from a bounded real process supervisor, not JSON
    claims. capture_line is the existing public TraceStore capture seam. It must
    return actual {partition,seq,hash}; failure never produces an admitted frame.
    """
    expected = expected_contract(expected)
    f = adapter().frontier()
    saved = []
    def originals():
        for line in lines:
            # Producer/consumer enforce line/total/deadline bounds. Keep only the
            # same bounded original bytes needed for replayable source evidence.
            saved.append(line)
            yield line
    status = []
    def actual_status():
        code = actual_exit()
        status.append(code)
        return code
    database = f.consume(originals(), expected['resource_declaration'], expected['source_binding'], actual_status)
    # Check all values before emitting any public raw line; fixed field allowlists
    # alone do not reject a secret-shaped value in a nominally public column.
    for line in saved:
        public_validator(f.strict_json(line))
    context = {'command': COMMAND, 'request_sha256': f.digest(request(expected)),
               'contract_sha256': f.digest(expected), 'stream_final_sha256': database['stream_final_sha256'],
               'producer_exit_code': status[0]}
    refs = [_reference(capture_line({**context, 'index': index}, line)) for index, line in enumerate(saved)]
    receipt = {**context, 'line_references': refs, 'stream_bytes': database['stream_bytes']}
    # TraceStore.capture can substitute a redaction marker and still return a
    # valid reference. Re-read and verify exact original bytes before return.
    return verify_snapshot(_frame(database, expected, receipt), expected, load_original_line)


def verify_snapshot(frame, expected, load_original_line):
    """Replay exact independently hash-verified trace rows, then retain schema2.

    load_original_line must use existing TraceStore partition/record-hash checks
    and return (original_metadata, raw_bytes). Arbitrary paths or caller-provided
    JSON are not a permitted implementation of this seam.
    """
    expected = expected_contract(expected)
    f = adapter().frontier()
    receipt = frame.get('frontier_stream_source')
    fields = {'command', 'request_sha256', 'contract_sha256', 'stream_final_sha256',
              'producer_exit_code', 'line_references', 'stream_bytes'}
    if (not isinstance(receipt, dict) or set(receipt) != fields or receipt['command'] != COMMAND
            or receipt['request_sha256'] != f.digest(request(expected)) or receipt['contract_sha256'] != f.digest(expected)
            or type(receipt['producer_exit_code']) is not int or receipt['producer_exit_code'] != 0
            or not isinstance(receipt['line_references'], list)
            or not 2 <= len(receipt['line_references']) <= expected['resource_declaration']['max_pages'] + 2):
        raise ValueError('original successful whole v2 stream receipt required')
    lines = []
    for index, reference in enumerate(receipt['line_references']):
        metadata, raw = load_original_line(_reference(reference))
        context = {k: receipt[k] for k in ['command', 'request_sha256', 'contract_sha256', 'stream_final_sha256', 'producer_exit_code']}
        if (not isinstance(metadata, dict) or type(metadata.get('index')) is not int
                or type(metadata.get('producer_exit_code')) is not int
                or metadata != {**context, 'index': index}):
            raise ValueError('original stream trace/context differs')
        lines.append(raw)
    database = f.consume(lines, expected['resource_declaration'], expected['source_binding'], lambda: receipt['producer_exit_code'])
    if frame != _frame(database, expected, receipt):
        raise ValueError('v2 snapshot differs from original successful stream')
    return frame

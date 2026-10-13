"""Bind a bounded bridge response to an immutable local public declaration.

The response supplies provenance only. Core derivation and the independent
rounds-wallet anchor remain necessary before any change script is accepted.
"""
from .model import canonical, integer, public_payload
from .ownership import EvidenceGap
from .process import json_command, public_command_capture
from .target_log_window import utc


def validate(config, response):
    public_payload(response)
    if len(canonical(response).encode()) > 16384:
        raise EvidenceGap('bounded rounds descriptor response required')
    if not isinstance(response, dict) or set(response) != {'kind', 'declaration'} or response['kind'] != 'rounds_descriptor':
        raise EvidenceGap('rounds descriptor bridge response required')
    value = response['declaration']
    fields = {'kind', 'version', 'declared_utc', 'network', 'genesis', 'server_pubkey',
              'target_vm', 'wallet_kind', 'descriptor', 'range', 'wallet_last_revealed_at_capture',
              'captured_utc', 'inventory_sha256', 'live_production_head', 'scope'}
    if not isinstance(value, dict) or set(value) != fields:
        raise EvidenceGap('complete public rounds descriptor provenance required')
    if (value['kind'] != 'operator_rounds_wallet_descriptor' or type(value['version']) is not int
            or value['version'] != 1 or value['wallet_kind'] != 'rounds'):
        raise EvidenceGap('public rounds wallet declaration required')
    if any(value[key] != expected for key, expected in (
            ('network', config.network), ('genesis', config.expected_genesis),
            ('server_pubkey', config.expected_server_pubkey))):
        raise EvidenceGap('rounds descriptor bridge target mismatch')
    descriptor = value['descriptor']
    if not isinstance(descriptor, str) or not descriptor or len(descriptor) > 4096:
        raise EvidenceGap('bounded public descriptor required')
    interval = value['range']
    if not isinstance(interval, list) or len(interval) != 2:
        raise EvidenceGap('bounded descriptor range required')
    first, last = (integer(index, 'descriptor index') for index in interval)
    if last < first or last > 1000000:
        raise EvidenceGap('bounded descriptor range required')
    revealed = integer(value['wallet_last_revealed_at_capture'], 'revealed index')
    if not first <= revealed <= last:
        raise EvidenceGap('revealed index outside descriptor range')
    captured, declared = utc(value['captured_utc']), utc(value['declared_utc'])
    if captured > declared:
        raise EvidenceGap('descriptor capture occurs after declaration')
    for field, length in (('inventory_sha256', 64), ('live_production_head', 40)):
        item = value[field]
        if not isinstance(item, str) or len(item) != length or any(c not in '0123456789abcdef' for c in item):
            raise EvidenceGap('bounded descriptor provenance hashes required')
    for field in ('target_vm', 'scope'):
        if not isinstance(value[field], str) or not value[field] or len(value[field]) > 2048:
            raise EvidenceGap('bounded descriptor provenance required')
    return value


async def observe(store, config):
    if not config.inventory_command:
        raise EvidenceGap('rounds descriptor bridge not configured')
    if store.trace is None:
        raise EvidenceGap('rounds descriptor trace capture required')
    request = {'kind': 'rounds_descriptor'}
    response = await json_command(list(config.inventory_command), request, timeout=30,
                                 **public_command_capture(store, 'operator.bridge', request))
    value = validate(config, response)
    reference = store.trace_capture('target.rounds_descriptor', {
        'response': response,
        'scope': 'bridge provenance; ownership still requires independent Core derivation and anchor'})
    if reference is None:
        raise EvidenceGap('rounds descriptor trace unavailable')
    return value, reference


def match(local, remote):
    if local['descriptor'] != remote['descriptor']:
        raise EvidenceGap('declared public descriptor differs from bridge')
    if remote['range'][0] > local['first_index'] or remote['range'][1] < local['last_index']:
        raise EvidenceGap('bridge range does not cover immutable local declaration')

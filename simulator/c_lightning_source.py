"""C-owned read-only CLN source; source transport is declared by a trusted launcher.

A hash-bound local declaration is not a treasury membership proof. The normal
collector must match its node IDs against independently verified boundary members
and retain this original frame in TraceStore before using existing reducers.
This source never invoices, pays, funds, opens a wallet or emits readiness.
"""
from __future__ import annotations

import asyncio
import hashlib
import re
import stat
import time
from pathlib import Path

from .model import SIGNET_GENESIS, canonical, integer, public_payload, timestamp
from .process import decode_object, json_command
from .remote_observer import own_output, peer_channel

ALIASES = {'operator', 'fixture_peer'}
METHODS = ('getinfo', 'listfunds', 'listpeerchannels')
MAX_BYTES = 256 * 1024
MAX_ROWS = 2000


def _hex(value, length=64):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{'+str(length)+'}', value) is None:
        raise ValueError('exact lowercase public identity required')
    return value


def _ids(node_ids):
    if not isinstance(node_ids, dict) or set(node_ids) != ALIASES:
        raise ValueError('two explicitly declared owned CLN roles required')
    if len(set(node_ids.values())) != 2:
        raise ValueError('distinct actual CLN node identities required')
    for value in node_ids.values():
        _hex(value, 66)
        if not value.startswith(('02', '03')):
            raise ValueError('compressed CLN public identity required')
    return dict(node_ids)


def _file(path):
    p = Path(path)
    if not p.is_absolute() or any(item.is_symlink() for item in [p, *p.parents]):
        raise ValueError('fixed absolute nonsymlink owned source path required')
    return p


def _msat(value):
    if isinstance(value, str) and re.fullmatch('[0-9]+msat', value):
        value = int(value[:-4])
    return integer(value, 'native exact millisatoshis')


def load_context(path, expected_sha256, *, node_ids):
    """Caller supplies independently pinned hash AND declared node IDs.

    Paths remain private launcher data; only their declaration digest enters the
    public source. No stock Docker names, default RPC path or fallback service.
    """
    p = _file(path)
    if not stat.S_ISREG(p.stat().st_mode) or p.stat().st_size > 16384:
        raise ValueError('bounded CLN transport declaration required')
    raw = p.read_bytes()
    if hashlib.sha256(raw).hexdigest() != _hex(expected_sha256):
        raise ValueError('owned CLN declaration hash differs')
    context = decode_object(raw.decode())
    if (set(context) != {'schema_version', 'network', 'genesis', 'nodes'}
            or type(context['schema_version']) is not int or context['schema_version'] != 1
            or context['network'] != 'signet' or context['genesis'] != SIGNET_GENESIS
            or not isinstance(context['nodes'], dict) or set(context['nodes']) != ALIASES):
        raise ValueError('exact owned Signet CLN transport declaration required')
    ids = _ids(node_ids)
    for alias, node in context['nodes'].items():
        if (not isinstance(node, dict) or set(node) != {'node_id', 'cli_path', 'cli_sha256', 'rpc_file', 'uid'}
                or node['node_id'] != ids[alias]):
            raise ValueError('transport owner differs from declared treasury node')
        integer(node['uid'], 'owned CLN socket uid')
        _hex(node['cli_sha256']); _file(node['cli_path']); _file(node['rpc_file'])
    return context


class LocalClnRpc:
    """Fixed local lightning-cli reads only; no shell, sudo or caller method args."""
    def __init__(self, context):
        self.context = context
        self.sockets = {}

    async def __call__(self, alias, method):
        if alias not in ALIASES or method not in METHODS:
            raise ValueError('fixed owned CLN read method required')
        node = self.context['nodes'][alias]
        executable = _file(node['cli_path']); socket = _file(node['rpc_file'])
        info = executable.stat(); sock = socket.stat()
        if (not stat.S_ISREG(info.st_mode) or info.st_size > 64*1024*1024 or info.st_mode & 0o022
                or hashlib.sha256(executable.read_bytes()).hexdigest() != node['cli_sha256']
                or not stat.S_ISSOCK(sock.st_mode) or sock.st_uid != node['uid']):
            raise ValueError('actual owned CLN executable/socket differs')
        identity = (sock.st_dev, sock.st_ino, sock.st_uid)
        if self.sockets.setdefault(alias, identity) != identity:
            raise ValueError('owned CLN socket replaced during collection')
        # Existing subprocess helper bounds bytes/time and kills/reaps its own
        # session on timeout/cancellation; never install a raw stderr callback.
        return await json_command([str(executable), '--network=signet',
                                   '--rpc-file='+str(socket), method], timeout=8)


def _tip(value):
    if (not isinstance(value, dict) or value.get('genesis') != SIGNET_GENESIS
            or value.get('initialblockdownload') is not False):
        raise ValueError('independent synchronized official Signet chain required')
    integer(value.get('height'), 'independent height'); _hex(value.get('tip_hash'))
    return value['height'], value['tip_hash']


def _node(raw, alias, node_ids, height):
    if not isinstance(raw, dict) or set(raw) != set(METHODS):
        raise ValueError('all three original CLN method replies required')
    public_payload(raw)
    if len(canonical(raw).encode()) > MAX_BYTES:
        raise ValueError('CLN source exceeds whole-node byte bound')
    info, funds, peers = (raw[m] for m in METHODS)
    if not all(isinstance(v, dict) for v in (info, funds, peers)):
        raise ValueError('original native CLN objects required')
    if (info.get('id') != node_ids[alias] or info.get('network') != 'signet'
            or type(info.get('blockheight')) is not int or info['blockheight'] != height
            or info.get('warning_bitcoind_sync') or info.get('warning_lightningd_sync')):
        raise ValueError('actual CLN owner/network/synchronized height differs')
    rows = [funds.get('outputs'), funds.get('channels'), peers.get('channels')]
    if any(not isinstance(v, list) for v in rows) or sum(map(len, rows)) > MAX_ROWS:
        raise ValueError('complete bounded native CLN row arrays required')
    if any(not isinstance(row, dict) for group in rows for row in group):
        raise ValueError('native CLN row objects required')
    other = node_ids['fixture_peer' if alias == 'operator' else 'operator']
    points = set()
    for row in funds['outputs']:
        point = (_hex(row.get('txid')), integer(row.get('output'), 'output index'))
        if point in points: raise ValueError('duplicate native CLN wallet output')
        points.add(point); _msat(row.get('amount_msat'))
        if row.get('status') not in {'confirmed', 'unconfirmed', 'spent'}:
            raise ValueError('unknown native CLN output state')
        if row['status'] == 'confirmed':
            if not 1 <= integer(row.get('blockheight'), 'output blockheight') <= height:
                raise ValueError('invalid native CLN confirmation height')
    channels = set()
    for row in peers['channels']:
        if row.get('peer_id') != other:
            raise ValueError('channel counterparty outside declared two-node boundary')
        for field in ('total_msat', 'to_us_msat', 'spendable_msat', 'receivable_msat'):
            if field in row: _msat(row[field])
        if row.get('state') == 'CHANNELD_NORMAL':
            identity = (_hex(row.get('channel_id')), _hex(row.get('funding_txid')),
                        integer(row.get('funding_outnum'), 'funding output'))
            if identity in channels: raise ValueError('duplicate native CLN channel')
            channels.add(identity)
            total = _msat(row.get('total_msat')); owned = _msat(row.get('to_us_msat'))
            if owned > total or any(_msat(row.get(k)) > total for k in ('spendable_msat', 'receivable_msat')):
                raise ValueError('native channel liquidity exceeds capacity')
    for row in funds['channels']:
        if row.get('peer_id') != other:
            raise ValueError('listfunds channel counterparty differs')
        for field in ('amount_msat', 'our_amount_msat'):
            if field in row: _msat(row[field])
    return {'node_id': info['id'], 'network': 'signet', 'blockheight': height,
            'unspent_outputs': [own_output(row) for row in funds['outputs'] if row['status'] != 'spent'],
            'channels': [peer_channel(row) for row in peers['channels']], 'fully_synced': True}


def verify_source(source, *, context_sha256, node_ids, height, tip_hash, now=None):
    """Replay original public frames at consumption; no ready boolean accepted."""
    ids = _ids(node_ids); now = time.time() if now is None else now
    if (not isinstance(source, dict) or set(source) != {'schema_version', 'genesis', 'network',
            'context_sha256', 'node_ids', 'height', 'tip_hash', 'started_at', 'completed_at', 'nodes'}
            or type(source['schema_version']) is not int or source['schema_version'] != 1
            or source['genesis'] != SIGNET_GENESIS or source['network'] != 'signet'
            or source['context_sha256'] != _hex(context_sha256) or source['node_ids'] != ids
            or source['height'] != integer(height, 'expected height') or source['tip_hash'] != _hex(tip_hash)
            or type(source['height']) is not int or not isinstance(source['nodes'], dict) or set(source['nodes']) != ALIASES):
        raise ValueError('original owned CLN source context/chain differs')
    start = timestamp(source['started_at'], 'source start'); end = timestamp(source['completed_at'], 'source end')
    if not start <= end <= timestamp(now, 'consumer time') or end-start > 20 or now-start > 90:
        raise ValueError('original CLN source stale/outside whole-call allowance')
    return {alias: _node(source['nodes'][alias], alias, ids, height) for alias in sorted(ALIASES)}


class OwnedClnReader:
    def __init__(self, rpc, chain, *, context_sha256, node_ids, clock=time.time):
        self.rpc, self.chain, self.clock = rpc, chain, clock
        self.context_sha256, self.node_ids = _hex(context_sha256), _ids(node_ids)

    async def collect(self):
        async with asyncio.timeout(20):
            started = self.clock(); before = _tip(await self.chain())
            async def node(alias):
                return {method: await self.rpc(alias, method) for method in METHODS}
            frames = await asyncio.gather(*(node(alias) for alias in sorted(ALIASES)))
            after = _tip(await self.chain())
            if before != after: raise ValueError('independent chain changed during CLN source')
            source = {'schema_version': 1, 'genesis': SIGNET_GENESIS, 'network': 'signet',
                      'context_sha256': self.context_sha256, 'node_ids': self.node_ids,
                      'height': before[0], 'tip_hash': before[1], 'started_at': started,
                      'completed_at': self.clock(), 'nodes': dict(zip(sorted(ALIASES), frames))}
            verify_source(source, context_sha256=self.context_sha256, node_ids=self.node_ids,
                          height=before[0], tip_hash=before[1], now=self.clock())
            return source

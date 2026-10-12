"""Seed-only payout recovery, separately booked and never replayed after broadcast.

Only confirmed, amount-checked payouts to permanently absent clients qualify.
The adapter scans BIP84 from genesis with gap 20 in a separate recovery working
directory; frozen outpoints constrain signing after discovery, never guide the
scan. Private backups must be explicitly declared outside original wallets.

Preparation runs in background. An orphaned preparation or unknown broadcast
is held for reconciliation. Neither state authorizes a newly generated spend.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import signal
import stat
import time
import urllib.request
from decimal import Decimal
from pathlib import Path

from .model import InvariantError, SIGNET_GENESIS, btc_to_sat, canonical, integer, public_payload
from .process import CommandError, decode_object, MAX_RESPONSE_BYTES

SCHEMA = '''
CREATE TABLE IF NOT EXISTS seed_recovery(id TEXT PRIMARY KEY, actor TEXT NOT NULL REFERENCES actor(id),
 state TEXT NOT NULL, intent TEXT NOT NULL, txid TEXT, raw_tx TEXT, fee_sat INTEGER,
 prepared TEXT, updated_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS seed_recovery_input(outpoint TEXT PRIMARY KEY,
 recovery_id TEXT NOT NULL REFERENCES seed_recovery(id));
CREATE TABLE IF NOT EXISTS recovered_capital(recovery_id TEXT PRIMARY KEY REFERENCES seed_recovery(id),
 actor TEXT NOT NULL, txid TEXT NOT NULL UNIQUE, gross_sat INTEGER NOT NULL,
 fee_sat INTEGER NOT NULL, recovered_sat INTEGER NOT NULL);
'''


def declared_seeds(values, wallet_root):
    if not isinstance(values, dict) or len(values) > 99:
        raise ValueError('declare recovery backups per actor')
    result = []
    for actor, value in sorted(values.items()):
        path = Path(value).expanduser() if isinstance(value, str) else None
        if (re.fullmatch(r'actor-\d{2}', actor) is None or path is None
                or not path.is_absolute() or '..' in path.parts or '://' in value
                or path.is_relative_to(Path(wallet_root).absolute())):
            raise ValueError('private recovery backups must be declared outside original wallets')
        result.append((actor, path))
    if len({str(p) for _, p in result}) != len(result):
        raise ValueError('recovery actors cannot share a private seed source')
    return tuple(result)


class RecoveryRpc:
    def __init__(self, config):
        command = config.recovery_command
        if len(command) != 3 or re.fullmatch(r'http://127\.0\.0\.1:\d+', command[1]) is None:
            raise ValueError('seed recovery requires a pinned adapter and independent loopback Core')
        if re.fullmatch(r'[A-Za-z0-9_-]{1,100}', config.funding_wallet) is None:
            raise ValueError('declare simulator funding wallet for recovery destination')
        self.url, self.credential, self.wallet = command[1], Path(command[2]), config.funding_wallet

    def call(self, method, *params):
        if method not in {'getblockhash', 'getblockchaininfo', 'getaddressinfo', 'gettxout',
                          'getrawtransaction', 'decoderawtransaction', 'sendrawtransaction'}:
            raise ValueError('unsupported recovery RPC')
        token = base64.b64encode(self.credential.read_text().strip().encode()).decode()
        url = self.url + ('/wallet/' + self.wallet if method == 'getaddressinfo' else '')
        request = urllib.request.Request(url, json.dumps({'jsonrpc': '2.0', 'id': 1,
            'method': method, 'params': params}).encode(),
            {'Authorization': 'Basic ' + token, 'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=12) as stream:
            response = json.load(stream, parse_float=Decimal)
        if response.get('error'): raise ValueError('recovery Core evidence unavailable')
        return response['result']


def _private_seed(path, wallet_root):
    # Config paths are checked again when a task starts; never resolve/follow an
    # alias into an original wallet or read a server/actor database as a backup.
    declared_seeds({'actor-01': str(path)}, wallet_root)
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            following = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor); descriptor = following
        following = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        with os.fdopen(following, 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                    or metadata.st_mode & 0o077 or metadata.st_size > 4096):
                raise ValueError('private seed backup has unsafe ownership, permissions or size')
            raw = stream.read(4097)
        phrase = raw.decode().strip()
        if len(raw) > 4096 or len(phrase.split()) not in {12, 24}:
            raise ValueError('private recovery backup is not a supported mnemonic')
        return phrase
    finally:
        os.close(descriptor)


async def prepare(config, actor, directory, outpoints):
    """Private stdin is intentionally separate from public JSON driver logging."""
    seed_path = dict(config.recovery_seeds)[actor]
    phrase = _private_seed(seed_path, config.wallet_root)
    private_input = canonical({'mnemonic': phrase, 'authorized_outpoints': outpoints}).encode()
    del phrase
    process = await asyncio.create_subprocess_exec(*config.recovery_command,
        config.recovery_destination, str(config.recovery_fee_rate_sat_vb),
        str(config.recovery_maximum_fee_sat), '--prepare-only', cwd=directory,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL, start_new_session=True)

    async def exchange():
        process.stdin.write(private_input); await process.stdin.drain(); process.stdin.close()
        output = bytearray()
        while True:
            chunk = await process.stdout.read(65536)
            if not chunk: break
            output.extend(chunk)
            if len(output) > MAX_RESPONSE_BYTES: raise CommandError('recovery output exceeds bound')
        await process.wait()
        if process.returncode: raise CommandError('seed recovery preparation failed')
        result = decode_object(output.decode())
        public_payload(result)
        return result
    try:
        return await asyncio.wait_for(exchange(), config.recovery_timeout_seconds)
    finally:
        if process.returncode is None:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            await process.wait()


def _directory(config, actor, identity):
    root = config.wallet_root / 'recovery' / actor / identity
    # Refuse aliases before creating any recovery directory. Original actor
    # directories are neither entered nor inspected.
    for parent in (root, *root.parents):
        if parent.is_symlink(): raise ValueError('unsafe recovery working directory')
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    return root


class RecoveryController:
    def __init__(self, store, config, *, rpc=None, prepare=prepare):
        permitted = {'signet': SIGNET_GENESIS, 'regtest': '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206'}
        if config.network not in permitted or config.expected_genesis != permitted[config.network]:
            raise ValueError('seed recovery permits only pinned official signet or isolated regtest')
        integer(config.recovery_maximum_fee_sat, 'seed recovery fee ceiling', 1)
        if config.recovery_maximum_fee_sat > min(2000, config.action_fee_reserve_sat):
            raise ValueError('seed recovery cap exceeds declared action reservation or 2000 sats')
        integer(config.recovery_fee_rate_sat_vb, 'seed recovery fee rate', 1)
        integer(config.recovery_timeout_seconds, 'seed recovery preparation timeout', 1)
        self.store, self.config, self.rpc, self.prepare = store, config, rpc or RecoveryRpc(config), prepare
        self.jobs = {}
        store.db.executescript(SCHEMA)

    async def close(self):
        jobs = list(self.jobs.values())
        for task in jobs: task.cancel()
        if jobs: await asyncio.gather(*jobs, return_exceptions=True)
        self.jobs.clear()

    def _destination(self):
        if self.rpc.call('getblockhash', 0) != self.config.expected_genesis:
            raise InvariantError('seed recovery chain differs from declared genesis')
        if self.rpc.call('getblockchaininfo').get('initialblockdownload') is not False:
            return None
        owned = self.rpc.call('getaddressinfo', self.config.recovery_destination)
        if owned.get('ismine') is not True or not isinstance(owned.get('scriptPubKey'), str):
            return None
        declaration = {'destination': self.config.recovery_destination, 'script': owned['scriptPubKey'],
            'funding_wallet': self.config.funding_wallet, 'genesis': self.config.expected_genesis,
            'network': self.config.network, 'maximum_fee_sat': self.config.recovery_maximum_fee_sat,
            'fee_rate_sat_vb': self.config.recovery_fee_rate_sat_vb,
            'seed_sources': {actor: hashlib.sha256(str(path).encode()).hexdigest()
                             for actor, path in self.config.recovery_seeds},
            'classification': 'seed-recovered payout capital; no recycling or traffic credit'}
        encoded = canonical(declaration); previous = self.store.get_meta('seed_recovery_declaration')
        if previous is not None and previous != encoded:
            raise InvariantError('seed recovery declaration changed')
        if previous is None:
            with self.store.transaction():
                self.store.db.execute("INSERT INTO meta VALUES ('seed_recovery_declaration',?)", (encoded,))
                self.store._event('seed_recovery_declared', declaration)
        return declaration

    def _sources(self, actor):
        sources = {}
        rows = self.store.db.execute("""SELECT c.* FROM checked_settlement c
            JOIN settlement_check s ON s.txid=c.txid WHERE c.actor=? AND s.state='amounts_checked'
            ORDER BY c.txid,c.script""", (actor,)).fetchall()
        for row in rows:
            cached = self.store.db.execute('SELECT payload FROM chain_payout WHERE txid=?', (row['txid'],)).fetchone()
            if cached is None: continue
            candidates = [o for o in json.loads(cached[0])['outputs'] if o['script'] == row['script']]
            if len(candidates) != 1: raise InvariantError('checked payout output is ambiguous')
            output = candidates[0]; outpoint = row['txid'] + ':' + str(output['vout'])
            if self.store.db.execute('SELECT 1 FROM seed_recovery_input WHERE outpoint=?', (outpoint,)).fetchone(): continue
            tx = self.rpc.call('getrawtransaction', row['txid'], True)
            if tx['txid'] != row['txid'] or tx.get('confirmations', 0) < 1: continue
            found = [o for o in tx['vout'] if o['n'] == output['vout']]
            if (len(found) != 1 or found[0]['scriptPubKey']['hex'] != row['script']
                    or btc_to_sat(found[0]['value']) != output['amount_sat']):
                raise InvariantError('confirmed recovery payout differs from amount-checked evidence')
            unspent = self.rpc.call('gettxout', row['txid'], output['vout'], True)
            if not unspent or unspent.get('confirmations', 0) < 1: continue
            if unspent['scriptPubKey']['hex'] != row['script'] or btc_to_sat(unspent['value']) != output['amount_sat']:
                raise InvariantError('seed recovery UTXO changed')
            sources[outpoint] = {'outpoint': outpoint, 'script': row['script'], 'amount_sat': output['amount_sat']}
        return [sources[key] for key in sorted(sources)][:16]

    def _validated_transaction(self, row, tx):
        intent = json.loads(row['intent']); expected = {s['outpoint']: s for s in intent['sources']}
        if tx['txid'] != row['txid']:
            raise InvariantError('recovery transaction identity changed')
        inputs = [i['txid'] + ':' + str(i['vout']) for i in tx['vin']]
        if len(inputs) != len(set(inputs)) or set(inputs) != set(expected):
            raise InvariantError('recovery spend differs from its frozen payout inputs')
        outputs = tx['vout']
        if len(outputs) != 1 or outputs[0]['scriptPubKey']['hex'] != intent['destination_script']:
            raise InvariantError('recovery pays a different destination')
        net = btc_to_sat(outputs[0]['value']); gross = sum(s['amount_sat'] for s in expected.values())
        fee = gross - net
        if net <= 0 or fee < 0 or fee > intent['maximum_fee_sat']:
            raise InvariantError('recovery mining fee does not conserve frozen principal within cap')
        return gross, fee, net

    def _freeze_prepared(self, row, result):
        public_payload(result)
        allowed = {'network', 'standard', 'lookahead', 'start_height', 'prepared_only', 'broadcast',
                   'spend_txid', 'raw_tx', 'fee_sat', 'inputs', 'outputs', 'tip', 'confirmation_verified'}
        if not isinstance(result, dict) or set(result) - allowed:
            raise InvariantError('native recovery returned unsupported public fields')
        integer(result.get('fee_sat'), 'native recovery mining fee')
        intent = json.loads(row['intent']); sources = intent['sources']
        if (result.get('network') != self.config.network or result.get('standard') != 'BIP84'
                or result.get('lookahead') != 20 or result.get('start_height') != 0
                or result.get('prepared_only') is not True or result.get('broadcast') is not False):
            raise InvariantError('native seed recovery did not prove a seed-only preparation')
        native = result.get('inputs', [])
        for item in native:
            if set(item) != {'outpoint', 'amount_sat', 'keychain', 'index'} or item['keychain'] not in {'External', 'Internal'}:
                raise InvariantError('native recovery input is not public BIP84 derivation evidence')
            integer(item['amount_sat'], 'native recovery input value', 1)
            integer(item['index'], 'native recovery derivation index')
        if (len(native) != len(sources) or sorted((i['outpoint'], i['amount_sat']) for i in native)
                != sorted((s['outpoint'], s['amount_sat']) for s in sources)):
            raise InvariantError('native seed recovery found different payout inputs')
        raw = result.get('raw_tx'); txid = result.get('spend_txid')
        if (not isinstance(raw, str) or re.fullmatch(r'(?:[0-9a-f]{2})+', raw) is None
                or not isinstance(txid, str) or re.fullmatch('[0-9a-f]{64}', txid) is None):
            raise InvariantError('native seed recovery omitted a signed public transaction')
        candidate = {**dict(row), 'txid': txid}
        tx = self.rpc.call('decoderawtransaction', raw)
        gross, fee, net = self._validated_transaction(candidate, tx)
        if fee != result.get('fee_sat'):
            raise InvariantError('native recovery fee differs from exact transaction')
        with self.store.transaction():
            self.store.db.execute("UPDATE seed_recovery SET state='prepared',txid=?,raw_tx=?,fee_sat=?,prepared=?,updated_at=? WHERE id=?",
                (txid, raw, fee, canonical(result), time.time(), row['id']))
            self.store._event('seed_recovery_prepared', {'recovery_id': row['id'], 'action_id': row['id'], 'actor': row['actor'],
                'txid': txid, 'raw_tx': raw, 'gross_sat': gross, 'fee_sat': fee, 'net_sat': net,
                'recycling_credit_sat': 0, 'traffic_credit_seconds': 0})

    def _broadcast(self, row):
        intent = json.loads(row['intent'])
        for source in intent['sources']:
            txid, index = source['outpoint'].split(':')
            unspent = self.rpc.call('gettxout', txid, int(index), True)
            if (not unspent or unspent.get('confirmations', 0) < 1
                    or btc_to_sat(unspent['value']) != source['amount_sat']
                    or unspent['scriptPubKey']['hex'] != source['script']):
                self._held(row, 'frozen payout input is unavailable'); return
        with self.store.transaction():
            self.store.db.execute("UPDATE seed_recovery SET state='broadcasting',updated_at=? WHERE id=?", (time.time(), row['id']))
            self.store.db.execute("UPDATE action SET state='dispatched',updated_at=? WHERE id=?", (time.time(), row['id']))
            self.store._event('seed_recovery_broadcast_intent', {'recovery_id': row['id'], 'action_id': row['id'], 'txid': row['txid']})
        try:
            actual = self.rpc.call('sendrawtransaction', row['raw_tx'])
            if actual != row['txid']: raise InvariantError('recovery broadcast returned a different transaction')
            state = 'broadcast'
        except Exception:
            state = 'outcome_unknown'
        with self.store.transaction():
            self.store.db.execute('UPDATE seed_recovery SET state=?,updated_at=? WHERE id=?', (state, time.time(), row['id']))
            if state == 'outcome_unknown': self.store.db.execute("UPDATE action SET state='outcome_unknown' WHERE id=?", (row['id'],))
            self.store._event('seed_recovery_spend', {'recovery_id': row['id'], 'action_id': row['id'], 'actor': row['actor'],
                'txid': row['txid'], 'state': state, 'retry_allowed': False})

    def _reconcile(self, row):
        try: tx = self.rpc.call('getrawtransaction', row['txid'], True)
        except Exception: return
        gross, fee, net = self._validated_transaction(row, tx)
        if fee != row['fee_sat']: raise InvariantError('confirmed recovery fee changed')
        if tx.get('confirmations', 0) < 1: return
        with self.store.transaction():
            self.store.db.execute("UPDATE seed_recovery SET state='confirmed',updated_at=? WHERE id=?", (time.time(), row['id']))
            self.store.db.execute('INSERT INTO recovered_capital VALUES (?,?,?,?,?,?)', (row['id'], row['actor'], row['txid'], gross, fee, net))
            self.store.db.execute("UPDATE action SET state='completed',actual_fee_sat=?,result=?,updated_at=? WHERE id=?",
                (fee, canonical({'data': {'seed_recovery_confirmed': True, 'txid': row['txid'],
                    'recovered_sat': net, 'fee_sat': fee, 'customer_traffic': False}}), time.time(), row['id']))
            self.store._event('seed_recovery_confirmed', {'recovery_id': row['id'], 'action_id': row['id'], 'actor': row['actor'],
                'txid': row['txid'], 'gross_sat': gross, 'fee_sat': fee, 'recovered_sat': net,
                'recycling_credit_sat': 0, 'traffic_credit_seconds': 0,
                'original_wallet_opened': False, 'classification': 'separate recovered capital bucket'})

    def _held(self, row, reason, state='held'):
        with self.store.transaction():
            self.store.db.execute('UPDATE seed_recovery SET state=?,updated_at=? WHERE id=?', (state, time.time(), row['id']))
            self.store._event('seed_recovery_held', {'recovery_id': row['id'], 'action_id': row['id'], 'reason': reason,
                'state': state, 'retry_allowed': False, 'original_wallet_opened': False})

    async def tick(self):
        if not self.config.active: return
        declaration = self._destination()
        for row in self.store.db.execute('SELECT * FROM seed_recovery ORDER BY updated_at,id').fetchall():
            if row['state'] in {'broadcast', 'broadcasting', 'outcome_unknown'}:
                self._reconcile(row)
            elif row['state'] == 'preparing':
                task = self.jobs.get(row['id'])
                if task is None:
                    self._held(row, 'preparation handle missing; reconcile before signing again', 'prepare_unknown')
                elif task.done():
                    del self.jobs[row['id']]
                    try: self._freeze_prepared(row, task.result())
                    except Exception as error: self._held(row, type(error).__name__)
            elif row['state'] == 'prepared' and declaration and not self.store.get_meta('paused'):
                self._broadcast(row)
        if not declaration or self.store.get_meta('paused'): return
        for actor, _ in self.config.recovery_seeds:
            if len(self.jobs) >= 2: break
            row = self.store.db.execute('SELECT online,details FROM actor WHERE id=?', (actor,)).fetchone()
            if row is None or row['online']: continue
            if actor not in {'actor-03', 'actor-09', 'actor-10'} and not json.loads(row['details']).get('permanent_absence'): continue
            if self.store.db.execute("SELECT 1 FROM action WHERE actor_id=? AND state IN ('dispatched','outcome_unknown')", (actor,)).fetchone(): continue
            if self.store.db.execute("SELECT 1 FROM seed_recovery WHERE actor=? AND state!='confirmed'", (actor,)).fetchone(): continue
            if self.store.remaining_fee_budget() < self.config.recovery_maximum_fee_sat: continue
            sources = self._sources(actor)
            if not sources: continue
            intent = {'actor': actor, 'sources': sources, 'destination': declaration['destination'],
                'destination_script': declaration['script'], 'maximum_fee_sat': declaration['maximum_fee_sat'],
                'seed_source_id': declaration['seed_sources'][actor], 'standard': 'BIP84', 'lookahead': 20,
                'start_height': 0, 'recycling_credit_sat': 0, 'traffic_credit_seconds': 0}
            identity = 'seed-recovery-' + hashlib.sha256(canonical(intent).encode()).hexdigest()
            directory = _directory(self.config, actor, identity)
            with self.store.transaction():
                self.store.queue(identity, actor, 'H26', 'seed_recovery', intent, self.config.recovery_maximum_fee_sat)
                self.store.db.execute("INSERT INTO seed_recovery VALUES (?,?,'preparing',?,NULL,NULL,NULL,NULL,?)",
                    (identity, actor, canonical(intent), time.time()))
                for source in sources: self.store.db.execute('INSERT INTO seed_recovery_input VALUES (?,?)', (source['outpoint'], identity))
                self.store._event('seed_recovery_intent', {'recovery_id': identity, 'action_id': identity, **intent,
                    'original_wallet_opened': False, 'funding_dispatched': False})
            self.jobs[identity] = asyncio.create_task(self.prepare(self.config, actor, directory,
                                                        [s['outpoint'] for s in sources]))

"""Seed-recovery state machine using synthetic Core and signer evidence only."""
import asyncio
import json
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from simulator.engine import initialize
from simulator.model import SIGNET_GENESIS, InvariantError, canonical
from simulator.store import Store


class RecoveryRpc:
    def __init__(self):
        self.calls = []
        self.source = 'a' * 64
        self.txid = 'b' * 64
        self.source_script = '0014' + 'c' * 40
        self.destination_script = '5120' + 'd' * 64
        self.fee = 330
        self.broadcast = False
        self.confirmations = 0
        self.source_unspent = True
        self.owned_destination = True
        self.timeout = False
        self.wrong_input = False
        self.wrong_destination = False
        self.before_broadcast = None

    def tx(self):
        return {'txid': self.txid, 'confirmations': self.confirmations,
            'vin': [{'txid': ('f' * 64 if self.wrong_input else self.source), 'vout': 0}],
            'vout': [{'n': 0, 'value': Decimal(4661 - self.fee) / 100000000,
                'scriptPubKey': {'hex': ('5120' + 'e' * 64 if self.wrong_destination else self.destination_script)}}]}

    def call(self, method, *args, **kwargs):
        self.calls.append((method, args))
        if method == 'getblockhash': return SIGNET_GENESIS
        if method == 'getblockchaininfo': return {'initialblockdownload': False}
        if method == 'getaddressinfo': return {'ismine': self.owned_destination, 'scriptPubKey': self.destination_script}
        if method == 'gettxout':
            if not self.source_unspent: return None
            return {'confirmations': 10, 'value': Decimal('0.00004661'), 'scriptPubKey': {'hex': self.source_script}}
        if method == 'getrawtransaction':
            if args[0] == self.source:
                return {'txid': self.source, 'confirmations': 10,
                    'vout': [{'n': 0, 'value': Decimal('0.00004661'), 'scriptPubKey': {'hex': self.source_script}}]}
            if not self.broadcast: raise ValueError('not observed')
            return self.tx()
        if method == 'decoderawtransaction': return self.tx()
        if method == 'sendrawtransaction':
            if self.before_broadcast: self.before_broadcast()
            self.broadcast = True
            if self.timeout: raise TimeoutError('accepted; reply lost')
            return self.txid
        raise AssertionError(method)


class RecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = Store(self.root / 'state', 'synthetic', 10000)
        initialize(self.store)
        self.rpc = RecoveryRpc()
        self.config = SimpleNamespace(active=True, recovery_command=('seed-restore', 'rpc', 'private-auth'),
            recovery_destination='tb1p-declared-funding-address', recovery_seeds=(('actor-09', self.root / 'backup.seed'),),
            recovery_maximum_fee_sat=2000, recovery_fee_rate_sat_vb=3, recovery_timeout_seconds=86400,
            wallet_root=self.root / 'original-wallets', funding_wallet='campaign-funding',
            expected_genesis=SIGNET_GENESIS, network='signet', action_fee_reserve_sat=2000)
        self.store.set_online('actor-09', False)
        self.store.db.execute('UPDATE actor SET details=? WHERE id=?',
            (canonical({'permanent_absence': {'rail': 'ark'}}), 'actor-09'))
        row = {'id': 'coin-09', 'txid': self.rpc.source, 'actor': 'actor-09',
            'script': self.rpc.source_script, 'amount_sat': 5000, 'evidence': '{}'}
        self.store.db.execute('INSERT INTO checked_settlement VALUES (?,?,?,?,?,?)', tuple(row.values()))
        self.store.db.execute('INSERT INTO settlement_check VALUES (?,?,NULL,0)', (self.rpc.source, 'amounts_checked'))
        cached = {'txid': self.rpc.source, 'confirmations': 10, 'outputs': [
            {'vout': 0, 'script': self.rpc.source_script, 'amount_sat': 4661}]}
        self.store.db.execute('INSERT INTO chain_payout VALUES (?,?)', (self.rpc.source, canonical(cached)))
        self.prepared = {'network': 'signet', 'standard': 'BIP84', 'lookahead': 20,
            'start_height': 0, 'prepared_only': True, 'broadcast': False,
            'spend_txid': self.rpc.txid, 'raw_tx': 'cafe', 'fee_sat': 330,
            'inputs': [{'outpoint': self.rpc.source + ':0', 'amount_sat': 4661,
                        'keychain': 'External', 'index': 0}],
            'outputs': [{'script': self.rpc.destination_script, 'amount_sat': 4331}]}
        self.prepare = AsyncMock(return_value=self.prepared)
        self.controller = None

    async def asyncTearDown(self):
        if self.controller is not None: await self.controller.close()
        self.store.close(); self.temp.cleanup()

    def controller_for(self):
        from simulator.recovery import RecoveryController
        self.controller = RecoveryController(self.store, self.config, rpc=self.rpc, prepare=self.prepare)
        return self.controller

    async def drive(self, ticks=4):
        controller = self.controller or self.controller_for()
        for _ in range(ticks):
            await controller.tick()
            await asyncio.sleep(0)

    def recoveries(self):
        return self.store.db.execute('SELECT * FROM seed_recovery').fetchall()

    def sends(self):
        return sum(method == 'sendrawtransaction' for method, _ in self.rpc.calls)

    async def test_verified_absent_payout_is_prepared_in_separate_directory_and_booked_on_confirmation(self):
        self.controller_for()
        await self.drive()
        self.assertEqual(1, self.prepare.await_count)
        args = self.prepare.call_args.args
        self.assertTrue(Path(args[2]).is_relative_to(self.config.wallet_root / 'recovery' / 'actor-09'))
        self.assertEqual([self.rpc.source + ':0'], args[3])
        self.assertEqual(1, self.sends())
        self.assertEqual(0, self.store.db.execute('SELECT COUNT(*) FROM recovered_capital').fetchone()[0])
        self.rpc.confirmations = 1
        await self.drive(2)
        row = self.store.db.execute('SELECT * FROM recovered_capital').fetchone()
        self.assertEqual((4661, 330, 4331), (row['gross_sat'], row['fee_sat'], row['recovered_sat']))
        self.assertFalse(self.store.online('actor-09'))
        self.assertEqual(0, self.store.db.execute("SELECT COUNT(*) FROM event WHERE kind IN ('recycle_confirmed','ark_transfer_verified','driver_request')").fetchone()[0])
        self.assertEqual(1, self.store.db.execute("SELECT COUNT(*) FROM event WHERE kind='seed_recovery_confirmed'").fetchone()[0])
        self.assertEqual(9670, self.store.remaining_fee_budget())
        self.store.verify_event_chain()

    async def test_intent_and_exact_signed_transaction_are_durable_before_broadcast(self):
        self.controller_for()
        def before():
            row = self.recoveries()[0]
            self.assertEqual('broadcasting', row['state'])
            self.assertEqual('cafe', row['raw_tx'])
            self.assertEqual(self.rpc.txid, row['txid'])
            self.assertTrue(self.store.db.execute("SELECT 1 FROM event WHERE kind='seed_recovery_intent'").fetchone())
            self.assertTrue(self.store.db.execute("SELECT 1 FROM event WHERE kind='seed_recovery_prepared'").fetchone())
        self.rpc.before_broadcast = before
        await self.drive()
        self.assertEqual(1, self.sends())

    async def test_pending_verdict_online_actor_unknown_action_and_foreign_destination_hold_recovery(self):
        self.controller_for()
        self.store.db.execute("UPDATE settlement_check SET state='pending'")
        await self.drive(); self.assertEqual(0, self.prepare.await_count)
        self.store.db.execute("UPDATE settlement_check SET state='amounts_checked'")
        self.store.set_online('actor-09', True)
        await self.drive(); self.assertEqual(0, self.prepare.await_count)
        self.store.set_online('actor-09', False)
        self.store.queue('unknown', 'actor-09', 'H01', 'sync', {}, 0)
        self.store.db.execute("UPDATE action SET state='outcome_unknown' WHERE id='unknown'")
        await self.drive(); self.assertEqual(0, self.prepare.await_count)
        self.store.db.execute("UPDATE action SET state='completed' WHERE id='unknown'")
        self.rpc.owned_destination = False
        await self.drive(); self.assertEqual(0, self.prepare.await_count)
        self.assertEqual(0, self.sends())

    async def test_lost_broadcast_reply_is_queried_and_never_signed_or_sent_twice(self):
        self.rpc.timeout = True; self.controller_for(); await self.drive(3)
        self.assertEqual('outcome_unknown', self.recoveries()[0]['state'])
        self.assertEqual(1, self.sends())
        await self.drive(4)
        self.assertEqual(1, self.prepare.await_count); self.assertEqual(1, self.sends())
        self.rpc.confirmations = 1; await self.drive(2)
        self.assertEqual('confirmed', self.recoveries()[0]['state'])
        self.assertEqual(1, self.sends())
        self.store.verify_event_chain()

    async def test_restart_reconciles_frozen_transaction_without_signing_or_funding(self):
        self.controller_for(); await self.drive()
        await self.controller.close()
        self.controller_for(); self.rpc.confirmations = 1; await self.drive(2)
        self.assertEqual(1, self.prepare.await_count); self.assertEqual(1, self.sends())
        self.assertEqual(1, self.store.db.execute('SELECT COUNT(*) FROM recovered_capital').fetchone()[0])

    async def test_wrong_input_destination_or_fee_never_broadcasts(self):
        self.rpc.wrong_input = True; self.controller_for(); await self.drive()
        self.assertEqual(0, self.sends())
        self.assertEqual('held', self.recoveries()[0]['state'])

    async def test_wrong_destination_and_fee_above_cap_are_held_without_broadcast(self):
        self.rpc.wrong_destination = True; self.controller_for(); await self.drive()
        self.assertEqual(0, self.sends())
        self.assertEqual('held', self.recoveries()[0]['state'])

    async def test_fee_above_native_and_campaign_cap_never_broadcasts(self):
        self.rpc.fee = 2001; self.prepared['fee_sat'] = 2001
        self.controller_for(); await self.drive()
        self.assertEqual(0, self.sends())
        self.assertEqual('held', self.recoveries()[0]['state'])

    async def test_unverified_extra_seed_utxo_cannot_be_spent_with_verified_payout(self):
        self.prepared['inputs'].append({'outpoint': 'f' * 64 + ':0', 'amount_sat': 8000,
                                       'keychain': 'External', 'index': 1})
        self.controller_for(); await self.drive()
        self.assertEqual(0, self.sends())
        self.assertEqual('held', self.recoveries()[0]['state'])

    async def test_secret_shaped_signer_output_is_held_without_journaling_seed(self):
        self.prepared['mnemonic'] = 'abandon ' * 12
        self.controller_for(); await self.drive()
        self.assertEqual(0, self.sends())
        events = ' '.join(r[0] for r in self.store.db.execute('SELECT payload FROM event'))
        self.assertNotIn('abandon', events)
        self.assertEqual('held', self.recoveries()[0]['state'])

    async def test_unvalidated_nested_signer_metadata_cannot_leak_private_values(self):
        self.prepared['outputs'][0]['comment'] = 'abandon ' * 12
        self.controller_for(); await self.drive()
        self.assertEqual(0, self.sends())
        self.assertIsNone(self.recoveries()[0]['prepared'])
        self.assertEqual('held', self.recoveries()[0]['state'])
        events = ' '.join(r[0] for r in self.store.db.execute('SELECT payload FROM event'))
        self.assertNotIn('abandon', events)

    async def test_native_broadcasting_reply_and_fee_above_cap_are_rejected(self):
        self.prepared['broadcast'] = True; self.controller_for(); await self.drive()
        self.assertEqual(0, self.sends())
        self.assertEqual('held', self.recoveries()[0]['state'])

    async def test_fee_cap_cannot_exceed_two_thousand_or_action_reservation(self):
        self.config.recovery_maximum_fee_sat = 2001
        with self.assertRaises(ValueError): self.controller_for()

    async def test_changed_destination_cannot_rewrite_frozen_declaration_or_transaction(self):
        self.controller_for(); await self.drive()
        await self.controller.close()
        self.config.recovery_destination = 'tb1p-other'
        self.controller_for()
        with self.assertRaises(InvariantError): await self.drive()
        self.assertEqual(1, self.sends())

    async def test_unavailable_payout_output_and_exhausted_budget_never_sign(self):
        self.rpc.source_unspent = False; self.controller_for(); await self.drive()
        self.assertEqual(0, self.prepare.await_count)
        self.rpc.source_unspent = True
        self.store.queue('reserved', 'actor-01', 'H01', 'board', {}, 9000)
        await self.drive(); self.assertEqual(0, self.prepare.await_count)

    async def test_long_seed_scan_is_polled_without_blocking_customer_ticks(self):
        future = asyncio.Future()
        async def blocked(*args): return await future
        self.prepare = AsyncMock(side_effect=blocked)
        self.controller_for()
        await asyncio.wait_for(self.controller.tick(), 1)
        await asyncio.sleep(0)
        await asyncio.wait_for(self.controller.tick(), 1)
        self.assertEqual('preparing', self.recoveries()[0]['state'])
        self.assertEqual(0, self.sends())
        future.set_result(self.prepared); await self.drive()
        self.assertEqual(1, self.sends())

    async def test_orphaned_prepare_is_held_and_never_automatically_restarted(self):
        future = asyncio.Future()
        async def blocked(*args): return await future
        self.prepare = AsyncMock(side_effect=blocked); self.controller_for()
        await self.drive(1); await self.controller.close()
        self.controller_for(); await self.drive(2)
        self.assertEqual('prepare_unknown', self.recoveries()[0]['state'])
        self.assertEqual(1, self.prepare.await_count); self.assertEqual(0, self.sends())


class RecoveryPrivacyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.wallets = self.root / 'original-wallets'; self.backup = self.root / 'backup.seed'
        self.backup.write_text('abandon ' * 12); self.backup.chmod(0o600)
    def tearDown(self): self.temp.cleanup()
    def test_private_backup_requires_owned_permissions_and_refuses_symlinks(self):
        from simulator.recovery import _private_seed
        self.assertEqual(12, len(_private_seed(self.backup, self.wallets).split()))
        self.backup.chmod(0o644)
        with self.assertRaises(ValueError): _private_seed(self.backup, self.wallets)
        self.backup.chmod(0o600)
        alias = self.root / 'alias.seed'; alias.symlink_to(self.backup)
        with self.assertRaises(OSError): _private_seed(alias, self.wallets)
    def test_original_wallet_and_relative_seed_paths_are_never_read(self):
        from simulator.recovery import declared_seeds
        for path in (self.wallets / 'actor-09' / 'mnemonic', Path('../backup.seed')):
            with self.assertRaises(ValueError): declared_seeds({'actor-09': str(path)}, self.wallets)
    def test_same_backup_cannot_be_declared_for_two_actor_identities(self):
        from simulator.recovery import declared_seeds
        with self.assertRaises(ValueError): declared_seeds({'actor-09': str(self.backup),
            'actor-10': str(self.backup)}, self.wallets)


class RecoveryConfigTests(unittest.TestCase):
    def setUp(self):
        import hashlib
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.path = self.root / 'config.toml'; self.native = self.root / 'seed-restore'
        self.native.write_bytes(b'synthetic adapter pin; never executed')
        self.pin = hashlib.sha256(self.native.read_bytes()).hexdigest()
        self.base = f'''[target]
network="signet"
genesis="{SIGNET_GENESIS}"
container="abandon-signet-fallback-test"
image_digest="sha256:{'a' * 64}"
server_pubkey="02{'b' * 64}"
[runtime]
state_dir="{self.root / 'state'}"
wallet_root="{self.root / 'original-wallets'}"
fee_budget_sat=10000
active=false
observer_command=[]
'''
        self.settings = {'command': [str(self.native), 'http://127.0.0.1:38332', str(self.root / 'private-core-auth')],
                         'maximum_fee_sat': 2000}
        self.seed = str(self.root / 'private-backup.seed')
    def tearDown(self): self.temp.cleanup()
    def write(self):
        text = self.base + '\n[funding]\nwallet="campaign-funding"\nrecovery_address="tb1p-declared"\n[recovery]\n'
        text += 'command=' + json.dumps(self.settings['command']) + '\n'
        text += 'maximum_fee_sat=' + str(self.settings['maximum_fee_sat']) + '\n'
        text += '[recovery.seeds]\nactor-09=' + json.dumps(self.seed) + '\n'
        text += '[executables]\n' + json.dumps(str(self.native)) + '=' + json.dumps(self.pin) + '\n'
        self.path.write_text(text)
    def test_private_backup_and_funding_destination_are_explicit_and_adapter_is_pinned(self):
        from simulator.config import Config
        self.write(); config = Config.load(self.path)
        self.assertEqual('tb1p-declared', config.recovery_destination)
        self.assertEqual((('actor-09', Path(self.seed)),), config.recovery_seeds)
        self.assertEqual(2000, config.recovery_maximum_fee_sat)
        self.assertEqual(tuple(self.settings['command']), config.recovery_command)
    def test_unsafe_backups_remote_core_and_large_fee_cap_are_rejected(self):
        from simulator.config import Config
        self.seed = str(self.root / 'original-wallets' / 'actor-09' / 'mnemonic')
        self.write()
        with self.assertRaises(ValueError): Config.load(self.path)
        self.seed = str(self.root / 'private-backup.seed'); self.settings['command'][1] = 'http://remote:38332'
        self.write()
        with self.assertRaises(ValueError): Config.load(self.path)
        self.settings['command'][1] = 'http://127.0.0.1:38332'; self.settings['maximum_fee_sat'] = 2001
        self.write()
        with self.assertRaises(ValueError): Config.load(self.path)
    def test_disabled_recovery_does_not_restrict_existing_small_action_reserve(self):
        from simulator.config import Config
        self.path.write_text(self.base + 'action_fee_reserve_sat=500\n')
        config = Config.load(self.path)
        self.assertEqual((), config.recovery_command)
        self.assertEqual(500, config.action_fee_reserve_sat)

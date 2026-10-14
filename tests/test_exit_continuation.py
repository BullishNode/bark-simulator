from tests import account_fixtures
"""Known exits retain one authorization across block-driven continuation."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from simulator import exits
from simulator.engine import initialize
from simulator.model import InvariantError, canonical
from simulator.store import Store


class ExitContinuationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.store = Store(root, 'synthetic', 10000); initialize(self.store)
        self.actor = 'actor-08'; self.coin_id = 'a' * 64 + ':0'
        key = '02' + '11' * 32
        binding = account_fixtures.binding({'mailbox_pk': 'mailbox', 'seq': 1, 'spk': 'owned', 'record_signature_valid': True, 'account_child_verified': True})
        self.store.db.execute('INSERT INTO owner_record VALUES (?,?,?,?,?)', (self.actor, 'mailbox', 'synthetic-account', 'owned', canonical(binding)))
        self.store.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)', (key, self.actor, 'mailbox', '{}'))
        proof = account_fixtures.proof({'id': self.coin_id, 'user_pubkey': key, 'amount_sat': 10000, 'signed_path_valid': True, 'anchor_confirmations': 1, 'binding': binding})
        self.store.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)', (self.coin_id, key, 10000, hashlib.sha256(bytes.fromhex('aa')).hexdigest(), 'aa', canonical(proof)))
        self.args = {'input_vtxo_ids': [self.coin_id], 'fee_rate_sat_per_vb': 1, 'fee_funding_outpoint': 'b' * 64 + ':0'}
        self.store.queue('original-exit', self.actor, 'H34', 'exit', self.args, 2000)
        self.assertIsNotNone(self.store.claim({'exit'}))
        self.store.finish('original-exit', 'outcome_unknown', {'reason': 'native exit initiated'})
        self.proposal = {'stage': 'start', 'input_vtxo_ids': [self.coin_id], 'signed_vtxos': ['aa'], 'fee_cap_sat': 2000,
            'fee_funding_outpoint': self.args['fee_funding_outpoint'], 'fee_rate_kwu': 250, 'no_automatic_fee_bumps': True}
        self.store.event('driver_evidence', {'action_id': 'original-exit', 'event': 'exit_proposal', 'data': self.proposal})
        self.config = SimpleNamespace(active=True, wallet_root=root / 'wallets', expected_server_pubkey='server', driver_command=('native',), proof_command=(), action_timeout_seconds=1)
        self.tip = {'initialblockdownload': False, 'blocks': 100, 'bestblockhash': 'c' * 64}
        self.chain = SimpleNamespace(identity=lambda: self.tip)
        self.native = AsyncMock(return_value={'action_id': 'original-exit', 'status': 'ok', 'actual_fee_sat': None, 'data': {'started': True}})

    def tearDown(self):
        self.store.close(); self.temp.cleanup()

    def original(self):
        return dict(self.store.db.execute("SELECT * FROM action WHERE id='original-exit'").fetchone())

    async def collect(self):
        with patch('simulator.exits.json_command', self.native):
            await exits.collect(self.store, self.config, self.chain)

    async def test_one_continuation_per_tip_keeps_original_action_budget_and_time(self):
        original = self.original()
        await self.collect(); await self.collect()
        self.assertEqual(1, self.native.await_count)
        request = self.native.call_args.args[1]
        self.assertEqual('original-exit', request['action_id'])
        self.assertEqual(2000, request['maximum_fee_sat'])
        self.assertEqual({**self.args, 'phase': 'advance'}, request['args'])
        self.assertEqual(original, self.original())
        self.tip = {**self.tip, 'blocks': 101, 'bestblockhash': 'd' * 64}
        await self.collect(); self.assertEqual(2, self.native.await_count)
        self.assertEqual(1, self.store.db.execute('SELECT COUNT(*) FROM action').fetchone()[0])
        self.assertTrue(self.store.verify_event_chain())

    async def test_lost_response_consumes_the_tip_attempt_without_retrying_start(self):
        original = self.original(); self.native.side_effect = TimeoutError
        await self.collect(); await self.collect()
        self.assertEqual(1, self.native.await_count)
        self.assertEqual(original, self.original())
        self.assertEqual(1, self.store.db.execute("SELECT COUNT(*) FROM event WHERE kind='exit_continuation_held'").fetchone()[0])

    async def test_absent_disabled_paused_and_missing_chain_do_not_open_wallet(self):
        self.store.set_online(self.actor, False); await self.collect()
        self.store.set_online(self.actor, True)
        self.store.db.execute('UPDATE actor SET details=? WHERE id=?', (canonical({'permanent_absence': {'trigger': 'receipt'}}), self.actor))
        await self.collect()
        self.store.db.execute('UPDATE actor SET details=? WHERE id=?', ('{}', self.actor))
        self.config.active = False; await self.collect(); self.config.active = True
        self.store.db.execute("INSERT INTO meta VALUES ('paused','incident')"); await self.collect()
        self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        await exits.collect(self.store, self.config, None)
        self.native.assert_not_called()

    async def test_missing_unique_start_or_checked_signed_inputs_retains_reservation(self):
        original = self.original()
        self.store.db.execute("DELETE FROM event WHERE kind='driver_evidence'"); await self.collect()
        self.store.event('driver_evidence', {'action_id': 'original-exit', 'event': 'exit_proposal', 'data': self.proposal})
        self.store.db.execute('DELETE FROM owned_coin'); await self.collect()
        self.native.assert_not_called(); self.assertEqual(original, self.original())

    async def test_changed_start_budget_or_signed_input_is_an_incident(self):
        for change in ({'fee_cap_sat': 2001}, {'signed_vtxos': ['bb']}):
            self.store.db.execute("DELETE FROM event WHERE kind='driver_evidence'")
            self.store.event('driver_evidence', {'action_id': 'original-exit', 'event': 'exit_proposal', 'data': {**self.proposal, **change}})
            with self.assertRaises(InvariantError): await self.collect()
        self.native.assert_not_called()

    async def test_incomplete_independent_tip_never_dispatches(self):
        for change in ({'initialblockdownload': True}, {'bestblockhash': None}, {'blocks': '100'}):
            self.tip = {'initialblockdownload': False, 'blocks': 100, 'bestblockhash': 'c' * 64, **change}
            await self.collect()
        self.native.assert_not_called()

    async def test_wrong_native_identity_is_an_incident_and_keeps_the_action(self):
        original = self.original()
        self.native.return_value = {'action_id': 'other', 'status': 'ok', 'actual_fee_sat': None}
        with self.assertRaises(InvariantError): await self.collect()
        self.assertEqual(original, self.original())

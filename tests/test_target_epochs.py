"""Same-campaign upgrade fencing with synthetic deployment receipts."""
import copy
import json
import tempfile
import time
import unittest
from pathlib import Path

from simulator.engine import initialize
from simulator.model import SIGNET_GENESIS, canonical
from simulator.store import Store


class TargetEpochTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name), 'synthetic', 10000)
        initialize(self.store)
        for actor in ('actor-03', 'actor-09', 'actor-10'):
            self.store.set_online(actor, False)
        self.old = dict(network='signet', genesis=SIGNET_GENESIS,
                        container='qualified-captaind', image_digest='sha256:'+'1'*64,
                        server_pubkey='02'+'2'*64)
        self.new = {**self.old, 'image_digest':'sha256:'+'3'*64}
        self.store.bind_target(self.old)
        self.store.bind_wallet_root(Path(self.temp.name)/'wallets')
        self.store.db.execute("INSERT INTO meta VALUES ('paused','declared target upgrade')")
        self.store.db.execute("INSERT INTO meta VALUES ('owner_renewal_declaration','original declaration')")
        self.store.event('failed_run_retained', {'outcome':'failed', 'fee_sat':0})

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def declaration(self):
        from simulator.target_epochs import declaration_hashes
        return dict(id='post-upgrade-1', previous_identity=self.old, identity=self.new,
                    observed_at=time.time(), sdk_commit='4'*40,
                    native_hashes={name:'5'*64 for name in ('bark-sim-driver','vtxo-proof','seed-restore')},
                    receipt_hashes={name:'6'*64 for name in ('upgrade_completion','independent_identity',
                        'sdk_qualification','simulator_release','nursery_reconciliation')},
                    ordinary_lifetime_blocks=48, pool_lifetime_blocks=48,
                    recovery_guard_verified=True, pending_server_payouts_preserved=True,
                    declaration_hashes=declaration_hashes(self.store))

    def declare(self, declaration=None):
        from simulator.target_epochs import declare
        return declare(self.store, declaration or self.declaration())

    def test_declared_upgrade_keeps_original_identity_declarations_history_and_wallet_root(self):
        before = [tuple(row) for row in self.store.db.execute('SELECT * FROM event ORDER BY sequence')]
        meta = [tuple(row) for row in self.store.db.execute('SELECT * FROM meta ORDER BY key')]
        self.declare()
        self.store.bind_target(self.new)
        self.assertEqual(before, [tuple(row) for row in self.store.db.execute('SELECT * FROM event ORDER BY sequence')][:len(before)])
        self.assertEqual(meta, [tuple(row) for row in self.store.db.execute('SELECT * FROM meta ORDER BY key')])
        self.assertEqual(canonical(self.old),self.store.get_meta('target_identity'))
        with self.assertRaises(ValueError): self.store.bind_target(self.old)

    def test_edited_config_cannot_select_new_deployment_without_declaration(self):
        with self.assertRaises(ValueError): self.store.bind_target(self.new)

    def test_same_id_is_idempotent_but_cannot_be_rewritten(self):
        value=self.declaration();self.declare(value)
        count=self.store.db.execute('SELECT COUNT(*) FROM event').fetchone()[0]
        self.declare(value)
        self.assertEqual(count,self.store.db.execute('SELECT COUNT(*) FROM event').fetchone()[0])
        value['sdk_commit']='7'*40
        with self.assertRaises(ValueError): self.declare(value)

    def test_unknown_or_dispatched_action_blocks_epoch(self):
        self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        self.store.queue('unknown','actor-01','H01','sync',{},1)
        self.store.db.execute("INSERT INTO meta VALUES ('paused','declared target upgrade')")
        for state in ('outcome_unknown','dispatched'):
            self.store.db.execute('UPDATE action SET state=?',(state,))
            with self.assertRaises(ValueError):self.declare()

    def test_seed_preparation_unknown_or_live_preparation_blocks_epoch(self):
        from simulator.recovery import SCHEMA
        self.store.db.executescript(SCHEMA)
        self.store.db.execute("INSERT INTO seed_recovery VALUES ('r','actor-03','prepare_unknown','{}',NULL,NULL,NULL,NULL,0)")
        for state in ('prepare_unknown','outcome_unknown','preparing','broadcasting'):
            self.store.db.execute('UPDATE seed_recovery SET state=?',(state,))
            with self.assertRaises(ValueError):self.declare()

    def test_changed_key_network_or_lifetime_cannot_be_declared(self):
        mutations=[('server_pubkey','02'+'8'*64),('genesis','9'*64),('network','mainnet'),('container','other-target')]
        for key,value in mutations:
            with self.subTest(key=key):
                declaration=self.declaration();declaration['identity'][key]=value
                with self.assertRaises(ValueError):self.declare(declaration)
        for key in ('ordinary_lifetime_blocks','pool_lifetime_blocks'):
            declaration=self.declaration();declaration[key]=24
            with self.assertRaises(ValueError):self.declare(declaration)

    def test_missing_receipt_stale_audit_guard_or_original_actor_online_blocks_epoch(self):
        mutations=[('receipt_hashes',{}),('observed_at',time.time()-601),('recovery_guard_verified',False),
                   ('pending_server_payouts_preserved',False),('declaration_hashes',{})]
        for key,value in mutations:
            with self.subTest(key=key):
                declaration=self.declaration();declaration[key]=value
                with self.assertRaises(ValueError):self.declare(declaration)
        self.store.set_online('actor-03',True)
        with self.assertRaises(ValueError):self.declare()

    def test_signed_pending_server_payout_is_retained_and_does_not_require_empty_nursery(self):
        self.store.db.execute('INSERT INTO payout VALUES (?,?,?,?)',('a'*64,13,5,canonical({'raw_tx':'cafe','confirmed':False})))
        self.declare()
        self.assertEqual(('a'*64,13,5,canonical({'raw_tx':'cafe','confirmed':False})),
                         tuple(self.store.db.execute('SELECT * FROM payout').fetchone()))

    def test_original_declarations_must_match_at_commit_time(self):
        declaration=self.declaration()
        self.store.db.execute("UPDATE meta SET value='changed' WHERE key='owner_renewal_declaration'")
        with self.assertRaises(ValueError):self.declare(declaration)

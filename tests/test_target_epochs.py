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
        self.store.db.execute("INSERT INTO meta VALUES ('qualified_campaign_active_seconds','0.0')")
        self.store.event('failed_run_retained', {'outcome':'failed', 'fee_sat':0})

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def declaration(self):
        from simulator.target_epochs import declaration_hashes
        return copy.deepcopy(dict(id='post-upgrade-1', previous_identity=self.old, identity=self.new,
                    observed_at=time.time(), sdk_commit='4'*40,
                    native_hashes={name:'5'*64 for name in ('bark-sim-driver','vtxo-proof','seed-restore')},
                    receipt_hashes={name:'6'*64 for name in ('upgrade_completion','independent_identity',
                        'sdk_qualification','simulator_release','nursery_reconciliation')},
                    ordinary_lifetime_blocks=48, pool_lifetime_blocks=48,
                    recovery_guard_verified=True, pending_server_payouts_preserved=True,
                    declaration_hashes=declaration_hashes(self.store)))

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

    def test_original_funding_source_cannot_change_during_epoch_qualification(self):
        self.store.db.execute("INSERT INTO meta VALUES ('owner_renewal_funding_source','original source')")
        declaration=self.declaration()
        self.store.db.execute("UPDATE meta SET value='replacement source' WHERE key='owner_renewal_funding_source'")
        with self.assertRaises(ValueError):self.declare(declaration)

    def test_direct_controller_lease_blocks_epoch_until_independently_reconciled(self):
        self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        self.assertTrue(self.store.acquire_actor_lease('actor-04','controller-1','qualified profile'))
        self.store.db.execute("INSERT INTO meta VALUES ('paused','declared target upgrade')")
        with self.assertRaises(ValueError):self.declare()
        self.store.finish_actor_lease('actor-04','controller-1','completed')
        self.declare()

    def test_unknown_direct_controller_lease_cannot_be_treated_as_quiescent(self):
        self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        self.assertTrue(self.store.acquire_actor_lease('actor-04','controller-1','qualified profile'))
        self.store.finish_actor_lease('actor-04','controller-1','outcome_unknown')
        self.store.db.execute("INSERT INTO meta VALUES ('paused','declared target upgrade')")
        with self.assertRaises(ValueError):self.declare()
        with self.assertRaises(ValueError):self.store.finish_actor_lease('actor-04','controller-1','completed')

    def test_legacy_private_controller_unknown_blocks_global_epoch(self):
        self.store.db.execute('CREATE TABLE noah_control(id TEXT PRIMARY KEY, actor TEXT, state TEXT)')
        self.store.db.execute("INSERT INTO noah_control VALUES ('legacy','noah-phone-1','outcome_unknown')")
        with self.assertRaises(ValueError):self.declare()

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

    def test_later_epoch_uses_last_deployment_and_replay_cannot_roll_it_back(self):
        original=self.declaration();self.declare(original)
        later=self.declaration();later['id']='post-upgrade-2'
        later['previous_identity']=copy.deepcopy(self.new)
        later['identity']['image_digest']='sha256:'+'9'*64
        self.declare(later)
        self.declare(original)
        self.store.bind_target(later['identity'])
        with self.assertRaises(ValueError):self.store.bind_target(self.new)
        self.assertEqual(canonical(self.old),self.store.get_meta('target_identity'))

    def test_running_dispatch_or_future_receipt_cannot_declare_epoch(self):
        self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        with self.assertRaises(ValueError):self.declare()
        self.store.db.execute("INSERT INTO meta VALUES ('paused','declared target upgrade')")
        declaration=self.declaration();declaration['observed_at']=time.time()+60
        with self.assertRaises(ValueError):self.declare(declaration)

    def test_changed_registry_identity_cannot_repin_a_valid_event_history(self):
        self.declare()
        undeclared={**self.new,'image_digest':'sha256:'+'8'*64}
        self.store.db.execute('UPDATE target_epoch SET identity=?',(canonical(undeclared),))
        with self.assertRaises(ValueError):self.store.bind_target(undeclared)

    def legacy_declaration(self):
        import hashlib
        event=self.store.db.execute("SELECT sequence,hash,payload FROM event WHERE kind='target_manifest' ORDER BY sequence LIMIT 1").fetchone()
        metadata=canonical(self.new)
        self.store.db.execute("UPDATE meta SET value=? WHERE key='target_identity'",(metadata,))
        return dict(id='observed-legacy-image-1',first_manifest_sequence=event['sequence'],
            first_manifest_hash=event['hash'],first_manifest_identity=json.loads(event['payload']),
            metadata_identity=self.new,metadata_sha256=hashlib.sha256(metadata.encode()).hexdigest(),
            observed_at=time.time(),receipt_hashes={'before_upgrade_identity':'a'*64,
                'preserved_campaign_history':'b'*64},historical_transition_qualified=False)

    def test_explicit_legacy_reconciliation_preserves_both_recorded_identities(self):
        from simulator.target_epochs import reconcile_legacy_identity
        declaration=self.legacy_declaration()
        with self.assertRaises(ValueError):self.store.bind_target(self.new)
        original=canonical(self.old)
        self.assertTrue(reconcile_legacy_identity(self.store,declaration))
        self.assertFalse(reconcile_legacy_identity(self.store,declaration))
        self.store.bind_target(self.new)
        self.assertEqual(original,self.store.db.execute("SELECT payload FROM event WHERE kind='target_manifest' ORDER BY sequence LIMIT 1").fetchone()[0])
        self.assertEqual(canonical(self.new),self.store.get_meta('target_identity'))
        self.store.verify_event_chain()
        epoch=self.declaration();epoch['previous_identity']=self.new
        epoch['identity']={**self.new,'image_digest':'sha256:'+'8'*64}
        self.declare(epoch);self.store.bind_target(epoch['identity'])

    def test_legacy_record_does_not_authorize_later_metadata_mutation_or_record_edit(self):
        from simulator.target_epochs import reconcile_legacy_identity
        declaration=self.legacy_declaration();reconcile_legacy_identity(self.store,declaration)
        altered={**self.new,'image_digest':'sha256:'+'9'*64}
        self.store.db.execute("UPDATE meta SET value=? WHERE key='target_identity'",(canonical(altered),))
        with self.assertRaises(ValueError):self.store.bind_target(altered)
        self.store.db.execute("UPDATE meta SET value=? WHERE key='target_identity'",(canonical(self.new),))
        declaration['receipt_hashes']['before_upgrade_identity']='c'*64
        with self.assertRaises(ValueError):reconcile_legacy_identity(self.store,declaration)
        self.store.db.execute("UPDATE event SET payload='{}' WHERE kind='legacy_target_identity_reconciled'")
        with self.assertRaises(ValueError):self.store.bind_target(self.new)

    def test_legacy_reconciliation_cannot_change_keys_or_claim_a_historical_upgrade_pass(self):
        from simulator.target_epochs import reconcile_legacy_identity
        declaration=self.legacy_declaration()
        declaration['historical_transition_qualified']=True
        with self.assertRaises(ValueError):reconcile_legacy_identity(self.store,declaration)
        declaration['historical_transition_qualified']=False
        declaration['first_manifest_identity']['server_pubkey']='02'+'9'*64
        with self.assertRaises(ValueError):reconcile_legacy_identity(self.store,declaration)

    def test_legacy_reconciliation_requires_paused_quiescent_campaign(self):
        from simulator.target_epochs import reconcile_legacy_identity
        declaration=self.legacy_declaration()
        self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        with self.assertRaises(ValueError):reconcile_legacy_identity(self.store,declaration)

        self.store.queue('legacy-unknown','actor-01','H01','sync',{},0)
        self.store.db.execute("UPDATE action SET state='outcome_unknown'")
        self.store.db.execute("INSERT INTO meta VALUES ('paused','declared target upgrade')")
        with self.assertRaises(ValueError):reconcile_legacy_identity(self.store,declaration)

    def test_deleted_legacy_event_cannot_roll_back_metadata_or_redeclare(self):
        from simulator.target_epochs import reconcile_legacy_identity
        declaration=self.legacy_declaration();reconcile_legacy_identity(self.store,declaration)
        self.store.db.execute("DELETE FROM event WHERE kind='legacy_target_identity_reconciled'")
        self.store.db.execute("UPDATE meta SET value=? WHERE key='target_identity'",(canonical(self.old),))
        self.store.verify_event_chain()  # A truncated prefix alone cannot detect rollback.
        with self.assertRaises(ValueError):self.store.bind_target(self.old)
        self.store.db.execute("UPDATE meta SET value=? WHERE key='target_identity'",(canonical(self.new),))
        with self.assertRaises(ValueError):reconcile_legacy_identity(self.store,declaration)

    def test_deleted_or_edited_legacy_registry_fails_closed(self):
        from simulator.target_epochs import reconcile_legacy_identity
        declaration=self.legacy_declaration();reconcile_legacy_identity(self.store,declaration)
        self.store.db.execute("UPDATE legacy_target_reconciliation SET event_hash=?",('e'*64,))
        with self.assertRaises(ValueError):self.store.bind_target(self.new)
        self.store.db.execute('DROP TABLE legacy_target_reconciliation')
        with self.assertRaises(ValueError):self.store.bind_target(self.new)

    def test_legacy_reconciliation_rejects_stale_or_missing_audit_receipts(self):
        from simulator.target_epochs import reconcile_legacy_identity
        declaration=self.legacy_declaration()
        declaration['observed_at']=time.time()-601
        with self.assertRaises(ValueError):reconcile_legacy_identity(self.store,declaration)
        declaration['observed_at']=time.time();declaration['receipt_hashes']={}
        with self.assertRaises(ValueError):reconcile_legacy_identity(self.store,declaration)

    def test_deleted_epoch_registry_cannot_restore_original_target(self):
        self.declare()
        self.store.db.execute('DROP TABLE target_epoch')
        with self.assertRaises(ValueError):self.store.bind_target(self.old)

    def test_idempotent_replay_does_not_ignore_a_damaged_registry(self):
        declaration=self.declaration();self.declare(declaration)
        self.store.db.execute('UPDATE target_epoch SET identity=?',(canonical(self.old),))
        with self.assertRaises(ValueError):self.declare(declaration)

    def test_funding_unknown_or_inflight_blocks_epoch_without_client_actions(self):
        self.store.db.execute('CREATE TABLE funding_batch(id TEXT PRIMARY KEY,state TEXT)')
        self.store.db.execute("INSERT INTO funding_batch VALUES ('funding','outcome_unknown')")
        for state in ('outcome_unknown','broadcasting'):
            self.store.db.execute('UPDATE funding_batch SET state=?',(state,))
            with self.assertRaises(ValueError):self.declare()

    def test_every_owner_tranche_and_fixed_ramp_realism_declaration_is_preserved(self):
        for key in ('owner_renewal_declaration:traffic-2','owner_renewal_funding_source:traffic-2',
                    'ramp_plan','campaign_realism'):
            self.store.db.execute('INSERT INTO meta VALUES (?,?)',(key,'original'))
        declaration=self.declaration()
        for key in ('owner_renewal_declaration:traffic-2','ramp_plan','campaign_realism'):
            self.store.db.execute('UPDATE meta SET value=? WHERE key=?',('changed',key))
            with self.assertRaises(ValueError):self.declare(declaration)
            self.store.db.execute('UPDATE meta SET value=? WHERE key=?',('original',key))
        self.declare(declaration)

    def test_deleted_original_manifest_metadata_cannot_rebootstrap_with_new_identity(self):
        self.store.db.execute("DELETE FROM meta WHERE key='target_identity'")
        with self.assertRaises(ValueError):self.store.bind_target(self.new)

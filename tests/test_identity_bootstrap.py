"""Synthetic filesystem/admission controls; no native create or Core scan credit."""
import asyncio
import hashlib
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from simulator.config import Config
from simulator.engine import Engine, Lease, initialize
from simulator import identity_bootstrap as bootstrap
from simulator.model import SIGNET_GENESIS
from simulator.store import Store


class IdentityBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)
        self.wallets=self.root/'wallets';self.wallets.mkdir(mode=0o700)
        self.driver=self.root/'driver';self.driver.write_bytes(b'synthetic driver; never executed')
        self.wallet_config=self.root/'wallet.toml';self.wallet_config.write_text('synthetic wallet configuration')
        self.native_config=self.root/'native.json'
        self.native_config.write_text(json.dumps({'network':'signet','wallet_root':str(self.wallets),
            'ark_endpoint':'http://127.0.0.1:1','wallet_config':str(self.wallet_config)}))
        self.environment=patch.dict(os.environ,{'SIM_DRIVER_CONFIG':str(self.native_config)})
        self.environment.start()
        self.store=Store(self.root/'state','synthetic',10000,architecture_profile='direct_xpub')
        initialize(self.store)
        self.config=Config(self.root/'state',('observer',),(str(self.driver),),self.wallets,
            SIGNET_GENESIS,'abandon-signet-fallback-fresh','sha256:'+'a'*64,'02'+'b'*64,
            10000,1,10,True,architecture_profile='direct_xpub',expected_sdk_commit='5e5994d3ab6844a443cef1e9d19a9195ed785486',
            trace_enabled=False)
        self.identity={'network':'signet','genesis':SIGNET_GENESIS,'container':self.config.expected_container,
            'image_digest':self.config.expected_image,'server_pubkey':self.config.expected_server_pubkey}
        self.pins={'product_commit':'1'*40,'sdk_commit':self.config.expected_sdk_commit,
            'driver_sha256':self.digest(self.driver),'configuration_sha256':'2'*64,'schema_sha256':'3'*64}
        self.value={'id':'synthetic-zero-principal','pins':self.pins,'identity':self.identity,
            'wallet_root':str(self.wallets),'actors':['actor-01','actor-02'],
            'driver_config_sha256':self.digest(self.native_config),'wallet_config_sha256':self.digest(self.wallet_config)}
        self.snapshot={'identity':self.identity,'financial_pins':self.pins,'architecture_profile':'direct_xpub',
            'observed_at':time.time(),'stable_tip':True,'initial_block_download':False,
            'server_status':{'status':'running'},'height':100,'tip_hash':'a'*64}
        self.store.db.execute("INSERT INTO meta VALUES ('paused','declare')")

    def tearDown(self):
        self.store.close();self.environment.stop();self.tmp.cleanup()

    def digest(self,path):return hashlib.sha256(path.read_bytes()).hexdigest()

    def declare(self):
        bootstrap.declare(self.store,self.config,self.value)
        self.store.add_snapshot(self.snapshot)
        self.store.db.execute("DELETE FROM meta WHERE key='paused'")

    def action(self,operation='create',fee=0,args=None,actor='actor-01'):
        scenario=self.store.db.execute('SELECT id FROM scenario LIMIT 1').fetchone()[0]
        identifier='identity-'+actor+'-'+operation
        self.store.queue(identifier,actor,scenario,operation,args or {},fee)
        return self.store.claim({operation})

    def test_fresh_hashed_context_allows_only_zero_fee_create_with_existing_lease(self):
        self.declare()
        action=self.action()
        with self.assertRaisesRegex(ValueError,'Lease|No such file'):
            try:bootstrap.eligible(self.store,self.config,self.snapshot,action)
            except FileNotFoundError as error:raise ValueError(str(error))
        with Lease(self.wallets):
            self.assertTrue(bootstrap.eligible(self.store,self.config,self.snapshot,action))
            bootstrap.begin(self.store,self.config,self.snapshot,action)
            self.assertEqual(1,self.store.db.execute("SELECT count(*) FROM event WHERE kind='identity_bootstrap_create_intent'").fetchone()[0])
        self.assertIsNotNone(self.store.get_meta('financial_qualification_required'))
        self.assertTrue(bootstrap.pending(self.store))

    def test_nonzero_fee_or_other_operation_never_enters_bootstrap(self):
        self.declare()
        action=self.action('board',fee=200)
        with Lease(self.wallets),self.assertRaisesRegex(ValueError,'only predeclared zero-fee create'):
            bootstrap.eligible(self.store,self.config,self.snapshot,action)
        action={**action,'operation':'create','fee_reservation_sat':1}
        with Lease(self.wallets),self.assertRaisesRegex(ValueError,'zero-fee create'):
            bootstrap.eligible(self.store,self.config,self.snapshot,action)

    def test_preexisting_files_symlinks_or_public_root_refuse_declaration(self):
        (self.wallets/'foreign').write_text('retained')
        with self.assertRaisesRegex(ValueError,'initially be empty'):
            bootstrap.declare(self.store,self.config,self.value)
        (self.wallets/'foreign').unlink()
        self.wallets.chmod(0o755)
        with self.assertRaisesRegex(ValueError,'private directory'):
            bootstrap.declare(self.store,self.config,self.value)

    def test_driver_configs_and_actual_snapshot_pins_are_rechecked(self):
        self.declare();action=self.action()
        with Lease(self.wallets):
            for path in (self.driver,self.native_config,self.wallet_config):
                original=path.read_bytes();path.write_bytes(original+b' changed')
                with self.subTest(path=path.name),self.assertRaises(ValueError):
                    bootstrap.eligible(self.store,self.config,self.snapshot,action)
                path.write_bytes(original)
            with self.assertRaisesRegex(ValueError,'actual financial pins differ'):
                bootstrap.eligible(self.store,self.config,{**self.snapshot,'financial_pins':{**self.pins,'schema_sha256':'4'*64}},action)

    def test_unknown_create_is_parked_and_never_retried(self):
        self.declare();action=self.action()
        with Lease(self.wallets):bootstrap.begin(self.store,self.config,self.snapshot,action)
        self.store.finish(action['id'],'outcome_unknown',{'synthetic':'timeout'})
        with Lease(self.wallets),self.assertRaisesRegex(ValueError,'unknown outcome parked'):
            bootstrap.eligible(self.store,self.config,self.snapshot)

    def test_native_reply_alone_holds_next_identity_and_all_financial_actions(self):
        self.declare();action=self.action()
        with Lease(self.wallets):bootstrap.begin(self.store,self.config,self.snapshot,action)
        self.store.finish(action['id'],'completed',{'synthetic':'unverified reply'},0)
        with Lease(self.wallets),self.assertRaisesRegex(ValueError,'independent zero-asset proof'):
            bootstrap.eligible(self.store,self.config,self.snapshot)
        from simulator.operating_limits import preflight
        with self.assertRaisesRegex(ValueError,'zero-asset proofs missing'):
            preflight(self.store,self.config,self.snapshot,operation='board')

    def test_unexpected_existing_actor_path_refuses_without_native_call(self):
        self.declare();self.action()
        (self.wallets/'actor-01').mkdir()
        self.store.add_snapshot(self.snapshot)
        engine=Engine(self.config,self.store)
        # Reuse the original claimed row rather than dispatching a second action.
        row=dict(self.store.db.execute('SELECT * FROM action LIMIT 1').fetchone());row['args']={}
        with Lease(self.wallets),patch('simulator.engine.json_command',AsyncMock()) as native:
            asyncio.run(engine.dispatch_one(row))
        native.assert_not_awaited()
        self.assertEqual('blocked',self.store.db.execute('SELECT state FROM action LIMIT 1').fetchone()[0])

    def test_engine_seals_intent_before_create_and_parks_unknown_without_retry(self):
        self.declare();action=self.action()
        self.store.add_snapshot(self.snapshot)
        engine=Engine(self.config,self.store)
        async def unknown(command,request,**kwargs):
            self.assertEqual('create',request['operation'])
            self.assertEqual(0,request['maximum_fee_sat'])
            self.assertEqual(1,self.store.db.execute(
                "SELECT count(*) FROM event WHERE kind='identity_bootstrap_create_intent'").fetchone()[0])
            raise TimeoutError('synthetic unknown; no native process')
        with Lease(self.wallets),patch('simulator.engine.json_command',side_effect=unknown) as native:
            asyncio.run(engine.dispatch_one(action))
            self.assertFalse(engine.ready_for_actions(self.snapshot))
        native.assert_awaited_once()
        self.assertEqual('outcome_unknown',self.store.db.execute('SELECT state FROM action LIMIT 1').fetchone()[0])
        self.assertIsNotNone(self.store.get_meta('financial_qualification_required'))

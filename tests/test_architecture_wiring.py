"""Profile routing controls, not real native or live financial qualification."""
import asyncio
import copy
import json
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from simulator.campaign import _signed_coin
from simulator.config import Config
from simulator.engine import Engine, initialize
from simulator.model import SIGNET_GENESIS, canonical
from simulator.store import Store
from tests import account_fixtures
from tests import test_final_campaign as final_controls

SDK='8f2286ee7e1631b0ceccd1631ec3b728a1bb0a52'


def config(root, profile=None, sdk=SDK):
    base=Config(root,('observer',),(),root/'wallets',SIGNET_GENESIS,
                'abandon-signet-fallback-a','sha256:'+'a'*64,'02'+'b'*64,
                10000,1,10,False,trace_enabled=False)
    # A SimpleNamespace keeps pre-change behavioural REDs independent of new
    # Config constructor fields. Production config tests below use real TOML.
    return SimpleNamespace(**{**vars(base),'architecture_profile':profile,
                              'expected_sdk_commit':sdk if profile else None})


class ProfileConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.path=self.root/'config.toml'
    def tearDown(self):self.tmp.cleanup()
    def write(self,profile=None,sdk=None):
        extra=''
        if profile is not None:extra+='architecture_profile='+json.dumps(profile)+'\n'
        if sdk is not None:extra+='sdk_commit='+json.dumps(sdk)+'\n'
        self.path.write_text(f'''[target]
network="signet"
genesis="{SIGNET_GENESIS}"
container="abandon-signet-fallback-a"
image_digest="sha256:{'a'*64}"
server_pubkey="02{'b'*64}"
{extra}[runtime]
state_dir="{self.root}/state"
wallet_root="{self.root}/wallets"
observer_command=["observer"]
fee_budget_sat=10000
''')
    def test_loads_explicit_profile_and_actual_declared_sdk_without_guessing(self):
        for profile in ('two_step_per_key','direct_xpub'):
            with self.subTest(profile=profile):
                self.write(profile,SDK);cfg=Config.load(self.path)
                self.assertEqual(profile,cfg.architecture_profile)
                self.assertEqual(SDK,cfg.expected_sdk_commit)
    def test_explicit_profile_requires_valid_sdk_and_sdk_requires_profile(self):
        for profile,sdk in [('two_step_per_key',None),('direct_xpub','8f'),
                            ('typo',SDK),(None,SDK),('two_step_per_key','G'*40)]:
            with self.subTest(profile=profile,sdk=sdk):
                self.write(profile,sdk)
                with self.assertRaises(ValueError):Config.load(self.path)
    def test_unprofiled_default_remains_compatible(self):
        self.write();cfg=Config.load(self.path)
        self.assertIsNone(cfg.architecture_profile)
        self.assertIsNone(cfg.expected_sdk_commit)
    def test_observed_profile_and_sdk_must_match_configuration(self):
        self.write('two_step_per_key',SDK);cfg=Config.load(self.path)
        snapshot={'identity':{'network':'signet','genesis':SIGNET_GENESIS,
                  'container':cfg.expected_container,'image_digest':cfg.expected_image,
                  'server_pubkey':cfg.expected_server_pubkey},
                  'architecture_profile':'two_step_per_key','financial_pins':{'sdk_commit':SDK}}
        cfg.validate_identity(snapshot)
        for change in ({'architecture_profile':'direct_xpub'},
                       {'architecture_profile':None},{'financial_pins':{'sdk_commit':'0'*40}},
                       {'financial_pins':None}):
            with self.subTest(change=change),self.assertRaises(ValueError):
                cfg.validate_identity({**snapshot,**change})
    def test_cli_passes_profile_to_store_before_initializing_campaign(self):
        self.write('two_step_per_key',SDK)
        from simulator.cli import main
        argv=['bark-simulator','offline','--config',str(self.path),'--actor','actor-02']
        with patch.object(sys,'argv',argv),patch('simulator.cli.generate'):
            main()
        store=Store(self.root/'state','live',10000,architecture_profile='two_step_per_key')
        try:
            self.assertEqual(0,store.db.execute("SELECT online FROM actor WHERE id='actor-02'").fetchone()[0])
        finally:store.close()


class ProfileEngineTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.opened=[]
    async def asyncTearDown(self):
        for store in self.opened:store.close()
        self.tmp.cleanup()
    def setup(self,profile):
        root=self.root/(profile or 'default')
        store=Store(root,'synthetic',10000,architecture_profile=profile)
        self.opened.append(store);initialize(store)
        return store,config(root,profile)
    async def test_profile_mismatch_or_omission_refuses_engine_start(self):
        store,cfg=self.setup('two_step_per_key')
        for declared in (None,'direct_xpub'):
            with self.subTest(profile=declared),self.assertRaises(ValueError):
                Engine(config(cfg.state_dir,declared),store)
    async def test_explicit_config_cannot_adopt_unprofiled_default_store(self):
        store,cfg=self.setup(None)
        with self.assertRaises(ValueError):Engine(config(cfg.state_dir,'direct_xpub'),store)
    async def test_both_profiles_require_complete_financial_readiness(self):
        healthy={'observed_at':time.time(),'stable_tip':True,
                 'initial_block_download':False,'server_status':{'status':'running'}}
        for profile in ('two_step_per_key','direct_xpub'):
            with self.subTest(profile=profile):
                store,cfg=self.setup(profile);engine=Engine(cfg,store)
                self.assertFalse(engine.ready_for_actions(healthy))
                self.assertIsNotNone(store.get_meta('financial_qualification_required'))
    async def test_existing_default_direct_health_api_remains_compatible(self):
        store,cfg=self.setup(None);engine=Engine(cfg,store)
        self.assertTrue(engine.ready_for_actions({'observed_at':time.time(),'stable_tip':True,
                        'initial_block_download':False,'server_status':{'status':'running'}}))
    async def test_only_selected_native_settlement_collector_runs(self):
        for profile in ('two_step_per_key','direct_xpub',None):
            with self.subTest(profile=profile):
                store,cfg=self.setup(profile);engine=Engine(cfg,store);chain=object()
                with patch('simulator.engine.collect_direct_settlements',AsyncMock()) as direct, \
                     patch('simulator.engine.collect_two_step_settlements',AsyncMock(),create=True) as two_step:
                    await engine.collect_settlement_evidence(chain)
                if profile=='two_step_per_key':
                    two_step.assert_awaited_once_with(store,chain);direct.assert_not_awaited()
                else:
                    direct.assert_awaited_once_with(store,cfg,chain);two_step.assert_not_awaited()
    async def test_two_step_inventory_reaches_original_settlements_and_nursery(self):
        store,cfg=self.setup('two_step_per_key');cfg.inventory_command=('bridge',)
        engine=Engine(cfg,store);seen=[]
        async def fetch(command,request,**kwargs):
            seen.append(request['kind'])
            return {'kind':request['kind'],'rows':[],'next':None,'inventory_consistent':False}
        with patch('simulator.engine.json_command',side_effect=fetch), \
             patch('simulator.engine.collect_padding',AsyncMock()):
            for _ in range(6):await engine.collect_inventory()
        self.assertEqual({'coins','pending','links','records','settlements','nursery'},set(seen))
    async def test_final_epoch_sdk_cannot_be_overridden_by_configuration(self):
        store,cfg=self.setup('two_step_per_key')
        from simulator.final_campaign import declare_epoch
        store.db.execute("INSERT INTO meta VALUES ('paused','declare')")
        declare_epoch(store,{'id':'final','pins':{'product_commit':'1'*40,'sdk_commit':SDK,
                      'driver_sha256':'2'*64,'configuration_sha256':'3'*64,'schema_sha256':'4'*64},
                      'started_at':time.time(),'windows_seconds':{'ark':600,'internal_lightning':600,'external_lightning':600},
                      'minimum_observations':{'ark':1,'internal_lightning':1,'external_lightning':1}})
        cfg.expected_sdk_commit='0'*40
        with self.assertRaises(ValueError):Engine(cfg,store)


class ProfileSignedCoinTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.opened=[]
    def tearDown(self):
        for store in self.opened:store.close()
        self.tmp.cleanup()
    def proof(self,profile):
        if profile=='two_step_per_key':
            bound={'mailbox_pk':'mailbox','seq':7,'spk':'script',
                   'record_signature_valid':True,'key_link_signature_valid':True}
        else:
            bound=account_fixtures.proof({'user_pubkey':'pubkey','binding':{'mailbox_pk':'mailbox'}})['binding']
        return {'id':'coin:0','user_pubkey':'pubkey','amount_sat':1000,'signed_path_valid':True,
                'anchor_confirmations':1,'binding':bound}
    def setup(self,profile):
        store=Store(self.root/profile,'synthetic',10000,architecture_profile=profile)
        self.opened.append(store);initialize(store)
        proof=self.proof(profile)
        store.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',('pubkey','actor-01','mailbox',canonical(proof)))
        store.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',('coin:0','pubkey',1000,'hash','bb',canonical(proof)))
        return store,proof
    def test_truthful_per_key_signatures_qualify_shared_coin_predicate(self):
        store,proof=self.setup('two_step_per_key')
        self.assertIsNotNone(_signed_coin(store,'coin:0','actor-01'))
        self.assertNotIn('account_child_verified',proof['binding'])
    def test_each_profile_requires_its_own_signature_contract(self):
        for profile in ('two_step_per_key','direct_xpub'):
            with self.subTest(profile=profile):
                store,_=self.setup(profile)
                wrong=self.proof('direct_xpub' if profile=='two_step_per_key' else 'two_step_per_key')
                store.db.execute('UPDATE owned_coin SET proof=?',(canonical(wrong),))
                self.assertIsNone(_signed_coin(store,'coin:0','actor-01'))
    def test_exitability_owner_and_confirmation_requirements_are_kept(self):
        store,proof=self.setup('two_step_per_key')
        for field,value in [('signed_path_valid',False),('anchor_confirmations',0),('user_pubkey','other'),('amount_sat',999)]:
            with self.subTest(field=field):
                changed={**proof,field:value};store.db.execute('UPDATE owned_coin SET proof=?',(canonical(changed),))
                self.assertIsNone(_signed_coin(store,'coin:0','actor-01'))
        store.db.execute('UPDATE owned_coin SET proof=?',(canonical(proof),))
        self.assertIsNone(_signed_coin(store,'coin:0','actor-02'))


class PerKeyFinalClockControls(unittest.TestCase):
    """Reuse shared three-rail oracles with truthful per-key proof metadata."""
    action=final_controls.FinalEpochEvidenceTests.action
    event=final_controls.FinalEpochEvidenceTests.event
    credit=final_controls.FinalEpochEvidenceTests.credit
    ark=final_controls.FinalEpochEvidenceTests.ark
    internal=final_controls.FinalEpochEvidenceTests.internal
    external=final_controls.FinalEpochEvidenceTests.external
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.store=Store(Path(self.tmp.name),'synthetic',1000000,architecture_profile='two_step_per_key')
        initialize(self.store)
        self.store.db.execute("INSERT INTO meta VALUES ('paused','declare')")
        from simulator.final_campaign import declare_epoch
        declare_epoch(self.store,{'id':'per-key-final','pins':final_controls.PINS,'started_at':100,
                     'windows_seconds':{'ark':600,'internal_lightning':600,'external_lightning':600},
                     'minimum_observations':{'ark':1,'internal_lightning':1,'external_lightning':1}})
        self.store.db.execute("DELETE FROM meta WHERE key='paused'")
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def coin(self,actor,identity,action,at):
        key='key-'+identity
        bound={'mailbox_pk':actor,'seq':1,'spk':'script-'+actor,
               'record_signature_valid':True,'key_link_signature_valid':True}
        proof={'id':identity,'user_pubkey':key,'amount_sat':1000,'binding':bound,
               'signed_path_valid':True,'anchor_confirmations':1}
        self.store.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',(key,actor,actor,canonical(proof)))
        self.store.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',
                             (identity,key,1000,'synthetic-hash','bb',canonical(proof)))
        self.store.db.execute('INSERT INTO coin_observation VALUES (?,?,?,?)',(identity,action,'Spendable',at))
        self.event('public_ownership_verified',{'actor':actor,'action_id':action,'objects':1})
    def test_three_real_proof_contracts_are_required_with_same_freshness_and_pins(self):
        from simulator.final_campaign import traffic_ready
        self.ark();self.internal()
        self.assertFalse(traffic_ready(self.store,104,final_controls.PINS))
        self.external()
        self.assertTrue(traffic_ready(self.store,104,final_controls.PINS))
        self.assertFalse(traffic_ready(self.store,702,final_controls.PINS))
        self.assertFalse(traffic_ready(self.store,104,{**final_controls.PINS,'sdk_commit':'9'*40}))
        for row in self.store.db.execute('SELECT proof FROM owned_coin'):
            self.assertNotIn('account_child_verified',json.loads(row[0])['binding'])
    def test_shared_clock_still_excludes_missing_pins_pause_and_restart_time(self):
        final_controls.FinalEpochEvidenceTests.test_final_clock_requires_live_financial_pins(self)

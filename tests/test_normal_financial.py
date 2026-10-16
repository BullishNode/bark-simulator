"""Real Store/Engine integration controls with synthetic monetary sources.

These test the collection boundary, not native money proofs or live readiness.
The injected test collector is deliberately not a qualified production adapter.
"""
import asyncio
import copy
import tempfile
import time
import unittest
from decimal import Decimal
from pathlib import Path
from unittest.mock import AsyncMock, patch

from simulator.config import Config
from simulator.engine import Engine, initialize
from simulator.model import SIGNET_GENESIS
from simulator.normal_financial import collect, validate_collection, KEY
from simulator.operating_limits import declare_envelope, preflight
from simulator.store import Store
from simulator.treasury import declare_boundary
from tests.test_final_campaign import PINS


class Chain:
    def __init__(self):
        self.height=100; self.tip='a'*64; self.genesis=SIGNET_GENESIS
    def identity(self):
        return {'chain':'signet','blocks':self.height,'bestblockhash':self.tip,'initialblockdownload':False}
    def call(self, method, *args):
        if method=='getblockhash':return self.genesis
        if method=='getdescriptorinfo':return {'hasprivatekeys':False,'descriptor':args[0]}
        if method=='deriveaddresses':return ['synthetic-address']
        if method=='validateaddress':return {'scriptPubKey':'synthetic-script'}
        if method=='gettxout':return {'confirmations':1,'value':Decimal('.00001000'),'scriptPubKey':{'hex':'synthetic-script'}}
        raise AssertionError('no financial or wallet RPC permitted by this fixture')


class NormalFinancialTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir='/dev/shm'); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); self.chain=Chain()
        self.setup_profile('two_step_per_key')

    def setup_profile(self, profile):
        if hasattr(self,'store'):self.store.close()
        self.store=Store(self.root/profile,'synthetic',10000,architecture_profile=profile)
        self.addCleanup(self.store.close)
        initialize(self.store); self.store.db.execute("INSERT INTO meta VALUES ('paused','declare')")
        self.config=Config(self.root/profile,('observer',),(),self.root/'wallets',SIGNET_GENESIS,
            'fixture-server','sha256:'+'6'*64,'02'+'7'*64,10000,1,10,True,
            board_amount_sat=800,action_fee_reserve_sat=200,architecture_profile=profile,
            expected_sdk_commit=PINS['sdk_commit'],trace_enabled=False,
            proof_command=('proof','http://127.0.0.1:1',str(self.root/'cookie'),'server'))
        member={'id':'operator','kind':'wallet','role':'operator','identity':'synthetic-wallet','descriptors':['synthetic-public-descriptor']}
        self.store.event('treasury_member_verified',{'member':member,'genesis':SIGNET_GENESIS,'financial_pins':PINS})
        seq=self.sequence(); boundary={'id':'normal-boundary','genesis':SIGNET_GENESIS,'pins':PINS,
            'members':[{**member,'verification_sequence':seq}],'excluded':[]}
        declare_boundary(self.store,boundary,self.chain)
        self.store.event('treasury_inventory',{'member_id':'operator','identity':member['identity'],
            'financial_pins':PINS,'tip_hash':self.chain.tip,'height':100,'complete':True,
            'utxos':[{'outpoint':'b'*64+':0','amount_sat':1000,'script':'synthetic-script','descriptor_index':0,'child_index':0}]})
        self.limits={'id':'normal-limits','pins':PINS,'boundary_id':boundary['id'],'capital_exposure_msat':2000000,
            'fee_budgets_msat':{'ordinary':300000,'urgent':300000},
            'fee_ceilings_sat_kvb':{'round':2000,'pool':2000,'sweep':2000,'payout':2000,'claim':4000,'progression':4000},
            'per_action_fee_sat':200,'grant_sat':1000,'board_sat':800,'board_fee_reserve_sat':200,
            'minimum_pool_sat':1,'minimum_channel_msat':1,'fee_assets':['b'*64+':0']}
        declare_envelope(self.store,self.limits,self.config,{'operator':self.sequence()},self.chain)
        self.snapshot={'identity':{'network':'signet','genesis':SIGNET_GENESIS,'container':'fixture-server',
            'image_digest':self.config.expected_image,'server_pubkey':self.config.expected_server_pubkey},
            'architecture_profile':profile,'runtime_transport':'systemd','financial_pins':PINS,
            'height':100,'tip_hash':self.chain.tip,'stable_tip':True,'initial_block_download':False,
            'server_status':{'status':'running'},'observed_at':time.time()}
        self.engine=Engine(self.config,self.store,financial_source_collector=self.producer)
        self.contexts=[]

    def sequence(self):return self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]

    async def producer(self, store, config, chain, snapshot, observation, **changes):
        self.contexts.append(copy.deepcopy(observation))
        proof={'source_observation':observation,'financial_pins':PINS,'boundary_id':'normal-boundary',
            'height':100,'tip_hash':self.chain.tip,'complete':True,'observed_at':time.time(),
            'effective_fee_ceilings_sat_kvb':self.limits['fee_ceilings_sat_kvb'],
            'capital_exposure_msat':1000000,'available_fee_funding_msat':1000000,
            'estimated_fee_rate_sat_kvb':1000}
        proof.update(changes);store.event('financial_operating_readiness',proof)
        return self.sequence()

    async def call(self, producer=None):
        return await collect(self.store,self.config,self.chain,self.snapshot,producer or self.producer)

    async def test_each_profile_collects_new_original_proof_on_every_observation(self):
        for profile in ('two_step_per_key','direct_xpub','direct_per_key'):
            if profile!='two_step_per_key':self.setup_profile(profile)
            one=await self.call();two=await self.call()
            self.assertNotEqual(one['operating_readiness_sequence'],two['operating_readiness_sequence'])
            self.assertNotEqual(self.contexts[-2]['id'],self.contexts[-1]['id'])
            self.assertTrue(preflight(self.store,self.config,two)['allowed'])
            self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM action').fetchone()[0])
            self.store.verify_event_chain()

    async def test_flag_reply_and_old_sequence_cannot_replace_new_producer_proof(self):
        original=await self.call()
        for value in (True,{'complete':True},original['operating_readiness_sequence']):
            async def wrong(*args):return value
            with self.subTest(value=type(value).__name__),self.assertRaises(ValueError):await self.call(wrong)
        with self.assertRaises(ValueError):
            await collect(self.store,self.config,self.chain,self.snapshot,None)

    async def test_mismatched_partial_stale_future_and_foreign_context_refuse(self):
        changes=[{'complete':False},{'financial_pins':{**PINS,'sdk_commit':'8'*40}},
            {'boundary_id':'foreign'},{'height':99},{'source_observation':{}},
            {'observed_at':time.time()-91},{'observed_at':time.time()+3600},
            {'effective_fee_ceilings_sat_kvb':{}},{'capital_exposure_msat':True}]
        for change in changes:
            async def wrong(*args):return await self.producer(*args,**change)
            with self.subTest(change=change),self.assertRaises(ValueError):await self.call(wrong)

    async def test_wrong_genesis_and_mid_collection_tip_change_hold(self):
        self.chain.genesis='f'*64
        with self.assertRaises(ValueError):await self.call()
        self.assertEqual([],self.contexts)
        self.chain.genesis=SIGNET_GENESIS
        async def race(*args):
            seq=await self.producer(*args);self.chain.tip='c'*64;return seq
        with self.assertRaisesRegex(ValueError,'chain changed'):await self.call(race)
        self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM event WHERE kind='normal_financial_source_collected'").fetchone()[0])

    async def test_final_independent_tip_read_counts_toward_whole_collection_deadline(self):
        clock=[time.time()];identity=self.chain.identity;calls=[0]
        def advancing_identity():
            calls[0]+=1
            if calls[0]==2:clock[0]+=91
            return identity()
        with patch('simulator.normal_financial.time.time',side_effect=lambda:clock[0]), \
                patch.object(self.chain,'identity',side_effect=advancing_identity):
            with self.assertRaisesRegex(ValueError,'deadline'):
                await self.call()
        self.assertEqual(0,self.store.db.execute("SELECT count(*)FROM event WHERE kind='normal_financial_source_collected'").fetchone()[0])
    async def test_real_quote_above_quiet_ceiling_keeps_separate_urgent_preflight(self):
        async def spike(*args):return await self.producer(*args,estimated_fee_rate_sat_kvb=3000)
        snapshot=await self.call(spike)
        self.assertFalse(preflight(self.store,self.config,snapshot)['allowed'])
        self.assertTrue(preflight(self.store,self.config,snapshot,operation='claim')['allowed'])

    async def test_collection_missing_stale_tampered_or_from_another_snapshot_refuses(self):
        snapshot=await self.call()
        for altered in ({**snapshot,'financial_collection_sequence':None},
                        {**snapshot,'tip_hash':'c'*64}):
            with self.assertRaises(ValueError):validate_collection(self.store,altered)
        with self.assertRaises(ValueError):validate_collection(self.store,snapshot,now=time.time()+91)
        self.store.db.execute("UPDATE event SET payload='{}' WHERE kind='normal_financial_source_collected'")
        with self.assertRaises(ValueError):validate_collection(self.store,snapshot)

    async def test_engine_observe_binds_producer_before_snapshot_and_skips_partial_as_gate(self):
        with patch('simulator.engine.json_command',AsyncMock(return_value=copy.deepcopy(self.snapshot))), \
             patch('simulator.engine.ChainReader',return_value=self.chain), \
             patch('simulator.financial_observer.collect_partial',AsyncMock()) as partial:
            snapshot=await self.engine.observe()
            self.assertTrue(await self.engine.refresh_financial_sources())
            self.assertTrue(self.engine.ready_for_actions(snapshot))
        partial.assert_not_awaited()
        validate_collection(self.store,snapshot)

    async def test_engine_missing_or_failed_producer_removes_observer_ready_claim(self):
        old=await self.call()
        async def failing(*args):raise ValueError('synthetic source unavailable')
        for collector in (None,failing):
            self.engine.financial_source_collector=collector
            with patch('simulator.engine.json_command',AsyncMock(return_value=copy.deepcopy(old))), \
                 patch('simulator.engine.ChainReader',return_value=self.chain):
                observed=await self.engine.observe()
            self.assertNotIn('operating_readiness_sequence',observed)
            self.assertNotIn('financial_collection_sequence',observed)
            self.assertFalse(self.engine.ready_for_actions(observed))
        self.assertIsNotNone(self.store.get_meta(KEY))
        self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM action').fetchone()[0])

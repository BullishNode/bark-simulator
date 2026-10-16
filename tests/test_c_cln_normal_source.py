"""Synthetic two-host transports/runtime/Core; real trace+shared CLN reducers."""
import copy
import hashlib
import tempfile
import time
import unittest
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from simulator import c_cln_normal_source as c
from simulator.model import SIGNET_GENESIS,canonical
from simulator.store import Store
from tests.test_final_campaign import PINS


class TwoHostCln(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=Store(Path(self.tmp.name),'synthetic-C',architecture_profile='direct_per_key');self.store.attach_trace();self.addCleanup(self.store.close)
        self.ids={'operator':'02'+'1'*64,'fixture_peer':'03'+'2'*64};self.member_ids={'operator':'operator-cln','fixture_peer':'fixture-cln'}
        self.tip='a'*64;self.point='b'*64+':0';self.frames={};self.members=[]
        self.observation={'id':'c'*32,'started_at':time.time(),'architecture_profile':'direct_per_key','financial_pins':PINS,'boundary_id':'Cfull','height':100,'tip_hash':self.tip}
        for alias in c.ALIASES:
            member={'id':self.member_ids[alias],'kind':'lightning_peer','role':'operator'if alias=='operator'else'fixture_peer',
              'identity':self.ids[alias],'descriptors':[]}
            self.store.event('treasury_member_verified',{'member':member,'genesis':SIGNET_GENESIS,'financial_pins':PINS})
            self.members.append({**member,'verification_sequence':self.sequence()})
            self.frames[alias]={'getinfo':{'id':self.ids[alias],'network':'signet','blockheight':100},
              'listfunds':{'outputs':[],'channels':[]},'listpeerchannels':{'channels':[]}}
        self.boundary={'id':'Cfull','genesis':SIGNET_GENESIS,'pins':PINS,'members':self.members,'excluded':[]}
        self.reader=c.FixedClnReads({a:{m:['/synthetic/'+a,'readonly-cln',m]for m in c.native.METHODS}for a in c.ALIASES})
        self.profile={'schema_version':1,'mode':'fullnormal_sources','operating_source_sha256':{'captaind':'d'*64,'watchmand':'e'*64},
          'lightning_context_sha256':'f'*64,'node_ids':self.ids,'ordinary_fee_policy_sha256':'1'*64}
        self.runtime={'product_commit':PINS['product_commit'],'schema_sha256':PINS['schema_sha256'],'observed_at':time.time(),
          'startup_source_sha256':'2'*64,'operating_profile':self.profile}
        self.store.event('owned_runtime_configuration_verified',self.runtime);self.runtime_sequence=self.sequence()
        self.admission={'architecture_profile':'direct_per_key','financial_pins':PINS,'node_ids':self.ids,'context_sha256':'f'*64,
          'commands_sha256':self.reader.hashes(),'startup_source_sha256':'2'*64,'component_sha256':{
            'adapter':c.digest(Path(c.__file__).read_bytes()),'native':c.module_hash(c.native.verify_source),'shared_cln_projection':c.module_hash(c.cln_projection),'native_projection_helpers':c.module_hash(c.native.peer_channel),
            'treasury':c.module_hash(__import__('simulator.treasury',fromlist=['_capture_assets'])._capture_assets)}}
        self.store.event('c_native_cln_source_qualified',self.admission);self.qualification=self.sequence();outer=self
        class Core:
            def identity(self):return {'chain':'signet','blocks':100,'bestblockhash':outer.tip,'initialblockdownload':False}
            def call(self,method,*args):
                if method=='getblockhash':return SIGNET_GENESIS
                if method=='gettxout':return {'value':Decimal('0.00020000'),'confirmations':3,'bestblock':outer.tip,'scriptPubKey':{'hex':'0020'+'3'*64}}
                raise AssertionError('unexpected Core wallet/method')
        self.chain=Core();self.calls=[]
    def sequence(self):return self.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
    def channels(self):
        for alias in c.ALIASES:
            other=self.ids['fixture_peer'if alias=='operator'else'operator']
            self.frames[alias]['listfunds']['channels']=[{'peer_id':other,'funding_txid':'b'*64,'funding_output':0,
              'state':'CHANNELD_NORMAL','our_amount_msat':'10000000msat','amount_msat':'20000000msat'}]
            self.frames[alias]['listpeerchannels']['channels']=[{'peer_id':other,'channel_id':'4'*64,'funding_txid':'b'*64,'funding_outnum':0,
              'state':'CHANNELD_NORMAL','htlcs':[],'to_us_msat':'10000000msat','total_msat':'20000000msat',
              'spendable_msat':'9000000msat','receivable_msat':'9000000msat'}]
    async def command(self,argv,**kwargs):
        alias=Path(argv[0]).name;method=argv[-1];self.calls.append((alias,method))
        raw=canonical(self.frames[alias][method]).encode()
        kwargs['on_stdout_raw']({'raw':raw,'bytes':len(raw),'truncated':False,'exit_code':0})
        return raw.decode()
    async def collect(self):
        with (patch.object(c,'text_command',side_effect=self.command),patch('simulator.c_normal_source._context',return_value=self.observation),
             patch('simulator.runtime_startup._read',return_value=({},'5'*64)),patch('simulator.target_epochs.verified_runtime_source',return_value={})):
            return await c.collect(self.store,SimpleNamespace(),self.chain,self.observation,boundary=self.boundary,
              reader=self.reader,member_ids=self.member_ids,context_sha256='f'*64,qualification_sequence=self.qualification,
              runtime_source_sequence=self.runtime_sequence,current_startup_path='/synthetic/private/runtime')
    async def test_empty_actual_reply_shape_is_two_node_component_not_ready(self):
        result=await self.collect();self.assertEqual({(a,m)for a in c.ALIASES for m in c.native.METHODS},set(self.calls))
        self.assertFalse(result['channel_route_observed']);self.assertFalse(result['complete']);self.assertFalse(result['qualified'])
        self.assertEqual(0,result['actual_cln_assets']['total_msat']);self.assertEqual(6,len(result['original_traces']))
        self.assertEqual(0,self.store.db.execute("SELECT count(*)FROM event WHERE kind='financial_operating_readiness'").fetchone()[0])
    async def test_string_native_msat_normalizes_both_owners_without_doublecount(self):
        self.channels();result=await self.collect()
        self.assertTrue(result['channel_route_observed']);self.assertEqual(20000000,result['actual_cln_assets']['total_msat'])
        self.assertEqual(20000000,result['component']['observed_physical_msat']);self.assertFalse(result['financial_readiness'])
    async def test_wrong_native_owner_or_foreign_peer_and_conditional_HTLC_hold(self):
        original=copy.deepcopy(self.frames);self.frames['operator']['getinfo']['id']=self.ids['fixture_peer']
        with self.assertRaises(ValueError):await self.collect()
        self.frames=copy.deepcopy(original);self.channels();self.frames['operator']['listpeerchannels']['channels'][0]['peer_id']='02'+'9'*64
        with self.assertRaises(ValueError):await self.collect()
        self.frames=copy.deepcopy(original);self.channels();self.frames['operator']['listpeerchannels']['channels'][0]['htlcs']=[{'amount_msat':1000}]
        with self.assertRaisesRegex(ValueError,'conditional'):await self.collect()
    async def test_actual_original_trace_replay_rejects_wrong_method_or_command(self):
        result=await self.collect();ref=result['original_traces']['operator:getinfo']
        with self.assertRaises(ValueError):c.replay_original(self.store,ref,alias='operator',method='listfunds',observation=self.observation,command_sha256=self.reader.hashes()['operator']['getinfo'])
        with self.assertRaises(ValueError):c.replay_original(self.store,ref,alias='operator',method='getinfo',observation=self.observation,command_sha256='e'*64)
    async def test_runtime_or_command_identity_change_holds_before_read(self):
        self.reader.commands['operator']['getinfo']=('/synthetic/changed','readonly-cln','getinfo')
        with self.assertRaisesRegex(ValueError,'qualification'):await self.collect()
        self.assertEqual([],self.calls)

    async def test_secret_bearing_reply_never_reaches_public_trace_or_inventory(self):
        self.frames['operator']['getinfo']['payment_preimage']='e'*64
        with self.assertRaises(ValueError):await self.collect()
        self.assertEqual(0,self.store.db.execute("SELECT count(*)FROM event WHERE kind='treasury_inventory'").fetchone()[0])

    async def test_wrong_loaded_context_binding_refuses_before_any_node_read(self):
        self.admission['context_sha256']='e'*64
        self.store.event('c_native_cln_source_qualified',self.admission);self.qualification=self.sequence()
        with self.assertRaisesRegex(ValueError,'qualification'):await self.collect()
        self.assertEqual([],self.calls)

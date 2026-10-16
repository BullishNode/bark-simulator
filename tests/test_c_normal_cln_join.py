"""Real CLN/TraceStore/treasury joins with synthetic native/Core authority.

No live runtime, payment, complete cohort or financial readiness credit.
"""
import copy
import unittest
from types import SimpleNamespace
from unittest.mock import patch, AsyncMock

from simulator import c_normal_cln_join as c
from simulator import c_normal_runtime_source as runtime_source
from simulator.final_campaign import _source_event
from simulator.model import SIGNET_GENESIS, canonical
from tests import test_c_normal_owning_join as fixture


class ClnJoin(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.f = fixture.OwningJoin(); self.f.setUp()
        for function, args, kwargs in self.f._cleanups:
            self.addCleanup(function, *args, **kwargs)
        self.f._cleanups.clear()
        self.store = self.f.store; self.observation = self.f.observation
        self.ids = {'operator':'02'+'1'*64, 'fixture_peer':'03'+'2'*64}
        self.member_ids = {'operator':'operator-cln', 'fixture_peer':'fixture-cln'}
        self.frames = {}; self.members = list(self.f.f.boundary['members'])
        for alias in c.cln.ALIASES:
            member = {'id':self.member_ids[alias], 'kind':'lightning_peer',
                'role':'operator' if alias=='operator' else 'fixture_peer',
                'identity':self.ids[alias], 'descriptors':[]}
            self.store.event('treasury_member_verified', {'member':member,
                'genesis':SIGNET_GENESIS, 'financial_pins':self.observation['financial_pins']})
            self.members.append({**member, 'verification_sequence':self.sequence()})
            self.frames[alias] = {'getinfo':{'id':self.ids[alias], 'network':'signet', 'blockheight':self.observation['height']},
                'listfunds':{'outputs':[], 'channels':[]}, 'listpeerchannels':{'channels':[]}}
        self.boundary = {**self.f.f.boundary, 'members':self.members}
        self.reader = c.cln.FixedClnReads({a:{m:['/synthetic/'+a, 'readonly-cln', m]
            for m in c.cln.native.METHODS} for a in c.cln.ALIASES})
        self.profile = {'schema_version':1, 'mode':'fullnormal_sources',
            'operating_source_sha256':{'captaind':'d'*64, 'watchmand':'e'*64},
            'lightning_context_sha256':'f'*64, 'node_ids':self.ids, 'ordinary_fee_policy_sha256':'1'*64}
        self.f.f.runtime['operating_profile'] = self.profile
        self.store.event('owned_runtime_configuration_verified', self.f.f.runtime)
        self.runtime_sequence = self.sequence(); self.f.f.runtime_sequence = self.runtime_sequence
        safe = self.f.runtime['safe']; event, _ = _source_event(self.store, self.runtime_sequence)
        safe.update(runtime_source_sequence=self.runtime_sequence, runtime_source_event_hash=event['hash'])
        self.store.event(runtime_source.KIND, {k:v for k,v in safe.items() if k!='source_sequence'})
        safe['source_sequence'] = self.sequence()
        self.admission = {'architecture_profile':'direct_per_key', 'financial_pins':self.observation['financial_pins'],
            'node_ids':self.ids, 'context_sha256':'f'*64, 'commands_sha256':self.reader.hashes(),
            'startup_source_sha256':self.f.f.runtime['startup_source_sha256'], 'component_sha256':{
                'adapter':c.cln.digest(c.cln.Path(c.cln.__file__).read_bytes()),
                'native':c.cln.module_hash(c.cln.native.verify_source),
                'shared_cln_projection':c.cln.module_hash(c.cln.cln_projection),
                'native_projection_helpers':c.cln.module_hash(c.cln.native.peer_channel),
                'treasury':c.cln.module_hash(__import__('simulator.treasury', fromlist=['_capture_assets'])._capture_assets)}}
        self.store.event('c_native_cln_source_qualified', self.admission)
        self.binding = c.ClnBinding(self.reader, self.member_ids, 'f'*64, self.sequence())
        self.calls = []

    def sequence(self):
        return self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]

    def count(self, kind):
        return self.store.db.execute('SELECT count(*) FROM event WHERE kind=?', (kind,)).fetchone()[0]

    def replace_runtime_profile(self, value):
        if value is None:self.f.f.runtime.pop('operating_profile', None)
        else:self.f.f.runtime['operating_profile'] = value
        self.store.event('owned_runtime_configuration_verified', self.f.f.runtime)
        sequence = self.sequence(); self.f.f.runtime_sequence = sequence
        event, _ = _source_event(self.store, sequence); safe = self.f.runtime['safe']
        safe.update(runtime_source_sequence=sequence, runtime_source_event_hash=event['hash'])
        self.store.event(runtime_source.KIND, {k:v for k,v in safe.items() if k!='source_sequence'})
        safe['source_sequence'] = self.sequence()

    async def command(self, argv, **kwargs):
        alias = c.cln.Path(argv[0]).name; method = argv[-1]; self.calls.append((alias, method))
        raw = canonical(self.frames[alias][method]).encode()
        kwargs['on_stdout_raw']({'raw':raw, 'bytes':len(raw), 'truncated':False, 'exit_code':0})
        return raw.decode()

    async def owning(self):
        return await self.f.collect()

    async def collect(self, owning=None):
        owning = await self.owning() if owning is None else owning
        with patch.object(c, '_context'), patch('simulator.c_normal_source._context'), \
                patch.object(c.cln, 'text_command', side_effect=self.command):
            return await c.collect(self.store, SimpleNamespace(), self.f.f.chain, self.observation,
                boundary=self.boundary, checked=self.f.checked, runtime=self.f.runtime, owning=owning, binding=self.binding)

    async def test_real_six_CLN_originals_join_four_member_union_without_readiness(self):
        result = await self.collect(); safe = result['safe']
        self.assertEqual({(a,m) for a in c.cln.ALIASES for m in c.cln.native.METHODS}, set(self.calls))
        self.assertEqual(4, len(safe['inventory_sequences']))
        self.assertEqual(100000000, safe['actual_owning_and_cln_assets']['total_msat'])
        self.assertEqual(6, len(safe['original_cln_traces']))
        self.assertFalse(safe['channel_route_observed']); self.assertFalse(safe['complete'])
        self.assertFalse(safe['qualified']); self.assertFalse(safe['financial_readiness'])
        self.assertEqual(0, self.count('financial_operating_readiness'))
        with self.assertRaisesRegex(c.EvidenceGap, 'already collected'):
            await self.collect(result['private_owning_join'])
        self.assertEqual(6, len(self.calls))

    async def test_original_owning_or_runtime_observation_mismatch_refuses_before_CLN(self):
        owning = await self.owning()
        owning['safe']['runtime_source_sequence'] += 1
        with self.assertRaisesRegex(c.EvidenceGap, 'original'):
            await self.collect(owning)
        self.assertEqual([], self.calls)

    async def test_missing_or_foreign_CLN_runtime_profile_is_not_defaulted(self):
        self.replace_runtime_profile(None)
        owning = await self.owning()
        with self.assertRaisesRegex(ValueError, 'fullnormal source profile'):
            await self.collect(owning)
        self.assertEqual([], self.calls)
        self.assertEqual(0, self.count(c.KIND))

    async def test_cached_CLN_component_is_not_new_collection(self):
        owning = await self.owning()
        with patch('simulator.c_normal_source._context'), patch.object(c.cln,'text_command',side_effect=self.command):
            cached = await c.cln.collect(self.store,SimpleNamespace(),self.f.f.chain,self.observation,
                boundary=self.boundary,reader=self.reader,member_ids=self.member_ids,context_sha256='f'*64,
                qualification_sequence=self.binding.qualification_sequence,
                runtime_source_sequence=self.runtime_sequence,current_startup_path=self.f.runtime['safe']['current_startup_path'])
        with patch.object(c.cln, 'collect', new=AsyncMock(return_value=cached)):
            with self.assertRaisesRegex(c.EvidenceGap, 'this invocation'):
                await self.collect(owning)
        self.assertEqual(0, self.count(c.KIND))
        self.assertEqual(6, len(self.calls))

    async def test_declared_node_context_cannot_be_swapped_after_owning_source(self):
        self.replace_runtime_profile({**self.profile,'lightning_context_sha256':'e'*64})
        owning = await self.owning()
        with self.assertRaisesRegex(ValueError,'runtime/source context'):
            await self.collect(owning)
        self.assertEqual([],self.calls)

    async def test_actual_channel_capacity_is_counted_once_across_two_owned_nodes(self):
        owning = await self.owning()
        from tests import test_wallet_projection as w
        core = self.f.f.chain
        txid = core.add(w.transaction(['cc'*32+':0'],[(20000,w.SCRIPTS[3])],nonce=2),3)
        core.coin(txid,0,20000,3,3)
        for alias in c.cln.ALIASES:
            other = self.ids['fixture_peer' if alias=='operator' else 'operator']
            self.frames[alias]['listfunds']['channels'] = [{'peer_id':other,'funding_txid':txid,'funding_output':0,
                'state':'CHANNELD_NORMAL','our_amount_msat':'10000000msat','amount_msat':'20000000msat'}]
            self.frames[alias]['listpeerchannels']['channels'] = [{'peer_id':other,'channel_id':'4'*64,
                'funding_txid':txid,'funding_outnum':0,'state':'CHANNELD_NORMAL','htlcs':[],
                'to_us_msat':'10000000msat','total_msat':'20000000msat',
                'spendable_msat':'9000000msat','receivable_msat':'9000000msat'}]
        result = await self.collect(owning); safe = result['safe']
        self.assertEqual(120000000,safe['actual_owning_and_cln_assets']['total_msat'])
        self.assertEqual(110000000,safe['actual_owning_and_cln_assets']['operator_controlled_msat'])
        self.assertTrue(safe['channel_route_observed']); self.assertFalse(safe['financial_readiness'])

    async def test_fixed_binding_cannot_use_owning_member_or_mutable_reader_override(self):
        owning = await self.owning()
        bad = c.ClnBinding(self.reader, {'operator':'watchman', 'fixture_peer':'fixture-cln'}, 'f'*64, self.binding.qualification_sequence)
        with self.assertRaises(c.EvidenceGap): bad.check()
        self.reader.read = lambda *args: None
        with self.assertRaisesRegex(c.EvidenceGap, 'fixed distinct'):
            await self.collect(owning)
        self.assertEqual([], self.calls)

    async def test_actual_whole_union_rejects_CLN_cash_already_in_owning_wallet(self):
        owning = await self.owning()
        coin = self.f.f.responses['watchman']['watchman']['utxos'][0]
        txid, index = coin['outpoint'].split(':')
        self.frames['operator']['listfunds']['outputs'] = [{'txid':txid, 'output':int(index),
            'amount_msat':coin['value_sat']*1000, 'scriptpubkey':coin['script_pubkey'],
            'status':'confirmed', 'blockheight':998}]
        with self.assertRaisesRegex(ValueError, 'same physical output'):
            await self.collect(owning)
        self.assertEqual(1, self.count(c.cln.KIND)); self.assertEqual(0, self.count(c.KIND))
        self.assertEqual(0, self.count('financial_operating_readiness'))

    async def test_profile_uses_exact_binding_and_missing_binding_holds(self):
        from simulator.c_normal_profile_adapter import DirectPerKeyProfile
        profile = DirectPerKeyProfile.__new__(DirectPerKeyProfile); profile.cln = None
        with self.assertRaisesRegex(c.EvidenceGap, 'not installed'):
            await profile.collect_cln(None,None,None,None,None,None,None,None)
        profile.cln = self.binding; owning = await self.owning()
        with patch.object(c, '_context'), patch('simulator.c_normal_source._context'), \
                patch.object(c.cln, 'text_command', side_effect=self.command):
            result = await profile.collect_cln(self.store,SimpleNamespace(),self.f.f.chain,
                self.observation,self.boundary,self.f.checked,self.f.runtime,owning)
        self.assertEqual(4,len(result['safe']['inventory_sequences']))


if __name__=='__main__':unittest.main()

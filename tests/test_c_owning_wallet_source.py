"""Synthetic transport/runtime/Core; real wallet, trace and treasury reducers."""
import copy
import hashlib
import json
import tempfile
import time
import unittest
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from simulator import c_owning_wallet_source as c
from simulator import confirmed_scan
from simulator.architecture import DIRECT_PER_KEY
from simulator.model import SIGNET_GENESIS, canonical
from simulator.store import Store
from tests import test_wallet_projection as w
from tests.test_final_campaign import PINS
from tests.owned_activity_fixture import capture as capture_activity

WATCH_DESCRIPTOR = 'tr(publicwatch/0/*)#fixture'


class OwningSources(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.store = Store(self.root/'state', 'synthetic-C', architecture_profile=DIRECT_PER_KEY)
        self.store.attach_trace(); self.addCleanup(self.store.close)
        self.observation = {'id':'a'*32,'started_at':time.time(),'architecture_profile':DIRECT_PER_KEY,
            'financial_pins':PINS,'boundary_id':'C-normal-future','height':1000,'tip_hash':w.TIP}
        self.calls = []; self.responses = {}; self.change_after = None; self.extra_scan = False
        self.members = []
        for owner in c.OWNERS:
            member = {'id':owner,'kind':'wallet','role':'operator','identity':'synthetic-owned-'+owner,
                'descriptors':[WATCH_DESCRIPTOR if owner == 'watchman' else 'tr(publicrounds/0/*)#fixture']}
            self.store.event('treasury_member_verified', {'member':member,'genesis':SIGNET_GENESIS,'financial_pins':PINS})
            member['verification_sequence'] = self.sequence(); self.members.append(member)
        self.boundary = {'id':'C-normal-future','genesis':SIGNET_GENESIS,'pins':PINS,'members':self.members,'excluded':[]}
        outer = self
        class Core(w.Core):
            def identity(self):
                return self.call('getblockchaininfo')
            def call(self, method, *args, **kwargs):
                if method == 'deriveaddresses':
                    prefix = 'watch' if args[0] == WATCH_DESCRIPTOR else 'rounds'
                    return [prefix+':'+str(i) for i in range(args[1][0], args[1][1]+1)]
                if method == 'validateaddress':
                    owner, index = args[0].split(':'); index = int(index)
                    script = w.SCRIPTS[index] if owner == 'watch' and index < len(w.SCRIPTS) else '5120'+hashlib.sha256(args[0].encode()).hexdigest()
                    return {'isvalid':True,'scriptPubKey':script}
                if method == 'scantxoutset':
                    if args[0] == 'status': return None
                    coins = [ {'txid':point[0],'vout':point[1],'amount':coin['value'],'scriptPubKey':coin['scriptPubKey']['hex']}
                        for point,coin in self.unspent.items()]
                    if outer.extra_scan:
                        coins.append({'txid':'f'*64,'vout':0,'amount':Decimal('0.00001000'),'scriptPubKey':w.SCRIPTS[2]})
                    result = {'success':True,'height':self.height,'bestblock':self.tip,'unspents':coins,
                        'total_amount':str(sum(v['amount'] for v in coins))}
                    self.last_capture = outer.store.trace_sample({'kind':'chain.rpc','payload':{
                        'method':method,'params':list(args),'result':__import__('simulator.trace',fromlist=['normalized']).normalized(result),'error':None},
                        'raw':canonical(__import__('simulator.trace',fromlist=['normalized']).normalized({'result':result,'error':None})).encode()})
                    return result
                if method == 'getdescriptoractivity':
                    return capture_activity(self, outer.store, args, {'activity':[]})
                return super().call(method, *args)
        self.chain = Core()
        txid = self.chain.add(w.transaction(['bb'*32+':2'], [(50000,w.SCRIPTS[0]),(50000,w.SCRIPTS[1])]), 3)
        self.chain.coin(txid,0,50000,0,3); self.chain.coin(txid,1,50000,1,3)
        for owner in c.OWNERS:
            native = {'wallet':owner,'network':'signet','public_descriptor':self.members[0 if owner=='rounds' else 1]['descriptors'][0],
                'tip_height':1000,'tip_hash':w.TIP,'min_trusted_confirmations':3,'complete':True,
                'reserved_outpoints':[],'last_revealed_index':1,'utxos':[],
                'pending_transaction_scope':'canonical_wallet_graph_only','pending_transactions':[],
                'pending_parents':[],'unavailable_parent_txids':[]}
            if owner == 'watchman':
                native['utxos'] = [w.native_coin(txid+':'+str(i),50000,i,confirmations=3) for i in (0,1)]
            other = 'watchman' if owner == 'rounds' else 'rounds'
            missing = ('watchmand owns its wallet; inventory unavailable from captaind' if owner=='rounds' else
                'captaind owns its rounds wallet; collect its separate source without assuming global atomicity')
            self.responses[owner] = {owner:native,other:None,'complete':False,'missing_sources':[missing]}
        self.reader = c.FixedOwningReader({o:['/synthetic/admitted-fixed-ops','wallet-inventory',o] for o in c.OWNERS}, ops_sha256='c'*64)
        self.runtime = {'product_commit':PINS['product_commit'],'schema_sha256':PINS['schema_sha256'],
            'loaded_configuration_identity_verified':True,'observed_at':time.time(),'startup_source_sha256':'d'*64,
            'current_source_sha256':'e'*64,'daemons':{'captaind':{'binary_sha256':'f'*64},'watchmand':{'binary_sha256':'1'*64}}}
        self.store.event('owned_runtime_configuration_verified', self.runtime); self.runtime_sequence = self.sequence()
        self.admission = {'financial_pins':PINS,'architecture_profile':DIRECT_PER_KEY,
            'producer_sha256':c.digest(Path(c.__file__).read_bytes()), 'validator_sha256':c.digest(c.VALIDATOR.read_bytes()),
            'ops_sha256':self.reader.ops_sha256,'commands_sha256':self.reader.hashes(),
            'startup_source_sha256':self.runtime['startup_source_sha256']}
        self.store.event('c_native_owning_wallet_source_qualified', self.admission); self.qualification_sequence = self.sequence()
        self.patches = [patch('simulator.runtime_startup._read', return_value=({},'e'*64)),
            patch('simulator.target_epochs.verified_runtime_source',return_value=self.runtime),
            patch.object(confirmed_scan,'_identity',return_value={'owners':copy.deepcopy(self.members),'synthetic_runtime':'explicit'})]
        for handle in self.patches: handle.start(); self.addCleanup(handle.stop)

    def sequence(self):
        return self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]

    async def command(self, argv, **kwargs):
        self.calls.append((tuple(argv), kwargs))
        owner = argv[-1]; response = copy.deepcopy(self.responses[owner])
        if self.change_after is not None and len(self.calls)>2:
            self.change_after(response[owner])
        return canonical(response)

    async def invoke(self):
        with patch.object(c, 'text_command', side_effect=self.command):
            return await c.collect(self.store,SimpleNamespace(network='signet',expected_genesis=SIGNET_GENESIS),
                self.chain,self.observation,boundary=self.boundary,reader=self.reader,
                qualification_sequence=self.qualification_sequence,runtime_source_sequence=self.runtime_sequence,
                current_startup_path='/synthetic/private/current-runtime')

    async def test_actual_reducers_preserve_whole_50k_outputs_and_scope(self):
        result = await self.invoke()
        self.assertEqual(4,len(self.calls)); self.assertEqual(100000000,result['actual_owning_wallet_assets']['total_msat'])
        self.assertEqual(100000000,result['watchman_native_fee_eligible_msat'])
        self.assertEqual({'rounds','watchman'},set(result['inventory_sequences']))
        self.assertFalse(result['complete']);self.assertFalse(result['qualified']);self.assertFalse(result['financial_readiness'])
        self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM action').fetchone()[0])
        self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM event WHERE kind='financial_operating_readiness'").fetchone()[0])
        for owner in c.OWNERS:
            _,original = __import__('simulator.final_campaign',fromlist=['_source_event'])._source_event(self.store,result['inventory_source_sequences'][owner])
            self.assertFalse(original['owning_projection']['coverage']['operating_readiness'])
        with self.assertRaisesRegex(ValueError,'already collected'):await self.invoke()

    async def test_unreported_descriptor_output_is_not_filtered(self):
        self.extra_scan=True
        with self.assertRaisesRegex(ValueError,'exhaustive confirmed'):await self.invoke()
        self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM event WHERE kind=?',(c.KIND,)).fetchone()[0])

    async def test_private_unknown_field_and_wrong_owner_refuse_before_original_trace(self):
        self.responses['rounds']['rounds']['private_key']='synthetic-forbidden'
        with self.assertRaises(ValueError):await self.invoke()
        self.assertEqual(1,len(self.calls))
        self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM event WHERE kind=?',(c.KIND,)).fetchone()[0])

    async def test_actual_after_frame_change_and_pending_reservation_hold(self):
        self.change_after=lambda native:native.update(last_revealed_index=2)
        with self.assertRaisesRegex(ValueError,'changed during'):await self.invoke()
        self.change_after=None
        native=self.responses['watchman']['watchman'];coin=native['utxos'][0]
        native['reserved_outpoints']=[coin['outpoint']];coin.update(reserved=True,transaction_eligible=False,confirmed_fee_eligible=False)
        with self.assertRaisesRegex(ValueError,'unreserved'):await self.invoke()

    async def test_wrong_source_qualification_refuses_before_command(self):
        bad=copy.deepcopy(self.admission);bad['ops_sha256']='0'*64
        self.store.event('c_native_owning_wallet_source_qualified',bad);self.qualification_sequence=self.sequence()
        with self.assertRaisesRegex(ValueError,'qualification'):await self.invoke()
        self.assertEqual([],self.calls)

    async def test_wrong_runtime_or_core_tip_refuses_before_command(self):
        bad={**self.runtime,'product_commit':'0'*40};self.store.event('owned_runtime_configuration_verified',bad);self.runtime_sequence=self.sequence()
        with self.assertRaisesRegex(ValueError,'runtime'):await self.invoke()
        self.assertEqual([],self.calls)

    async def test_actual_independent_tip_change_refuses_before_command(self):
        self.chain.tip='2'*64
        with self.assertRaisesRegex(ValueError,'independent synchronized tip'):await self.invoke()
        self.assertEqual([],self.calls)

    async def test_foreign_descriptor_or_raw_prevout_amount_mismatch_holds(self):
        native=self.responses['watchman']['watchman'];descriptor=native['public_descriptor']
        native['public_descriptor']='tr(foreignpublic/0/*)#fixture'
        with self.assertRaisesRegex(ValueError,'owning wallet scope'):await self.invoke()
        native['public_descriptor']=descriptor;native['utxos'][0]['value_sat']+=1
        with self.assertRaisesRegex(ValueError,'Core raw prevout'):await self.invoke()

    async def test_raw_original_hash_is_literal_not_json_reserialization(self):
        async def spaced(argv,**kwargs):
            return json.dumps(self.responses[argv[-1]],indent=2)+'\n'
        with patch.object(c,'text_command',side_effect=spaced):
            result=await c.collect(self.store,SimpleNamespace(network='signet',expected_genesis=SIGNET_GENESIS),
                self.chain,self.observation,boundary=self.boundary,reader=self.reader,
                qualification_sequence=self.qualification_sequence,runtime_source_sequence=self.runtime_sequence,
                current_startup_path='/synthetic/private/current-runtime')
        expected=c.digest((json.dumps(self.responses['watchman'],indent=2)+'\n').encode())
        self.assertEqual(expected,result['original_source_hashes']['before:watchman'])
        self.assertNotEqual(expected,c.digest(canonical(self.responses['watchman']).encode()))

    async def test_runtime_source_changed_during_independent_checks_refuses_inventory_events(self):
        with patch('simulator.runtime_startup._read',side_effect=[({},'e'*64),({},'a'*64)]):
            with self.assertRaisesRegex(ValueError,'runtime source changed'):await self.invoke()
        self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM event WHERE kind='treasury_inventory'").fetchone()[0])

    async def test_trace_original_replays_and_loss_refuses(self):
        result=await self.invoke();reference=result['original_traces']['before:watchman']
        response,raw=c.replay_original(self.store,reference,owner='watchman',phase='before',observation=self.observation)
        self.assertEqual(self.responses['watchman'],response);self.assertEqual(canonical(response).encode(),raw)
        from simulator.trace import partition_paths
        p=next(p for p in partition_paths(self.store.trace.root) if p.name==reference['partition']);missing=p.with_suffix('.missing');p.rename(missing)
        try:
            with self.assertRaisesRegex(ValueError,'missing'):
                c.replay_original(self.store,reference,owner='watchman',phase='before',observation=self.observation)
        finally:missing.rename(p)

    def test_fixed_constructor_rejects_mutating_or_observer_selected_suffix(self):
        for suffix in (['sendrawtransaction','watchman'],['wallet-inventory','foreign'],['wallet-inventory','watchman','extra']):
            with self.subTest(suffix=suffix),self.assertRaises(ValueError):
                c.FixedOwningReader({'rounds':['/fixed','wallet-inventory','rounds'],'watchman':['/fixed',*suffix]},ops_sha256='a'*64)

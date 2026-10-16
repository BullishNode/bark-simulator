"""Synthetic private transcripts/processes; no CLN/payment/source qualification credit."""
import asyncio
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from simulator import cln_router_cost as router
from simulator import c_cln_payment_parts as parts
from simulator.controlled_peer_evidence import action_boundary
from simulator.final_campaign import _source_event
from simulator.model import canonical
from simulator.normal_money_join import journal_money_sources
from simulator.operating_limits import fee_totals
from simulator.ownership import EvidenceGap
from tests import test_final_campaign as fixture_module
from tests.controlled_peer_fixture import NODES, INVOICE, external_send


class RouterSourceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        asyncio.get_running_loop().set_debug(False);asyncio.get_running_loop().slow_callback_duration=10
        self.fixture=fixture_module.FinalEpochEvidenceTests();self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown);self.store=self.fixture.store
        self.secret=bytes(range(32)).hex();self.h=hashlib.sha256(bytes.fromhex(self.secret)).hexdigest()
        self.fee=getattr(self,'fixture_fee',3)
        with patch('tests.controlled_peer_fixture.HASH',self.h): self.external=external_send(self.fixture,router_fee_msat=self.fee)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.evidence=self.root/'evidence';self.evidence.mkdir(mode=0o700)
        self.started=time.time()
        async def rpc(alias,method,params):
            if method=='getinfo':value={'id':NODES[alias],'network':'signet','version':'synthetic'}
            elif method=='listpays':value={'pays':[{'payment_hash':self.h,'bolt11':INVOICE,'status':'complete','preimage':self.secret,
                'amount_msat':1000000,'amount_sent_msat':1000000+self.fee,'completed_at':103,
                'destination':NODES['fixture_peer'],'number_of_parts':2}]}
            elif method=='listinvoices':value={'invoices':[]}
            elif method=='decode':value={'type':'bolt11 invoice','valid':True,'payment_hash':self.h,'currency':'tbs',
                'payee':NODES['fixture_peer'],'amount_msat':1000000}
            elif method=='listsendpays':value={'payments':[{'id':i,'created_index':i,'groupid':7,'partid':i,'payment_hash':self.h,
                'status':'complete','created_at':100,'amount_msat':500000,'amount_sent_msat':500000+fee,
                'destination':NODES['fixture_peer'],'payment_preimage':self.secret} for i,fee in ([(1,1),(2,self.fee-1)]if self.fee else [(1,0),(2,0)])]}
            else:raise AssertionError(method)
            return canonical(value).encode()
        self.rpc=rpc
        self.original=await parts.CompletedPartsReader(rpc,node_ids=NODES,network='signet').read('operator',self.h)
        originals=[{k:r[k] for k in ('alias','method','params')} | {'raw_hex':r['raw'].hex()} for r in self.original['private_originals']]
        self.template={'schema_version':1,'request_sha256':'0'*64,'source_program_sha256':router._components()['source_program'],'source_configuration_sha256':'b'*64,
                       'query_times':self.original['query_times'],'originals':originals}
        self.helper=self.root/'synthetic_reader.py'
        # Real bounded process invocation, but its native replies are synthetic.
        self.helper.write_text('import sys,json,hashlib,time\nr=json.loads(sys.stdin.readline())\nv='+repr(self.template)+
            '\nv["request_sha256"]=hashlib.sha256((json.dumps(r,sort_keys=True,separators=(",",":"))+"\\n").encode()).hexdigest()\nv["query_times"]=[time.time()]*4\nprint(json.dumps(v))\n')
        self.config={'command':[sys.executable,str(self.helper)],'evidence_directory':str(self.evidence),'timeout':10}
        self.admitted=self.current_event('normal_financial_collector_qualified',{'financial_pins':fixture_module.PINS,
            'router_cost':{'configuration':self.config,'component_sha256':router._components(),'source_program_sha256':router._components()['source_program'],'source_configuration_sha256':'b'*64}})
        self.started=time.time()
        observation={'id':'1'*32,'started_at':self.started,'architecture_profile':'direct-per-key',
            'financial_pins':fixture_module.PINS,'boundary_id':'synthetic-external','height':10,'tip_hash':'2'*64}
        self.normal=self.current_event('normal_financial_source',{'financial_pins':fixture_module.PINS,
            'boundary_id':'synthetic-external','source_observation':observation,'height':10,'tip_hash':'2'*64})

    def current_event(self,kind,payload):
        self.store.event(kind,payload)
        return self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]

    async def capture(self):
        return await router.RouterCostProducer(self.admitted).collect(self.store,source_sequence=self.normal,external_sequence=self.external)

    def cost(self,source):
        proof=source['source']
        return {k:proof[k] for k in ('monetary_id','kind','amount_msat','budget','source','destination','financial_pins')} | {'router_source_sequence':source['source_sequence']}

    async def test_actual_private_process_and_exact_replay_are_source_only(self):
        result=await self.capture();safe=router.verify_source(self.store,result['source_sequence'])
        self.assertEqual(3,safe['amount_msat']);self.assertTrue(safe['monetary_id'].endswith(':7'))
        self.assertNotIn(self.secret,canonical(safe));self.assertNotIn(INVOICE,canonical(safe))
        self.assertNotIn('action_id',self.cost(result));self.assertFalse(result['financial_admission'])
        self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM event WHERE kind='financial_cost_verified'").fetchone()[0])

    async def test_concrete_fixed_cli_source_and_private_transport_replay_end_to_end(self):
        from simulator.cln_router_source import FixedClnRpc
        replies={r['method']:r['raw'].decode()for r in self.original['private_originals']}
        binary=self.root/'synthetic-lightning-cli'
        binary.write_text('#!'+sys.executable+'\nimport sys\nreplies='+repr(replies)+
            '\ni=sys.argv.index("-k")+1\nassert sys.argv[i] in replies\nprint(replies[sys.argv[i]])\n')
        binary.chmod(0o700);node=self.root/'existing-synthetic-node';node.mkdir(mode=0o700)
        cfg={'schema_version':1,'node_alias':'operator','node_ids':NODES,'network':'signet',
             'lightning_cli':str(binary),'lightning_cli_sha256':router.digest(binary.read_bytes()),'lightning_dir':str(node)}
        path=self.root/'fixed-cln-source.json';path.write_text(canonical(cfg));path.chmod(0o600)
        config_sha=router.digest(path.read_bytes())
        fixed=FixedClnRpc(path,config_sha)
        for method,params in [('pay',{}),('invoice',{}),('listsendpays',{'payment_hash':self.h,'limit':1})]:
            with self.assertRaises(ValueError):await fixed.read('operator',method,params)
        self.config['command']=[sys.executable,'-m','simulator.cln_router_source',str(path),config_sha]
        self.admitted=self.current_event('normal_financial_collector_qualified',{'financial_pins':fixture_module.PINS,
            'router_cost':{'configuration':self.config,'component_sha256':router._components(),
                'source_program_sha256':router._components()['source_program'],'source_configuration_sha256':config_sha}})
        _,old_source=_source_event(self.store,self.normal)
        source=copy.deepcopy(old_source);source['source_observation']['started_at']=time.time();source['source_observation']['id']='4'*32
        self.normal=self.current_event('normal_financial_source',source)
        result=await self.capture();checked=router.verify_source(self.store,result['source_sequence'])
        self.assertEqual(3,checked['amount_msat']);self.assertEqual(2,len(checked['parts']['complete_parts']))
        binary.write_text(binary.read_text()+'# changed\n')
        with self.assertRaises(ValueError):await fixed.read('operator','getinfo',{})

    async def test_positive_original_controlled_proof_without_any_certificate_holds(self):
        with self.assertRaisesRegex(EvidenceGap,'known positive controlled payer'):
            router.require_routing_readiness(self.store)
        self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM event WHERE kind=?',(router.KIND,)).fetchone()[0])

    async def test_fixed_cli_stream_excess_refuses_before_json_or_whole_reply(self):
        from simulator.cln_router_source import FixedClnRpc
        # Only the fixed private process drain is exercised, no CLN RPC.
        reader=object.__new__(FixedClnRpc)
        for pipe in ('stdout','stderr'):
            program='import sys;sys.'+pipe+'.write("x"*300000);sys.'+pipe+'.flush()'
            with self.assertRaises(ValueError):await asyncio.wait_for(reader._run([sys.executable,'-c',program]),timeout=3)

    async def test_fixed_cli_cancellation_reaps_its_actual_process(self):
        import os
        from simulator.cln_router_source import FixedClnRpc
        reader=object.__new__(FixedClnRpc);pid_path=self.root/'synthetic-child.pid'
        program='import os,time;from pathlib import Path;Path('+repr(str(pid_path))+').write_text(str(os.getpid()));time.sleep(600)'
        task=asyncio.create_task(reader._run([sys.executable,'-c',program]))
        try:
            async with asyncio.timeout(2):
                while not pid_path.exists():await asyncio.sleep(0.01)
            pid=int(pid_path.read_text());task.cancel()
            with self.assertRaises(asyncio.CancelledError):await asyncio.wait_for(task,timeout=3)
            with self.assertRaises(ProcessLookupError):os.kill(pid,0)
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task,return_exceptions=True)

    async def test_sync_replay_exactly_equals_frozen_async_replay(self):
        expected=await parts.replay(self.original['private_originals'],alias='operator',payment_hash=self.h,node_ids=NODES,
            network='signet',query_times=self.original['query_times'])
        self.assertEqual(expected,router.replay_exact(self.original['private_originals'],alias='operator',payment_hash=self.h,
            node_ids=NODES,query_times=self.original['query_times']))

    async def test_raw_private_reply_changed_after_capture_refuses(self):
        result=await self.capture();safe=result['source'];path=self.evidence/safe['capture_id']/'source.tar'
        body=json.loads(path.read_bytes());body['originals'][-1]['raw_hex']=b'{}'.hex();path.write_text(canonical(body))
        with self.assertRaises((ValueError,EvidenceGap,KeyError)):router.verify_source(self.store,result['source_sequence'])

    async def test_nonce_and_native_ancestry_cannot_be_swapped(self):
        result=await self.capture()
        self.store.db.execute("UPDATE action SET args=? WHERE id='external'",(canonical({'invoice':'other','amount_sat':1000}),))
        with self.assertRaises(ValueError):router.verify_source(self.store,result['source_sequence'])

    async def test_observed_positive_expense_joins_once_but_launch_stays_held(self):
        result=await self.capture();cost=self.cost(result);parent,source=_source_event(self.store,self.normal)
        payload={'cost_records':[cost],'flow_records':[],'reused_cost_ids':[],'reused_flow_ids':[],
                 'evidence_hashes':{},'zero_fee_carriers':{},'pending_carriers':{}}
        with self.assertRaises(EvidenceGap):router.require_routing_readiness(self.store)
        _,joined=journal_money_sources(self.store,payload,parent,source,helper_sha256='a'*64)
        journal_money_sources(self.store,payload,parent,source,helper_sha256='a'*64)
        self.assertEqual(1,self.store.db.execute("SELECT count(*) FROM event WHERE kind='financial_cost_verified'").fetchone()[0])
        self.assertEqual(3,fee_totals(self.store,fixture_module.PINS)['ordinary'])
        with self.assertRaisesRegex(EvidenceGap,'miner-only 2000'):router.require_routing_readiness(self.store)
        from simulator.two_step_normal import verified_money
        class NoCore:
            def transaction(self,txid):raise AssertionError('router expense must never enter Bitcoin miner cost lookup')
        flows,bitcoin_costs=verified_money(self.store,NoCore(),joined)
        self.assertEqual({},bitcoin_costs);self.assertEqual([3],[v['amount_msat']for v in flows])
        from simulator.treasury import reconcile_edge
        edge=reconcile_edge({'total_msat':1000},{'total_msat':997,'operator_controlled_msat':997},flows,[],
            {'operator':{'role':'operator'},'fixture_peer':{'role':'fixture_peer'}})
        self.assertEqual(3,edge['miner_router_cost_msat'])
        from simulator.financial_transition import _original_cost
        cost_sequence=joined['cost_sequences'][0]
        self.assertEqual(cost,_original_cost(self.store,cost_sequence)[1])
        found=router.collect_cost_records(self.store,fixture_module.PINS)
        self.assertEqual([],found['cost_records']);self.assertEqual([cost['monetary_id']],found['reused_cost_ids'])

    async def test_routing_debit_cannot_be_truncated_or_absorb_queued_action_hold(self):
        result=await self.capture();cost=self.cost(result)
        self.store.event('financial_cost_verified',cost)
        self.fixture.action('held','pay_invoice',at=104,data={},args={})
        self.store.db.execute("UPDATE action SET state='queued',fee_reservation_sat=2 WHERE id='held'")
        self.assertEqual(2003,fee_totals(self.store,fixture_module.PINS)['ordinary'])
        with self.assertRaises(EvidenceGap):router.require_routing_readiness(self.store)
        for changes in ({'amount_msat':1},{'budget':'urgent'},{'source':'fixture_peer'},{'financial_pins':{}}):
            with self.assertRaises(ValueError):router.verify_cost(self.store,cost|changes)

    async def test_duplicate_observation_is_once_only_and_global_id_collision_refuses(self):
        first=await self.capture();second=await self.capture()
        self.assertNotEqual(first['source_sequence'],second['source_sequence'])
        found=router.collect_cost_records(self.store,fixture_module.PINS)
        self.assertEqual(1,len(found['cost_records']))
        self.assertEqual(first['source_sequence'],found['cost_records'][0]['router_source_sequence'])
        cost=found['cost_records'][0]
        self.store.event('treasury_flow_verified',{'monetary_id':cost['monetary_id'],'kind':'internal_transfer',
            'amount_msat':3,'source':'operator','destination':'fixture_peer','financial_pins':fixture_module.PINS})
        parent,source=_source_event(self.store,self.normal)
        payload={'cost_records':[cost],'flow_records':[],'reused_cost_ids':[],'reused_flow_ids':[],
                 'evidence_hashes':{},'zero_fee_carriers':{},'pending_carriers':{}}
        count=self.store.db.execute('SELECT count(*) FROM event').fetchone()[0]
        with self.assertRaisesRegex(ValueError,'identity/pins'):
            journal_money_sources(self.store,payload,parent,source,helper_sha256='a'*64)
        self.assertEqual(count,self.store.db.execute('SELECT count(*) FROM event').fetchone()[0])

    async def test_authenticated_overlay_preserves_old_source_without_redebit(self):
        result=await self.capture();cost=self.cost(result);self.store.event('financial_cost_verified',cost)
        old=dict(fixture_module.PINS);new=old|{'sdk_commit':'e'*40}
        limits={'id':'old','pins':old,'fee_budgets_msat':{'ordinary':60000000,'urgent':40000000}}
        self.store.db.execute('INSERT INTO meta VALUES (?,?)',('financial_operating_envelope',canonical(limits)))
        self.fixture.event('financial_operating_envelope_declared',{'declaration':limits})
        from simulator.preserved_treasury_upgrade import _originals, _cost_key
        originals=_originals(self.store)
        new_boundary={**originals[0][0],'id':'new-boundary','pins':new}
        cost_event=self.store.db.execute("SELECT sequence,hash FROM event WHERE kind='financial_cost_verified'").fetchone()
        self.fixture.event('preserved_treasury_upgrade_verified',{'costs':[{'sequence':cost_event[0],'hash':cost_event[1]}],'previous_boundary':originals[0][1],
            'previous_envelope':originals[1][1],'sources':[],'boundary':new_boundary,'envelope':limits|{'id':'new','pins':new}})
        checked=router.verify_source(self.store,result['source_sequence'])
        self.assertEqual(old,checked['financial_pins']);self.assertEqual(_cost_key(cost),('other',cost['monetary_id']))
        self.assertEqual(3,fee_totals(self.store,new)['ordinary'])
        found=router.collect_cost_records(self.store,new)
        self.assertEqual([],found['cost_records']);self.assertEqual([cost['monetary_id']],found['reused_cost_ids'])
        from simulator.two_step_normal import verified_money
        self.fixture.event('financial_operating_readiness',{'preserved_history_opening':{
            'historical_cost_sequences':[self.store.db.execute("SELECT sequence FROM event WHERE kind='financial_cost_verified'").fetchone()[0]],
            'historical_flow_sequences':[]}})
        opening={'declaration':{'readiness_sequence':self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]}}
        source={'cost_sequences':[self.store.db.execute("SELECT sequence FROM event WHERE kind='financial_cost_verified'").fetchone()[0]],'flow_sequences':[]}
        flows,miners=verified_money(self.store,object(),source,opening=opening)
        self.assertEqual([],flows);self.assertEqual({},miners)
        self.assertEqual(new_boundary,action_boundary(self.store,{'created_at':time.time()+1},new))

    async def test_failed_process_produces_no_source_certificate(self):
        self.helper.write_text('import sys\nsys.exit(7)\n')
        before=self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
        with self.assertRaises(ValueError):await self.capture()
        self.assertEqual(before,self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0])

    async def test_wrong_source_program_and_missing_admission_hold(self):
        self.helper.write_text(self.helper.read_text().replace("'a'*64","'b'*64"))
        # The fixture literal contains an expanded digest.
        self.helper.write_text(self.helper.read_text().replace(router._components()['source_program'],'c'*64))
        with self.assertRaises(ValueError):await self.capture()
        with self.assertRaises(EvidenceGap):await router.RouterCostProducer(self.external).collect(self.store,source_sequence=self.normal,external_sequence=self.external)

    async def test_source_proof_cannot_cover_independent_native_client_fee(self):
        result=await self.capture();cost=self.cost(result);cost['action_id']='external'
        with self.assertRaisesRegex(ValueError,'native action coverage is separate'):router.verify_cost(self.store,cost)

    async def test_retained_old_action_uses_original_boundary_not_current_overlay(self):
        action=self.store.db.execute("SELECT * FROM action WHERE id='external'").fetchone()
        original=action_boundary(self.store,action,fixture_module.PINS)
        with patch('simulator.treasury.boundary',return_value={'pins':{'sdk_commit':'f'*40},'members':[]}):
            result=await self.capture();checked=router.verify_source(self.store,result['source_sequence'])
        self.assertEqual(original['id'],'synthetic-external');self.assertEqual(3,checked['amount_msat'])

    async def test_foreign_group_and_reordered_private_calls_refuse(self):
        for change in ('group','order'):
            rows=copy.deepcopy(self.original['private_originals'])
            if change=='order':rows[0],rows[1]=rows[1],rows[0]
            else:
                i=next(i for i,r in enumerate(rows)if r['method']=='listsendpays')
                body=json.loads(rows[i]['raw']);body['payments'][1]['groupid']=8;rows[i]['raw']=canonical(body).encode()
            with self.assertRaises((ValueError,EvidenceGap)):
                router.replay_exact(rows,alias='operator',payment_hash=self.h,node_ids=NODES,query_times=self.original['query_times'])


class ZeroRouterSourceTests(unittest.IsolatedAsyncioTestCase):
    fixture_fee=0
    asyncSetUp=RouterSourceTests.asyncSetUp
    current_event=RouterSourceTests.current_event
    capture=RouterSourceTests.capture

    async def test_zero_payment_has_separate_complete_proof_and_no_positive_expense(self):
        result=await self.capture();self.assertTrue(result['zero_fee'])
        safe=router.verify_source(self.store,result['source_sequence']);self.assertEqual(0,safe['amount_msat'])
        result=router.collect_cost_records(self.store,fixture_module.PINS)
        self.assertEqual([],result['cost_records']);self.assertEqual(1,len(result['zero_fee_router_payments']))
        router.require_routing_readiness(self.store)
        with self.assertRaises(ValueError):router.cost_record(safe,1)

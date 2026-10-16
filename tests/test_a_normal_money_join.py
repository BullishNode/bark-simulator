"""Journal-only controls; supplied test records are not financial proof."""
import copy,tempfile,unittest
from pathlib import Path
from simulator.store import Store
from simulator.final_campaign import _source_event
from simulator.normal_money_join import journal_money_sources
from tests.test_final_campaign import PINS

class JoinTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name),'money-source-journal',10000)
        self.source={'financial_pins':PINS,'source_observation':{'id':'a'*32},'cost_sequences':[],'flow_sequences':[]}
        self.store.event('normal_financial_source',self.source);self.event,_=_source_event(self.store,1)
        self.cost={'monetary_id':'miner:'+'b'*64,'kind':'miner_cost','txid':'b'*64,'amount_msat':1030000,'budget':'ordinary','source':'backing','destination':'miners','financial_pins':PINS}
        self.result={'cost_records':[self.cost],'flow_records':[],'zero_fee_carriers':{},'pending_carriers':{},'reused_cost_ids':[],'reused_flow_ids':[],'evidence_hashes':{}}
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def test_append_only_join_preserves_original_source_and_cost_dedup(self):
        event,source=journal_money_sources(self.store,self.result,self.event,self.source,helper_sha256='c'*64)
        self.assertEqual(self.source,_source_event(self.store,1)[1]);self.assertEqual(1,len(source['cost_sequences']))
        self.result['reused_cost_ids']=[self.cost['monetary_id']]
        journal_money_sources(self.store,self.result,self.event,self.source,helper_sha256='c'*64)
        self.assertEqual(1,self.store.db.execute("SELECT count(*)FROM event WHERE kind='financial_cost_verified'").fetchone()[0]);self.store.verify_event_chain()
    def test_changed_old_record_wrongpins_duplicate_and_zero_expense_refuse(self):
        journal_money_sources(self.store,self.result,self.event,self.source,helper_sha256='c'*64)
        self.result['cost_records'][0]={**self.cost,'amount_msat':1031000}
        with self.assertRaisesRegex(ValueError,'rewritten'):journal_money_sources(self.store,self.result,self.event,self.source,helper_sha256='c'*64)
        self.result['cost_records']=[self.cost,self.cost]
        with self.assertRaisesRegex(ValueError,'twice'):journal_money_sources(self.store,self.result,self.event,self.source,helper_sha256='c'*64)
        self.result['cost_records']=[{**self.cost,'amount_msat':0}]
        with self.assertRaises(ValueError):journal_money_sources(self.store,self.result,self.event,self.source,helper_sha256='c'*64)
    def test_zero_fee_carrier_evidence_is_not_a_positive_budget_expense(self):
        self.result['cost_records']=[];self.result['zero_fee_carriers']={'b'*64:{'txid':'b'*64,'fee_sat':0}}
        _,source=journal_money_sources(self.store,self.result,self.event,self.source,helper_sha256='c'*64)
        self.assertEqual([],source['cost_sequences']);self.assertEqual(self.result['zero_fee_carriers'],source['zero_fee_carriers'])


class VerifiedMoneyIntegrationTests(unittest.TestCase):
    """Real Store/raw-wire component join; not native or live qualification."""
    def setUp(self):
        from tests import test_normal_money_sources as source_controls
        self.fixture=source_controls.Controls();self.fixture.setUp()
        self.sources=source_controls
    def tearDown(self):self.fixture.tearDown()
    def prepare(self,zero=False):
        from simulator import two_step_normal as adapter
        f=self.fixture
        if zero:
            raw=self.sources.wire([(f.pid,0)],[(1000,b'\x51')])
            f.chain=self.sources.Chain([f.parent,raw]);f.native('ProgressParent',0,raw)
        else:f.native()
        self.txid=next(iter(f.chain.values.keys()-{f.pid}))
        f.chain.transaction=lambda txid:{'txid':txid,'confirmations':1,'blockhash':self.sources.TIP,'fee_sat':0 if zero else 100}
        source={'financial_pins':self.sources.PINS,'flow_sequences':[],'cost_sequences':[], 'injection_declaration_hashes':[]}
        f.store.event('normal_financial_source',source)
        sequence=f.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
        event,_=_source_event(f.store,sequence)
        result=f.collect()
        _,joined=journal_money_sources(f.store,result,event,source,helper_sha256=adapter.module_hash(adapter.collect_money_sources))
        return adapter,result,joined,event,source
    def test_raw_native_cost_journals_once_and_original_source_remains_unchanged(self):
        adapter,result,joined,event,source=self.prepare();f=self.fixture
        self.assertEqual(source,_source_event(f.store,event['sequence'])[1])
        flows,costs=adapter.verified_money(f.store,f.chain,joined)
        self.assertEqual(100000,costs[self.txid]['amount_msat']);self.assertEqual(1,len(flows))
        self.assertEqual(['miner:'+self.txid],f.collect()['reused_cost_ids'])
        self.assertEqual(1,f.store.db.execute("SELECT count(*)FROM event WHERE kind='financial_cost_verified'").fetchone()[0])
    def test_zero_confirmed_parent_has_no_expense_and_changed_independent_fee_refuses(self):
        adapter,result,joined,_,_=self.prepare(zero=True);f=self.fixture
        fee={'ordinary_booked_sat':0,'urgent_booked_sat':0}
        held,_=adapter.native_fee_exposure(f.tables,fee,f.chain,{},store=f.store,zero_fee_carriers=result['zero_fee_carriers'])
        self.assertEqual({'ordinary':0,'urgent':0},held);self.assertEqual([],joined['cost_sequences'])
        f.chain.transaction=lambda txid:{'txid':txid,'confirmations':1,'blockhash':self.sources.TIP,'fee_sat':1}
        with self.assertRaisesRegex(ValueError,'zero fee differs'):
            adapter.native_fee_exposure(f.tables,fee,f.chain,{},store=f.store,zero_fee_carriers=result['zero_fee_carriers'])
    def test_detached_zero_body_or_confirmation_does_not_satisfy_physical_coverage(self):
        adapter,result,_,_,_=self.prepare(zero=True);f=self.fixture
        bad=copy.deepcopy(result['zero_fee_carriers']);bad[self.txid]['raw_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'zero fee differs'):adapter.verified_zero_carriers(f.chain,bad)
        f.chain.values[self.txid]['confirmations']=0
        with self.assertRaisesRegex(ValueError,'zero fee differs'):adapter.verified_zero_carriers(f.chain,result['zero_fee_carriers'])

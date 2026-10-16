"""Synthetic wire/Store controls; no native witness, Core or readiness credit."""
import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from simulator import c_native_fee_sources as c
from simulator.bundle_audit import decode_transaction
from simulator.final_campaign import _source_event
from simulator.model import SIGNET_GENESIS,canonical
from simulator.store import Store
from tests.test_final_campaign import PINS

# Qualification may point at the separately frozen shared importer source.
# No runtime/product path or A-owned checkout is baked into this contribution.
JOIN_SOURCE=os.environ.get('C_SHARED_MONEY_JOIN_SOURCE')
JOIN_SPEC=importlib.util.find_spec('simulator.normal_money_join')
JOIN=pathlib.Path(JOIN_SOURCE or JOIN_SPEC.origin)if JOIN_SOURCE or JOIN_SPEC else None
JOIN_SHA='a7b3557131cb0270301c977fd807267291d9385470244e2158bf4b85cb7aa48c'
TIP='b'*64;KEY='02'+'1'*64

def encoded(value):return json.dumps(value,separators=(',',':'),ensure_ascii=False).encode()
def wire(inputs,outputs,witness=False):
    raw=(2).to_bytes(4,'little')+(b'\x00\x01'if witness else b'')+bytes([len(inputs)])
    for txid,vout in inputs:raw+=bytes.fromhex(txid)[::-1]+vout.to_bytes(4,'little')+b'\0'+b'\xff'*4
    raw+=bytes([len(outputs)])
    for amount,script in outputs:raw+=amount.to_bytes(8,'little')+bytes([len(script)])+script
    if witness:
        for _ in inputs:raw+=b'\x01\x40'+b'\x00'*64
    return raw+b'\0'*4

class Core:
    def __init__(self,raws):
        self.values={decode_transaction(v.hex())['txid']:{'txid':decode_transaction(v.hex())['txid'],'hex':v.hex(),'confirmations':1,'blockhash':TIP}for v in raws}
    def identity(self):return {'chain':'signet','blocks':100,'bestblockhash':TIP,'initialblockdownload':False}
    def call(self,method,*args):
        assert method=='getblockhash';return SIGNET_GENESIS if args==(0,)else TIP
    def tx(self,txid):return copy.deepcopy(self.values[txid])

class CNativeFeeSources(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=Store(pathlib.Path(self.tmp.name),'synthetic-C-fee',60000);self.addCleanup(self.store.close);self.store.attach_trace()
        self.config=SimpleNamespace(closed_frontier_schema=2,architecture_profile='direct_per_key',trace_enabled=True,network='signet',expected_genesis=SIGNET_GENESIS,expected_server_pubkey=KEY)
        member={'id':'watchman','kind':'wallet','role':'operator','identity':'synthetic-own-watch','descriptors':['synthetic-public-descriptor']}
        self.store.event('treasury_member_verified',{'member':member,'genesis':SIGNET_GENESIS,'financial_pins':PINS})
        self.member={**member,'verification_sequence':1};self.root={'device':1,'inode':2,'uid':1000,'mode':448}
        self.parent=wire([('0'*64,4294967295)],[(25000,bytes.fromhex('5120'+'5'*64))]);self.pid=decode_transaction(self.parent.hex())['txid']
        self.raw=wire([(self.pid,0)],[(24000,bytes.fromhex('5120'+'3'*64)),(900,bytes.fromhex('5120'+'4'*64))],True)
        self.txid=decode_transaction(self.raw.hex())['txid'];self.chain=Core([self.parent,self.raw]);point=self.pid+':0'
        allocation={'id':point,'freeze_set':'synthetic-freeze','owner_pubkey':KEY,'spk':'5120'+'3'*64,'disposition':'pay','gross_sat':25000,'fee_sat':1000,'payout_sat':24000,'forfeited_sat':0,'source':'registered','retirement_ids':[point],'frozen_at':'synthetic'}
        row={'txid':self.txid,'generation':1,'backing_ids':[point],'fee_inputs':[],'miner_fee_sat':100,'funding_subsidy_sat':0,'confirmed_height':100,'confirmed_block':TIP}
        self.database={'schema_version':2,'architecture_profile':'direct_per_key','fallback_protocol':4,'declared_financial_pins':PINS,'database_tables_complete':True,'inventory_consistent':True,'read_only':True,'complete':False,'qualified':False,'snapshot':'synthetic-fixed-RR','rows':{'journal_carriers':[row],'journal_allocations':[allocation],'journal_mappings':[{'txid':self.txid,'allocation_id':point,'vout':0}]}}
        aw=encoded({'id':point,'owner':'\\x'+KEY,'spk':'\\x'+allocation['spk'],'disposition':'pay','gross':25000,'fee':1000,'payout':24000,'forfeited':0,'source':'registered','evidence':{'synthetic':True},'retirement':[point]}).decode()
        cw=encoded({'generation':1,'backing':[point],'fee_inputs':[],'miner':100,'subsidy':0,'mappings':[{'id':point,'vout':0}]}).decode()
        self.record={'freeze_set':'synthetic-freeze','tx':list(self.raw),'allocation_hash':c.digest(c._native_vec([aw])),'carrier_hash':c.digest(cw.encode())}
        self.policy=encoded({'urgent_reserve_sat':40000,'ordinary_budget_sat':58000})
        self.cut={'schema_version':1,'root_identity':self.root,'identity_hex':encoded({'version':1,'genesis':c.NATIVE_SIGNET_CHAIN_HASH,'server_pubkey':KEY}).hex(),'policy_hex':self.policy.hex(),'budget_hex':b'20000\n'.hex(),'history_hex':(self.txid+'\n').encode().hex(),'records':{self.txid:encoded(self.record).hex()},'allocation_witnesses':{'synthetic-freeze':[aw]},'carrier_witnesses':{self.txid:cw},'database_snapshot':self.database['snapshot']}
        self.check={'txid':self.txid,'freeze_set':'synthetic-freeze','physical_inputs':[point],'carrier_versions':[self.txid],'accounting':{'synthetic':True}}
        self.store.event('direct_payment_checked',self.check)
    def source(self):
        self.private=encoded(self.cut)
        self.body={'financial_pins':PINS,'source_observation':{'id':'a'*32,'architecture_profile':'direct_per_key','financial_pins':PINS,'started_at':time.time(),'height':100,'tip_hash':TIP},'private_native_fee_sha256':c.digest(self.private),'native_history_root_identity':self.root,'native_fee_policy_sha256':c.digest(self.policy),'direct_carrier_max_miner_fee_sat':20000,'database':copy.deepcopy(self.database),'direct_carrier_cost_member':'watchman','members':[self.member]}
        self.store.event('closed_cohort_original_source',{'source_kind':'closed_frontier','financial_pins':PINS,'response':copy.deepcopy(self.database),'response_sha256':hashlib.sha256(canonical(self.database).encode()).hexdigest()})
        self.body['database_source_sequence']=self.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
        self.store.event('normal_financial_source',self.body);self.event,_=_source_event(self.store,self.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0])
    def collect(self):
        self.source()
        # Real immutable event/digest/schema routing; only installed worker is a double.
        with patch('simulator.frontier_source._run_sync',side_effect=lambda request:request['frame']):
            return c.collect_cost_records(self.store,self.chain,config=self.config,private_cut=self.private,source_event=self.event,source=self.body,expected_history_identity=self.root,expected_policy_sha256=c.digest(self.policy),expected_server_pubkey=KEY)
    def join(self,result):
        if JOIN is None:raise unittest.SkipTest('separately frozen shared money importer not installed')
        if not JOIN.is_file()or c.digest(JOIN.read_bytes())!=JOIN_SHA:raise AssertionError('exact shared importer dependency unavailable/changed')
        spec=importlib.util.spec_from_file_location('simulator.normal_money_join',JOIN);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with patch.dict(sys.modules,{'simulator.normal_money_join':module}):return c.journal_cost_records(self.store,result,self.event,self.body)
    def test_actual_wire_fee_and_reservation_are_disjoint_then_existing_join_costs_once(self):
        value=self.collect();self.assertEqual(value['cost_records'][0]['amount_msat'],100000);self.assertEqual(value['cost_records'][0]['source'],'watchman')
        self.assertEqual(value['native_fee']['ordinary_booked_sat'],20000);self.assertEqual(value['native_fee']['ordinary_held_sat'],19900)
        self.assertIsNone(value['native_fee']['urgent_fee_cost_coverage']);self.join(value)
        again=self.collect();self.assertEqual([],again['cost_records']);self.assertEqual(again['reused_cost_ids'],['miner:'+self.txid]);self.join(again)
        self.assertEqual(1,self.store.db.execute("SELECT count(*)FROM event WHERE kind='financial_cost_verified'").fetchone()[0]);self.store.verify_event_chain()
    def test_legacy_C_miner_ID_is_reused_without_second_physical_cost(self):
        ident='bitcoin-miner:'+self.txid
        self.store.event('financial_cost_verified',{'monetary_id':ident,'financial_pins':PINS,'budget':'ordinary','amount_msat':100000,'mining_fee_sat':100,'direct_payment_sequence':2})
        value=self.collect();self.assertEqual(value['cost_records'],[]);self.assertEqual(value['reused_cost_ids'],[ident]);self.join(value)
        self.assertEqual(1,self.store.db.execute("SELECT count(*)FROM event WHERE kind='financial_cost_verified'").fetchone()[0])
    def test_duplicate_physical_TXID_under_both_historical_spellings_refuses(self):
        for prefix in ('miner:','bitcoin-miner:'):self.store.event('financial_cost_verified',{'monetary_id':prefix+self.txid,'financial_pins':PINS,'budget':'ordinary','amount_msat':100000})
        with self.assertRaisesRegex(ValueError,'physical miner'):self.collect()
    def test_torn_noncanonical_budget_exhaustion_and_missing_construction_reservation_refuse(self):
        for budget in (b'20000',b'020000\n',b'0\n',b'20000\n20000\n20000\n',b''):
            self.cut['budget_hex']=budget.hex()
            with self.subTest(budget=budget),self.assertRaises(ValueError):self.collect()
    def test_missing_record_pg_row_index_or_private_witness_never_means_empty(self):
        original=copy.deepcopy(self.cut)
        for field,value in [('records',{}),('history_hex',''),('allocation_witnesses',{}),('carrier_witnesses',{})]:
            self.cut=copy.deepcopy(original);self.cut[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.collect()
        self.cut=original;self.database['rows']['journal_carriers']=[]
        with self.assertRaises(ValueError):self.collect()
    def test_changed_native_witness_or_public_allocation_owner_refuses(self):
        original=copy.deepcopy(self.cut)
        self.cut['carrier_witnesses'][self.txid]+=' '
        with self.assertRaisesRegex(ValueError,'witness'):self.collect()
        self.cut=original;self.database['rows']['journal_allocations'][0]['owner_pubkey']='03'+'2'*64
        with self.assertRaisesRegex(ValueError,'owner'):self.collect()
    def test_Core_fee_parent_witness_and_active_block_substitution_refuse(self):
        initial=copy.deepcopy(self.chain.values)
        self.chain.values[self.txid]['blockhash']='e'*64
        with self.assertRaisesRegex(ValueError,'active chain'):self.collect()
        self.chain.values=copy.deepcopy(initial);self.chain.values[self.txid]['hex']=self.raw[:-6].hex()
        with self.assertRaises(ValueError):self.collect()
        self.chain.values=copy.deepcopy(initial);del self.chain.values[self.pid]
        with self.assertRaises(KeyError):self.collect()
    def test_unconfirmed_signed_fee_is_reserved_never_paid(self):
        self.chain.values[self.txid]['confirmations']=0
        value=self.collect();self.assertEqual(value['cost_records'],[]);self.assertIn(self.txid,value['pending_carriers']);self.assertEqual(value['native_fee']['ordinary_held_sat'],20000)
    def test_missing_original_liability_or_operator_identity_check_holds(self):
        # Fresh valid journal with the member source but no payment check.
        _,member=_source_event(self.store,1)
        self.store=Store(pathlib.Path(self.tmp.name)/'missing-payment','synthetic-C-missing',60000)
        self.addCleanup(self.store.close);self.store.attach_trace();self.store.event('treasury_member_verified',member)
        with self.assertRaisesRegex(ValueError,'payment check missing'):self.collect()
    def test_source_context_tip_and_immutable_policy_are_bound(self):
        self.source();bad=copy.deepcopy(self.body);bad['source_observation']['tip_hash']='e'*64
        self.store.event('normal_financial_source',bad);event,_=_source_event(self.store,self.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0])
        with self.assertRaises(ValueError):c.collect_cost_records(self.store,self.chain,config=self.config,private_cut=self.private,source_event=event,source=bad,expected_history_identity=self.root,expected_policy_sha256=c.digest(self.policy),expected_server_pubkey=KEY)
    def test_retained_budget_cannot_roll_back_after_existing_importer_join(self):
        value=self.collect();self.join(value);self.cut['budget_hex']=b'10000\n'.hex()
        with self.assertRaisesRegex(ValueError,'rollback'):self.collect()
    def test_missing_shared_importer_is_explicit_integration_hold(self):
        value=self.collect()
        with patch.dict(sys.modules,{'simulator.normal_money_join':None}),self.assertRaisesRegex(ValueError,'importer'):
            c.journal_cost_records(self.store,value,self.event,self.body)

    def test_original_protected_frame_is_replayed_not_a_true_flag(self):
        self.source();bad=copy.deepcopy(self.body);bad['database']['rows']['journal_carriers'][0]['miner_fee_sat']=99
        self.store.event('normal_financial_source',bad);event,_=_source_event(self.store,self.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0])
        with patch('simulator.frontier_source._run_sync',side_effect=lambda request:request['frame']),self.assertRaisesRegex(ValueError,'immutable original'):
            c.collect_cost_records(self.store,self.chain,config=self.config,private_cut=self.private,source_event=event,source=bad,expected_history_identity=self.root,expected_policy_sha256=c.digest(self.policy),expected_server_pubkey=KEY)
        self.config.closed_frontier_schema=1
        with self.assertRaisesRegex(ValueError,'schema2'):self.collect()
    def test_costed_carrier_reorg_cannot_be_refunded_or_costed_plus_reserved_again(self):
        self.join(self.collect());self.chain.values[self.txid]['confirmations']=0
        with self.assertRaisesRegex(ValueError,'reconciliation'):self.collect()
        self.assertEqual(1,self.store.db.execute("SELECT count(*)FROM event WHERE kind='financial_cost_verified'").fetchone()[0])
    def test_frozen_group_without_private_carrier_retains_liability_hold(self):
        allocation=copy.deepcopy(self.database['rows']['journal_allocations'][0]);allocation.update(id='e'*64+':0',freeze_set='unresolved')
        self.database['rows']['journal_allocations'].append(allocation);self.cut['allocation_witnesses']['unresolved']=[]
        with self.assertRaisesRegex(ValueError,'liabilities'):self.collect()

    def test_existing_operator_member_identity_is_not_a_caller_selected_cost_label(self):
        self.member['identity']='another-wallet'
        with self.assertRaisesRegex(ValueError,'member source'):self.collect()

    def test_actual_native_ChainHash_header_uses_BOLT_byte_order(self):
        self.cut['identity_hex']=encoded({'version':1,'genesis':'f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000','server_pubkey':KEY}).hex()
        self.assertEqual(self.collect()['native_fee']['ordinary_booked_sat'],20000)

    def test_RPC_display_order_cannot_substitute_for_native_identity_header(self):
        self.cut['identity_hex']=encoded({'version':1,'genesis':SIGNET_GENESIS,'server_pubkey':KEY}).hex()
        with self.assertRaisesRegex(ValueError,'network/server identity'):self.collect()

    def test_existing_flow_ID_cannot_be_imported_as_C_miner_cost(self):
        value=self.collect()
        self.store.event('treasury_flow_verified',{'monetary_id':'miner:'+self.txid,'kind':'injection','financial_pins':PINS,'amount_msat':100000})
        before=self.store.db.execute('SELECT count(*) FROM event').fetchone()[0]
        with self.assertRaises(ValueError):self.join(value)
        self.assertEqual(before,self.store.db.execute('SELECT count(*) FROM event').fetchone()[0])
        self.assertEqual(0,self.store.db.execute("SELECT count(*)FROM event WHERE kind='financial_cost_verified'").fetchone()[0])
        self.store.verify_event_chain()

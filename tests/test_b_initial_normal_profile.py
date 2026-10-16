"""Synthetic component controls. No capture/readiness/native qualification."""
import copy
import hashlib
import json
import sqlite3
import time
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from simulator import b_initial_normal_profile as b
from simulator.model import SIGNET_GENESIS, canonical
from simulator.ownership import EvidenceGap


def encoded(value): return canonical(value).encode()


class BudgetControls(unittest.TestCase):
    def run_budget(self, raw, mutate=None):
        runtime={'native_budget':{'files':{'ordinary-fee-budget':{'sha256':b.digest(raw),'bytes':len(raw)}},
            'disk_budget':{'budget_file_sha256':b.digest(raw),'attempt_count':len(raw.splitlines()),
                'reserved_ceiling_sum_sat':sum(int(x) for x in raw.splitlines() if x.isdigit())}}}
        if mutate: mutate(runtime)
        return b.ordinary_budget_subset(raw,runtime)
    def test_empty_opening_and_actual_ordinary_subset(self):
        self.assertEqual(0,self.run_budget(b'')['ordinary_attempts'])
        self.assertEqual(30000,self.run_budget(b'10000\n20000\n')['ordinary_ceiling_sum_sat'])
    def test_urgent_reservation_refuses_even_if_aggregate_count_matches(self):
        with self.assertRaisesRegex(EvidenceGap,'urgent'): self.run_budget(b'u:0:10000\n')
    def test_urgent_binding_refuses_without_exporting_signed_package(self):
        with self.assertRaisesRegex(EvidenceGap,'urgent'): self.run_budget(b'p:0:'+b'a'*64+b':[[1,2,3]]\n')
    def test_changed_file_hash_and_length_refuse(self):
        for change in (lambda r:r['native_budget']['files']['ordinary-fee-budget'].update(sha256='0'*64),
                       lambda r:r['native_budget']['files']['ordinary-fee-budget'].update(bytes=0)):
            with self.assertRaisesRegex(EvidenceGap,'hash/length'): self.run_budget(b'10000\n',change)
    def test_torn_noncanonical_overflow_and_unknown_refuse(self):
        for raw in (b'10000',b'010000\n',b'0\n',b'18446744073709551616\n',b'x:2\n',b'\xff\n'):
            with self.subTest(raw=raw),self.assertRaises(EvidenceGap): self.run_budget(raw)
    def test_aggregate_urgent_labels_cannot_be_reused_as_ordinary(self):
        with self.assertRaisesRegex(EvidenceGap,'aggregate'):
            self.run_budget(b'',lambda r:r['native_budget']['disk_budget'].update(attempt_count=1))
    def test_factory_holds_before_any_reader_or_store_call(self):
        with self.assertRaisesRegex(EvidenceGap,'seam absent'): b.build_collector(object(), reader=lambda:1/0)


class PublicBudgetControls(unittest.TestCase):
    def setUp(self):
        self.runtime={'native_budget':{'files':{'ordinary-fee-budget':{'sha256':'a'*64}},
            'disk_budget':{'budget_file_sha256':'a'*64,'attempt_count':0,'reserved_ceiling_sum_sat':0},
            'public_ledger':{'budget_file_sha256':'a'*64,'ordinary_reservations':[],
                'urgent_reservations':[],'urgent_bindings':[],'record_count':0}}}
    def run_subset(self):return b.ordinary_public_subset(self.runtime)
    def test_public_empty_opening_is_ordinary_only_without_private_raw(self):
        self.assertEqual(0,self.run_subset()['ordinary_attempts'])
    def test_real_ordinary_lines_are_counted_in_order(self):
        n=self.runtime['native_budget'];n['public_ledger'].update(ordinary_reservations=[{'line':1,'ceiling_sat':10000}],record_count=1)
        n['disk_budget'].update(attempt_count=1,reserved_ceiling_sum_sat=10000)
        self.assertEqual(10000,self.run_subset()['ordinary_ceiling_sum_sat'])
    def test_urgent_authorization_or_binding_remains_hold(self):
        for name in ('urgent_reservations','urgent_bindings'):
            n=copy.deepcopy(self.runtime);n['native_budget']['public_ledger'][name]=[{'line':1}]
            with self.assertRaisesRegex(EvidenceGap,'urgent'):b.ordinary_public_subset(n)
    def test_changed_file_identity_or_uncovered_line_holds(self):
        self.runtime['native_budget']['public_ledger']['budget_file_sha256']='b'*64
        with self.assertRaisesRegex(EvidenceGap,'file identity'):self.run_subset()
        self.setUp();self.runtime['native_budget']['public_ledger']['record_count']=1
        with self.assertRaisesRegex(EvidenceGap,'coverage'):self.run_subset()
    def test_unknown_schema_cannot_be_legacy_fallback(self):
        self.runtime['native_budget']['public_ledger']['complete']=True
        with self.assertRaisesRegex(EvidenceGap,'unknown fields'):self.run_subset()


class RuntimeControls(unittest.TestCase):
    def setUp(self):
        self.values=[encoded({'id':'expected'}),encoded({'id':'checkpoint'}),encoded({'actual':'observation'})]
        self.producer=b.digest(Path(b.runtime_source.__file__).read_bytes())
        self.admission={'runtime_producer_sha256':self.producer,
            'runtime_expected_source_sha256':b.digest(self.values[0]),
            'runtime_checkpoint_source_sha256':b.digest(self.values[1])}
        self.result={'derived':True,'complete':False,'qualified':False}
        self.receipt={**self.result,'operator_expected_source_sha256':b.digest(self.values[0]),
            'operator_checkpoint_source_sha256':b.digest(self.values[1]),'producer_source_sha256':self.producer}
    def run_runtime(self, receipt=None, values=None):
        with patch.object(b.runtime_source,'verify',return_value=self.result) as verify:
            result=b.checked_runtime(b.RuntimeBuffers(*(values or self.values),encoded(receipt or self.receipt)),self.admission)
            verify.assert_called_once_with(*[json.loads(v)for v in (values or self.values)])
            return result
    def test_replays_actual_producer_and_keeps_false_flags(self): self.assertEqual(self.result,self.run_runtime())
    def test_caller_positive_receipt_refuses(self):
        with self.assertRaisesRegex(EvidenceGap,'independent replay'):self.run_runtime({**self.receipt,'qualified':True})
    def test_original_raw_whitespace_identity_is_not_replaced_by_parsed_json(self):
        with self.assertRaisesRegex(EvidenceGap,'original identity'):
            self.run_runtime(values=[self.values[0]+b' ',*self.values[1:]])
    def test_different_installed_producer_refuses(self):
        self.admission['runtime_producer_sha256']='0'*64
        with self.assertRaisesRegex(EvidenceGap,'producer'):self.run_runtime()


class HistoricalControls(unittest.TestCase):
    def setUp(self):
        db=sqlite3.connect(':memory:');db.row_factory=sqlite3.Row
        db.execute('CREATE TABLE event(sequence INTEGER, observed_at REAL, kind TEXT, payload TEXT, previous_hash TEXT, hash TEXT)')
        self.store=SimpleNamespace(db=db,get_meta=lambda key:None)
        self.bank={'id':'bank','kind':'wallet','role':'funding_bank','identity':'actual-public-bank',
            'descriptors':['public-desc'],'verification_sequence':5}
        self.old={'id':'old','pins':{'synthetic':'pins'},'members':[self.bank]};self.new=copy.deepcopy(self.old)
        self.tx={b.RECEIPT:{'txid':b.RECEIPT,'inputs':[{'outpoint':'a'*64+':0','amount_sat':10000248,'script':'outside'}],
            'outputs':[{'vout':0,'amount_sat':10000000,'script':b.RECEIPT_SCRIPT}],
            'fee_sat':248,'confirmations':11,'blockhash':'c'*64},
            b.SUCCESSOR:{'txid':b.SUCCESSOR,'inputs':[{'outpoint':b.RECEIPT+':0','amount_sat':10000000,'script':b.RECEIPT_SCRIPT}],
            'outputs':[{'vout':0,'amount_sat':9997622,'script':'bank'}],
            'fee_sat':2378,'confirmations':6,'blockhash':'d'*64}}
        self.height=326521
        self.hashes={0:SIGNET_GENESIS,326473:b.CUT_HASH,326474:b.REPLACEMENT,326511:'c'*64,326516:'d'*64}
        self.chain=SimpleNamespace(transaction=lambda txid:copy.deepcopy(self.tx[txid]),
            identity=lambda:{'chain':'signet','initialblockdownload':False,'blocks':self.height,'bestblockhash':'e'*64},
            call=lambda method,height:self.hashes[height])
        self.recon={'id':'reconstructed-original','financial_pins':self.old['pins'],
            'canonical_cut':{'height':326473,'hash':b.CUT_HASH},
            'original_orphan':{'height':326474,'hash':b.ORPHAN},'script_count':611,
            'original_roots':[{'id':i}for i in range(12)],
            'block_effects':{'blocks':[{'owned_created':[],'owned_consumed':[]}]}}
        r=self.add(1,'treasury_original_opening_reconciled',self.recon)
        immutable=lambda tx:{key:tx[key]for key in('txid','inputs','outputs','fee_sat','blockhash')}
        self.source={'financial_pins':self.old['pins'],'original_boundary_id':'old',
            'original_boundary_sha256':b.digest(encoded(self.old)),'opening_reconciliation_id':self.recon['id'],
            'opening_reconciliation_sequence':1,'opening_reconciliation_event_hash':r[2],
            'opening_reconciliation_sha256':b.digest(encoded(self.recon)),
            'flow_id':'injection:'+b.RECEIPT+':0','amount_msat':10000000000,'outpoint':b.RECEIPT+':0',
            'script':b.RECEIPT_SCRIPT,'receipt_transaction':immutable(self.tx[b.RECEIPT]),
            'spent_successor':immutable(self.tx[b.SUCCESSOR]),'receipt_height':326511,'successor_height':326516,
            'successor_cost_sequence':4447}
        i=self.add(2,'treasury_external_injection_source_verified',self.source)
        self.flow={'id':self.source['flow_id'],'kind':'injection','source':'outside-b-neutral-funding',
            'destination':'bank','amount_msat':10000000000}
        f=self.add(3,'treasury_flow_verified',self.flow)
        self.refs=(r,i,f);self.costs=[{'sequence':seq,'budget':'ordinary'}for seq in b.COST_SEQUENCES]
        self.scripts={b.RECEIPT_SCRIPT:{'member_id':'bank'}}
    def tearDown(self):self.store.db.close()
    def add(self,seq,kind,value):
        payload=canonical(value);observed=123.0;prev='0'*64
        sha=b.digest(encoded([seq,observed,kind,payload,prev]))
        self.store.db.execute('INSERT INTO event VALUES (?,?,?,?,?,?)',(seq,observed,kind,payload,prev,sha))
        return seq,kind,sha
    def run_join(self):
        with patch.multiple(b,RECONCILIATION=self.refs[0],INJECTION=self.refs[1],FLOW=self.refs[2]), \
             patch.object(b.native,'original_costs',return_value=self.costs), \
             patch.object(b.native,'physical_cost_payers',return_value={234:'bank',600:'actor-01',2947:'watchman',4447:'bank'}):
            before=self.store.db.total_changes
            result=b.historical_money(self.store,self.chain,self.old,self.new,self.scripts,[])
            self.assertEqual(before,self.store.db.total_changes)
            return result
    def test_actual_three_link_source_shape_spent_receipt_is_once_only_flow(self):
        result=self.run_join();self.assertEqual([3],result['flow_sequences'])
        self.assertEqual(10000000000,sum(v['amount_msat']for v in result['flows']))
        self.assertEqual(4447,result['costs'][-1]['sequence'])
    def test_changed_original_event_frame_refuses(self):
        self.store.db.execute("UPDATE event SET payload='{}' WHERE sequence=2")
        with self.assertRaisesRegex(ValueError,'frame changed'):self.run_join()
    def test_wrong_source_identity_hash_refuses(self):
        self.refs=(self.refs[0],(2,self.refs[1][1],'0'*64),self.refs[2])
        with self.assertRaisesRegex(EvidenceGap,'source identity'):self.run_join()
    def test_duplicate_flow_refuses_without_rebook(self):
        self.add(4,'treasury_flow_verified',self.flow)
        with self.assertRaisesRegex(EvidenceGap,'duplicate'):self.run_join()
    def test_receipt_unconfirmed_or_new_canonical_fork_refuses(self):
        self.tx[b.RECEIPT]['confirmations']=0
        with self.assertRaisesRegex(EvidenceGap,'unconfirmed'):self.run_join()
        self.tx[b.RECEIPT]['confirmations']=11;self.hashes[326511]='f'*64
        with self.assertRaisesRegex(EvidenceGap,'canonical height'):self.run_join()
    def test_original_orphan_is_preserved_and_not_required_canonical(self):
        self.assertNotEqual(b.ORPHAN,self.hashes[326474]);self.run_join()
    def test_bank_descriptor_replacement_is_not_membership_expansion(self):
        self.new['members'][0]['descriptors']=['changed']
        with self.assertRaisesRegex(EvidenceGap,'identity/descriptors'):self.run_join()
    def test_future_or_urgent_costs_hold(self):
        self.costs.append({'sequence':5555,'budget':'ordinary'})
        with self.assertRaisesRegex(EvidenceGap,'cost domain'):self.run_join()
        self.costs.pop();self.costs[-1]['budget']='urgent'
        with self.assertRaisesRegex(EvidenceGap,'urgent'):self.run_join()
    def test_chain_tip_change_during_join_holds(self):
        n=[0]
        def identity():
            n[0]+=1;return {'chain':'signet','initialblockdownload':False,'blocks':self.height,'bestblockhash':str(n[0])*64}
        self.chain.identity=identity
        with self.assertRaisesRegex(EvidenceGap,'tip changed'):self.run_join()


class ClnControls(unittest.TestCase):
    def setUp(self):
        self.now=time.time();self.height=100;self.tip='a'*64;self.channel='b'*64
        self.outputs={self.channel+':0':(2000,'0020'+'c'*64),
                      self.channel+':1':(1000,'0014'+'d'*40),
                      'e'*64+':0':(500,'0014'+'f'*40)}
        self.members=[];self.nodes={}
        for name,identity,peer,owned,cash in [('operator','02'+'1'*64,'03'+'2'*64,1500000,self.channel+':1'),
                ('fixture_peer','03'+'2'*64,'02'+'1'*64,500000,'e'*64+':0')]:
            self.members.append({'id':'owned-'+name,'identity':identity,'kind':'lightning_peer'})
            txid,index=cash.split(':');amount,script=self.outputs[cash]
            self.nodes[name]={'getinfo':{'id':identity,'network':'signet','blockheight':100},
                'listfunds':{'outputs':[{'txid':txid,'output':int(index),'amount_msat':amount*1000,
                    'scriptpubkey':script,'status':'confirmed','blockheight':90}],
                    'channels':[{'funding_txid':self.channel,'funding_output':0,'state':'CHANNELD_NORMAL',
                        'our_amount_msat':owned,'amount_msat':2000000}]},
                'listpeerchannels':{'channels':[{'funding_txid':self.channel,'funding_outnum':0,
                    'channel_id':'c'*64,'state':'CHANNELD_NORMAL','peer_id':peer,'to_us_msat':owned,
                    'total_msat':2000000,'htlcs':[]}]}}
        self.frame={'kind':'b_owned_cln_original_projection','network':'signet','genesis':SIGNET_GENESIS,
            'height':100,'tip_hash':self.tip,'observed_at':self.now-1,'completed_at':self.now,'nodes':self.nodes,
            'reported_current_channel_owned_msat':999999999,'complete':True}
        self.creation=90;self.spent=False
        self.chain=SimpleNamespace(identity=lambda:{'chain':'signet','blocks':100,'bestblockhash':self.tip,'initialblockdownload':False},
            call=self.call,tx=self.tx)
    def call(self,method,*args):
        if method=='getblockhash':return SIGNET_GENESIS if args[0]==0 else '9'*64
        if method=='gettxout':
            if self.spent and args[2]:return None
            amount,script=self.outputs[args[0]+':'+str(args[1])]
            return {'value':str(amount/100000000),'confirmations':11,'scriptPubKey':{'hex':script}}
        raise AssertionError(method)
    def tx(self,txid):
        return {'txid':txid,'confirmations':101-self.creation,'blockhash':'9'*64,
            'vout':[{'n':int(point.split(':')[1]),'value':str(amount/100000000),'scriptPubKey':{'hex':script}}
                for point,(amount,script)in self.outputs.items()if point.startswith(txid+':')]}
    def run_cln(self,old_scripts=None):
        raw=encoded(self.frame)
        return b.preexisting_cln(raw,b.digest(raw),self.members,self.chain,tip=(100,self.tip),
            opening_cut=95,original_scripts=old_scripts or {})
    def test_preexisting_owned_pair_counts_capacity_once_and_ignores_claimed_totals(self):
        r=self.run_cln();self.assertEqual(3500,r['preexisting_physical_sat'])
        self.assertEqual(3,len(r['physical']));self.assertFalse(r['current_component']['qualified'])
        self.assertNotIn('flows',r)
    def test_partial_or_external_peer_cannot_cover_capacity(self):
        self.nodes['fixture_peer']['getinfo']['id']='02'+'7'*64
        with self.assertRaisesRegex(EvidenceGap,'both distinct'):self.run_cln()
    def test_current_htlc_refuses(self):
        self.nodes['operator']['listpeerchannels']['channels'][0]['htlcs']=[{'amount_msat':1}]
        with self.assertRaisesRegex(ValueError,'conditional'):self.run_cln()
    def test_postopening_created_capital_cannot_be_called_preexisting(self):
        self.creation=96
        with self.assertRaisesRegex(EvidenceGap,'before explicit opening'):self.run_cln()
    def test_mempool_spent_original_output_refuses(self):
        self.spent=True
        with self.assertRaisesRegex(EvidenceGap,'spent/pending'):self.run_cln()
    def test_old_descriptor_boundary_overlap_refuses(self):
        with self.assertRaisesRegex(EvidenceGap,'overlaps original'):
            self.run_cln({'0014'+'d'*40:{'member_id':'bank'}})
    def test_stale_source_is_not_new_historical_opening(self):
        self.frame['completed_at']-=91
        with self.assertRaisesRegex(EvidenceGap,'stale'):self.run_cln()


if __name__=='__main__':unittest.main()

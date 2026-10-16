"""Two-split real Store handoff into opening validation, with explicit native stubs.

The monetary setup is the existing synthetic transition fixture. These controls
qualify source wiring only, never native signatures or live financial readiness.
"""
import copy
import json
import time
import unittest
from unittest.mock import patch

from simulator import financial_transition as transition
from simulator import normal_lineage_join as join
from simulator.fees import board_fee
from simulator.model import canonical
from simulator.normal_lineage import bind_coin
from simulator.two_step_capture import SourceCapture
from simulator.two_step_normal import Collector, module_hash
from tests import test_financial_transition as opening_tests
from tests import test_normal_lineage_join as lineage_tests
from tests import test_normal_pending_board as pending_tests
from tests.test_final_campaign import PINS


class OpeningLineageTests(unittest.TestCase):
    def setUp(self):
        self.base=opening_tests.FinancialTransitionTests();self.base.setUp();self.store=self.base.store
        self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        self.lineage=lineage_tests.LineageIntegrationTests()
        with patch.object(pending_tests,'Store',return_value=self.store),patch.object(pending_tests,'initialize'):
            self.lineage.setUp()
        self.store.db.execute("INSERT INTO meta VALUES ('paused','preserve synthetic original scope')")
        self.value=self.lineage.frontier();self.frontier=join.public_frontier(self.value)
        self.assertEqual(3,len(self.value['claims']));self.assertEqual(670,sum(v['amount_sat']for v in self.value['claims']))
        self.context={'id':'b'*32,'architecture_profile':'two_step_per_key','financial_pins':PINS,'boundary_id':'new-boundary','height':100,'tip_hash':'tip','started_at':time.time()}
        self.originals={'native_sql':'a'*64,'policy':'c'*64,'core':'d'*64,'rounds_inventory':'e'*64}
        self.admission={'financial_pins':PINS,'ordinary_lineage':join.CONFIGURATION,
            'component_sha256':{'ordinary_lineage':module_hash(join.authenticate_frontier),'typed_lineage':module_hash(bind_coin),'adapter':module_hash(Collector.produce),'capture':module_hash(SourceCapture.collect)},
            'capture_dependencies_sha256':{'ordinary_lineage':module_hash(join.authenticate_frontier),'typed_lineage':module_hash(bind_coin)},
            'proof_tool_sha256':{'binding':'1'*64,'policy':'2'*64},'proof_commands_sha256':{'binding':'3'*64,'policy':'4'*64}}
        self.store.event('normal_financial_collector_qualified',self.admission);self.admission_sequence=self.base.seq()
        old=self.base.chain.transaction
        self.base.chain.transaction=lambda txid: {'txid':txid,'confirmations':3,'fee_sat':100,'outputs':[{'vout':0,'amount_sat':1000,'script':'51'}]}if txid==self.lineage.txid else old(txid)
        board=self.store.db.execute("SELECT *FROM action WHERE id='original-board'").fetchone()
        fee=board_fee(self.store,board,self.base.chain.transaction(self.lineage.txid))
        self.store.event('client_fee_reconciled',{'action_id':'original-board',**fee})
        self.store.event('financial_cost_verified',{'monetary_id':'miner:'+self.lineage.txid,'kind':'miner_cost','txid':self.lineage.txid,'amount_msat':100000,'budget':'ordinary','source':'actor-01','destination':'miners','action_id':'original-board'})
        board_cost=self.base.seq();liabilities=[]
        for claim in self.value['claims']:
            row={'id':'coin:'+claim['coin_id'],'borrower':'rounds','amount_msat':claim['amount_sat']*1000}
            self.store.event('treasury_liability_verified',row);liabilities.append({**row,'source_sequence':self.base.seq()})
        self.base.historical=transition.history(self.store)
        self.base.opening['history']=self.base.historical
        self.base.readiness.update(source_observation=self.context,original_source_hashes=self.originals,ordinary_lineage=self.frontier)
        self.base.readiness['preserved_history_opening'].update(history=self.base.historical,retained_client_rights=self.value['claims'],pending_liabilities=liabilities,historical_cost_sequences=[self.base.cost_seq,board_cost])
        self.source={'financial_pins':PINS,'boundary_id':'new-boundary','source_observation':self.context,'ordinary_lineage':self.frontier,'original_sha256':self.originals,'lineage_admission_sequence':self.admission_sequence}
        self.emit()
    def tearDown(self):
        self.lineage.doCleanups();self.lineage.tmp.cleanup();self.base.tearDown()
    def emit(self):
        self.store.event('normal_financial_source',self.source)
        self.base.readiness['source_event_hash']=self.store.db.execute('SELECT hash FROM event WHERE sequence=?',(self.base.seq(),)).fetchone()[0]
        self.base.readiness['observed_at']=time.time();self.base.source()
    def test_two_split_frontier_passes_actual_opening_gate_without_legacy_direct_origin(self):
        before=transition.history(self.store)
        with patch('simulator.financial_transition._current_claims',side_effect=AssertionError('legacy direct-origin fallback must not run')):
            result=self.base.validate()
        self.assertEqual(self.value['claims'],result['retained_client_rights'])
        self.assertEqual(3,len(result['pending_liabilities']));self.assertEqual(before,transition.history(self.store))
        self.assertIsNone(self.store.get_meta('preserved_financial_opening'));self.store.verify_event_chain()
    def test_detached_frontier_nonce_sql_or_source_event_refuses(self):
        original=copy.deepcopy(self.base.readiness)
        for change in [{'source_event_hash':'0'*64},{'source_observation':{**self.context,'id':'9'*32}},
                {'original_source_hashes':{**self.originals,'native_sql':'9'*64}},
                {'ordinary_lineage':{**self.frontier,'current_claim_ids':self.frontier['current_claim_ids'][:-1]}}]:
            with self.subTest(change=list(change)):
                self.base.readiness=copy.deepcopy(original);self.base.readiness.update(change);self.base.source()
                with self.assertRaisesRegex(ValueError,'opening typed frontier'):self.base.validate()
        self.base.readiness=original
    def test_missing_wrong_or_later_admission_refuses(self):
        for seq in [None,True,self.base.opening['readiness_sequence']]:
            with self.subTest(sequence=seq):
                self.source['lineage_admission_sequence']=seq;self.emit()
                with self.assertRaisesRegex(ValueError,'admission'):self.base.validate()
        self.source['lineage_admission_sequence']=self.admission_sequence
        bad=copy.deepcopy(self.admission);bad['component_sha256']['typed_lineage']='0'*64
        self.store.event('normal_financial_collector_qualified',bad);self.source['lineage_admission_sequence']=self.base.seq();self.emit()
        with self.assertRaisesRegex(ValueError,'admission differs'):self.base.validate()
    def test_current_and_intermediate_proof_hash_coverage_or_principal_omission_refuses(self):
        original=copy.deepcopy(self.frontier)
        for mutation in ['intermediate','amount','origin','current']:
            value=copy.deepcopy(original)
            if mutation=='intermediate':del value['coin_proof_hashes'][self.lineage.ids[1]]
            elif mutation=='amount':value['obligation_groups'][0]['current_principal_sat']-=1
            elif mutation=='origin':value['obligation_groups'][0]['original_claim_ids']=[]
            else:value['current_claim_ids'].pop()
            self.source['ordinary_lineage']=value;self.base.readiness['ordinary_lineage']=value;self.emit()
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.base.validate()
    def test_missing_typed_frontier_cannot_silently_use_caller_ids(self):
        self.base.readiness.pop('ordinary_lineage');self.base.source()
        with self.assertRaises(ValueError):self.base.validate()

if __name__=='__main__':unittest.main()

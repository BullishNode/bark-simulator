"""Synthetic source/cost joins only; no money/native qualification."""
import unittest
from unittest.mock import patch

from simulator import b_native_ordinary_money as money
from simulator.bundle_audit import decode_transaction
from simulator.final_campaign import _source_event
from simulator.model import InvariantError
from simulator.ownership import EvidenceGap
from tests import test_b_current_native_liabilities as rights_fixture
from tests.test_final_campaign import PINS


class OrdinaryMoneyTests(unittest.TestCase):
    def setUp(self):
        self.f=rights_fixture.CurrentRightsTests();self.addCleanup(self.f.doCleanups);self.f.setUp()
        self.store=self.f.store;self.bank_script='5120'+'a'*64
        self.boundary={'id':'synthetic','genesis':rights_fixture.SIGNET_GENESIS,'pins':PINS,'excluded':[],'members':[
            {'id':'bank','kind':'wallet','role':'operator','identity':'bank','descriptors':['bank-desc']},
            {'id':'watchman','kind':'wallet','role':'operator','identity':'watch','descriptors':['watch-desc']},
            {'id':'customer','kind':'wallet','role':'customer','identity':'customer','descriptors':['customer-desc']},
            {'id':'ark','kind':'ark_backing','role':'operator','identity':self.f.server,'descriptors':[]}]}
        for member in self.boundary['members']:member['verification_sequence']=1
        self.tx_number=0
        self.scripts={self.bank_script:{'member_id':'bank'},self.f.operator:{'member_id':'watchman'},
                      self.f.destination:{'member_id':'customer'}}
        self.store.event('treasury_flow_verified',{'id':'original-receipt','kind':'injection',
            'source':'outside','destination':'bank','amount_msat':100000000})
        self.flow=self.seq()
        self.bank_tx=self.add_transaction(self.bank_script,1000)
        self.bank_cost=self.cost(self.bank_tx)
        self.groups=[]

    def seq(self):return self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]

    def add_transaction(self,script,fee):
        self.tx_number+=1
        point=f'{100+self.tx_number:064x}'+':0'
        raw=rights_fixture.raw_transaction(point,[(10000,script)])
        body=decode_transaction(raw,public_body=True);txid=body['txid']
        self.f.transactions[txid]={'txid':txid,'confirmations':1,'blockhash':self.f.tip,
            'inputs':[{'outpoint':point,'amount_sat':10000+fee,'script':script}],
            'outputs':body['outputs'],'fee_sat':fee}
        self.f.raw[txid]={'hex':raw,'weight':body['weight'],'vsize':body['vsize']}
        return txid

    def cost(self,txid,*,budget='ordinary',direct=False,alias='bitcoin-miner:',pins=None):
        marker=None
        if direct:
            group=next(g for g in self.groups if g['transaction']['txid']==txid)
            self.store.event('direct_payment_checked',{k:v for k,v in group['result'].items()if k!='owners'})
            marker=self.seq()
        self.store.event('financial_cost_verified',{'monetary_id':alias+txid,
            'kind':'miner_cost','txid':txid,'amount_msat':self.f.transactions[txid]['fee_sat']*1000,
            'budget':budget,'financial_pins':PINS if pins is None else pins,
            **({'direct_payment_sequence':marker}if direct else {})})
        return self.seq()

    def project(self):
        return money.current_ordinary_miner_costs(self.store,self.f.chain,boundary=self.boundary,
            scripts=self.scripts,groups=self.groups,tip=(self.f.height,self.f.tip),
            bank_member_id='bank',backing_member_id='ark')

    def add_direct(self):
        txid=self.f.carrier(True);self.groups=self.f.collect()['groups']
        sequence=self.cost(txid,direct=True)
        return txid,sequence

    def opening(self):
        event,_=_source_event(self.store,self.bank_cost);flow,_=_source_event(self.store,self.flow)
        return {'sources':[{'sequence':flow['sequence'],'hash':flow['hash']}],
            'costs':[{'sequence':event['sequence'],'hash':event['hash'],'budget':'ordinary',
                      'payer':'bank','amount_msat':1000000}], 'boundary':self.boundary}

    def deltas(self,projection=None,opening=None):
        if projection is None:projection=self.project()
        if opening is None:opening=self.opening()
        with patch.object(money,'recorded',return_value=opening):
            return money.opening_money_deltas(self.store,projection)

    def test_self_funded_exact_direct_fee_belongs_to_operator_backing_not_invented_watch_utxo(self):
        _,sequence=self.add_direct();before=self.store.db.total_changes;result=self.project()
        self.assertEqual('ark',result['cost_payers'][sequence])
        self.assertEqual('native_ordinary_direct',result['cost_classes'][sequence])
        self.assertEqual('bank',result['cost_payers'][self.bank_cost])
        self.assertEqual(before,self.store.db.total_changes)

    def test_new_confirmed_cost_is_delta_once_old_cost_and_receipt_not_rebooked(self):
        txid,sequence=self.add_direct();projection=self.project();before=self.store.db.total_changes
        first=self.deltas(projection);second=self.deltas(projection)
        self.assertEqual(first,second)
        self.assertEqual([{'id':'miner:'+txid,'kind':'miner_cost','source':'ark',
            'destination':'outside-bitcoin-miners','amount_msat':500000}],first['delta_flows'])
        self.assertEqual([self.flow],first['flow_sequences'])
        self.assertEqual([self.bank_cost,sequence],first['cost_sequences'])
        self.assertEqual(before,self.store.db.total_changes)

    def test_no_delta_requires_exhaustive_actual_unchanged_costs_and_flows(self):
        result=self.deltas();self.assertEqual([],result['delta_flows'])
        self.assertEqual([self.flow],result['flow_sequences'])
        self.assertEqual([self.bank_cost],result['cost_sequences'])

    def test_missing_actual_cost_projection_cannot_make_empty_delta(self):
        self.add_direct();projection=self.project()
        projection['costs']=[r for r in projection['costs']if r['sequence']==self.bank_cost]
        with self.assertRaisesRegex(EvidenceGap,'exhaustive actual cost coverage'):self.deltas(projection)

    def test_missing_confirmed_direct_fee_event_is_not_zero(self):
        self.f.carrier(True);self.groups=self.f.collect()['groups']
        with self.assertRaisesRegex(EvidenceGap,'lacks exact original cost event'):self.project()

    def test_unknown_native_operator_fee_cannot_consume_external_partition(self):
        txid=self.add_transaction(self.f.operator,500);self.cost(txid)
        with self.assertRaisesRegex(EvidenceGap,'unproved native operator funding/purpose'):self.project()

    def test_urgent_cost_cannot_be_classified_as_ordinary(self):
        txid=self.add_transaction(self.f.destination,171);self.cost(txid,budget='urgent')
        with self.assertRaisesRegex(EvidenceGap,'urgent cost requires private'):self.project()

    def test_new_flow_without_genuine_provenance_holds_even_if_shape_is_strict(self):
        self.store.event('treasury_flow_verified',{'id':'new-receipt','kind':'injection',
            'source':'outside','destination':'bank','amount_msat':1000000})
        sequence=self.seq()
        with self.assertRaisesRegex(EvidenceGap,'genuine B provenance join '+str(sequence)):self.deltas()

    def test_rich_a_flow_alias_cannot_be_accepted_as_fivefield_b(self):
        self.store.event('treasury_flow_verified',{'monetary_id':'new','kind':'injection',
            'source':'outside','destination':'bank','amount_msat':1000000})
        with self.assertRaisesRegex(EvidenceGap,'strict five-field flow'):self.deltas()

    def test_changed_opening_cost_hash_or_payer_never_rebooks_it(self):
        opening=self.opening();opening['costs'][0]['payer']='watchman'
        with self.assertRaisesRegex(EvidenceGap,'preserved original cost changed'):self.deltas(opening=opening)

    def test_new_cost_pin_cannot_borrow_original_opening(self):
        txid=self.f.carrier(True);self.groups=self.f.collect()['groups']
        self.cost(txid,direct=True,pins={**PINS,'sdk_commit':'f'*40})
        with self.assertRaisesRegex(EvidenceGap,'financial epoch differs'):self.deltas()

    def test_changed_current_core_prevout_arithmetic_holds(self):
        self.f.transactions[self.bank_tx]['inputs'][0]['amount_sat']+=1
        with self.assertRaisesRegex(EvidenceGap,'current canonical body/fee'):self.project()

    def test_duplicated_cost_alias_is_not_two_charges(self):
        self.cost(self.bank_tx,alias='miner:')
        with self.assertRaises(InvariantError):self.project()

    def test_wrong_server_cannot_own_self_funded_direct_fee(self):
        self.add_direct();self.boundary['members'][-1]['identity']='other-server'
        with self.assertRaisesRegex(EvidenceGap,'economic backing identity differs'):self.project()

    def test_opening_must_be_actual_recorded_kernel_not_caller_ready_bit(self):
        with patch.object(money,'recorded',return_value=None):
            with self.assertRaisesRegex(EvidenceGap,'opening not recorded'):
                money.opening_money_deltas(self.store,self.project())

    def test_unrelated_event_sequence_is_not_direct_payment_provenance(self):
        txid=self.f.carrier(True);self.groups=self.f.collect()['groups']
        self.store.event('financial_cost_verified',{'monetary_id':'bitcoin-miner:'+txid,
            'amount_msat':500000,'budget':'ordinary','financial_pins':PINS,
            'direct_payment_sequence':self.flow})
        with self.assertRaisesRegex(EvidenceGap,'original payment provenance'):self.project()

    def test_conflicting_original_direct_payment_body_holds(self):
        txid=self.f.carrier(True);self.groups=self.f.collect()['groups']
        self.store.event('direct_payment_checked',{'txid':txid,'freeze_set':'other'})
        marker=self.seq()
        self.store.event('financial_cost_verified',{'monetary_id':'bitcoin-miner:'+txid,
            'amount_msat':500000,'budget':'ordinary','financial_pins':PINS,
            'direct_payment_sequence':marker})
        with self.assertRaisesRegex(EvidenceGap,'original payment provenance'):self.project()

    def test_unknown_cost_class_cannot_disappear_from_partition(self):
        projection=self.project();projection['cost_classes'][self.bank_cost]='new-funding-domain'
        with self.assertRaisesRegex(EvidenceGap,'unclassified actual cost domain'):self.deltas(projection)

    def test_repeated_physical_input_across_costs_holds(self):
        txid=self.add_transaction(self.f.destination,171)
        original=self.f.transactions[self.bank_tx]['inputs'][0]['outpoint']
        body=decode_transaction(rights_fixture.raw_transaction(original,
            [(10000,self.f.destination)]),public_body=True)
        tx=self.f.transactions.pop(txid);self.f.raw.pop(txid)
        txid=body['txid'];tx['txid']=txid;tx['inputs'][0]['outpoint']=original
        self.f.transactions[txid]=tx
        self.f.raw[txid]={'hex':body['raw_hex'] if 'raw_hex' in body else rights_fixture.raw_transaction(original,[(10000,self.f.destination)]),
                         'weight':body['weight'],'vsize':body['vsize']}
        self.cost(txid)
        with self.assertRaisesRegex(EvidenceGap,'repeat a physical input'):self.project()

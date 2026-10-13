"""Independent arithmetic fixtures, never live settlement or protocol qualification."""
import unittest
from simulator.direct_accounting import expected_outputs,claim_accounts
from simulator.model import InvariantError

class DirectAccountingTests(unittest.TestCase):
    def leaf(self,identity='a',amount=10000,script='owner',dust=294):
        return {'id':identity,'gross_sat':amount,'script':script,'dust_sat':dust}
    def tx(self,principal=10000,net=9000,operator_input=0,change=800):
        return {'inputs':[{'amount_sat':principal+operator_input}],
            'outputs':[{'script':'owner','amount_sat':net},{'script':'operator','amount_sat':change}]}
    def test_flat_deduction_can_exceed_mining_cost(self):
        result=claim_accounts([self.leaf()],self.tx(),0,{'operator'})
        self.assertEqual(1000,result['flat_fee_sat'])
        self.assertEqual(200,result['mining_fee_sat'])
        self.assertEqual(800,result['flat_fee_surplus_sat'])
        self.assertEqual(800,result['operator_capital_delta_sat'])
    def test_operator_fee_inputs_fund_shortfall_without_reducing_recipient(self):
        result=claim_accounts([self.leaf()],self.tx(operator_input=2000,change=330),2000,{'operator'})
        self.assertEqual(9000,result['recipient_net_sat'])
        self.assertEqual(2670,result['mining_fee_sat'])
        self.assertEqual(1670,result['mining_shortfall_after_flat_fees_sat'])
        self.assertEqual(-1670,result['operator_capital_delta_sat'])
    def test_grouping_charges_once_including_tiny_first_leaf(self):
        self.assertEqual({'owner':9000},expected_outputs([self.leaf('a',1),self.leaf('b',9999)])['outputs'])
    def test_script_specific_dust_exact_boundaries(self):
        for threshold in (294,330,540,546):
            below=expected_outputs([self.leaf(amount=999+threshold,dust=threshold)])
            self.assertEqual({},below['outputs'])
            self.assertEqual(999+threshold,below['forfeit_sat'])
            self.assertEqual(0,below['flat_fee_sat'])
            exact=expected_outputs([self.leaf(amount=1000+threshold,dust=threshold)])
            self.assertEqual({'owner':threshold},exact['outputs'])
            self.assertEqual(0,exact['forfeit_sat'])
    def test_tiny_groups_have_no_negative_net_or_flat_charge(self):
        for amount in (1,999,1000):
            value=expected_outputs([self.leaf(amount=amount)])
            self.assertEqual(amount,value['forfeit_sat']);self.assertEqual(0,value['flat_fee_sat'])
    def test_duplicate_source_or_wrong_output_fails(self):
        with self.assertRaises(InvariantError):expected_outputs([self.leaf(),self.leaf()])
        with self.assertRaises(InvariantError):claim_accounts([self.leaf()],self.tx(net=8999),0,{'operator'})
        with self.assertRaises(InvariantError):claim_accounts([self.leaf()],self.tx(),0,{'other'})
    def test_terminal_forfeit_is_not_a_later_retained_entitlement(self):
        self.assertEqual(1100,expected_outputs([self.leaf(amount=1100)])['forfeit_sat'])
        self.assertEqual({'owner':5000},expected_outputs([self.leaf('new',6000)])['outputs'])
    def test_customer_and_operator_sources_are_not_counted_twice(self):
        with self.assertRaises(InvariantError):claim_accounts([self.leaf()],self.tx(),1000,{'operator'})
        with self.assertRaises(InvariantError):claim_accounts([self.leaf()],self.tx(),0,{'owner','operator'})

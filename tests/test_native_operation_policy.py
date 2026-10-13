"""Request policy checks; no SDK/native operation is executed."""
import unittest

class NativeOperationPolicyTests(unittest.TestCase):
    def test_scheduled_refresh_preserves_future_height_and_security_margins(self):
        from simulator.native_operation_policy import scheduled_height
        self.assertEqual(105,scheduled_height(100,105,[140,145],3,6))
        for height,expiries,confirmations,margin in [(100,[140],3,6),(132,[140],3,6),(105,[],3,6),(105,[140],0,6),(105,[140],3,0),(True,[140],3,6)]:
            with self.assertRaises(ValueError):scheduled_height(100,height,expiries,confirmations,margin)
    def test_lifetime_exit_cap_counts_unknown_reserved_attempts_without_enlargement(self):
        from simulator.native_operation_policy import exit_budget
        self.assertEqual(600,exit_budget(1000,1000,[400],600))
        for frozen,requested,prior,new in [(1000,1001,[400],600),(1000,1000,[400],601),(0,0,[],0),(1000,1000,[2**64],1),(1000,1000,[True],1)]:
            with self.assertRaises(ValueError):exit_budget(frozen,requested,prior,new)
    def test_exact_nonempty_input_set_is_required(self):
        from simulator.native_operation_policy import exact_inputs
        one='11'*32+':0';two='22'*32+':1'
        self.assertEqual([one,two],exact_inputs([one,two]))
        for inputs in [[],[one,one],['not-a-coin'],['11'*32+':-1'],[one]*17]:
            with self.assertRaises(ValueError):exact_inputs(inputs)

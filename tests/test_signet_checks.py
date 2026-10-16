from decimal import Decimal
import unittest

from simulator.signet_checks import confirmed_backing, transfer_values
from tests.test_signet import Core


def coin(identifier, amount, *, state="spendable", owner="02" + "1" * 64):
    return {"id": identifier * 64 + ":0", "amount_sat": amount, "user_pubkey": owner,
            "chain_anchor": "d" * 64 + ":0", "expiry_height": 150, "state": state}


class SignetCheckTests(unittest.TestCase):
    def snapshots(self):
        return ([coin("a", 10000)], [coin("a", 10000, state="spent"), coin("b", 4900)],
                [], [coin("c", 5000, owner="03" + "2" * 64)])

    def test_exact_transfer_conservation_counts_only_current_value(self):
        result = transfer_values(*self.snapshots(), 5000, 100)
        self.assertEqual(result["observed_offchain_fee_sat"], 100)
        self.assertEqual(result["opening_sat"], 10000)
        self.assertEqual(result["closing_sat"], 9900)
        self.assertEqual(result["signature_path_verification"], "NOT_EVALUATED")

    def test_wrong_amount_or_unexplained_value_is_not_accepted(self):
        values = self.snapshots()
        with self.assertRaisesRegex(ValueError, "intended amount"):
            transfer_values(*values, 4999, 100)
        with self.assertRaisesRegex(ValueError, "declared bound"):
            transfer_values(*values, 5000, 99)
        values[1][-1]["amount_sat"] = 5001
        with self.assertRaises(ValueError):
            transfer_values(*values, 5000, 100)

    def test_duplicate_or_locked_coins_block_settled_checkpoint(self):
        values = self.snapshots()
        values[3].append(values[1][-1])
        with self.assertRaisesRegex(ValueError, "both wallets"):
            transfer_values(*values, 5000, 100)
        values = self.snapshots()
        values[1][-1]["state"] = "locked"
        with self.assertRaisesRegex(ValueError, "not settled"):
            transfer_values(*values, 5000, 100)

    def test_independent_backing_does_not_count_an_anchor_twice(self):
        class BackingCore(Core):
            def call(self, method, *args):
                if method == "gettxout":
                    return {"value": Decimal("0.00010000"), "confirmations": 2,
                            "bestblock": self.info["bestblockhash"]}
                return super().call(method, *args)
        values = self.snapshots()
        result = confirmed_backing(BackingCore(), [values[1], values[3]])
        self.assertEqual(len(result["anchors"]), 1)
        self.assertEqual(next(iter(result["anchors"].values()))["cohort_value_sat"], 9900)

    def test_unconfirmed_or_insufficient_backing_is_rejected(self):
        class BackingCore(Core):
            def call(self, method, *args):
                if method == "gettxout":
                    return {"value": Decimal("0.00001000"), "confirmations": 2,
                            "bestblock": self.info["bestblockhash"]}
                return super().call(method, *args)
        with self.assertRaisesRegex(ValueError, "exceed"):
            confirmed_backing(BackingCore(), [self.snapshots()[3]])


if __name__ == "__main__":
    unittest.main()

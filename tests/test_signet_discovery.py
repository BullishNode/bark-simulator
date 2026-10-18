"""Public block discovery fault tests; these are not live Signet receipts."""
import json
import unittest
from unittest.mock import patch

from simulator.signet_discovery import discover_payouts
from tests import test_signet_s02 as fixture

LifecycleCore, PAYOUT, SCRIPT, output = fixture.LifecycleCore, fixture.PAYOUT, fixture.SCRIPT, fixture.output


class DiscoveryCore(LifecycleCore):
    def __init__(self):
        super().__init__()
        self.info["blocks"] = 190
        for transaction in self.transactions.values():
            transaction["confirmations"] = max(0, transaction["confirmations"] - 10)
        self.reorg = False
        self.inventory = {}
        for height in range(180, 191):
            txid = f"{1000 + height:064x}"
            self.inventory[height] = [txid]
            self.transactions[txid] = {"txid": txid, "blockhash": self.block_hash(height),
                                      "vin": [{"coinbase": "private bytes not captured"}],
                                      "vout": [output(1, "51")]}
        self.inventory[190].append(PAYOUT)
        self.transactions[PAYOUT]["confirmations"] = 1

    def block_hash(self, height):
        return ("3" if self.reorg else "2") * 64 if height == 190 else f"{height:064x}"

    def call(self, method, *args):
        if method == "getblockhash" and args[0] >= 180:
            return self.block_hash(args[0])
        if method == "getblock":
            assert args[1] == 1
            height = next(height for height in self.inventory if self.block_hash(height) == args[0])
            return {"hash": args[0], "height": height, "tx": self.inventory[height]}
        return super().call(method, *args)


class DiscoveryTests(unittest.TestCase):
    setUp, tearDown = fixture.S02Tests.setUp, fixture.S02Tests.tearDown
    source, receipt, freeze = fixture.S02Tests.source, fixture.S02Tests.receipt, fixture.S02Tests.freeze

    def prepare(self):
        frozen = self.freeze()
        self.campaign.core = DiscoveryCore()
        return frozen

    def test_resumes_bounded_public_blocks_without_opening_absent_wallet(self):
        self.prepare()
        with patch("simulator.signet.subprocess.run") as native:
            first = discover_payouts(self.campaign, "absent", 1)
            second = discover_payouts(self.campaign, "absent", 128)
        native.assert_not_called()
        self.assertEqual(first["scanned_transactions"], 1)
        self.assertFalse(first["caught_up"])
        self.assertEqual(second["scanned_transactions"], 11)
        self.assertEqual(second["candidates"][0]["payout_check"], "PASS")
        self.assertTrue(second["caught_up"])
        self.assertEqual(second["case_verdict"], "INCOMPLETE")
        self.assertEqual(discover_payouts(self.campaign, "absent")["scanned_transactions"], 0)

    def test_reorg_rewinds_even_after_old_chain_was_fully_scanned(self):
        self.prepare()
        discover_payouts(self.campaign, "absent")
        self.campaign.core.reorg = True
        self.campaign.core.transactions[PAYOUT]["blockhash"] = "3" * 64
        self.campaign.core.transactions[self.campaign.core.inventory[190][0]]["blockhash"] = "3" * 64
        result = discover_payouts(self.campaign, "absent")
        self.assertTrue(result["rewound_after_reorg"])
        self.assertEqual(result["scanned_transactions"], 12)
        self.assertEqual(result["candidates"][0]["payout_check"], "PASS")

    def test_in_progress_block_reorg_also_rewinds(self):
        self.prepare()
        first = discover_payouts(self.campaign, "absent", 11)
        self.assertEqual(first["next_height"], 190)
        self.assertEqual(first["next_transaction_offset"], 1)
        self.campaign.core.reorg = True
        for txid in self.campaign.core.inventory[190]:
            self.campaign.core.transactions[txid]["blockhash"] = "3" * 64
        self.assertTrue(discover_payouts(self.campaign, "absent")["rewound_after_reorg"])

    def test_wrong_value_stays_incomplete_and_plain_deposit_does_not_qualify(self):
        self.prepare()
        self.campaign.core.transactions[PAYOUT]["vout"][0] = output(9001)
        deposit = self.campaign.core.inventory[180][0]
        self.campaign.core.transactions[deposit]["vout"] = [output(9000, SCRIPT)]
        result = discover_payouts(self.campaign, "absent")
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(result["candidates"][0]["payout_check"], "INCOMPLETE")
        self.assertIn("exact amount", result["candidates"][0]["reason"])
        self.assertEqual(result["case_verdict"], "INCOMPLETE")

    def test_tip_change_does_not_advance_durable_cursor(self):
        self.prepare()
        core = self.campaign.core
        original = core.call
        def changing(method, *args):
            result = original(method, *args)
            if method == "getrawtransaction":
                core.info["bestblockhash"] = "cd" * 32
            return result
        core.call = changing
        with self.assertRaisesRegex(ValueError, "chain changed"):
            discover_payouts(self.campaign, "absent", 1)
        self.assertIsNone(self.campaign.db.execute("SELECT value FROM meta WHERE key='s02_discovery:absent'").fetchone())

    def test_requires_frozen_cohort_and_bounded_batch(self):
        with self.assertRaisesRegex(ValueError, "frozen"):
            discover_payouts(self.campaign, "absent")
        for value in [0, -1, True, 513]:
            with self.assertRaises(ValueError):
                discover_payouts(self.campaign, "absent", value)


if __name__ == "__main__":
    unittest.main()

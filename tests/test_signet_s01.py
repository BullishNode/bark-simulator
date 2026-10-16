"""Test S01 supervisor scheduling with a stub; never a Signet campaign proof."""
from decimal import Decimal
import json
import subprocess
import unittest
from unittest.mock import patch

from simulator.signet import Campaign
from simulator.signet_s01 import S01, funding_receipt
from tests.test_signet import Core
from tests import test_signet


class CampaignCore(Core):
    def call(self, method, *args):
        if method == "validateaddress":
            return {"isvalid": True, "scriptPubKey": "0014" + "0" * 40}
        if method == "gettxout":
            funding = args[0] in {"d" * 64, "e" * 64}
            return {"value": Decimal("0.00020000" if funding else "0.00010000"),
                    "scriptPubKey": {"hex": "0014" + "0" * 40},
                    "confirmations": 3, "bestblock": self.info["bestblockhash"]}
        return super().call(method, *args)


class S01Tests(unittest.TestCase):
    # Reuse only setup/teardown, not the journal tests themselves.
    setUp = test_signet.SignetTests.setUp
    tearDown = test_signet.SignetTests.tearDown

    def native(self, argv, **kwargs):
        actor = argv[4].split("/")[-1]
        operation = argv[5]
        self.calls.append((actor, operation))
        result = b""
        if operation == "address":
            result = b"tark1abcdef"
        elif operation == "onchain":
            result = json.dumps({"address": "tb1q" + actor}).encode()
        elif operation == "board":
            result = json.dumps({"funding_tx": {"txid": ("a" if actor == "sender" else "b") * 64},
                                 "vtxos": [], "amount_sat": 9900, "movement_id": 1}).encode()
        elif operation == "send":
            self.sent = True
        elif operation == "vtxos":
            def coin(identifier, amount, anchor, state="spendable"):
                return {"id": identifier * 64 + ":0", "amount_sat": amount,
                        "user_pubkey": "02" + identifier * 64, "chain_anchor": anchor * 64 + ":0",
                        "expiry_height": 150, "state": {"type": state}}
            if actor == "sender":
                coins = ([coin("1", 9900, "a", "spent"), coin("3", 4800, "a")]
                         if self.sent else [coin("1", 9900, "a")])
            else:
                coins = [coin("2", 9900, "b")]
                if self.sent:
                    coins.append(coin("4", 5000, "a"))
            result = json.dumps(coins).encode()
        kwargs["stdout"].write(result)
        return subprocess.CompletedProcess(argv, 0)

    def test_waits_for_explicit_funding_then_resumes_without_repeating_payment(self):
        self.campaign.core = CampaignCore()
        self.sent = False
        self.calls = []
        with patch("simulator.signet.subprocess.run", side_effect=self.native), patch(
                "simulator.signet_proof.verify_coin", return_value={"status": "UNAVAILABLE"}):
            scenario = S01(self.campaign, board_sat=10000, transfer_sat=5000, maximum_fee_sat=100)
            self.assertEqual(scenario.advance()["stage"], "WAITING_FOR_OWNER_ALLOCATED_FUNDING")
            self.assertNotIn(("sender", "board"), self.calls)
            funding_receipt(self.campaign, "sender", "d" * 64, 0)
            funding_receipt(self.campaign, "receiver", "e" * 64, 0)
            result = scenario.advance()
            self.assertEqual(result["stage"], "NATIVE_TRANSFER_OBSERVED")
            self.assertEqual(result["evidence"]["observed_offchain_fee_sat"], 100)
            self.assertEqual(result["evidence"]["signature_path_verification"], "NOT_EVALUATED")
            self.campaign.close()
            self.campaign = Campaign(self.root / "campaign", self.config)
            self.campaign.core = CampaignCore()
            resumed = S01(self.campaign, board_sat=10000, transfer_sat=5000, maximum_fee_sat=100).advance()
        self.assertEqual(resumed["stage"], "NATIVE_TRANSFER_OBSERVED")
        self.assertEqual(self.calls.count(("sender", "send")), 1)
        self.assertEqual(self.calls.count(("sender", "board")), 1)
        self.assertEqual(self.calls.count(("receiver", "board")), 1)

    def test_s01_parameters_cannot_change_after_restart(self):
        S01(self.campaign, board_sat=10000, transfer_sat=5000, maximum_fee_sat=100)
        with self.assertRaisesRegex(ValueError, "immutable"):
            S01(self.campaign, board_sat=10000, transfer_sat=6000, maximum_fee_sat=100)

    def test_funding_outpoint_cannot_credit_two_wallets(self):
        self.campaign.core = CampaignCore()
        self.sent = False
        self.calls = []
        with patch("simulator.signet.subprocess.run", side_effect=self.native):
            S01(self.campaign, board_sat=10000, transfer_sat=5000, maximum_fee_sat=100).advance()
        funding_receipt(self.campaign, "sender", "d" * 64, 0)
        with self.assertRaisesRegex(ValueError, "reused"):
            funding_receipt(self.campaign, "receiver", "d" * 64, 0)


if __name__ == "__main__":
    unittest.main()

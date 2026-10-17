"""Different-expiry controller checks use stub native/Core, not Signet proof."""
import json
import unittest
from unittest.mock import patch

from simulator.model import canonical
from simulator.signet_epochs import S05
from simulator.signet_grouping import S03
from simulator.signet_s02_case import S02
from tests import test_signet_s02 as fixture


class EpochTests(unittest.TestCase):
    setUp, tearDown = fixture.S02Tests.setUp, fixture.S02Tests.tearDown
    receipt = fixture.S02Tests.receipt

    def case(self):
        self.campaign.core = fixture.LifecycleCore()
        return S05(self.campaign, board_sat=30000, maximum_control_fee_sat=1000,
                   recovery_destination="tb1qrecovered")

    def originals(self):
        return {actor: [{"id": digit * 64 + ":0", "chain_anchor": digit * 64 + ":0",
                         "expiry_height": expiry, "amount_sat": 29670, "state": "spendable"}]
                for actor, digit, expiry in [("absent", "a", 184), ("control", "b", 180)]}

    def funded(self):
        for actor in ["absent", "control"]:
            self.campaign.db.execute("INSERT INTO result VALUES (?,?,?)", ("funded-" + actor, 1,
                canonical({"kind": "external_funding", "actor": actor, "amount_sat": 100000})))

    def test_same_expiry_and_reversed_order_do_not_qualify_different_epochs(self):
        coins = self.originals()
        self.assertEqual(S05.originals(coins), coins)
        for height in [180, 179]:
            coins["absent"][0]["expiry_height"] = height
            with self.assertRaisesRegex(ValueError, "earlier actual expiry"):
                S05.originals(coins)

    def test_no_funding_issues_neither_first_board_nor_absence(self):
        case = self.case()
        with patch.object(S02, "prepare", return_value={"stage": "WAITING_FOR_OWNER_ALLOCATED_FUNDING"}), \
             patch.object(case, "_native") as native, patch.object(S03, "_prepare_and_freeze") as later:
            self.assertEqual(case.advance()["stage"], "WAITING_FOR_OWNER_ALLOCATED_FUNDING")
        native.assert_not_called()
        later.assert_not_called()

    def test_first_board_wait_is_durable_and_restart_keeps_the_same_intent(self):
        case = self.case()
        self.funded()
        self.campaign.core.info["blocks"] = 170
        issued = []
        def native(intent, actor, operation, args):
            if not self.campaign.db.execute("SELECT 1 FROM action WHERE id=?", (intent,)).fetchone():
                issued.append(intent)
                self.receipt(intent, operation, {"amount_sat": 29670}, args, actor)
        with patch.object(case, "_native", side_effect=native), patch.object(S03, "_prepare_and_freeze") as later:
            first = case.advance()
            self.campaign.core.info["blocks"] = 173
            second = case.advance()
        self.assertEqual(first["earliest_second_board_height"], 174)
        self.assertEqual(second["stage"], "WAITING_FOR_DIFFERENT_BOARD_HEIGHT")
        self.assertEqual(issued, ["s02-control-board"])
        later.assert_not_called()
        with patch.object(case, "_native", side_effect=native), \
             patch.object(S03, "_prepare_and_freeze") as later:
            self.campaign.core.info["blocks"] = 174
            case._prepare_and_freeze()
        later.assert_called_once()
        self.assertEqual(issued, ["s02-control-board"])

    def completed(self):
        case = self.case()
        originals = self.originals()
        coins = [originals["absent"][0], {**originals["control"][0], "amount_sat": 10000}]
        self.campaign.db.execute("INSERT INTO meta VALUES ('s02_absent:absent',?)", (canonical({"coins": coins}),))
        self.campaign.db.execute("INSERT INTO result VALUES (?,?,?)", ("earlier-payout", 200,
            canonical({"kind": "S02_payout_observation", "payout_check": "PASS", "coin_ids": [coins[1]["id"]],
                       "outpoint": "c" * 64 + ":0", "confirmation_height": 181})))
        return case, {"case_verdict": "PASS", "confirmed_payout_outpoints": ["c" * 64 + ":0", "d" * 64 + ":0"],
                      "confirmed_recovered_payout_sat": 37670}

    def test_merged_or_single_fee_result_cannot_pass_separate_epoch_case(self):
        case, result = self.completed()
        result.update(confirmed_payout_outpoints=["c" * 64 + ":0"], confirmed_recovered_payout_sat=38670)
        with patch.object(S02, "advance", return_value=result):
            self.assertEqual(case.advance()["stage"], "EPOCH_EXPECTATION_FAILED")

    def test_payment_waited_until_later_expiry_does_not_prove_early_release(self):
        case, result = self.completed()
        row = self.campaign.db.execute("SELECT payload FROM result WHERE id='earlier-payout'").fetchone()
        observation = json.loads(row[0]);observation["confirmation_height"] = 184
        self.campaign.db.execute("UPDATE result SET payload=? WHERE id='earlier-payout'", (canonical(observation),))
        with patch.object(S02, "advance", return_value=result):
            self.assertEqual(case.advance()["case_verdict"], "FAIL")

    def test_both_outputs_and_confirmed_seed_recovery_have_only_scoped_credit(self):
        case, result = self.completed()
        with patch.object(S02, "advance", return_value=result):
            actual = case.advance()
        self.assertEqual(actual["case_verdict"], "PASS")
        self.assertEqual(actual["payout_output_fees_sat"], 2000)
        self.assertLess(actual["earlier_payout_confirmation_height"], actual["later_expiry_height"])
        self.assertIn("Continuing post-absence receipts remain a separate case", actual["scope"])

    def test_unknown_action_prevents_second_board_or_transfer(self):
        case = self.case()
        self.receipt("uncertain", "board", {})
        self.campaign.db.execute("UPDATE action SET state='unknown' WHERE id='uncertain'")
        with patch.object(case, "_prepare_and_freeze") as prepare:
            self.assertEqual(case.advance()["stage"], "RECONCILIATION_REQUIRED")
        prepare.assert_not_called()


if __name__ == "__main__":
    unittest.main()

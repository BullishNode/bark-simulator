"""S03 controller invariants with stub native/chain actions; no Signet credit."""
import json
import unittest
from unittest.mock import patch

from simulator.model import canonical
from simulator.signet_grouping import S03
from simulator.signet_s02_case import S02
from simulator.signet_s02 import _freeze
from tests import test_signet_s02 as fixture


class GroupingTests(unittest.TestCase):
    setUp, tearDown = fixture.S02Tests.setUp, fixture.S02Tests.tearDown
    receipt = fixture.S02Tests.receipt

    def case(self):
        self.campaign.core = fixture.LifecycleCore()
        return S03(self.campaign, board_sat=30000, maximum_control_fee_sat=1000,
                   recovery_destination="tb1qrecovered")

    def originals(self):
        return {actor: [{"id": digit * 64 + ":0", "chain_anchor": digit * 64 + ":0",
                         "expiry_height": 180, "amount_sat": 29670, "state": "spendable",
                         "user_pubkey": "02" + "1" * 64}]
                for actor, digit in [("absent", "a"), ("control", "b")]}

    def test_distinct_backing_and_same_expiry_are_required_before_send(self):
        case = self.case()
        coins = self.originals()
        coins["control"][0]["expiry_height"] += 1
        self.receipt("absent-before", "sync_vtxos", coins["absent"])
        self.receipt("control-before", "sync_vtxos", coins["control"], actor="control")
        with patch.object(S02, "prepare", return_value={"stage": "READY_FOR_EXPLICIT_ABSENCE",
                          "snapshot_intents": {"absent": "absent-before", "control": "control-before"}}), \
             patch.object(case, "_native") as native:
            with self.assertRaisesRegex(ValueError, "different-expiry"):
                case.advance()
        native.assert_not_called()
        self.assertIsNone(self.campaign.db.execute("SELECT 1 FROM meta WHERE key='s02_absent:absent'").fetchone())

    def test_two_coin_ids_under_one_anchor_are_not_two_tree_outputs(self):
        coins = self.originals()
        coins["control"][0]["chain_anchor"] = coins["absent"][0]["chain_anchor"]
        with self.assertRaisesRegex(ValueError, "independently backed"):
            S03.originals(coins)

    def test_unknown_original_action_prevents_all_subsequent_work(self):
        case = self.case()
        self.receipt("uncertain", "send", {}, actor="control")
        self.campaign.db.execute("UPDATE action SET state='unknown' WHERE id='uncertain'")
        with patch.object(case, "_prepare_and_freeze") as prepare, patch.object(S02, "advance") as later:
            self.assertEqual(case.advance()["stage"], "RECONCILIATION_REQUIRED")
        prepare.assert_not_called()
        later.assert_not_called()

    def test_funding_wait_does_not_declare_absence(self):
        case = self.case()
        with patch.object(S02, "prepare", return_value={"stage": "WAITING_FOR_OWNER_ALLOCATED_FUNDING"}), \
             patch("simulator.signet_grouping.begin_absence") as absent:
            result = case.advance()
        self.assertEqual(result["case"], "S03")
        self.assertEqual(result["stage"], "WAITING_FOR_OWNER_ALLOCATED_FUNDING")
        absent.assert_not_called()

    def test_actual_pair_checker_precedes_freeze_and_restart_cannot_repeat_payment(self):
        case = self.case()
        fixture.S02Tests.source(self)
        self.campaign.core.info["blocks"] = 170
        coins = self.originals()
        self.receipt("absent-before", "sync_vtxos", coins["absent"], created=1)
        self.receipt("control-before", "sync_vtxos", coins["control"], actor="control", created=2)
        self.receipt("s02-absent-registration", "fallback_record",
                     {"payout_address": "tb1qpayout", "record": {"spk": fixture.SCRIPT}}, created=3)
        sequence = [10]
        payments = []
        def native(intent, actor, operation, args=None):
            old = self.campaign.db.execute("SELECT reply FROM action WHERE id=?", (intent,)).fetchone()
            if old:
                return json.loads(old[0])
            sequence[0] += 1
            if operation == "address":
                reply = {"address": "tark1actualrecipient"}
            elif operation == "send":
                payments.append(intent)
                reply = {}
            elif actor == "control":
                reply = [{**coins["control"][0], "state": "spent"},
                         {**coins["control"][0], "id": "c" * 64 + ":0", "amount_sat": 19670}]
            else:
                reply = coins["absent"] + [{**coins["control"][0], "id": "d" * 64 + ":0", "amount_sat": 10000}]
            self.receipt(intent, operation, reply, args, actor, created=sequence[0])
            return reply
        def proof(campaign, actor, coin, **unused):
            return {"status": "PASS", "coin_id": coin["id"], "path_outpoints": [coin["chain_anchor"], coin["id"]]}
        with patch.object(S02, "prepare", return_value={"stage": "READY_FOR_EXPLICIT_ABSENCE",
                          "snapshot_intents": {"absent": "absent-before", "control": "control-before"}}), \
             patch.object(case, "_native", side_effect=native), \
             patch("simulator.signet_grouping.verify_coin", side_effect=proof), \
             patch("simulator.signet_s02.verify_coin", side_effect=proof), \
             patch("simulator.signet_grouping.confirmed_backing", return_value={"backing": "PASS"}), \
             patch("simulator.signet_checks.confirmed_backing", return_value={"backing": "PASS"}):
            case._prepare_and_freeze()
        self.assertEqual(payments, ["s03-control-to-absent"])
        self.assertEqual(sum(c["amount_sat"] for c in _freeze(self.campaign, "absent")["coins"]), 39670)
        check = json.loads(self.campaign.db.execute("SELECT payload FROM result WHERE id='s03-transfer-check'").fetchone()[0])
        self.assertEqual(check["arithmetic"], "PASS")
        with patch.object(case, "_native") as actions, \
             patch.object(S02, "advance", return_value={"stage": "WAITING_FOR_CANONICAL_PAYOUTS", "case_verdict": "INCOMPLETE"}):
            self.assertEqual(case.advance()["case_verdict"], "INCOMPLETE")
        actions.assert_not_called()

    def completed_fixture(self):
        case = self.case()
        coins = self.originals()
        frozen = {"coins": [coins["absent"][0], {**coins["control"][0], "amount_sat": 10000}]}
        self.campaign.db.execute("INSERT INTO meta VALUES ('s02_absent:absent',?)", (canonical(frozen),))
        self.campaign.db.execute("INSERT INTO meta VALUES ('s03_originals',?)", (canonical({"coins": coins}),))
        return case, {"case_verdict": "PASS", "confirmed_payout_outpoints": ["c" * 64 + ":0"],
                      "confirmed_recovered_payout_sat": 38670}

    def test_two_separate_successful_recoveries_cannot_claim_one_grouped_fee(self):
        case, result = self.completed_fixture()
        result.update(confirmed_payout_outpoints=["c" * 64 + ":0", "d" * 64 + ":0"],
                      confirmed_recovered_payout_sat=37670)
        with patch.object(S02, "advance", return_value=result):
            observed = case.advance()
        self.assertEqual(observed["case_verdict"], "FAIL")
        self.assertEqual(observed["stage"], "GROUPING_EXPECTATION_FAILED")

    def test_correct_single_output_and_one_fee_has_only_narrow_grouping_credit(self):
        case, result = self.completed_fixture()
        with patch.object(S02, "advance", return_value=result):
            observed = case.advance()
        self.assertEqual(observed["case_verdict"], "PASS")
        self.assertEqual(observed["expected_grouped_payout_sat"], 38670)
        self.assertEqual(observed["payout_output_fee_sat"], 1000)
        self.assertIn("Unresolved-root isolation is a separate case", observed["scope"])


if __name__ == "__main__":
    unittest.main()

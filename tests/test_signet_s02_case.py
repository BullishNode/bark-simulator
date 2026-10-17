"""Sequential lifecycle tests with stub native/chain actions; no Signet credit."""
import json
import subprocess
import time
import unittest
from unittest.mock import patch

from simulator.model import canonical
from simulator.signet_s02 import _backup_recovery_source
from simulator.signet_s02_case import S02
from tests import test_signet_s02 as fixture


class S02CaseTests(unittest.TestCase):
    setUp, tearDown = fixture.S02Tests.setUp, fixture.S02Tests.tearDown
    source, receipt, freeze = fixture.S02Tests.source, fixture.S02Tests.receipt, fixture.S02Tests.freeze

    def case(self):
        return S02(self.campaign, board_sat=30000, maximum_control_fee_sat=1000,
                   recovery_destination="tb1qrecovered")

    def test_preparation_waits_for_funds_and_never_starts_absence(self):
        calls = []
        def native(intent, actor, operation, args=None):
            calls.append((actor, operation))
            if operation == "onchain_address":
                return {"address": "tb1qfunding"}
            if operation == "fallback_record":
                return {"payout_address": "tb1qpayout", "record": {"spk": fixture.SCRIPT}}
            if operation == "ark_info":
                return {"vtxo_lifetime": 12, "vtxo_exit_delta": 3,
                        "required_board_confirmations": 3, "min_board_amount_sat": 20000}
            return {}
        self.campaign.core = fixture.LifecycleCore()
        case = self.case()
        with patch.object(case, "_native", side_effect=native):
            progress = case.advance()
        self.assertEqual(progress["stage"], "WAITING_FOR_OWNER_ALLOCATED_FUNDING")
        self.assertNotIn(("absent", "board"), calls)
        self.assertIsNone(self.campaign.db.execute("SELECT value FROM meta WHERE key='s02_absent:absent'").fetchone())
        with self.assertRaisesRegex(ValueError, "immutable"):
            S02(self.campaign, board_sat=31000, maximum_control_fee_sat=1000,
                recovery_destination="tb1qrecovered")

    def prepare_control(self):
        frozen = self.freeze()
        original = {**frozen["coins"][0], "id": "f" * 64 + ":0"}
        self.receipt("control-before", "sync_vtxos", [original], actor="control")
        self.campaign.db.execute("INSERT INTO meta VALUES ('s02_control_before','control-before')")
        return original

    def test_both_boards_are_dispatched_before_waiting_for_public_confirmations(self):
        self.campaign.core = fixture.LifecycleCore()
        for actor in ["absent", "control"]:
            self.campaign.db.execute("INSERT INTO result VALUES (?,?,?)", (
                "funding-" + actor, time.time(), canonical({"kind": "external_funding", "actor": actor, "amount_sat": 100000})))
        calls = []
        def native(intent, actor, operation, args=None):
            calls.append((actor, operation))
            if operation == "onchain_address":
                return {"address": "tb1qfunding"}
            if operation == "fallback_record":
                return {"payout_address": "tb1qpayout", "record": {"spk": fixture.SCRIPT}}
            if operation == "ark_info":
                return {"vtxo_lifetime": 12, "vtxo_exit_delta": 3,
                        "required_board_confirmations": 3, "min_board_amount_sat": 20000}
            if operation == "board":
                return {"amount_sat": 29670}
            if operation == "sync_vtxos":
                return [{"amount_sat": 29670, "state": "locked"}]
            return {}
        case = self.case()
        with patch.object(case, "_native", side_effect=native):
            progress = case.advance()
        self.assertEqual(progress["stage"], "WAITING_FOR_NATIVE_SETTLEMENT")
        self.assertLess(calls.index(("absent", "board")), calls.index(("absent", "sync_vtxos")))
        self.assertLess(calls.index(("control", "board")), calls.index(("absent", "sync_vtxos")))

    def test_unknown_native_outcome_holds_all_later_actions(self):
        self.campaign.core = fixture.LifecycleCore()
        self.receipt("unknown-coin-operation", "maintain", {}, actor="control")
        self.campaign.db.execute("UPDATE action SET state='unknown' WHERE id='unknown-coin-operation'")
        case = self.case()
        with patch.object(case, "_native") as native:
            progress = case.advance()
        self.assertEqual(progress["stage"], "RECONCILIATION_REQUIRED")
        native.assert_not_called()

    def test_invalid_recovery_destination_is_rejected_before_native_actions(self):
        self.campaign.core = fixture.LifecycleCore()
        with patch.object(self.campaign.core, "call", return_value={"isvalid": False}), \
             patch("simulator.signet.subprocess.run") as native:
            with self.assertRaisesRegex(ValueError, "recovery destination"):
                self.case()
        native.assert_not_called()
        self.assertEqual(self.campaign.db.execute("SELECT count(*) FROM action").fetchone()[0], 0)

    def test_completed_case_never_opens_control_again_but_unknown_still_holds(self):
        self.campaign.core = fixture.LifecycleCore()
        case = self.case()
        completed = {"kind": "case_result", "case": "S02", "actor": "absent",
                     "case_verdict": "PASS", "stage": "COMPLETE",
                     "chain": {"height": 200}, "confirmed_recovered_payout_sat": 9000}
        self.campaign.db.execute("INSERT INTO result VALUES (?,?,?)", (
            "original-complete", time.time(), canonical(completed)))
        with patch.object(case, "_native") as native, \
             patch("simulator.signet_s02_case.network_identity") as network:
            self.assertEqual(case.advance(), completed)
            self.assertEqual(case.advance(), completed)
            self.receipt("post-pass-unknown", "maintain", {}, actor="control")
            self.campaign.db.execute("UPDATE action SET state='unknown' WHERE id='post-pass-unknown'")
            self.assertEqual(case.advance()["stage"], "RECONCILIATION_REQUIRED")
        native.assert_not_called()
        network.assert_not_called()

    def test_absent_wallet_is_never_opened_while_waiting_for_chain_payout(self):
        original = self.prepare_control()
        case = self.case()
        calls = []
        def native(intent, actor, operation, args=None):
            calls.append((actor, operation))
            return [original] if operation == "sync_vtxos" else {}
        with patch.object(case, "_native", side_effect=native), \
             patch("simulator.signet_s02_case.check_control", return_value={"control_check": "INCOMPLETE"}), \
             patch("simulator.signet_s02_case.discover_payouts", return_value={"case_verdict": "INCOMPLETE"}):
            progress = case.advance()
        self.assertEqual(progress["stage"], "WAITING_FOR_CANONICAL_PAYOUTS")
        self.assertTrue(calls)
        self.assertEqual({actor for actor, _ in calls}, {"control"})

    def test_seed_restore_and_single_drain_wait_for_real_confirmation_then_reconcile(self):
        original = self.prepare_control()
        self.receipt("s02-absent-create", "create", {}, actor="absent")
        self.campaign.db.execute("UPDATE action SET chain=? WHERE id='s02-absent-create'", (canonical({"height": 100}),))
        from simulator.signet_s02 import observe_payout
        observe_payout(self.campaign, "absent", fixture.PAYOUT, 0, ["e" * 64 + ":0"])
        replacement = {**original, "id": "0" * 64 + ":0", "amount_sat": 9900, "expiry_height": 220}
        case = self.case()
        def native(intent, actor, operation, args=None):
            self.assertNotEqual(actor, "absent")
            old = self.campaign.db.execute("SELECT reply FROM action WHERE id=?", (intent,)).fetchone()
            if old:
                return json.loads(old[0])
            reply = {}
            if operation == "sync_vtxos":
                reply = [{**original, "state": "spent"}, replacement]
            elif operation == "onchain_utxos":
                reply = [{"outpoint": fixture.PAYOUT + ":0", "amount_sat": 9000, "confirmation_height": 190}]
            elif operation == "onchain_drain":
                reply = {"txid": fixture.RECOVERY}
            self.receipt(intent, operation, reply, args, actor=actor, created=time.time())
            return reply
        self.campaign.core.transactions[fixture.RECOVERY]["confirmations"] = 0
        with patch.object(case, "_native", side_effect=native), \
             patch("simulator.signet_s02.verify_coin", return_value={"status": "PASS"}), \
             patch("simulator.signet_s02_case.discover_payouts", return_value={"case_verdict": "INCOMPLETE"}):
            waiting = case.advance()
            self.assertEqual(waiting["stage"], "WAITING_FOR_CONFIRMED_RECOVERY_SPEND")
            self.campaign.core.transactions[fixture.RECOVERY]["confirmations"] = 1
            complete = case.advance()
        self.assertEqual(complete["case_verdict"], "PASS")
        self.assertEqual(complete["confirmed_recovered_payout_sat"], 9000)
        self.assertEqual(self.campaign.db.execute("SELECT count(*) FROM action WHERE operation='restore'").fetchone()[0], 1)
        self.assertEqual(self.campaign.db.execute("SELECT count(*) FROM action WHERE operation='onchain_drain'").fetchone()[0], 1)
        restore = json.loads(self.campaign.db.execute("SELECT arguments FROM action WHERE id='s02-seed-restore'").fetchone()[0])
        self.assertEqual(restore["source_actor"], "absent")
        self.assertEqual(restore["birthday_height"], 100)
        self.assertEqual(restore["wallet_profile"]["vtxo_exit_margin"], 2)

    def test_restore_profile_is_written_before_native_process_and_pinned_afterwards(self):
        self.source()
        _backup_recovery_source(self.campaign, "absent")
        args = {"source_actor": "absent", "birthday_height": 100,
                "wallet_profile": {"vtxo_refresh_expiry_threshold": 4, "vtxo_exit_margin": 2}}
        def native(argv, **kwargs):
            config = (self.campaign.actor_path("restored") / "config.toml").read_text()
            self.assertIn("vtxo_exit_margin = 2", config)
            self.assertIn("--mnemonic-file", argv)
            self.assertNotIn("--ark", argv)
            return subprocess.CompletedProcess(argv, 0)
        with patch("simulator.signet.subprocess.run", side_effect=native):
            result = self.campaign.execute("profile-restore", "restored", "restore", args)
        self.assertEqual(result["state"], "acknowledged")
        path = self.campaign.actor_path("restored") / "config.toml"
        path.write_text(path.read_text().replace("vtxo_exit_margin = 2", "vtxo_exit_margin = 12"))
        with patch("simulator.signet.subprocess.run") as native:
            with self.assertRaisesRegex(ValueError, "configuration changed"):
                self.campaign.execute("changed-restore-open", "restored", "onchain_utxos", {})
        native.assert_not_called()


if __name__ == "__main__":
    unittest.main()

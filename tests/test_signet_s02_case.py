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

    def case(self, profile="short"):
        return S02(self.campaign, board_sat=30000, maximum_control_fee_sat=1000,
                   recovery_destination="tb1qrecovered", profile=profile)

    def test_legacy_parameters_stay_identical_and_cannot_be_relabelled_production(self):
        self.campaign.core = fixture.LifecycleCore()
        original = canonical({"board_sat": 30000, "maximum_control_fee_sat": 1000,
                              "recovery_destination": "tb1qrecovered",
                              "wallet_profile": {"vtxo_refresh_expiry_threshold": 4, "vtxo_exit_margin": 2}})
        self.campaign.db.execute("INSERT INTO meta VALUES ('s02_parameters',?)", (original,))
        self.case()
        with self.assertRaisesRegex(ValueError, "immutable"):
            self.case("production")
        self.assertEqual(self.campaign.db.execute("SELECT value FROM meta WHERE key='s02_parameters'").fetchone()[0], original)
        self.assertEqual(self.campaign.db.execute("SELECT count(*) FROM action").fetchone()[0], 0)

    def test_profile_selection_precedes_existing_actor_actions_or_any_native_work(self):
        self.campaign.core = fixture.LifecycleCore()
        with patch.object(self.campaign.core, "call") as core:
            with self.assertRaisesRegex(ValueError, "explicit short or production"):
                self.case("custom")
            self.receipt("existing-actor", "create", {})
            with self.assertRaisesRegex(ValueError, "before actor actions"):
                self.case("production")
        core.assert_not_called()
        self.assertIsNone(self.campaign.db.execute("SELECT 1 FROM meta WHERE key='s02_parameters'").fetchone())

    def test_production_preparation_pins_exact_geometry_and_waits_for_real_funding(self):
        self.campaign.core = fixture.LifecycleCore()
        case = self.case("production")
        target = {"network": "signet", "vtxo_lifetime": 4320, "vtxo_exit_delta": 144,
                  "required_board_confirmations": 3, "min_board_amount_sat": 20000}
        calls = []
        def native(intent, actor, operation, args=None):
            calls.append((actor, operation, args))
            if operation == "onchain_address":
                return {"address": "tb1qfunding"}
            if operation == "fallback_record":
                return {"payout_address": "tb1qpayout", "record": {"spk": fixture.SCRIPT}}
            return target if operation == "ark_info" else {}
        with patch.object(case, "_native", side_effect=native):
            self.assertEqual(case.advance()["stage"], "WAITING_FOR_OWNER_ALLOCATED_FUNDING")
            self.assertEqual([args["wallet_profile"] for _, op, args in calls if op == "create"],
                             [{"vtxo_refresh_expiry_threshold": 144, "vtxo_exit_margin": 12}] * 2)
            for key, wrong in [("vtxo_lifetime", 32), ("vtxo_exit_delta", 12),
                               ("required_board_confirmations", 1), ("network", "bitcoin"),
                               ("vtxo_exit_delta", 144.0)]:
                with self.subTest(key=key, wrong=wrong), patch.dict(target, {key: wrong}):
                    with self.assertRaisesRegex(ValueError, "server profile differs"):
                        case.prepare()
        self.assertNotIn("board", [op for _, op, _ in calls])
        self.assertIsNone(self.campaign.db.execute("SELECT 1 FROM meta WHERE key='s02_absent:absent'").fetchone())

    def test_production_absence_cannot_skip_original_target_admission(self):
        self.campaign.core = fixture.LifecycleCore()
        case = self.case("production")
        self.prepare_control()
        with patch.object(case, "_native") as native:
            with self.assertRaisesRegex(ValueError, "original production S02 target admission"):
                case.advance()
        native.assert_not_called()

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

    def test_production_waits_for_parent_child_and_exact_recovery_six_confirmations(self):
        self.campaign.core = fixture.LifecycleCore()
        case = self.case("production")
        original = self.prepare_control()
        self.receipt("s02-target-info", "ark_info", case.target_profile, actor="control")
        self.receipt("s02-absent-create", "create", {}, actor="absent")
        self.campaign.db.execute("UPDATE action SET chain=? WHERE id='s02-absent-create'", (canonical({"height": 100}),))
        from simulator.signet_s02 import observe_payout
        payout = observe_payout(self.campaign, "absent", fixture.PAYOUT, 0, ["e" * 64 + ":0"])
        replacement = {**original, "id": "0" * 64 + ":0", "amount_sat": 9900, "expiry_height": 240}
        def native(intent, actor, operation, args=None):
            self.assertNotEqual(actor, "absent")
            row = self.campaign.db.execute("SELECT reply FROM action WHERE id=?", (intent,)).fetchone()
            if row:
                return json.loads(row[0])
            reply = {}
            if operation == "sync_vtxos":
                reply = [{**original, "state": "spent"}, replacement]
            elif operation == "onchain_utxos":
                reply = [{"outpoint": fixture.PAYOUT + ":0", "amount_sat": 9000, "confirmation_height": 190}]
            elif operation == "onchain_drain":
                reply = {"txid": fixture.RECOVERY}
            self.receipt(intent, operation, reply, args, actor=actor, created=time.time())
            return reply
        with patch.object(case, "_native", side_effect=native), \
             patch("simulator.signet_s02.verify_coin", return_value={"status": "PASS"}), \
             patch("simulator.signet_s02_case.discover_payouts", return_value={"case_verdict": "INCOMPLETE"}), \
             patch("simulator.signet_repair._fee_child") as fee:
            for child in [None, {"confirmations": 5}]:
                fee.return_value = child
                self.assertEqual(case.advance()["stage"], "WAITING_FOR_SIX_CONFIRMED_PARENTS_AND_CHILDREN")
            fee.return_value = {"confirmations": 6}
            with patch.object(case, "_payouts", return_value=([("unused", {**payout, "confirmations": 5})], True)):
                self.assertEqual(case.advance()["stage"], "WAITING_FOR_SIX_CONFIRMED_PARENTS_AND_CHILDREN")
            self.assertEqual(self.campaign.db.execute("SELECT count(*) FROM action WHERE operation IN ('restore','onchain_drain')").fetchone()[0], 0)
            def advance_chain():
                self.campaign.core.info["blocks"] += 1
                for transaction in self.campaign.core.transactions.values():
                    transaction["confirmations"] += 1
            def proof_after_new_block(*args):
                advance_chain()
                return {"confirmations": 6}
            fee.side_effect = proof_after_new_block
            self.assertEqual(case.advance()["stage"], "WAITING_FOR_STABLE_CHAIN_VIEW")
            def chain_moved_during_proof(*args):
                advance_chain()
                raise ValueError("proof crossed a changing canonical view")
            fee.side_effect = chain_moved_during_proof
            self.assertEqual(case.advance()["stage"], "WAITING_FOR_STABLE_CHAIN_VIEW")
            fee.side_effect = ValueError("invalid proof on the unchanged chain")
            with self.assertRaisesRegex(ValueError, "invalid proof on the unchanged chain"):
                case.advance()
            fee.side_effect = None
            self.assertEqual(self.campaign.db.execute("SELECT count(*) FROM action WHERE operation IN ('restore','onchain_drain')").fetchone()[0], 0)
            waiting = case.advance()
            self.assertEqual(waiting["stage"], "WAITING_FOR_SIX_CONFIRMED_RECOVERY_SPEND")
            self.assertEqual(waiting["confirmations"], 3)
            with patch("simulator.signet_s02_case._confirmed_transaction", side_effect=chain_moved_during_proof):
                self.assertEqual(case.advance()["stage"], "WAITING_FOR_STABLE_CHAIN_VIEW")
            self.assertIsNone(self.campaign.db.execute("SELECT 1 FROM result WHERE json_extract(payload,'$.kind')='case_result'").fetchone())
            increment = 6 - self.campaign.core.transactions[fixture.RECOVERY]["confirmations"]
            self.campaign.core.info["blocks"] += increment
            for transaction in self.campaign.core.transactions.values():
                transaction["confirmations"] += increment
            self.assertEqual(case.advance()["case_verdict"], "PASS")
        self.assertEqual(self.campaign.db.execute("SELECT count(*) FROM action WHERE operation='restore'").fetchone()[0], 1)
        self.assertEqual(self.campaign.db.execute("SELECT count(*) FROM action WHERE operation='onchain_drain'").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()

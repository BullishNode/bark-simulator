"""Closed-window audit guards with real controller/SQLite and stub native/Core."""
import json
import unittest
from unittest.mock import patch

from simulator.signet_load import _transfer
from tests import test_signet, test_signet_load


class ClosedWindowAuditTests(unittest.TestCase):
    setUp = test_signet.SignetTests.setUp
    tearDown = test_signet.SignetTests.tearDown
    worker_fixture = test_signet_load.LoadTests.worker_fixture
    native = test_signet_load.LoadTests.native
    child_campaign = test_signet_load.LoadTests.child_campaign

    def test_partial_window_audits_actual_money_without_changing_original_hold(self):
        phase = self.worker_fixture(transfers=2)
        self.campaign.db.execute("INSERT INTO meta VALUES ('load_admitted',?)", (json.dumps({"opening_coin_sat": 120000}),))
        hold = {"stage": "LOAD_WINDOW_LIMIT_REACHED", "successful_reconciled_transfers": 1,
                "intended_transfers": 2, "money_dispatched": False}
        with patch("simulator.signet.Campaign", side_effect=self.child_campaign), \
             patch("simulator.signet_phase._verify_runtime"), \
             patch("simulator.signet_load.verify_coin", return_value={"status": "PASS"}), \
             patch("simulator.signet.subprocess.run", side_effect=self.native) as native:
            _transfer(self.campaign.root, self.config, phase.parameters, 0)
            self.campaign.db.execute("INSERT INTO meta VALUES ('load_hold',?)", (json.dumps(hold),))
            sends = sum(call.args[0][5] == "send" for call in native.call_args_list)
            result = phase.audit_closed_window()
            self.assertEqual(sum(call.args[0][5] == "send" for call in native.call_args_list), sends)
        self.assertEqual(result["stage"], "LOAD_INCOMPLETE_WINDOW_FINANCIALLY_AUDITED")
        self.assertEqual(result["case_verdict"], "INCOMPLETE")
        self.assertFalse(result["workload_complete"])
        self.assertEqual(result["successful_reconciled_transfers"], 1)
        self.assertEqual(result["intended_transfers"], 2)
        self.assertEqual(result["not_dispatched_transfers"], 1)
        self.assertEqual(result["opening_coin_sat"], result["closing_coin_sat"])
        self.assertEqual(json.loads(self.campaign.db.execute("SELECT value FROM meta WHERE key='load_hold'").fetchone()[0]), hold)
        self.assertEqual(phase.parameters["transfers"], 2)
        with self.assertRaisesRegex(ValueError, "unreconciled"):
            phase.finish()
        with self.assertRaisesRegex(ValueError, "held"):
            phase.advance_batch()

    def test_other_failures_unknowns_or_unreconciled_ack_cannot_be_audited_as_clean(self):
        phase = self.worker_fixture(transfers=2)
        self.campaign.db.execute("INSERT INTO meta VALUES ('load_hold',?)", (json.dumps({"stage": "LOAD_BATCH_HOLD"}),))
        with patch.object(phase, "native") as native:
            with self.assertRaisesRegex(ValueError, "only a terminal"):
                phase.audit_closed_window()
            self.campaign.db.execute("UPDATE meta SET value=? WHERE key='load_hold'", (json.dumps({
                "stage": "LOAD_WINDOW_LIMIT_REACHED", "successful_reconciled_transfers": 1,
                "intended_transfers": 2}),))
            self.campaign.db.execute("INSERT INTO action VALUES (?,?,?,?,?,?,?,?,?,?)", (
                "original-send", "load-000", "send", "{}", "unknown", 0, 0, None, None, "lost reply"))
            with self.assertRaisesRegex(ValueError, "requires reconciliation"):
                phase.audit_closed_window()
            self.campaign.db.execute("UPDATE action SET state='acknowledged' WHERE id='original-send'")
            with self.assertRaisesRegex(ValueError, "every original acknowledged"):
                phase.audit_closed_window()
            native.assert_not_called()


if __name__ == "__main__":
    unittest.main()

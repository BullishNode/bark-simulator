"""Bounded reporting and action timing; stub processes are not Signet evidence."""
import json
import subprocess
import unittest
from unittest.mock import patch

from simulator.model import canonical
from simulator.signet_load import Load
from tests import test_signet


class LoadProgressTests(unittest.TestCase):
    setUp = test_signet.SignetTests.setUp
    tearDown = test_signet.SignetTests.tearDown

    def test_large_history_stays_in_journal_not_progress(self):
        phase = Load(self.campaign)
        payload = canonical({"kind": "historic_observation", "details": "x" * 20000})
        self.campaign.db.executemany("INSERT INTO result VALUES (?,?,?)",
            [(f"history-{i}", i, payload) for i in range(500)])
        self.campaign.db.execute("INSERT INTO meta VALUES ('load_hold','{}')")
        batch = {"stage": "LOAD_BATCH_HOLD", "results": [
            {"signature_proofs": [payload], "timings": {"wallet_subprocess_seconds": 2.5}}],
            "failures": [{"error": "private diagnostic must remain in original journal"}],
            "resource_observation": {"samples": 4, "sample_interval_seconds": .05,
                "maximum_observed_rss_kib": {"controller": 1234, "captaind": 5678},
                "reaped_child_cpu_seconds": {"user": 1.25, "system": .5}}}
        destination = self.root / "progress.json"
        with patch.object(self.campaign, "report", side_effect=AssertionError("full report forbidden")):
            cost = phase.write_observation(destination, batch=batch)
        result = json.loads(destination.read_text())
        self.assertTrue(result["held"])
        self.assertEqual(result["latest_batch"]["failure_count"], 1)
        self.assertEqual(result["latest_batch"]["timings"]["wallet_subprocess_seconds"], 2.5)
        self.assertEqual(result["latest_batch"]["resource_observation"], batch["resource_observation"])
        self.assertLess(cost["bytes"], 2000)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.campaign.db.execute("SELECT count(*) FROM result").fetchone()[0], 500)
        self.assertEqual(self.campaign.db.execute("SELECT payload FROM result LIMIT 1").fetchone()[0], payload)

    def test_full_start_end_report_and_write_timings_preserve_original_shape(self):
        phase = Load(self.campaign)
        expected = self.campaign.report()
        destination = self.root / "full-report.json"
        cost = phase.write_observation(destination, full=True)
        self.assertEqual(json.loads(destination.read_text()), expected)
        self.assertTrue(cost["full"])
        for key in ("projection_seconds", "serialization_seconds", "write_seconds",
                    "wall_seconds", "controller_cpu_seconds"):
            self.assertGreaterEqual(cost[key], 0)
        self.assertEqual(cost["bytes"], len(destination.read_bytes()))

    def test_unknown_process_records_time_without_replay_or_changed_action_reply(self):
        args = {"destination": "tark1abcdef", "amount_sat": 1000}
        with patch("simulator.signet.subprocess.run", side_effect=subprocess.TimeoutExpired("bark", 1)) as run:
            original = self.campaign.execute("timed-send", "alice", "send", args)
            timings = dict(self.campaign.timings)
            replay = self.campaign.execute("timed-send", "alice", "send", args)
        self.assertEqual(original, replay)
        self.assertEqual(original["state"], "unknown")
        self.assertEqual(run.call_count, 1)
        self.assertEqual(timings, self.campaign.timings)
        self.assertEqual(timings["wallet_subprocess_calls"], 1)
        self.assertEqual(timings["wallet_binary_hash_calls"], 1)

    def test_actual_binary_change_still_refuses_before_dispatch(self):
        self.binary.write_bytes(b"different executable")
        with patch("simulator.signet.subprocess.run") as run:
            with self.assertRaisesRegex(ValueError, "executable hash changed"):
                self.campaign.execute("bad-hash", "alice", "send",
                    {"destination": "tark1abcdef", "amount_sat": 1000})
        run.assert_not_called()
        self.assertEqual(self.campaign.db.execute("SELECT count(*) FROM action").fetchone()[0], 0)
        self.assertEqual(self.campaign.timings["wallet_binary_hash_calls"], 1)

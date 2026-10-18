"""Real pacing/SQLite regression with a fake clock and stub transfers; no load proof."""
import json
import sqlite3
import unittest
from unittest.mock import patch

from simulator.signet_load import Load
from tests import test_signet


class Clock:
    def __init__(self):
        self.now = 1000.0
        self.sleeps = []
        self.on_sleep = None

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds
        if self.on_sleep:
            self.on_sleep()


class StubSamples:
    def __enter__(self):
        self.result = {"scope": "resource sampler stub; no CPU or memory proof"}
        return self

    def __exit__(self, *_):
        pass


class LoadPacingTests(unittest.TestCase):
    setUp = test_signet.SignetTests.setUp
    tearDown = test_signet.SignetTests.tearDown

    def phase(self, transfers=15, window_seconds=30):
        result = Load(self.campaign, wallets=50, concurrency=5, transfers=transfers,
                      funding_sat_per_actor=40000, window_seconds=window_seconds)
        self.campaign.db.execute("INSERT INTO meta VALUES ('load_admitted','{}')")
        return result

    def complete_stub_transfer(self, directory, config, parameters, index):
        # Keep the real durable pending/completed scheduling, without calling a
        # wallet or claiming any financial conservation from these stub replies.
        result = {"index": index, "scope": "stub transfer, not a payment proof"}
        with sqlite3.connect(directory / "signet.sqlite", timeout=10) as db:
            db.execute("INSERT INTO result VALUES (?,?,?)", (
                f"load-transfer-{index:06d}-complete", self.clock.now, json.dumps(result)))
        return result

    def run_clocked(self, phase, function):
        self.clock = Clock()
        with patch("simulator.signet_load.time.time", side_effect=lambda: self.clock.now), \
             patch("simulator.signet_load.time.sleep", side_effect=self.clock.sleep), \
             patch("simulator.signet_load.RSSSamples", side_effect=lambda _: StubSamples()), \
             patch("simulator.signet_load._transfer", side_effect=self.complete_stub_transfer) as transfer:
            function(transfer)

    def starts(self):
        return [(observed, json.loads(payload)["pacing"]) for observed, payload in self.campaign.db.execute(
            "SELECT observed,payload FROM result WHERE json_extract(payload,'$.kind')='load_batch_started' ORDER BY observed")]

    def test_600_stub_operations_keep_schedule_after_each_reporting_cost(self):
        phase = self.phase(transfers=600, window_seconds=1200)

        def run(transfer):
            for _ in range(120):
                result = phase.advance_batch(wait_until_due=True)
                self.assertEqual(result["stage"], "LOAD_BATCH_RECONCILED")
                # Previously a delay calculated before this work added its cost
                # to every interval. The next call now computes what remains.
                self.clock.now += 6.5
            self.assertEqual(phase.advance_batch(wait_until_due=True)["stage"], "LOAD_WORKLOAD_COMPLETE")
            self.assertEqual(transfer.call_count, 600)

        self.run_clocked(phase, run)
        starts = self.starts()
        self.assertEqual([observed for observed, _ in starts], [1000 + 10 * i for i in range(120)])
        self.assertLess(starts[-1][0], starts[0][0] + 1200)
        self.assertTrue(all(p["actual_started_at"] == p["scheduled_start_at"] and
                            p["schedule_lateness_seconds"] == 0 for _, p in starts))
        self.assertEqual(starts[1][1]["controller_requested_at"], 1006.5)
        self.assertEqual(phase.parameters["window_seconds"], 1200)

    def test_slow_reporting_is_recorded_without_a_catchup_burst(self):
        phase = self.phase()

        def run(transfer):
            phase.advance_batch(wait_until_due=True)
            self.clock.now += 14
            late = phase.advance_batch(wait_until_due=True)
            self.assertEqual(late["pacing"]["schedule_lateness_seconds"], 4)
            next_batch = phase.advance_batch(wait_until_due=True)
            self.assertEqual(next_batch["pacing"]["actual_started_at"], 1024)
            self.assertEqual(transfer.call_count, 15)

        self.run_clocked(phase, run)
        self.assertEqual([v[0] for v in self.starts()], [1000, 1014, 1024])

    def test_original_window_expires_during_wait_without_dispatch_or_extension(self):
        phase = self.phase()

        def run(transfer):
            phase.advance_batch(wait_until_due=True)
            self.clock.now += 20
            phase.advance_batch(wait_until_due=True)
            self.clock.now += 8
            result = phase.advance_batch(wait_until_due=True)
            self.assertEqual(result["stage"], "LOAD_WINDOW_LIMIT_REACHED")
            self.assertFalse(result["money_dispatched"])
            self.assertEqual(self.clock.now, 1030)
            self.assertEqual(transfer.call_count, 10)
            with self.assertRaisesRegex(ValueError, "held"):
                phase.advance_batch(wait_until_due=True)

        self.run_clocked(phase, run)
        self.assertEqual(len(self.starts()), 2)
        self.assertEqual(phase.parameters["window_seconds"], 30)

    def test_unknown_original_action_appearing_during_wait_blocks_next_batch(self):
        phase = self.phase()

        def run(transfer):
            phase.advance_batch(wait_until_due=True)

            def unresolved():
                self.clock.on_sleep = None
                self.campaign.db.execute("INSERT INTO action VALUES (?,?,?,?,?,?,?,?,?,?)", (
                    "original-uncertain-send", "load-000", "send", "{}", "unknown",
                    self.clock.now, self.clock.now, None, None, "original reply lost"))

            self.clock.on_sleep = unresolved
            with self.assertRaisesRegex(ValueError, "requires reconciliation"):
                phase.advance_batch(wait_until_due=True)
            self.assertEqual(transfer.call_count, 5)

        self.run_clocked(phase, run)
        self.assertEqual(len(self.starts()), 1)

    def test_stop_during_wait_leaves_next_intent_undispatched(self):
        phase = self.phase()

        def run(transfer):
            phase.advance_batch(wait_until_due=True)
            result = phase.advance_batch(wait_until_due=True,
                                         stop_requested=lambda: self.clock.now >= 1002)
            self.assertEqual(result["stage"], "LOAD_STOP_REQUESTED")
            self.assertFalse(result["money_dispatched"])
            self.assertEqual(transfer.call_count, 5)

        self.run_clocked(phase, run)
        self.assertEqual(len(self.starts()), 1)


if __name__ == "__main__":
    unittest.main()

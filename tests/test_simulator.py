import asyncio
import json
import random
import sys
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, patch
from decimal import Decimal
from pathlib import Path

from simulator.config import Config
from simulator.engine import Engine, Lease, catalog, initialize
from simulator.model import SIGNET_GENESIS, InvariantError, btc_to_sat, capital_summary, fee_allocation, public_payload, unique_settlement_fee
from simulator.process import CommandError, decode_object, json_command
from simulator.observations import observe, recorded_observations
from simulator.report import generate
from simulator.store import Store
from simulator.workload import record_actor_result, schedule_pilot
from simulator.vm_observer import confirmed_value


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name), "synthetic", 100)
        initialize(self.store)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def queue(self, identifier="action1", fee=40, actor="actor-01"):
        self.store.queue(identifier, actor, "H01", "create", {}, fee)

    def test_80_unique_behaviors(self):
        cases = catalog()
        self.assertEqual([f"H{i:02}" for i in range(1, 41)] + [f"D{i:02}" for i in range(1, 41)], [c["id"] for c in cases])

    def test_budget_reservations_survive_unknown_outcome(self):
        self.queue()
        action = self.store.claim({"create"})
        self.store.finish(action["id"], "outcome_unknown", {})
        with self.assertRaises(ValueError):
            self.queue("too-much", 61)
        self.queue("can-afford", 60, "actor-02")

    def test_offline_actor_not_dispatched(self):
        self.queue()
        self.store.set_online("actor-01", False)
        self.assertIsNone(self.store.claim({"create"}))

    def test_same_actor_unknown_blocks_next_request(self):
        self.queue()
        self.store.claim({"create"})
        self.store.recover_dispatched()
        self.queue("second")
        self.assertIsNone(self.store.claim({"create"}))

    def test_only_dispatched_may_finish(self):
        self.queue()
        with self.assertRaises(ValueError):
            self.store.finish("action1", "completed", {})

    def test_pause_after_actual_fee_exceeds_budget(self):
        self.queue()
        self.store.claim({"create"})
        self.store.finish("action1", "completed", {}, 41)
        self.assertEqual(self.store.get_meta("paused"), "incident")
        self.assertIsNone(self.store.claim({"create"}))

    def test_restart_preserves_offline_and_marks_dispatch_unknown(self):
        self.queue()
        self.store.claim({"create"})
        self.store.set_online("actor-09", False)
        self.store.close()
        self.store = Store(Path(self.temp.name), "synthetic", 100)
        self.assertEqual(self.store.recover_dispatched(), 1)
        self.assertFalse(self.store.online("actor-09"))
        self.assertIsNone(self.store.claim({"create"}))

    def add_coins(self):
        self.store.add_entitlement("a", "actor-09", "registered", 12_000, "user", {"fixture": True})
        self.store.add_entitlement("b", "actor-09", "pending_board", 8000, "user", {"fixture": True})

    def payout(self):
        return {"txid": "tx", "inputs": [{"amount_sat": 22_000}],
                "outputs": [{"script": "user", "amount_sat": 19_000}, {"script": "change", "amount_sat": 1900}]}

    def test_grouped_payout_resolves_once(self):
        self.add_coins()
        self.store.record_payout(self.payout(), ["a", "b"], 1000, 100)
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM resolution").fetchone()[0], 2)
        with self.assertRaises(InvariantError):
            self.store.record_payout({**self.payout(), "txid": "second"}, ["a", "b"], 1000, 100)

    def test_identical_payout_observation_replay_is_idempotent(self):
        self.add_coins()
        self.store.record_payout(self.payout(),["a","b"],1000,100)
        tip=self.store.verify_event_chain()
        self.store.record_payout(self.payout(),["b","a"],1000,100)
        self.assertEqual(self.store.verify_event_chain(),tip)
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM resolution").fetchone()[0],2)
        altered=self.payout()
        altered["outputs"][0]["script"]="other"
        with self.assertRaises(InvariantError):
            self.store.record_payout(altered,["a","b"],1000,100)

    def test_wrong_payee_rolls_back_every_state_change(self):
        self.add_coins()
        tx = self.payout()
        tx["outputs"][0]["script"] = "attacker"
        with self.assertRaises(InvariantError):
            self.store.record_payout(tx, ["a", "b"], 1000, 100)
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM payout").fetchone()[0], 0)
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM entitlement WHERE state='live'").fetchone()[0], 2)

    def test_bad_operator_fee_detected(self):
        self.add_coins()
        with self.assertRaises(InvariantError):
            self.store.record_payout(self.payout(), ["a", "b"], 1100, 0)

    def test_replacement_not_counted_twice_and_cannot_pay_predecessor(self):
        self.store.add_entitlement("a", "actor-09", "registered", 20_000, "user", {})
        self.store.add_entitlement("b", "actor-09", "hark_unclaimed", 19_900, "user", {}, "a")
        self.assertEqual(self.store.db.execute("SELECT SUM(gross_sat) FROM entitlement WHERE state='live'").fetchone()[0], 19_900)
        with self.assertRaises(InvariantError):
            self.store.record_payout(self.payout(), ["a"], 1000, 100)

    def test_invalid_replacement_rolls_back_predecessor(self):
        self.store.add_entitlement("a", "actor-09", "registered", 20_000, "user", {})
        with self.assertRaises(InvariantError):
            self.store.add_entitlement("b", "actor-10", "registered", 20_000, "user", {}, "a")
        self.assertEqual(self.store.db.execute("SELECT state FROM entitlement WHERE id='a'").fetchone()[0], "live")

    def test_event_tampering_detected(self):
        self.store.event("test", {"value": 1})
        self.store.verify_event_chain()
        self.store.db.execute("UPDATE event SET payload='{}' WHERE sequence=1")
        with self.assertRaises(InvariantError):
            self.store.verify_event_chain()

    def test_report_does_not_promote_action_into_scenario_pass(self):
        self.queue()
        self.store.claim({"create"})
        self.store.finish("action1", "completed", {}, 0)
        report = generate(self.store)
        case = next(c for c in report["coverage"] if c["id"] == "H01")
        self.assertEqual(case["scenario_verdict"], "not_qualified")
        self.assertEqual(len(report["actors"]), 12)
        self.assertIn("SYNTHETIC", (Path(self.temp.name) / "index.html").read_text())

    def test_epoch_cannot_mix_live_and_synthetic(self):
        with self.assertRaises(ValueError):
            Store(Path(self.temp.name), "live", 100)

    def test_target_identity_cannot_be_changed_mid_epoch(self):
        identity = {"network": "signet", "image_digest": "first"}
        self.store.bind_target(identity)
        self.store.bind_target(identity)
        with self.assertRaises(ValueError):
            self.store.bind_target({**identity, "image_digest": "replacement"})
        self.assertEqual(json.loads(self.store.get_meta("target_identity")), identity)

    def test_actor_state_and_action_result_commit_together(self):
        self.queue()
        self.store.claim({"create"})
        def faulty_update():
            record_actor_result(self.store, "actor-01", "create", {"funding_address": "test", "fallback_script":"script", "fallback_seq":1})
            raise RuntimeError("crash before transaction commit")
        with self.assertRaises(RuntimeError):
            self.store.finish("action1", "completed", {}, 0, on_completed=faulty_update)
        self.assertEqual(self.store.db.execute("SELECT state FROM action").fetchone()[0], "dispatched")
        self.assertNotIn("created", json.loads(self.store.db.execute("SELECT details FROM actor WHERE id='actor-01'").fetchone()[0]))

    def test_pilot_absence_never_wakes_actor(self):
        record_actor_result(self.store, "actor-09", "create", {"funding_address": "test", "fallback_script":"script", "fallback_seq":1})
        record_actor_result(self.store, "actor-09", "address", {"address": "ark-test"})
        record_actor_result(self.store, "actor-09", "snapshot", {"balance": {"spendable_sat": 12000}, "onchain":{"confirmed_sat":0}, "vtxos": [{"id": "coin"}]})
        for i in range(1, 13):
            if i != 9:
                self.store.set_online(f"actor-{i:02}", False)
        config = Config(Path(self.temp.name), (), (), Path(self.temp.name), SIGNET_GENESIS, "test", "test", "test", 100, 1, 1, True, "pilot")
        schedule_pilot(self.store, config)
        self.assertFalse(self.store.online("actor-09"))
        schedule_pilot(self.store, config)
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM action").fetchone()[0], 0)

    def test_lease_rejects_another_supervisor(self):
        with Lease(Path(self.temp.name)):
            with self.assertRaises(RuntimeError):
                with Lease(Path(self.temp.name)):
                    pass

    def test_offline_queue_does_not_block_other_actors_pilot(self):
        self.queue(actor="actor-09")
        self.store.set_online("actor-09", False)
        config = Config(Path(self.temp.name), (), (), Path(self.temp.name), SIGNET_GENESIS, "test", "test", "test", 100, 1, 1, True, "pilot")
        tick=time.time()+2
        with patch("simulator.workload.time.time",return_value=tick):
            schedule_pilot(self.store, config)
            ready = self.store.claim({"create"})
        self.assertIsNotNone(ready)
        self.assertNotEqual(ready["actor_id"], "actor-09")

    def test_fee_exhaustion_does_not_stop_free_observations(self):
        self.queue(fee=100)
        self.store.claim({"create"})
        self.store.finish("action1", "completed", {}, 100)
        record_actor_result(self.store, "actor-01", "create", {"funding_address":"test", "fallback_script":"script", "fallback_seq":1})
        record_actor_result(self.store, "actor-01", "address", {"address":"ark-test"})
        for i in range(2,13):
            self.store.set_online(f"actor-{i:02}", False)
        config = Config(Path(self.temp.name), (), (), Path(self.temp.name), SIGNET_GENESIS, "test", "test", "test", 100, 1, 1, True, "pilot")
        tick=time.time()+2
        with patch("simulator.workload.time.time",return_value=tick):
            schedule_pilot(self.store, config)
            self.assertEqual(self.store.claim({"snapshot"})["operation"], "snapshot")

    def test_wallet_directory_binding_cannot_change_within_epoch(self):
        self.store.bind_wallet_root(Path(self.temp.name)/"one")
        with self.assertRaises(ValueError):
            self.store.bind_wallet_root(Path(self.temp.name)/"two")

    def test_invalid_amounts_or_times_cannot_enter_snapshot(self):
        for value in (True, -1, 1.5):
            with self.assertRaises(ValueError):
                self.store.add_snapshot({"observed_at":1,"rounds_confirmed_sat":value})
        with self.assertRaises(ValueError):
            self.store.add_snapshot({"observed_at":float("nan")})

    def test_recorder_rejects_oversized_or_nonobject_intents(self):
        for args in ([],{"payload":"x"*200_000}):
            with self.assertRaises(ValueError):
                self.store.queue("oversized","actor-01","H01","create",args,0)

    def test_observation_lifecycle_deduplicates_and_does_not_clear_on_missing_evidence(self):
        base={"observed_at":time.time(),"complete":False,"rounds_confirmed_sat":10,
              "capabilities":{"lightning_configured":False},"stable_tip":True,
              "initial_block_download":False,"server_status":{"status":"running"}}
        self.store.add_snapshot(base)
        observe(self.store)
        observe(self.store)
        warnings=[o for o in recorded_observations(self.store) if o["key"]=="lightning_unconfigured"]
        self.assertEqual(warnings[0]["occurrences"],2)
        opened=self.store.db.execute("SELECT COUNT(*) FROM event WHERE kind='observation_opened' AND json_extract(payload,'$.key')='lightning_unconfigured'").fetchone()[0]
        self.assertEqual(opened,1)
        self.store.add_snapshot({"observed_at":time.time(),"error":"TimeoutError"})
        observe(self.store)
        self.assertEqual(self.store.db.execute("SELECT status FROM observation WHERE key='lightning_unconfigured'").fetchone()[0],"active")
        self.store.add_snapshot({**base,"observed_at":time.time(),"capabilities":{"lightning_configured":True}})
        observe(self.store)
        self.assertEqual(self.store.db.execute("SELECT status FROM observation WHERE key='lightning_unconfigured'").fetchone()[0],"cleared")

    def test_small_coin_observation_uses_grouped_amount(self):
        self.store.add_snapshot({"observed_at":time.time(),"timings":{"min_payout_sat":1000}})
        self.store.add_entitlement("a","actor-09","registered",600,"script",{})
        self.store.add_entitlement("b","actor-09","registered",600,"script",{})
        observe(self.store)
        self.assertFalse(any(o["key"].startswith("below_minimum:") for o in recorded_observations(self.store)))
        self.store.add_entitlement("c","actor-10","registered",500,"other",{})
        observe(self.store)
        warning=next(o for o in recorded_observations(self.store) if o["key"]=="below_minimum:other")
        self.assertEqual(warning["evidence"]["gross_sat"],500)

    def test_bounded_reports_keep_epoch_totals_and_full_export_available(self):
        with self.store.transaction():
            self.store.db.executemany("INSERT INTO action VALUES (?, 'actor-01','H01','board','{}','completed',0,1,1,'{}',?,?)",
                [(f"fixture-{i}",i,i) for i in range(2010)])
            self.store.db.executemany("INSERT INTO snapshot(observed_at,payload) VALUES (?,?)",
                [(i,json.dumps({"observed_at":i,"complete":False,"rounds_confirmed_sat":100+i})) for i in range(1501)])
        report=generate(self.store)
        self.assertEqual(len(report["actions"]),2000)
        self.assertEqual(report["known_action_fees_sat"],2010)
        self.assertEqual(next(c for c in report["coverage"] if c["id"]=="H01")["actions"],2010)
        self.assertEqual(report["capital"]["samples"],1501)
        self.assertEqual(report["capital"]["opening_rounds_confirmed_sat"],100)
        self.assertEqual(report["report_scope"]["snapshot_rows"],1440)
        full=generate(self.store,full=True)
        self.assertEqual(len(full["actions"]),2010)
        self.assertTrue((Path(self.temp.name)/"events.jsonl").exists())

    def test_chart_does_not_connect_missing_observations(self):
        for i,value in enumerate((10,None,20)):
            self.store.add_snapshot({"observed_at":i,"rounds_confirmed_sat":value})
        generate(self.store)
        chart=(Path(self.temp.name)/"index.html").read_text()
        self.assertEqual(chart.count("<polyline"),2)
        self.assertIn("UTC",chart)


class AccountingTests(unittest.TestCase):
    def test_drawdown_measures_later_peak_and_missing_capital_is_not_outage(self):
        result = capital_summary([{"observed_at":i,"complete":False,"rounds_confirmed_sat":amount}
                                  for i,amount in enumerate((100,500,200))])
        self.assertEqual(result["peak_observed_rounds_drawdown_sat"], 300)
        self.assertEqual(result["observed_rounds_change_from_opening_sat"], 100)
        self.assertEqual(result["observation_gaps"], 0)
        self.assertEqual(result["incomplete_capital_samples"], 3)

    def test_nonfinite_or_duplicate_json_is_not_evidence(self):
        for response in ('{"fee":NaN}', '{"fee":1,"fee":2}', '{"fee":Infinity}'):
            with self.assertRaises(CommandError):
                decode_object(response)
    def test_exact_sats_and_float_refusal(self):
        self.assertEqual(btc_to_sat(Decimal("0.00000029")), 29)
        self.assertEqual(btc_to_sat("12.12345678"), 1_212_345_678)
        for value in (0.01, "0.000000001", "NaN", "-1"):
            with self.assertRaises(ValueError):
                btc_to_sat(value)

    def test_fee_conservation_over_many_independent_amounts(self):
        rng = random.Random(42)
        for _ in range(1000):
            amounts = {str(i): rng.randrange(1, 100_000) for i in range(rng.randrange(1, 20))}
            fee = rng.randrange(sum(amounts.values()))
            shares = fee_allocation(amounts, fee)
            self.assertEqual(sum(shares.values()), fee)
            total = sum(amounts.values())
            for key, amount in amounts.items():
                self.assertLess(abs(shares[key] * total - amount * fee), total)

    def test_repeated_settlement_fees_are_not_multiplied(self):
        rows = [{"txid": "a", "fee_sat": 200}] * 101 + [{"txid": "b", "fee_sat": 300}]
        self.assertEqual(unique_settlement_fee(rows), 500)
        with self.assertRaises(InvariantError):
            unique_settlement_fee(rows + [{"txid": "a", "fee_sat": 201}])

    def test_unknowns_not_zero_or_measured_minimum(self):
        result = capital_summary([{"observed_at": 1, "complete": False, "rounds_confirmed_sat": 5000},
                                  {"observed_at": 2, "complete": False, "rounds_confirmed_sat": None}])
        self.assertEqual(result["status"], "partial")
        self.assertIsNone(result["peak_observed_tree_locked_sat"])
        self.assertIsNone(result["minimum_required_capital_sat"])

    def test_secrets_rejected_recursively(self):
        with self.assertRaises(ValueError):
            public_payload({"nested": [{"mnemonic": "secret"}]})


class EngineTests(unittest.IsolatedAsyncioTestCase):
    async def test_unstable_or_stale_snapshot_never_authorizes_dispatch(self):
        from dataclasses import replace
        config=replace(self.config,active=True)
        self.store.queue("a","actor-01","H01","create",{},0)
        base={"observed_at":time.time(),"identity":self.identity,"complete":False,
              "stable_tip":True,"initial_block_download":False,"server_status":{"status":"running"}}
        for changes in ({"stable_tip":False},{"observed_at":time.time()-100},{"initial_block_download":True},{"server_status":{"status":"exited"}}):
            with patch("simulator.engine.json_command", AsyncMock(return_value={**base,**changes})) as command:
                await Engine(config,self.store).run(once=True)
            self.assertEqual(command.await_count,1)
        self.assertEqual(self.store.db.execute("SELECT state FROM action WHERE id='a'").fetchone()[0],"queued")

    async def test_incomplete_snapshot_response_is_unknown_not_zero(self):
        from dataclasses import replace
        response={"action_id":"a","status":"ok","actual_fee_sat":0,"data":{"balance":{}}}
        config=replace(self.config,active=True)
        self.store.queue("a","actor-01","H01","snapshot",{},10)
        with patch("simulator.engine.json_command",AsyncMock(return_value=response)):
            await Engine(config,self.store).dispatch_one()
        self.assertEqual(self.store.db.execute("SELECT state FROM action").fetchone()[0],"outcome_unknown")
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM event WHERE kind='driver_response'").fetchone()[0],1)
        self.assertNotIn("registered_spendable_sat",json.loads(self.store.db.execute("SELECT details FROM actor WHERE id='actor-01'").fetchone()[0]))

    async def test_protocol_evidence_survives_driver_timeout(self):
        from dataclasses import replace
        event={"kind":"driver_event","action_id":"a","event":"board_proposal","data":{"planned_mining_fee_sat":50}}
        code=f"import time; print({json.dumps(event)!r},flush=True); time.sleep(60)"
        config=replace(self.config,active=True,driver_command=(sys.executable,"-c",code))
        self.store.queue("a","actor-01","H01","board",{},10)
        await Engine(config,self.store).dispatch_one()
        evidence=json.loads(self.store.db.execute("SELECT payload FROM event WHERE kind='driver_evidence'").fetchone()[0])
        self.assertEqual(evidence["data"]["planned_mining_fee_sat"],50)
        self.assertEqual(self.store.db.execute("SELECT state FROM action").fetchone()[0],"outcome_unknown")

    async def test_duplicate_final_driver_results_are_rejected(self):
        code='print(\'{"action_id":"a","status":"ok"}\'); print(\'{"action_id":"a","status":"ok"}\')'
        with self.assertRaises(CommandError):
            await json_command([sys.executable,"-c",code],on_event=lambda _:None)
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.store = Store(root, "live", 100)
        initialize(self.store)
        self.identity = {"network": "signet", "genesis": SIGNET_GENESIS,
                         "container": "abandon-signet-fallback-fb-captaind-1", "image_digest": "sha256:" + "a" * 64,
                         "server_pubkey": "02" + "b" * 64}
        snapshot = {"observed_at": time.time(), "identity": self.identity, "complete": False, "rounds_confirmed_sat": 1000,
                    "stable_tip":True, "initial_block_download":False, "server_status":{"status":"running"}}
        self.config = Config(root, (sys.executable, "-c", f"print({json.dumps(snapshot)!r})"),
                             (sys.executable, "-c", "raise SystemExit('driver must not be called')"), root / "wallets",
                             SIGNET_GENESIS, self.identity["container"], self.identity["image_digest"],
                             self.identity["server_pubkey"], 100, 1, 1, False)

    async def asyncTearDown(self):
        self.store.close()
        self.temp.cleanup()

    async def test_observe_never_dispatches(self):
        self.store.queue("a", "actor-01", "H01", "create", {}, 10)
        await Engine(self.config, self.store).run(once=True)
        self.assertEqual(self.store.db.execute("SELECT state FROM action").fetchone()[0], "queued")

    async def test_wrong_network_never_dispatches_and_gap_is_visible(self):
        from dataclasses import replace
        bad = {"observed_at": time.time(), "identity": {**self.identity, "network": "mainnet"}}
        config = replace(self.config, active=True, observer_command=(sys.executable, "-c", f"print({json.dumps(bad)!r})"))
        self.store.queue("a", "actor-01", "H01", "create", {}, 10)
        await Engine(config, self.store).run(once=True)
        self.assertEqual(self.store.db.execute("SELECT state FROM action").fetchone()[0], "queued")
        self.assertEqual(generate(self.store)["capital"]["status"], "unknown")

    async def test_timeout_is_unknown_and_not_retried(self):
        from dataclasses import replace
        config = replace(self.config, active=True, driver_command=(sys.executable, "-c", "import time; time.sleep(60)"))
        self.store.queue("a", "actor-01", "H01", "create", {}, 10)
        await Engine(config, self.store).run(once=True)
        self.assertEqual(self.store.db.execute("SELECT state FROM action").fetchone()[0], "outcome_unknown")
        self.assertIsNone(self.store.claim({"create"}))

    async def test_output_cap(self):
        with self.assertRaises(CommandError):
            await json_command([sys.executable, "-c", "print('a' * 3000000)"], timeout=3)

    async def test_cleanup_does_not_kill_unrelated_process(self):
        neighbour = await asyncio.create_subprocess_exec(sys.executable, "-c", "import time; time.sleep(60)")
        try:
            with self.assertRaises(TimeoutError):
                await json_command([sys.executable, "-c", "import time; time.sleep(60)"], timeout=1)
            self.assertIsNone(neighbour.returncode)
        finally:
            neighbour.kill()
            await neighbour.wait()

    async def test_pilot_refuses_to_board_on_a_stack_without_payouts(self):
        from dataclasses import replace
        config = replace(self.config, active=True, workload="pilot")
        await Engine(config, self.store).run(once=True)
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM action").fetchone()[0], 0)

    async def test_driver_invariant_incident_stops_other_clients(self):
        from dataclasses import replace
        config = replace(self.config, active=True)
        self.store.queue("raw", "actor-11", "D02", "raw_record_tamper", {}, 0)
        self.store.queue("ordinary", "actor-01", "H01", "board", {}, 10)
        with patch("simulator.engine.json_command", AsyncMock(return_value={"action_id": "raw", "status": "incident"})):
            await Engine(config, self.store).dispatch_one()
        self.assertEqual(self.store.get_meta("paused"), "incident")
        self.assertIsNone(self.store.claim({"board"}))


class ObserverTests(unittest.IsolatedAsyncioTestCase):
    async def test_unconfirmed_utxo_is_not_confirmed_liquidity(self):
        with patch("simulator.vm_observer.text_command",AsyncMock(return_value='{"value":0.01,"confirmations":0}')):
            with self.assertRaises(ValueError):
                await confirmed_value("ops",["a"*64+":0"])
    async def test_core_decimals_and_bounded_parallel_inventory(self):
        outpoints = [f"{i:064x}:0" for i in range(12)]
        reader = AsyncMock(return_value='{"value":0.00000029,"confirmations":1}')
        with patch("simulator.vm_observer.text_command", reader):
            value, gap = await confirmed_value("ops", outpoints)
        self.assertEqual(value, 348)
        self.assertIsNone(gap)
        self.assertEqual(reader.await_count, 12)

    async def test_oversized_inventory_is_unknown_without_partial_total(self):
        with patch("simulator.vm_observer.text_command", AsyncMock()) as reader:
            value, gap = await confirmed_value("ops", [f"{i:064x}:0" for i in range(65)])
        self.assertIsNone(value)
        self.assertIn("limit", gap)
        reader.assert_not_called()

    async def test_duplicate_or_spent_outpoints_cannot_be_counted(self):
        outpoint = "a" * 64 + ":0"
        with self.assertRaises(ValueError):
            await confirmed_value("ops", [outpoint, outpoint])
        with patch("simulator.vm_observer.text_command", AsyncMock(return_value="null")):
            with self.assertRaises(ValueError):
                await confirmed_value("ops", [outpoint])


class PilotIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_twelve_mock_clients_board_then_absent_clients_stay_silent(self):
        """Supervisor integration with a fixture driver, not Bark/network evidence."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store = Store(root, "synthetic", 100_000)
            try:
                initialize(store)
                identity = {"network": "signet", "genesis": SIGNET_GENESIS,
                            "container": "abandon-signet-fallback-fixture", "image_digest": "sha256:" + "a" * 64,
                            "server_pubkey": "02" + "b" * 64}
                config = Config(root, ("fixture-observer",), ("fixture-driver",), root / "wallets",
                                SIGNET_GENESIS, identity["container"], identity["image_digest"],
                                identity["server_pubkey"], 100_000, 1, 1, True, "pilot")
                tick = [time.time()]
                calls = []

                async def command(argv, request=None, timeout=30, on_event=None):
                    if request is None:
                        return {"observed_at": tick[0], "identity": identity, "complete": False,
                                "rounds_confirmed_sat": 1000, "timings": {"payout_enabled": True},
                                "stable_tip":True, "initial_block_download":False, "server_status":{"status":"running"}}
                    actor = Path(request["actor_dir"]).name
                    self.assertTrue(store.online(actor))
                    operation = request["operation"]
                    calls.append((actor, operation))
                    data = {}
                    if operation == "create":
                        data = {"funding_address": actor + "-funding", "fallback_script": actor + "-script", "fallback_seq": 1}
                    elif operation == "address":
                        data = {"address": actor + "-ark"}
                    elif operation == "snapshot":
                        boarded = store.db.execute("SELECT 1 FROM action WHERE actor_id=? AND operation='board' AND state='completed'", (actor,)).fetchone()
                        data = {"balance": {"spendable_sat": 12_000 if boarded else 0},
                                "onchain": {"confirmed_sat": 14_000}, "vtxos": [{"id": actor + "-coin"}] if boarded else []}
                    status = "expected_refusal" if operation.startswith("raw_") else "ok"
                    return {"action_id": request["action_id"], "status": status, "data": data,
                            "actual_fee_sat": 1000 if operation == "board" else 0}

                with patch("simulator.engine.json_command", command), patch("simulator.workload.time.time", lambda: tick[0]):
                    for _ in range(170):
                        tick[0] += 31
                        await Engine(config, store).run(once=True)
                self.assertEqual(sum(op == "create" for _, op in calls), 12)
                self.assertEqual(sum(op == "board" for _, op in calls), 12)
                self.assertFalse(store.online("actor-09"))
                self.assertFalse(store.online("actor-10"))
                self.assertTrue(any(op == "send_arkoor" for _, op in calls))
                self.assertTrue(any(op.startswith("raw_") for _, op in calls))
                self.assertIsNone(store.get_meta("paused"))
                self.assertTrue(store.verify_event_chain())
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()

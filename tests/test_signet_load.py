"""Load preparation scheduling tests; native outputs are explicitly stubbed."""
import hashlib
from decimal import Decimal
import json
import subprocess
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from simulator.signet_load import Load, _transfer
from simulator.signet import Campaign
from simulator.signet_checks import ChainObservationChanged, confirmed_backing
from tests import test_signet


class LoadCore(test_signet.Core):
    def __init__(self):
        super().__init__()
        self.transactions = {}
        self.funding = {}

    def call(self, method, *args):
        if method == "validateaddress":
            return {"isvalid": True, "scriptPubKey": "0014" + args[0][-40:]}
        if method == "gettxout":
            if args[0] in self.funding:
                return self.funding[args[0]]
            return {"value": Decimal("0.00100000"), "confirmations": 3,
                    "bestblock": self.info["bestblockhash"]}
        if method == "getrawtransaction":
            return self.transactions[args[0]]
        return super().call(method, *args)


class LoadTests(unittest.TestCase):
    setUp = test_signet.SignetTests.setUp
    tearDown = test_signet.SignetTests.tearDown

    def native(self, argv, **kwargs):
        actor = Path(argv[argv.index("--datadir") + 1]).name
        key = hashlib.sha256(actor.encode()).hexdigest()
        operation = argv[5]
        if operation == "create":
            values = tomllib.loads((self.campaign.actor_path(actor) / "config.toml").read_text())
            self.assertEqual(values["fallback_fee_rate"], 750)
            self.assertEqual(values["vtxo_refresh_expiry_threshold"], 144)
            value = b""
        elif operation == "onchain":
            if argv[6] == "utxos":
                value = json.dumps(self.onchain[actor]).encode()
            else:
                value = json.dumps({"address": "tb1q" + key[:40]}).encode()
        elif operation == "dev":
            payout = hashlib.sha256((actor + "-payout").encode()).hexdigest()[:40]
            value = json.dumps({"network": "signet", "mailbox_pk": "02" + key,
                "payout_address": "tb1q" + payout, "record_hex": key,
                "record": {"spk": "0014" + payout, "account_xpub": "tpubfixture" + key,
                           "mailbox_signature": key * 2, "account_signature": key * 2}}).encode()
        elif operation == "address":
            value = ("tark1" + key).encode()
        elif operation == "ark-info":
            value = json.dumps({"network": "signet", "server_pubkey": "02" + key,
                "required_board_confirmations": 3, "vtxo_lifetime": 4320,
                "vtxo_exit_delta": 144, "htlc_send_expiry_delta": 258,
                "htlc_expiry_delta": 40, "min_board_amount_sat": 20000}).encode()
        elif operation == "board":
            self.ledger[actor][0]["amount_sat"] = 29670
            value = json.dumps({"funding_tx": {"txid": key}, "vtxos": [],
                                "amount_sat": 29670, "movement_id": 1}).encode()
        elif operation == "vtxos":
            value = json.dumps(self.ledger[actor]).encode()
        elif operation == "send":
            if getattr(self, "unknown_send", False):
                raise subprocess.TimeoutExpired("bark", 1)
            receiver = next(a for a in self.ledger if argv[6] == "tark1" + hashlib.sha256(a.encode()).hexdigest())
            old = next(coin for coin in self.ledger[actor] if coin["state"]["type"] == "spendable")
            old["state"] = {"type": "spent"}
            change, received = dict(old), dict(old)
            change.update(id=hashlib.sha256((actor + "change").encode()).hexdigest() + ":0", amount_sat=old["amount_sat"] - 1000, state={"type": "spendable"})
            received.update(id=hashlib.sha256((receiver + "received").encode()).hexdigest() + ":0", amount_sat=1000, state={"type": "spendable"})
            self.ledger[actor].append(change); self.ledger[receiver].append(received)
            value = b""
        else:
            raise AssertionError("no monetary action authorized during preparation")
        kwargs["stdout"].write(value)
        return subprocess.CompletedProcess(argv, 0)

    def test_twelve_genuine_wallet_actions_before_any_funding_board_or_transfer(self):
        self.campaign.core = LoadCore()
        with patch("simulator.signet.subprocess.run", side_effect=self.native) as native:
            request = Load(self.campaign).prepare()
            self.assertEqual(native.call_count, 49)
            self.assertEqual(Load(self.campaign).prepare(), request)
            self.assertEqual(native.call_count, 49)
        self.assertEqual(request["stage"], "PREPARED_UNFUNDED")
        self.assertEqual(request["total_actor_principal_sat"], 1200000)
        self.assertEqual(len({actor["address"] for actor in request["actors"]}), 12)
        self.assertFalse(request["money_dispatched"])

    def test_unknown_native_creation_holds_instead_of_repeating_it(self):
        self.campaign.core = LoadCore()
        with patch("simulator.signet.subprocess.run", side_effect=subprocess.TimeoutExpired("bark", 1)) as native:
            with self.assertRaisesRegex(ValueError, "requires reconciliation"):
                Load(self.campaign).prepare()
            with self.assertRaisesRegex(ValueError, "unresolved"):
                Load(self.campaign).prepare()
        self.assertEqual(native.call_count, 1)

    def test_workload_bounds_and_parameters_are_immutable(self):
        Load(self.campaign)
        for changes in [{"wallets": 50}, {"concurrency": 6}, {"transfers": 1001},
                        {"transfer_sat": 6000}, {"batch_interval_seconds": 1}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                Load(self.campaign, **changes)

    def worker_fixture(self, transfers=60):
        self.campaign.core = LoadCore()
        with patch("simulator.signet.subprocess.run", side_effect=self.native):
            phase = Load(self.campaign, transfers=transfers); phase.prepare()
        self.ledger = {}
        for actor in phase.actors:
            key = hashlib.sha256(actor.encode()).hexdigest()
            self.ledger[actor] = [{"id": key + ":0", "amount_sat": 10000,
                "chain_anchor": key + ":0", "user_pubkey": "02" + key,
                "expiry_height": 500, "state": {"type": "spendable"}}]
        return phase

    def child_campaign(self, directory, config):
        child = Campaign(directory, config); child.core = self.campaign.core
        return child

    def test_real_controller_pair_accounting_and_duplicate_call_never_repeat_send(self):
        phase = self.worker_fixture(transfers=1)
        self.campaign.db.execute("INSERT INTO meta VALUES ('load_admitted',?)", (json.dumps({"opening_coin_sat": 120000}),))
        with patch("simulator.signet.Campaign", side_effect=self.child_campaign), \
             patch("simulator.signet_phase._verify_runtime"), \
             patch("simulator.signet_load.verify_coin", return_value={"status": "PASS"}), \
             patch("simulator.signet.subprocess.run", side_effect=self.native) as native:
            result = _transfer(self.campaign.root, self.config, phase.parameters, 0)
            self.assertEqual(result["status"], "RECONCILED")
            self.assertEqual(result["check"]["received_sat"], 1000)
            self.assertEqual(result["check"]["observed_offchain_fee_sat"], 0)
            self.assertEqual(_transfer(self.campaign.root, self.config, phase.parameters, 0), result)
            self.assertEqual(native.call_count, 5)
            final = phase.finish()
            self.assertEqual(final["closing_coin_sat"], 120000)
            self.assertEqual(final["successful_reconciled_transfers"], 1)
        self.assertEqual(native.call_count, 17)

    def test_unknown_load_payment_is_durable_and_cannot_replay(self):
        phase = self.worker_fixture(); self.unknown_send = True
        self.campaign.db.execute("INSERT INTO meta VALUES ('load_admitted','{}')")
        with patch("simulator.signet.Campaign", side_effect=self.child_campaign), \
             patch("simulator.signet_phase._verify_runtime"), \
             patch("simulator.signet.subprocess.run", side_effect=self.native) as native:
            for attempt in range(2):
                with self.assertRaises(ValueError):
                    _transfer(self.campaign.root, self.config, phase.parameters, 0)
        self.assertEqual(native.call_count, 3)
        self.assertEqual(self.campaign.db.execute("SELECT state FROM action WHERE operation='send'").fetchone()[0], "unknown")

    def test_block_during_post_ack_proofs_reobserves_without_another_send(self):
        phase = self.worker_fixture(transfers=1)
        self.campaign.db.execute("INSERT INTO meta VALUES ('load_admitted','{}')")
        calls = 0
        def backing(core, snapshots):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ChainObservationChanged("forward block during final read")
            return confirmed_backing(core, snapshots)
        proofs = 0
        def proof(*args, **kwargs):
            nonlocal proofs
            proofs += 1
            return ({"status": "UNAVAILABLE", "diagnostic": "ChainObservationChanged", "retryable_chain_observation": True}
                    if proofs == 1 else {"status": "PASS"})
        with patch("simulator.signet.Campaign", side_effect=self.child_campaign), \
             patch("simulator.signet_phase._verify_runtime"), \
             patch("simulator.signet_load.verify_coin", side_effect=proof), \
             patch("simulator.signet_load.confirmed_backing", side_effect=backing), \
             patch("simulator.signet_load.time.sleep"), \
             patch("simulator.signet.subprocess.run", side_effect=self.native) as native:
            result = _transfer(self.campaign.root, self.config, phase.parameters, 0)
        self.assertEqual(result["status"], "RECONCILED")
        self.assertEqual(sum(c.args[0][5] == "send" for c in native.call_args_list), 1)
        self.assertEqual(self.campaign.db.execute("SELECT count(*) FROM result WHERE json_extract(payload,'$.kind')='load_observation_retry'").fetchone()[0], 2)

    def test_failure_finishes_original_disjoint_batch_then_holds_future_dispatch(self):
        phase = self.worker_fixture()
        self.campaign.db.execute("INSERT INTO meta VALUES ('load_admitted','{}')")
        def worker(directory, config, parameters, index):
            if index == 1:
                raise ValueError("original payment incomplete")
            return {"index": index, "status": "RECONCILED"}
        with patch("simulator.signet_load._transfer", side_effect=worker) as native:
            result = phase.advance_batch()
            self.assertEqual(result["indices"], [0, 1, 2])
            self.assertEqual(result["stage"], "LOAD_BATCH_HOLD")
            self.assertEqual(len(result["results"]), 2)
            with self.assertRaisesRegex(ValueError, "held"):
                phase.advance_batch()
        self.assertEqual(native.call_count, 3)

    def test_each_funded_actor_boards_once_before_native_cohort_admission(self):
        phase = self.worker_fixture()
        self.onchain = {}
        for actor in phase.actors:
            key = hashlib.sha256(actor.encode()).hexdigest()
            funding = hashlib.sha256((actor + "-fund").encode()).hexdigest()
            self.onchain[actor] = [{"outpoint": funding + ":0", "amount_sat": 100000, "confirmation_height": 120}]
            self.campaign.core.funding[funding] = {"value": Decimal("0.001"), "confirmations": 3,
                "bestblock": self.campaign.core.info["bestblockhash"], "scriptPubKey": {"hex": "0014" + key[:40]}}
            self.campaign.core.transactions[funding] = {"txid": funding,"vout": [{"n": 0, "value": Decimal("0.001")} ]}
            self.campaign.core.transactions[key] = {"txid": key,"vin": [{"txid": funding,"vout": 0}],
                "vout": [{"n": 0,"value": Decimal("0.0003")}, {"n": 1,"value": Decimal("0.00069542")}]}
            self.campaign.db.execute("INSERT INTO result VALUES (?,0,?)", (actor + "-fund", json.dumps(
                {"kind": "external_funding", "actor": actor, "outpoint": funding + ":0", "amount_sat": 100000})))
        with patch("simulator.signet.subprocess.run", side_effect=self.native) as native, \
             patch("simulator.signet_load.verify_coin", return_value={"status": "PASS"}):
            admitted = phase.admit()
            self.assertEqual(admitted["opening_coin_sat"], 12 * 29670)
            self.assertEqual(sum(row["miner_fee_sat"] for row in admitted["board_costs"].values()), 12 * 458)
            self.assertEqual(phase.admit(), admitted)
        self.assertEqual(sum(call.args[0][5] == "board" for call in native.call_args_list), 12)

    def test_unadmitted_work_is_blocked_and_durable_pacing_prevents_another_batch(self):
        phase = self.worker_fixture()
        with self.assertRaisesRegex(ValueError, "admission"):
            phase.advance_batch()
        self.campaign.db.execute("INSERT INTO meta VALUES ('load_admitted','{}')")
        with patch("simulator.signet_load._transfer", side_effect=lambda d, c, p, i: {"index": i}) as worker:
            result = phase.advance_batch()
            self.assertEqual(result["stage"], "LOAD_BATCH_RECONCILED")
            self.assertGreaterEqual(result["resource_observation"]["samples"], 2)
            self.assertEqual(phase.advance_batch()["stage"], "WAITING_FOR_LOAD_BATCH_INTERVAL")
        self.assertEqual(worker.call_count, 3)

    def test_whole_cohort_rejects_duplicate_coins_even_if_aggregate_value_matches(self):
        phase = self.worker_fixture(transfers=1)
        self.campaign.db.execute("INSERT INTO meta VALUES ('load_admitted',?)", (json.dumps({"opening_coin_sat": 120000}),))
        with patch("simulator.signet.Campaign", side_effect=self.child_campaign), \
             patch("simulator.signet_phase._verify_runtime"), \
             patch("simulator.signet_load.verify_coin", return_value={"status": "PASS"}), \
             patch("simulator.signet.subprocess.run", side_effect=self.native):
            _transfer(self.campaign.root, self.config, phase.parameters, 0)
            self.ledger["load-001"][0]["id"] = self.ledger["load-002"][0]["id"]
            with self.assertRaisesRegex(ValueError, "multiple load actors"):
                phase.finish()


if __name__ == "__main__":
    unittest.main()

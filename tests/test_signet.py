"""Fault tests for the public-Signet supervisor; no network simulation claim."""
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from simulator.model import SIGNET_GENESIS
from simulator.signet import Campaign, PUBLIC_SIGNET_CHALLENGE, command, network_identity, project_reply


class Core:
    def __init__(self, **changes):
        self.info = {"chain": "signet", "initialblockdownload": False,
                     "signet_challenge": PUBLIC_SIGNET_CHALLENGE,
                     "blocks": 123, "bestblockhash": "ab" * 32, **changes}

    def call(self, method, *args):
        return self.info if method == "getblockchaininfo" else SIGNET_GENESIS


class SignetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.binary = self.root / "native-bark"
        self.binary.write_bytes(b"pinned test executable, not a native proof")
        self.config = {"binary": str(self.binary), "source_commit": "a" * 40,
                       "binary_sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest(),
                       "product_config_sha256": "b" * 64, "ark_url": "http://127.0.0.1:3535",
                       "core_url": "http://127.0.0.1:38332", "core_credential": "/private/core.auth"}
        self.campaign = Campaign(self.root / "campaign", self.config)
        self.campaign.core = Core()

    def tearDown(self):
        self.campaign.close()
        self.tmp.cleanup()

    def test_custom_signet_with_same_genesis_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "default public Signet"):
            network_identity(Core(signet_challenge="51"))
        with self.assertRaises(ValueError):
            network_identity(Core(initialblockdownload=True))

    def test_unknown_payment_is_not_replayed_after_restart(self):
        with patch("simulator.signet.subprocess.run", side_effect=subprocess.TimeoutExpired("bark", 5)) as run:
            action = self.campaign.execute("transfer-1", "alice", "send", {
                "destination": "tark1abcdef", "amount_sat": 5000})
        self.assertEqual(action["state"], "unknown")
        self.campaign.close()
        self.campaign = Campaign(self.root / "campaign", self.config)
        self.campaign.core = Core()
        with patch("simulator.signet.subprocess.run") as replay:
            action = self.campaign.execute("transfer-1", "alice", "send", {
                "destination": "tark1abcdef", "amount_sat": 5000})
            self.assertEqual(action["state"], "unknown")
            with self.assertRaisesRegex(ValueError, "reconcile first"):
                self.campaign.execute("transfer-2", "alice", "send", {
                    "destination": "tark1abcdef", "amount_sat": 5000})
        replay.assert_not_called()
        run.assert_called_once()

    def test_intent_committed_before_native_process_and_nonzero_is_unknown(self):
        def native(*args, **kwargs):
            observer = sqlite3.connect(self.root / "campaign" / "signet.sqlite")
            try:
                self.assertEqual(observer.execute("SELECT state FROM action").fetchone()[0], "dispatched")
            finally:
                observer.close()
            return subprocess.CompletedProcess(args[0], 1, b"potentially sensitive error")
        with patch("simulator.signet.subprocess.run", side_effect=native):
            row = self.campaign.execute("create-1", "alice", "create", {})
        self.assertEqual(row["state"], "unknown")
        self.assertNotIn("sensitive", json.dumps(self.campaign.report()))

    def test_reused_intent_cannot_change_amount(self):
        with patch("simulator.signet.subprocess.run", return_value=subprocess.CompletedProcess([], 0, b"")):
            self.campaign.execute("transfer-1", "alice", "send", {
                "destination": "tark1abcdef", "amount_sat": 5000})
        with self.assertRaisesRegex(ValueError, "reused"):
            self.campaign.execute("transfer-1", "alice", "send", {
                "destination": "tark1abcdef", "amount_sat": 6000})

    def test_absent_wallet_cannot_be_opened_for_observation(self):
        self.campaign.abandon("alice")
        with patch("simulator.signet.subprocess.run") as run:
            with self.assertRaisesRegex(ValueError, "absent"):
                self.campaign.execute("observe", "alice", "vtxos", {})
        run.assert_not_called()

    def test_zero_exit_does_not_pass_a_scenario(self):
        with patch("simulator.signet.subprocess.run", return_value=subprocess.CompletedProcess([], 0, b"")):
            row = self.campaign.execute("transfer-1", "alice", "send", {
                "destination": "tark1abcdef", "amount_sat": 5000})
        self.assertEqual(row["state"], "acknowledged")
        self.assertEqual(self.campaign.report()["case_verdict"], "NOT_EVALUATED")
        self.assertEqual(json.loads(row["reply"])["completion"], "requires_reconciliation")

    def test_wallet_coin_projection_discards_unknown_fields(self):
        coin = {"id": "a" * 64 + ":0", "amount_sat": 5000, "user_pubkey": "02" + "b" * 64,
                "chain_anchor": "c" * 64 + ":1", "expiry_height": 150,
                "state": {"type": "spendable", "secret_key": "private"},
                "payment_preimage": "secret"}
        result = project_reply("vtxos", json.dumps([coin]).encode())
        self.assertNotIn("secret", json.dumps(result))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            project_reply("vtxos", json.dumps([coin, coin]).encode())
        coin["amount_sat"] = 5000.0
        with self.assertRaises(ValueError):
            project_reply("vtxos", json.dumps([coin]).encode())

    def test_pin_changes_require_new_campaign(self):
        self.binary.write_bytes(b"different binary")
        with self.assertRaisesRegex(ValueError, "hash changed"):
            self.campaign.execute("create", "alice", "create", {})
        with self.assertRaisesRegex(ValueError, "pins changed"):
            Campaign(self.root / "campaign", {**self.config, "source_commit": "c" * 40})

    def test_create_never_falls_back_to_upstream_public_server(self):
        args = command("create", {}, self.config)
        self.assertEqual(args[:4], ["create", "--signet", "--ark", self.config["ark_url"]])
        self.assertIn("--bitcoind-cookie", args)
        with self.assertRaises(ValueError):
            command("send", {"destination": "bitcoin:tb1qqqq", "amount_sat": 1}, self.config)
        with self.assertRaises(ValueError):
            command("create", {"force": True}, self.config)


if __name__ == "__main__":
    unittest.main()

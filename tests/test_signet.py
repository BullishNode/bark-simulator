"""Fault tests for the public-Signet supervisor; no network simulation claim."""
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import tomllib
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

    def test_acknowledged_address_survives_restart_without_reissuing_it(self):
        def native(argv, **kwargs):
            kwargs["stdout"].write(b"tark1abcdef\n")
            return subprocess.CompletedProcess(argv, 0)
        with patch("simulator.signet.subprocess.run", side_effect=native):
            self.campaign.execute("address-1", "alice", "address", {})
        self.campaign.close()
        self.campaign = Campaign(self.root / "campaign", self.config)
        with patch("simulator.signet.subprocess.run") as replay:
            row = self.campaign.execute("address-1", "alice", "address", {})
        replay.assert_not_called()
        self.assertEqual(json.loads(row["reply"]), {"address": "tark1abcdef"})

    def test_actor_cannot_be_abandoned_while_native_process_is_dispatched(self):
        def native(argv, **kwargs):
            with self.assertRaisesRegex(ValueError, "cannot declare absent"):
                self.campaign.abandon("alice")
            return subprocess.CompletedProcess(argv, 0)
        with patch("simulator.signet.subprocess.run", side_effect=native):
            row = self.campaign.execute("create-1", "alice", "create", {})
        self.assertEqual(row["state"], "acknowledged")

    def test_controller_death_after_dispatch_does_not_replay(self):
        with patch("simulator.signet.subprocess.run", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.campaign.execute("create-1", "alice", "create", {})
        self.campaign.close()
        self.campaign = Campaign(self.root / "campaign", self.config)
        with patch("simulator.signet.subprocess.run") as replay:
            row = self.campaign.execute("create-1", "alice", "create", {})
        replay.assert_not_called()
        self.assertEqual(row["state"], "dispatched")

    def test_failure_diagnostics_are_private_and_public_receipts_are_hashes(self):
        sensitive = b"payment_preimage=" + b"ab" * 32
        def native(argv, **kwargs):
            kwargs["stderr"].write(sensitive)
            return subprocess.CompletedProcess(argv, 7)
        with patch("simulator.signet.subprocess.run", side_effect=native):
            row = self.campaign.execute("send-failed", "alice", "send", {
                "destination": "tark1abcdef", "amount_sat": 5000})
        report = self.campaign.report()
        self.assertEqual(row["diagnostic"], "NativeExit:7")
        self.assertNotIn(sensitive.decode(), json.dumps(report))
        reference = next(a for a in report["protected_artifacts"] if a["kind"] == "stderr")
        path = self.campaign.root / reference["relative_path"]
        self.assertEqual(path.read_bytes(), sensitive)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(reference["sha256"], hashlib.sha256(sensitive).hexdigest())

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

    def test_short_profile_is_durable_and_explicit_before_native_create(self):
        profile = {"vtxo_refresh_expiry_threshold": 4, "vtxo_exit_margin": 2}
        def native(argv, **kwargs):
            path = self.campaign.actor_path("short-control") / "config.toml"
            values = tomllib.loads(path.read_text())
            self.assertEqual(values, {"server_address": self.config["ark_url"],
                                     "bitcoind_address": self.config["core_url"],
                                     "bitcoind_cookiefile": self.config["core_credential"], **profile})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(argv[-2:], ["create", "--signet"])
            self.assertNotIn("--ark", argv)
            observer = sqlite3.connect(self.root / "campaign" / "signet.sqlite")
            self.assertEqual(observer.execute("SELECT state FROM action").fetchone()[0], "dispatched")
            observer.close()
            return subprocess.CompletedProcess(argv, 0)
        with patch("simulator.signet.subprocess.run", side_effect=native):
            row = self.campaign.execute("short-create", "short-control", "create", {"wallet_profile": profile})
        self.assertEqual(row["state"], "acknowledged")
        self.assertEqual(json.loads(row["reply"])["wallet_profile"], profile)
        with patch("simulator.signet.subprocess.run") as run:
            self.campaign.execute("short-create", "short-control", "create", {"wallet_profile": profile})
        run.assert_not_called()

    def test_short_profile_never_overwrites_an_existing_wallet(self):
        path = self.campaign.actor_path("alice")
        path.mkdir(parents=True)
        (path / "config.toml").write_text("existing protected wallet")
        with patch("simulator.signet.subprocess.run") as run:
            row = self.campaign.execute("short-create", "alice", "create", {"wallet_profile": {
                "vtxo_refresh_expiry_threshold": 4, "vtxo_exit_margin": 2}})
        self.assertEqual(row["state"], "unknown")
        self.assertEqual((path / "config.toml").read_text(), "existing protected wallet")
        run.assert_not_called()

    def test_short_profile_change_blocks_a_new_native_wallet_open(self):
        profile = {"vtxo_refresh_expiry_threshold": 4, "vtxo_exit_margin": 2}
        with patch("simulator.signet.subprocess.run", return_value=subprocess.CompletedProcess([], 0)):
            row = self.campaign.execute("short-create", "alice", "create", {"wallet_profile": profile})
        self.assertEqual(row["state"], "acknowledged")
        path = self.campaign.actor_path("alice") / "config.toml"
        path.write_text(path.read_text().replace("vtxo_exit_margin = 2", "vtxo_exit_margin = 12"))
        with patch("simulator.signet.subprocess.run") as run:
            with self.assertRaisesRegex(ValueError, "profile configuration changed"):
                self.campaign.execute("new-observation", "alice", "sync_vtxos", {})
        run.assert_not_called()

    def test_short_profile_rejects_missing_unsafe_and_unbounded_parameters(self):
        for profile in [{"vtxo_exit_margin": 2},
                        {"vtxo_refresh_expiry_threshold": 2, "vtxo_exit_margin": 4},
                        {"vtxo_refresh_expiry_threshold": 4, "vtxo_exit_margin": True},
                        {"vtxo_refresh_expiry_threshold": 65536, "vtxo_exit_margin": 2}]:
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                command("create", {"wallet_profile": profile}, self.config)

    def test_process_identity_does_not_mistake_reopening_an_object_for_restart(self):
        first = self.campaign.controller_id
        config_path = self.root / "config.json"
        config_path.write_text(json.dumps(self.config))
        config_path.chmod(0o600)
        self.campaign.close()
        self.campaign = Campaign(self.root / "campaign", self.config)
        self.assertEqual(self.campaign.controller_id, first)
        child = subprocess.check_output([
            sys.executable, "-c",
            "import json,sys; from pathlib import Path; from simulator.signet import Campaign; "
            "c=Campaign(Path(sys.argv[1]),json.loads(Path(sys.argv[2]).read_text())); "
            "print(c.controller_id); c.close()",
            str(self.root / "campaign"), str(config_path),
        ], text=True).strip()
        self.assertNotEqual(child, first)


if __name__ == "__main__":
    unittest.main()

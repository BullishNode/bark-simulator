"""Load preparation scheduling tests; native outputs are explicitly stubbed."""
import hashlib
import json
import subprocess
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from simulator.signet_load import Load
from tests import test_signet


class LoadCore(test_signet.Core):
    def call(self, method, *args):
        if method == "validateaddress":
            return {"isvalid": True, "scriptPubKey": "0014" + args[0][-40:]}
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


if __name__ == "__main__":
    unittest.main()

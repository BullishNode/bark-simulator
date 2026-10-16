"""Native verifier transport binding tests; cryptography belongs to product tests."""
from decimal import Decimal
import json
import subprocess
import unittest
from unittest.mock import patch

from simulator.signet_proof import verify_coin
from tests import test_signet


class ProofCore(test_signet.Core):
    def call(self, method, *args):
        if method == "getrawtransaction":
            return "00"
        if method == "gettxout":
            return {"value": Decimal("0.00010000"), "confirmations": 3,
                    "bestblock": self.info["bestblockhash"]}
        return super().call(method, *args)


class ProofTests(unittest.TestCase):
    setUp = test_signet.SignetTests.setUp
    tearDown = test_signet.SignetTests.tearDown

    def coin(self):
        return {"id": "a" * 64 + ":0", "amount_sat": 5000,
                "user_pubkey": "02" + "b" * 64, "chain_anchor": "c" * 64 + ":1",
                "expiry_height": 200, "state": "spendable"}

    def native(self, argv, **kwargs):
        if argv[3] == "dev":
            self.assertEqual(argv[3:6], ["dev", "vtxo", "verify"])
            self.assertNotIn("--datadir", argv)
            result = {"verified": True, "anchor_txid": "c" * 64,
                      "vtxo": {k: v for k, v in self.coin().items() if k != "state"}}
            result.update(self.override)
            kwargs["stdout"].write(json.dumps(result).encode())
        else:
            self.assertEqual(argv[5:7], ["raw-vtxo", self.coin()["id"]])
            kwargs["stdout"].write(b"010203\n")
        return subprocess.CompletedProcess(argv, self.exit_code if argv[3] == "dev" else 0)

    def test_verifier_binds_snapshot_and_survives_absence_without_opening_wallet(self):
        self.campaign.core = ProofCore()
        self.override, self.exit_code = {}, 0
        with patch("subprocess.run", side_effect=self.native) as native:
            result = verify_coin(self.campaign, "alice", self.coin())
            self.assertEqual(result["status"], "PASS")
            self.campaign.abandon("alice")
            again = verify_coin(self.campaign, "alice", self.coin())
        self.assertEqual(result, again)
        self.assertEqual(native.call_count, 2)
        with self.assertRaisesRegex(ValueError, "differs"):
            verify_coin(self.campaign, "alice", {**self.coin(), "amount_sat": 6000})

    def test_other_anchor_or_wrong_coin_fields_do_not_verify(self):
        self.campaign.core = ProofCore()
        self.override, self.exit_code = {"anchor_txid": "f" * 64}, 0
        with patch("subprocess.run", side_effect=self.native):
            result = verify_coin(self.campaign, "alice", self.coin())
        self.assertNotEqual(result["status"], "PASS")

    def test_rejected_signature_never_becomes_an_acknowledged_proof(self):
        self.campaign.core = ProofCore()
        self.override, self.exit_code = {}, 1
        with patch("subprocess.run", side_effect=self.native):
            result = verify_coin(self.campaign, "alice", self.coin())
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["native_exit_code"], 1)

    def test_changed_private_bytes_cannot_reuse_a_cached_passing_proof(self):
        self.campaign.core = ProofCore()
        self.override, self.exit_code = {}, 0
        with patch("subprocess.run", side_effect=self.native):
            result = verify_coin(self.campaign, "alice", self.coin())
        artifact = self.campaign.db.execute("SELECT relative_path FROM native_artifact WHERE intent=? AND kind='stdout'",
                                            (result["raw_intent"],)).fetchone()[0]
        (self.campaign.root / artifact).write_bytes(b"ff")
        with self.assertRaisesRegex(ValueError, "artifact changed"):
            verify_coin(self.campaign, "alice", self.coin())


if __name__ == "__main__":
    unittest.main()

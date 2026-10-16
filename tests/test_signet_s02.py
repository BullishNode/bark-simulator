"""Adversarial stubbed lifecycle tests; no public-Signet qualification."""
from decimal import Decimal
import json
import time
import unittest
from unittest.mock import patch

from simulator.model import canonical
from simulator.signet_s02 import begin_absence, observe_payout, check_recovery
from tests import test_signet


ANCHOR, PAYOUT, RECOVERY, CHANGE = [char * 64 for char in "abcd"]
SCRIPT = "0014" + "1" * 40
DESTINATION = "0014" + "2" * 40


def output(amount, script=SCRIPT, index=0):
    return {"n": index, "value": Decimal(amount) / 100000000, "scriptPubKey": {"hex": script}}


class LifecycleCore(test_signet.Core):
    def __init__(self):
        super().__init__(blocks=200)
        self.transactions = {
            ANCHOR: {"txid": ANCHOR, "version": 3, "confirmations": 101, "blockhash": "1" * 64,
                     "vin": [], "vout": [output(20000)]},
            PAYOUT: {"txid": PAYOUT, "version": 3, "confirmations": 11, "blockhash": "2" * 64,
                     "vin": [{"txid": ANCHOR, "vout": 0}],
                     "vout": [output(9000), output(11000, "0014" + "3" * 40, 1)]},
            CHANGE: {"txid": CHANGE, "version": 2, "confirmations": 51, "blockhash": "4" * 64,
                     "vin": [], "vout": [output(10000)]},
            RECOVERY: {"txid": RECOVERY, "version": 2, "confirmations": 1, "blockhash": "3" * 64,
                       "vin": [{"txid": PAYOUT, "vout": 0}, {"txid": CHANGE, "vout": 0}],
                       "vout": [output(18000, DESTINATION)]}}

    def call(self, method, *args):
        if method == "validateaddress":
            return {"isvalid": True, "scriptPubKey": DESTINATION if args[0] == "tb1qrecovered" else SCRIPT}
        if method == "getrawtransaction":
            return self.transactions[args[0]]
        if method == "gettxout":
            return {"confirmations": 30, "bestblock": self.info["bestblockhash"], "value": Decimal("0.00020000")}
        if method == "getblockhash" and args[0] != 0:
            return {100: "1" * 64, 150: "4" * 64, 190: "2" * 64, 200: "3" * 64}.get(args[0], "f" * 64)
        return super().call(method, *args)


class S02Tests(unittest.TestCase):
    setUp = test_signet.SignetTests.setUp
    tearDown = test_signet.SignetTests.tearDown

    def receipt(self, intent, operation, reply, args=None, actor="absent", created=1):
        self.campaign.db.execute("INSERT INTO action VALUES (?,?,?,?,?,?,?,?,?,?)", (
            intent, actor, operation, canonical(args or {}), "acknowledged", created, created,
            None, canonical(reply), None))

    def freeze(self):
        self.campaign.core = LifecycleCore()
        coin = {"id": "e" * 64 + ":0", "amount_sat": 10000, "chain_anchor": ANCHOR + ":0",
                "user_pubkey": "02" + "1" * 64, "expiry_height": 180, "state": "spendable"}
        self.receipt("snapshot", "sync_vtxos", [coin])
        self.receipt("registration", "fallback_record", {"payout_address": "tb1qpayout", "record": {"spk": SCRIPT}})
        proof = {"status": "PASS", "coin_id": coin["id"], "path_outpoints": [ANCHOR + ":0", coin["id"]]}
        self.campaign.core.info["blocks"] = 170
        with patch("simulator.signet_s02.verify_coin", return_value=proof):
            result = begin_absence(self.campaign, "absent", "snapshot", "registration")
        self.campaign.core.info["blocks"] = 200
        return result

    def payout(self):
        frozen = self.freeze()
        result = observe_payout(self.campaign, "absent", PAYOUT, 0, [frozen["coins"][0]["id"]])
        return frozen, result

    def test_absence_freezes_signed_paths_and_blocks_all_native_wallet_opens(self):
        frozen = self.freeze()
        self.assertEqual(frozen["stage"], "ABSENT_WAITING_FOR_REAL_EXPIRY")
        with patch("simulator.signet.subprocess.run") as native:
            with self.assertRaisesRegex(ValueError, "absent actor"):
                self.campaign.execute("no-reopen", "absent", "vtxos", {})
        native.assert_not_called()
        with patch("simulator.signet_s02.verify_coin") as proof:
            self.assertEqual(begin_absence(self.campaign, "absent", "snapshot", "registration"), frozen)
        proof.assert_not_called()

    def test_stale_snapshot_cannot_declare_absence(self):
        self.campaign.core = LifecycleCore()
        self.campaign.core.info["blocks"] = 170
        coin = {"id": "e" * 64 + ":0", "amount_sat": 10000, "expiry_height": 180,
                "chain_anchor": ANCHOR + ":0", "state": "spendable"}
        self.receipt("snapshot", "sync_vtxos", [coin])
        self.receipt("registration", "fallback_record", {"payout_address": "tb1qpayout", "record": {"spk": SCRIPT}})
        self.receipt("refresh", "refresh", {}, created=2)
        with patch("simulator.signet_s02.verify_coin", return_value={"status": "PASS", "path_outpoints": [ANCHOR + ":0"]}):
            with self.assertRaisesRegex(ValueError, "actor changed"):
                begin_absence(self.campaign, "absent", "snapshot", "registration")
        self.assertIsNone(self.campaign.db.execute("SELECT * FROM actor WHERE id='absent'").fetchone())

    def test_exact_payout_requires_actual_signed_path_and_preserves_failed_observations(self):
        frozen, good = self.payout()
        self.assertEqual(good["payout_check"], "PASS")
        self.assertEqual(good["case_verdict"], "INCOMPLETE")
        # Sending the exact expected value to the correct script is insufficient.
        self.campaign.core.transactions[PAYOUT]["vin"][0]["txid"] = CHANGE
        self.campaign.core.transactions[PAYOUT]["vout"][1]["value"] = Decimal("0.00001000")
        wrong = observe_payout(self.campaign, "absent", PAYOUT, 0, [frozen["coins"][0]["id"]])
        self.assertNotEqual(wrong["payout_check"], "PASS")
        self.assertIn("signed path", wrong["reason"])
        self.assertEqual(self.campaign.db.execute("SELECT count(*) FROM result WHERE id LIKE 's02-payout-%'").fetchone()[0], 2)

    def test_wrong_payee_wrong_value_and_reorg_are_not_payouts(self):
        frozen, _ = self.payout()
        tx = self.campaign.core.transactions[PAYOUT]
        for field, bad in (("value", Decimal("0.00009001")), ("scriptPubKey", {"hex": DESTINATION})):
            old = tx["vout"][0][field]
            tx["vout"][0][field] = bad
            result = observe_payout(self.campaign, "absent", PAYOUT, 0, [frozen["coins"][0]["id"]])
            self.assertNotEqual(result["payout_check"], "PASS")
            tx["vout"][0][field] = old
        tx["blockhash"] = "f" * 64
        result = observe_payout(self.campaign, "absent", PAYOUT, 0, [frozen["coins"][0]["id"]])
        self.assertIn("canonical", result["reason"])

    def test_confirmed_restored_spend_must_consume_payout_not_ordinary_change(self):
        frozen, _ = self.payout()
        self.receipt("restore", "restore", {}, {"source_actor": "absent"}, actor="restored")
        self.receipt("drain", "onchain_drain", {"txid": RECOVERY}, {"destination": "tb1qrecovered"}, actor="restored")
        result = check_recovery(self.campaign, "absent", "restored", "drain", "s02-payout-absent-0", "tb1qrecovered")
        self.assertEqual(result["recovery_check"], "PASS")
        self.assertEqual(result["recovered_payout_sat"], 9000)
        self.assertEqual(result["other_inputs"], [{"outpoint": CHANGE + ":0", "amount_sat": 10000}])
        self.assertEqual(result["miner_fee_sat"], 1000)
        self.assertEqual(result["case_verdict"], "INCOMPLETE")
        self.campaign.core.transactions[RECOVERY]["vin"] = [{"txid": CHANGE, "vout": 0}]
        self.campaign.core.transactions[RECOVERY]["vout"][0]["value"] = Decimal("0.00009000")
        bad = check_recovery(self.campaign, "absent", "restored", "drain", "s02-payout-absent-0", "tb1qrecovered")
        self.assertNotEqual(bad["recovery_check"], "PASS")
        self.assertIn("actual fallback payout", bad["reason"])


if __name__ == "__main__":
    unittest.main()

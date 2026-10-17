"""One same-expiry grouping case, reusing the executed two-wallet lifecycle.

This is S03 only. An unrelated unresolved root needs its own authentic producer;
no unregistered-recipient or synthetic readiness flag stands in for that case.
"""
import json

from .model import canonical
from .signet_checks import confirmed_backing
from .signet_proof import verify_coin
from .signet_s02 import _freeze, begin_absence
from .signet_s02_case import S02


class S03(S02):
    transfer_sat = 10000

    def _progress(self, stage, **evidence):
        return {**super()._progress(stage, **evidence), "case": "S03"}

    @staticmethod
    def originals(coins):
        current = {actor: [coin for coin in values if coin["state"] == "spendable"]
                   for actor, values in coins.items()}
        if (set(current) != {"absent", "control"} or any(len(values) != 1 for values in current.values())
                or any(coin["state"] not in {"spendable", "spent"} for values in coins.values() for coin in values)):
            raise ValueError("S03 requires one genuinely admitted original coin per actor")
        originals = [current[actor][0] for actor in ["absent", "control"]]
        if len({coin["chain_anchor"] for coin in originals}) != 2:
            raise ValueError("S03 needs two independently backed tree outputs")
        if len({coin["expiry_height"] for coin in originals}) != 1:
            raise ValueError("different-expiry originals cannot qualify same-expiry grouping")
        if originals[1]["amount_sat"] < S03.transfer_sat + 1000:
            raise ValueError("control needs transfer and bounded fee headroom")
        return current

    def advance(self):
        c = self.campaign
        if c.db.execute("SELECT 1 FROM action WHERE state IN ('unknown','dispatched')").fetchone():
            return self._progress("RECONCILIATION_REQUIRED")
        if not c.db.execute("SELECT 1 FROM meta WHERE key='s02_absent:absent'").fetchone():
            self._prepare_and_freeze()
            if not c.db.execute("SELECT 1 FROM meta WHERE key='s02_absent:absent'").fetchone():
                return self._last_preparation
        result = super().advance()
        result = {**result, "case": "S03"}
        if result.get("case_verdict") != "PASS":
            return result
        frozen = _freeze(c, "absent")
        original = json.loads(c.db.execute("SELECT value FROM meta WHERE key='s03_originals'").fetchone()[0])
        expected = original["coins"]["absent"][0]["amount_sat"] + self.transfer_sat - 1000
        if (len(frozen["coins"]) != 2 or len({coin["chain_anchor"] for coin in frozen["coins"]}) != 2
                or len({coin["expiry_height"] for coin in frozen["coins"]}) != 1
                or len(result["confirmed_payout_outpoints"]) != 1
                or result["confirmed_recovered_payout_sat"] != expected):
            return {**result, "stage": "GROUPING_EXPECTATION_FAILED", "case_verdict": "FAIL",
                    "reason": "S02 recovery alone does not prove one output/fee across two same-expiry roots"}
        return {**result, "stage": "S03_GROUPED_PAYOUT_AND_RECOVERY_CONFIRMED",
                "expected_grouped_payout_sat": expected, "payout_output_fee_sat": 1000,
                "scope": "Two independently backed same-expiry roots paid one absent user through one output and one fee, then original-seed recovery spent it. Unresolved-root isolation is a separate case."}

    def _prepare_and_freeze(self):
        c = self.campaign
        saved = c.db.execute("SELECT value FROM meta WHERE key='s03_originals'").fetchone()
        if saved:
            original = json.loads(saved[0])
        else:
            ready = super().prepare()
            self._last_preparation = {**ready, "case": "S03"}
            if ready["stage"] != "READY_FOR_EXPLICIT_ABSENCE":
                return
            snapshots = ready["snapshot_intents"]
            coins = {actor: json.loads(c.db.execute("SELECT reply FROM action WHERE id=?", (intent,)).fetchone()[0])
                     for actor, intent in snapshots.items()}
            current = self.originals(coins)
            for actor, values in current.items():
                for coin in values:
                    if verify_coin(c, actor, coin)["status"] != "PASS":
                        raise ValueError("native original signed receipts required before S03 transfer")
            confirmed_backing(c.core, list(current.values()))
            original = {"snapshots": snapshots, "coins": current}
            c.db.execute("INSERT INTO meta VALUES ('s03_originals',?)", (canonical(original),))
        address = self._native("s03-absent-receive-address", "absent", "address")["address"]
        done = c.db.execute("SELECT payload FROM result WHERE id='s03-transfer-check'").fetchone()
        if done:
            check = json.loads(done[0])
        else:
            self._native("s03-control-to-absent", "control", "send", {
                "destination": address, "amount_sat": self.transfer_sat})
            sender_after, _ = self._snapshot("control", "after-s03-send")
            receiver_after, coins = self._snapshot("absent", "after-s03-receive")
            check = c.check_transfer("s03-transfer-check", "s03-control-to-absent",
                                     original["snapshots"]["control"], sender_after,
                                     original["snapshots"]["absent"], receiver_after, 1000)
        if check.get("arithmetic") != "PASS" or check.get("backing") != "PASS":
            raise ValueError("original S03 transfer needs independent financial reconciliation")
        receiver_after = check["snapshots"][3]
        coins = json.loads(c.db.execute("SELECT reply FROM action WHERE id=?", (receiver_after,)).fetchone()[0])
        active = [coin for coin in coins if coin["state"] == "spendable"]
        first = original["coins"]["absent"][0]
        if (len(active) != 2 or first not in active
                or {coin["chain_anchor"] for coin in active} != {
                    first["chain_anchor"], original["coins"]["control"][0]["chain_anchor"]}
                or sum(coin["amount_sat"] for coin in active) != first["amount_sat"] + self.transfer_sat):
            raise ValueError("S03 recipient must own its original coin plus the distinct-root receive")
        for coin in active:
            if coin["id"] != first["id"] and verify_coin(c, "absent", coin, expected_address=address)["status"] != "PASS":
                raise ValueError("S03 received signed policy differs from native recipient address")
        c.db.execute("INSERT OR REPLACE INTO meta VALUES ('s02_control_before',?)", (check["snapshots"][1],))
        begin_absence(c, "absent", receiver_after, "s02-absent-registration")

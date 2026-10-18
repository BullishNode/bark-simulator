"""Different-expiry receipt case using the existing native recovery lifecycle."""
import json

from .model import canonical
from .signet import network_identity
from .signet_grouping import S03
from .signet_s02 import _freeze
from .signet_s02_case import S02


class S05(S03):
    board_height_gap = 4

    def _progress(self, stage, **evidence):
        return {**super()._progress(stage, **evidence), "case": "S05"}

    @staticmethod
    def originals(coins):
        current = {actor: [coin for coin in values if coin["state"] == "spendable"]
                   for actor, values in coins.items()}
        if (set(current) != {"absent", "control"} or any(len(values) != 1 for values in current.values())
                or any(coin["state"] not in {"spendable", "spent"} for values in coins.values() for coin in values)):
            raise ValueError("S05 requires one genuinely admitted original coin per actor")
        absent, control = (current[actor][0] for actor in ["absent", "control"])
        if absent["chain_anchor"] == control["chain_anchor"]:
            raise ValueError("S05 needs independently backed tree outputs")
        if absent["expiry_height"] - control["expiry_height"] < S05.board_height_gap:
            raise ValueError("S05 control must have the deliberately earlier actual expiry")
        if control["amount_sat"] < S03.transfer_sat + 1000:
            raise ValueError("control needs transfer and bounded fee headroom")
        return current

    def _prepare_and_freeze(self):
        c = self.campaign
        parameters = canonical({"first_board_actor": "control", "board_height_gap": self.board_height_gap})
        c.db.execute("INSERT OR IGNORE INTO meta VALUES ('s05_setup',?)", (parameters,))
        if c.db.execute("SELECT value FROM meta WHERE key='s05_setup'").fetchone()[0] != parameters:
            raise ValueError("S05 setup parameters are immutable")
        # Do not split the genuine native preparation until both original
        # allocations have been independently confirmed and recorded.
        funding = [json.loads(row[0]) for row in c.db.execute(
            "SELECT payload FROM result WHERE json_extract(payload,'$.kind')='external_funding'")]
        if any(sum(item["amount_sat"] for item in funding if item["actor"] == actor)
               <= self.params["board_sat"] for actor in ["absent", "control"]):
            self._last_preparation = {**S02.prepare(self), "case": "S05"}
            return
        self._native("s02-control-board", "control", "board", {"amount_sat": self.params["board_sat"]})
        first = c.db.execute("SELECT chain FROM action WHERE id='s02-control-board'").fetchone()
        height = network_identity(c.core)["height"]
        earliest = json.loads(first[0])["height"] + self.board_height_gap
        if height < earliest:
            self._last_preparation = self._progress("WAITING_FOR_DIFFERENT_BOARD_HEIGHT",
                current_height=height, earliest_second_board_height=earliest,
                scope="Control board issued once; absent board, transfer and absence have not started.")
            return
        # S03's native transfer/freeze accepts originals through this class's
        # actual-expiry validator. Every original journal ID remains unchanged.
        super()._prepare_and_freeze()
        if hasattr(self, "_last_preparation"):
            self._last_preparation = {**self._last_preparation, "case": "S05"}

    def advance(self):
        c = self.campaign
        if c.db.execute("SELECT 1 FROM action WHERE state IN ('unknown','dispatched')").fetchone():
            return self._progress("RECONCILIATION_REQUIRED")
        if not c.db.execute("SELECT 1 FROM meta WHERE key='s02_absent:absent'").fetchone():
            self._prepare_and_freeze()
            if not c.db.execute("SELECT 1 FROM meta WHERE key='s02_absent:absent'").fetchone():
                return self._last_preparation
        result = {**S02.advance(self), "case": "S05"}
        if result.get("case_verdict") != "PASS":
            return result
        frozen = _freeze(c, "absent")
        coins = frozen["coins"]
        expected = sum(coin["amount_sat"] for coin in coins) - 2000
        points = result["confirmed_payout_outpoints"]
        if (len(coins) != 2 or len({coin["expiry_height"] for coin in coins}) != 2
                or len({coin["chain_anchor"] for coin in coins}) != 2 or len(points) != 2
                or result["confirmed_recovered_payout_sat"] != expected):
            return {**result, "stage": "EPOCH_EXPECTATION_FAILED", "case_verdict": "FAIL",
                    "reason": "two different-expiry entitlements require two actual outputs and fees"}
        early = min(coins, key=lambda coin: coin["expiry_height"])
        later_expiry = max(coin["expiry_height"] for coin in coins)
        observed = None
        for row in c.db.execute("""SELECT payload FROM result WHERE
            json_extract(payload,'$.kind')='S02_payout_observation'
            AND json_extract(payload,'$.payout_check')='PASS' ORDER BY observed DESC"""):
            candidate = json.loads(row[0])
            if candidate["outpoint"] in points and candidate["coin_ids"] == [early["id"]]:
                observed = candidate
                break
        if not observed or observed["confirmation_height"] >= later_expiry:
            return {**result, "stage": "EPOCH_EARLY_PAYMENT_NOT_DEMONSTRATED", "case_verdict": "FAIL",
                    "reason": "no current verified earlier payout confirmed before later backing expiry"}
        return {**result, "stage": "S05_SEPARATE_EPOCH_PAYOUTS_AND_RECOVERY_CONFIRMED",
                "expected_separate_payout_sat": expected, "payout_output_fees_sat": 2000,
                "earlier_payout_confirmation_height": observed["confirmation_height"],
                "later_expiry_height": later_expiry,
                "scope": "Two pre-absence receipts at distinct expiry heights paid separately with one fee per output; the earlier payout confirmed before later expiry. Original-seed recovery spent both. Continuing post-absence receipts remain a separate case."}

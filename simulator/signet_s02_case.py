"""Small sequential S02 campaign using genuine native actions and public Core.

Preparation stops before absence. The existing explicit begin-absence command
is the operational handoff; no synthetic product-readiness flag exists here.
"""
from __future__ import annotations

import json

from .model import canonical, integer
from .signet import network_identity
from .signet_discovery import discover_payouts
from .signet_s02 import _freeze, observe_payout, check_control, check_recovery, reconcile


class S02:
    def __init__(self, campaign, *, board_sat: int, maximum_control_fee_sat: int,
                 recovery_destination: str):
        self.campaign = campaign
        self.params = {"board_sat": integer(board_sat, "board amount", 1),
                       "maximum_control_fee_sat": integer(maximum_control_fee_sat, "maximum control fee"),
                       "recovery_destination": recovery_destination,
                       "wallet_profile": {"vtxo_refresh_expiry_threshold": 4, "vtxo_exit_margin": 2}}
        from .signet import command
        command("onchain_drain", {"destination": recovery_destination}, campaign.config)
        destination = campaign.core.call("validateaddress", recovery_destination)
        if not isinstance(destination, dict) or destination.get("isvalid") is not True or not destination.get("scriptPubKey"):
            raise ValueError("valid actual Signet recovery destination required before actor work")
        encoded = canonical(self.params)
        campaign.db.execute("INSERT OR IGNORE INTO meta VALUES ('s02_parameters',?)", (encoded,))
        if campaign.db.execute("SELECT value FROM meta WHERE key='s02_parameters'").fetchone()[0] != encoded:
            raise ValueError("S02 parameters are immutable within this campaign")

    def _native(self, intent, actor, operation, args=None):
        row = self.campaign.execute(intent, actor, operation, args or {})
        if row["state"] != "acknowledged":
            raise ValueError("original native outcome requires reconciliation: " + intent)
        return json.loads(row["reply"])

    def _snapshot(self, actor, purpose):
        prefix = f"s02-{purpose}-{actor}-"
        number = self.campaign.db.execute("SELECT count(*) FROM action WHERE id LIKE ?", (prefix + "%",)).fetchone()[0]
        intent = prefix + str(number)
        return intent, self._native(intent, actor, "sync_vtxos")

    def _progress(self, stage, **evidence):
        return {"case": "S02", "stage": stage, "case_verdict": "INCOMPLETE", **evidence}

    def prepare(self):
        campaign = self.campaign
        addresses = {}
        for actor in ["absent", "control"]:
            self._native(f"s02-{actor}-create", actor, "create", {"wallet_profile": self.params["wallet_profile"]})
            addresses[actor] = self._native(f"s02-{actor}-onchain-address", actor, "onchain_address")["address"]
            registration = self._native(f"s02-{actor}-registration", actor, "fallback_record")
            address_info = campaign.core.call("validateaddress", registration["payout_address"])
            if (not address_info.get("isvalid") or address_info.get("scriptPubKey") != registration["record"]["spk"]
                    or registration["payout_address"] == addresses[actor]):
                raise ValueError("authenticated reserved payout script differs from native funding address")
        target = self._native("s02-target-info", "control", "ark_info")
        if any(target[key] != expected for key, expected in
               {"vtxo_lifetime": 12, "vtxo_exit_delta": 3, "required_board_confirmations": 3}.items()):
            raise ValueError("declared short-profile server parameters differ")
        if self.params["board_sat"] < target["min_board_amount_sat"]:
            raise ValueError("declared S02 board is below the real server minimum")
        funding = [json.loads(row[0]) for row in campaign.db.execute(
            "SELECT payload FROM result WHERE json_extract(payload,'$.kind')='external_funding'")]
        if any(sum(item["amount_sat"] for item in funding if item["actor"] == actor) <= self.params["board_sat"]
               for actor in addresses):
            return self._progress("WAITING_FOR_OWNER_ALLOCATED_FUNDING", funding_addresses=addresses)
        boards = {actor: self._native(f"s02-{actor}-board", actor, "board", {"amount_sat": self.params["board_sat"]})
                  for actor in addresses}
        snapshots = {}
        for actor in addresses:
            intent, coins = self._snapshot(actor, "before")
            if (any(coin["state"] not in {"spent", "spendable"} for coin in coins)
                    or sum(coin["amount_sat"] for coin in coins if coin["state"] == "spendable") != boards[actor]["amount_sat"]):
                return self._progress("WAITING_FOR_NATIVE_SETTLEMENT", actor=actor, snapshot_intent=intent)
            snapshots[actor] = intent
        # The control baseline can be replaced while both wallets are active.
        # The explicit absence action then freezes this prepared pair.
        campaign.db.execute("INSERT OR REPLACE INTO meta VALUES ('s02_control_before',?)", (snapshots["control"],))
        return self._progress("READY_FOR_EXPLICIT_ABSENCE", snapshot_intents=snapshots,
                              registration_intent="s02-absent-registration",
                              instruction="After the deployed payout path has been checked, invoke s02-begin-absence for the absent snapshot. No absence has been started.")

    def _payouts(self, frozen):
        campaign = self.campaign
        rows = campaign.db.execute("""SELECT id,payload FROM result
            WHERE json_extract(payload,'$.kind')='S02_payout_observation'
            AND json_extract(payload,'$.actor')='absent'
            AND json_extract(payload,'$.payout_check')='PASS' ORDER BY observed""").fetchall()
        current, covered, points = [], set(), set()
        for row in rows:
            old = json.loads(row["payload"])
            if old["outpoint"] in points:
                continue
            txid, index = old["outpoint"].split(":")
            now = observe_payout(campaign, "absent", txid, int(index), old["coin_ids"])
            if now["payout_check"] != "PASS":
                continue
            if covered.intersection(old["coin_ids"]):
                raise ValueError("overlapping frozen payout allocations")
            covered.update(old["coin_ids"])
            points.add(old["outpoint"])
            current.append((row["id"], now))
        return current, covered == {coin["id"] for coin in frozen["coins"]}

    def advance(self):
        campaign = self.campaign
        chain = network_identity(campaign.core)
        if campaign.db.execute("SELECT 1 FROM action WHERE state IN ('dispatched','unknown')").fetchone():
            return self._progress("RECONCILIATION_REQUIRED")
        if not campaign.db.execute("SELECT 1 FROM meta WHERE key='s02_absent:absent'").fetchone():
            return self.prepare()
        frozen = _freeze(campaign, "absent")
        before = campaign.db.execute("SELECT value FROM meta WHERE key='s02_control_before'").fetchone()
        if not before:
            raise ValueError("prepared original active control checkpoint required")
        self._native(f"s02-control-maintain-{chain['height']}", "control", "maintain")
        after, _ = self._snapshot("control", "current")
        original = json.loads(campaign.db.execute("SELECT reply FROM action WHERE id=?", (before[0],)).fetchone()[0])
        control_id = None
        if chain["height"] >= min(coin["expiry_height"] for coin in original if coin["state"] == "spendable"):
            control = check_control(campaign, "control", before[0], after, self.params["maximum_control_fee_sat"])
            if control["control_check"] == "PASS":
                control_id = campaign.db.execute("""SELECT id FROM result WHERE
                    json_extract(payload,'$.kind')='S02_control_observation' ORDER BY observed DESC LIMIT 1""").fetchone()[0]
        discovery = discover_payouts(campaign, "absent")
        payouts, complete = self._payouts(frozen)
        if not complete:
            return self._progress("WAITING_FOR_CANONICAL_PAYOUTS", discovery=discovery,
                                  expiry_heights=sorted({coin["expiry_height"] for coin in frozen["coins"]}))
        created = campaign.db.execute("SELECT chain FROM action WHERE id='s02-absent-create'").fetchone()
        if not created:
            raise ValueError("original native wallet creation height required")
        self._native("s02-seed-restore", "restored", "restore", {
            "source_actor": "absent", "birthday_height": json.loads(created[0])["height"],
            "wallet_profile": self.params["wallet_profile"]})
        spend = campaign.db.execute("SELECT 1 FROM action WHERE id='s02-recovery-drain'").fetchone()
        if not spend:
            _, utxos = self._snapshot_onchain()
            found = {item["outpoint"]: item for item in utxos if item["confirmation_height"] is not None}
            if any(item["outpoint"] not in found or found[item["outpoint"]]["amount_sat"] != item["amount_sat"]
                   for _, item in payouts):
                return self._progress("WAITING_FOR_NATIVE_SEED_RECOVERY")
        self._native("s02-recovery-drain", "restored", "onchain_drain", {"destination": self.params["recovery_destination"]})
        recovery = [check_recovery(campaign, "absent", "restored", "s02-recovery-drain", payout_id,
                                   self.params["recovery_destination"]) for payout_id, _ in payouts]
        if any(item["recovery_check"] != "PASS" for item in recovery):
            return self._progress("WAITING_FOR_CONFIRMED_RECOVERY_SPEND", recovery=recovery)
        if control_id is None:
            return self._progress("WAITING_FOR_REFRESHED_ACTIVE_CONTROL", recovery=recovery)
        return reconcile(campaign, "absent", control_id)

    def _snapshot_onchain(self):
        number = self.campaign.db.execute("SELECT count(*) FROM action WHERE operation='onchain_utxos' AND actor='restored'").fetchone()[0]
        intent = f"s02-restored-utxos-{number}"
        return intent, self._native(intent, "restored", "onchain_utxos")

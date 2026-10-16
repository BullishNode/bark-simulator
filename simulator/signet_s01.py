"""Resumable first native two-wallet flow; no synthetic chain or clock."""
from __future__ import annotations

import json
import time

from .model import btc_to_sat, canonical, integer
from .signet import network_identity


def funding_receipt(campaign, actor: str, txid: str, index: int) -> dict:
    """Bind an externally allocated, confirmed funding output to its native address."""
    import re
    if not re.fullmatch(r"[0-9a-f]{64}", txid):
        raise ValueError("funding transaction ID required")
    integer(index, "funding output index")
    key = f"funding:{txid}:{index}"
    previous = campaign.db.execute("SELECT payload FROM result WHERE id=?", (key,)).fetchone()
    if previous:
        old = json.loads(previous[0])
        if old["actor"] != actor:
            raise ValueError("funding outpoint reused with different ownership or value")
        return old  # Historical funding can already have been consumed by a board.
    address = campaign.db.execute("""SELECT id,reply FROM action WHERE actor=?
        AND operation='onchain_address' AND state='acknowledged' ORDER BY created DESC LIMIT 1""", (actor,)).fetchone()
    if not address:
        raise ValueError("native funding address receipt required")
    destination = json.loads(address["reply"])["address"]
    chain = network_identity(campaign.core)
    expected = campaign.core.call("validateaddress", destination)
    output = campaign.core.call("gettxout", txid, index, True)
    if not output or output.get("confirmations", 0) < 1:
        return {"state": "WAITING_FOR_FUNDING_CONFIRMATION", "actor": actor,
                "outpoint": f"{txid}:{index}", "height": chain["height"]}
    if (expected.get("isvalid") is not True or not expected.get("scriptPubKey")
            or output["scriptPubKey"]["hex"] != expected["scriptPubKey"]
            or output["bestblock"] != chain["hash"]):
        raise ValueError("funding output does not match the actor's native address at this tip")
    receipt = {"kind": "external_funding", "actor": actor, "outpoint": f"{txid}:{index}",
               "address_intent": address["id"], "amount_sat": btc_to_sat(output["value"]),
               "confirmations": output["confirmations"], "chain": chain}
    campaign.db.execute("INSERT INTO result VALUES (?,?,?)", (key, time.time(), canonical(receipt)))
    return receipt


class S01:
    def __init__(self, campaign, *, board_sat: int, transfer_sat: int, maximum_fee_sat: int):
        self.campaign = campaign
        self.params = {"board_sat": integer(board_sat, "board amount", 1),
                       "transfer_sat": integer(transfer_sat, "transfer amount", 1),
                       "maximum_fee_sat": integer(maximum_fee_sat, "maximum fee")}
        if transfer_sat + maximum_fee_sat > board_sat:
            raise ValueError("board does not cover transfer and its declared fee bound")
        serialized = canonical(self.params)
        campaign.db.execute("INSERT OR IGNORE INTO meta VALUES ('s01_parameters',?)", (serialized,))
        if campaign.db.execute("SELECT value FROM meta WHERE key='s01_parameters'").fetchone()[0] != serialized:
            raise ValueError("S01 parameters are immutable within this campaign")

    def _native(self, intent, actor, operation, args=None):
        row = self.campaign.execute(intent, actor, operation, args or {})
        if row["state"] != "acknowledged":
            return None, {"case": "S01", "stage": "RECONCILIATION_REQUIRED", "intent": intent,
                          "native_state": row["state"], "case_verdict": "INCOMPLETE"}
        return json.loads(row["reply"]), None

    def _snapshot_pair(self, prefix):
        replies, names = [], []
        # Each poll is a new observation, never a replay of a monetary intent.
        number = self.campaign.db.execute("SELECT count(*) FROM action WHERE id LIKE ?", (prefix + "-%",)).fetchone()[0]
        for actor in ("sender", "receiver"):
            name = f"{prefix}-{number}-{actor}"
            reply, wait = self._native(name, actor, "sync_vtxos")
            if wait:
                return None, None, wait
            replies.append(reply)
            names.append(name)
        if any(c["state"] not in {"spent", "spendable"} for reply in replies for c in reply):
            return None, None, {"case": "S01", "stage": "WAITING_FOR_NATIVE_SETTLEMENT",
                                "snapshots": names, "case_verdict": "INCOMPLETE"}
        return replies, names, None

    def _proofs(self, check):
        from .signet_proof import verify_coin
        proofs = []
        for snapshot_name in (check["snapshots"][1], check["snapshots"][3]):
            snapshot = self.campaign.db.execute("SELECT actor,reply FROM action WHERE id=?", (snapshot_name,)).fetchone()
            for coin in json.loads(snapshot["reply"]):
                if coin["state"] == "spendable":
                    try:
                        proofs.append(verify_coin(self.campaign, snapshot["actor"], coin))
                    except ValueError as error:
                        proofs.append({"coin_id": coin["id"], "status": "UNAVAILABLE",
                                       "diagnostic": type(error).__name__})
        return {"case": "S01", "stage": "NATIVE_TRANSFER_OBSERVED", "evidence": check,
                "signature_proofs": proofs,
                "signature_path_verification": "PASS" if proofs and all(p["status"] == "PASS" for p in proofs)
                else "INCOMPLETE"}

    def advance(self) -> dict:
        campaign = self.campaign
        chain = network_identity(campaign.core)
        for actor in ("sender", "receiver"):
            for operation in ("create", "onchain_address"):
                _, wait = self._native(f"s01-{actor}-{operation}", actor, operation)
                if wait:
                    return wait
        address, wait = self._native("s01-receiver-address", "receiver", "address")
        if wait:
            return wait
        funding = [json.loads(row[0]) for row in campaign.db.execute(
            "SELECT payload FROM result WHERE json_extract(payload,'$.kind')='external_funding'")]
        funded = {actor: sum(row["amount_sat"] for row in funding if row["actor"] == actor)
                  for actor in ("sender", "receiver")}
        if any(amount <= self.params["board_sat"] for amount in funded.values()):
            return {"case": "S01", "stage": "WAITING_FOR_OWNER_ALLOCATED_FUNDING",
                    "height": chain["height"], "funding_sat": funded,
                    "board_sat": self.params["board_sat"],
                    "note": "Each native funding address needs confirmed board value plus miner-fee headroom.",
                    "case_verdict": "INCOMPLETE"}
        boarded = {}
        for actor in ("sender", "receiver"):
            receipt, wait = self._native(f"s01-{actor}-board", actor, "board", {"amount_sat": self.params["board_sat"]})
            if wait:
                return wait
            # Native PendingBoard.amount_sat is net of the protocol board fee,
            # not the gross funding output requested by `board <amount>`.
            boarded[actor] = receipt["amount_sat"]
        if boarded["sender"] < self.params["transfer_sat"] + self.params["maximum_fee_sat"]:
            return {"case": "S01", "stage": "INSUFFICIENT_NATIVE_BOARD_VALUE",
                    "boarded_sat": boarded["sender"], "case_verdict": "INCOMPLETE"}
        before = campaign.db.execute("SELECT value FROM meta WHERE key='s01_before'").fetchone()
        if before is None:
            coins, names, wait = self._snapshot_pair("s01-before")
            if wait:
                return wait
            if any(sum(c["amount_sat"] for c in snapshot if c["state"] == "spendable") < boarded[actor]
                   for actor, snapshot in zip(("sender", "receiver"), coins)):
                return {"case": "S01", "stage": "WAITING_FOR_BOARD_CONFIRMATIONS",
                        "height": chain["height"], "snapshots": names, "case_verdict": "INCOMPLETE"}
            campaign.db.execute("INSERT INTO meta VALUES ('s01_before',?)", (canonical(names),))
            before = (canonical(names),)
        _, wait = self._native("s01-transfer", "sender", "send", {
            "destination": address["address"], "amount_sat": self.params["transfer_sat"]})
        if wait:
            return wait
        completed = campaign.db.execute("SELECT value FROM meta WHERE key='s01_observed'").fetchone()
        previous_check = (campaign.db.execute("SELECT payload FROM result WHERE id=?", (completed[0],)).fetchone()
                          if completed else None)
        if previous_check:
            return self._proofs(json.loads(previous_check[0]))
        _, after, wait = self._snapshot_pair("s01-after")
        if wait:
            return wait
        names = json.loads(before[0])
        check_id = "s01-check-" + str(campaign.db.execute(
            "SELECT count(*) FROM result WHERE id LIKE 's01-check-%'").fetchone()[0])
        check = campaign.check_transfer(check_id, "s01-transfer", names[0], after[0],
                                       names[1], after[1], self.params["maximum_fee_sat"])
        if check.get("arithmetic") == "PASS" and check.get("backing") == "PASS":
            campaign.db.execute("INSERT INTO meta VALUES ('s01_observed',?)", (check_id,))
            return self._proofs(check)
        return {"case": "S01", "stage": "RECONCILIATION_REQUIRED", "evidence": check}

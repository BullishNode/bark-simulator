"""Independent arithmetic and Core backing checks for the first native flow.

These checks do not use the product ownership resolver or allocator. Native
wallet ownership observations are labelled separately from cryptographic proof.
"""
from __future__ import annotations

from .model import btc_to_sat, integer
from .signet import network_identity


class ChainObservationChanged(ValueError):
    """The tip moved during a read; no conclusion about payment or backing."""


def coin_map(coins: list[dict]) -> dict[str, dict]:
    result = {}
    for coin in coins:
        if coin["id"] in result:
            raise ValueError("duplicate coin ID in wallet snapshot")
        integer(coin["amount_sat"], "coin value", 1)
        result[coin["id"]] = coin
    return result


def held(coins: dict[str, dict]) -> int:
    if any(coin["state"] not in {"spent", "spendable"} for coin in coins.values()):
        raise ValueError("wallet still has locked or exiting value: checkpoint is not settled")
    return sum(coin["amount_sat"] for coin in coins.values() if coin["state"] == "spendable")


def transfer_values(sender_before, sender_after, receiver_before, receiver_after,
                    amount_sat: int, maximum_fee_sat: int) -> dict:
    amount_sat = integer(amount_sat, "transfer amount", 1)
    maximum_fee_sat = integer(maximum_fee_sat, "declared maximum transfer fee")
    before_s, after_s, before_r, after_r = map(
        coin_map, (sender_before, sender_after, receiver_before, receiver_after))
    for sender, receiver in ((before_s, before_r), (after_s, after_r)):
        if {cid for cid, c in sender.items() if c["state"] == "spendable"} & {
                cid for cid, c in receiver.items() if c["state"] == "spendable"}:
            raise ValueError("same spendable coin counted in both wallets")
    for before, after in ((before_s, after_s), (before_r, after_r)):
        for cid in before.keys() & after.keys():
            if any(before[cid][key] != after[cid][key] for key in (
                    "amount_sat", "user_pubkey", "chain_anchor", "expiry_height")):
                raise ValueError("immutable native coin fields changed")
    opening = held(before_s) + held(before_r)
    closing = held(after_s) + held(after_r)
    received = held(after_r) - held(before_r)
    if received != amount_sat:
        raise ValueError("receiver net change does not equal the intended amount")
    fee = opening - closing
    if not 0 <= fee <= maximum_fee_sat:
        raise ValueError("cohort value mismatch or fee above the declared bound")
    old_receiver = {cid for cid, coin in before_r.items() if coin["state"] == "spendable"}
    if any(cid not in after_r or after_r[cid]["state"] != "spendable" for cid in old_receiver):
        raise ValueError("receiver spent other coins during the isolated transfer checkpoint")
    new_received = [cid for cid, coin in after_r.items()
                    if cid not in before_r and coin["state"] == "spendable"]
    if sum(after_r[cid]["amount_sat"] for cid in new_received) != amount_sat:
        raise ValueError("new receiver coin values do not establish the transfer")
    return {"arithmetic": "PASS", "opening_sat": opening, "closing_sat": closing,
            "received_sat": received, "observed_offchain_fee_sat": fee,
            "new_receiver_coins": new_received,
            "ownership_evidence": "NATIVE_WALLET_OBSERVATION",
            "signature_path_verification": "NOT_EVALUATED"}


def confirmed_backing(core, snapshots: list[list[dict]]) -> dict:
    """Read actual unspent anchors; do not count anchors as additional assets."""
    chain = network_identity(core)
    coins = {}
    for snapshot in snapshots:
        for coin in snapshot:
            if coin["state"] != "spendable":
                continue
            previous = coins.get(coin["id"])
            if previous is not None and previous != coin:
                raise ValueError("conflicting observations of the same native coin")
            coins[coin["id"]] = coin
    anchors = {}
    for coin in coins.values():
        anchor = coin["chain_anchor"]
        anchors.setdefault(anchor, {"cohort_value_sat": 0})["cohort_value_sat"] += integer(
            coin["amount_sat"], "coin amount", 1)
    for anchor, row in anchors.items():
        txid, index = anchor.split(":")
        output = core.call("gettxout", txid, int(index), True)
        if not output or integer(output["confirmations"], "anchor confirmations") < 1:
            raise ValueError("anchor is missing, unconfirmed or spent")
        if output["bestblock"] != chain["hash"]:
            raise ChainObservationChanged("chain changed during backing observation")
        row["anchor_value_sat"] = btc_to_sat(output["value"])
        row["confirmations"] = output["confirmations"]
        if row["cohort_value_sat"] > row["anchor_value_sat"]:
            raise ValueError("cohort coin values exceed their backing output")
    if network_identity(core) != chain:
        raise ChainObservationChanged("chain changed during backing observation; observe again")
    return {"backing": "PASS", "chain": chain, "anchors": anchors,
            "note": "Backing coverage does not prove off-chain signatures or current ownership."}

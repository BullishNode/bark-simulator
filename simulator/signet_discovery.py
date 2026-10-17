"""Bounded independent public-block discovery for the frozen S02 cohort."""
from __future__ import annotations

import json
import re

from .model import canonical, integer
from .signet import network_identity
from .signet_s02 import _freeze, _save, observe_payout


def discover_payouts(campaign, actor: str, maximum_transactions: int = 128) -> dict:
    """Resume public transaction IDs, never wallet opens or product payout IDs.

    The cursor is only an optimization. A changed canonical block rewinds to
    the cohort's earliest expiry; strict payout checks decide every candidate.
    Native secret/witness bytes never enter the discovery projection.
    """
    integer(maximum_transactions, "discovery transaction budget", 1)
    if maximum_transactions > 512:
        raise ValueError("bounded public discovery batch required")
    frozen = _freeze(campaign, actor)
    first = min(coin["expiry_height"] for coin in frozen["coins"])
    chain = network_identity(campaign.core)
    key = "s02_discovery:" + actor
    row = campaign.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    cursor = json.loads(row[0]) if row else {"height": first, "offset": 0,
                                          "block_hash": None, "previous_hash": None}
    rewound = False
    if cursor["height"] > first:
        previous = cursor["height"] - 1
        if previous > chain["height"] or campaign.core.call("getblockhash", previous) != cursor["previous_hash"]:
            cursor = {"height": first, "offset": 0, "block_hash": None, "previous_hash": None}
            rewound = True
    if cursor["block_hash"] and (cursor["height"] > chain["height"] or
                                 campaign.core.call("getblockhash", cursor["height"]) != cursor["block_hash"]):
        cursor = {"height": first, "offset": 0, "block_hash": None, "previous_hash": None}
        rewound = True
    scanned, candidates = 0, []
    script = frozen["registration"]["record"]["spk"]
    while cursor["height"] <= chain["height"] and scanned < maximum_transactions:
        block_hash = campaign.core.call("getblockhash", cursor["height"])
        block = campaign.core.call("getblock", block_hash, 1)
        transactions = block.get("tx")
        if (block.get("hash") != block_hash or block.get("height") != cursor["height"]
                or not isinstance(transactions, list) or not transactions
                or any(not isinstance(txid, str) or not re.fullmatch("[0-9a-f]{64}", txid) for txid in transactions)
                or cursor["offset"] > len(transactions)):
            raise ValueError("canonical public block inventory required")
        cursor["block_hash"] = block_hash
        while cursor["offset"] < len(transactions) and scanned < maximum_transactions:
            txid = transactions[cursor["offset"]]
            tx = campaign.core.call("getrawtransaction", txid, True)
            if tx.get("txid") != txid or tx.get("blockhash") != block_hash:
                raise ValueError("discovery transaction differs from canonical block")
            matching = [output for output in tx["vout"] if output["scriptPubKey"]["hex"] == script]
            if matching:
                inputs = {item["txid"] + ":" + str(item["vout"]) for item in tx["vin"] if "txid" in item}
                selected = [proof["coin_id"] for proof in frozen["signature_proofs"]
                            if inputs.intersection(proof["path_outpoints"])]
                for output in matching:
                    if selected:
                        try:
                            result = observe_payout(campaign, actor, txid, output["n"], selected)
                        except ValueError as error:
                            result = {"payout_check": "INCOMPLETE", "reason": str(error)}
                        candidates.append({"outpoint": txid + ":" + str(output["n"]),
                                           "coin_ids": sorted(selected), "payout_check": result["payout_check"],
                                           **({"reason": result["reason"]} if "reason" in result else {})})
            cursor["offset"] += 1
            scanned += 1
        if cursor["offset"] == len(transactions):
            cursor = {"height": cursor["height"] + 1, "offset": 0,
                      "block_hash": None, "previous_hash": block_hash}
    if network_identity(campaign.core) != chain:
        # The old cursor remains. Any observations already written are historical
        # only and the lifecycle reconciler will independently recheck them.
        raise ValueError("chain changed during public payout discovery")
    campaign.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, canonical(cursor)))
    return _save(campaign, "s02-discovery-" + actor,
                 {"kind": "S02_public_discovery", "actor": actor, "chain": chain,
                  "stage": "WAITING_FOR_REAL_EXPIRY" if chain["height"] < first else "PUBLIC_BLOCK_DISCOVERY",
                  "scanned_transactions": scanned, "rewound_after_reorg": rewound,
                  "next_height": cursor["height"], "next_transaction_offset": cursor["offset"],
                  "caught_up": cursor["height"] > chain["height"], "candidates": candidates,
                  "case_verdict": "INCOMPLETE", "scope": "Independent payout candidates; seed-only recovery and active control still required."})

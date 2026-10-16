"""Frozen absent-wallet cohort and independent payout/recovery evidence.

No product decision table or allocator is imported. Candidate transaction IDs
are observations, not authority: signed paths, scripts and exact values decide.
"""
from __future__ import annotations

import json
import hashlib
import io
import os
import re
import stat
import time

from .model import btc_to_sat, canonical, integer, public_payload
from .signet import network_identity
from .signet_proof import verify_coin


def recovery_source(campaign, actor: str):
    """Return only a protected recovery phrase backup, never an original DB."""
    campaign.actor_path(actor)
    intent = "s02-recovery-source-" + actor
    row = campaign.db.execute("SELECT * FROM native_artifact WHERE intent=? AND kind='source'", (intent,)).fetchone()
    if not row or row["truncated"] or not 1 <= row["bytes"] <= 512:
        raise ValueError("complete protected recovery source backup required")
    path = campaign.root / row["relative_path"]
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("recovery source must be an owner-only regular file")
        raw = source.read(513)
    if len(raw) != row["bytes"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
        raise ValueError("protected recovery source changed")
    return path


def _backup_recovery_source(campaign, actor):
    intent = "s02-recovery-source-" + actor
    if campaign.db.execute("SELECT 1 FROM native_artifact WHERE intent=? AND kind='source'", (intent,)).fetchone():
        return recovery_source(campaign, actor)
    fd = os.open(campaign.actor_path(actor) / "mnemonic", os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("original recovery source must be owner-only")
        raw = source.read(513)
    if not raw or len(raw) > 512:
        raise ValueError("bounded original recovery source required")
    campaign._retain_private(intent, "source", io.BytesIO(raw))
    return recovery_source(campaign, actor)


def _save(campaign, prefix, payload):
    public_payload(payload)
    number = campaign.db.execute("SELECT count(*) FROM result WHERE id LIKE ?", (prefix + "-%",)).fetchone()[0]
    campaign.db.execute("INSERT INTO result VALUES (?,?,?)", (f"{prefix}-{number}", time.time(), canonical(payload)))
    return payload


def _freeze(campaign, actor):
    row = campaign.db.execute("SELECT value FROM meta WHERE key=?", ("s02_absent:" + actor,)).fetchone()
    if not row:
        raise ValueError("S02 frozen absent cohort required")
    return json.loads(row[0])


def begin_absence(campaign, actor: str, snapshot_intent: str, registration_intent: str) -> dict:
    """Explicit lifecycle action, ONLY after the deployed payout path is operational.

    Root owns that operational handoff; this command has no synthetic readiness
    switch. Capture signed receipts while active, then atomically fence opens.
    """
    campaign.actor_path(actor)
    old = campaign.db.execute("SELECT value FROM meta WHERE key=?", ("s02_absent:" + actor,)).fetchone()
    if old:
        return json.loads(old[0])
    rows = []
    for intent, operation in ((snapshot_intent, {"vtxos", "sync_vtxos"}),
                              (registration_intent, {"fallback_record"})):
        row = campaign.db.execute("SELECT * FROM action WHERE id=?", (intent,)).fetchone()
        if not row or row["actor"] != actor or row["state"] != "acknowledged" or row["operation"] not in operation:
            raise ValueError("acknowledged original actor snapshot and registration required")
        rows.append(row)
    snapshot, registration = rows
    observed_coins = json.loads(snapshot["reply"])
    coins = [coin for coin in observed_coins if coin["state"] == "spendable"]
    if not coins or any(coin["state"] not in {"spendable", "spent"} for coin in observed_coins):
        raise ValueError("all frozen coins must be native spendable, with no unresolved operation")
    public_record = json.loads(registration["reply"])
    destination = campaign.core.call("validateaddress", public_record["payout_address"])
    if destination.get("isvalid") is not True or destination.get("scriptPubKey") != public_record["record"]["spk"]:
        raise ValueError("registered payout script mismatch")
    proofs = [verify_coin(campaign, actor, coin) for coin in coins]
    if any(proof.get("status") != "PASS" or not proof.get("path_outpoints") for proof in proofs):
        raise ValueError("native signature and full signed path receipts required before absence")
    from .signet_checks import confirmed_backing
    confirmed_backing(campaign.core, [coins])
    chain = network_identity(campaign.core)
    if any(coin["expiry_height"] <= chain["height"] for coin in coins):
        raise ValueError("capture absence before the original coins expire")
    _backup_recovery_source(campaign, actor)
    frozen = {"kind": "S02_absent_cohort", "actor": actor, "snapshot_intent": snapshot_intent,
              "registration_intent": registration_intent, "registration": public_record,
              "coins": coins, "signature_proofs": proofs, "chain": chain,
              "case_verdict": "INCOMPLETE", "stage": "ABSENT_WAITING_FOR_REAL_EXPIRY"}
    public_payload(frozen)
    campaign.db.execute("BEGIN IMMEDIATE")
    try:
        # Raw receipt retrieval is allowed after the snapshot; any new wallet
        # mutation/sync could change this cohort and invalidates its checkpoint.
        changed = campaign.db.execute("""SELECT 1 FROM action WHERE actor=? AND created>=?
            AND id!=? AND operation NOT IN ('raw_vtxo','fallback_record','address','onchain_address','vtxos','balance','ark_info')""",
                                       (actor, snapshot["updated"], snapshot_intent)).fetchone()
        unknown = campaign.db.execute("SELECT 1 FROM action WHERE actor=? AND state IN ('dispatched','unknown')", (actor,)).fetchone()
        if changed or unknown:
            raise ValueError("actor changed or has unresolved work after the frozen snapshot")
        campaign.db.execute("INSERT OR IGNORE INTO actor(id) VALUES (?)", (actor,))
        if campaign.db.execute("SELECT absent FROM actor WHERE id=?", (actor,)).fetchone()[0]:
            raise ValueError("actor was already absent without a frozen cohort")
        campaign.db.execute("UPDATE actor SET absent=1 WHERE id=?", (actor,))
        campaign.db.execute("INSERT INTO meta VALUES (?,?)", ("s02_absent:" + actor, canonical(frozen)))
        campaign.db.execute("INSERT INTO result VALUES (?,?,?)", ("s02-absence-" + actor, time.time(), canonical(frozen)))
        campaign.db.execute("COMMIT")
    except BaseException:
        if campaign.db.in_transaction:
            campaign.db.execute("ROLLBACK")
        raise
    return frozen


def _confirmed_transaction(campaign, txid, chain):
    if not isinstance(txid, str) or not re.fullmatch(r"[0-9a-f]{64}", txid):
        raise ValueError("observed transaction ID required")
    transaction = campaign.core.call("getrawtransaction", txid, True)
    if transaction["txid"] != txid:
        raise ValueError("Core returned another transaction")
    confirmations = integer(transaction.get("confirmations", 0), "confirmations")
    if confirmations < 1:
        raise ValueError("transaction has not confirmed on the current chain")
    height = chain["height"] - confirmations + 1
    if height < 0 or campaign.core.call("getblockhash", height) != transaction.get("blockhash"):
        raise ValueError("transaction is not in the current canonical chain")
    return transaction, height


def observe_payout(campaign, actor: str, txid: str, index: int, coin_ids: list[str]) -> dict:
    """Check one actual payout, allowing isolated outputs at a shared expiry."""
    frozen = _freeze(campaign, actor)
    integer(index, "payout output index")
    if not coin_ids or len(set(coin_ids)) != len(coin_ids):
        raise ValueError("distinct allocated coin IDs required")
    selected = [coin for coin in frozen["coins"] if coin["id"] in coin_ids]
    if len(selected) != len(coin_ids) or len({coin["expiry_height"] for coin in selected}) != 1:
        raise ValueError("payout allocation must contain known coins at one expiry height")
    amount = sum(coin["amount_sat"] for coin in selected) - 1000
    # This lifecycle deliberately funds non-dust examples. Dust-class policy is
    # exercised by product tests, not credited by a missing on-chain output.
    if amount < 294:
        raise ValueError("S02 requires a non-dust registered P2WPKH payout")
    result = {"kind": "S02_payout_observation", "actor": actor, "outpoint": f"{txid}:{index}",
              "coin_ids": sorted(coin_ids), "expected_amount_sat": amount,
              "payout_fee_sat": 1000, "case_verdict": "INCOMPLETE", "payout_check": "INCOMPLETE"}
    try:
        chain = network_identity(campaign.core)
        transaction, height = _confirmed_transaction(campaign, txid, chain)
        if height < selected[0]["expiry_height"]:
            raise ValueError("payout confirmed before the frozen coins expired")
        outputs = transaction["vout"]
        output = next((out for out in outputs if out["n"] == index), None)
        script = frozen["registration"]["record"]["spk"]
        if (not output or output["scriptPubKey"]["hex"] != script
                or btc_to_sat(output["value"]) != amount
                or sum(out["scriptPubKey"]["hex"] == script for out in outputs) != 1):
            raise ValueError("payout script, exact amount or single-output grouping differs")
        inputs = {item["txid"] + ":" + str(item["vout"]) for item in transaction["vin"]}
        input_value = 0
        for item in transaction["vin"]:
            previous, previous_height = _confirmed_transaction(campaign, item["txid"], chain)
            if previous_height >= height:
                raise ValueError("payout input was not confirmed before the payout block")
            previous_output = next(out for out in previous["vout"] if out["n"] == item["vout"])
            input_value += btc_to_sat(previous_output["value"])
        if transaction.get("version") != 3 or input_value != sum(btc_to_sat(out["value"]) for out in outputs):
            raise ValueError("payout must use the selected version-3 zero-fee shape")
        matches = {}
        for proof in frozen["signature_proofs"]:
            if proof["coin_id"] in coin_ids:
                covered = inputs.intersection(proof["path_outpoints"])
                if len(covered) != 1:
                    raise ValueError("payout does not consume exactly one signed path output for each coin")
                matches[proof["coin_id"]] = next(iter(covered))
        if len(matches) != len(coin_ids):
            raise ValueError("missing signed coin path")
        # No allocator, owner table or native 'paid' flag is trusted here.
        if network_identity(campaign.core) != chain:
            raise ValueError("chain changed during payout observation")
        result.update({"payout_check": "PASS", "chain": chain, "confirmation_height": height,
                       "confirmations": transaction["confirmations"], "signed_path_inputs": matches,
                       "script": script, "amount_sat": amount, "parent_miner_fee_sat": 0,
                       "scope": "Independent signed-path, registered payee, allocation and canonical transaction check; recovery still required."})
    except ValueError as error:
        result["reason"] = str(error)
    return _save(campaign, "s02-payout-" + actor, result)


def check_recovery(campaign, actor: str, restored_actor: str, spend_intent: str,
                   payout_observation_id: str, expected_destination: str) -> dict:
    """Require a confirmed native restored-wallet spend of the exact payout."""
    frozen = _freeze(campaign, actor)
    if restored_actor == actor:
        raise ValueError("recovery must use a separate wallet directory")
    payout_row = campaign.db.execute("SELECT payload FROM result WHERE id=?", (payout_observation_id,)).fetchone()
    payout = json.loads(payout_row[0]) if payout_row else {}
    action = campaign.db.execute("SELECT * FROM action WHERE id=?", (spend_intent,)).fetchone()
    restore = campaign.db.execute("""SELECT * FROM action WHERE actor=? AND operation='restore'
        AND state='acknowledged' ORDER BY created LIMIT 1""", (restored_actor,)).fetchone()
    if (payout.get("payout_check") != "PASS" or payout.get("actor") != actor
            or not action or action["actor"] != restored_actor or action["operation"] != "onchain_drain"
            or action["state"] != "acknowledged" or not restore
            or json.loads(restore["arguments"]).get("source_actor") != actor
            or json.loads(action["arguments"]).get("destination") != expected_destination):
        raise ValueError("original payout and separate native recovery/drain receipts required")
    result = {"kind": "S02_recovery_observation", "actor": actor, "restored_actor": restored_actor,
              "payout_observation": payout_observation_id, "spend_intent": spend_intent,
              "case_verdict": "INCOMPLETE", "recovery_check": "INCOMPLETE"}
    try:
        chain = network_identity(campaign.core)
        payout_txid, index = payout["outpoint"].split(":")
        payout_tx, _ = _confirmed_transaction(campaign, payout_txid, chain)
        original = next(out for out in payout_tx["vout"] if out["n"] == int(index))
        if original["scriptPubKey"]["hex"] != frozen["registration"]["record"]["spk"] or btc_to_sat(original["value"]) != payout["amount_sat"]:
            raise ValueError("payout changed since its earlier observation")
        spend_txid = json.loads(action["reply"])["txid"]
        spend, height = _confirmed_transaction(campaign, spend_txid, chain)
        inputs = [item["txid"] + ":" + str(item["vout"]) for item in spend["vin"]]
        if payout["outpoint"] not in inputs:
            raise ValueError("restored-wallet spend does not consume the actual fallback payout")
        destination = campaign.core.call("validateaddress", expected_destination)
        if destination.get("isvalid") is not True or len(spend["vout"]) != 1 or spend["vout"][0]["scriptPubKey"]["hex"] != destination.get("scriptPubKey"):
            raise ValueError("recovery drain destination differs from the requested destination")
        total = 0
        other = []
        for item, point in zip(spend["vin"], inputs):
            previous = campaign.core.call("getrawtransaction", item["txid"], True)
            value = next(out for out in previous["vout"] if out["n"] == item["vout"])
            value_sat = btc_to_sat(value["value"])
            total += value_sat
            if point != payout["outpoint"]:
                other.append({"outpoint": point, "amount_sat": value_sat})
        delivered = btc_to_sat(spend["vout"][0]["value"])
        if delivered <= 0 or delivered > total:
            raise ValueError("invalid confirmed recovery value or fee")
        if network_identity(campaign.core) != chain:
            raise ValueError("chain changed during recovery observation")
        result.update({"recovery_check": "PASS", "chain": chain, "confirmation_height": height,
                       "spend_txid": spend_txid, "consumed_payout_outpoint": payout["outpoint"],
                       "recovered_payout_sat": payout["amount_sat"], "other_inputs": other,
                       "delivered_sat": delivered, "miner_fee_sat": total - delivered,
                       "scope": "One payout recovered through a separate restored wallet and confirmed spend; other frozen coins may remain pending."})
    except ValueError as error:
        result["reason"] = str(error)
    return _save(campaign, "s02-recovery-" + actor, result)

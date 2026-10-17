"""Static native signature verification, bound to independent Core evidence."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

from .model import canonical, public_payload
from .signet import digest, network_identity
from .signet_checks import ChainObservationChanged


def verify_coin(campaign, actor: str, coin: dict, *, expected_address: str | None = None) -> dict:
    token = hashlib.sha256((actor + ":" + coin["id"]).encode()).hexdigest()
    raw_intent = "coin-raw-" + token
    if expected_address is not None and not re.fullmatch(r"tark1[0-9a-z]+", expected_address):
        raise ValueError("expected native testnet Ark address required")
    context = token + ":" + (expected_address or "")
    proof_prefix = "coin-proof-" + hashlib.sha256(context.encode()).hexdigest()
    previous = campaign.db.execute("""SELECT payload FROM result WHERE id LIKE ?
        AND json_extract(payload,'$.status') IN ('PASS','FAILED') ORDER BY observed DESC LIMIT 1""",
                                   (proof_prefix + "-%",)).fetchone()
    cached = None
    if previous:
        cached = json.loads(previous[0])
        if cached["status"] == "PASS" and any(cached["verified_coin"][field] != coin[field]
                                              for field in cached["verified_coin"]):
            raise ValueError("cached signed coin differs from current observation")
    attempt = campaign.db.execute("SELECT count(*) FROM result WHERE id LIKE ?", (proof_prefix + "-%",)).fetchone()[0]
    proof_id = f"{proof_prefix}-{attempt}"
    # This operation opens only the declared active wallet. If the raw receipt
    # was captured earlier, execute returns it without reopening an absent user.
    raw = campaign.execute(raw_intent, actor, "raw_vtxo", {"coin_id": coin["id"]})
    if raw["state"] != "acknowledged":
        return {"kind": "vtxo_signature_proof", "coin_id": coin["id"],
                "status": "UNAVAILABLE", "reason": "raw native receipt unresolved"}
    receipt = campaign.db.execute("SELECT * FROM native_artifact WHERE intent=? AND kind='stdout'", (raw_intent,)).fetchone()
    if not receipt or receipt["truncated"]:
        raise ValueError("complete private serialized coin artifact required")
    path = campaign.root / receipt["relative_path"]
    encoded = path.read_bytes()
    if hashlib.sha256(encoded).hexdigest() != receipt["sha256"]:
        raise ValueError("serialized coin artifact changed")
    serialized = encoded.decode().strip()
    declared = json.loads(raw["reply"])
    if (hashlib.sha256(bytes.fromhex(serialized)).hexdigest() != declared["serialized_sha256"]
            or len(bytes.fromhex(serialized)) != declared["serialized_bytes"]):
        raise ValueError("serialized coin does not match original public receipt")
    if cached is not None:
        return cached
    result = {"kind": "vtxo_signature_proof", "actor": actor, "coin_id": coin["id"],
              "raw_intent": raw_intent, "binary_sha256": campaign.config["binary_sha256"],
              "source_commit": campaign.config["source_commit"], "status": "UNAVAILABLE",
              "expected_address": expected_address}
    try:
        chain = network_identity(campaign.core)
        txid, index = coin["chain_anchor"].split(":")
        output = campaign.core.call("gettxout", txid, int(index), True)
        if not output or output["confirmations"] < 1:
            raise ValueError("confirmed unspent backing required at the observed tip")
        if output["bestblock"] != chain["hash"]:
            raise ChainObservationChanged("chain changed during signature observation")
        funding = campaign.core.call("getrawtransaction", txid, False)
        if not isinstance(funding, str) or not re.fullmatch(r"(?:[0-9a-f]{2})+", funding):
            raise ValueError("raw funding transaction required from independent Core")
        if digest(Path(campaign.config["binary"])) != campaign.config["binary_sha256"]:
            raise ValueError("native executable changed")
        environment = {key: value for key, value in os.environ.items() if not key.startswith("BARK_")}
        with tempfile.TemporaryFile(dir=campaign.root) as stdout, tempfile.TemporaryFile(dir=campaign.root) as stderr:
            try:
                process = subprocess.run([
                    campaign.config["binary"], "--quiet", "--no-logfile", "dev", "vtxo", "verify",
                    serialized, funding, *(["--address", expected_address] if expected_address is not None else []),
                ], stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                    env=environment, timeout=60, check=False)
            finally:
                campaign._retain_private(proof_id, "stdout", stdout)
                campaign._retain_private(proof_id, "stderr", stderr)
            stdout.seek(0)
            response = stdout.read(4 * 1024 * 1024 + 1)
        if process.returncode:
            result.update({"status": "FAILED", "reason": "native signature verifier rejected coin",
                           "native_exit_code": process.returncode})
        else:
            if len(response) > 4 * 1024 * 1024:
                raise ValueError("native proof response too large")
            verified = json.loads(response)
            if verified.get("verified") is not True or verified.get("anchor_txid") != txid:
                raise ValueError("native verification identity mismatch")
            if expected_address is not None and verified.get("address_verified") is not True:
                raise ValueError("signed coin is not bound to the original destination")
            fields = ("id", "amount_sat", "user_pubkey", "chain_anchor", "expiry_height")
            if any(verified["vtxo"][field] != coin[field] for field in fields):
                raise ValueError("verified signed coin differs from native wallet observation")
            if network_identity(campaign.core) != chain:
                raise ChainObservationChanged("chain changed during signature observation")
            if "path_outpoints" in verified:
                path = verified["path_outpoints"]
                if (not isinstance(path, list) or not path or len(path) > 10000
                        or any(not isinstance(point, str) or not re.fullmatch(r"[0-9a-f]{64}:[0-9]+", point)
                               for point in path)
                        or len(path) != len(set(path))
                        or path[0] != coin["chain_anchor"] or path[-1] != coin["id"]):
                    raise ValueError("native signed path does not bind the coin and backing")
                result["path_outpoints"] = path
            result.update({"status": "PASS", "verified_coin": {key: coin[key] for key in fields},
                           "chain": chain, "anchor_confirmations": output["confirmations"]})
    except ChainObservationChanged:
        result.update({"diagnostic": "ChainObservationChanged", "retryable_chain_observation": True})
    except Exception as error:
        # Native stderr stays protected; Core/Rust errors may contain secrets.
        result["diagnostic"] = type(error).__name__
    public_payload(result)
    campaign.db.execute("INSERT INTO result VALUES (?,?,?)", (proof_id, time.time(), canonical(result)))
    return result

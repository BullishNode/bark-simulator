"""Prepare genuine independent wallets for a bounded public-Signet load phase."""
from __future__ import annotations

import json
import argparse
from pathlib import Path
import time
import math
import os
import threading
import hashlib
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed

from .model import btc_to_sat, canonical, integer
from .signet import measure, network_identity
from .signet_checks import ChainObservationChanged, confirmed_backing
from .signet_proof import verify_coin


def funding_batches(actors):
    """Bound recipient count; root still preflights each real signed PSBT fee."""
    pending = [row for row in actors if integer(row["amount_sat"], "requested actor principal")]
    return [{"batch_id": f"load-funding-{offset // 90:03d}",
             "actors": [row["actor"] for row in pending[offset:offset + 90]],
             "principal_sat": sum(row["amount_sat"] for row in pending[offset:offset + 90]),
             "maximum_miner_fee_sat": 10000}
            for offset in range(0, len(pending), 90)]


def _retry_observation(campaign, prefix, operation, *, retry_permitted=True):
    count = campaign.db.execute("SELECT count(*) FROM result WHERE id LIKE ?", (prefix + "-retry-%",)).fetchone()[0]
    campaign.db.execute("INSERT INTO result VALUES (?,?,?)", (
        prefix + f"-retry-{count}", time.time(), canonical({"kind": "load_observation_retry",
        "operation": operation, "reason": "ChainObservationChanged",
        "retry_permitted": retry_permitted,
        "scope": "Retained drift observation; any new read preserves the original money action."})))


def _observed_backing(campaign, snapshots, prefix, deadline=None):
    deadline = time.monotonic() + 60 if deadline is None else deadline
    while True:
        try:
            return confirmed_backing(campaign.core, snapshots)
        except ChainObservationChanged:
            remaining = deadline - time.monotonic()
            _retry_observation(campaign, prefix, "confirmed_backing", retry_permitted=remaining > 0)
            if remaining <= 0:
                raise
            time.sleep(min(1, remaining))
            if time.monotonic() >= deadline:
                raise ChainObservationChanged("chain observation retry budget exhausted")


def _verified_coin(campaign, actor, coin, *, expected_address=None, deadline=None):
    deadline = time.monotonic() + 60 if deadline is None else deadline
    token = hashlib.sha256((actor + coin["id"] + (expected_address or "")).encode()).hexdigest()
    while True:
        proof = verify_coin(campaign, actor, coin, expected_address=expected_address)
        if (proof.get("status") != "UNAVAILABLE" or proof.get("diagnostic") != "ChainObservationChanged"
                or proof.get("retryable_chain_observation") is not True):
            return proof
        remaining = deadline - time.monotonic()
        _retry_observation(campaign, "load-signature-" + token, "verify_coin", retry_permitted=remaining > 0)
        if remaining <= 0:
            return proof
        time.sleep(min(1, remaining))
        if time.monotonic() >= deadline:
            return proof


class Load:
    def __init__(self, campaign, *, wallets=12, concurrency=3, transfers=60,
                 transfer_sat=1000, batch_interval_seconds=10,
                 funding_sat_per_actor=100000, window_seconds=None):
        integer(wallets, "wallet count")
        integer(concurrency, "bounded concurrency", 1)
        bounds = {12: (5, 1000), 50: (5, 1000), 200: (10, 1800), 500: (20, 7200)}
        if wallets not in bounds or concurrency > min(bounds[wallets][0], wallets // 2):
            raise ValueError("declared 12/50/200/500 cohort and disjoint concurrency bound required")
        if integer(funding_sat_per_actor, "actor funding") not in {40000, 100000}:
            raise ValueError("explicit 40000 or legacy 100000 actor allocation required")
        self.campaign = campaign
        self.parameters = {"wallets": wallets, "concurrency": concurrency,
                           "transfers": integer(transfers, "transfer count", 1),
                           "transfer_sat": integer(transfer_sat, "transfer amount", 1),
                           "batch_interval_seconds": integer(batch_interval_seconds, "batch interval", 1),
                           "funding_sat_per_actor": funding_sat_per_actor, "board_sat_per_actor": 30000,
                           "maximum_offchain_fee_sat": 1000,
                           "wallet_profile": {"vtxo_refresh_expiry_threshold": 144,
                                              "vtxo_exit_margin": 12, "fallback_fee_rate": 750}}
        if transfers > bounds[wallets][1] or transfer_sat > 5000 or batch_interval_seconds < 5:
            raise ValueError("load phase exceeds the declared bounded test workload")
        if window_seconds is not None:
            integer(window_seconds, "maximum workload window", 1)
            if not math.ceil(transfers / concurrency) * batch_interval_seconds <= window_seconds <= 7200:
                raise ValueError("window must contain the offered schedule and stay within two hours")
            self.parameters["window_seconds"] = window_seconds
        encoded = canonical(self.parameters)
        campaign.db.execute("INSERT OR IGNORE INTO meta VALUES ('load_parameters',?)", (encoded,))
        if campaign.db.execute("SELECT value FROM meta WHERE key='load_parameters'").fetchone()[0] != encoded:
            raise ValueError("load phase parameters are immutable")
        self.actors = [f"load-{number:03d}" for number in range(wallets)]

    def native(self, intent, actor, operation, args=None):
        row = self.campaign.execute(intent, actor, operation, args or {})
        if row["state"] != "acknowledged":
            raise ValueError("original load native outcome requires reconciliation: " + intent)
        return json.loads(row["reply"])

    def prepare(self):
        """No board or payment; return the actual native funding-address packet."""
        c = self.campaign
        if c.db.execute("SELECT 1 FROM meta WHERE key='load_import_pending'").fetchone() and not c.db.execute(
                "SELECT 1 FROM meta WHERE key='load_import_complete'").fetchone():
            raise ValueError("partial existing-wallet import requires reconciliation")
        if c.db.execute("SELECT 1 FROM meta WHERE key='load_hold'").fetchone():
            raise ValueError("load phase is held for original-outcome reconciliation")
        if c.db.execute("SELECT 1 FROM action WHERE state IN ('unknown','dispatched')").fetchone():
            raise ValueError("load phase has an original unresolved action")
        actors = []
        for actor in self.actors:
            imported = c.db.execute("SELECT value FROM meta WHERE key=?", ("load_existing:" + actor,)).fetchone()
            if imported:
                imported = json.loads(imported[0])
            else:
                self.native(actor + "-create", actor, "create", {"wallet_profile": self.parameters["wallet_profile"]})
            address = self.native(actor + "-funding-address", actor, "onchain_address")["address"]
            registration = self.native(actor + "-registration", actor, "fallback_record")
            if imported and registration != imported["registration"]:
                raise ValueError("existing authenticated registration changed during load handoff")
            self.native(actor + "-ark-address", actor, "address")
            funding = c.core.call("validateaddress", address)
            payout = c.core.call("validateaddress", registration["payout_address"])
            if (funding.get("isvalid") is not True or payout.get("isvalid") is not True
                    or payout.get("scriptPubKey") != registration["record"]["spk"]
                    or address == registration["payout_address"]):
                raise ValueError("genuine native funding and reserved payout destinations required")
            created = c.db.execute("SELECT chain FROM action WHERE id=?", (actor + "-create",)).fetchone()
            actors.append({"actor": actor, "address": address, "amount_sat": 0 if imported else self.parameters["funding_sat_per_actor"],
                           "existing_native_inventory": imported is not None,
                           "original_pre_create_height": imported["original_pre_create_height"] if imported else json.loads(created[0])["height"],
                           "funding_address_intent": actor + "-funding-address",
                           "registration_intent": actor + "-registration"})
        if len({actor["address"] for actor in actors}) != len(actors):
            raise ValueError("load funding addresses must be distinct")
        target = self.native("load-native-target-info", self.actors[0], "ark_info")
        if (target["network"] != "signet" or target["vtxo_lifetime"] != 4320
                or target["vtxo_exit_delta"] != 144
                or target["required_board_confirmations"] != 3
                or target["min_board_amount_sat"] > 30000):
            raise ValueError("actual long-profile native target differs")
        previous = c.db.execute("SELECT value FROM meta WHERE key='load_import_complete'").fetchone()
        if previous and target["server_pubkey"] != json.loads(previous[0])["server_pubkey"]:
            raise ValueError("existing wallets cannot move to a different server identity")
        return {"kind": "load_funding_request", "stage": "PREPARED_UNFUNDED",
                "product_source": c.config["source_commit"], "binary_sha256": c.config["binary_sha256"],
                "product_config_sha256": c.config["product_config_sha256"],
                "parameters": self.parameters, "chain": network_identity(c.core), "target": target,
                "actors": actors, "total_actor_principal_sat": sum(v["amount_sat"] for v in actors),
                "funding_batches": funding_batches(actors),
                "fee_proposal": {"treasury_batch_sat_per_vb": 3, "treasury_batch_maximum_miner_fee_sat": 10000,
                                 "native_wallet_fallback_sat_per_kwu": 750,
                                 "native_wallet_fallback_sat_per_vb": 3,
                                 "note": "Fallback is used only if native fee estimation fails; actual board fees must be measured."},
                "money_dispatched": False,
                "scope": "Real native wallet/address/authenticated registration preparation; no load performance or successful board claim."}

    def admit(self):
        """Board each genuinely funded actor once, then prove the actual cohort."""
        c = self.campaign
        if c.db.execute("SELECT 1 FROM meta WHERE key='load_hold'").fetchone():
            raise ValueError("load phase is held for original-outcome reconciliation")
        if c.db.execute("SELECT 1 FROM action WHERE state IN ('unknown','dispatched')").fetchone():
            raise ValueError("original load action requires reconciliation")
        old = c.db.execute("SELECT value FROM meta WHERE key='load_admitted'").fetchone()
        if old:
            return json.loads(old[0])
        for actor in self.actors:
            imported = c.db.execute("SELECT 1 FROM meta WHERE key=?", ("load_existing:" + actor,)).fetchone()
            if c.db.execute("SELECT count(*) FROM action WHERE actor=? AND state='acknowledged' AND operation IN ('create','onchain_address','fallback_record','address')", (actor,)).fetchone()[0] != (3 if imported else 4):
                raise ValueError("genuine completed load wallet preparation required")
        reused = {actor: json.loads(row[0]) for actor in self.actors if (row := c.db.execute(
            "SELECT value FROM meta WHERE key=?", ("load_existing:" + actor,)).fetchone())}
        funded = [json.loads(row[0]) for row in c.db.execute(
            "SELECT payload FROM result WHERE json_extract(payload,'$.kind')='external_funding'")]
        if any(v["actor"] not in self.actors for v in funded):
            raise ValueError("funding receipt lies outside the declared cohort")
        if any(sum(v["amount_sat"] for v in funded if v["actor"] == actor) != (0 if actor in reused else self.parameters["funding_sat_per_actor"]) for actor in self.actors):
            return {"stage": "WAITING_FOR_EXACT_CONFIRMED_ACTOR_FUNDING", "money_dispatched": False}
        points = [v["outpoint"] for v in funded]
        if len(points) != len(set(points)):
            raise ValueError("funding outpoint assigned more than once")
        boards, costs = {}, {}
        for actor in self.actors:
            if actor in reused:
                continue
            row = c.db.execute("SELECT state FROM action WHERE id=?", (actor + "-board",)).fetchone()
            if row is None:
                try:
                    self.preflight_actor(actor, [v for v in funded if v["actor"] == actor])
                except ChainObservationChanged:
                    _retry_observation(c, "load-admit-funding-" + actor, "funding_inventory")
                    return {"stage": "WAITING_FOR_COHORT_CHAIN_OBSERVATION", "actor": actor,
                            "scope": "Funding read crossed a tip; no new board for this actor was dispatched."}
            boards[actor] = self.native(actor + "-board", actor, "board", {"amount_sat": 30000})
            costs[actor] = self.board_cost(actor, boards[actor]["funding_txid"])
        chain = network_identity(c.core)
        snapshots, intents = [], {}
        for actor in self.actors:
            intent = f"load-admit-{chain['height']}-{actor}"
            coins = self.native(intent, actor, "sync_vtxos")
            if actor in reused and sorted(coins, key=lambda v: v["id"]) != reused[actor]["coins"]:
                raise ValueError("existing native coin inventory changed during load handoff")
            if (any(coin["state"] not in {"spent", "spendable"} for coin in coins)
                    or (actor not in reused and sum(coin["amount_sat"] for coin in coins if coin["state"] == "spendable") != boards[actor]["amount_sat"])):
                return {"stage": "WAITING_FOR_GENUINE_NATIVE_BOARD_ADMISSION", "actor": actor,
                        "height": chain["height"], "snapshot_intent": intent}
            snapshots.append(coins)
            intents[actor] = intent
        proofs = [_verified_coin(c, actor, coin) for actor, coins in zip(self.actors, snapshots)
                  for coin in coins if coin["state"] == "spendable"]
        owned_ids = [coin["id"] for coins in snapshots for coin in coins if coin["state"] == "spendable"]
        if len(owned_ids) != len(set(owned_ids)):
            raise ValueError("same spendable coin attributed to multiple load actors")
        if not proofs or any(proof["status"] != "PASS" for proof in proofs):
            raise ValueError("actual native load signature proof unavailable")
        backing = _observed_backing(c, snapshots, "load-admit-backing")
        if network_identity(c.core) != chain:
            _retry_observation(c, "load-admit-tip", "cohort_admission")
            return {"stage": "WAITING_FOR_COHORT_CHAIN_OBSERVATION",
                    "scope": "Retain original board ACKs; observe the cohort again without replaying them."}
        admitted = {"stage": "LOAD_NATIVE_COHORT_ADMITTED", "chain": chain,
                    "snapshots": intents, "signature_proofs": proofs, "backing": backing,
                    "board_costs": costs,
                    "reused_actors": sorted(reused),
                    "opening_coin_sat": sum(coin["amount_sat"] for coins in snapshots for coin in coins if coin["state"] == "spendable")}
        c.db.execute("INSERT INTO meta VALUES ('load_admitted',?)", (canonical(admitted),))
        return admitted

    def preflight_actor(self, actor, funding):
        """Verify actual native-owned, confirmed inventory; this is not a fee quote."""
        c = self.campaign
        chain = network_identity(c.core)
        expected = {v["outpoint"]: v for v in funding}
        if not expected or len(expected) != len(funding):
            raise ValueError("distinct exact actor funding inventory required")
        address = json.loads(c.db.execute("SELECT reply FROM action WHERE id=?",
                                         (actor + "-funding-address",)).fetchone()[0])["address"]
        script = c.core.call("validateaddress", address)
        if script.get("isvalid") is not True or not script.get("scriptPubKey"):
            raise ValueError("actual native funding script required")
        native = self.native(f"load-funding-inventory-{chain['height']}-{actor}", actor, "onchain_utxos")
        if {v["outpoint"] for v in native} != set(expected):
            raise ValueError("native wallet inventory differs from the allocated funding; no board dispatched")
        total = 0
        for point, receipt in expected.items():
            txid, index = point.split(":")
            output = c.core.call("gettxout", txid, int(index), True)
            owned = next(v for v in native if v["outpoint"] == point)
            if (not output or output.get("confirmations", 0) < 1
                    or output["scriptPubKey"]["hex"] != script["scriptPubKey"]
                    or btc_to_sat(output["value"]) != receipt["amount_sat"]
                    or owned["amount_sat"] != receipt["amount_sat"] or owned["confirmation_height"] is None):
                raise ValueError("allocated native funding is spent, unconfirmed, misdirected or has different value")
            if output.get("bestblock") != chain["hash"]:
                raise ChainObservationChanged("chain changed during funding inventory preflight")
            total += receipt["amount_sat"]
        if total != self.parameters["funding_sat_per_actor"] or total <= self.parameters["board_sat_per_actor"]:
            raise ValueError("declared actor allocation and board fee headroom required")
        if network_identity(c.core) != chain:
            raise ChainObservationChanged("chain changed during funding inventory preflight")
        result = {"kind": "load_actor_funding_preflight", "actor": actor, "chain": chain,
                  "outpoints": sorted(expected), "allocated_sat": total,
                  "board_principal_sat": self.parameters["board_sat_per_actor"],
                  "combined_fee_and_reserve_capacity_sat": total - self.parameters["board_sat_per_actor"],
                  "fee_quote_available": False,
                  "scope": "Actual confirmed native inventory bound; no promised fee or minimum change reserve."}
        c.db.execute("INSERT OR IGNORE INTO result VALUES (?,?,?)", (
            f"load-funding-preflight-{chain['height']}-{actor}", time.time(), canonical(result)))
        return result

    def board_cost(self, actor, txid):
        """Measure the original acknowledged transaction, never repeat a board."""
        c = self.campaign
        tx = c.core.call("getrawtransaction", txid, True)
        if tx.get("txid") != txid:
            raise ValueError("original board transaction differs")
        expected = {json.loads(row[0])["outpoint"] for row in c.db.execute(
            "SELECT payload FROM result WHERE json_extract(payload,'$.kind')='external_funding' "
            "AND json_extract(payload,'$.actor')=?", (actor,))}
        inputs = [f"{v['txid']}:{v['vout']}" for v in tx["vin"]]
        if len(inputs) != len(set(inputs)) or set(inputs) != expected:
            raise ValueError("original board consumed inventory outside its exact allocation")
        total = 0
        for v in tx["vin"]:
            parent = c.core.call("getrawtransaction", v["txid"], True)
            if parent.get("txid") != v["txid"]:
                raise ValueError("board parent transaction differs")
            total += btc_to_sat(next(out["value"] for out in parent["vout"] if out["n"] == v["vout"]))
        output_sat = sum(btc_to_sat(v["value"]) for v in tx["vout"])
        fee = total - output_sat
        if (total != self.parameters["funding_sat_per_actor"] or fee < 0
                or not any(btc_to_sat(v["value"]) == self.parameters["board_sat_per_actor"] for v in tx["vout"])):
            raise ValueError("actual board allocation or miner-fee conservation differs")
        reserve = total - fee - self.parameters["board_sat_per_actor"]
        if reserve < 0:
            raise ValueError("board principal exceeds its actual funded inventory")
        result = {"kind": "load_board_cost", "actor": actor, "funding_txid": txid,
                  "allocated_sat": total, "board_principal_sat": self.parameters["board_sat_per_actor"],
                  "miner_fee_sat": fee, "other_outputs_sat": reserve,
                  "fee_warning_above_1000_sat": fee > 1000,
                  "scope": "Actual Core input/output fee; other outputs are not asserted wallet-owned change."}
        c.db.execute("INSERT OR IGNORE INTO result VALUES (?,?,?)", (
            "load-board-cost-" + actor, time.time(), canonical(result)))
        return result

    def _require_batch_admission(self):
        c = self.campaign
        if c.db.execute("SELECT 1 FROM meta WHERE key='load_hold'").fetchone():
            raise ValueError("load phase is held for original-outcome reconciliation")
        if c.db.execute("SELECT 1 FROM action WHERE state IN ('unknown','dispatched')").fetchone():
            raise ValueError("original load action requires reconciliation")
        if not c.db.execute("SELECT 1 FROM meta WHERE key='load_admitted'").fetchone():
            raise ValueError("actual native load cohort admission required")

    def progress(self, batch=None):
        """Bounded projection; the complete monetary/proof journal stays intact."""
        c = self.campaign
        counts = {row[0]: row[1] for row in c.db.execute(
            "SELECT state,count(*) FROM action GROUP BY state")}
        complete = c.db.execute("SELECT count(*) FROM result WHERE id LIKE 'load-transfer-%-complete'").fetchone()[0]
        hold = c.db.execute("SELECT 1 FROM meta WHERE key='load_hold'").fetchone() is not None
        result = {"kind": "load_progress", "intended_transfers": self.parameters["transfers"],
                  "successful_reconciled_transfers": complete, "action_counts": counts,
                  "held": hold, "source_commit": c.config["source_commit"],
                  "scope": "Progress only; counts and native ACKs do not qualify payment or capacity."}
        if batch is not None:
            result["latest_batch"] = {"stage": batch["stage"],
                "reconciled_count": len(batch.get("results", [])),
                "failure_count": len(batch.get("failures", [])),
                "pacing": batch.get("pacing"), "timings": {}}
            totals = result["latest_batch"]["timings"]
            for transfer in batch.get("results", []):
                for name, value in transfer.get("timings", {}).items():
                    totals[name] = totals.get(name, 0) + value
            result["latest_batch"]["timing_scope"] = (
                "Successful transfers only; worker sums overlap under concurrency. "
                "Independent-proof wall time includes nested verifier/hash/native receipt work; do not add it twice.")
        return result

    def write_observation(self, destination: Path, *, full=False, batch=None):
        """Use full at start/end, bounded progress between batches; no wallet opens."""
        started, cpu = time.perf_counter(), time.process_time()
        value = self.campaign.report() if full else self.progress(batch)
        projected = time.perf_counter()
        encoded = canonical(value).encode()
        serialized = time.perf_counter()
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as output:
                temporary = Path(output.name)
                output.write(encoded)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, destination)
            directory = os.open(destination.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        return {"kind": "load_report_cost", "full": full, "bytes": len(encoded),
                "projection_seconds": projected - started,
                "serialization_seconds": serialized - projected,
                "write_seconds": time.perf_counter() - serialized,
                "wall_seconds": time.perf_counter() - started,
                "controller_cpu_seconds": time.process_time() - cpu}

    def advance_batch(self, monitor_pids=None, *, wait_until_due=False, stop_requested=None):
        """One disjoint batch; optional pacing starts after the caller's reporting.

        The caller retains its writer lock. A waiting call rechecks the same
        admission/unknown guards before dispatch and never extends the window.
        It must replace an outer fixed sleep, not be added to one.
        """
        c = self.campaign
        self._require_batch_admission()
        completed = {row[0] for row in c.db.execute("SELECT id FROM result WHERE id LIKE 'load-transfer-%-complete'")}
        pending = [index for index in range(self.parameters["transfers"])
                   if f"load-transfer-{index:06d}-complete" not in completed]
        if not pending:
            return {"stage": "LOAD_WORKLOAD_COMPLETE", "successful_reconciled_transfers": len(completed)}
        indices = pending[:self.parameters["concurrency"]]
        pairs = [index % (len(self.actors) // 2) for index in indices]
        if len(set(pairs)) != len(pairs):
            raise ValueError("batch would overlap an active actor pair")
        last = c.db.execute("SELECT observed FROM result WHERE json_extract(payload,'$.kind')='load_batch_started' ORDER BY observed DESC LIMIT 1").fetchone()
        requested_at = now = time.time()
        not_before = last[0] + self.parameters["batch_interval_seconds"] if last else now
        while wait_until_due and now < not_before:
            if stop_requested is not None and stop_requested():
                return {"stage": "LOAD_STOP_REQUESTED", "money_dispatched": False,
                        "successful_reconciled_transfers": len(completed)}
            time.sleep(min(1, not_before - now))
            self._require_batch_admission()
            now = time.time()
        if stop_requested is not None and stop_requested():
            return {"stage": "LOAD_STOP_REQUESTED", "money_dispatched": False,
                    "successful_reconciled_transfers": len(completed)}
        if now < not_before:
            return {"stage": "WAITING_FOR_LOAD_BATCH_INTERVAL", "money_dispatched": False,
                    "next_batch_not_before": not_before,
                    "successful_reconciled_transfers": len(completed)}
        first = c.db.execute("SELECT min(observed) FROM result WHERE json_extract(payload,'$.kind')='load_batch_started'").fetchone()[0]
        window = self.parameters.get("window_seconds")
        if first is not None and window is not None and now >= first + window:
            result = {"stage": "LOAD_WINDOW_LIMIT_REACHED", "successful_reconciled_transfers": len(completed),
                      "intended_transfers": self.parameters["transfers"], "money_dispatched": False}
            c.db.execute("INSERT OR IGNORE INTO meta VALUES ('load_hold',?)", (canonical(result),))
            return result
        scheduled_at = (first + (len(completed) // self.parameters["concurrency"]) *
                        self.parameters["batch_interval_seconds"]) if first is not None else now
        pacing = {"controller_requested_at": requested_at, "scheduled_start_at": scheduled_at,
                  "minimum_interval_not_before": not_before, "actual_started_at": now,
                  "schedule_lateness_seconds": max(0, now - scheduled_at)}
        c.db.execute("INSERT OR IGNORE INTO result VALUES (?,?,?)", (
            f"load-batch-{indices[0]:06d}-started", now,
            canonical({"kind": "load_batch_started", "indices": indices, "pacing": pacing})))
        results, failures = [], []
        with RSSSamples(monitor_pids or {}) as resources, ThreadPoolExecutor(max_workers=self.parameters["concurrency"]) as workers:
            futures = {workers.submit(_transfer, c.root, c.config, self.parameters, index): index for index in indices}
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as error:
                    failures.append({"index": futures[future], "error_type": type(error).__name__, "error": str(error)})
        # All originally dispatched workers have finished; never cancel a money
        # command or schedule another batch after a failed reconciliation.
        result = {"stage": "LOAD_BATCH_HOLD" if failures else "LOAD_BATCH_RECONCILED",
                  "indices": indices, "results": sorted(results, key=lambda value: value["index"]),
                  "failures": failures, "successful_reconciled_transfers": len(completed) + len(results),
                  "pacing": pacing,
                  "resource_observation": resources.result}
        if failures:
            c.db.execute("INSERT OR IGNORE INTO meta VALUES ('load_hold',?)", (canonical(result),))
        return result

    def finish(self):
        """Fresh whole-cohort accounting after the declared bounded workload."""
        c = self.campaign
        if c.db.execute("SELECT 1 FROM meta WHERE key='load_hold'").fetchone() or c.db.execute(
                "SELECT 1 FROM action WHERE state IN ('unknown','dispatched')").fetchone():
            raise ValueError("load has an unreconciled original outcome")
        completed = [(row[0], json.loads(row[1])) for row in c.db.execute(
            "SELECT observed,payload FROM result WHERE id LIKE 'load-transfer-%-complete'")]
        if len(completed) != self.parameters["transfers"]:
            raise ValueError("declared load transfers are not all independently reconciled")
        return self._final_cohort_report(completed)

    def audit_closed_window(self):
        """Audit a known terminal window shortfall without clearing its HOLD.

        The caller must first verify the original writer exited and acquire its
        released lock. Native snapshots run normal Wallet::sync, which may
        progress existing operations; that effect requires operational admission.
        This cannot resume transfers or qualify the unfinished requested workload.
        """
        c = self.campaign
        if c.db.execute("SELECT 1 FROM action WHERE state IN ('unknown','dispatched')").fetchone():
            raise ValueError("original load action requires reconciliation")
        row = c.db.execute("SELECT value FROM meta WHERE key='load_hold'").fetchone()
        hold = json.loads(row[0]) if row else {}
        if hold.get("stage") != "LOAD_WINDOW_LIMIT_REACHED":
            raise ValueError("only a terminal dispatch-window shortfall can be audited")
        actors = list(c.db.execute("SELECT id,absent FROM actor"))
        if {row[0] for row in actors} != set(self.actors) or any(row[1] for row in actors):
            raise ValueError("exact original active load cohort required before native sync")
        if c.db.execute("SELECT 1 FROM action WHERE id LIKE 'load-final-%'").fetchone():
            raise ValueError("prior final audit observations require reconciliation; no cached retry")
        completed = [(row[0], json.loads(row[1])) for row in c.db.execute(
            "SELECT observed,payload FROM result WHERE id LIKE 'load-transfer-%-complete'")]
        acknowledged = c.db.execute("SELECT count(*) FROM action WHERE operation='send' AND state='acknowledged'").fetchone()[0]
        if (not 0 < len(completed) < self.parameters["transfers"]
                or acknowledged != len(completed)
                or hold.get("successful_reconciled_transfers") != len(completed)
                or hold.get("intended_transfers") != self.parameters["transfers"]):
            raise ValueError("every original acknowledged send must be reconciled; original shortfall stays incomplete")
        result = self._final_cohort_report(completed)
        result.update(kind="load_window_audit", stage="LOAD_INCOMPLETE_WINDOW_FINANCIALLY_AUDITED",
                      case_verdict="INCOMPLETE", workload_complete=False,
                      intended_transfers=self.parameters["transfers"],
                      not_dispatched_transfers=self.parameters["transfers"] - len(completed),
                      original_hold=hold,
                      scope="Known completed transfers independently audited; original requested workload remains incomplete and held. No resume, full-workload or production qualification.")
        return result

    def _final_cohort_report(self, completed):
        c = self.campaign
        baseline = json.loads(c.db.execute("SELECT value FROM meta WHERE key='load_admitted'").fetchone()[0])
        snapshots = [self.native("load-final-" + actor, actor, "sync_vtxos") for actor in self.actors]
        if any(coin["state"] not in {"spent", "spendable"} for coins in snapshots for coin in coins):
            raise ValueError("final native cohort is not settled")
        fees = sum(value["check"]["observed_offchain_fee_sat"] for _, value in completed)
        closing = sum(coin["amount_sat"] for coins in snapshots for coin in coins if coin["state"] == "spendable")
        owned_ids = [coin["id"] for coins in snapshots for coin in coins if coin["state"] == "spendable"]
        if len(owned_ids) != len(set(owned_ids)):
            raise ValueError("same spendable coin attributed to multiple load actors")
        if closing + fees != baseline["opening_coin_sat"]:
            raise ValueError("whole-cohort load conservation differs from isolated pair results")
        proofs = [_verified_coin(c, actor, coin) for actor, coins in zip(self.actors, snapshots)
                  for coin in coins if coin["state"] == "spendable"]
        if not proofs or any(proof["status"] != "PASS" for proof in proofs):
            raise ValueError("final load native signed path unavailable")
        backing = _observed_backing(c, snapshots, "load-final-backing")
        first = c.db.execute("SELECT min(created) FROM action WHERE operation='send' AND id LIKE 'load-transfer-%-send'").fetchone()[0]
        elapsed = max(observed for observed, _ in completed) - first
        def timing(field):
            values = sorted(value[field] for _, value in completed)
            return {"samples": len(values), "p50_seconds": values[math.ceil(len(values) * .5) - 1],
                    "p95_seconds": values[math.ceil(len(values) * .95) - 1], "maximum_seconds": max(values)}
        return {"kind": "load_workload_result", "stage": "LOAD_WORKLOAD_FINANCIALLY_RECONCILED",
                "parameters": self.parameters, "successful_reconciled_transfers": len(completed),
                "failed_or_unknown_transfers": 0, "opening_coin_sat": baseline["opening_coin_sat"],
                "closing_coin_sat": closing, "observed_offchain_fee_sat": fees,
                "native_invocation_including_open_and_journal": timing("native_ack_seconds"),
                "send_intent_through_observed_recipient_availability": timing("observed_receiver_available_seconds"),
                "send_through_financial_reconciliation": timing("reconciliation_seconds"),
                "observed_workload_wall_seconds_including_pacing_and_pauses": elapsed,
                "observed_successful_transfers_per_minute": len(completed) * 60 / elapsed if elapsed > 0 else None,
                "backing": backing, "signature_proofs": proofs,
                "scope": "Measured bounded workload under these pins and schedule, not maximum TPS or production-scale qualification."}


class RSSSamples:
    """Read-only 50ms Linux RSS sampling; these are observed, not exact peaks."""
    def __init__(self, pids):
        self.pids = {**pids, "controller": os.getpid()}
        self.stop = threading.Event()
        self.result = {"sample_interval_seconds": .05, "samples": 0,
                       "maximum_observed_rss_kib": {}, "missing_samples": {},
                       "note": "Sampled RSS; short-lived peaks can be missed. Native child RSS is summed concurrently."}

    @staticmethod
    def cpu(pid):
        try:
            # comm may contain spaces or parentheses; fields after its final ')'
            # start at state (field3), not PID.
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
            return {"start_ticks": int(fields[19]),
                    "cpu_seconds": (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")}
        except (OSError, ValueError, IndexError, ProcessLookupError):
            return None

    @staticmethod
    def rss(pid):
        try:
            for line in Path(f"/proc/{pid}/status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
        except (OSError, ProcessLookupError):
            pass
        return None

    def sample(self):
        current = {role: self.rss(pid) for role, pid in self.pids.items()}
        children = set()
        for task in Path("/proc/self/task").glob("*/children"):
            try:
                children.update(int(pid) for pid in task.read_text().split())
            except OSError:
                pass
        current["concurrent_native_children"] = sum(self.rss(pid) or 0 for pid in children)
        self.result["samples"] += 1
        for role, value in current.items():
            if value is None:
                self.result["missing_samples"][role] = self.result["missing_samples"].get(role, 0) + 1
            else:
                self.result["maximum_observed_rss_kib"][role] = max(value, self.result["maximum_observed_rss_kib"].get(role, 0))
        try:
            memory = {key: int(value.split()[0]) for key, value in (
                line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
                if key in {"MemAvailable", "SwapTotal", "SwapFree"}}
            available = memory["MemAvailable"]
            self.result["minimum_sampled_host_available_memory_kib"] = min(
                available, self.result.get("minimum_sampled_host_available_memory_kib", available))
            self.result["maximum_sampled_host_swap_used_kib"] = max(
                memory["SwapTotal"] - memory["SwapFree"], self.result.get("maximum_sampled_host_swap_used_kib", 0))
        except (OSError, ValueError, KeyError):
            self.result["host_memory_missing_samples"] = self.result.get("host_memory_missing_samples", 0) + 1

    def run(self):
        while not self.stop.wait(.05):
            self.sample()

    def __enter__(self):
        self.started = time.monotonic()
        self.cpu_before = {role: self.cpu(pid) for role, pid in self.pids.items()}
        self.times_before = os.times()
        self.sample()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *unused):
        self.stop.set()
        self.thread.join()
        self.sample()
        self.result["observed_wall_seconds"] = time.monotonic() - self.started
        self.result["process_cpu_seconds"] = {}
        self.result["cpu_identity_missing_or_changed"] = []
        for role, pid in self.pids.items():
            before, after = self.cpu_before[role], self.cpu(pid)
            if (before is None or after is None or before["start_ticks"] != after["start_ticks"]
                    or after["cpu_seconds"] < before["cpu_seconds"]):
                self.result["cpu_identity_missing_or_changed"].append(role)
            else:
                self.result["process_cpu_seconds"][role] = after["cpu_seconds"] - before["cpu_seconds"]
        times_after = os.times()
        self.result["reaped_child_cpu_seconds"] = {
            "user": times_after.children_user - self.times_before.children_user,
            "system": times_after.children_system - self.times_before.children_system,
            "scope": "All child processes reaped by this controller during the batch, including native proof commands; not send-only CPU."}


def _transfer(directory, config, parameters, index):
    from .signet import Campaign
    from .signet_phase import _verify_runtime
    c = Campaign(directory, config)
    try:
        with measure(c.timings, "runtime_verification"):
            _verify_runtime(c)
        if not c.db.execute("SELECT 1 FROM meta WHERE key='load_admitted'").fetchone():
            raise ValueError("actual native load cohort admission required")
        if integer(index, "load transfer index") >= parameters["transfers"]:
            raise ValueError("load transfer index exceeds the frozen workload")
        prefix = f"load-transfer-{index:06d}"
        done = c.db.execute("SELECT payload FROM result WHERE id=?", (prefix + "-complete",)).fetchone()
        if done:
            return json.loads(done[0])
        pair = index % (parameters["wallets"] // 2)
        sender, receiver = [f"load-{2 * pair + n:03d}" for n in [0, 1]]
        if index // (parameters["wallets"] // 2) % 2:
            sender, receiver = receiver, sender

        def native(intent, actor, operation, args=None):
            row = c.execute(intent, actor, operation, args or {})
            if row["state"] != "acknowledged":
                raise ValueError("original load native outcome requires reconciliation: " + intent)
            return json.loads(row["reply"])

        address = json.loads(c.db.execute("SELECT reply FROM action WHERE id=?", (receiver + "-ark-address",)).fetchone()[0])["address"]
        sb = native(prefix + "-sender-before", sender, "sync_vtxos")
        rb = native(prefix + "-receiver-before", receiver, "sync_vtxos")
        if (any(coin["state"] not in {"spent", "spendable"} for coin in sb + rb)
                or sum(coin["amount_sat"] for coin in sb if coin["state"] == "spendable") < parameters["transfer_sat"] + parameters["maximum_offchain_fee_sat"]):
            raise ValueError("settled native pair and bounded fee headroom required")
        with measure(c.timings, "independent_proof"):
            _observed_backing(c, [sb, rb], prefix + "-before-backing")
        if c.db.execute("SELECT 1 FROM action WHERE state='unknown'").fetchone():
            raise ValueError("another load outcome became unknown; no new send")
        native(prefix + "-send", sender, "send", {"destination": address, "amount_sat": parameters["transfer_sat"]})
        payment = c.db.execute("SELECT * FROM action WHERE id=?", (prefix + "-send",)).fetchone()
        attempt = c.db.execute("SELECT count(*) FROM result WHERE id LIKE ?", (prefix + "-check-%",)).fetchone()[0]
        deadline = time.monotonic() + 60
        while True:
            after_s, after_r = prefix + f"-sender-after-{attempt}", prefix + f"-receiver-after-{attempt}"
            sa = native(after_s, sender, "sync_vtxos")
            ra = native(after_r, receiver, "sync_vtxos")
            with measure(c.timings, "independent_proof"):
                check = c.check_transfer(prefix + f"-check-{attempt}", prefix + "-send",
                                         prefix + "-sender-before", after_s, prefix + "-receiver-before", after_r,
                                         parameters["maximum_offchain_fee_sat"])
            if check.get("arithmetic") == "PASS" and check.get("backing") == "PASS":
                with measure(c.timings, "independent_proof"):
                    proofs = [_verified_coin(c, actor, coin, expected_address=(address if actor == receiver and coin["id"] in check["new_receiver_coins"] else None), deadline=deadline)
                              for actor, snapshot in [(sender, sa), (receiver, ra)] for coin in snapshot if coin["state"] == "spendable"]
                if not proofs or any(proof["status"] != "PASS" for proof in proofs):
                    raise ValueError("load signed-path reconciliation failed")
                with measure(c.timings, "independent_proof"):
                    backing = _observed_backing(c, [sa, ra], prefix + "-after-backing", deadline=deadline)
                result = {"kind": "load_transfer_observation", "index": index, "sender": sender, "receiver": receiver,
                          "amount_sat": parameters["transfer_sat"], "status": "RECONCILED",
                          "native_ack_seconds": payment["updated"] - payment["created"],
                          "observed_receiver_available_seconds": c.db.execute("SELECT updated FROM action WHERE id=?", (after_r,)).fetchone()[0] - payment["created"],
                          "reconciliation_seconds": time.time() - payment["created"],
                          "timings": dict(c.timings),
                          "check": check, "backing": backing, "signature_proofs": proofs,
                          "scope": "Actual isolated pair send, native invocation timing and independent financial reconciliation; no claimed maximum TPS."}
                c.db.execute("INSERT INTO result VALUES (?,?,?)", (prefix + "-complete", time.time(), canonical(result)))
                return result
            # Fresh observation intents can reconcile an acknowledged send's
            # asynchronous delivery. They never dispatch the send again.
            if time.monotonic() >= deadline:
                raise ValueError("original acknowledged load payment remains financially incomplete")
            attempt += 1
            time.sleep(1)
    finally:
        c.close()


def main():
    from .signet import Campaign
    from .signet_phase import _verify_runtime
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--runtime-pins", required=True, type=Path)
    parser.add_argument("--wallets", type=int, choices=[12, 50, 200, 500], default=12)
    parser.add_argument("--concurrency", type=int, default=3)
    parser.add_argument("--transfers", type=int, default=60)
    parser.add_argument("--funding-sat-per-actor", type=int, choices=[40000, 100000], default=100000)
    parser.add_argument("--batch-interval-seconds", type=int, default=10)
    parser.add_argument("--window-seconds", type=int)
    parser.add_argument("--wait-until-due", action="store_true",
                        help="For batch only: subtract completed reporting/work from the next interval")
    parser.add_argument("command", choices=["prepare", "admit", "batch", "finish"])
    args = parser.parse_args()
    if args.wait_until_due and args.command != "batch":
        parser.error("--wait-until-due applies only to batch")
    campaign = Campaign(args.state, json.loads(args.config.read_text()))
    try:
        pins = canonical(json.loads(args.runtime_pins.read_text()))
        campaign.db.execute("INSERT OR IGNORE INTO meta VALUES ('phase_runtime_pins',?)", (pins,))
        if campaign.db.execute("SELECT value FROM meta WHERE key='phase_runtime_pins'").fetchone()[0] != pins:
            raise ValueError("load runtime pins are immutable")
        _verify_runtime(campaign)
        load = Load(campaign, wallets=args.wallets, concurrency=args.concurrency, transfers=args.transfers,
                    funding_sat_per_actor=args.funding_sat_per_actor,
                    batch_interval_seconds=args.batch_interval_seconds, window_seconds=args.window_seconds)
        method = getattr(load, {"prepare": "prepare", "admit": "admit", "batch": "advance_batch", "finish": "finish"}[args.command])
        result = method(wait_until_due=args.wait_until_due) if args.command == "batch" else method()
        print(json.dumps(result, indent=2))
    finally:
        campaign.close()


if __name__ == "__main__":
    main()

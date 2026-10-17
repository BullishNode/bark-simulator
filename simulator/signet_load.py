"""Prepare genuine independent wallets for a bounded public-Signet load phase."""
from __future__ import annotations

import json
import argparse
from pathlib import Path
import time
import math
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from .model import canonical, integer
from .signet import network_identity
from .signet_checks import confirmed_backing
from .signet_proof import verify_coin


class Load:
    def __init__(self, campaign, *, wallets=12, concurrency=3, transfers=60,
                 transfer_sat=1000, batch_interval_seconds=10):
        integer(wallets, "wallet count")
        integer(concurrency, "bounded concurrency", 1)
        if wallets not in {12, 50} or concurrency > min(5, wallets // 2):
            raise ValueError("12 or 50 wallets with at most five disjoint concurrent pairs required")
        self.campaign = campaign
        self.parameters = {"wallets": wallets, "concurrency": concurrency,
                           "transfers": integer(transfers, "transfer count", 1),
                           "transfer_sat": integer(transfer_sat, "transfer amount", 1),
                           "batch_interval_seconds": integer(batch_interval_seconds, "batch interval", 1),
                           "funding_sat_per_actor": 100000, "board_sat_per_actor": 30000,
                           "maximum_offchain_fee_sat": 1000,
                           "wallet_profile": {"vtxo_refresh_expiry_threshold": 144,
                                              "vtxo_exit_margin": 12, "fallback_fee_rate": 750}}
        if transfers > 1000 or transfer_sat > 5000 or batch_interval_seconds < 5:
            raise ValueError("load phase exceeds the declared bounded test workload")
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
        if c.db.execute("SELECT 1 FROM meta WHERE key='load_hold'").fetchone():
            raise ValueError("load phase is held for original-outcome reconciliation")
        if c.db.execute("SELECT 1 FROM action WHERE state IN ('unknown','dispatched')").fetchone():
            raise ValueError("load phase has an original unresolved action")
        actors = []
        for actor in self.actors:
            self.native(actor + "-create", actor, "create", {"wallet_profile": self.parameters["wallet_profile"]})
            address = self.native(actor + "-funding-address", actor, "onchain_address")["address"]
            registration = self.native(actor + "-registration", actor, "fallback_record")
            self.native(actor + "-ark-address", actor, "address")
            funding = c.core.call("validateaddress", address)
            payout = c.core.call("validateaddress", registration["payout_address"])
            if (funding.get("isvalid") is not True or payout.get("isvalid") is not True
                    or payout.get("scriptPubKey") != registration["record"]["spk"]
                    or address == registration["payout_address"]):
                raise ValueError("genuine native funding and reserved payout destinations required")
            created = c.db.execute("SELECT chain FROM action WHERE id=?", (actor + "-create",)).fetchone()
            actors.append({"actor": actor, "address": address, "amount_sat": 100000,
                           "original_pre_create_height": json.loads(created[0])["height"],
                           "funding_address_intent": actor + "-funding-address",
                           "registration_intent": actor + "-registration"})
        if len({actor["address"] for actor in actors}) != len(actors):
            raise ValueError("load funding addresses must be distinct")
        target = self.native("load-native-target-info", self.actors[0], "ark_info")
        if (target["network"] != "signet" or target["vtxo_lifetime"] != 4320
                or target["required_board_confirmations"] != 3
                or target["min_board_amount_sat"] > 30000):
            raise ValueError("actual long-profile native target differs")
        return {"kind": "load_funding_request", "stage": "PREPARED_UNFUNDED",
                "product_source": c.config["source_commit"], "binary_sha256": c.config["binary_sha256"],
                "product_config_sha256": c.config["product_config_sha256"],
                "parameters": self.parameters, "chain": network_identity(c.core), "target": target,
                "actors": actors, "total_actor_principal_sat": 100000 * len(actors),
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
            if c.db.execute("SELECT count(*) FROM action WHERE actor=? AND state='acknowledged' AND operation IN ('create','onchain_address','fallback_record','address')", (actor,)).fetchone()[0] != 4:
                raise ValueError("genuine completed load wallet preparation required")
        funded = [json.loads(row[0]) for row in c.db.execute(
            "SELECT payload FROM result WHERE json_extract(payload,'$.kind')='external_funding'")]
        if any(sum(v["amount_sat"] for v in funded if v["actor"] == actor) != 100000 for actor in self.actors):
            return {"stage": "WAITING_FOR_EXACT_CONFIRMED_ACTOR_FUNDING", "money_dispatched": False}
        boards = {actor: self.native(actor + "-board", actor, "board", {"amount_sat": 30000})
                  for actor in self.actors}
        chain = network_identity(c.core)
        snapshots, intents = [], {}
        for actor in self.actors:
            intent = f"load-admit-{chain['height']}-{actor}"
            coins = self.native(intent, actor, "sync_vtxos")
            if (any(coin["state"] not in {"spent", "spendable"} for coin in coins)
                    or sum(coin["amount_sat"] for coin in coins if coin["state"] == "spendable") != boards[actor]["amount_sat"]):
                return {"stage": "WAITING_FOR_GENUINE_NATIVE_BOARD_ADMISSION", "actor": actor,
                        "height": chain["height"], "snapshot_intent": intent}
            snapshots.append(coins)
            intents[actor] = intent
        proofs = [verify_coin(c, actor, coin) for actor, coins in zip(self.actors, snapshots)
                  for coin in coins if coin["state"] == "spendable"]
        owned_ids = [coin["id"] for coins in snapshots for coin in coins if coin["state"] == "spendable"]
        if len(owned_ids) != len(set(owned_ids)):
            raise ValueError("same spendable coin attributed to multiple load actors")
        if not proofs or any(proof["status"] != "PASS" for proof in proofs):
            raise ValueError("actual native load signature proof unavailable")
        backing = confirmed_backing(c.core, snapshots)
        if network_identity(c.core) != chain:
            raise ValueError("chain changed during load cohort admission")
        admitted = {"stage": "LOAD_NATIVE_COHORT_ADMITTED", "chain": chain,
                    "snapshots": intents, "signature_proofs": proofs, "backing": backing,
                    "opening_coin_sat": sum(coin["amount_sat"] for coins in snapshots for coin in coins if coin["state"] == "spendable")}
        c.db.execute("INSERT INTO meta VALUES ('load_admitted',?)", (canonical(admitted),))
        return admitted

    def advance_batch(self, monitor_pids=None):
        """At most one disjoint batch; the external runner owns pacing/its lock."""
        c = self.campaign
        if c.db.execute("SELECT 1 FROM meta WHERE key='load_hold'").fetchone():
            raise ValueError("load phase is held for original-outcome reconciliation")
        if c.db.execute("SELECT 1 FROM action WHERE state IN ('unknown','dispatched')").fetchone():
            raise ValueError("original load action requires reconciliation")
        if not c.db.execute("SELECT 1 FROM meta WHERE key='load_admitted'").fetchone():
            raise ValueError("actual native load cohort admission required")
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
        now = time.time()
        if last and now - last[0] < self.parameters["batch_interval_seconds"]:
            return {"stage": "WAITING_FOR_LOAD_BATCH_INTERVAL", "money_dispatched": False,
                    "successful_reconciled_transfers": len(completed)}
        c.db.execute("INSERT OR IGNORE INTO result VALUES (?,?,?)", (
            f"load-batch-{indices[0]:06d}-started", now,
            canonical({"kind": "load_batch_started", "indices": indices})))
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
        proofs = [verify_coin(c, actor, coin) for actor, coins in zip(self.actors, snapshots)
                  for coin in coins if coin["state"] == "spendable"]
        if not proofs or any(proof["status"] != "PASS" for proof in proofs):
            raise ValueError("final load native signed path unavailable")
        backing = confirmed_backing(c.core, snapshots)
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

    def run(self):
        while not self.stop.wait(.05):
            self.sample()

    def __enter__(self):
        self.sample()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *unused):
        self.stop.set()
        self.thread.join()
        self.sample()


def _transfer(directory, config, parameters, index):
    from .signet import Campaign
    from .signet_phase import _verify_runtime
    c = Campaign(directory, config)
    try:
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
        confirmed_backing(c.core, [sb, rb])
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
            check = c.check_transfer(prefix + f"-check-{attempt}", prefix + "-send",
                                     prefix + "-sender-before", after_s, prefix + "-receiver-before", after_r,
                                     parameters["maximum_offchain_fee_sat"])
            if check.get("arithmetic") == "PASS" and check.get("backing") == "PASS":
                proofs = [verify_coin(c, actor, coin, expected_address=(address if actor == receiver and coin["id"] in check["new_receiver_coins"] else None))
                          for actor, snapshot in [(sender, sa), (receiver, ra)] for coin in snapshot if coin["state"] == "spendable"]
                if not proofs or any(proof["status"] != "PASS" for proof in proofs):
                    raise ValueError("load signed-path reconciliation failed")
                backing = confirmed_backing(c.core, [sa, ra])
                result = {"kind": "load_transfer_observation", "index": index, "sender": sender, "receiver": receiver,
                          "amount_sat": parameters["transfer_sat"], "status": "RECONCILED",
                          "native_ack_seconds": payment["updated"] - payment["created"],
                          "observed_receiver_available_seconds": c.db.execute("SELECT updated FROM action WHERE id=?", (after_r,)).fetchone()[0] - payment["created"],
                          "reconciliation_seconds": time.time() - payment["created"],
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
    parser.add_argument("--wallets", type=int, choices=[12, 50], default=12)
    parser.add_argument("--concurrency", type=int, default=3)
    parser.add_argument("--transfers", type=int, default=60)
    parser.add_argument("command", choices=["prepare", "admit", "batch", "finish"])
    args = parser.parse_args()
    campaign = Campaign(args.state, json.loads(args.config.read_text()))
    try:
        pins = canonical(json.loads(args.runtime_pins.read_text()))
        campaign.db.execute("INSERT OR IGNORE INTO meta VALUES ('phase_runtime_pins',?)", (pins,))
        if campaign.db.execute("SELECT value FROM meta WHERE key='phase_runtime_pins'").fetchone()[0] != pins:
            raise ValueError("load runtime pins are immutable")
        _verify_runtime(campaign)
        load = Load(campaign, wallets=args.wallets, concurrency=args.concurrency, transfers=args.transfers)
        result = getattr(load, {"prepare": "prepare", "admit": "admit", "batch": "advance_batch", "finish": "finish"}[args.command])()
        print(json.dumps(result, indent=2))
    finally:
        campaign.close()


if __name__ == "__main__":
    main()

"""Prepare genuine independent wallets for a bounded public-Signet load phase."""
from __future__ import annotations

import json
import argparse
from pathlib import Path

from .model import canonical, integer
from .signet import network_identity


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
    parser.add_argument("command", choices=["prepare"])
    args = parser.parse_args()
    campaign = Campaign(args.state, json.loads(args.config.read_text()))
    try:
        pins = canonical(json.loads(args.runtime_pins.read_text()))
        campaign.db.execute("INSERT OR IGNORE INTO meta VALUES ('phase_runtime_pins',?)", (pins,))
        if campaign.db.execute("SELECT value FROM meta WHERE key='phase_runtime_pins'").fetchone()[0] != pins:
            raise ValueError("load runtime pins are immutable")
        _verify_runtime(campaign)
        result = Load(campaign, wallets=args.wallets, concurrency=args.concurrency, transfers=args.transfers).prepare()
        print(json.dumps(result, indent=2))
    finally:
        campaign.close()


if __name__ == "__main__":
    main()

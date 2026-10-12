from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import sys
import time
from pathlib import Path

from .config import Config
from .engine import Engine, Lease, OPERATIONS, initialize
from .report import generate
from .store import Store


def demo(root: Path, seed: int):
    with Lease(root):
        store = Store(root, "synthetic", 10_000)
        if store.db.execute("SELECT 1 FROM snapshot").fetchone():
            raise ValueError("demo requires a fresh directory")
        initialize(store)
        store.event("manifest", {"mode": "synthetic", "seed": seed, "network": "synthetic", "actors": 12})
        rng = random.Random(seed)
        beginning = time.time() - 7200
        for index in range(12):
            store.add_snapshot({"observed_at": beginning + index * 600, "height": 100 + index,
                                "complete": True, "rounds_confirmed_sat": 500_000 - index * 1500 + rng.randrange(1000),
                                "rounds_unconfirmed_sat": 3000, "tree_locked_sat": index * 20_000,
                                "watchman_confirmed_sat": 20_000, "ln_spendable_msat": 300_000_000,
                                "ln_receivable_msat": 200_000_000})
        store.add_entitlement("demo-board-a", "actor-09", "registered", 12_000, "0014" + "11" * 20, {"fixture": True})
        store.add_entitlement("demo-board-b", "actor-09", "pending_board", 8000, "0014" + "11" * 20, {"fixture": True})
        store.set_online("actor-09", False)
        store.record_payout({"txid": "synthetic-payout", "inputs": [{"amount_sat": 22_000}],
                             "outputs": [{"script": "0014" + "11" * 20, "amount_sat": 19_000},
                                         {"script": "operator-change", "amount_sat": 1900}]},
                            ["demo-board-a", "demo-board-b"], 1000, 100)
        report = generate(store, full=True)
        store.close()
        return report


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description="Bark simulator and operator observations")
    sub = parser.add_subparsers(dest="command", required=True)
    d = sub.add_parser("demo", help="deterministic synthetic report; no services or coins")
    d.add_argument("--output", type=Path, required=True)
    d.add_argument("--seed", type=int, default=20261010)
    for name in ("observe", "run", "enqueue", "offline", "online", "report"):
        child = sub.add_parser(name)
        child.add_argument("--config", type=Path, required=True)
        if name in {"observe", "run"}:
            child.add_argument("--once", action="store_true")
        if name == "enqueue":
            child.add_argument("--id", required=True)
            child.add_argument("--actor", required=True)
            child.add_argument("--scenario", required=True)
            child.add_argument("--operation", choices=sorted(OPERATIONS), required=True)
            child.add_argument("--args", type=json.loads, default={})
            child.add_argument("--fee-reserve-sat", type=int, required=True)
        if name in {"offline", "online"}:
            child.add_argument("--actor", required=True)
    args = parser.parse_args()
    try:
        if args.command == "demo":
            result = demo(args.output, args.seed)
            print(json.dumps({"mode": result["mode"], "report": str(args.output / "index.html"), "actors": len(result["actors"]), "catalogue": len(result["coverage"])}))
            return
        config = Config.load(args.config)
        with Lease(config.state_dir):
            store = Store(config.state_dir, "live", config.fee_budget_sat)
            try:
                store.verify_event_chain()
                initialize(store)
                if args.command in {"observe", "run"}:
                    if args.command == "run" and not config.active:
                        raise ValueError("run requires runtime.active=true; observe never dispatches actions")
                    if args.command == "observe":
                        from dataclasses import replace
                        config = replace(config, active=False)
                    if args.command == "run":
                        with Lease(config.wallet_root):
                            asyncio.run(Engine(config, store).run(args.once))
                    else:
                        asyncio.run(Engine(config, store).run(args.once))
                elif args.command == "enqueue":
                    store.queue(args.id, args.actor, args.scenario, args.operation, args.args, args.fee_reserve_sat)
                    generate(store)
                elif args.command in {"offline", "online"}:
                    store.set_online(args.actor, args.command == "online")
                    generate(store)
                else:
                    generate(store, full=True)
            finally:
                store.close()
    except (ValueError, RuntimeError, OSError) as error:
        print(f"simulator: {error}", file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()

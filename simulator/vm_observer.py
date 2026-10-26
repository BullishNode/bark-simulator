"""Read-only local bridge for the existing LunaNode deployment; no SSH or writes."""
from __future__ import annotations

import argparse
import asyncio
import json
import time
import tomllib
from decimal import Decimal
from pathlib import Path

from .model import btc_to_sat, integer
from .process import json_command, text_command


async def collect_client(config_path: Path) -> dict:
    """Current client path: public SDK handshake, measured container and Core.

    Deleted server attribution tables are not an observation interface.
    Operator balances and expiry payout deadlines remain unknown here.
    """
    from .config import Config
    from .architecture import SIGNATURE_LINK
    from .chain import ChainReader
    config = Config.load(config_path)
    if config.architecture_profile != SIGNATURE_LINK or len(config.proof_command) != 5:
        raise ValueError('current profile and independent verifier required')
    chain = ChainReader(config.proof_command[1], config.proof_command[2], config.expected_genesis)
    started = time.time()
    before, genesis, inspected, response = await asyncio.gather(
        asyncio.to_thread(chain.call, 'getblockchaininfo'),
        asyncio.to_thread(chain.call, 'getblockhash', 0),
        json_command(['docker','inspect','--format',
            '{"image_digest":{{json .Image}},"status":{{json .State.Status}}}',config.expected_container],timeout=12),
        json_command(list(config.driver_command),{'operation':'info',
            'expected_server_pubkey':config.expected_server_pubkey},timeout=20))
    if response.get('status') != 'ok':
        raise ValueError('SDK handshake unavailable')
    info = response['data']
    if (genesis != config.expected_genesis or info['sdk_commit'] != config.expected_sdk_commit
            or info['server_mailbox_pubkey'] != config.proof_command[4]):
        raise ValueError('SDK, chain or mailbox pin differs')
    ending = await asyncio.to_thread(chain.call, 'getblockchaininfo')
    return {'observed_at':started,'completed_at':time.time(),'height':ending['blocks'],
        'tip_hash':ending['bestblockhash'],'stable_tip':before['bestblockhash']==ending['bestblockhash'],
        'initial_block_download':ending['initialblockdownload'],'server_status':inspected,
        'identity':{'network':info['network'],'genesis':genesis,'container':config.expected_container,
            'image_digest':inspected['image_digest'],'server_pubkey':info['server_pubkey']},
        'architecture_profile':SIGNATURE_LINK,'financial_pins':{'sdk_commit':info['sdk_commit']},
        'complete':False,'rounds_confirmed_sat':None,'rounds_unconfirmed_sat':None,
        'tree_locked_sat':None,'watchman_confirmed_sat':None,'ln_spendable_msat':None,'ln_receivable_msat':None,
        'timings':{'vtxo_lifetime':info['vtxo_lifetime'],
            'required_board_confirmations':info['required_board_confirmations'],
            'round_interval_secs':info['round_interval_secs'],'payout_enabled':None},
        'unknown_buckets':['operator capital','actual payout policy and deadlines','Lightning readiness']}


async def confirmed_value(ops: str, outpoints: list[str]) -> tuple[int | None, str | None]:
    """Bound observation work; an incomplete inventory is unknown, never zero."""
    if len(set(outpoints)) != len(outpoints):
        raise ValueError("duplicate confirmed outpoint in wallet inventory")
    if len(outpoints) > 64:
        return None, "confirmed inventory exceeds first-version observation limit (64)"
    semaphore = asyncio.Semaphore(4)

    async def read(outpoint: str) -> int:
        txid, index = outpoint.split(":")
        if len(txid) != 64 or any(c not in "0123456789abcdef" for c in txid) or not index.isdecimal():
            raise ValueError("invalid confirmed outpoint")
        async with semaphore:
            output = await text_command([ops, "cli", "gettxout", txid, index, "true"], timeout=8)
        utxo = json.loads(output, parse_float=Decimal)
        if not isinstance(utxo, dict):
            raise ValueError("wallet/chain snapshot changed: expected UTXO disappeared")
        if integer(utxo["confirmations"], "UTXO confirmations") < 1:
            raise ValueError("wallet inventory included an unconfirmed output")
        return btc_to_sat(utxo["value"])

    tasks = [asyncio.create_task(read(outpoint)) for outpoint in outpoints]
    try:
        async with asyncio.timeout(12):
            values = await asyncio.gather(*tasks)
        return sum(values), None
    except TimeoutError:
        return None, "confirmed inventory exceeded observation time budget"
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def collect(deployment: Path, container: str, driver: Path, pubkey: str) -> dict:
    ops = str(deployment / "fallback" / "ops.sh")
    configuration = tomllib.loads((deployment / "state" / "signet-fallback" / "captaind.toml").read_text())
    start = time.time()
    chain = await json_command([ops, "cli", "getblockchaininfo"], timeout=20)
    # docker inspect returns an array; use --format to select public fields only.
    inspected = await json_command(["sudo", "-n", "docker", "inspect", "--format",
        '{"image_digest":{{json .Image}},"status":{{json .State.Status}},"restarts":{{json .RestartCount}}}', container], timeout=20)
    info_response = await json_command([str(driver)], {"operation": "info", "expected_server_pubkey": pubkey}, timeout=30)
    if info_response.get("status") != "ok":
        raise ValueError("cannot validate server identity")
    info = info_response["data"]
    # A fixed read operation, not arbitrary SQL or an operator-supplied RPC mutation.
    rounds_response = await json_command([ops, "capt", "rpc", "wallet"], timeout=20)
    rounds = rounds_response["rounds"]
    confirmed, confirmed_gap = await confirmed_value(ops, rounds["confirmed_utxos"])
    # Monetary Core values are decoded as exact Decimals, never floats.
    ending = await json_command([ops, "cli", "getblockchaininfo"], timeout=20)
    genesis = await get_genesis(ops)
    payout = configuration.get("expiry_payout", {})
    stable = chain["bestblockhash"] == ending["bestblockhash"]
    if not stable:
        confirmed, confirmed_gap = None, "chain tip changed during inventory collection"
    return {
        "observed_at": start, "completed_at": time.time(), "height": chain["blocks"],
        "tip_hash": chain["bestblockhash"],
        "identity": {"network": chain["chain"], "genesis": genesis, "container": container,
                     "image_digest": inspected["image_digest"], "server_pubkey": info["server_pubkey"]},
        "complete": False, # Full tree/liability/LN attribution is not implemented yet.
        "stable_tip": stable, "initial_block_download": chain["initialblockdownload"],
        "rounds_confirmed_sat": confirmed,
        "confirmed_inventory_gap": confirmed_gap,
        "rounds_trusted_sat": integer(rounds["trusted_balance"], "trusted rounds balance"),
        "rounds_untrusted_sat": integer(rounds["untrusted_balance"], "untrusted rounds balance"),
        "rounds_unconfirmed_sat": None, "tree_locked_sat": None,
        "watchman_confirmed_sat": None, "ln_spendable_msat": None, "ln_receivable_msat": None,
        "server_status": inspected,
        "timings": {"vtxo_lifetime": info["vtxo_lifetime"],
                    "required_board_confirmations": info["required_board_confirmations"],
                    "round_interval_secs": info["round_interval_secs"],
                    "grace_blocks": payout.get("grace_blocks"), "sweep_min_confs": payout.get("sweep_min_confs"),
                    "min_payout_sat": payout.get("min_payout_sat"), "payout_enabled": payout.get("enabled")},
        "capabilities": {"lightning_configured": bool(configuration.get("cln_array")),
                         "full_capital_attribution": False, "seed_only_restore": False},
        "unknown_buckets": ["tree/backing attribution", "watchman fees", "LN liquidity", "all user liabilities", "reserved-input exclusions"],
    }


async def get_genesis(ops: str) -> str:
    # getblockhash returns a JSON string, unlike other bridge responses.
    from .process import text_command
    output = await text_command([ops, "cli", "getblockhash", "0"], timeout=20)
    return output.strip().strip('"')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client-config', type=Path)
    parser.add_argument("--deployment", type=Path)
    parser.add_argument("--container")
    parser.add_argument("--driver", type=Path)
    parser.add_argument("--server-pubkey")
    args = parser.parse_args()
    if args.client_config:
        print(json.dumps(asyncio.run(collect_client(args.client_config)),allow_nan=False))
        return
    if not all((args.deployment,args.container,args.driver,args.server_pubkey)):
        parser.error('legacy observer requires deployment, container, driver and server-pubkey')
    if not args.container.startswith("abandon-signet-fallback-"):
        parser.error("only the fallback stack is supported")
    result = asyncio.run(collect(args.deployment, args.container, args.driver, args.server_pubkey))
    print(json.dumps(result, allow_nan=False))


if __name__ == "__main__":
    main()

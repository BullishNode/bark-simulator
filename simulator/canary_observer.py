"""Owning bounded native bridge plus independently pinned public SDK info.

This produces ordinary health facts with complete=false. The engine's explicit
exploratory checker separately validates whether this sample authorizes its
small declared operating path. It never claims full treasury qualification.
"""
import argparse
import asyncio
import json
import time
from pathlib import Path

from .config import Config
from .process import json_command


async def collect(config, declaration):
    start=time.time()
    packet=await json_command(list(config.inventory_command),{'kind':'observer_snapshot'},timeout=25)
    info=await json_command(list(config.driver_command),{'operation':'info','action_id':'canary-observer-info',
        'expected_server_pubkey':config.expected_server_pubkey},timeout=15)
    if info.get('status')!='ok':raise ValueError('actual public server unavailable')
    info=info['data'];inspected=packet['container_inspect'];chain=packet['core_before']
    if packet['source_key']!=declaration['source_key'] or packet['config_sha256']!=declaration['configuration_sha256']:
        raise ValueError('actual source or running configuration differs')
    identity={'network':info['network'],'genesis':packet['genesis'],'container':inspected['Name'].lstrip('/'),
        'image_digest':inspected['Image'],'server_pubkey':info['server_pubkey']}
    wallet=packet['rounds_inventory']
    if wallet['exit']!=0:raise ValueError('owning rounds source unavailable')
    wallet=wallet['data']['rounds'];policy=packet['public_policy']
    snapshot={'observed_at':start,'completed_at':time.time(),'height':chain['blocks'],'tip_hash':chain['bestblockhash'],
        'identity':identity,'architecture_profile':config.architecture_profile,'financial_pins':declaration['pins'],
        'stable_tip':packet['stable_tip'],'initial_block_download':chain['initialblockdownload'],'complete':False,
        'server_status':{'status':'running' if inspected['State']['Running'] and not inspected['State']['OOMKilled'] else 'unavailable',
            'native_pid':inspected['State']['Pid'],'container_id':inspected['Id']},
        'rounds_confirmed_sat':sum(u['value_sat'] for u in wallet['utxos'] if u['confirmations']>0),
        'rounds_unconfirmed_sat':sum(u['value_sat'] for u in wallet['utxos'] if u['confirmations']==0),
        'tree_locked_sat':None,'watchman_confirmed_sat':None,'ln_spendable_msat':None,'ln_receivable_msat':None,
        'timings':{'vtxo_lifetime':info['vtxo_lifetime'],'required_board_confirmations':info['required_board_confirmations'],
            'round_interval_secs':info['round_interval_secs'],'payout_enabled':policy['expiry_payout']['enabled']},
        'capabilities':{'lightning_configured':False,'full_capital_attribution':False},
        'unknown_buckets':['full conserved treasury boundary','complete continuing liabilities','Lightning readiness'],
        'scope':'actual native health and supplied owning wallet facts only; scoped admission checked separately'}
    config.validate_identity(snapshot)
    return snapshot


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True);parser.add_argument('--scope',type=Path,required=True)
    args=parser.parse_args();config=Config.load(args.config)
    print(json.dumps(asyncio.run(collect(config,json.loads(args.scope.read_text()))),allow_nan=False))


if __name__=='__main__':main()

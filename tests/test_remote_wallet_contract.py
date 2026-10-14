import asyncio
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch
from simulator.model import SIGNET_GENESIS
from simulator.remote_observer import collect

class MissingWalletInventory(unittest.TestCase):
    def test_read_only_bridge_null_wallet_preserves_unknown_not_zero(self):
        remote={'genesis':SIGNET_GENESIS,'network':'signet','height':100,'tip_hash':'a'*64,
            'stable_tip':True,'initial_block_download':False,'wallet':None,
            'wallet_inventory_complete':False,
            'wallet_scope':'legacy wallet status reveals an address; signer inventory unavailable',
            'container':'captaind','server_status':{'status':'running','image_digest':'sha256:'+'c'*64},
            'timings':{'enabled':None,'min_payout_sat':None,'grace_blocks':None,'sweep_min_confs':None},
            'lightning_configured':False,'complete':False}
        args=SimpleNamespace(core_cookie=Path('/unused'),known_hosts=Path('/unused'),
            ssh_identity=Path('/unused'),driver=Path('/unused'),server_pubkey='server')
        class Core:
            def __init__(self,*args,**kwargs): pass
            def call(self,method,*args):
                if method=='getblockhash': return SIGNET_GENESIS
                if method=='getblockchaininfo':return {'blocks':100,'headers':100,'bestblockhash':'a'*64,'initialblockdownload':False}
                if method=='getmempoolinfo':return {}
                raise AssertionError('missing signer inventory must not invent chain queries')
        async def public_command(command,*,method,**kwargs):
            if method=='snapshot':return remote
            if method=='pool_status':return {'complete':False}
            return {'status':'ok','data':{'network':'signet','server_pubkey':'server','vtxo_lifetime':48,
                'required_board_confirmations':1,'round_interval_secs':600}}
        with patch('simulator.remote_observer.Core',Core), patch('simulator.remote_observer.public_command',AsyncMock(side_effect=public_command)), patch('simulator.remote_observer.lightning',AsyncMock(return_value={'unknown':True})):
            result=asyncio.run(collect(args))
        self.assertIsNone(result['rounds_confirmed_sat'])
        self.assertIsNone(result['rounds_trusted_sat'])
        self.assertTrue(result['confirmed_inventory_gap'])
        self.assertEqual([],result['rounds_owned_scripts'])
        self.assertTrue(result['stable_tip'])
        self.assertFalse(result['complete'])

if __name__=='__main__':unittest.main()

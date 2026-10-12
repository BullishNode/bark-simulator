import json
from pathlib import Path
import tempfile
import unittest

from simulator.lightning_setup import IDS, PLAN, fund_nodes, open_channel, check_channel, save
from simulator.model import SIGNET_GENESIS
from simulator.store import Store


class Core:
    def __init__(self):
        self.calls = []
        self.genesis = SIGNET_GENESIS
    def call(self, method, *args, **kwargs):
        self.calls.append(method)
        if method == 'getblockhash': return self.genesis
        if method == 'getblockchaininfo': return {'initialblockdownload': False, 'blocks': 300000}
        if method == 'getbalances': return {'mine': {'trusted': '0.00000000'}}
        if method == 'getrawtransaction':
            if args[0] == 'grant': return {'confirmations': 1}
            return {'confirmations': 6, 'vin': [{'txid':'grant','vout':0}],
                    'vout':[{'value':'0.00050000'},{'value':'0.00034900'}]}
        raise AssertionError('unexpected money RPC: ' + method)


class Nodes:
    def __init__(self):
        self.open_calls = 0
        self.channels = {'internal': [], 'external': []}
    def call(self, node, method, **params):
        if method == 'getinfo': return {'id':IDS[node], 'network':'signet', 'blockheight':300000}
        if method == 'listpeerchannels': return {'channels':self.channels[node]}
        if method == 'listfunds':
            return {'outputs':[{'txid':'grant','output':0,'status':'confirmed',
                                'address':'tb1qinternal','amount_msat':85000000}]}
        if method == 'fundchannel':
            self.open_calls += 1
            assert params['utxos'] == ['grant:0']
            assert params['amount'] == 50000 and params['push_msat'] == 25000000
            assert params['feerate'] == '3000perkb' and params['announce'] is False
            raise TimeoutError('request may have reached CLN')
        raise AssertionError(method)


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name), 'live', 1000000)
        self.core, self.nodes = Core(), Nodes()
    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()
    def state(self, **updates):
        value = {'plan':PLAN, 'state':'grant_confirmed','grant_txid':'grant',
                 'addresses':{'internal':'tb1qinternal','external':'tb1qexternal'}}
        value.update(updates)
        save(self.store, value, 'test_setup')
    def test_wrong_chain_never_transfers_or_opens(self):
        self.core.genesis = 'wrong'
        with self.assertRaises(ValueError): fund_nodes(self.store,self.core,self.nodes)
        self.assertEqual(self.core.calls, ['getblockhash'])
        self.assertEqual(self.nodes.open_calls, 0)
    def test_unfunded_setup_never_prepares_transaction(self):
        with self.assertRaisesRegex(ValueError, 'no confirmed fixture capital'):
            fund_nodes(self.store,self.core,self.nodes)
        self.assertNotIn('walletcreatefundedpsbt', self.core.calls)
    def test_lost_open_reply_cannot_open_twice_across_restart(self):
        self.state()
        with self.assertRaisesRegex(ValueError, 'do not retry'):
            open_channel(self.store,self.core,self.nodes)
        self.store.close()
        self.store = Store(Path(self.tmp.name), 'live', 1000000)
        with self.assertRaisesRegex(ValueError, 'do not retry'):
            open_channel(self.store,self.core,self.nodes)
        self.assertEqual(self.nodes.open_calls, 1)
        self.assertEqual(json.loads(self.store.get_meta('fixture_lightning_setup'))['state'], 'opening_unknown')
    def test_preexisting_channel_prevents_new_open(self):
        self.state()
        self.nodes.channels['internal'] = [{'peer_id':IDS['external']}]
        with self.assertRaisesRegex(ValueError, 'pre-existing'):
            open_channel(self.store,self.core,self.nodes)
        self.assertEqual(self.nodes.open_calls, 0)
    def ready_channels(self):
        for node, other in [('internal','external'),('external','internal')]:
            self.nodes.channels[node] = [{'peer_id':IDS[other], 'funding_txid':'channel',
                'funding_outnum':0,'channel_id':'id','state':'CHANNELD_NORMAL',
                'spendable_msat':90000000,'receivable_msat':90000000}]
    def test_lost_reply_recovers_only_exact_channel_and_fee(self):
        self.state(state='opening_unknown', opening_utxo='grant:0')
        self.ready_channels()
        result = check_channel(self.store,self.core,self.nodes)
        self.assertEqual(result['state'], 'ready')
        self.assertEqual(result['channel_fee_sat'], 100)
        self.assertEqual(self.nodes.open_calls, 0)
    def test_other_channel_transaction_is_not_adopted(self):
        self.state(state='channel_found', opening_utxo='grant:0', channel_txid='other')
        self.ready_channels()
        with self.assertRaisesRegex(ValueError, 'identity changed'):
            check_channel(self.store,self.core,self.nodes)
    def test_one_way_channel_does_not_become_ready(self):
        self.state(state='opening_unknown', opening_utxo='grant:0')
        self.ready_channels()
        self.nodes.channels['external'][0]['spendable_msat'] = 0
        self.assertEqual(check_channel(self.store,self.core,self.nodes)['state'], 'channel_found')


if __name__ == '__main__': unittest.main()

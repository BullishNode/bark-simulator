"""Source-collector controls only: no Core, credentials or wallet actions."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from simulator.funding_bank import collect_funding_bank_source, EVENT_KIND, MAX_BYTES
from simulator.model import SIGNET_GENESIS, canonical
from simulator.store import Store
from simulator.funding import WalletRpc


TIP = 'a' * 64
DESCRIPTOR = 'wpkh(public-test-key)#public-checksum'


class Core:
    def __init__(self, *args):
        self.last_response_bytes = 0
        self.calls = []

    def call(self, method, *args, **kwargs):
        self.calls.append((method, args, kwargs))
        if method == 'getblockhash':
            result = SIGNET_GENESIS
        elif method == 'getblockchaininfo':
            result = {'blocks': 100, 'bestblockhash': TIP, 'chain': 'signet', 'initialblockdownload': False}
        elif method == 'getdescriptorinfo':
            result = {'descriptor': DESCRIPTOR, 'hasprivatekeys': False}
        elif method == 'gettxout':
            result = {'bestblock': TIP, 'value': '0.00002' if args[0] == 'b' * 64 else '0.00001',
                      'confirmations': 3, 'scriptPubKey': {'hex': '0014' + '12' * 20}}
        else:
            raise AssertionError('unexpected or mutating RPC: ' + method)
        self.last_response_bytes = len(canonical(result).encode())
        return copy.deepcopy(result)


class Bank(Core):
    wallet = 'original-funding-bank'
    def __init__(self, *args):
        super().__init__()
        self.frames = {
            'getwalletinfo': {'walletname': self.wallet, 'walletversion': 169900, 'format': 'sqlite',
                'txcount': 1, 'descriptors': True, 'scanning': False,
                'private_keys_enabled': True, 'lastprocessedblock': {'height': 100, 'hash': TIP}},
            'listdescriptors': {'wallet_name': self.wallet, 'descriptors': [{'desc': DESCRIPTOR,
                'timestamp': 0, 'active': True, 'internal': False, 'range': [0, 20], 'next': 0}]},
            'listunspent': [{'txid': 'b' * 64, 'vout': 0, 'amount': '0.00002', 'confirmations': 3,
                             'scriptPubKey': '0014' + '12' * 20}],
            'listlockunspent': [{'txid': 'c' * 64, 'vout': 1}],
            'listsinceblock': {'lastblock': TIP, 'transactions': [], 'removed': []},
            'getbalances': {'mine': {'trusted': '0.00003', 'untrusted_pending': '0', 'immature': '0'}}}

    def call(self, method, *args, **kwargs):
        if method not in self.frames:
            return super().call(method, *args, **kwargs)
        if method == 'listdescriptors':
            assert args == (False,), 'private descriptor request forbidden'
        if method == 'listunspent':
            assert args == (0, 9999999, [], True), 'full unsafe-inclusive inventory required'
        self.calls.append((method, args, kwargs))
        result = copy.deepcopy(self.frames[method])
        self.last_response_bytes = len(canonical(result).encode())
        return result


class FundingBankSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name), 'synthetic', 10000)
        self.bank = Bank()
        self.core = Core()

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def collect(self):
        with patch('simulator.funding_bank.WalletRpc', return_value=self.bank), \
             patch('simulator.funding_bank.ChainReader', return_value=self.core):
            return collect_funding_bank_source(self.store,
                SimpleNamespace(token_file='unused', wallet=Bank.wallet),
                SimpleNamespace(url='http://127.0.0.1:38332', credential='unused', expected=SIGNET_GENESIS))

    def rejected(self):
        with self.assertRaises((ValueError, KeyError)):
            self.collect()
        self.assertEqual(0, self.store.db.execute('SELECT COUNT(*) FROM event').fetchone()[0])

    def test_original_named_bank_and_locked_coin_are_preserved(self):
        sequence = self.collect()
        row = self.store.db.execute('SELECT kind,payload FROM event WHERE sequence=?', (sequence,)).fetchone()
        payload = json.loads(row['payload'])
        self.assertEqual(EVENT_KIND, row['kind'])
        self.assertEqual(Bank.wallet, payload['source_identity']['wallet_name'])
        self.assertEqual([DESCRIPTOR], payload['source_identity']['descriptors'])
        self.assertEqual('c' * 64 + ':1', payload['locked_coins'][0]['outpoint'])
        self.assertTrue(payload['complete_source_projection'])
        self.assertNotIn('private_keys_enabled', payload['getwalletinfo'])
        self.assertLess(payload['bounds']['response_bytes'], MAX_BYTES)

    def test_private_descriptor_never_reaches_event_or_descriptor_rpc(self):
        self.bank.frames['listdescriptors']['descriptors'][0]['desc'] = 'wpkh(tprv' + 'A' * 50 + ')'
        self.rejected()
        self.assertNotIn('getdescriptorinfo', [c[0] for c in self.core.calls])

    def test_partial_reply_and_partial_coin_inventory_fail_closed(self):
        del self.bank.frames['getbalances']['mine']['immature']
        self.rejected()
        self.bank.frames['getbalances']['mine']['immature'] = '0'
        self.bank.frames['listunspent'] = []
        self.rejected()

    def test_wrong_bank_identity_and_unstable_tip_fail_closed(self):
        self.bank.frames['listdescriptors']['wallet_name'] = 'customer-driver'
        self.rejected()
        self.bank.frames['listdescriptors']['wallet_name'] = Bank.wallet
        self.bank.frames['getwalletinfo']['lastprocessedblock']['hash'] = 'd' * 64
        self.rejected()

    def test_changed_wallet_reply_fails_closed(self):
        original = self.bank.call
        reads = 0
        def changing(method, *args, **kwargs):
            nonlocal reads
            result = original(method, *args, **kwargs)
            if method == 'getbalances':
                reads += 1
                if reads == 2:
                    result['mine']['trusted'] = '0.00004'
            return result
        self.bank.call = changing
        self.rejected()

    def test_byte_and_row_bounds_fail_without_event(self):
        original = self.bank.call
        def oversized(*args, **kwargs):
            result = original(*args, **kwargs)
            self.bank.last_response_bytes = MAX_BYTES + 1
            return result
        self.bank.call = oversized
        self.rejected()
        self.bank.call = original
        self.bank.frames['listunspent'] *= 2001
        self.rejected()

    def test_private_descriptor_rpc_is_rejected_before_credentials_or_http(self):
        wallet = WalletRpc('/nonexistent-test-credential', Bank.wallet)
        for args in ((), (True,), (0,)):
            with self.assertRaises(ValueError), patch('urllib.request.urlopen') as request:
                wallet.call('listdescriptors', *args)
            request.assert_not_called()

    def test_invalid_deadline_makes_no_calls(self):
        with self.assertRaises(ValueError):
            collect_funding_bank_source(self.store, None, None, timeout_seconds=0)
        self.assertEqual([], self.bank.calls)


if __name__ == '__main__':
    unittest.main()

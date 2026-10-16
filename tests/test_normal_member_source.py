"""Actual private config/SQLite and synthetic source accounting controls."""
import copy
import os
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path
from simulator.normal_member_source import ConfigCredential, bank_projection

class PrivateReadTests(unittest.TestCase):
    def test_read_uses_bounded_fd_not_unbounded_path_read(self):
        from unittest.mock import patch
        from simulator.normal_member_source import private_file
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'original';path.write_bytes(b'abc');path.chmod(0o600)
            with patch.object(Path,'read_bytes',side_effect=AssertionError('unbounded read')):
                self.assertEqual(b'abc',private_file(path,3))
            with self.assertRaises(ValueError):private_file(path,2)
    def test_actual_growth_during_fd_read_refuses(self):
        import os
        from unittest.mock import patch
        from simulator.normal_member_source import private_file
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'original';path.write_bytes(b'abc');path.chmod(0o600)
            original=os.fdopen
            class Reader:
                def __init__(self,fd,mode):self.stream=original(fd,mode)
                def __enter__(self):return self
                def __exit__(self,*args):self.stream.close()
                def fileno(self):return self.stream.fileno()
                def read(self,count):
                    self_count=count
                    with path.open('ab')as writer:writer.write(b'd')
                    if self_count!=4:raise AssertionError('read cap differs')
                    return self.stream.read(count)
            with patch('simulator.normal_member_source.os.fdopen',Reader),self.assertRaisesRegex(ValueError,'changed while'):
                private_file(path,3)

class CredentialTests(unittest.TestCase):
    def test_config_fields_stay_local_and_raw_cookie_other_fields_or_public_mode_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'scoped.conf';path.write_text('rpcuser=synthetic-reader\nrpcpassword=synthetic-token\n');path.chmod(0o600)
            self.assertEqual('synthetic-reader:synthetic-token',ConfigCredential(path).read_text())
            for raw in ('synthetic-reader:synthetic-token','rpcuser=a\nrpcpassword=b\nrpcwallet=bank\n','rpcuser=a\nrpcuser=b\nrpcpassword=c\n'):
                path.write_text(raw)
                with self.subTest(raw=raw),self.assertRaises(ValueError):ConfigCredential(path).read_text()
            path.write_text('rpcuser=a\nrpcpassword=b\n');path.chmod(0o644)
            with self.assertRaises(ValueError):ConfigCredential(path).read_text()

class BankTests(unittest.TestCase):
    def setUp(self):
        self.member={'descriptors':['external','internal']};self.raw={'getwalletinfo':{'scanning':False,'descriptors':True,'txcount':2},
            'getbalances':{'mine':{'untrusted_pending':Decimal(0),'immature':Decimal(0)}},
            'listdescriptors':{'descriptors':[{'desc':'internal'},{'desc':'external'}]},
            'listtransactions':[{'confirmations':2},{'confirmations':1}], 'listlockunspent':[],
            'listunspent':[{'txid':'a'*64,'vout':1,'address':'owned','scriptPubKey':'51','amount':Decimal('.002'),'confirmations':2}],
            'getaddressinfo':{'owned':{'hdkeypath':'m/84h/1h/0h/1/7','scriptPubKey':'51','ismine':True}},'locked_gettxout':{}}
        self.coin={'bestblock':'tip','confirmations':2,'value':Decimal('.002'),'scriptPubKey':{'hex':'51'}}
        outer=self
        class Chain:
            def call(inner,method,*args):
                if method=='getdescriptorinfo':return {'descriptor':args[0],'hasprivatekeys':False}
                if method=='deriveaddresses':return ['owned' if args[0]=='internal' else 'foreign']
                if method=='gettxout':return outer.coin
                raise AssertionError(method)
        self.chain=Chain()
    def project(self):return bank_projection(self.raw,self.member,self.chain,height=100,tip_hash='tip',records=['b'*64])
    def test_actual_bank_branch_child_and_current_cash_are_retained_once(self):
        value=self.project();self.assertEqual({'outpoint':'a'*64+':1','amount_sat':200000,'script':'51','descriptor_index':1,'child_index':7},value['utxos'][0])
        self.assertNotIn('confirmed_fee_eligible',value)
    def test_zero_pending_balance_does_not_hide_pending_outgoing_transaction(self):
        self.raw['listtransactions'][0]['confirmations']=0
        with self.assertRaisesRegex(ValueError,'unconfirmed'):self.project()
    def test_locked_unresolved_or_noncanonical_descriptor_refuses(self):
        original=copy.deepcopy(self.raw)
        self.raw['listlockunspent']=[{'txid':'a'*64,'vout':1}]
        with self.assertRaisesRegex(ValueError,'locked'):self.project()
        self.raw=original;self.raw['listdescriptors']['descriptors'].pop()
        with self.assertRaisesRegex(ValueError,'membership'):self.project()
    def test_scanning_truncated_or_immature_source_refuses(self):
        for change in ('scanning','truncated','immature'):
            original=copy.deepcopy(self.raw)
            if change=='scanning':self.raw['getwalletinfo']['scanning']={'progress':.5}
            elif change=='truncated':self.raw['getwalletinfo']['txcount']=2001
            else:self.raw['getbalances']['mine']['immature']=Decimal('.1')
            with self.subTest(change=change),self.assertRaises(ValueError):self.project()
            self.raw=original
    def test_foreign_script_wrong_child_or_changed_core_coin_refuses(self):
        self.coin['value']=Decimal('.003')
        with self.assertRaisesRegex(ValueError,'independent'):self.project()
        self.coin['value']=Decimal('.002');self.raw['getaddressinfo']['owned']['hdkeypath']='m/7h'
        with self.assertRaisesRegex(ValueError,'ordinary derivation'):self.project()

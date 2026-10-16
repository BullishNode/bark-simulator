"""Actual private config/SQLite and synthetic source accounting controls."""
import copy
import os
import tempfile
import unittest
import asyncio
import sys
from decimal import Decimal
from pathlib import Path
from simulator.normal_member_source import ConfigCredential, bank_projection


class MemberCaptureTests(unittest.IsolatedAsyncioTestCase):
    async def test_ownership_root_discovery_preserves_raw_helper_originals(self):
        """Run a private local synthetic producer through the actual reader."""
        from unittest.mock import patch
        from simulator import normal_member_source as source
        from simulator.model import canonical, SIGNET_GENESIS
        from simulator.store import Store
        from tests.test_two_step_normal import TablesTests
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'capture').mkdir();(root/'helper').mkdir()
            helper=root/'producer.py'
            helper.write_text('''import hashlib,json,pathlib,sys,time
root=pathlib.Path(__file__).parent
nonce=sys.argv[1]; out=root/'helper'/nonce; out.mkdir(mode=0o700)
identity={'chain':'signet','blocks':100,'bestblockhash':'tip','initialblockdownload':False}
originals={'core':json.dumps({'genesis':GENESIS,'before':identity,'after':identity}).encode(),
           'bank':b'{}','fixture_cln':b'{"selected":"literal fixture original"}'}
files={};hashes={}
for name,raw in originals.items():
 p=out/name;p.write_bytes(raw);p.chmod(0o600)
 hashes[name]=hashlib.sha256(raw).hexdigest();files[name]={'sha256':hashes[name],'size_bytes':len(raw)}
manifest={'source_observation_id':nonce,'unresolved_sources':[],
 'source_program_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
 'height':100,'tip_hash':'tip','started_at':time.time(),'completed_at':time.time(),
 'files':files,'originals_map':{name:name for name in originals},'original_sha256':hashes}
p=out/'manifest.json';raw=json.dumps(manifest).encode();p.write_bytes(raw);p.chmod(0o600)
print(json.dumps({'manifest_path':str(p),'manifest_sha256':hashlib.sha256(raw).hexdigest()}))
'''.replace('GENESIS',repr(SIGNET_GENESIS)))
            helper.chmod(0o600)
            prepared=root/'prepared.json';prepared.write_bytes(b'{}');prepared.chmod(0o600)
            cfg={'evidence_root':str(root/'capture'),'helper_evidence_root':str(root/'helper'),
                'helper_command':[sys.executable,str(helper)],'helper_sha256':source.digest(helper.read_bytes()),
                'chain_url':'http://synthetic.invalid','scoped_core_config':str(root/'unused.conf'),
                'prepared_descriptors':str(prepared),'prepared_descriptors_sha256':source.digest(b'{}'),
                'actor_member_ids':{},'descriptor_checkpoint':'unused','descriptor_checkpoint_sha256':'a'*64,
                'bank_member_id':'bank','fixture_member_id':'fixture','target_cln_member_id':'target-cln',
                'backing_member_id':'backing'}
            class Chain:
                def identity(self):return {'blocks':100,'bestblockhash':'tip','initialblockdownload':False}
            tables=TablesTests();tables.setUp();raw_sql=tables.raw()
            target={'raw_sql':raw_sql,'manifest':{'original_sha256':{'native_sql':source.digest(raw_sql)},
                'auxiliary_originals':{'target_cln':'cln'}},'auxiliary_originals':{'cln':b'{"target":"literal"}'}}
            store=Store(root/'store','member-control',10000)
            try:
                with patch.object(source,'ChainReader',return_value=Chain()), \
                        patch.object(source,'current_from_checkpoint',return_value={}), \
                        patch.object(source,'bank_projection',return_value={'synthetic_bank':True}):
                    result=await source.MemberReader(cfg,store).read(
                        {'id':'b'*32,'height':100,'tip_hash':'tip'},{'bank':{}},target)
                self.assertEqual(b'{"selected":"literal fixture original"}',result['members']['fixture']['raw_original'])
                self.assertEqual(target['auxiliary_originals']['cln'],result['members']['target-cln']['raw_original'])
                self.assertEqual({'bank','fixture','target-cln','backing'},set(result['members']))
            finally:store.close()

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


class MemberLiteralOriginalTests(unittest.IsolatedAsyncioTestCase):
    """Real private helper process/files; Core/financial boundaries are explicit stubs."""
    async def test_backing_discovery_preserves_literal_bank_and_cln_originals(self):
        import hashlib
        import json
        import sys
        import time
        from types import SimpleNamespace
        from unittest.mock import patch
        from simulator.model import SIGNET_GENESIS
        from simulator.normal_member_source import MemberReader
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);evidence=root/'evidence';helper_root=root/'helper';wallets=root/'wallets'
            for path in (evidence,helper_root,wallets):path.mkdir(mode=0o700)
            prepared=root/'prepared.json';prepared.write_bytes(b'{}');prepared.chmod(0o600)
            fixture_raw=b'{ "getinfo" : {}, "listfunds":{}, "listpeerchannels":{} }\n'
            target_raw=b'{ "getinfo":{}, "listfunds" : {}, "listpeerchannels":{} }\n'
            tip='a'*64;anchor='b'*64+':0';identifier='c'*32
            helper=root/'helper.py'
            helper.write_text("import pathlib,json,hashlib,sys,time\n"+
                "root=pathlib.Path("+repr(str(helper_root))+ ")/sys.argv[1];root.mkdir(mode=0o700)\n"+
                "files={'bank.json':b'{}','fixture.json':"+repr(fixture_raw)+",'core.json':json.dumps("+
                repr({'genesis':SIGNET_GENESIS,'before':{'chain':'signet','blocks':100,'bestblockhash':tip,'initialblockdownload':False},'after':{'chain':'signet','blocks':100,'bestblockhash':tip,'initialblockdownload':False}})+
                ").encode()}\n"+
                "entries={}\nfor name,raw in files.items():\n p=root/name;p.write_bytes(raw);p.chmod(0o600);entries[name]={'sha256':hashlib.sha256(raw).hexdigest(),'size_bytes':len(raw)}\n"+
                "roles={'bank':'bank.json','fixture_cln':'fixture.json','core':'core.json'}\n"+
                "manifest={'source_observation_id':sys.argv[1],'unresolved_sources':[],'source_program_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'height':100,'tip_hash':"+repr(tip)+",'started_at':time.time(),'completed_at':time.time(),'files':entries,'originals_map':roles,'original_sha256':{k:entries[v]['sha256']for k,v in roles.items()}}\n"+
                "p=root/'manifest.json';p.write_text(json.dumps(manifest));p.chmod(0o600);print(json.dumps({'manifest_path':str(p),'manifest_sha256':hashlib.sha256(p.read_bytes()).hexdigest()}))\n")
            helper.chmod(0o600)
            cfg={'evidence_root':str(evidence),'helper_evidence_root':str(helper_root),'helper_command':[sys.executable,str(helper)],
                'helper_sha256':hashlib.sha256(helper.read_bytes()).hexdigest(),'chain_url':'unused','scoped_core_config':'unused',
                'prepared_descriptors':str(prepared),'prepared_descriptors_sha256':hashlib.sha256(prepared.read_bytes()).hexdigest(),
                'actor_member_ids':{},'wallet_root':str(wallets),'descriptor_checkpoint':'unused','descriptor_checkpoint_sha256':'d'*64,
                'bank_member_id':'bank','fixture_member_id':'fixture','target_cln_member_id':'target','backing_member_id':'backing'}
            class Chain:
                def __init__(self,*args,**kwargs):pass
                def identity(self):return {'blocks':100,'bestblockhash':tip,'initialblockdownload':False}
                def call(self,method,*args):
                    if (method,args)!=('gettxout',('b'*64,0,True)):raise AssertionError((method,args))
                    return {'bestblock':tip,'value':Decimal('.001'),'scriptPubKey':{'hex':'51'}}
            class Database:
                def execute(self,query):
                    if query!='SELECT id,proof FROM owned_coin ORDER BY id':raise AssertionError(query)
                    return SimpleNamespace(fetchall=lambda:[{'id':'preserved-original','proof':json.dumps({'chain_anchor':anchor})}])
            target={'raw_sql':b'original-sql','manifest':{'original_sha256':{'native_sql':'e'*64},'auxiliary_originals':{'target_cln':'target-cln.json'}},'auxiliary_originals':{'target-cln.json':target_raw}}
            tables={'vtxo':[{'vtxo_id':anchor,'onchain_spent_txid':None}]}
            members={name:{}for name in ('bank','fixture','target','backing')}
            with patch('simulator.normal_member_source.ChainReader',Chain),patch('simulator.normal_member_source.current_from_checkpoint',return_value={}),patch('simulator.normal_member_source.bank_projection',return_value={'bank':'projection'}),patch('simulator.normal_member_source.native_tables',return_value=tables):
                value=await MemberReader(cfg,SimpleNamespace(db=Database())).read({'id':identifier,'height':100,'tip_hash':tip},members,target)
            self.assertEqual(fixture_raw,value['members']['fixture']['raw_original'])
            self.assertEqual(target_raw,value['members']['target']['raw_original'])
            self.assertEqual(hashlib.sha256(fixture_raw).hexdigest(),value['manifest']['original_sha256']['fixture'])
            backing=json.loads(value['members']['backing']['raw_original'])
            self.assertEqual({anchor:{'amount_sat':100000,'script':'51'}},backing['roots'])
            self.assertEqual([],value['manifest']['unresolved_sources'])

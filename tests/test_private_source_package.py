"""Bounded synthetic private transport cases; no server, wallet or RPC calls."""
import copy
import io
import json
import os
import tarfile
import tempfile
import unittest
import sys
from pathlib import Path

from simulator.private_source_package import load_target_tar, relative
from simulator.two_step_normal import digest, private_history_hash


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'source.tar'
        self.files={name+'.json':b'{}' for name in ('native_sql','policy','core','rounds_inventory','watchman_inventory','runtime')}
        self.files.update({'fee-history/identity.json':b'policy','fee-history/history':b''})
        self.history={'root_identity':'1:2','identity_bytes':b'policy','index_bytes':b'','candidates':{}}
        self.manifest={'files':{},'originals_map':{name:name+'.json' for name in ('native_sql','policy','core','rounds_inventory','watchman_inventory','runtime')},
            'fee_history_paths':{'root_identity':'1:2','identity':'fee-history/identity.json','index':'fee-history/history','candidates':{}},
            'original_sha256':{name:digest(b'{}') for name in ('native_sql','policy','core','rounds_inventory','watchman_inventory','runtime')},
            'fee_history_sha256':private_history_hash(self.history)}
    def tearDown(self):self.tmp.cleanup()
    def write(self,*,extra=None,skip=None,duplicate=None,special=None,rehash=True):
        if rehash:self.manifest['files']={name:{'sha256':digest(raw),'size_bytes':len(raw)} for name,raw in self.files.items()}
        with tarfile.open(self.path,'w') as archive:
            members={**self.files,'manifest.json':json.dumps(self.manifest).encode()}
            if extra:members.update(extra)
            for name,raw in members.items():
                if name==skip:continue
                info=tarfile.TarInfo(name);info.size=len(raw);info.mode=0o600
                archive.addfile(info,io.BytesIO(raw))
                if name==duplicate:archive.addfile(info,io.BytesIO(raw))
            if special:archive.addfile(special)
        self.path.chmod(0o600)
    def test_actual_original_bytes_and_manifest_are_preserved_not_reserialized(self):
        self.files['runtime.json']=b'{ "public_runtime" : true }\n'
        self.manifest['original_sha256']['runtime']=digest(self.files['runtime.json'])
        self.write();result=load_target_tar(self.path)
        self.assertEqual(self.files['runtime.json'],result['raw_runtime']);self.assertEqual(self.history,result['fee_history'])
        self.assertEqual(digest(result['raw_manifest']),result['manifest_sha256'])
    def test_traversal_absolute_and_noncanonical_relative_names_refuse(self):
        for name in ('../other','/other','a/../other','a//other','./other','a\\other','a/./other'):
            with self.subTest(name=name),self.assertRaises(ValueError):relative(name)
    def test_extra_missing_duplicate_and_link_members_refuse(self):
        for keyword in ({'extra':{'extra':b'not declared'}},{'skip':'core.json'},{'duplicate':'core.json'}):
            self.write(**keyword)
            with self.subTest(keyword=keyword),self.assertRaises(ValueError):load_target_tar(self.path)
        link=tarfile.TarInfo('link');link.type=tarfile.SYMTYPE;link.linkname='/outside'
        self.write(special=link)
        with self.assertRaisesRegex(ValueError,'type/link'):load_target_tar(self.path)
    def test_manifest_hash_size_original_role_and_fee_history_substitution_refuse(self):
        self.write();original=copy.deepcopy(self.manifest)
        for change in ('hash','size','role','history'):
            self.manifest=copy.deepcopy(original)
            if change=='hash':self.manifest['files']['core.json']['sha256']='0'*64
            elif change=='size':self.manifest['files']['core.json']['size_bytes']=3
            elif change=='role':self.manifest['originals_map'].pop('core')
            else:self.manifest['fee_history_paths']['root_identity']='other'
            self.write(rehash=False)
            with self.subTest(change=change),self.assertRaises(ValueError):load_target_tar(self.path)
    def test_public_mode_or_symlink_original_is_not_accepted(self):
        self.write();self.path.chmod(0o644)
        with self.assertRaisesRegex(ValueError,'private original'):load_target_tar(self.path)
        self.path.chmod(0o600);link=self.path.with_name('link.tar');link.symlink_to(self.path)
        with self.assertRaisesRegex(ValueError,'private original'):load_target_tar(link)


class ProjectionTests(unittest.TestCase):
    def wallet(self):
        return {'wallet':'rounds','network':'signet','tip_height':100,'tip_hash':'tip','public_descriptor':'public-desc',
            'last_revealed_index':3,'min_trusted_confirmations':2,'pending_transactions':[],'reserved_outpoints':[],
            'unavailable_parent_txids':[],'complete':False,'utxos':[{'outpoint':'a'*64+':0','value_sat':200000,
                'script_pubkey':'51','derivation_index':3,'keychain':'external','coinbase':False,'confirmations':3,
                'confirmed_fee_eligible':True,'mature':True,'reserved':False,'trusted':True,'opaque_ignored':'not projected'}]}
    def test_native_global_complete_false_is_not_a_missing_owning_frame_or_readiness(self):
        from simulator.two_step_capture import wallet_projection
        report,rows=wallet_projection({'descriptors':['public-desc']},self.wallet(),height=100,tip_hash='tip')
        self.assertEqual(3,rows[0]['child_index']);self.assertNotIn('complete',report)
        self.assertNotIn('opaque_ignored',report['utxos'][0]);self.assertNotIn('ready',report)
    def test_wrong_descriptor_missing_source_pending_and_other_keychain_hold(self):
        from simulator.two_step_capture import wallet_projection
        for field,value in [('public_descriptor','foreign'),('pending_transactions',['pending']),('tip_hash','foreign')]:
            wallet=self.wallet();wallet[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):wallet_projection({'descriptors':['public-desc']},wallet,height=100,tip_hash='tip')
        wallet=self.wallet();wallet['utxos'][0]['keychain']='internal'
        with self.assertRaisesRegex(ValueError,'keychain'):wallet_projection({'descriptors':['public-desc']},wallet,height=100,tip_hash='tip')
    def test_cln_private_fields_are_omitted_and_full_owned_balance_is_used(self):
        from simulator.two_step_capture import cln_projection
        raw={'getinfo':{'id':'node','network':'signet','blockheight':100,'ignored':'not projected'},
            'listfunds':{'outputs':[],'channels':[{'funding_txid':'a'*64,'funding_output':1,'state':'CHANNELD_NORMAL','our_amount_msat':180000000,'amount_msat':200000000}]},
            'listpeerchannels':{'channels':[{'funding_txid':'a'*64,'funding_outnum':1,'state':'CHANNELD_NORMAL','channel_id':'channel',
                'peer_id':'peer','to_us_msat':180000000,'total_msat':200000000,'spendable_msat':173000000,'htlcs':[],
                'funding':{'psbt':'private synthetic data'},'preimage':'private synthetic data'}]}}
        native,cash,channels=cln_projection({'identity':'node'},raw,height=100)
        self.assertEqual([],cash);self.assertEqual(180000000,channels[0]['owned_balance_msat'])
        self.assertNotIn('psbt',json.dumps(native));self.assertNotIn('preimage',json.dumps(native))
        raw['listpeerchannels']['channels'][0]['htlcs']=[{'opaque':'conditional'}]
        with self.assertRaisesRegex(ValueError,'conditional'):cln_projection({'identity':'node'},raw,height=100)
    def test_two_descriptor_bank_is_a_public_cash_source_not_native_fee_eligibility(self):
        from simulator.two_step_capture import public_wallet_projection
        member={'role':'funding_bank','descriptors':['external-desc','internal-desc']}
        raw={'source_kind':'core_wallet_rpc','network':'signet','height':100,'tip_hash':'tip',
            'public_descriptors':member['descriptors'],'pending_transactions':[],'reserved_outpoints':[],
            'discovery_gaps':[],'source_records':['a'*64],'utxos':[{'outpoint':'b'*64+':0','amount_sat':2000,
                'script':'51','descriptor_index':1,'child_index':3}]}
        rows=public_wallet_projection(member,raw,height=100,tip_hash='tip')
        self.assertEqual(1,rows[0]['descriptor_index']);self.assertNotIn('confirmed_fee_eligible',rows[0])
        for change in ('operator','missing','descriptor'):
            value=copy.deepcopy(raw);selected=copy.deepcopy(member)
            if change=='operator':selected['role']='operator'
            elif change=='missing':value['source_records']=[]
            else:value['public_descriptors']=['foreign']
            with self.subTest(change=change),self.assertRaises(ValueError):public_wallet_projection(selected,value,height=100,tip_hash='tip')


class PrivateTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_child_receives_only_canonical_remote_token_and_keeps_original_bytes(self):
        from simulator.private_source_package import TargetTarReader
        fixture=PackageTests();fixture.setUp()
        try:
            fixture.write();parent=Path(fixture.tmp.name)/'captures';parent.mkdir(mode=0o700)
            script='import pathlib,sys; assert sys.argv[2]=="financial-source 12345678-1234-5678-1234-567812345678"; assert sys.stdin.buffer.read()==b""; sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())'
            reader=TargetTarReader([sys.executable,'-c',script,str(fixture.path)],parent)
            result=await reader.read({'id':'12345678123456781234567812345678'})
            self.assertEqual(b'{}',result['raw_sql'])
            directory=next(parent.iterdir());terminal=json.loads((directory/'terminal.json').read_bytes())
            self.assertEqual(0,terminal['exit']);self.assertEqual('financial-source 12345678-1234-5678-1234-567812345678',terminal['remote_command'])
            self.assertEqual(fixture.path.read_bytes(),(directory/'source.tar').read_bytes())
            self.assertTrue(all(path.stat().st_mode&0o777==0o600 for path in directory.iterdir()))
        finally:fixture.tearDown()
    async def test_failed_actual_child_preserves_partial_package_stderr_and_terminal(self):
        from simulator.private_source_package import TargetTarReader
        with tempfile.TemporaryDirectory() as temporary:
            script='import sys; sys.stdout.buffer.write(b"partial"); sys.stderr.write("diagnostic"); sys.exit(2)'
            reader=TargetTarReader([sys.executable,'-c',script],temporary)
            with self.assertRaisesRegex(ValueError,'command refused'):
                await reader.read({'id':'12345678123456781234567812345678'})
            directory=next(Path(temporary).iterdir())
            self.assertEqual(b'partial',(directory/'source.tar').read_bytes());self.assertEqual(b'diagnostic',(directory/'stderr').read_bytes())
            self.assertEqual(2,json.loads((directory/'terminal.json').read_bytes())['exit'])

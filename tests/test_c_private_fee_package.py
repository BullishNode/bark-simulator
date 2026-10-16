"""Real private tar parser boundaries; synthetic PG/Core, no transport credit."""
import io
import json
import os
from pathlib import Path
import tarfile
import unittest

from simulator import c_private_fee_cut as capture
from simulator import c_private_fee_package as loader
from tests import test_c_private_fee_cut as fixtures


class PrivatePackage(unittest.TestCase):
    def setUp(self):
        self.x=fixtures.PrivateFeeCapture();self.x.setUp();self.addCleanup(self.x.doCleanups)
        self.result=self.x.capture(self.x.pg(True));self.path=self.x.root/'source.tar'
        self.safe=capture.write_private_package(self.result,self.path)
    def load(self,exit=0,**overrides):
        args={'expected_package_sha256':capture.digest(self.path.read_bytes()),
              'expected_source_sha256':capture.digest(Path(capture.__file__).read_bytes()),
              'expected_financial_pins':self.x.observation['financial_pins'],'expected_observation':self.x.observation,
              'expected_history_identity':self.x.expected,'expected_policy_sha256':capture.digest(self.x.fixture.policy),
              'expected_server_pubkey':fixtures.fee_fixtures.KEY,'adapter':self.x.fixed,
              'limits':self.x.limits,'binding':self.x.binding,'producer_exit':lambda:exit}
        args.update(overrides);return loader.load_target_tar(self.path,**args)
    def members(self):
        with tarfile.open(self.path,'r:')as t:return[(v.name,t.extractfile(v).read())for v in t]
    def rewrite(self,change=lambda rows:rows):
        rows=change(self.members())
        with tarfile.open(self.path,'w',format=tarfile.USTAR_FORMAT)as t:
            for name,raw in rows:
                entry=tarfile.TarInfo(name);entry.size=len(raw);entry.mode=0o600;t.addfile(entry,io.BytesIO(raw))
        self.path.chmod(0o600)
    def mutation(self,name,fn,*,rehash=True):
        rows=dict(self.members());rows[name]=capture.canonical(fn(capture._json(rows[name]))).encode()
        if rehash:
            m=capture._json(rows['manifest.json']);m['files'][name]={'sha256':capture.digest(rows[name]),'size_bytes':len(rows[name])};rows['manifest.json']=capture.canonical(m).encode()
        self.rewrite(lambda _:[(k,v)for k,v in rows.items()])
    def test_real_package_positive_and_only_safe_source_references(self):
        result=self.load();self.assertFalse(result['database']['complete']);self.assertFalse(result['database']['qualified'])
        self.assertEqual(result['database']['snapshot'],json.loads(result['private_cut'])['database_snapshot'])
        refs=result['original_private_source_references'];self.assertEqual(self.safe['sha256'],refs['archive_sha256'])
        self.assertEqual(self.x.observation['id'],refs['source_observation_id']);self.assertNotIn('raw',capture.canonical(refs))
    def test_actual_transport_failure_never_accepted_from_manifest(self):
        for status in(1,None,True):
            with self.subTest(status=status),self.assertRaises(ValueError):self.load(exit=status)
    def test_whole_tar_and_source_pin_and_context_substitution_refuse(self):
        for field,value in [('expected_package_sha256','f'*64),('expected_source_sha256','f'*64),
                            ('expected_policy_sha256','f'*64),('expected_server_pubkey','03'+'f'*64),
                            ('expected_observation',{**self.x.observation,'id':'b'*32})]:
            with self.subTest(field=field),self.assertRaises(ValueError):self.load(**{field:value})
    def test_native_original_byte_hash_change_refuses(self):
        self.rewrite(lambda rows:[(k,v+b' 'if k=='history/identity.json'else v)for k,v in rows])
        with self.assertRaisesRegex(ValueError,'hash/size'):self.load()
    def test_duplicate_unsafe_unrelated_and_link_members_refuse(self):
        original=self.path.read_bytes()
        for name in('../outside','history/hsm_secret','unrelated','cut.json'):
            self.path.write_bytes(original);self.rewrite(lambda rows:rows+[(name,b'not-read')])
            with self.subTest(name=name),self.assertRaises(ValueError):self.load()
        self.path.write_bytes(original)
        with tarfile.open(self.path,'w',format=tarfile.USTAR_FORMAT)as t:
            entry=tarfile.TarInfo('cut.json');entry.type=tarfile.SYMTYPE;entry.linkname='outside';entry.mode=0o600;t.addfile(entry)
        with self.assertRaises(ValueError):self.load()
    def test_truncated_or_appended_data_never_aliases_valid_tar(self):
        original=self.path.read_bytes()
        for changed in(original[:-512],original+b'not-padding',original[:-1024]):
            self.path.write_bytes(changed)
            with self.subTest(size=len(changed)),self.assertRaises(ValueError):self.load()
    def test_PG_snapshot_change_with_rehashed_manifest_still_refuses(self):
        self.mutation('private-pg.json',lambda v:{**v,'snapshot':'other-real-snapshot'})
        self.mutation('cut.json',lambda v:{**v,'database_snapshot':'other-real-snapshot'})
        with self.assertRaisesRegex(ValueError,'same-RR'):self.load()
    def test_rehashed_manifest_cannot_authorize_PG_signed_bytes_substitution(self):
        def changed(v):v['carriers'][0]['signed_tx_hex']='00';return v
        self.mutation('private-pg.json',changed)
        with self.assertRaisesRegex(ValueError,'signed bytes'):self.load()
    def test_private_file_permissions_links_and_manifest_coverage_refuse(self):
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):self.load()
        self.path.chmod(0o600);other=self.path.with_name('linked');os.link(self.path,other)
        with self.assertRaises(ValueError):self.load()
        other.unlink();self.mutation('manifest.json',lambda v:{**v,'files':{}},rehash=False)
        with self.assertRaisesRegex(ValueError,'coverage'):self.load()
    def test_standalone_capture_canonical_and_pins_match_existing_kernel(self):
        from simulator.model import canonical
        from simulator.final_campaign import _pins
        self.assertEqual(canonical({'unicode':'é','boolean':True,'nested':[1,2]}),capture.canonical({'nested':[1,2],'unicode':'é','boolean':True}))
        self.assertEqual(_pins(self.x.observation['financial_pins']),capture._pins(self.x.observation['financial_pins']))
        self.assertEqual(self.x.observation['financial_pins'],self.load()['manifest']['financial_pins'])

"""Synthetic executable/SDK metadata; actual child processes and immutable trace.

No Rust signature, actual wallet-load or runtime/financial qualification credit.
"""
import copy
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest import mock

from simulator import c_client_transition as c, c_cohort
from simulator.model import SIGNET_GENESIS
from tests import test_c_premoney


class ClientSignatureControls(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fixture=test_c_premoney.PremoneyControls();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.fixture.verify();self.store=self.fixture.store
        c_cohort.seal_unfunded(self.store,self.fixture.config,self.fixture.chain)
        self.root=self.fixture.fixture.root
        self.verifier=self.root/'synthetic-verifier'
        self.verifier.write_text('''#!/usr/bin/python3
import json,sys,os
r=json.load(sys.stdin);raw=bytes.fromhex(r['key_link_attestation'])
b={**r['binding'],'record_version':4,'key_link_version':1,'key_link_attestation':r['key_link_attestation'],
'recovery_index':int.from_bytes(raw[35:39],'little'),'policy_pubkey_full':r['user_pubkey'],
'record_signature_valid':True,'key_link_signature_valid':True}
p={'user_pubkey':r['user_pubkey'],'genesis':GENESIS,'binding':b}
if os.environ.get('SYNTHETIC_BAD_PROOF')=='yes':p['genesis']='wrong'
print(json.dumps(p))
'''.replace('GENESIS',repr(SIGNET_GENESIS)))
        self.verifier.chmod(0o700)
        self.config=dataclasses.replace(self.fixture.config,expected_sdk_commit='f'*40)
        self.manifest=self.root/'synthetic-qualified-client.json'
        driver=Path(self.config.driver_command[0])
        self.body={'common':'1'*40,'tree':'2'*40,'SDK':'f'*40,'SDK_tree':'3'*40,'GIT_HASH':'f'*40,
            'feature':'direct-per-key','runtime_profile':'direct_per_key','runtime_executed':False,
            'artifacts':{'bark-sim-driver':{'bytes':driver.stat().st_size,'sha256':self.hash(driver)},
                         'vtxo-proof':{'bytes':self.verifier.stat().st_size,'sha256':self.hash(self.verifier)}}}
        self.manifest.write_text(json.dumps(self.body))
        self.proof=(str(self.verifier),'synthetic-owned-Core','private-cookie-path',self.config.expected_server_pubkey)

    def hash(self,path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    async def collect(self,identifier='source-component',**changes):
        args={'identifier':identifier,'manifest_path':str(self.manifest),'manifest_sha256':self.hash(self.manifest),
            'previous_driver_config_path':str(self.fixture.fixture.native_config),'proof_command':self.proof}
        args.update(changes)
        return await c.reverify_original_bindings(self.store,self.config,**args)

    async def test_fiftyone_actual_processes_preserve_origin_and_do_not_qualify_wallet_or_runtime(self):
        original=self.store.get_meta('zero_principal_identity_bootstrap')
        actions=[tuple(r) for r in self.store.db.execute('SELECT * FROM action')]
        sequence=await self.collect();value=c.verified_original_bindings(self.store,sequence)
        self.assertEqual(self.fixture.pins,value['origin_financial_pins'])
        self.assertEqual('f'*40,value['execution_client']['sdk_commit'])
        self.assertEqual(51,len(value['proofs']))
        self.assertFalse(value['wallet_load_qualified']);self.assertFalse(value['runtime_qualified'])
        self.assertFalse(value['financial_readiness'])
        self.assertEqual(original,self.store.get_meta('zero_principal_identity_bootstrap'))
        self.assertEqual(actions,[tuple(r) for r in self.store.db.execute('SELECT * FROM action')])
        with self.assertRaisesRegex(ValueError,'retain completed'):await self.collect()
        self.assertEqual(1,self.store.db.execute('SELECT count(*) FROM event WHERE kind=?',(c.KIND,)).fetchone()[0])
        # Tamper real retained stdout: replay must refuse rather than trust flags.
        reference=value['proofs'][0]['trace']
        from simulator.trace import partition_paths
        import sqlite3
        trace=next(p for p in partition_paths(self.store.trace.root) if p.name==reference['partition'])
        conn=sqlite3.connect(trace)
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("UPDATE trace SET raw=? WHERE seq=?",(b'{}',reference['seq']))
        # Simulate privileged/offline corruption of this synthetic fixture,
        # beyond the normal SQL append-only guard; replay still must refuse.
        conn.execute('DROP TRIGGER trace_no_update')
        conn.execute("UPDATE trace SET raw=? WHERE seq=?",(b'{}',reference['seq']));conn.commit();conn.close()
        with self.assertRaises(ValueError):c.verified_original_bindings(self.store,sequence)

    async def test_wrong_installed_artifact_or_manifest_sdk_refuses_before_child(self):
        from simulator import c_client_transition
        with mock.patch.object(c_client_transition,'json_command') as child:
            self.verifier.write_text(self.verifier.read_text()+'# changed\n')
            with self.assertRaisesRegex(ValueError,'artifact changed'):await self.collect()
            child.assert_not_called()
        self.body['artifacts']['vtxo-proof']={'bytes':self.verifier.stat().st_size,'sha256':self.hash(self.verifier)}
        self.body['SDK']='e'*40;self.manifest.write_text(json.dumps(self.body))
        with mock.patch.object(c_client_transition,'json_command') as child:
            with self.assertRaisesRegex(ValueError,'qualified C client'):await self.collect()
            child.assert_not_called()

    async def test_old_sdk_cannot_be_relabeled_as_the_new_client(self):
        old=self.fixture.pins['sdk_commit'];self.body['SDK']=old;self.body['GIT_HASH']=old
        self.manifest.write_text(json.dumps(self.body))
        self.config=dataclasses.replace(self.config,expected_sdk_commit=old)
        with mock.patch.object(c,'json_command') as child:
            with self.assertRaisesRegex(ValueError,'not a new client'):await self.collect()
            child.assert_not_called()

    async def test_wrong_native_network_proof_never_emits_completed_component(self):
        with mock.patch.dict(os.environ,{'SYNTHETIC_BAD_PROOF':'yes'}):
            with self.assertRaisesRegex(ValueError,'incomplete'):await self.collect()
        self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM event WHERE kind=?',(c.KIND,)).fetchone()[0])
        self.assertEqual(1,self.store.db.execute("SELECT count(*) FROM event WHERE kind='c_client_signature_qualification_held'").fetchone()[0])
        self.assertEqual(1,self.store.db.execute('SELECT count(*) FROM action').fetchone()[0])

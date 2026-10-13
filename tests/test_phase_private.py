"""Private signer material is retained separately from public trial events."""
import os,stat,tempfile,unittest
from pathlib import Path

class PhasePrivateTests(unittest.TestCase):
    def test_immutable_private_checkpoint_survives_reopen_and_detects_tamper(self):
        from simulator.phase_private import Vault
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'private';vault=Vault(root);ref=vault.put('nonce_checkpoint',b'opaque-private-signer-state',trial_id='phase-test',leg_id='left')
            self.assertEqual(ref,Vault(root).put('nonce_checkpoint',b'opaque-private-signer-state',trial_id='phase-test',leg_id='left'))
            self.assertTrue(vault.verify(ref));self.assertEqual(0,stat.S_IMODE(root.stat().st_mode)&0o077)
            path=root/'objects'/ref['sha256'];self.assertEqual(0,stat.S_IMODE(path.stat().st_mode)&0o077)
            path.write_bytes(b'changed');self.assertFalse(vault.verify(ref))
    def test_symlink_hardlink_and_unsafe_references_cannot_expose_private_payload(self):
        from simulator.phase_private import Vault
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'outside').mkdir();(root/'private').symlink_to(root/'outside')
            with self.assertRaises(ValueError):Vault(root/'private')
            vault=Vault(root/'safe');ref=vault.put('private_preimage',b'private-test-material',trial_id='trial',leg_id='claim')
            os.link(vault.root/'objects'/ref['sha256'],root/'second-link');self.assertFalse(vault.verify(ref))
            for checksum in ['../outside','x'*64,'/tmp/value']:
                self.assertFalse(vault.verify({**ref,'sha256':checksum}))
    def test_public_reference_contains_no_material_or_absolute_path(self):
        from simulator.phase_private import Vault
        with tempfile.TemporaryDirectory() as directory:
            ref=Vault(Path(directory)/'private').put('forfeit_bundle',b'private-test-bundle',trial_id='trial',leg_id='forfeit')
            self.assertEqual({'kind','sha256','bytes','trial_id','leg_id'},set(ref));self.assertNotIn('private-test-bundle',str(ref))

"""Durable transport capture controls, without network/scenario qualification."""
import tempfile,unittest
from pathlib import Path
from simulator.model import InvariantError
from simulator.phase_private import Vault

class TransportTests(unittest.TestCase):
    def test_full_secret_frames_are_private_and_public_index_is_only_hashes(self):
        from simulator.phase_transport import CaptureIndex
        with tempfile.TemporaryDirectory() as directory:
            index=CaptureIndex(Vault(Path(directory)/'private'),'actor-11','phase-test','ee'*32)
            raw=b'authorization: private-token\x00'+bytes(range(32))
            ref=index.record('request',1,0,'data',raw)
            self.assertNotIn('private-token',str(ref));self.assertTrue(index.vault.verify(ref['object']))
            self.assertEqual(ref,index.record('request',1,0,'data',raw))
            with self.assertRaises(InvariantError):index.record('request',1,0,'data',b'changed')
    def test_second_submit_and_reopened_invocation_are_fenced_before_forward(self):
        from simulator.phase_transport import CaptureIndex
        with tempfile.TemporaryDirectory() as directory:
            vault=Vault(Path(directory)/'private');index=CaptureIndex(vault,'actor-11','phase-test','ee'*32)
            index.request_frozen(1,'SubmitPayment',b'\0\0\0\0\1\x00',b'content-type: application/grpc')
            self.assertTrue(index.release(1))
            index.request_frozen(3,'SubmitPayment',b'\0\0\0\0\1\x01',b'content-type: application/grpc')
            self.assertFalse(index.release(3))
            restarted=CaptureIndex(vault,'actor-11','phase-test','ee'*32)
            self.assertFalse(restarted.release(1));self.assertFalse(restarted.release(3))
    def test_stream_trailers_and_status_survive_capture_and_unsafe_scope_is_rejected(self):
        from simulator.phase_transport import CaptureIndex
        with tempfile.TemporaryDirectory() as directory:
            vault=Vault(Path(directory)/'private')
            with self.assertRaises(ValueError):CaptureIndex(vault,'actor-03','phase-test','ee'*32)
            index=CaptureIndex(vault,'actor-11','phase-test','ee'*32)
            index.record('response',1,0,'headers',b':status: 200')
            index.record('response',1,1,'data',b'first event')
            final=index.record('response',1,2,'trailers',b'grpc-status: 3\ngrpc-message: refusal')
            self.assertTrue(index.vault.verify(final['object']))
            with self.assertRaises(InvariantError):index.record('response',1,4,'data',b'gap')

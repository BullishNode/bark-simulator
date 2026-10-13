import unittest
from simulator.ownership import EvidenceGap
from simulator.model import InvariantError
class ProtocolVersionTests(unittest.TestCase):
    def test_negotiated_pinned_header_never_defaults_to_max_or_accepts_drift(self):
        from simulator.phase_rpc import negotiated_version
        self.assertEqual(19,negotiated_version(18,19,18,20,19))
        for pinned in (None,18,20,True):
            with self.assertRaises((EvidenceGap,InvariantError)):negotiated_version(18,19,18,20,pinned)
        with self.assertRaises(EvidenceGap):negotiated_version(21,22,18,20,20)

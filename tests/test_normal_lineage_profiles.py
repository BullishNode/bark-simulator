"""Cross-profile admission controls; no native execution or readiness credit."""
import unittest

from simulator.b_normal_profile_adapter import InitialDirectProfile
from simulator.normal_lineage_join import CONFIGURATION


class ProfileIsolationTests(unittest.TestCase):
    def test_B_collector_cannot_admit_A_lineage_even_with_matching_module_pins(self):
        from tests.test_two_step_normal import AdmissionTests
        fixture=AdmissionTests();fixture.setUp()
        try:
            fixture.collector.native_profile=InitialDirectProfile()
            fixture.value['ordinary_lineage']=dict(CONFIGURATION)
            fixture.value['component_sha256'].update(fixture.collector.native_profile.component_hashes())
            fixture.admit()
            with self.assertRaisesRegex(ValueError,'another native profile'):
                fixture.collector.admission(fixture.store,fixture.value['financial_pins'])
        finally:fixture.tearDown()

    def test_B_capture_cannot_admit_A_lineage_before_any_reader_runs(self):
        from tests.test_two_step_capture_admission import AdmissionTests
        fixture=AdmissionTests();fixture.setUp()
        try:
            fixture.capture.native_profile=InitialDirectProfile()
            fixture.value['ordinary_lineage']=dict(CONFIGURATION)
            fixture.value['capture_dependencies_sha256'].update(fixture.capture.native_profile.component_hashes())
            fixture.store.event('normal_financial_collector_qualified',fixture.value)
            fixture.capture.admission_sequence=fixture.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
            with self.assertRaisesRegex(ValueError,'another native profile'):
                fixture.capture.admission(fixture.store,{'financial_pins':fixture.value['financial_pins']})
        finally:fixture.tearDown()

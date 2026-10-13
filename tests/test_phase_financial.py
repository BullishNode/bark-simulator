"""Independent financial model checks; these do not qualify live scenarios."""
import unittest
import test_phase_trials as fixtures
from simulator.ownership import EvidenceGap
from simulator.model import InvariantError

class FinancialOracleTests(unittest.TestCase):
    setUp=fixtures.PhaseTrialTests.setUp
    tearDown=fixtures.PhaseTrialTests.tearDown
    trial=fixtures.PhaseTrialTests.trial
    def test_all_nine_cases_retain_liabilities_without_independent_money_evidence(self):
        from simulator.phase_financial import audit,SCENARIOS
        self.assertEqual({'D18','D19','D20','D26','D27','D28','D33','D34','D36'},set(SCENARIOS))
        for scenario in SCENARIOS:
            trial=self.trial(scenario,payment_hash='aa'*32,sender_actor='actor-04',sender_htlc_ids=['b'*64+':0'],scheduled_height=150)
            with self.assertRaises(EvidenceGap):audit(self.controller,trial)
            self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM action').fetchone()[0])
    def test_success_or_verified_driver_flags_cannot_close_a_financial_case(self):
        from simulator.phase_financial import audit
        trial=self.trial('D36',payment_hash='aa'*32,withhold_until_height=120)
        self.controller.reply(trial,'claim',{'kind':'withheld','claim_dispatch_count':0,'deadline_reached':True,'financial_outcome_verified':True,'sender_refund_authorized':True})
        with self.assertRaises(EvidenceGap):audit(self.controller,trial)
    def test_unknown_attempt_fee_is_not_a_zero_measurement(self):
        from simulator.phase_financial import audit
        trial=self.trial('D28')
        self.store.queue('release','actor-11','D28','phase_check',{},0)
        self.store.db.execute("UPDATE phase_trial SET release_action='release' WHERE id=?",(trial,))
        with self.assertRaises(EvidenceGap):audit(self.controller,trial)
        self.assertIsNone(self.store.db.execute("SELECT actual_fee_sat FROM action WHERE id='release'").fetchone()[0])

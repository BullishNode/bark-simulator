import json,unittest
from tests import test_settlements
from simulator.report import generate

def payout_fees(store):
    report=generate(store)
    return {"recipient_fee_sat":report["payout_recipient_fees_sat"],"operator_fee_sat":report["payout_operator_change_fees_sat"],"verified_transactions":report.get("payout_fees",{}).get("verified_transactions")}
from simulator.model import InvariantError

class PayoutFeeReportTests(unittest.TestCase):
    setUp=test_settlements.SettlementTests.setUp
    tearDown=test_settlements.SettlementTests.tearDown
    evidence=test_settlements.SettlementTests.evidence
    record=test_settlements.SettlementTests.record
    proof=test_settlements.SettlementTests.proof
    def verified(self):
        row,tx=self.evidence()
        self.s.db.execute('INSERT INTO chain_payout VALUES (?,?)',(tx['txid'],json.dumps(tx)))
        self.s.db.execute('INSERT INTO checked_settlement VALUES (?,?,?,?,?,?)',('coin:0','payout','actor-01',row['spk'],10000,json.dumps({'row':row})))
        self.s.event('confirmed_payout_amounts_checked',{'txid':'payout','coins':['coin:0'],'recipient_fee_sat':297,'operator_fee_sat':129})
    def test_active_proofs_supply_fees_without_legacy_payout_rows(self):
        self.verified();self.s.db.execute("UPDATE meta SET value='signet' WHERE key='mode'")
        report=payout_fees(self.s)
        self.assertEqual((297,129),(report['recipient_fee_sat'],report['operator_fee_sat']))
        self.assertEqual(1,report['verified_transactions'])
    def test_missing_live_proof_is_unknown_not_zero(self):
        self.s.db.execute("UPDATE meta SET value='signet' WHERE key='mode'")
        report=payout_fees(self.s)
        self.assertIsNone(report['recipient_fee_sat']);self.assertIsNone(report['operator_fee_sat'])
    def test_repeated_matching_receipts_do_not_double_count(self):
        self.verified()
        self.s.event('confirmed_payout_amounts_checked',{'txid':'payout','coins':['coin:0'],'recipient_fee_sat':297,'operator_fee_sat':129})
        self.assertEqual(297,payout_fees(self.s)['recipient_fee_sat'])
    def test_conflicting_or_nonconserving_receipt_is_not_a_reported_fee(self):
        self.verified()
        self.s.event('confirmed_payout_amounts_checked',{'txid':'payout','coins':['coin:0'],'recipient_fee_sat':298,'operator_fee_sat':129})
        with self.assertRaises(InvariantError):payout_fees(self.s)

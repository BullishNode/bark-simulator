import unittest
from tests import test_ownership
from simulator.model import InvariantError
from simulator.ownership import EvidenceGap
from simulator.settlements import check_payment,pre_state

class SettlementTests(unittest.TestCase):
    setUp=test_ownership.OwnershipTests.setUp
    tearDown=test_ownership.OwnershipTests.tearDown
    proof=test_ownership.OwnershipTests.proof
    record=test_ownership.OwnershipTests.record
    server=test_ownership.OwnershipTests.server
    def evidence(self):
        self.record('actor-01','coin:0','user',amount=10000)
        self.s.db.execute("INSERT OR IGNORE INTO operator_script VALUES ('change','{}')")
        row={'id':'coin:0','txid':'payout','fee_sat':297,'spk':'spk-actor-01','pre_commit_rows':[{'spend_state':'spendable'}], 'tx_settlement_count':1,'htlc':None}
        tx={'txid':'payout','confirmations':6,'fee_sat':426,'outputs':[{'script':'spk-actor-01','amount_sat':9703},{'script':'change','amount_sat':297}]}
        return row,tx
    def test_confirmed_group_amounts_and_repeated_fee_are_exact(self):
        row,tx=self.evidence();self.record('actor-01','coin:1','user2',amount=5000)
        row['tx_settlement_count']=2;other={**row,'id':'coin:1'};tx['outputs'][0]['amount_sat']=14703
        result=check_payment(self.s,[row,other],tx)
        self.assertEqual(297,result['recipient_fee_sat']);self.assertEqual(129,result['operator_fee_sat'])
    def test_partial_cyclic_inventory_does_not_accuse_wrong_amount(self):
        row,tx=self.evidence();row['tx_settlement_count']=2;tx['outputs'][0]['amount_sat']=14703
        with self.assertRaises(EvidenceGap):check_payment(self.s,[row],tx)
    def test_wrong_owner_or_wrong_group_amount_is_an_incident(self):
        for mutate in ['script','amount']:
            with self.subTest(mutate=mutate):
                row,tx=self.evidence()
                if mutate=='script':
                    self.record('actor-02','other:0','foreign',amount=5000)
                    row['spk']='spk-actor-02'
                else:tx['outputs'][0]['amount_sat']=9702
                with self.assertRaises(InvariantError):check_payment(self.s,[row],tx)
    def test_missing_historical_record_remains_pending_without_claiming_payment(self):
        row,tx=self.evidence()
        self.s.db.execute("DELETE FROM owner_record WHERE script=?",(row['spk'],))
        with self.assertRaisesRegex(EvidenceGap,'historical payout destination record'):
            check_payment(self.s,[row],tx)
        self.assertEqual(0,self.s.db.execute('SELECT COUNT(*) FROM checked_settlement').fetchone()[0])

    def test_known_competing_destination_is_an_incident(self):
        row,tx=self.evidence();self.record('actor-02','other:0','foreign',amount=5000)
        row['spk']='spk-actor-02'
        with self.assertRaises(InvariantError):check_payment(self.s,[row],tx)

    def test_unconfirmed_payment_and_unverified_change_are_not_success(self):
        row,tx=self.evidence();tx['confirmations']=0
        with self.assertRaises(EvidenceGap):check_payment(self.s,[row],tx)
        tx['confirmations']=1;tx['outputs'][1]['script']='unknown'
        with self.assertRaises(EvidenceGap):check_payment(self.s,[row],tx)
    def test_collected_lightning_sender_is_never_refunded(self):
        row,tx=self.evidence();row['htlc']={'direction':'incoming','collection_recorded':True,'subscription_settled':True}
        with self.assertRaises(InvariantError):check_payment(self.s,[row],tx)
        row['htlc']['collection_recorded']=False;row['htlc']['subscription_settled']=False
        with self.assertRaises(EvidenceGap):check_payment(self.s,[row],tx)
    def test_ambiguous_precommit_never_guesses(self):
        with self.assertRaises(EvidenceGap):pre_state({'pre_commit_rows':[{'spend_state':'spent'},{'spend_state':'unregistered'}]})
        self.assertEqual('pending-board',pre_state({'pre_commit_rows':[],'board_reserved':True}))

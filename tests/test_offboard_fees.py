import asyncio,json,tempfile,unittest
from pathlib import Path
from simulator.engine import initialize
from simulator.fees import offboard_fee,collect
from simulator.model import InvariantError
from simulator.ownership import EvidenceGap
from simulator.store import Store

class OffboardFeeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.s=Store(Path(self.tmp.name),'synthetic',10000);initialize(self.s)
        self.s.queue('exit','actor-01','H33','offboard_all',{},2000)
        self.s.db.execute("UPDATE action SET state='dispatched' WHERE id='exit'")
        self.proposal={'action_id':'sdk-exit','destination_script':'own-spk','input_vtxo_ids':['coin-a','coin-b'],'net_sat':14500,'committed_fee_sat':500}
        self.s.event('driver_evidence',{'action_id':'exit','event':'offboard_proposal','data':self.proposal})
        self.s.finish('exit','completed',{'data':{'offboard_action_id':'sdk-exit','destination_script':'own-spk','txid':'a'*64,'committed_fee_sat':500}})
        self.s.db.execute("INSERT INTO owner_key VALUES ('key','actor-01','mailbox','{}')")
        for coin,amount in [('coin-a',10000),('coin-b',5000)]:
            self.s.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',(coin,'key',amount,'digest','signed','{}'))
        self.tx={'txid':'a'*64,'confirmations':2,'fee_sat':1200,'outputs':[{'script':'own-spk','amount_sat':14500},{'script':'another-customer','amount_sat':9500}]}
    def tearDown(self):self.s.close();self.tmp.cleanup()
    def action(self):return self.s.db.execute("SELECT * FROM action WHERE id='exit'").fetchone()
    def test_customer_charge_does_not_include_other_customers_mining_weight(self):
        result=offboard_fee(self.s,self.action(),self.tx)
        self.assertEqual(500,result['actual_fee_sat']);self.assertEqual(1200,result['confirmed_transaction_mining_fee_sat'])
    def test_wrong_destination_and_wrong_owner_are_incidents(self):
        self.tx['outputs'][0]['script']='thief'
        with self.assertRaises(InvariantError):offboard_fee(self.s,self.action(),self.tx)
        self.tx['outputs'][0]['script']='own-spk';self.s.db.execute("UPDATE owner_key SET actor='actor-02'")
        with self.assertRaises(InvariantError):offboard_fee(self.s,self.action(),self.tx)
    def test_unconfirmed_or_missing_signed_principal_keeps_the_reserve(self):
        self.tx['confirmations']=0
        with self.assertRaises(EvidenceGap):offboard_fee(self.s,self.action(),self.tx)
        self.tx['confirmations']=1;self.s.db.execute("DELETE FROM owned_coin WHERE id='coin-b'")
        with self.assertRaises(EvidenceGap):offboard_fee(self.s,self.action(),self.tx)
        self.assertIsNone(self.action()['actual_fee_sat'])
    def test_intent_mismatch_and_over_cap_are_incidents(self):
        self.s.db.execute("UPDATE action SET fee_reservation_sat=499 WHERE id='exit'")
        with self.assertRaises(InvariantError):offboard_fee(self.s,self.action(),self.tx)
        self.s.db.execute("UPDATE action SET fee_reservation_sat=2000 WHERE id='exit'")
        self.tx['outputs'][0]['amount_sat']=14499
        with self.assertRaises(InvariantError):offboard_fee(self.s,self.action(),self.tx)
    def test_completed_charge_is_closed_exactly_once_without_another_request(self):
        tx=self.tx
        class Chain:
            def identity(self):return {}
            def transaction(self,txid):return tx
        asyncio.run(collect(self.s,Chain()));asyncio.run(collect(self.s,Chain()))
        self.assertEqual(500,self.action()['actual_fee_sat'])
        self.assertEqual(1,self.s.db.execute("SELECT COUNT(*) FROM event WHERE kind='client_fee_reconciled'").fetchone()[0])
        self.assertEqual(1,self.s.db.execute('SELECT COUNT(*) FROM action').fetchone()[0]);self.s.verify_event_chain()

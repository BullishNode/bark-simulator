import asyncio,json,tempfile,unittest
from pathlib import Path
from simulator.engine import initialize
from simulator.store import Store
from simulator.fees import board_fee,collect
from simulator.model import InvariantError
from simulator.ownership import EvidenceGap
class BoardFeeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name),'synthetic',10000);initialize(self.store)
        self.store.queue('board','actor-01','H01','board',{'amount_sat':12000},2000)
        self.store.db.execute("UPDATE action SET state='dispatched' WHERE id='board'")
        result={'data':{'board':{'vtxos':['coin']},'sdk_service_fee_sat':330}}
        self.store.finish('board','completed',result)
        self.store.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',('key','actor-01','mailbox','{}'))
        self.store.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',('coin','key',11670,'digest','signed',json.dumps({'chain_anchor':'a'*64+':0'})))
        self.tx={'txid':'a'*64,'confirmations':1,'fee_sat':500,'inputs':[], 'outputs':[{'vout':0,'amount_sat':12000,'script':'anchor'}]}
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def action(self):return self.store.db.execute("SELECT * FROM action WHERE id='board'").fetchone()
    def test_actual_mining_fee_and_service_charge_remain_separate(self):
        result=board_fee(self.store,self.action(),self.tx)
        self.assertEqual((500,330,830),(result['mining_fee_sat'],result['service_charge_sat'],result['actual_fee_sat']))
    def test_unconfirmed_transaction_does_not_release_reserve(self):
        self.tx['confirmations']=0
        with self.assertRaises(EvidenceGap):board_fee(self.store,self.action(),self.tx)
        self.assertIsNone(self.action()['actual_fee_sat'])
    def test_wrong_anchor_or_owner_is_an_incident(self):
        self.tx['txid']='b'*64
        with self.assertRaises(InvariantError):board_fee(self.store,self.action(),self.tx)
        self.tx['txid']='a'*64;self.store.db.execute("UPDATE owner_key SET actor='actor-02'")
        with self.assertRaises(InvariantError):board_fee(self.store,self.action(),self.tx)
    def test_cost_above_the_cap_is_an_incident(self):
        self.tx['fee_sat']=2000
        with self.assertRaises(InvariantError):board_fee(self.store,self.action(),self.tx)
    def test_completed_board_is_reconciled_once_without_resubmission(self):
        tx=self.tx
        class Chain:
            def identity(self):return {}
            def transaction(self,txid):return tx
        before=self.store.remaining_fee_budget()
        asyncio.run(collect(self.store,Chain()));asyncio.run(collect(self.store,Chain()))
        self.assertEqual(830,self.action()['actual_fee_sat'])
        self.assertEqual(1170,self.store.remaining_fee_budget()-before)
        self.assertEqual(1,self.store.db.execute("SELECT COUNT(*) FROM event WHERE kind='client_fee_reconciled'").fetchone()[0])
        self.assertEqual(1,self.store.db.execute('SELECT COUNT(*) FROM action').fetchone()[0]);self.store.verify_event_chain()

import json
import unittest
from simulator.fees import board_fee
from simulator.model import InvariantError
from simulator.ownership import EvidenceGap
from tests import test_fees as helpers


class RecyclingQuoteTests(unittest.TestCase):
    setUp=helpers.BoardFeeTests.setUp
    tearDown=helpers.BoardFeeTests.tearDown
    action=helpers.BoardFeeTests.action

    def prepare(self, proposal=True):
        source={'outpoint':'b'*64+':0','amount_sat':4119,'script':'own'}
        args={'amount_sat':3636,'recycle_autosize':True,'board_cap_sat':5000,
              'minimum_ark_amount_sat':3000,'recycle_source':source}
        self.store.db.execute("UPDATE action SET args=? WHERE id='board'",(json.dumps(args),))
        self.store.db.execute("UPDATE owned_coin SET amount_sat=3636 WHERE id='coin'")
        self.tx.update(fee_sat=153,inputs=[source],outputs=[{'vout':0,'amount_sat':3966,'script':'anchor'}])
        if proposal:
            self.store.event('driver_evidence',{'action_id':'board','event':'board_proposal',
                'data':{'funding_txid':self.tx['txid'],'amount_sat':3966,
                        'planned_mining_fee_sat':153,'estimated_service_fee_sat':330,'recycle_autosize':True}})

    def test_autosize_uses_exact_frozen_proposal_not_estimate_hint(self):
        self.prepare()
        result=board_fee(self.store,self.action(),self.tx)
        self.assertEqual(483,result['actual_fee_sat'])
        self.assertEqual(3966,result['funded_amount_sat'])

    def test_quote_missing_never_releases_reserve(self):
        self.prepare(False)
        with self.assertRaises(EvidenceGap):board_fee(self.store,self.action(),self.tx)

    def test_quote_mining_mismatch_or_foreign_input_is_incident(self):
        self.prepare()
        self.tx['fee_sat']=154
        with self.assertRaises(InvariantError):board_fee(self.store,self.action(),self.tx)
        self.tx['fee_sat']=153
        self.tx['inputs'][0]['outpoint']='c'*64+':0'
        with self.assertRaises(InvariantError):board_fee(self.store,self.action(),self.tx)

    def test_quote_cannot_exceed_board_cap_or_principal_floor(self):
        self.prepare()
        args=json.loads(self.action()['args']);args['board_cap_sat']=3900
        self.store.db.execute("UPDATE action SET args=? WHERE id='board'",(json.dumps(args),))
        with self.assertRaises(InvariantError):board_fee(self.store,self.action(),self.tx)
        args['board_cap_sat']=5000;args['minimum_ark_amount_sat']=4000
        self.store.db.execute("UPDATE action SET args=? WHERE id='board'",(json.dumps(args),))
        with self.assertRaises(InvariantError):board_fee(self.store,self.action(),self.tx)

"""Real Store/pending call path with native-proof stubs; no financial credit."""
import copy
import unittest

from simulator.normal_pending_board import join_board_service_allocations
from tests import test_normal_pending_board as pending_fixture


class BoardServiceAllocationTests(unittest.TestCase):
    def setUp(self):
        self.fixture=pending_fixture.PendingTests();self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups);self.addCleanup(self.fixture.tearDown)
        f=self.fixture
        self.claims=[{**row,'server_pubkey':f.server}for row in f.claims]
        self.resolution=f.verify()
        self.members={'actor-01':{'role':'customer','kind':'wallet','identity':'customer'},
            'backing':{'role':'operator','kind':'ark_backing','identity':f.server}}
        self.money={'client_service_charges':[{'action_id':'original-board','txid':f.txid,
            'coin_id':f.coin,'amount_msat':330000,
            'scope':'internal customer-to-operator charge; never miner expense'}]}

    def join(self):
        return join_board_service_allocations(self.resolution,self.money,self.claims,self.members,
            server_pubkey=self.fixture.server,native_source_sha256='d'*64)

    def test_actual_pending_call_path_attributes_service_without_journaling_or_paying_principal(self):
        before=self.fixture.store.db.execute('SELECT count(*)FROM event').fetchone()[0]
        result=self.join()
        self.assertEqual((1000,670,330),(result['gross_backing_sat'],result['unpaid_principal_sat'],result['internal_service_charge_sat']))
        self.assertEqual('backing',result['allocations'][0]['operator_borrower'])
        self.assertEqual([self.fixture.coin],result['allocations'][0]['current_claim_ids'])
        self.assertEqual(before,self.fixture.store.db.execute('SELECT count(*)FROM event').fetchone()[0])
        self.assertNotIn('flow_records',result);self.assertNotIn('ready',result)

    def test_recovered_root_preserves_principal_and_original_service_separately_from_sweep_fee(self):
        f=self.fixture;f.tables['vtxo'][1]['onchain_spent_txid']='e'*64
        f.recovered={'liabilities':[{'coin_id':f.coin,'amount_sat':670,'root_outpoint':f.root,'receipt_id':'e'*64}]}
        self.resolution=f.verify()
        result=self.join()
        self.assertEqual(670,result['unpaid_principal_sat']);self.assertEqual(330,result['internal_service_charge_sat'])
        self.assertEqual(0,self.resolution['customer_payment_credit_sat'])

    def test_two_board_arithmetic_keeps_all_four_split_rights_and_gross_holds(self):
        # Arithmetic control only: 2 x (28,000 = 27,670 + 330), four rights.
        boards=[];claims=[];services=[]
        for index,amounts in enumerate(((27670,),(1000,13335,13335))):
            board=copy.deepcopy(self.resolution['resolved_registered_boards'][0]);root=str(index+1)*64+':0'
            ids=[str(index+3)*63+str(i)+':0' for i in range(len(amounts))]
            board.update(root_outpoint=root,registered_coin_id=ids[0],original_board_action='board-'+str(index),
                amount_sat=27670,funded_amount_sat=28000,current_claim_ids=ids)
            boards.append(board)
            claims.extend({'coin_id':name,'amount_sat':amount,'chain_anchor':root,'server_pubkey':self.fixture.server}
                for name,amount in zip(ids,amounts))
            services.append({'action_id':board['original_board_action'],'txid':root[:-2],
                'coin_id':ids[0],'amount_msat':330000,'scope':'internal customer-to-operator charge; never miner expense'})
        self.resolution['resolved_registered_boards']=boards;self.claims=claims;self.money['client_service_charges']=services
        result=self.join()
        self.assertEqual((56000,55340,660),(result['gross_backing_sat'],result['unpaid_principal_sat'],result['internal_service_charge_sat']))
        self.assertEqual(4,sum(len(row['current_claim_ids'])for row in result['allocations']))

    def test_wrong_service_amount_identity_or_scope_refuses(self):
        for field,value in [('amount_msat',430000),('coin_id','foreign'),('txid','f'*64),('scope','miner expense')]:
            original=copy.deepcopy(self.money);self.money['client_service_charges'][0][field]=value
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'attribution differs'):self.join()
            self.money=original

    def test_missing_extra_or_duplicate_charge_cannot_disappear(self):
        original=copy.deepcopy(self.money)
        for charges in ([],[original['client_service_charges'][0]]*2,
                original['client_service_charges']+[{**original['client_service_charges'][0],'action_id':'unmatched'}]):
            self.money['client_service_charges']=charges
            with self.assertRaises(ValueError):self.join()

    def test_missing_repeated_or_repriced_principal_refuses(self):
        original=copy.deepcopy(self.claims)
        for claims in ([],original*2,[{**original[0],'amount_sat':669}]):
            self.claims=claims
            with self.assertRaisesRegex(ValueError,'claim'):self.join()

    def test_foreign_root_or_server_cannot_own_original_service(self):
        original=copy.deepcopy(self.claims)
        for field,value in [('chain_anchor','f'*64+':0'),('server_pubkey','foreign')]:
            self.claims=[{**original[0],field:value}]
            with self.assertRaisesRegex(ValueError,'another backing or server'):self.join()

    def test_unknown_actor_or_borrower_cannot_be_inferred(self):
        original=copy.deepcopy(self.members)
        for members in ({'backing':original['backing']},{'actor-01':original['actor-01']},
                {**original,'duplicate':original['backing']}):
            self.members=members
            with self.assertRaises(ValueError):self.join()

    def test_incorrect_gross_and_duplicate_board_refuse(self):
        board=self.resolution['resolved_registered_boards'][0];board['funded_amount_sat']=999
        with self.assertRaisesRegex(ValueError,'conserve'):self.join()
        board['funded_amount_sat']=1000;self.resolution['resolved_registered_boards'].append(copy.deepcopy(board))
        with self.assertRaisesRegex(ValueError,'repeated'):self.join()

    def test_unresolved_or_paid_flags_cannot_clear_obligation(self):
        for field,value in [('additional_liabilities',[{'amount':1}]),('customer_payment_credit_sat',670)]:
            original=copy.deepcopy(self.resolution);self.resolution[field]=value
            with self.assertRaisesRegex(ValueError,'cannot be omitted'):self.join()
            self.resolution=original

    def test_empty_board_history_requires_empty_charge_projection(self):
        self.resolution['resolved_registered_boards']=[];self.claims=[]
        with self.assertRaisesRegex(ValueError,'no authenticated'):self.join()
        self.money['client_service_charges']=[];self.assertEqual([],self.join()['allocations'])


if __name__=='__main__':unittest.main()

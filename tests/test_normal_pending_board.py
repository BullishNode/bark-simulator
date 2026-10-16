"""Consumer/Store controls with isolated crypto stubs; no native/live credit."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from simulator.bundle_audit import decode_transaction
from simulator.engine import initialize
from simulator.model import SIGNET_GENESIS,canonical
from simulator.normal_pending_board import verify_pending_boards
from simulator.store import Store
from tests.test_normal_money_sources import wire


class PendingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name),'pending-source',10000);initialize(self.store)
        self.raw=wire([('f'*64,0)],[(1000,b'\x51')]);self.txid=decode_transaction(self.raw.hex())['txid'];self.root=self.txid+':0'
        self.coin='a'*64+':0';self.key='02'+'1'*64;self.server='02'+'2'*64;self.tip='b'*64
        self.store.queue('original-board','actor-01','H01','board',{'amount_sat':1000},500)
        self.store.claim({'board'});self.store.finish('original-board','completed',{'status':'ok','data':{'board':{'vtxos':[self.coin]},'sdk_service_fee_sat':330}},430)
        self.owned={'id':self.coin,'user_pubkey':self.key,'chain_anchor':self.root,'expiry_height':148,'amount_sat':670}
        self.store.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',(self.key,'actor-01','mailbox','{}'))
        self.store.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',(self.coin,self.key,670,hashlib.sha256(b'\x01').hexdigest(),'01',canonical(self.owned)))
        self.store.event('driver_evidence',{'action_id':'original-board','event':'board_proposal','data':{'funding_txid':self.txid,'unsigned_funding_tx':self.raw.hex(),'planned_mining_fee_sat':100,'estimated_service_fee_sat':330}})
        leaf={'vtxo_id':self.coin,'anchor_point':self.root,'signed_vtxo_hex':'01','amount':670,'expiry':148,'exit_delta':12,
            'policy_type':'pubkey','server_pubkey':self.server,'spend_state':'spendable','oor_spent_txid':None,'onchain_spent_txid':None,'spent_in_round':None,'offboarded_in':None}
        root={'vtxo_id':self.root,'anchor_point':self.root,'amount':1000,'expiry':148,'policy_type':'expiry','server_pubkey':self.server,'onchain_spent_txid':None}
        self.tables={'pending_board':[{'id':self.root,'vtxo_id':self.coin,'signed_vtxo_hex':'00','expiry':148}],
            'vtxo':[leaf,root],'virtual_transaction':[{'txid':self.txid,'is_funding':True,'signed_transaction_hex':self.raw.hex()}]}
        self.claims=[{'coin_id':self.coin,'amount_sat':670,'chain_anchor':self.root}];self.fresh={self.root:{'root_sat':1000,'claim_sat':670}};self.recovered=None
        self.proof={'schema_version':2,'anchor_spender_txid':self.coin.split(':')[0],'id':self.coin,'chain_anchor':self.root,'server_pubkey':self.server,'user_pubkey':self.key,
            'amount_sat':670,'expiry_height':148,'exit_delta':12,'exit_depth':1,
            'pending_unsigned_structure_verified':True,'registered_signed_board_verified':True,'same_unsigned_transaction_path':True,
            'pending_signature_verified':False,'current_liability_or_payment_verified':False}
        self.tool={'sha256':'c'*64};outer=self
        class Chain:
            def identity(inner):return {'chain':'signet','blocks':100,'bestblockhash':outer.tip,'initialblockdownload':False}
            def tx(inner,txid):return {'txid':txid,'hex':outer.raw.hex(),'confirmations':3,'blockhash':'d'*64}
            def transaction(inner,txid):return {'txid':txid,'confirmations':3,'outputs':[{'vout':0,'amount_sat':1000,'script':'51'}],'fee_sat':100}
            def call(inner,method,*args):
                if method=='getblockhash':return SIGNET_GENESIS if args==(0,)else 'd'*64
                if method=='gettxout':return None if outer.tables['vtxo'][1]['onchain_spent_txid']else {'bestblock':outer.tip}
                raise AssertionError(method)
        self.chain=Chain()
        def proof(tool,request):return canonical(request).encode(),canonical(self.proof).encode()
        self.native=patch('simulator.two_step_normal.run_proof',side_effect=proof);self.native_mock=self.native.start();self.addCleanup(self.native.stop)
        def coins(store,ids,actor):
            row=store.db.execute('SELECT c.*,?AS actor FROM owned_coin c WHERE id=?',(actor,ids[0])).fetchone()
            return [(row,json.loads(row['proof']))]
        self.coin_auth=patch('simulator.unknown_outcomes._coins',side_effect=coins);self.coin_auth.start();self.addCleanup(self.coin_auth.stop)
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def verify(self,tool=True):return verify_pending_boards(self.store,self.tables,self.claims,self.chain,self.tool if tool else None,
        server_pubkey=self.server,height=100,tip_hash=self.tip,fresh_backing=self.fresh,recovered=self.recovered)
    def test_unsigned_and_registered_bytes_differ_but_exact_native_contract_and_current_right_join(self):
        before=self.store.db.execute('SELECT count(*)FROM event').fetchone()[0];result=self.verify();row=result['resolved_registered_boards'][0]
        self.assertIs(False,row['pending_signature_verified']);self.assertIs(False,row['current_liability_or_payment_verified'])
        self.assertEqual([self.coin],row['current_claim_ids']);self.assertEqual([],result['additional_liabilities']);self.assertEqual(0,result['customer_payment_credit_sat'])
        self.assertEqual(before,self.store.db.execute('SELECT count(*)FROM event').fetchone()[0])
        self.assertNotEqual(self.native_mock.call_args.args[1]['pending_vtxo'],self.native_mock.call_args.args[1]['registered_vtxo'])
    def test_missing_qualified_tool_unregistered_or_extra_pending_remains_real_hold(self):
        with self.assertRaisesRegex(ValueError,'qualified native'):self.verify(False)
        original=copy.deepcopy(self.tables)
        self.tables['vtxo']=self.tables['vtxo'][1:]
        with self.assertRaisesRegex(ValueError,'obligation'):self.verify()
        self.tables=original;self.tables['pending_board'].append(copy.deepcopy(self.tables['pending_board'][0]))
        with self.assertRaisesRegex(ValueError,'duplicate pending'):self.verify()
    def test_detached_signature_paid_or_path_flags_never_resolve_pending(self):
        for key,value in [('pending_signature_verified',True),('current_liability_or_payment_verified',True),
                ('same_unsigned_transaction_path',False),('registered_signed_board_verified',False),('schema_version',1),('anchor_spender_txid',None),('exit_delta',13),('id','f'*64+':0')]:
            original=copy.deepcopy(self.proof);self.proof[key]=value
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'native proof differs'):self.verify()
            self.proof=original
    def test_changed_original_intent_terminal_or_proposal_holds(self):
        self.store.db.execute("UPDATE action SET fee_reservation_sat=499 WHERE id='original-board'")
        with self.assertRaisesRegex(ValueError,'changed since authorization'):self.verify()
        self.store.db.execute("UPDATE action SET fee_reservation_sat=500,result='{}'WHERE id='original-board'")
        with self.assertRaisesRegex(ValueError,'original completed intent'):self.verify()
    def test_amount_root_coverage_and_spent_unknown_cannot_omit_liability(self):
        original=copy.deepcopy(self.claims);self.claims=[]
        with self.assertRaisesRegex(ValueError,'liability lineage'):self.verify()
        self.claims=original;self.fresh={}
        with self.assertRaisesRegex(ValueError,'physical backing'):self.verify()
        self.fresh={self.root:{'claim_sat':670}};self.tables['vtxo'][0]['spend_state']='spent'
        with self.assertRaisesRegex(ValueError,'unknown current spend'):self.verify()
    def test_recovered_root_retains_unpaid_right_without_duplicate_cash_or_liability(self):
        receipt='e'*64;self.tables['vtxo'][1]['onchain_spent_txid']=receipt
        self.recovered={'liabilities':[{'coin_id':self.coin,'amount_sat':670,'root_outpoint':self.root,'receipt_id':receipt}]}
        result=self.verify();self.assertEqual(0,result['customer_payment_credit_sat']);self.assertEqual([],result['additional_liabilities'])
        self.recovered['liabilities'][0]['receipt_id']='f'*64
        with self.assertRaisesRegex(ValueError,'recovered backing'):self.verify()
    def test_authenticated_superseded_ark_requires_all_exact_signed_descendants_and_amounts(self):
        spend='e'*64;child='f'*64+':0';self.tables['vtxo'][0].update(spend_state='spent',oor_spent_txid=spend)
        self.claims=[{'coin_id':child,'amount_sat':670,'chain_anchor':self.root}]
        self.store.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',(child,self.key,670,'digest','00',canonical({'id':child})))
        with patch('simulator.financial_transition._superseded_ark_input',return_value=True),patch('simulator.campaign._receipt_origin',return_value={'branch_txid':spend}):
            self.assertEqual([child],self.verify()['resolved_registered_boards'][0]['current_claim_ids'])
        with patch('simulator.financial_transition._superseded_ark_input',return_value=False):
            with self.assertRaisesRegex(ValueError,'positive original Ark'):self.verify()
        with patch('simulator.financial_transition._superseded_ark_input',return_value=True),patch('simulator.campaign._receipt_origin',return_value={'branch_txid':'a'*64}):
            with self.assertRaisesRegex(ValueError,'signed Ark lineage'):self.verify()
    def test_unconfirmed_or_changed_chain_cannot_resolve_registered_row(self):
        original=self.chain.tx;self.chain.tx=lambda txid:{**original(txid),'confirmations':0}
        with self.assertRaisesRegex(ValueError,'confirmed Core'):self.verify()
        self.chain.tx=original;identity=self.chain.identity;calls=[0]
        def changing():
            calls[0]+=1
            return {**identity(),'bestblockhash':'a'*64}if calls[0]>1 else identity()
        self.chain.identity=changing
        with self.assertRaisesRegex(ValueError,'chain changed'):self.verify()

    def test_native_shaped_reserved_board_root_flows_through_fresh_backing_and_pending_join(self):
        from simulator.two_step_normal import verify_fresh_backing
        root=self.tables['vtxo'][1];root['oor_spent_txid']=self.coin.split(':')[0]
        self.claims[0]['anchor_raw_sha256']=hashlib.sha256(self.raw).hexdigest()
        call=self.chain.call
        def current(method,*args):
            if method=='gettxout':return {'bestblock':self.tip,'confirmations':3,'value':'0.00001','scriptPubKey':{'hex':'51'}}
            return call(method,*args)
        self.chain.call=current
        with self.assertRaisesRegex(ValueError,'qualified native'):
            verify_fresh_backing(self.claims,self.tables,self.chain,height=100,server_pubkey=self.server)
        self.fresh=verify_fresh_backing(self.claims,self.tables,self.chain,height=100,server_pubkey=self.server,pending_tool=self.tool)
        self.assertEqual([self.coin],self.verify()['resolved_registered_boards'][0]['current_claim_ids'])
        self.assertEqual(2,self.native_mock.call_count)
        for edge in ['f'*64,None]:
            if edge is None:
                self.tables['pending_board'][0]['id']='f'*64+':0'
                root['oor_spent_txid']=self.coin.split(':')[0]
            else:root['oor_spent_txid']=edge
            with self.subTest(edge=edge),self.assertRaisesRegex(ValueError,'exact pending registered exit edge'):
                verify_fresh_backing(self.claims,self.tables,self.chain,height=100,server_pubkey=self.server,pending_tool=self.tool)
    def test_mempool_spent_fresh_root_holds_even_when_confirmed_view_reports_unspent(self):
        from simulator.two_step_normal import verify_fresh_backing
        self.claims[0]['anchor_raw_sha256']=hashlib.sha256(self.raw).hexdigest()
        call=self.chain.call
        def mempool(method,*args):
            if method=='gettxout':
                return None if args[-1]is True else {'bestblock':self.tip,'confirmations':3,'value':'0.00001','scriptPubKey':{'hex':'51'}}
            return call(method,*args)
        self.chain.call=mempool
        with self.assertRaisesRegex(ValueError,'confirmed independent backing'):
            verify_fresh_backing(self.claims,self.tables,self.chain,height=100,server_pubkey=self.server,pending_tool=self.tool)
        with self.assertRaisesRegex(ValueError,'physical backing'):self.verify()

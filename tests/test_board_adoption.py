from tests.owned_activity_fixture import capture as capture_activity, script
"""Synthetic single-Board controls; no native/Core execution credit."""
import copy
import json
import sqlite3
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch,AsyncMock
from simulator.board_adoption import _client_state,_database,validate_adoption_scope,collect_board_adoption_sources
from simulator.model import canonical
from simulator.engine import Lease
from tests.test_fresh_cash_readiness import CashSourceControls,CashSQLiteControls
from tests.test_final_campaign import PINS


def origin():
    return {'financial_pins':PINS,'boundary_id':'finite','actor':'actor-01','board_action_id':'board-first-01',
        'vtxo_id':'f'*64+':0','net_liability_sat':19500,'anchor':'e'*64+':0',
        'anchor_output':{'vout':0,'script':script('board-anchor'),'amount_sat':20000},'expiry_height':200,'exit_margin':12,
        'user_pubkey':'02'+'1'*64,'binding':{'mailbox_pk':'02'+'2'*64,'child_index':0},'movement_id':1,
        'mining_fee_sat':1200,'service_charge_sat':500,'funding_fee_sat':1000,'funding_plan':{'bank_wallet_name':'bank'}}


class BoardNativeControls(unittest.TestCase):
    def setUp(self):
        self.fixture=CashSQLiteControls();self.fixture.setUp();self.f=self.fixture.fixture;self.origin=origin();self.origin['financial_pins']=self.f.pins
        path=self.fixture.paths[0];conn=sqlite3.connect(path)
        definitions={
            'bark_vtxo':'id TEXT,amount_sat INTEGER,expiry_height INTEGER',
            'bark_vtxo_state':'id INTEGER,vtxo_id TEXT,state_kind TEXT',
            'bark_movements':'id INTEGER,status TEXT,subsystem_name TEXT,effective_balance INTEGER,offchain_fee INTEGER',
            'bark_movements_output_vtxos':'movement_id INTEGER,vtxo_id TEXT',
            'bark_wallet_action_checkpoint':'id TEXT,payload BLOB'}
        for table,columns in definitions.items():conn.execute('DROP TABLE '+table);conn.execute('CREATE TABLE '+table+'('+columns+')')
        conn.execute('INSERT INTO bark_vtxo VALUES (?,?,?)',(self.origin['vtxo_id'],19500,200))
        conn.execute('INSERT INTO bark_vtxo_state VALUES (?,?,?)',(1,self.origin['vtxo_id'],'Locked'))
        conn.execute('INSERT INTO bark_movements VALUES (?,?,?,?,?)',(1,'pending','bark.board',19500,500))
        conn.execute('INSERT INTO bark_movements_output_vtxos VALUES (?,?)',(1,self.origin['vtxo_id']))
        self.payload={'Board':{'id':'board.'+self.origin['anchor'].replace(':','.'),'vtxo_id':self.origin['vtxo_id'],
            'amount':19500,'movement_id':1,'progress':{'Confirming':{'last_park_error':None}},'funding_psbt':'opaque-private-not-exported'}}
        conn.execute('INSERT INTO bark_wallet_action_checkpoint VALUES (?,?)',(self.payload['Board']['id'],canonical(self.payload).encode()));conn.commit();conn.close()
    def tearDown(self):self.fixture.tearDown()
    def check(self,height=100):
        return _client_state(self.f.store,self.f.config,self.origin,height)
    def test_original_confirming_projection_reads_no_private_payload_into_receipt(self):
        with Lease(self.f.wallets):result=self.check()
        self.assertEqual(1,result['actor-01']['checkpoint_count']);self.assertEqual('Locked',result['actor-01']['state'])
        self.assertNotIn('opaque-private',canonical(result));self.assertNotIn('funding_psbt',canonical(result))
    def test_unrelated_lightning_checkpoint_or_near_expiry_refuses(self):
        with Lease(self.f.wallets),self.assertRaisesRegex(ValueError,'near expiry'):self.check(182)
        conn=sqlite3.connect(self.fixture.paths[0]);conn.execute('INSERT INTO bark_lightning_send VALUES (1)');conn.commit();conn.close()
        with Lease(self.f.wallets),self.assertRaisesRegex(ValueError,'unrelated persisted'):self.check()
    def test_broadcasting_or_other_board_checkpoint_and_incomplete_adoption_refuse(self):
        self.payload['Board']['progress']={'Broadcasting':{'signed_vtxo':'opaque'}}
        conn=sqlite3.connect(self.fixture.paths[0]);conn.execute('UPDATE bark_wallet_action_checkpoint SET payload=?',(canonical(self.payload).encode(),));conn.commit();conn.close()
        with Lease(self.f.wallets),self.assertRaisesRegex(ValueError,'Confirming'):self.check()
        conn=sqlite3.connect(self.fixture.paths[0]);conn.execute('DELETE FROM bark_wallet_action_checkpoint');conn.commit();conn.close()
        with Lease(self.f.wallets),self.assertRaisesRegex(ValueError,'completed adoption'):self.check()
        conn=sqlite3.connect(self.fixture.paths[0]);conn.execute("UPDATE bark_vtxo_state SET state_kind='Spendable'");conn.execute("UPDATE bark_movements SET status='successful'");conn.commit();conn.close()
        with Lease(self.f.wallets):self.assertEqual(0,self.check()['actor-01']['checkpoint_count'])


class BoardDatabaseControls(unittest.TestCase):
    def setUp(self):
        self.origin=origin();self.prior={'rows':{name:[] for name in ('coins','pending_boards','links','journal_links','records','journal_records','htlcs','rounds','journal_allocations')}}
        self.database={'kind':'closed_frontier','database_tables_complete':True,'inventory_consistent':True,'read_only':True,'rows':copy.deepcopy(self.prior['rows'])}
        link={'user_pubkey':self.origin['user_pubkey'],'mailbox_pk':self.origin['binding']['mailbox_pk'],'child_index':0}
        self.database['rows']['links']=[link];self.database['rows']['journal_links']=[link]
        self.anchor={'vtxo_id':self.origin['anchor'],'anchor_point':self.origin['anchor'],'amount':20000,'expiry':200,
            'policy_type':'expiry','spend_state':'spent','oor_spent_txid':'f'*64,'spent_in_round':None,
            'offboarded_in':None,'onchain_spent_txid':None,'onchain_spent_height':None}
        self.database['rows']['coins']=[self.anchor];self.database['rows']['pending_boards']=[{'vtxo_id':'f'*64+':0','expiry':200}]
    def test_pending_and_registered_views_have_one_liability_without_counting_anchor_twice(self):
        self.assertFalse(_database(self.database,self.prior,self.origin)['registered'])
        leaf={**self.anchor,'vtxo_id':self.origin['vtxo_id'],'amount':19500,'policy_type':'pubkey','spend_state':'spendable','oor_spent_txid':None}
        self.database['rows']['coins'].append(leaf)
        self.assertTrue(_database(self.database,self.prior,self.origin)['registered'])
        invalid=copy.deepcopy(self.database);invalid['rows']['coins'][0]['spend_state']='oor-spent'
        with self.assertRaisesRegex(ValueError,'server state differs'):_database(invalid,self.prior,self.origin)
    def test_foreign_coin_or_round_or_expiry_carrier_refuses(self):
        for name in ('htlcs','rounds','journal_allocations'):
            value=copy.deepcopy(self.database);value['rows'][name]=[{'unexpected':True}]
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'unrelated server'):_database(value,self.prior,self.origin)
        value=copy.deepcopy(self.database);value['rows']['coins'].append({**self.anchor,'vtxo_id':'9'*64+':0'})
        with self.assertRaisesRegex(ValueError,'one original Board'):_database(value,self.prior,self.origin)


class BoardSourceControls(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fixture=CashSourceControls();self.fixture.setUp();self.f=self.fixture;self.origin=origin();self.tip=self.f.tip
    def tearDown(self):self.fixture.tearDown()
    async def test_full_cash_plus_anchor_closure_and_undeclared_change_refusal(self):
        from simulator.fresh_cash_readiness import collect_fresh_cash_sources
        import sys
        with self.f.dependencies():cash=await collect_fresh_cash_sources(self.f.store,self.f.config,self.f.chain,None,current_startup_path='/synthetic-only')
        self.origin['funding_confirmation_sequence']=cash['source']['funding_confirmation_sequence']
        # Confirming a new Board changes the chainstate; never model new confirmed outputs at the old tip.
        self.f.height=101;self.f.tip=self.tip='d'*64
        self.f.bank.update(height=101,tip_hash=self.tip);self.f.bankseq=self.f.event('treasury_bank_original_source',self.f.bank)
        self.origin['transaction']={'txid':'e'*64,'inputs':[{'outpoint':self.f.txid+':2','amount_sat':50000,'script':script('actor-01:0')}],
            'outputs':[self.origin['anchor_output'],{'vout':1,'amount_sat':28800,'script':script('actor-01:2')}],'fee_sat':1200,'confirmations':1}
        current={field:{owner:{'complete':True,'network':'signet','wallet':owner,'public_descriptor':'desc-'+owner,
            'last_revealed_index':1,'tip_height':101,'tip_hash':self.tip}} for owner,field in [('rounds','rounds_inventory'),('watchman','watchman_inventory')]}
        old_call=self.f.chain.call
        def call(method,*args,**kwargs):
            if method=='scantxoutset' and args[0]=='start':
                rows=[{'txid':self.f.txid,'vout':row['vout'],'amount':str(__import__('decimal').Decimal(row['amount_sat'])/100000000),'scriptPubKey':row['script']}
                    for row in self.f.transaction['outputs'] if row['vout']!=2]
                rows.append({'txid':'e'*64,'vout':1,'amount':'0.00028800','scriptPubKey':script('actor-01:2')})
                return self.f.capture_scan({'success':True,'height':101,'bestblock':self.tip,'unspents':rows,'total_amount':'0.00643254'},args[1])
            if method=='gettxout' and args[0]=='e'*64:
                row=self.origin['transaction']['outputs'][args[1]]
                return {'confirmations':1,'value':str(__import__('decimal').Decimal(row['amount_sat'])/100000000),'scriptPubKey':{'hex':row['script']}}
            return old_call(method,*args,**kwargs)
        self.f.chain.call=call
        with ExitStack() as stack:
            stack.enter_context(patch('simulator.confirmed_scan._identity',side_effect=self.f.scan_identity))
            stack.enter_context(patch('simulator.board_adoption._origin',return_value=self.origin))
            stack.enter_context(patch('simulator.board_adoption._history'))
            stack.enter_context(patch('simulator.board_adoption._client_state',return_value={'synthetic':True}))
            stack.enter_context(patch('simulator.board_adoption._database',return_value={'registered':False}))
            stack.enter_context(patch.dict(sys.modules,{'simulator.runtime_startup':SimpleNamespace(_read=lambda path:(current,'synthetic'))}))
            stack.enter_context(patch('simulator.funding_bank.collect_funding_bank_source',return_value=self.f.bankseq))
            stack.enter_context(patch('simulator.process.public_command_capture',return_value={}))
            stack.enter_context(patch('simulator.process.json_command',new=AsyncMock(return_value=self.f.db)))
            result=await collect_board_adoption_sources(self.f.store,self.f.config,self.f.chain,None,cash_source_sequence=cash['source_sequence'],current_startup_path='/synthetic-only')
            self.assertEqual(663254,result['source']['physical_total_sat']);self.assertEqual(19500,result['source']['net_liability_sat'])
            self.assertEqual(7,len(result['source']['physical_assets']));self.assertEqual(0,self.f.store.db.execute("SELECT count(*) FROM event WHERE kind='financial_operating_readiness'").fetchone()[0])
            from simulator.board_adoption import record_board_adoption_readiness
            import time
            caps={'round':None,'pool':None,'sweep':20000,'payout':20000,'claim':None,'progression':None}
            for owner,field,index in [('rounds','rounds_inventory',0),('watchman','watchman_inventory',1)]:
                output=self.f.transaction['outputs'][index]
                current[field][owner].update(reserved_outpoints=[],pending_transactions=[],pending_parents=[],unavailable_parent_txids=[],
                    utxos=[{'outpoint':self.f.txid+':'+str(index),'value_sat':output['amount_sat'],'script_pubkey':output['script'],
                        'confirmed_fee_eligible':owner=='watchman','trusted':owner=='watchman','mature':True,'reserved':False}])
            runtime=self.f.event('owned_runtime_configuration_verified',{'loaded_configuration_identity_verified':True,
                'current_source_sha256':'synthetic','product_commit':PINS['product_commit'],'schema_sha256':PINS['schema_sha256'],
                'effective_fee_ceilings_sat_kvb':caps,'observed_at':time.time()})
            self.f.event('financial_cost_verified',{'monetary_id':'bitcoin-miner:funding','financial_pins':PINS,'budget':'ordinary','amount_msat':1000000})
            limits={'pins':PINS,'boundary_id':'finite','fee_ceilings_sat_kvb':caps,'fee_budgets_msat':{'ordinary':60000000,'urgent':15000000},
                'operation_fee_paths':{operation:['sweep','payout'] for operation in ('sync','snapshot')}}
            assets={point:{'member':coin['member_id'],'amount_msat':coin['amount_sat']*1000} for point,coin in result['source']['physical_assets'].items() if point!=self.origin['anchor']}
            with patch('simulator.treasury.capture_assets',return_value={'height':101,'tip_hash':self.tip,'total_msat':643254000,'assets':assets}),\
                    patch('simulator.treasury.boundary',return_value={'id':'finite','members':self.f.members}),\
                    patch('simulator.operating_limits.envelope',return_value=limits):
                ready=record_board_adoption_readiness(self.f.store,self.f.config,self.f.chain,source_sequence=result['source_sequence'],runtime_source_sequence=runtime,current_startup_path='/synthetic-only')
                self.assertEqual(['sync','snapshot'],ready['operation_scope']);self.assertEqual(663254000,ready['capital_exposure_msat'])
                self.assertEqual(75000000,ready['available_fee_funding_msat']);self.assertEqual(19500,ready['net_liability_sat'])
                # Re-observation cannot duplicate an independently observed Board charge.
                record_board_adoption_readiness(self.f.store,self.f.config,self.f.chain,source_sequence=result['source_sequence'],runtime_source_sequence=runtime,current_startup_path='/synthetic-only')
                self.assertEqual(2,self.f.store.db.execute("SELECT count(*) FROM event WHERE kind='financial_cost_verified'").fetchone()[0])
                from simulator.operating_limits import fee_totals
                costs=[json.loads(row[0]) for row in self.f.store.db.execute("SELECT payload FROM event WHERE kind='financial_cost_verified'")]
                board_cost=next(cost for cost in costs if cost.get('action_id')==self.origin['board_action_id'])
                self.assertEqual('bitcoin-miner:'+'e'*64,board_cost['monetary_id'])
                self.assertEqual(1200000,board_cost['amount_msat'])
                self.assertEqual(500,board_cost['service_charge_sat'])
                self.assertEqual(1700,board_cost['customer_total_fee_sat'])
                self.assertFalse(board_cost['service_charge_is_boundary_cost'])
                self.assertEqual({'ordinary':2200000,'urgent':0},fee_totals(self.f.store,PINS))
                self.assertEqual(665454-2200,result['source']['physical_total_sat'])
                self.assertEqual(2200000,sum(cost['amount_msat'] for cost in costs))
                for operation in ('board','address','send_arkoor','pay_invoice','exit'):
                    with self.subTest(operation=operation),self.assertRaisesRegex(ValueError,'adoption scope'):
                        validate_adoption_scope(self.f.store,self.f.config,ready,operation=operation,maximum_fee_sat=0,reserved_action_id=None)
            self.origin['transaction']['outputs'][1]['script']='foreign'
            with self.assertRaisesRegex(ValueError,'change not in original'):
                await collect_board_adoption_sources(self.f.store,self.f.config,self.f.chain,None,cash_source_sequence=cash['source_sequence'],current_startup_path='/synthetic-only')


class BoardOriginalEvidenceControls(unittest.TestCase):
    def test_original_proposal_core_transaction_and_native_signed_proof_bind_exact_gross_net(self):
        import sys,hashlib
        from simulator.bundle_audit import decode_transaction
        from simulator.board_adoption import _origin
        from simulator import ownership
        fixture=CashSourceControls();fixture.setUp();store=fixture.store
        try:
            ownership.initialize(store)
            plan={'id':'first','pins':PINS,'boundary_id':'finite','board_actions':{'actor-01':'board-original'}}
            point='a'*64+':2'
            # Canonical public unsigned body, with one input and two outputs.
            raw=(bytes.fromhex('02000000')+b'\x01'+bytes.fromhex('a'*64)[::-1]+(2).to_bytes(4,'little')+b'\x00'+bytes.fromhex('feffffff')+b'\x02'
                +(20000).to_bytes(8,'little')+b'\x01\x51'+(27800).to_bytes(8,'little')+b'\x01\x52'+bytes(4)).hex()
            decoded=decode_transaction(raw,public_body=True);txid=decoded['txid'];vtxo='f'*64+':0';pub='02'+'1'*64;mailbox='02'+'2'*64
            binding={'record_signature_valid':True,'account_child_verified':True,'spk':'fallback','mailbox_pk':mailbox,'child_index':0}
            proof={'financial_pins':PINS,'chain_anchor':txid+':0','authorization_path_valid':True,'signed_path_valid':True,'conditional_steps':0,
                'binding':binding,'expiry_height':200}
            nativecoin={'id':vtxo,'amount_sat':19500,'user_pubkey':pub,'signed_vtxo':'00'}
            data={'board':{'vtxos':[vtxo],'amount':19500,'movement_id':1},'expiry_height':200,'fallback_script':'fallback',
                'evidence':{'coins':[nativecoin]},'sdk_service_fee_sat':500,'planned_mining_fee_sat':2200}
            reply={'action_id':'board-original','status':'ok','actual_fee_sat':None,'data':data}
            scenario=store.db.execute('SELECT id FROM scenario LIMIT 1').fetchone()[0]
            store.queue('board-original','actor-01',scenario,'board',{'amount_sat':20000},4000);action=store.claim({'board'})
            store.finish(action['id'],'completed',reply,None)
            fixture.event('driver_response',{'action_id':action['id'],'response':reply})
            for name,value in [('board_proposal',{'funding_txid':txid,'unsigned_funding_tx':raw,'amount_sat':20000,'planned_mining_fee_sat':2200,
                    'estimated_service_fee_sat':500,'expiry_height':200,'recycle_autosize':False}),
                    ('board_fee_quote',{'source':'SDK chain backend','used_fallback':False,'same_process':True,'regular_confirmation_target':3,'fee_rate_sat_per_kwu':2000}),
                    ('wallet_runtime_parameters',{'run_daemon':False,'daemon_manual_sync':True,'vtxo_exit_margin':12})]:
                fixture.event('driver_evidence',{'action_id':action['id'],'event':name,'data':value})
            store.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',(pub,'actor-01',mailbox,'{}'))
            store.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',(vtxo,pub,19500,hashlib.sha256(b'\0').hexdigest(),'00',canonical(proof)))
            boardtx={'txid':txid,'inputs':[{'outpoint':point,'amount_sat':50000,'script':'original'}],
                'outputs':decoded['outputs'],'fee_sat':2200,'confirmations':1,'blockhash':fixture.tip}
            funded={'batch':'finite:cash','txid':fixture.txid,'financial_pins':PINS,'confirmed_transaction':fixture.transaction}
            fixture.event('fixture_funding_confirmed',funded)
            chain=SimpleNamespace(transaction=lambda txid:copy.deepcopy(boardtx if txid==boardtx['txid'] else fixture.transaction),
                tx=lambda txid:{'txid':txid,'weight':800,'vsize':200})
            funding={'id':'cash','pins':PINS,'boundary_id':'finite'}
            with patch.dict(sys.modules,{'simulator.first_board_readiness':SimpleNamespace(board_plan=lambda store:plan),
                    'simulator.finite_funding':SimpleNamespace(_plan=lambda store:funding)}),patch('simulator.board_adoption._action_pins'):
                value=_origin(store,chain);self.assertEqual(20000,value['anchor_output']['amount_sat']);self.assertEqual(19500,value['net_liability_sat'])
                self.assertEqual(2200,value['mining_fee_sat']);self.assertEqual(500,value['service_charge_sat'])
                chain.tx=lambda txid:{'txid':txid,'weight':decoded['weight'],'vsize':(decoded['weight']+3)//4}
                with self.assertRaisesRegex(ValueError,'weight/rate'):_origin(store,chain)
                chain.tx=lambda txid:{'txid':txid,'weight':800,'vsize':200}
                boardtx['inputs'][0]['amount_sat']=60000
                with self.assertRaisesRegex(ValueError,'original50k'):_origin(store,chain)
                boardtx['inputs'][0]['amount_sat']=50000
                # Reuse the existing resolver to create its real result/event
                # envelope from synthetic public sources, without any SDK call.
                from simulator import unknown_outcomes
                native_sequence=store.db.execute("SELECT sequence FROM event WHERE kind='driver_response' AND json_extract(payload,'$.action_id')=?",(action['id'],)).fetchone()[0]
                public_proof={'actor':'actor-01','actual_fee_sat':2700,'native_response_event_sequence':native_sequence,
                    'chain_transaction':boardtx}
                wrapped={'action_id':action['id'],'status':'ok','data':data,'actual_fee_sat':2700,
                    'resolution':{'original_result':{'reason':'synthetic parked reply'},'proof':public_proof,'scope':'synthetic'}}
                store.db.execute('UPDATE action SET result=?,actual_fee_sat=2700 WHERE id=?',(canonical(wrapped),action['id']))
                with self.assertRaises(ValueError):_origin(store,chain)  # orphan wrapper cannot qualify
                store.db.execute("UPDATE action SET state='outcome_unknown',result=?,actual_fee_sat=NULL WHERE id=?",(canonical({'reason':'synthetic parked reply'}),action['id']))
                with patch('simulator.unknown_outcomes._prove',return_value=(data,public_proof,{'reason':'synthetic parked reply'})):
                    self.assertTrue(unknown_outcomes.resolve(store,action['id']))
                self.assertEqual(19500,_origin(store,chain)['net_liability_sat'])
                resolved=json.loads(store.db.execute("SELECT payload FROM event WHERE kind='unknown_outcome_resolved'").fetchone()[0])
                fixture.event('unknown_outcome_resolved',resolved)
                with self.assertRaisesRegex(ValueError,'unique original Board'):_origin(store,chain)

        finally:fixture.tearDown()


class BoardSerialScopeControls(unittest.TestCase):
    def test_readiness_probes_allow_one_queued_intent_then_bind_actual_dispatch(self):
        import time
        fixture=CashSourceControls();fixture.setUp();store=fixture.store;value=origin()
        try:
            store.db.execute('CREATE TABLE funding_batch(state TEXT)')
            sequence=fixture.event('original_board_adoption_sources_verified',{'origin':value,'financial_pins':PINS,
                'boundary_id':'finite','height':100,'tip_hash':fixture.tip,'observed_at':time.time()})
            proof={'financial_pins':PINS,'boundary_id':'finite','height':100,'tip_hash':fixture.tip,'operation_scope':['sync','snapshot'],
                'board_adoption_scope':{'actor':'actor-01','board_action_id':value['board_action_id'],'source_sequence':sequence,'maximum_fee_sat':0,'args':{}}}
            scenario=store.db.execute('SELECT id FROM scenario LIMIT 1').fetchone()[0]
            store.queue('adopt-snapshot','actor-01',scenario,'snapshot',{},0)
            with patch('simulator.board_adoption._client_state'),patch('simulator.board_adoption._action_pins') as pins:
                validate_adoption_scope(store,fixture.config,proof,operation='snapshot',maximum_fee_sat=0,reserved_action_id=None)
                action=store.claim({'snapshot'})
                validate_adoption_scope(store,fixture.config,proof,operation='snapshot',maximum_fee_sat=0,reserved_action_id=action['id'])
                pins.assert_called_with(store,action['id'],PINS)
                store.db.execute("UPDATE action SET actor_id='actor-02' WHERE id=?",(action['id'],))
                with self.assertRaisesRegex(ValueError,'serial zero-fee'):
                    validate_adoption_scope(store,fixture.config,proof,operation='snapshot',maximum_fee_sat=0,reserved_action_id=action['id'])
                store.db.execute("UPDATE action SET actor_id='actor-01' WHERE id=?",(action['id'],))
                store.finish(action['id'],'outcome_unknown',{'reason':'synthetic retained uncertainty'})
                with self.assertRaisesRegex(ValueError,'serial zero-fee'):
                    validate_adoption_scope(store,fixture.config,proof,operation='snapshot',maximum_fee_sat=0,reserved_action_id=action['id'])
        finally:fixture.tearDown()

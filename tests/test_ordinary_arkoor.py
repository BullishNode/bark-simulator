"""Synthetic finite ordinary controls; no native/live payment qualification."""
import copy
import json
import sqlite3
import tempfile
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from simulator import ordinary_arkoor as ordinary
from simulator.engine import initialize,Lease
from simulator.model import canonical
from simulator.ownership import record_verified
from simulator.store import Store
from tests import account_fixtures
from tests.test_final_campaign import PINS
from tests.owned_activity_fixture import receipt as activity_receipt


class OrdinaryFixture(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name),'synthetic',100000);initialize(self.store)
        from simulator.funding import _funding_table
        _funding_table(self.store)
        self.store.add_snapshot({'observed_at':time.time(),'financial_pins':PINS})
        self.store.db.execute("INSERT INTO meta VALUES ('financial_qualification_required','true')")
        self.value={'id':'ordinary-first','pins':PINS,'boundary_id':'finite','board_action_id':'original-board',
            'actions':{step:'ordinary-'+step for step in ordinary.STEPS},'amount_sat':2000,'maximum_fee_sat':0}
        self.anchor='a'*64+':0';self.parent='b'*64+':0';self.fork='c'*64
        self.destination='synthetic-authenticated-address';self.recipient_pk='02'+'4'*64
        self.origin={'financial_pins':PINS,'boundary_id':'finite','board_action_id':'original-board','actor':'actor-01',
            'vtxo_id':self.parent,'net_liability_sat':19670,'anchor':self.anchor,'expiry_height':200,'exit_margin':0,
            'user_pubkey':'02'+'1'*64,'binding':self.binding('actor-01','02'+'1'*64),'movement_id':1,
            'mining_fee_sat':171,'service_charge_sat':330,'funding_fee_sat':708}
        original={'pins':PINS,'boundary_id':'finite','board_actions':{'actor-01':'original-board'}}
        self.store.db.execute("INSERT INTO meta VALUES ('paused','declaration')")
        with patch('simulator.first_board_readiness.board_plan',return_value=original):ordinary.declare_ordinary_arkoor(self.store,self.value)
        self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        self.coins={};self.movements={}
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def binding(self,actor,pubkey):
        return account_fixtures.proof({'user_pubkey':pubkey,'binding':{'mailbox_pk':'mailbox-'+actor,'spk':'fallback-'+actor}})['binding']
    def action(self,step,data,*,actor=None,args=None,fee=0,complete=True):
        actor,operation,expected=ordinary._expected(self.value,step,{'address':self.destination}) if actor is None else (actor,ordinary._expected(self.value,step,{'address':self.destination})[1],{})
        args=expected if args is None else args
        identity=self.value['actions'][step];self.store.queue(identity,actor,'H01',operation,args,fee)
        row=self.store.claim({operation},action_id=identity)
        if not complete:return row
        self.store.event('driver_request',{'action_id':identity,'request':{'action_id':identity,'operation':operation,'args':args,'maximum_fee_sat':0}})
        response={'action_id':identity,'status':'ok','actual_fee_sat':0,'data':data}
        self.store.event('driver_response',{'action_id':identity,'response':response})
        self.store.finish(identity,'completed',response,0)
        return row
    def address(self):
        data={'address':self.destination,'user_pubkey':self.recipient_pk,'child_index':0,'blinded_mailbox_id':'02'+'11'*32,
            'binding':self.binding('actor-02',self.recipient_pk)}
        row=self.action('address',data)
        proof=account_fixtures.proof({'user_pubkey':self.recipient_pk,'binding':data['binding'],'financial_pins':PINS})
        record_verified(self.store,'actor-02',row['id'],{'objects':[{'kind':'key','proof':proof,'request_origin':data}],
            'movements':[],'financial_pins':PINS})
        return data
    def coin(self,actor,point,amount,pubkey,action_id,state='Spendable'):
        binding=self.binding(actor,pubkey)
        coin=account_fixtures.coin({'id':point,'user_pubkey':pubkey,'amount_sat':amount,'signed_vtxo':'aa',
            'state':state,'expiry_height':200})
        proof=account_fixtures.proof({'id':point,'user_pubkey':pubkey,'amount_sat':amount,'binding':binding,
            'financial_pins':PINS,'signed_path_valid':True,'authorization_path_valid':True,'anchor_confirmations':1,
            'chain_anchor':self.anchor,'expiry_height':200,'conditional_steps':0,
            'path':[{'txid':point.split(':')[0],'output_index':int(point.split(':')[1]),'inputs':[self.parent],'output_amount_sat':amount}]})
        record_verified(self.store,actor,action_id,{'objects':[{'kind':'coin','coin':coin,'proof':proof,
            'signed_hash':__import__('hashlib').sha256(bytes.fromhex(coin['signed_vtxo'])).hexdigest(),'request_binding':binding}],'movements':[],'financial_pins':PINS})
        self.coins[point]=coin
        return coin
    def send(self,estimated_fee=0):
        self.address();identity=self.value['actions']['send'];self.store.queue(identity,'actor-01','H01','send_arkoor',
            {'destination':self.destination,'recipient_actor':'actor-02','amount_sat':2000},0)
        self.store.claim({'send_arkoor'},action_id=identity)
        self.store.event('driver_request',{'action_id':identity,'request':{'action_id':identity,'operation':'send_arkoor',
            'args':{'destination':self.destination,'recipient_actor':'actor-02','amount_sat':2000},'maximum_fee_sat':0}})
        self.store.event('driver_evidence',{'action_id':identity,'event':'arkoor_request','data':{
            'destination':self.destination,'amount_sat':2000,'estimated_fee_sat':estimated_fee,'input_vtxo_ids':[self.parent]}})
        changes=[self.coin('actor-01',self.fork+':'+str(index),8835,'02'+str(index+4)*64,identity) for index in (1,2)]
        movement={'id':'2','subsystem':'bark.arkoor','status':'successful','input_vtxos':[self.parent],
            'output_vtxos':[coin['id'] for coin in changes],'effective_balance_sat':-2000,'offchain_fee_sat':0}
        data={'submitted':'send_arkoor','amount_sat':2000,'estimated_fee_sat':estimated_fee,'actual_fee_sat':0,
            'evidence':{'coins':changes,'movements':[movement]}}
        response={'action_id':identity,'status':'ok','actual_fee_sat':0,'data':data}
        self.store.event('driver_response',{'action_id':identity,'response':response});self.store.finish(identity,'completed',response,0)
        return ordinary._send(self.store,self.origin)
    def graph(self,send=None):
        send=self.send() if send is None else send;prior={'rows':{name:[] for name in ('coins','pending_boards','records','journal_records','links','journal_links','htlcs','rounds')}}
        def node(point,amount,kind='pubkey',spent=None,key=None):
            return {'vtxo_id':point,'amount':amount,'policy_type':kind,'policy':'00'+(key or self.origin['user_pubkey']),
                'anchor_point':self.anchor,'expiry':200,'spend_state':'spent' if spent else 'spendable','oor_spent_txid':spent,
                'spent_in_round':None,'offboarded_in':None,'onchain_spent_txid':None,'onchain_spent_height':None}
        coins=[node(self.anchor,20000,'expiry',self.parent.split(':')[0]),node(self.parent,19670,spent=self.fork),
            node(self.fork+':0',2000,key=self.recipient_pk)]
        coins.extend(node(point,item['amount_sat'],key=item['user_pubkey']) for point,item in send['changes'].items())
        bindings={self.origin['user_pubkey']:self.origin['binding'],self.recipient_pk:send['destination']['binding']}
        bindings.update({item['user_pubkey']:item['proof']['binding'] for item in send['changes'].values()})
        links=[{'user_pubkey':pk,'mailbox_pk':bound['mailbox_pk'],'child_index':bound['child_index']} for pk,bound in bindings.items()]
        rows={**prior['rows'],'coins':coins,'links':links,'journal_links':copy.deepcopy(links)}
        return {'kind':'closed_frontier','database_tables_complete':True,'read_only':True,'inventory_consistent':True,'rows':rows},prior


class PlanControls(OrdinaryFixture):
    def test_exact_plan_idempotence_and_immutable_limit(self):
        self.assertEqual(self.value,ordinary.plan(self.store))
        self.assertFalse(ordinary.declare_ordinary_arkoor(self.store,self.value))
        for change in ({'amount_sat':2001},{'maximum_fee_sat':1},{'amount_sat':True},
                {'actions':{**self.value['actions'],'send':self.value['actions']['address']}}):
            with self.subTest(change=change),self.assertRaises(ValueError):ordinary.declare_ordinary_arkoor(self.store,{**self.value,**change})
    def test_queued_intent_is_authenticated_but_unknown_never_retried(self):
        self.store.queue(self.value['actions']['address'],'actor-02','H01','address',{},0)
        self.assertEqual('address',ordinary._history(self.store,self.origin,allow_queued=True)[0])
        self.store.claim({'address'});self.store.finish(self.value['actions']['address'],'outcome_unknown',{'unknown':True})
        with self.assertRaisesRegex(ValueError,'nonterminal'):ordinary._history(self.store,self.origin,allow_queued=True)
    def test_destination_needs_original_account_child_verification(self):
        data=self.address();self.assertEqual(self.destination,ordinary._destination(self.store,self.value)['address'])
        self.store.db.execute('DELETE FROM owner_key')
        with self.assertRaisesRegex(ValueError,'ownership proof missing'):ordinary._destination(self.store,self.value)
    def test_order_actor_amount_and_second_send_are_refused(self):
        self.action('send',{},complete=False)
        with self.assertRaisesRegex(ValueError,'serial action'):ordinary._history(self.store,self.origin,allow_queued=True)
    def test_signed_two_piece_change_and_zero_native_quote(self):
        send=self.send();self.assertEqual(17670,sum(coin['amount_sat'] for coin in send['changes'].values()))
        self.assertEqual('receiver_sync',ordinary._history(self.store,self.origin)[0])
        row=self.store.db.execute('SELECT result FROM action WHERE id=?',(self.value['actions']['send'],)).fetchone()
        reply=json.loads(row[0]);reply['data']['estimated_fee_sat']=1
        self.store.db.execute('UPDATE action SET result=? WHERE id=?',(canonical(reply),self.value['actions']['send']))
        with self.assertRaisesRegex(ValueError,'original completed'):ordinary._send(self.store,self.origin)


class NonzeroQuoteControls(OrdinaryFixture):
    def test_actual_nonzero_native_quote_refuses_credit(self):
        with self.assertRaisesRegex(ValueError,'native zero-fee quote'):self.send(estimated_fee=1)


class ServerGraphControls(OrdinaryFixture):
    def test_one_physical_root_and_exact_split_liability(self):
        graph,prior=self.graph();result=ordinary._server(graph,prior,self.origin,self.store)
        self.assertEqual(1,result['physical_anchor_count']);self.assertEqual(19670,result['liability_sat'])
        self.assertEqual([self.fork+':0'],result['recipient_coins'])
    def test_extra_root_wrong_recipient_policy_unregistered_and_fee_loss_refuse(self):
        graph,prior=self.graph()
        for mutate in (
            lambda g:g['rows']['coins'].append({**g['rows']['coins'][0],'vtxo_id':'d'*64+':0'}),
            lambda g:g['rows']['coins'][2].update(policy='00'+'02'+'9'*64),
            lambda g:g['rows']['coins'][2].update(spend_state='unregistered'),
            lambda g:g['rows']['coins'][2].update(amount=1999),
            lambda g:g['rows']['coins'][2].update(policy_type='server-htlc-send'),
            lambda g:g['rows']['rounds'].append({'round':'unexpected'})):
            invalid=copy.deepcopy(graph);mutate(invalid)
            with self.subTest(graph=invalid),self.assertRaises(ValueError):ordinary._server(invalid,prior,self.origin,self.store)
    def test_missing_complete_projection_or_foreign_owner_link_refuses(self):
        graph,prior=self.graph();invalid=copy.deepcopy(graph);invalid['database_tables_complete']=False
        with self.assertRaises(ValueError):ordinary._server(invalid,prior,self.origin,self.store)
        graph['rows']['links'].append({'user_pubkey':'foreign','mailbox_pk':'foreign','child_index':3})
        with self.assertRaisesRegex(ValueError,'owner links'):ordinary._server(graph,prior,self.origin,self.store)


class ScopeControls(OrdinaryFixture):
    def proof(self,step='address'):
        source={'financial_pins':PINS,'boundary_id':'finite','origin':self.origin,'height':100,'tip_hash':'tip',
            'observed_at':time.time(),'complete':True,'ordinary_plan_id':self.value['id'],'ordinary_step':step}
        self.store.event(ordinary.KIND,source);sequence=self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
        operation=ordinary._expected(self.value,step,{'address':self.destination})[1]
        return {'financial_pins':PINS,'boundary_id':'finite','height':100,'tip_hash':'tip','operation_scope':[operation],
            'ordinary_arkoor_scope':{'plan_id':self.value['id'],'step':step,'action_id':self.value['actions'][step],'source_sequence':sequence}}
    def test_exact_dispatch_actor_and_action_id_fee_and_consumed_proof(self):
        proof=self.proof();row=self.action('address',{},complete=False)
        with patch.object(ordinary,'_native'):
            ordinary.validate_ordinary_scope(self.store,None,proof,operation='address',maximum_fee_sat=0,reserved_action_id=row['id'])
            for changes in ({'operation':'send_arkoor'},{'maximum_fee_sat':1},{'reserved_action_id':'different'}):
                options={'operation':'address','maximum_fee_sat':0,'reserved_action_id':row['id'],**changes}
                with self.subTest(options=options),self.assertRaises(ValueError):ordinary.validate_ordinary_scope(self.store,None,proof,**options)
            self.store.finish(row['id'],'outcome_unknown',{'unknown':True})
            with self.assertRaises(ValueError):ordinary.validate_ordinary_scope(self.store,None,proof,operation='address',maximum_fee_sat=0,reserved_action_id=row['id'])
    def test_prior_phase_source_cannot_admit_next_send(self):
        proof=self.proof();self.address();proof['ordinary_arkoor_scope'].update(step='send',action_id=self.value['actions']['send']);proof['operation_scope']=['send_arkoor']
        with patch.object(ordinary,'_native'),self.assertRaisesRegex(ValueError,'source context'):
            ordinary.validate_ordinary_scope(self.store,None,proof,operation='send_arkoor',maximum_fee_sat=0,reserved_action_id=None)



class PreflightHookControls(ScopeControls):
    def test_existing_financial_preflight_runs_exact_ordinary_guard(self):
        from simulator.operating_limits import preflight
        proof=self.proof();caps={'sweep':20000,'payout':20000}
        proof.update(observed_at=time.time(),complete=True,effective_fee_ceilings_sat_kvb=caps,
            capital_exposure_msat=100000000,available_fee_funding_msat=75000000,estimated_fee_rate_sat_kvb=1001)
        self.store.event('financial_operating_readiness',proof)
        sequence=self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
        snapshot={'financial_pins':PINS,'height':100,'tip_hash':'tip','operating_readiness_sequence':sequence}
        limits={'pins':PINS,'boundary_id':'finite','operation_fee_paths':{'address':['sweep','payout']},
            'fee_ceilings_sat_kvb':caps,'capital_exposure_msat':100000000,'fee_budgets_msat':{'ordinary':60000000,'urgent':15000000},'per_action_fee_sat':4000}
        with patch('simulator.identity_bootstrap.pending',return_value=False),patch('simulator.operating_limits.envelope',return_value=limits),patch.object(ordinary,'_native'):
            self.assertTrue(preflight(self.store,None,snapshot,operation='address')['allowed'])
            wrong=self.action('address',{},actor='actor-01',complete=False)
            with self.assertRaisesRegex(ValueError,'recipient address action'):
                preflight(self.store,None,snapshot,operation='address',reserved_action_id=wrong['id'])


class NativeAdoptionControls(OrdinaryFixture):
    def setUp(self):
        super().setUp();self.send_record=self.send();self.root=Path(self.tmp.name)/'wallets';self.root.mkdir(mode=0o700)
        self.paths={}
        definitions={'bark_vtxo':'id TEXT,amount_sat INTEGER,expiry_height INTEGER',
            'bark_vtxo_state':'id INTEGER,vtxo_id TEXT,state_kind TEXT',
            'bark_movements':'id INTEGER,status TEXT,subsystem_name TEXT,effective_balance INTEGER,offchain_fee INTEGER',
            'bark_movements_output_vtxos':'movement_id INTEGER,vtxo_id TEXT',
            'bark_movements_input_vtxos':'movement_id INTEGER,vtxo_id TEXT'}
        for actor in ('actor-01','actor-02','actor-04'):
            directory=self.root/actor;directory.mkdir(mode=0o700);path=directory/'db.sqlite';self.paths[actor]=path
            conn=sqlite3.connect(path);conn.execute('CREATE TABLE migrations(value INTEGER)');conn.execute('INSERT INTO migrations VALUES (43)')
            for table in ordinary.ECONOMIC_TABLES|ordinary.METADATA_TABLES:
                conn.execute('CREATE TABLE '+table+'('+definitions.get(table,'dummy INTEGER')+')')
            if actor=='actor-01':
                for index,(point,amount) in enumerate([(self.parent,19670),*[(point,item['amount_sat']) for point,item in self.send_record['changes'].items()]]):
                    conn.execute('INSERT INTO bark_vtxo VALUES (?,?,?)',(point,amount,200))
                    conn.execute('INSERT INTO bark_vtxo_state VALUES (?,?,?)',(index,point,'Spent' if point==self.parent else 'Spendable'))
                conn.execute("INSERT INTO bark_movements VALUES (1,'successful','bark.board',19670,330)")
                conn.execute("INSERT INTO bark_movements VALUES (2,'successful','bark.arkoor',-2000,0)")
                conn.execute('INSERT INTO bark_movements_output_vtxos VALUES (?,?)',(1,self.parent))
                conn.execute('INSERT INTO bark_movements_input_vtxos VALUES (?,?)',(2,self.parent))
                for point in self.send_record['changes']:conn.execute('INSERT INTO bark_movements_output_vtxos VALUES (?,?)',(2,point))
            conn.commit();conn.close();path.chmod(0o600)
        self.config=SimpleNamespace()
        value={'pins':PINS,'wallet_root':str(self.root),'actors':['actor-01','actor-02','actor-04']}
        self.bootstrap={'declaration':value,'filesystem':{'synthetic':'root'}}
    def dependencies(self):
        stack=ExitStack();stack.enter_context(patch('simulator.identity_bootstrap.declaration',return_value=self.bootstrap))
        stack.enter_context(patch('simulator.identity_bootstrap._context'))
        stack.enter_context(patch('simulator.identity_bootstrap._sole_writer'))
        stack.enter_context(patch('simulator.identity_bootstrap._root',return_value=self.bootstrap['filesystem']))
        return stack
    def adopted(self):
        point=self.fork+':0'
        movement={'id':'1','subsystem':'bark.arkoor','status':'successful','input_vtxos':[],
            'output_vtxos':[point],'effective_balance_sat':2000,'offchain_fee_sat':0}
        row=self.action('receiver_sync',{'receive_count_before':0,'receive_count_after':0})
        self.coin('actor-02',point,2000,self.recipient_pk,row['id'])
        record_verified(self.store,'actor-02',row['id'],{'objects':[],'movements':[movement],'financial_pins':PINS})
        conn=sqlite3.connect(self.paths['actor-02'])
        conn.execute('INSERT INTO bark_vtxo VALUES (?,?,?)',(point,2000,200));conn.execute('INSERT INTO bark_vtxo_state VALUES (1,?,?)',(point,'Spendable'))
        conn.execute("INSERT INTO bark_movements VALUES (1,'successful','bark.arkoor',2000,0)")
        conn.execute('INSERT INTO bark_movements_output_vtxos VALUES (1,?)',(point,));conn.commit();conn.close()
    def test_real_readonly_empty_receiver_then_signed_adoption_conserves_once(self):
        with self.dependencies():
            result=ordinary._native(self.store,self.config,self.origin,100)
            self.assertEqual(17670,result['actor-01']['spendable_sat']);self.assertFalse(result['actor-02']['recipient_adopted'])
        self.adopted()
        with self.dependencies():
            result=ordinary._native(self.store,self.config,self.origin,100)
            self.assertEqual(2000,result['actor-02']['spendable_sat']);self.assertTrue(result['actor-02']['recipient_adopted'])
            self.assertNotIn('signed_vtxo',canonical(result))
    def test_unrelated_checkpoint_inflated_receiver_wrong_state_or_near_expiry_refuse(self):
        self.adopted()
        conn=sqlite3.connect(self.paths['actor-02']);conn.execute('UPDATE bark_vtxo SET amount_sat=2001');conn.commit();conn.close()
        with self.dependencies(),self.assertRaisesRegex(ValueError,'coins differ'):ordinary._native(self.store,self.config,self.origin,100)
        conn=sqlite3.connect(self.paths['actor-02']);conn.execute('UPDATE bark_vtxo SET amount_sat=2000');conn.execute('INSERT INTO bark_wallet_action_checkpoint VALUES (1)');conn.commit();conn.close()
        with self.dependencies(),self.assertRaisesRegex(ValueError,'checkpoint'):ordinary._native(self.store,self.config,self.origin,100)
        with self.dependencies(),self.assertRaisesRegex(ValueError,'near expiry'):ordinary._native(self.store,self.config,self.origin,195)

    def terminal(self):
        graph,prior=self.graph(self.send_record)
        server=ordinary._server(graph,prior,self.origin,self.store)
        self.adopted()
        self.store.queue('original-board','actor-01','H01','board',{'amount_sat':20000},4000)
        self.store.claim({'board'},action_id='original-board')
        self.store.finish('original-board','completed',{'synthetic':'original-board'},501)
        self.coin('actor-01',self.parent,19670,self.origin['user_pubkey'],'original-board',state='Spent')
        self.action('receiver_snapshot',{'evidence':{'coins':[self.coins[self.fork+':0']]}})
        self.action('sender_snapshot',{'evidence':{'coins':[self.coins[point] for point in [self.parent,*self.send_record['changes']]]}})
        source={'financial_pins':PINS,'boundary_id':'finite','ordinary_plan_id':self.value['id'],'ordinary_step':None,
            'origin':self.origin,'height':100,'tip_hash':'tip','observed_at':time.time(),'complete':True,'server':server,
            'physical_total_sat':664575,'physical_assets':{self.anchor:{'amount_sat':20000,'script':'anchor'},'cash:0':{'amount_sat':644575,'script':'cash'}}}
        source['descriptor_ranges']=[]
        self.origin['anchor_output']={'script':'anchor'}
        source['mempool']=activity_receipt(self.store,source,'board_backing')
        self.store.event(ordinary.KIND,source);sequence=self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
        chain=SimpleNamespace(identity=lambda:{'initialblockdownload':False,'blocks':100,'bestblockhash':'tip'},
            call=lambda *args:{'confirmations':1,'value':'0.00020000','scriptPubKey':{'hex':'anchor'}})
        return source,sequence,chain
    def test_terminal_existing_receipt_api_requires_both_adoptions_and_is_once_only(self):
        source,sequence,chain=self.terminal()
        with self.dependencies(),patch.object(ordinary.backing,'_origin',return_value=self.origin):
            first=ordinary.record_ordinary_journey(self.store,self.config,chain,source_sequence=sequence)
            second=ordinary.record_ordinary_journey(self.store,self.config,chain,source_sequence=sequence)
        self.assertEqual(first,second);self.assertEqual(2000,first['amount_sat']);self.assertEqual(1,first['physical_anchor_count'])
        self.assertEqual(1,self.store.db.execute("SELECT count(*) FROM event WHERE kind='ark_transfer_verified'").fetchone()[0])
        self.assertEqual(1,self.store.db.execute("SELECT count(*) FROM event WHERE kind='ordinary_arkoor_journey_verified'").fetchone()[0])

    def test_terminal_missing_actual_backing_or_inflated_physical_assets_never_credits(self):
        source,sequence,chain=self.terminal()
        with self.dependencies(),patch.object(ordinary.backing,'_origin',return_value=self.origin):
            unavailable=SimpleNamespace(identity=chain.identity,call=lambda *args:None)
            with self.assertRaisesRegex(ValueError,'backing unavailable'):
                ordinary.record_ordinary_journey(self.store,self.config,unavailable,source_sequence=sequence)
            source['physical_assets']['another-root:0']={'amount_sat':20000,'script':'foreign'}
            self.store.event(ordinary.KIND,source);changed=self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
            with self.assertRaisesRegex(ValueError,'physical capital'):
                ordinary.record_ordinary_journey(self.store,self.config,chain,source_sequence=changed)
        self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM event WHERE kind='ark_transfer_verified'").fetchone()[0])
    def test_terminal_claimed_receipt_without_native_adoption_does_not_credit(self):
        source,sequence,chain=self.terminal()
        conn=sqlite3.connect(self.paths['actor-02']);conn.execute("UPDATE bark_vtxo_state SET state_kind='Locked'");conn.commit();conn.close()
        with self.dependencies(),patch.object(ordinary.backing,'_origin',return_value=self.origin),self.assertRaisesRegex(ValueError,'terminal state'):
            ordinary.record_ordinary_journey(self.store,self.config,chain,source_sequence=sequence)
        self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM event WHERE kind='ark_transfer_verified'").fetchone()[0])


class HistoricalObservationControls(OrdinaryFixture):
    def historical(self,identity,actor,operation,*,fee=0,state='completed',data_override=None):
        self.store.db.execute("DELETE FROM meta WHERE key='financial_qualification_required'")
        self.store.queue(identity,actor,'H01',operation,{},fee);self.store.claim({operation},action_id=identity)
        data={'evidence':{'coins':[],'movements':[]},'vtxos':[]}
        if operation=='sync':data.update(receive_count_before=0,receive_count_after=0)
        if data_override:data.update(data_override)
        self.store.event('driver_request',{'action_id':identity,'request':{'action_id':identity,'operation':operation,'args':{},'maximum_fee_sat':fee}})
        reply={'action_id':identity,'status':'ok','actual_fee_sat':fee,'data':data}
        self.store.event('driver_response',{'action_id':identity,'response':reply})
        self.store.finish(identity,state,reply,fee if state=='completed' else None)
        self.store.db.execute("INSERT INTO meta VALUES ('financial_qualification_required','true')")
    def original_board(self):
        self.store.queue('original-board','actor-01','H01','board',{'amount_sat':20000},4000)
        self.store.claim({'board'},action_id='original-board');self.store.finish('original-board','completed',{'synthetic':'board'},501)
    def test_original_bootstrap_and_cash_reads_remain_unqualified_but_do_not_block_new_scope(self):
        for actor in ('actor-01','actor-02','actor-04'):
            for operation in ('create','sync','snapshot'):self.historical('old-'+actor+'-'+operation,actor,operation)
        self.original_board()
        before=[dict(row) for row in self.store.db.execute("SELECT * FROM event WHERE kind IN ('action_intent','action_dispatched') AND json_extract(payload,'$.action_id') LIKE 'old-%'")]
        self.assertEqual('address',ordinary._history(self.store,self.origin)[0])
        after=[dict(row) for row in self.store.db.execute("SELECT * FROM event WHERE kind IN ('action_intent','action_dispatched') AND json_extract(payload,'$.action_id') LIKE 'old-%'")]
        self.assertEqual(before,after)
        self.assertTrue(all('financial_pins' not in json.loads(row['payload']) for row in after))
    def test_late_unpinned_read_and_old_nonzero_or_money_or_unknown_refuse(self):
        self.original_board();self.historical('late-read','actor-02','snapshot')
        with self.assertRaisesRegex(ValueError,'pins differ'):ordinary._history(self.store,self.origin)
    def test_old_nonzero_observation_refuses(self):
        self.historical('old-cost','actor-02','snapshot',fee=1);self.original_board()
        with self.assertRaisesRegex(ValueError,'unrelated'):ordinary._history(self.store,self.origin)
    def test_old_monetary_operation_and_unknown_refuse(self):
        self.historical('old-money','actor-02','send_arkoor');self.original_board()
        with self.assertRaisesRegex(ValueError,'unrelated'):ordinary._history(self.store,self.origin)
    def test_original_unknown_observation_refuses(self):
        self.historical('old-unknown','actor-02','snapshot',state='outcome_unknown');self.original_board()
        with self.assertRaisesRegex(ValueError,'unrelated'):ordinary._history(self.store,self.origin)

    def test_original_read_reporting_ark_assets_is_not_an_empty_legacy_observation(self):
        self.historical('old-assets','actor-02','snapshot',data_override={'balance':{'spendable_sat':2000}});self.original_board()
        with self.assertRaisesRegex(ValueError,'monetary evidence'):ordinary._history(self.store,self.origin)

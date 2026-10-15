"""Controller scenario limits only; no native refresh or live qualification."""
import copy
import hashlib
import json
import unittest
from tests import test_exploratory as fixture
from simulator import exploratory as e
from simulator.model import canonical

class AdoptionScopeTests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.ExploratoryTests();self.f.setUp();self.s=self.f.store
        self.old=copy.deepcopy(self.f.d);e.declare(self.s,self.old)
        proof=self.f.checked();self.s.event('exploratory_operating_readiness',proof)
        snap={'height':proof['height'],'tip_hash':proof['tip_hash'],'exploratory_readiness_sequence':self.s.db.execute('SELECT MAX(sequence) FROM event').fetchone()[0]}
        self.closed=e.close(self.s,snap,'sealed original scenario',now=self.f.now)
        raw=self.s.get_meta(e.KEY)
        self.d={**self.old,'id':'new-adoption','started_at':self.f.now-1,'deadline':self.f.now+1700,
            'per_action_fee_sat':500,'fee_budget_sat':5500,'capital_budget_sat':300000}
        self.inputs=['11'*32+':0','22'*32+':0']
        self.d['adoption']={'actor':'actor-01','input_coin_ids':self.inputs,'input_total_sat':26670,
            'input_expiry_height':326521,'maximum_syncs':6,'operator_fee_budget_sat':5000,'client_fee_budget_sat':500,
            'opening_fee_by_txid':{'a'*64:500},'opening_source_sha256':hashlib.sha256(canonical(self.f.p).encode()).hexdigest(),
            'previous_declaration_sha256':hashlib.sha256(raw.encode()).hexdigest(),
            'previous_closure_sha256':hashlib.sha256(canonical(self.closed).encode()).hexdigest(),'previous_action_ids':[]}
    def tearDown(self):self.f.tearDown()
    def declare(self):return e.declare_adoption(self.s,self.d,self.f.p,self.f.chain,now=self.f.now)
    def proof(self):
        p=e.checked_source(self.d,self.f.p,self.f.chain,now=self.f.now);self.s.event('exploratory_operating_readiness',p)
        return {'height':p['height'],'tip_hash':p['tip_hash'],'exploratory_readiness_sequence':self.s.db.execute('SELECT MAX(sequence) FROM event').fetchone()[0]}
    def test_new_declaration_preserves_original_closure_qualified_counter_and_source(self):
        old=self.s.get_meta(e.KEY);closed=self.s.get_meta(e.KEY+':closed:'+hashlib.sha256(old.encode()).hexdigest())
        self.declare();self.assertEqual(old,self.s.get_meta(e.KEY));self.assertEqual(closed,self.s.get_meta(e.KEY+':closed:'+hashlib.sha256(old.encode()).hexdigest()))
        self.assertEqual('0',self.s.get_meta('qualified_campaign_active_seconds'));self.assertEqual('true',self.s.get_meta('financial_qualification_required'))
        self.assertEqual('new-adoption',e.scope(self.s)['id']);self.s.verify_event_chain()
    def test_substituted_history_opening_packet_and_fee_baseline_are_refused(self):
        original=copy.deepcopy(self.d)
        for key,value in [('previous_declaration_sha256','f'*64),('previous_closure_sha256','f'*64),('previous_action_ids',['missing']),('opening_source_sha256','f'*64),('opening_fee_by_txid',{'a'*64:499})]:
            self.d=copy.deepcopy(original);self.d['adoption'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.declare()
        self.d=original;self.assertIsNone(e.scope(self.s))
    def test_new_fees_have_separate_5000_cap_and_cannot_hide_changed_or_missing_history(self):
        self.declare();p=e.checked_source(self.d,self.f.p,self.f.chain,now=self.f.now)
        self.assertEqual(0,p['scoped_operator_miner_fees_sat']);self.assertEqual(500,p['miner_fees_sat'])
        self.f.p['postgres_financial_rows']['funding_txids']=['b'*64]
        self.assertEqual(500,e.checked_source(self.d,self.f.p,self.f.chain,now=self.f.now)['scoped_operator_miner_fees_sat'])
        old=self.f.chain.transaction
        self.f.chain.tx=lambda txid:{'vsize':2000}
        self.f.chain.transaction=lambda txid:{'fee_sat':5001 if txid=='b'*64 else 500}
        with self.assertRaisesRegex(ValueError,'operator miner budget'):e.checked_source(self.d,self.f.p,self.f.chain,now=self.f.now)
        self.f.chain.transaction=lambda txid:{'fee_sat':499}
        with self.assertRaisesRegex(ValueError,'historical'):e.checked_source(self.d,self.f.p,self.f.chain,now=self.f.now)
        self.f.chain.transaction=old
    def test_only_original_actor_and_refresh_or_bounded_zero_fee_observations_are_admitted(self):
        self.declare();snapshot=self.proof()
        for op in ['board','send_arkoor','pay_invoice','invoice','exit','refresh','refresh_scheduled','address','create']:
            with self.subTest(op=op),self.assertRaises(ValueError):e.admit(self.s,'actor-01',op,{})
        e.admit(self.s,'actor-02','sync',{});e.admit(self.s,'actor-02','snapshot',{})
        with self.assertRaises(ValueError):e.admit(self.s,'actor-02','refresh_delegated',{'input_vtxo_ids':self.inputs})
        with self.assertRaises(ValueError):e.admit(self.s,'actor-03','sync',{})
        with self.assertRaises(ValueError):e.admit(self.s,'actor-01','sync',{'receive_payment_hash':'11'*32})
        with self.assertRaisesRegex(ValueError,'zero new fee'):e.preflight(self.s,self.f.config,snapshot,operation='progression',maximum_fee_sat=1,now=self.f.now)
        self.s.db.execute("DELETE FROM meta WHERE key='paused'")
        for i in range(6):self.s.queue('read-'+str(i),'actor-01','H01','sync',{},0)
        with self.assertRaisesRegex(ValueError,'sync count'):e.admit(self.s,'actor-01','sync',{})
    def test_exact_two_signed_current_holdings_are_required_before_first_refresh(self):
        self.declare();args={'input_vtxo_ids':self.inputs}
        with self.assertRaisesRegex(ValueError,'complete spendable set'):e.admit(self.s,'actor-01','refresh_delegated',args)
        key='02'+'11'*32;self.s.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',(key,'actor-01','mailbox','{}'))
        self.s.db.execute("DELETE FROM meta WHERE key='paused'")
        self.s.queue('snapshot-original','actor-01','H01','snapshot',{},0)
        for coin in self.inputs:
            proof={'id':coin,'amount_sat':13335,'server_pubkey':self.d['server_pubkey'],'user_pubkey':key,
                'expiry_height':326521,'signed_path_valid':True,'conditional_steps':0,'anchor_confirmations':1,
                'binding':{'record_signature_valid':True,'key_link_signature_valid':True,'seq':7,'mailbox_pk':'mailbox','spk':'0014'+'11'*20}}
            self.s.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',(coin,key,13335,'hash','wire',canonical(proof)))
            self.s.db.execute('INSERT INTO coin_observation VALUES (?,?,?,?)',(coin,'snapshot-original','Spendable',self.f.now))
        e.admit(self.s,'actor-01','refresh_delegated',args)
        self.s.queue('one-refresh','actor-01','H17','refresh_delegated',args,500)
        with self.assertRaisesRegex(ValueError,'one original'):e.admit(self.s,'actor-01','refresh_delegated',args)
        self.s.db.execute("UPDATE action SET state='failed' WHERE id='one-refresh'")
        with self.assertRaisesRegex(ValueError,'never retry'):e.admit(self.s,'actor-01','refresh_delegated',args)
    def test_adoption_preserves_ordinary_headroom_and_rejects_adoption_after_original_expiry(self):
        self.declare()
        for declaration in [self.old,self.d]:
            self.f.p['postgres_financial_rows']['earliest_expiry_height']=1030
            with self.assertRaisesRegex(ValueError,'thirty'):e.checked_source(declaration,self.f.p,self.f.chain,now=self.f.now)
            self.f.p['postgres_financial_rows']['earliest_expiry_height']=1031
            e.checked_source(declaration,self.f.p,self.f.chain,now=self.f.now)
        self.d['adoption']['input_expiry_height']=1000
        with self.assertRaisesRegex(ValueError,'original signed expiry'):e.checked_source(self.d,self.f.p,self.f.chain,now=self.f.now)
    def test_real_engine_readiness_uses_new_scoped_proof_without_global_or_clock_claim(self):
        from types import SimpleNamespace
        from simulator.engine import Engine
        self.declare();snapshot=self.proof();snapshot.update(observed_at=self.f.now,stable_tip=True,initial_block_download=False,server_status={'status':'running'})
        config=SimpleNamespace(architecture_profile='two_step_per_key',trace_enabled=False,workload='none',recovery_command=())
        engine=Engine(config,self.s)
        self.assertTrue(engine.ready_for_actions(snapshot));self.assertEqual('0',self.s.get_meta('qualified_campaign_active_seconds'))
        self.s.db.execute("UPDATE meta SET value='17' WHERE key='qualified_campaign_active_seconds'")
        self.assertFalse(engine.ready_for_actions(snapshot))
        self.assertEqual('17',self.s.get_meta('qualified_campaign_active_seconds'))
    def test_new_scope_refuses_positive_clock_or_unknown_without_erasing_evidence(self):
        self.s.db.execute("UPDATE meta SET value='17' WHERE key='qualified_campaign_active_seconds'")
        with self.assertRaises(ValueError):self.declare()
        self.assertEqual('17',self.s.get_meta('qualified_campaign_active_seconds'));self.assertIsNone(e.scope(self.s))
        self.s.db.execute("UPDATE meta SET value='0' WHERE key='qualified_campaign_active_seconds'")
        self.s.db.execute("DELETE FROM meta WHERE key='paused'")
        self.s.queue('uncertain','actor-01','H01','sync',{},0);self.s.db.execute("UPDATE action SET state='outcome_unknown' WHERE id='uncertain'")
        self.s.db.execute("INSERT INTO meta VALUES ('paused','unknown preserved')")
        with self.assertRaises(ValueError):self.declare()
        self.assertEqual('outcome_unknown',self.s.db.execute("SELECT state FROM action WHERE id='uncertain'").fetchone()[0])

    def test_economic_refresh_cannot_use_the_observation_only_scope_without_exitability_producer(self):
        self.declare();snapshot=self.proof()
        e.preflight(self.s,self.f.config,snapshot,operation='sync',maximum_fee_sat=0,now=self.f.now)
        with self.assertRaisesRegex(ValueError,'exitability policy'):
            e.preflight(self.s,self.f.config,snapshot,operation='refresh_delegated',maximum_fee_sat=500,now=self.f.now)

    def historical_board(self):
        proof=self.s.db.execute("SELECT sequence,payload FROM event WHERE kind='exploratory_operating_readiness'").fetchone()
        source=json.loads(proof['payload']);snapshot={'height':source['height'],'tip_hash':source['tip_hash'],
            'exploratory_readiness_sequence':proof['sequence']}
        cursor=self.s.db.execute('INSERT INTO snapshot(observed_at,payload) VALUES (?,?)',(self.f.now,canonical(snapshot)))
        context={'height':snapshot['height'],'tip_hash':snapshot['tip_hash'],'snapshot_id':cursor.lastrowid}
        self.s.db.execute("DELETE FROM meta WHERE key='paused'")
        self.s.queue('historical-board','actor-01','H01','board',{'amount_sat':28000},self.old['per_action_fee_sat'])
        request={'operation':'board','action_id':'historical-board','args':{'amount_sat':28000},
            'expected_server_pubkey':self.old['server_pubkey'],'maximum_fee_sat':self.old['per_action_fee_sat']}
        self.s.event('driver_request',{'action_id':'historical-board','request':request,'context':context})
        return self.s.db.execute("SELECT * FROM action WHERE id='historical-board'").fetchone(),context

    def test_historical_board_cap_is_bound_to_original_request_snapshot_and_checked_scope(self):
        action,context=self.historical_board();bound=e._original_board_scope(self.s,action)
        self.assertEqual(1000,bound['original_scope_fee_limit_sat']);self.assertEqual('historical-board',bound['original_action_id'])
        self.assertEqual(500,self.d['per_action_fee_sat']);self.s.verify_event_chain()
        self.s.db.execute("UPDATE snapshot SET payload=? WHERE id=?",(canonical({'height':999,'tip_hash':'f'*64,
            'exploratory_readiness_sequence':bound['original_readiness_sequence']}),context['snapshot_id']))
        with self.assertRaisesRegex(ValueError,'differs'):e._original_board_scope(self.s,action)

    def test_missing_substituted_or_duplicate_original_native_board_request_is_refused(self):
        action,context=self.historical_board()
        row=self.s.db.execute("SELECT * FROM event WHERE kind='driver_request'").fetchone();original=json.loads(row['payload'])
        variants=[]
        for field,value in [('maximum_fee_sat',500),('expected_server_pubkey','02'+'f'*64),('operation','sync'),('action_id','different')]:
            changed=copy.deepcopy(original);changed['request'][field]=value;variants.append(changed)
        changed=copy.deepcopy(original);changed['context']['snapshot_id']=99999;variants.append(changed)
        for changed in variants:
            self.s.db.execute('UPDATE event SET payload=? WHERE sequence=?',(canonical(changed),row['sequence']))
            with self.subTest(changed=changed),self.assertRaises(ValueError):e._original_board_scope(self.s,action)
        self.s.db.execute('UPDATE event SET payload=? WHERE sequence=?',(row['payload'],row['sequence']))
        self.s.event('driver_request',original)
        with self.assertRaisesRegex(ValueError,'unique'):e._original_board_scope(self.s,action)

    def test_historical_override_cannot_raise_an_ordinary_or_new_board_limit(self):
        proposal={'planned_mining_fee_sat':500,'estimated_service_fee_sat':0,'maximum_fee_sat':1000,
            'original_scope_fee_limit_sat':1000,'original_action_id':'not-in-original-history'}
        self.f.chain.tx=lambda txid:{'vsize':100}
        d={**self.d,'client_board_fee_ceiling_sat_kvb':None}
        with self.assertRaisesRegex(ValueError,'affordable proposal'):
            e.checked_source(d,self.f.p,self.f.chain,now=self.f.now,client_board_proposals={'a'*64:proposal})
        d.pop('adoption')
        with self.assertRaisesRegex(ValueError,'affordable proposal'):
            e.checked_source(d,self.f.p,self.f.chain,now=self.f.now,client_board_proposals={'a'*64:proposal})

if __name__=='__main__':unittest.main()

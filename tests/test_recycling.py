import asyncio,json,time,unittest
from decimal import Decimal
from simulator.continuous import schedule
from tests import test_continuous as fixtures

class RecyclingTests(unittest.TestCase):
    setUp=fixtures.ContinuousTests.setUp
    tearDown=fixtures.ContinuousTests.tearDown
    detail=fixtures.ContinuousTests.detail
    action=fixtures.ContinuousTests.action

    def source(self,amount=6481,confirmations=2,actor='actor-04'):
        self.detail(actor,board_submitted=True,onchain_confirmed_sat=amount)
        self.s.queue('recent-sync',actor,'H01','sync',{},0)
        self.s.db.execute("UPDATE action SET state='completed',actual_fee_sat=0 WHERE id='recent-sync'")
        source={'actor':actor,'outpoint':'a'*64+':1','script':'0014'+'b'*40,
            'amount_sat':amount,'kind':'confirmed_own_collaborative_exit',
            'source_action_id':'exit','confirmations':confirmations,'checked_at':time.time()}
        self.s.event('recycle_source_unspent_verified',source)
        return source

    def test_actual_confirmed_exit_can_be_reboarded_with_fresh_source_id(self):
        source=self.source()
        schedule(self.s,self.c,self.snapshot)
        action=self.action()
        self.assertIsNotNone(action,'a dry online wallet currently never reboards its own return')
        self.assertEqual('board',action['operation'])
        args=json.loads(action['args'])
        self.assertEqual(5998,args['amount_sat'])
        self.assertEqual(source['outpoint'],args['recycle_source']['outpoint'])
        self.assertEqual(3000,args['minimum_ark_amount_sat'])
        self.assertEqual(1,self.s.db.execute("SELECT COUNT(*) FROM event WHERE kind='recycle_intent'").fetchone()[0])
        self.s.verify_event_chain()

    def test_never_reboard_uncertain_or_absent_source(self):
        self.source(actor='actor-09');self.s.set_online('actor-09',False)
        schedule(self.s,self.c,self.snapshot);self.assertIsNone(self.action())

    def test_unconfirmed_and_stale_sources_do_not_recycle(self):
        self.source(confirmations=0)
        schedule(self.s,self.c,self.snapshot);self.assertIsNone(self.action())

    def test_generic_confirmed_balance_is_not_recycling_evidence(self):
        self.detail('actor-04',board_submitted=True,onchain_confirmed_sat=20000)
        self.s.queue('recent-sync','actor-04','H01','sync',{},0)
        self.s.db.execute("UPDATE action SET state='completed',actual_fee_sat=0 WHERE id='recent-sync'")
        schedule(self.s,self.c,self.snapshot);self.assertIsNone(self.action())

    def test_finite_fee_exhaustion_is_reported_without_topup(self):
        self.source(amount=2500)
        schedule(self.s,self.c,self.snapshot);self.assertIsNone(self.action())
        event=self.s.db.execute("SELECT payload FROM event WHERE kind='recycle_fee_exhaustion'").fetchone()
        self.assertIsNotNone(event,'dry returned capital is currently silent')
        self.assertEqual(2500,json.loads(event[0])['confirmed_source_sat'])
        schedule(self.s,self.c,self.snapshot)
        self.assertEqual(1,self.s.db.execute("SELECT COUNT(*) FROM event WHERE kind='recycle_fee_exhaustion'").fetchone()[0])

    def test_source_is_never_used_twice_even_after_lost_reply(self):
        self.source();schedule(self.s,self.c,self.snapshot)
        action=self.action();self.assertIsNotNone(action)
        self.s.db.execute("UPDATE action SET state='outcome_unknown' WHERE id=?",(action['id'],))
        for _ in range(5):schedule(self.s,self.c,self.snapshot)
        self.assertEqual(1,self.s.db.execute("SELECT COUNT(*) FROM event WHERE kind='recycle_intent'").fetchone()[0])

    def test_recycle_intent_and_action_roll_back_together(self):
        self.source();original=self.s._event
        def crash(kind,payload):
            if kind=='recycle_intent':raise RuntimeError('crash before commit')
            return original(kind,payload)
        self.s._event=crash
        with self.assertRaises(RuntimeError):schedule(self.s,self.c,self.snapshot)
        self.assertIsNone(self.action())
        self.assertFalse(self.s.db.execute("SELECT 1 FROM event WHERE kind='recycle_intent'").fetchone())
        self.s._event=original;self.s.verify_event_chain()

    def test_source_claim_survives_failed_board_without_blind_retry(self):
        self.source();schedule(self.s,self.c,self.snapshot);action=self.action()
        self.s.db.execute("UPDATE action SET state='blocked',updated_at=? WHERE id=?",(time.time(),action['id']))
        for _ in range(5):schedule(self.s,self.c,self.snapshot)
        self.assertIsNone(self.action())
        self.assertEqual(1,self.s.db.execute("SELECT COUNT(*) FROM event WHERE kind='recycle_intent'").fetchone()[0])

    def test_pending_coin_and_sync_debt_do_not_start_another_board(self):
        self.source();self.detail('actor-04',board_submitted=True,onchain_confirmed_sat=6481,coin_ids=['unknown'])
        schedule(self.s,self.c,self.snapshot);self.assertIsNone(self.action())
        self.detail('actor-04',board_submitted=True,onchain_confirmed_sat=6481,needs_sync=True)
        schedule(self.s,self.c,self.snapshot);self.assertIsNone(self.action())

    def test_reconcile_exact_source_principal_fees_and_change_once(self):
        from simulator.recycling import reconcile
        source=self.source();schedule(self.s,self.c,self.snapshot);action=self.action()
        tx={'txid':'c'*64,'confirmations':2,'inputs':[{'outpoint':source['outpoint'],'amount_sat':6481,'script':source['script']}],
            'outputs':[{'amount_sat':5981}]}
        self.s.event('client_fee_reconciled',{'action_id':action['id'],'chain_transaction':tx,'funded_amount_sat':5981,'service_charge_sat':330,'mining_fee_sat':500})
        reconcile(self.s);reconcile(self.s)
        p=json.loads(self.s.db.execute("SELECT payload FROM event WHERE kind='recycle_confirmed'").fetchone()[0])
        self.assertEqual(5651,p['new_ark_principal_sat']);self.assertEqual(0,p['own_onchain_change_sat'])
        self.assertEqual(0,p['external_injection_sat'])
        self.assertEqual(1,self.s.db.execute("SELECT COUNT(*) FROM event WHERE kind='recycle_confirmed'").fetchone()[0])

    def test_confirmed_board_using_other_funding_is_never_called_recycling(self):
        from simulator.recycling import reconcile
        from simulator.model import InvariantError
        self.source();schedule(self.s,self.c,self.snapshot);action=self.action()
        tx={'txid':'c'*64,'confirmations':2,'inputs':[{'outpoint':'d'*64+':0','amount_sat':6481,'script':'other'}],
            'outputs':[{'amount_sat':4481},{'amount_sat':1500}]}
        self.s.event('client_fee_reconciled',{'action_id':action['id'],'chain_transaction':tx,'service_charge_sat':330,'mining_fee_sat':500})
        with self.assertRaises(InvariantError):reconcile(self.s)
        self.assertFalse(self.s.db.execute("SELECT 1 FROM event WHERE kind='recycle_confirmed'").fetchone())

    def exit_evidence(self,online=True):
        self.detail('actor-04',board_submitted=True,onchain_confirmed_sat=6481)
        self.s.set_online('actor-04',online)
        script='0014'+'b'*40
        self.s.queue('exit','actor-04','H33','offboard_all',{},10000)
        self.s.db.execute("UPDATE action SET state='completed',result=? WHERE id='exit'",(json.dumps({'data':{'destination_script':script}}),))
        self.s.event('client_fee_reconciled',{'action_id':'exit','net_sat':6481,
            'chain_transaction':{'txid':'a'*64,'confirmations':2,'outputs':[{'vout':1,'script':script,'amount_sat':6481}]}})
        return script

    def test_collection_requires_actual_unspent_confirmation_and_exact_own_output(self):
        from simulator.recycling import collect
        script=self.exit_evidence()
        class Chain:
            def identity(self):pass
            def call(self,*args):return {'confirmations':2,'value':Decimal('0.00006481'),'scriptPubKey':{'hex':script}}
        asyncio.run(collect(self.s,Chain()))
        p=json.loads(self.s.db.execute("SELECT payload FROM event WHERE kind='recycle_source_unspent_verified'").fetchone()[0])
        self.assertEqual(6481,p['amount_sat']);self.assertEqual('actor-04',p['actor'])

    def test_collection_never_queries_offline_actor_and_spent_source_is_no_credit(self):
        from simulator.recycling import collect
        self.exit_evidence(online=False)
        class Chain:
            calls=0
            def identity(self):self.calls+=1
            def call(self,*args):self.calls+=1;return None
        chain=Chain();asyncio.run(collect(self.s,chain));self.assertEqual(0,chain.calls)
        self.s.set_online('actor-04',True);asyncio.run(collect(self.s,chain));self.assertEqual(2,chain.calls)
        self.assertFalse(self.s.db.execute("SELECT 1 FROM event WHERE kind='recycle_source_unspent_verified'").fetchone())

    def test_collection_detects_wrong_value_without_releasing_reserves(self):
        from simulator.recycling import collect
        from simulator.model import InvariantError
        script=self.exit_evidence()
        class Chain:
            def identity(self):pass
            def call(self,*args):return {'confirmations':2,'value':Decimal('0.00006480'),'scriptPubKey':{'hex':script}}
        with self.assertRaises(InvariantError):asyncio.run(collect(self.s,Chain()))
        self.assertFalse(self.s.db.execute("SELECT 1 FROM event WHERE kind='recycle_source_unspent_verified'").fetchone())

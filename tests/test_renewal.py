import json,time,unittest
from decimal import Decimal
from simulator.model import InvariantError,SIGNET_GENESIS
from simulator import renewal
from tests import test_continuous as fixtures
from simulator.continuous import schedule

class RenewalTests(unittest.TestCase):
    setUp=fixtures.ContinuousTests.setUp
    tearDown=fixtures.ContinuousTests.tearDown
    detail=fixtures.ContinuousTests.detail
    action=fixtures.ContinuousTests.action
    def grant(self,actor='actor-01'):
        source={'outpoint':'e'*64+':0','script':'0014'+'b'*40,'amount_sat':8000,
            'kind':'new_owner_funded_renewal','tranche':'owner-renewal-2026-10-11-1','confirmations':2}
        self.detail(actor,board_submitted=True,onchain_confirmed_sat=10000,owner_renewal_source=source)
        self.s.queue('sync-done',actor,'H01','sync',{},0)
        self.s.db.execute("UPDATE action SET state='completed',actual_fee_sat=0 WHERE id='sync-done'")
        self.c.board_amount_sat=5000
        self.s.event('owner_renewal_confirmed',{'recipient_outputs':{actor:{k:source[k] for k in ('outpoint','script','amount_sat')}}})
        return source
    def test_confirmed_owner_grant_can_board_without_being_called_recycling(self):
        source=self.grant();schedule(self.s,self.c,self.snapshot)
        a=self.action();self.assertIsNotNone(a,'new confirmed renewal currently cannot resume a previously boarded wallet')
        self.assertEqual('board',a['operation']);self.assertEqual(5000,json.loads(a['args'])['amount_sat'])
        self.assertEqual(source['outpoint'],json.loads(a['args'])['recycle_source']['outpoint'])
        self.assertEqual(1,self.s.db.execute("SELECT COUNT(*) FROM event WHERE kind='owner_renewal_board_intent'").fetchone()[0])
        self.assertFalse(self.s.db.execute("SELECT 1 FROM event WHERE kind='recycle_intent'").fetchone())
    def test_absent_newly_funded_wallet_never_reopens(self):
        self.grant('actor-09');self.s.set_online('actor-09',False)
        schedule(self.s,self.c,self.snapshot);self.assertIsNone(self.action())
    def test_same_renewal_receipt_never_retries_after_unknown_reply(self):
        self.grant();schedule(self.s,self.c,self.snapshot);a=self.action();self.assertIsNotNone(a)
        self.s.db.execute("UPDATE action SET state='outcome_unknown' WHERE id=?",(a['id'],))
        for _ in range(5):schedule(self.s,self.c,self.snapshot)
        self.assertEqual(1,self.s.db.execute("SELECT COUNT(*) FROM event WHERE kind='owner_renewal_board_intent'").fetchone()[0])

class FundingRpc:
    def __init__(self):
        self.calls=[];self.outputs=[];self.fee=1000;self.timeout=False;self.confirmations=1
        self.wrong_input=False;self.wrong_output=False;self.source_confirmations=3
    def transaction(self):
        outputs=[{'n':i,'value':Decimal(str(v)),'scriptPubKey':{'address':a,'hex':'0014'+'b'*40}}
            for i,item in enumerate(self.outputs) for a,v in item.items()]
        if self.wrong_output:outputs[0]['value']+=Decimal('0.00000001')
        change=100000-sum(int(o['value']*100000000) for o in outputs)-self.fee
        outputs.append({'n':len(outputs),'value':Decimal(change)/100000000,'scriptPubKey':{'address':'owned-change','hex':'0014'+'c'*40}})
        return {'txid':'e'*64,'confirmations':self.confirmations,'vin':[{'txid':('f' if self.wrong_input else 'a')*64,'vout':0}],'vout':outputs}
    def call(self,method,*args,**kw):
        self.calls.append((method,args))
        if method=='getblockhash':return SIGNET_GENESIS
        if method=='getblockchaininfo':return {'initialblockdownload':False}
        if method=='gettxout':return {'confirmations':self.source_confirmations,'value':Decimal('0.00100000'),'scriptPubKey':{'hex':'0014'+'a'*40}}
        if method=='walletcreatefundedpsbt':self.outputs=args[1];return {'psbt':'unsigned','fee':Decimal(self.fee)/100000000}
        if method=='walletprocesspsbt':return {'psbt':'signed'}
        if method=='finalizepsbt':return {'complete':True,'hex':'public-signed-transaction'}
        if method in {'decoderawtransaction','getrawtransaction'}:return self.transaction()
        if method=='getaddressinfo':return {'ismine':args[0]=='owned-change'}
        if method=='sendrawtransaction':
            if self.timeout:raise TimeoutError('node accepted but reply lost')
            return 'e'*64
        raise AssertionError(method)

class OwnerRenewalFundingTests(unittest.TestCase):
    setUp=fixtures.ContinuousTests.setUp
    tearDown=fixtures.ContinuousTests.tearDown
    detail=fixtures.ContinuousTests.detail
    def prepare(self,actors=(1,)):
        self.c.board_amount_sat=5000
        for i in range(1,13):self.s.set_online(f'actor-{i:02}',i in actors)
        for i in actors:self.detail(f'actor-{i:02}',board_submitted=True,funding_address=f'tb1q-client-{i:02}')
        source={'outpoint':'a'*64+':0','script':'0014'+'a'*40,'amount_sat':100000}
        self.s.event('external_owner_injection_observed',{'txid':'a'*64,'owned_outputs':[source],'allocated_sat':0})
        declaration={'tranche_id':renewal.TRANCHE,'maximum_principal_sat':80000,'maximum_actor_grant_sat':8000,
            'maximum_mining_fee_sat':2000,'maximum_batches':1,'sources':[{'txid':'a'*64,'outputs':[source]}]}
        renewal.declare(self.s,declaration);self.rpc=FundingRpc()
        return declaration
    def test_funding_is_new_injection_and_transaction_is_durable_before_broadcast(self):
        self.prepare();original=self.rpc.call
        def call(method,*args,**kw):
            if method=='sendrawtransaction':
                row=self.s.db.execute('SELECT * FROM funding_batch WHERE id=?',(renewal.TRANCHE,)).fetchone()
                self.assertEqual('broadcasting',row['state']);self.assertEqual('public-signed-transaction',row['raw_tx'])
            return original(method,*args,**kw)
        self.rpc.call=call
        result=renewal.fund(self.s,self.rpc,self.c);self.assertEqual('broadcast',result['state'])
        renewal.fund(self.s,self.rpc,self.c);renewal.fund(self.s,self.rpc,self.c)
        event=json.loads(self.s.db.execute("SELECT payload FROM event WHERE kind='owner_renewal_confirmed'").fetchone()[0])
        self.assertEqual((8000,1000,0,0),(event['principal_sat'],event['fee_sat'],event['recycling_credit_sat'],event['traffic_credit_seconds']))
        self.assertEqual(1,sum(m=='sendrawtransaction' for m,_ in self.rpc.calls))
        self.assertEqual(1,sum(m=='walletcreatefundedpsbt' for m,_ in self.rpc.calls));self.s.verify_event_chain()
    def test_timeout_pauses_and_never_regenerates_or_rebroadcasts(self):
        self.prepare();self.rpc.timeout=True
        result=renewal.fund(self.s,self.rpc,self.c);self.assertEqual('outcome_unknown',result['state'])
        self.assertEqual(renewal.PAUSE,self.s.get_meta('paused'))
        renewal.fund(self.s,self.rpc,self.c);self.assertIsNone(self.s.get_meta('paused'))
        self.assertEqual(1,sum(m=='sendrawtransaction' for m,_ in self.rpc.calls))
        self.assertEqual(1,sum(m=='walletcreatefundedpsbt' for m,_ in self.rpc.calls))
    def test_fee_cap_and_unconfirmed_source_never_broadcast(self):
        self.prepare();self.rpc.source_confirmations=0
        self.assertEqual('no_confirmed_unallocated_owner_receipt',renewal.fund(self.s,self.rpc,self.c)['state'])
        self.rpc.source_confirmations=3;self.rpc.fee=2001
        self.assertEqual('held_fee_cap',renewal.fund(self.s,self.rpc,self.c)['state'])
        self.assertFalse(any(m=='sendrawtransaction' for m,_ in self.rpc.calls))
    def test_changed_source_or_recipient_cannot_be_funded(self):
        self.prepare();self.rpc.wrong_input=True
        with self.assertRaises(InvariantError):renewal.fund(self.s,self.rpc,self.c)
        self.rpc.wrong_input=False;self.rpc.wrong_output=True
        with self.assertRaises(InvariantError):renewal.fund(self.s,self.rpc,self.c)
        self.assertFalse(any(m=='sendrawtransaction' for m,_ in self.rpc.calls))
    def test_disappearance_after_grant_broadcast_stays_closed(self):
        self.prepare();renewal.fund(self.s,self.rpc,self.c);self.s.set_online('actor-01',False)
        renewal.fund(self.s,self.rpc,self.c)
        self.assertFalse(self.s.online('actor-01'))
        detail=json.loads(self.s.db.execute("SELECT details FROM actor WHERE id='actor-01'").fetchone()[0])
        self.assertNotIn('owner_renewal_source',detail)
        self.assertFalse(self.s.db.execute("SELECT 1 FROM action WHERE operation='board'").fetchone())
    def test_total_cap_excludes_original_permanent_absences_and_ramp(self):
        self.prepare(tuple(range(1,13)))
        result=renewal.fund(self.s,self.rpc,self.c);self.assertEqual('broadcast',result['state'])
        row=self.s.db.execute('SELECT recipients FROM funding_batch WHERE id=?',(renewal.TRANCHE,)).fetchone();recipients=json.loads(row[0])
        self.assertEqual(80000,sum(r['amount_sat'] for r in recipients));self.assertEqual(10,len(recipients))
        self.assertFalse({'actor-09','actor-10'}&{r['actor'] for r in recipients})
        self.assertIsNone(self.s.get_meta('fixture_funding_plan'));self.assertIsNone(self.s.get_meta('ramp_applied'))
    def test_new_permanent_absence_and_unknown_actions_are_not_funded(self):
        self.prepare((1,2));self.detail('actor-01',board_submitted=True,funding_address='tb1q-client-01',permanent_absence={'rail':'ark'})
        self.s.queue('unknown','actor-02','H01','board',{},2000);self.s.db.execute("UPDATE action SET state='outcome_unknown' WHERE id='unknown'")
        self.assertEqual('held_uncertainty',renewal.fund(self.s,self.rpc,self.c)['state'])
        self.assertFalse(any(m=='sendrawtransaction' for m,_ in self.rpc.calls))
    def test_declaration_is_immutable(self):
        declaration=self.prepare();declaration['sources'][0]['outputs'][0]['amount_sat']=99999
        with self.assertRaises(InvariantError):renewal.declare(self.s,declaration)
    def test_isolated_regtest_prefix_is_explicit_and_mainnet_is_rejected(self):
        self.prepare();self.c.network='regtest'
        self.detail('actor-01',board_submitted=True,funding_address='bcrt1q-client-01')
        self.assertEqual(['actor-01'],[r['actor'] for r in renewal.eligible(self.s,self.c)])
        self.c.network='mainnet'
        with self.assertRaises(InvariantError):renewal.fund(self.s,self.rpc,self.c)
        self.assertFalse(self.rpc.calls)

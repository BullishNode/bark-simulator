import json,tempfile,unittest
from pathlib import Path
from decimal import Decimal
from simulator.engine import initialize
from simulator.funding import fund,declare_plan
from simulator.model import SIGNET_GENESIS
from simulator.store import Store
class Rpc:
    def __init__(self):self.calls=[];self.uncertain=False;self.found=False;self.outputs=[]
    def call(self,method,*args,**kwargs):
        self.calls.append(method)
        if method=='getblockhash':return SIGNET_GENESIS
        if method=='getblockchaininfo':return {'initialblockdownload':False}
        if method=='getbalances':return {'mine':{'trusted':Decimal('.01')}}
        if method=='walletcreatefundedpsbt':self.outputs=args[1];return {'fee':Decimal('.00001'),'psbt':'fixture'}
        if method=='walletprocesspsbt':return {'psbt':'signed'}
        if method=='finalizepsbt':return {'complete':True,'hex':'public-signed-tx'}
        if method=='decoderawtransaction':return {'txid':'a'*64,'vout':[{'n':i,'scriptPubKey':{'address':next(iter(o))},'value':Decimal(next(iter(o.values())))} for i,o in enumerate(self.outputs)]}
        if method=='sendrawtransaction':
            if self.uncertain:raise TimeoutError()
            return 'a'*64
        if method=='getrawtransaction':
            if not self.found:raise ValueError('not observed')
            return {'txid':'a'*64,'confirmations':1}
        raise AssertionError(method)
class FundingTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.s=Store(Path(self.temp.name),'synthetic',1000000);initialize(self.s);self.rpc=Rpc()
        self.declaration={'id':'fresh-fixture','initial_clients':12,'ramp_clients':12,'grant_sat':20000,
            'batch_maximum_fee_sat':3000,'maximum_total_principal_sat':480000,
            'maximum_total_fee_sat':6000,'fee_rate_sat_kvb':3000}
        self.s.db.execute("INSERT INTO meta VALUES ('paused','declare')")
        declare_plan(self.s,self.declaration)
        self.s.db.execute("DELETE FROM meta WHERE key='paused'")
        for i in range(1,13):self.s.db.execute('UPDATE actor SET details=? WHERE id=?',(json.dumps({'created':True,'funding_address':f'tb1qfixture{i}'}),f'actor-{i:02}'))
    def tearDown(self):self.s.close();self.temp.cleanup()
    def test_uncertain_broadcast_is_never_replaced_or_sent_twice(self):
        self.rpc.uncertain=True;result=fund(self.s,self.rpc,'initial');self.assertEqual('outcome_unknown',result['state'])
        fund(self.s,self.rpc,'initial');self.assertEqual(1,self.rpc.calls.count('walletcreatefundedpsbt'));self.assertEqual(1,self.rpc.calls.count('sendrawtransaction'))
        self.rpc.found=True;self.assertEqual('confirmed',fund(self.s,self.rpc,'initial')['state']);self.s.verify_event_chain()
        self.assertTrue(all(json.loads(r[0])['needs_sync'] for r in self.s.db.execute('SELECT details FROM actor')))
        self.assertEqual(1,self.s.db.execute("SELECT COUNT(*) FROM event WHERE kind='fixture_funding_confirmed'").fetchone()[0])
        fund(self.s,self.rpc,'initial')
        self.assertEqual(1,self.s.db.execute("SELECT COUNT(*) FROM event WHERE kind='fixture_funding_confirmed'").fetchone()[0])
    def test_transaction_is_durable_before_network_send(self):
        original=self.rpc.call
        def call(method,*args,**kwargs):
            if method=='sendrawtransaction':
                row=self.s.db.execute('SELECT * FROM funding_batch').fetchone();self.assertEqual('broadcasting',row['state']);self.assertEqual('a'*64,row['txid']);self.assertEqual('public-signed-tx',row['raw_tx'])
            return original(method,*args,**kwargs)
        self.rpc.call=call;self.assertEqual('broadcast',fund(self.s,self.rpc,'initial')['state'])
    def test_ramp_and_pause_cannot_bypass_the_declared_gate(self):
        with self.assertRaises(ValueError):fund(self.s,self.rpc,'ramp')
        self.s.db.execute("INSERT INTO meta VALUES ('paused','incident')")
        self.rpc.calls.clear()
        with self.assertRaises(ValueError):fund(self.s,self.rpc,'initial')
        self.assertEqual([],self.rpc.calls)
    def test_cohort_address_change_cannot_regenerate_funding(self):
        fund(self.s,self.rpc,'initial');self.s.db.execute("UPDATE actor SET details=? WHERE id='actor-01'",(json.dumps({'created':True,'funding_address':'tb1qchanged'}),))
        with self.assertRaises(ValueError):fund(self.s,self.rpc,'initial')
        self.assertEqual(1,self.rpc.calls.count('sendrawtransaction'))

    def test_fresh_explicit_twenty_thousand_grants_and_fee_rate_are_used(self):
        self.assertEqual('broadcast',fund(self.s,self.rpc,'initial')['state'])
        self.assertEqual(240000,sum(int(Decimal(next(iter(o.values())))*100000000) for o in self.rpc.outputs))
        self.assertEqual(self.declaration,json.loads(self.s.get_meta('fixture_funding_plan')))
    def test_cannot_increase_grant_cap_or_fee_after_declaration(self):
        self.s.db.execute("INSERT INTO meta VALUES ('paused','declare')")
        with self.assertRaisesRegex(ValueError,'immutable'):
            declare_plan(self.s,{**self.declaration,'grant_sat':21000,'maximum_total_principal_sat':504000})
        self.s.db.execute("DELETE FROM meta WHERE key='paused'")
        with self.assertRaisesRegex(ValueError,'differs'):
            fund(self.s,self.rpc,'initial',amount_sat=21000)
        with self.assertRaisesRegex(ValueError,'differs'):
            fund(self.s,self.rpc,'initial',maximum_fee_sat=3001)
        self.assertEqual([],self.rpc.calls)
    def test_total_principal_fee_and_actor_count_caps_are_not_guessed(self):
        for changed in ({'maximum_total_principal_sat':479999},{'maximum_total_fee_sat':5999},{'ramp_clients':13}):
            with self.assertRaises(ValueError):declare_plan(self.s,{**self.declaration,**changed})
    def test_old_r_and_d_plan_cannot_be_silently_upgraded(self):
        self.s.db.execute("UPDATE meta SET value=? WHERE key='fixture_funding_plan'",(json.dumps({'initial_principal_sat':96000}),))
        with self.assertRaisesRegex(ValueError,'fresh namespace'):fund(self.s,self.rpc,'initial')
        self.assertEqual([],self.rpc.calls)

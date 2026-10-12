"""A new owner allocation cannot reuse or mutate an earlier funding tranche."""
import json,time,unittest
from pathlib import Path
from simulator.store import Store
from decimal import Decimal
from unittest.mock import patch
from simulator.model import InvariantError,canonical
from simulator import renewal
from tests import test_renewal as legacy
from tests import test_continuous as fixtures

TRANCHE='owner-renewal-2026-10-12-traffic-2'

class AllocationRpc(legacy.FundingRpc):
    def __init__(self):
        super().__init__();self.source_spendable=True;self.source_amount_sat=100000;self.available=True
        self.source_wallet_owned=True;self.unavailable_broadcast=False;self.allocated_input=None
    def call(self,method,*args,**kw):
        if method=='listunspent':
            self.calls.append((method,args))
            return [{'txid':'a'*64,'vout':0,'amount':Decimal(self.source_amount_sat)/100000000,'scriptPubKey':'0014'+'a'*40,
                'address':'owned-source','confirmations':self.source_confirmations,'spendable':self.source_spendable,'solvable':True,'safe':True}] if self.available else []
        if method=='getaddressinfo' and args[0]=='owned-source':
            self.calls.append((method,args));return {'ismine':self.source_wallet_owned,'scriptPubKey':'0014'+'a'*40}
        if method=='getrawtransaction' and args[0]=='a'*64:
            self.calls.append((method,args));return {'txid':'a'*64,'confirmations':3,'vout':[{'n':0,'value':Decimal(self.source_amount_sat)/100000000,'scriptPubKey':{'hex':'0014'+'a'*40}}]}
        if method=='getrawtransaction' and self.unavailable_broadcast:
            self.calls.append((method,args));raise ValueError('transaction not yet proven')
        if method=='gettxout':
            if not self.available:self.calls.append((method,args));return None
            result=super().call(method,*args,**kw);result['value']=Decimal(self.source_amount_sat)/100000000;return result
        if method=='decodepsbt':self.calls.append((method,args));return {'tx':self.transaction()}
        if method=='decoderawtransaction' and args[0]=='prior-frozen-transaction':
            self.calls.append((method,args));return {'txid':'f'*64,'vin':[{'txid':self.allocated_input or 'd'*64,'vout':0}],'vout':[]}
        return super().call(method,*args,**kw)

class OwnerAllocationTrancheTests(unittest.TestCase):
    def setUp(self):
        fixtures.ContinuousTests.setUp(self)
        self.s.db.execute('CREATE TABLE IF NOT EXISTS funding_batch(id TEXT PRIMARY KEY,state TEXT NOT NULL,recipients TEXT NOT NULL,txid TEXT,raw_tx TEXT,fee_sat INTEGER,updated_at REAL NOT NULL)')
    tearDown=fixtures.ContinuousTests.tearDown
    detail=fixtures.ContinuousTests.detail
    def prepare(self):
        self.c.funding_wallet='abandon-simulator-funding';self.rpc=AllocationRpc();recipients=[]
        for number in range(1,13):
            actor=f'actor-{number:02}';online=number not in (3,9,10);self.s.set_online(actor,online)
            self.detail(actor,board_submitted=True,funding_address=f'tb1q-client-{number:02}',registered_spendable_sat=100)
            if online:recipients.append({'actor':actor,'address':f'tb1q-client-{number:02}','amount_sat':13200 if number==5 else 9200,'minimum_ark_amount_sat':12000 if number==5 else 8000})
        declaration={'tranche_id':TRANCHE,'maximum_principal_sat':86800,'maximum_actor_grant_sat':13200,'maximum_mining_fee_sat':2000,'maximum_batches':1,
            'funding_wallet':self.c.funding_wallet,'source':{'outpoint':'a'*64+':0','script':'0014'+'a'*40,'amount_sat':100000},'recipients':recipients}
        renewal.declare(self.s,declaration)
        return declaration
    def fund(self):return renewal.fund(self.s,self.rpc,self.c,tranche_id=TRANCHE)
    def test_second_allocation_funds_exact_frozen_online_grants_from_one_unspent_source(self):
        declaration=self.prepare();result=self.fund();self.assertEqual('broadcast',result['state'])
        row=self.s.db.execute('SELECT * FROM funding_batch WHERE id=?',(TRANCHE,)).fetchone()
        self.assertEqual(86800,sum(r['amount_sat'] for r in json.loads(row['recipients'])))
        self.assertEqual(declaration['recipients'],json.loads(row['recipients']))
        self.assertEqual(1,sum(m=='sendrawtransaction' for m,_ in self.rpc.calls))
        args=next(args for m,args in self.rpc.calls if m=='walletcreatefundedpsbt')
        self.assertEqual([{'txid':'a'*64,'vout':0}],args[0]);self.assertFalse(args[3]['add_inputs'])
        self.assertTrue(any(m=='listunspent' for m,_ in self.rpc.calls));self.assertIsNone(self.s.get_meta('owner_renewal_declaration'))
    def test_new_declaration_cannot_replace_first_renewal_or_initial_ramp(self):
        old={'tranche_id':renewal.TRANCHE,'maximum_principal_sat':80000,'maximum_actor_grant_sat':8000,'maximum_mining_fee_sat':2000,'maximum_batches':1,'sources':[]}
        renewal.declare(self.s,old);before=self.s.get_meta('owner_renewal_declaration')
        for name in ('initial','ramp',renewal.TRANCHE):self.s.db.execute("INSERT INTO funding_batch VALUES (?,'confirmed','[]',?,'prior-frozen-transaction',1000,1)",(name,'f'*64))
        rows=[dict(r) for r in self.s.db.execute('SELECT * FROM funding_batch ORDER BY id')]
        self.prepare();self.fund();self.fund();self.fund();self.assertEqual(before,self.s.get_meta('owner_renewal_declaration'))
        self.assertEqual(rows,[dict(r) for r in self.s.db.execute('SELECT * FROM funding_batch WHERE id!=? ORDER BY id',(TRANCHE,))])
    def test_source_must_be_wallet_owned_confirmed_spendable_and_unallocated(self):
        self.prepare()
        for field,value in (('source_spendable',False),('source_wallet_owned',False),('source_confirmations',0),('available',False)):
            with self.subTest(field=field):
                old=getattr(self.rpc,field);setattr(self.rpc,field,value)
                self.assertNotEqual('broadcast',self.fund()['state']);setattr(self.rpc,field,old)
        self.assertFalse(any(m=='walletprocesspsbt' for m,_ in self.rpc.calls))
        self.s.db.execute("INSERT INTO funding_batch VALUES ('initial','prepared','[]',?,'prior-frozen-transaction',1000,1)",('f'*64,));self.rpc.allocated_input='a'*64
        self.assertEqual('held_source_allocated',self.fund()['state']);self.assertFalse(any(m=='sendrawtransaction' for m,_ in self.rpc.calls))
    def test_lost_reply_restart_reconciles_only_same_transaction(self):
        self.prepare();self.rpc.timeout=True;self.assertEqual('outcome_unknown',self.fund()['state'])
        self.s.close();self.s=Store(Path(self.tmp.name),'synthetic',1000000)
        self.rpc.unavailable_broadcast=True
        for _ in range(3):self.assertEqual('outcome_unknown',self.fund()['state'])
        self.rpc.unavailable_broadcast=False;self.assertEqual('confirmed',self.fund()['state'])
        self.assertEqual(1,sum(m=='walletcreatefundedpsbt' for m,_ in self.rpc.calls));self.assertEqual(1,sum(m=='sendrawtransaction' for m,_ in self.rpc.calls))
        self.assertIsNone(self.s.get_meta('paused'));self.s.verify_event_chain()
    def test_declared_recipient_change_disappearance_or_pending_hazard_holds_entire_tranche(self):
        self.prepare();self.s.set_online('actor-01',False);self.assertEqual('held_recipient_change',self.fund()['state']);self.s.set_online('actor-01',True)
        self.s.db.execute("INSERT INTO meta VALUES ('realism_hazards',?)",(canonical({'actor-02':{'pending':True}}),));self.assertEqual('held_recipient_change',self.fund()['state'])
        self.s.db.execute("DELETE FROM meta WHERE key='realism_hazards'")
        self.detail('actor-02',board_submitted=True,funding_address='tb1q-changed',registered_spendable_sat=100)
        self.assertEqual('held_recipient_change',self.fund()['state']);self.assertFalse(any(m=='walletprocesspsbt' for m,_ in self.rpc.calls))
    def test_fixed_caps_grants_and_original_absent_actors_cannot_be_redeclared(self):
        declaration=self.prepare()
        for change in ({'maximum_mining_fee_sat':2001},{'source':dict(declaration['source'],amount_sat=99999)},
                       {'recipients':[dict(declaration['recipients'][0],actor='actor-03')]},
                       {'recipients':[dict(declaration['recipients'][0],amount_sat=8000)]}):
            with self.subTest(change=change),self.assertRaises((InvariantError,ValueError)):renewal.declare(self.s,declaration|change)
    def test_quote_over_cap_or_wrong_unsigned_outputs_never_signs(self):
        self.prepare();self.rpc.fee=2001;self.assertEqual('held_fee_cap',self.fund()['state'])
        self.rpc.fee=1000;self.rpc.wrong_output=True
        with self.assertRaises(InvariantError):self.fund()
        self.assertFalse(any(m=='walletprocesspsbt' for m,_ in self.rpc.calls));self.assertFalse(any(m=='sendrawtransaction' for m,_ in self.rpc.calls))
    def test_new_source_boards_once_with_net_floor_without_first_action_id_collision(self):
        declaration=self.prepare();self.fund();self.fund()
        self.s.queue('owner-renewal-board-actor-01-1','actor-01','H01','board',{},2000)
        self.s.db.execute("UPDATE action SET state='completed',actual_fee_sat=1000 WHERE id='owner-renewal-board-actor-01-1'")
        row=self.s.db.execute("SELECT details FROM actor WHERE id='actor-01'").fetchone();detail=json.loads(row[0]);detail.update(needs_sync=False,snapshot_at=time.time(),onchain_confirmed_sat=9200)
        self.s.db.execute("UPDATE actor SET details=? WHERE id='actor-01'",(canonical(detail),))
        self.assertTrue(renewal.queue_board(self.s,'actor-01',detail,self.c));a=self.s.db.execute("SELECT * FROM action WHERE state='queued'").fetchone();args=json.loads(a['args'])
        self.assertIn(TRANCHE,a['id']);self.assertEqual(8000,args['minimum_ark_amount_sat']);self.assertEqual(9200,args['board_cap_sat']);self.assertTrue(args['recycle_autosize']);self.assertEqual(2000,a['fee_reservation_sat'])
        self.assertFalse(renewal.queue_board(self.s,'actor-01',detail,self.c));self.assertFalse(self.s.db.execute("SELECT 1 FROM event WHERE kind='recycle_intent'").fetchone())

    def test_reconciliation_advances_only_selected_tranche_and_confirms_exactly_once(self):
        self.prepare();self.fund();self.fund();self.fund()
        row=self.s.db.execute('SELECT state FROM funding_batch WHERE id=?',(TRANCHE,)).fetchone()
        self.assertEqual('confirmed',row[0])
        self.assertEqual(1,self.s.db.execute("SELECT count(*) FROM event WHERE kind='owner_renewal_confirmed' AND json_extract(payload,'$.tranche')=?",(TRANCHE,)).fetchone()[0])
    def test_disappearance_during_preparation_cannot_broadcast_signed_grants(self):
        self.prepare();original=self.rpc.call
        def call(method,*args,**kw):
            result=original(method,*args,**kw)
            if method=='walletprocesspsbt':self.s.set_online('actor-01',False)
            return result
        self.rpc.call=call
        self.assertEqual('held_recipient_change',self.fund()['state'])
        self.assertFalse(any(m=='sendrawtransaction' for m,_ in self.rpc.calls))
        self.assertEqual('prepared',self.s.db.execute('SELECT state FROM funding_batch WHERE id=?',(TRANCHE,)).fetchone()[0])
    def test_restarted_prepared_bytes_drift_never_broadcasts_or_regenerates(self):
        self.prepare();original=self.rpc.call
        class PowerFailure(BaseException):pass
        def call(method,*args,**kw):
            if method=='sendrawtransaction':raise PowerFailure()
            return original(method,*args,**kw)
        self.rpc.call=call
        with self.assertRaises(PowerFailure):self.fund()
        self.s.db.execute("UPDATE funding_batch SET state='prepared',raw_tx='different-signed-bytes' WHERE id=?",(TRANCHE,))
        self.rpc.call=original
        with self.assertRaises(InvariantError):self.fund()
        self.assertEqual(1,sum(m=='walletcreatefundedpsbt' for m,_ in self.rpc.calls));self.assertFalse(any(m=='sendrawtransaction' for m,_ in self.rpc.calls))
    def test_offline_permanent_or_disappearing_grant_never_queues_a_board(self):
        self.prepare();self.fund();self.fund()
        detail=json.loads(self.s.db.execute("SELECT details FROM actor WHERE id='actor-05'").fetchone()[0]);detail.update(needs_sync=False,snapshot_at=time.time(),onchain_confirmed_sat=13200)
        self.s.db.execute("UPDATE actor SET details=? WHERE id='actor-05'",(canonical(detail),))
        self.s.set_online('actor-05',False);self.assertFalse(renewal.queue_board(self.s,'actor-05',detail,self.c));self.s.set_online('actor-05',True)
        detail['permanent_absence']={'original_wallet_must_stay_closed':True};self.s.db.execute("UPDATE actor SET details=? WHERE id='actor-05'",(canonical(detail),))
        self.assertFalse(renewal.queue_board(self.s,'actor-05',detail,self.c));self.assertFalse(self.s.db.execute("SELECT 1 FROM action WHERE operation='board'").fetchone())

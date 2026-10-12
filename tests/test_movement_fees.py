import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from simulator.engine import initialize
from simulator.fees import collect, movement_fee
from simulator.model import InvariantError, canonical
from simulator.ownership import EvidenceGap
from simulator.store import Store


class MovementFeeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.s = Store(Path(self.tmp.name),'synthetic',10000)
        initialize(self.s)
        self.key = '02'+'11'*32
        self.s.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',
            (self.key,'actor-01','mailbox','{}'))
        for coin,amount,signed in [('input',10000,'a1'),('output',9900,'b1')]:
            self.s.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',
                (coin,self.key,amount,'digest',signed,'{}'))
        self.proposal = {'committed_fee_sat':100,'participation':{
            'inputs':['a1'],'outputs':[{'policy':'00'+self.key,'amount':9900}]}}
        self.movement = {'id':'7','subsystem':'bark.round','status':'successful',
            'payment_hash':None,'input_vtxos':['input'],'output_vtxos':['output'],
            'offchain_fee_sat':100,'effective_balance_sat':-100}
        self.action('refresh','refresh_proposal',self.proposal,{'committed_fee_sat':100})
        self.save_movement()

    def tearDown(self):
        self.s.close()
        self.tmp.cleanup()

    def action(self,operation,kind,proposal,data,name='cost'):
        self.s.queue(name,'actor-01','H17',operation,{},1000)
        self.s.db.execute("UPDATE action SET state='dispatched' WHERE id=?",(name,))
        self.s.event('driver_evidence',{'action_id':name,'event':kind,'data':proposal})
        self.s.finish(name,'completed',{'data':data})

    def save_movement(self):
        self.s.db.execute('INSERT OR REPLACE INTO movement_evidence VALUES (?,?,?)',
            ('actor-01',self.movement['id'],canonical(self.movement)))

    def row(self,name='cost'):
        return self.s.db.execute('SELECT * FROM action WHERE id=?',(name,)).fetchone()

    def send(self):
        self.s.db.execute("DELETE FROM action WHERE id='cost'")
        self.s.db.execute("DELETE FROM event WHERE kind='driver_evidence'")
        self.proposal = {'payment_hash':'a'*64,'amount_sat':2000,'fee_ceiling_sat':150,
            'input_vtxo_ids':['input']}
        self.s.db.execute("UPDATE owned_coin SET amount_sat=7900 WHERE id='output'")
        self.movement.update(subsystem='bark.lightning_send',payment_hash='a'*64,
            effective_balance_sat=-2000)
        self.save_movement()
        self.action('pay_invoice','lightning_proposal',self.proposal,
            {'payment_hash':'a'*64,'payment_state':'succeeded','payment_status_verified':True,
             'committed_fee_sat':100})

    def test_round_cost_comes_from_signed_inputs_and_frozen_key_amounts(self):
        result=movement_fee(self.s,self.row())
        self.assertEqual(100,result['actual_fee_sat'])
        self.assertEqual((10000,9900,0),(result['signed_input_sat'],result['signed_output_sat'],result['transferred_sat']))

    def test_pending_round_keeps_reservation(self):
        self.movement['status']='pending';self.save_movement()
        with self.assertRaises(EvidenceGap):movement_fee(self.s,self.row())
        self.assertIsNone(self.row()['actual_fee_sat'])

    def test_missing_signed_input_or_output_keeps_reservation(self):
        self.s.db.execute("DELETE FROM owned_coin WHERE id='output'")
        with self.assertRaises(EvidenceGap):movement_fee(self.s,self.row())
        self.s.db.execute("DELETE FROM owned_coin WHERE id='input'")
        with self.assertRaises(EvidenceGap):movement_fee(self.s,self.row())

    def test_another_owners_output_is_an_incident(self):
        self.s.db.execute("UPDATE owner_key SET actor='actor-02'")
        with self.assertRaises(InvariantError):movement_fee(self.s,self.row())

    def test_frozen_round_amount_or_key_cannot_be_changed(self):
        self.s.db.execute("UPDATE owned_coin SET amount_sat=9899 WHERE id='output'")
        with self.assertRaises(InvariantError):movement_fee(self.s,self.row())
        self.s.db.execute("UPDATE owned_coin SET amount_sat=9900 WHERE id='output'")
        self.proposal['participation']['outputs'][0]['policy']='00'+'03'+'22'*32
        self.s.db.execute("UPDATE event SET payload=? WHERE kind='driver_evidence'",
            (canonical({'action_id':'cost','event':'refresh_proposal','data':self.proposal}),))
        with self.assertRaises(InvariantError):movement_fee(self.s,self.row())

    def test_duplicate_input_or_output_is_an_incident(self):
        self.movement['output_vtxos'].append('output');self.save_movement()
        with self.assertRaises(InvariantError):movement_fee(self.s,self.row())

    def test_successful_send_separates_payment_principal_from_service_cost(self):
        self.send();result=movement_fee(self.s,self.row())
        self.assertEqual((2000,100),(result['transferred_sat'],result['actual_fee_sat']))

    def test_pending_failed_or_unverified_send_never_releases_reserve(self):
        self.send()
        for state,verified in [('pending',True),('failed',True),('succeeded',False)]:
            result=json.loads(self.row()['result']);result['data'].update(payment_state=state,payment_status_verified=verified)
            self.s.db.execute("UPDATE action SET result=? WHERE id='cost'",(canonical(result),))
            with self.assertRaises(EvidenceGap):movement_fee(self.s,self.row())
            self.assertIsNone(self.row()['actual_fee_sat'])

    def test_hash_mismatch_or_overspend_is_an_incident(self):
        self.send()
        self.s.db.execute("UPDATE owned_coin SET amount_sat=7800 WHERE id='output'")
        with self.assertRaises(InvariantError):movement_fee(self.s,self.row())
        self.s.db.execute("UPDATE owned_coin SET amount_sat=7900 WHERE id='output'")
        result=json.loads(self.row()['result']);result['data']['payment_hash']='b'*64
        self.s.db.execute("UPDATE action SET result=? WHERE id='cost'",(canonical(result),))
        with self.assertRaises(InvariantError):movement_fee(self.s,self.row())

    def test_reported_cost_must_conserve_signed_values_and_respect_reserve(self):
        self.movement['offchain_fee_sat']=99;self.save_movement()
        with self.assertRaises(InvariantError):movement_fee(self.s,self.row())
        self.movement['offchain_fee_sat']=100;self.save_movement()
        self.s.db.execute("UPDATE action SET fee_reservation_sat=99 WHERE id='cost'")
        with self.assertRaises(InvariantError):movement_fee(self.s,self.row())

    def test_same_movement_cannot_close_two_actions(self):
        self.s.event('client_fee_reconciled',{'action_id':'other','actor':'actor-01','movement_id':'7'})
        with self.assertRaises(InvariantError):movement_fee(self.s,self.row())

    def test_collection_closes_once_without_wallet_or_node_requests(self):
        class Chain:
            def identity(self):raise AssertionError('no chain request needed')
        before=self.s.remaining_fee_budget()
        asyncio.run(collect(self.s,Chain()));asyncio.run(collect(self.s,Chain()))
        self.assertEqual(100,self.row()['actual_fee_sat'])
        self.assertEqual(900,self.s.remaining_fee_budget()-before)
        self.assertEqual(1,self.s.db.execute("SELECT COUNT(*) FROM event WHERE kind='client_fee_reconciled'").fetchone()[0])
        self.s.verify_event_chain()

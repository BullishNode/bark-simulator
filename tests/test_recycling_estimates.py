import asyncio
import json
import unittest
from unittest.mock import patch
import tests.test_recycling as helpers
from simulator.recycling import collect, plan


class RecyclingEstimates(unittest.TestCase):
    setUp=helpers.RecyclingTests.setUp
    tearDown=helpers.RecyclingTests.tearDown
    detail=helpers.RecyclingTests.detail
    action=helpers.RecyclingTests.action
    source=helpers.RecyclingTests.source

    def test_4119_return_uses_estimate_and_keeps_two_thousand_ceiling(self):
        self.source(amount=4119)
        result=plan(self.s,'actor-04',json.loads(self.s.db.execute(
            "SELECT details FROM actor WHERE id='actor-04'").fetchone()[0]),self.c)
        self.assertIsNotNone(result)
        self.assertEqual(3636,result['amount_sat'])
        self.assertEqual(3000,result['minimum_ark_amount_sat'])

    def test_unrelated_live_spendable_coin_does_not_block_owned_return(self):
        self.source(amount=6000)
        detail=json.loads(self.s.db.execute("SELECT details FROM actor WHERE id='actor-04'").fetchone()[0])
        detail['registered_spendable_sat']=1500
        result=plan(self.s,'actor-04',detail,self.c)
        self.assertIsNotNone(result)
        self.assertEqual(5517,result['amount_sat'])

    def test_real_high_cost_quote_holds_sub_floor_source(self):
        self.source(amount=4119)
        self.s.event('client_fee_reconciled',{'actor':'actor-04','action_id':'quoted-board',
            'service_charge_sat':330,'mining_fee_sat':1000,'actual_fee_sat':1330,
            'chain_transaction':{'txid':'b'*64,'confirmations':2}})
        result=plan(self.s,'actor-04',json.loads(self.s.db.execute(
            "SELECT details FROM actor WHERE id='actor-04'").fetchone()[0]),self.c)
        self.assertIsNone(result)

    def test_ten_unchanged_chain_checks_write_one_verification_event(self):
        source=self.source(amount=6000)
        self.s.db.execute("DELETE FROM event WHERE kind='recycle_source_unspent_verified'")
        class Chain:
            def identity(self):return {}
            def call(self,*args):return {'confirmations':2,'value':'0.00006000',
                'scriptPubKey':{'hex':source['script']}}
        with patch('simulator.recycling.sources',return_value={source['outpoint']:source}):
            for _ in range(10):asyncio.run(collect(self.s,Chain()))
        self.assertEqual(1,self.s.db.execute("SELECT COUNT(*) FROM event WHERE kind='recycle_source_unspent_verified'").fetchone()[0])
        result=plan(self.s,'actor-04',json.loads(self.s.db.execute(
            "SELECT details FROM actor WHERE id='actor-04'").fetchone()[0]),self.c)
        self.assertIsNotNone(result)

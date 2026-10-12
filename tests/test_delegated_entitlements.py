"""Delegated intent lifetime: no wallet return or payout assumption is needed."""
import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from simulator.config import Config
from simulator.engine import Engine, initialize
from simulator.model import SIGNET_GENESIS, canonical
from simulator.store import Store


class DelegatedEntitlementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.s = Store(self.root, 'synthetic', 100000)
        initialize(self.s)
        self.actor = 'actor-08'
        self.input_key = '02' + '11' * 32
        self.output_key = '02' + '22' * 32
        self.binding = {'mailbox_pk':'mailbox','spk':'owner-script','seq':1,
                        'record_signature_valid':True,'key_link_signature_valid':True}
        self.s.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',
                          (self.input_key,self.actor,'mailbox','{}'))
        self.s.db.execute('INSERT INTO owner_record VALUES (?,?,?,?,?)',
                          (self.actor,'mailbox',1,'owner-script',canonical(self.binding)))
        proof = {'id':'input','user_pubkey':self.input_key,'amount_sat':10000,
                 'signed_path_valid':True,'anchor_confirmations':1,
                 'chain_anchor':'a'*64+':0','binding':self.binding}
        self.s.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',
                          ('input',self.input_key,10000,'digest','aa',canonical(proof)))
        self.proposal = {'committed_fee_sat':100,'participation':{
            'inputs':['aa'],'outputs':[{'amount':9900,'policy':'00'+self.output_key}]}}
        self.result = {'action_id':'delegated','status':'ok','actual_fee_sat':None,
                       'data':{'round_state_id':'1','committed_fee_sat':100,
                       'actual_fee_sat':None,'evidence':{'coins':[], 'movements':[],
                       'binding':self.binding}}}
        self.s.queue('delegated',self.actor,'H20','refresh_delegated',{},2000)
        self.s.event('driver_evidence',{'action_id':'delegated','operation':'refresh_delegated',
                                      'event':'refresh_proposal','data':self.proposal})
        config = Config(self.root,(),('mock-driver',),self.root/'wallets',SIGNET_GENESIS,
                        'test','test','test',100000,1,1,True)
        with patch('simulator.engine.json_command',AsyncMock(return_value=self.result)) as command:
            asyncio.run(Engine(config,self.s).dispatch_one())
        self.assertEqual(1,command.await_count)

    def tearDown(self):
        self.s.close()
        self.tmp.cleanup()

    def entitlement(self):
        if not self.s.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='delegated_entitlement'").fetchone():
            return None
        return self.s.db.execute("SELECT * FROM delegated_entitlement WHERE action_id='delegated'").fetchone()

    def test_completed_delegated_intent_is_durable_without_any_later_sync(self):
        self.assertEqual('completed',self.s.db.execute("SELECT state FROM action WHERE id='delegated'").fetchone()[0])
        row = self.entitlement()
        self.assertIsNotNone(row,'completed delegated refresh has no durable submitted entitlement')
        self.assertEqual('submitted',row['state'])
        self.assertEqual(['input'],json.loads(row['input_coin_ids']))
        self.assertIsNone(row['round_txid'])
        self.assertEqual([],json.loads(row['replacement_ids']))
        self.assertIsNone(self.s.db.execute("SELECT actual_fee_sat FROM action WHERE id='delegated'").fetchone()[0])
        self.assertEqual(0,self.s.db.execute("SELECT count(*) FROM action WHERE operation='sync'").fetchone()[0])


if __name__ == '__main__':
    unittest.main()

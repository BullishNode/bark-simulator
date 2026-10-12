import asyncio
import json
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch
from simulator.config import Config
from simulator.engine import Engine
from tests import test_candidate_dedup as helpers


class TransientDedupTests(unittest.TestCase):
    setUp=helpers.CandidateDedupTests.setUp
    tearDown=helpers.CandidateDedupTests.tearDown

    def test_failed_second_coin_keeps_cached_first_coin_state_for_retry(self):
        self.s.db.execute("DELETE FROM action WHERE id='observe'")
        self.s.queue('observe','actor-01','H01','sync',{},2000)
        coins=[{**self.coin,'state':'Spent'},
               {**self.coin,'id':'new-coin','signed_vtxo':'abce'}]
        response={'action_id':'observe','status':'ok','actual_fee_sat':None,
                  'data':{'evidence':{'binding':self.binding,'coins':coins,'movements':[]}}}
        config=Config(state_dir=Path(self.tmp.name),wallet_root=Path(self.tmp.name)/'wallets',
                      active=True,driver_command=('driver',),proof_command=('proof',),
                      observer_command=(),expected_genesis='fixture',expected_container='fixture',
                      expected_image='fixture',expected_server_pubkey='fixture',fee_budget_sat=10000,
                      interval_seconds=1,action_timeout_seconds=30)
        with patch('simulator.engine.json_command',AsyncMock(return_value=response)), \
             patch('simulator.ownership.json_command',AsyncMock(side_effect=TimeoutError)):
            asyncio.run(Engine(config,self.s).dispatch_one())
        self.assertEqual('completed',self.s.db.execute("SELECT state FROM action WHERE id='observe'").fetchone()[0])
        cached=self.s.db.execute("SELECT payload FROM client_coin_candidate WHERE id='coin'").fetchone()
        self.assertIsNotNone(cached,'partial verification must retain the cached coin state as a retry candidate')
        self.assertEqual('Spent',json.loads(cached[0])['state'])
        self.assertEqual(0,self.s.db.execute('SELECT count(*) FROM coin_observation').fetchone()[0])
        self.s.verify_event_chain()

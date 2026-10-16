"""Actual collector/source-event handoff with synthetic native dependencies."""
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from simulator import two_step_normal as normal
from simulator.model import SIGNET_GENESIS
from simulator.normal_lineage_join import CONFIGURATION
from simulator.store import Store
from tests.test_final_campaign import PINS
from tests import test_two_step_normal as fixtures


class ObservationHandoffTests(unittest.IsolatedAsyncioTestCase):
    async def test_authenticated_observation_reaches_extracted_A_lineage_reducer(self):
        with tempfile.TemporaryDirectory() as directory:
            store=Store(Path(directory),'nonce-handoff',10000,architecture_profile='two_step_per_key')
            try:
                tables=fixtures.TablesTests();tables.setUp()
                originals={'native_sql':tables.raw(),'policy':b'{}','core':b'{}','rounds_inventory':b'{}'}
                captured={**{'raw_'+key:raw for key,raw in originals.items() if key!='native_sql'},
                    'raw_sql':originals['native_sql'],'fee_history':{}}
                observation={'id':'b'*32,'started_at':time.time(),'financial_pins':PINS,
                    'boundary_id':'finite','height':100,'tip_hash':'tip','architecture_profile':'two_step_per_key'}
                admitted={'binary_sha256':{'captaind':'c'*64},'rounds_member_id':'rounds',
                    'watchman_member_id':'watchman','injection_declaration_hashes':[],
                    'policy_sha256':normal.digest(originals['policy']),
                    'proof_tool_sha256':{},'ordinary_lineage':dict(CONFIGURATION)}
                async def capture(*args):
                    source={'source_observation':observation,'financial_pins':PINS,'boundary_id':'finite',
                        'identity':{'server_pubkey':'public-server'},'binary_sha256':admitted['binary_sha256'],
                        'observed_at':time.time(),'height':100,'tip_hash':'tip',
                        'rounds_member_id':'rounds','watchman_member_id':'watchman',
                        'injection_declaration_hashes':[],
                        'original_sha256':{key:normal.digest(raw) for key,raw in originals.items()},
                        'fee_history_sha256':normal.private_history_hash({})}
                    store.event('normal_financial_source',source)
                    return {**captured,'source_sequence':store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]}
                class Chain:
                    def identity(self):return {'chain':'signet','initialblockdownload':False,'blocks':100,'bestblockhash':'tip'}
                    def call(self,method,*args):
                        if (method,args)==('getblockhash',(0,)):return SIGNET_GENESIS
                        raise AssertionError('unexpected synthetic chain call')
                collector=normal.Collector(capture,1,{})
                with patch.object(collector,'admission',return_value=admitted), \
                        patch.object(normal,'active_identity',return_value={'server_pubkey':'public-server'}), \
                        patch('simulator.normal_lineage_join.authenticate_frontier',
                            side_effect=RuntimeError('authenticated frontier reached')) as frontier:
                    with self.assertRaisesRegex(RuntimeError,'authenticated frontier reached'):
                        await collector._produce(store,None,Chain(),{'financial_pins':PINS},observation,
                            {'pins':PINS,'id':'finite'},{'pins':PINS},opening={})
                self.assertEqual(observation['id'],frontier.call_args.kwargs['observation_id'])
                self.assertEqual(0,store.db.execute("SELECT count(*) FROM event WHERE kind='financial_operating_readiness'").fetchone()[0])
                store.verify_event_chain()
            finally:store.close()

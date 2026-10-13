"""Release supervisor uses the actual window contract and isolates log gaps."""
import tempfile,time,unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import AsyncMock,patch
from simulator.config import Config
from simulator.engine import Engine,initialize
from simulator.model import SIGNET_GENESIS
from simulator.store import Store


class ReleaseLogHooks(unittest.IsolatedAsyncioTestCase):
    async def test_target_configuration_selects_window_source_and_unavailable_logs_do_not_pause_money(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);store=Store(root/'state','synthetic',10000);initialize(store)
            cfg=Config(root/'state',('observer',),(),root/'wallets',SIGNET_GENESIS,'container','image','server',10000,1,1,False,
                inventory_command=('readonly-bridge',),log_target_enabled=True,log_since_us=123)
            engine=Engine(cfg,store)
            snapshot={'observed_at':time.time(),'stable_tip':True,'initial_block_download':False,'height':100,'server_status':{'status':'running'}}
            try:
                with ExitStack() as stack:
                    stack.enter_context(patch.object(engine,'observe',AsyncMock(return_value=snapshot)))
                    stack.enter_context(patch.object(engine,'collect_inventory',AsyncMock()))
                    for name in ('collect_public_proofs','collect_negative_checks','retry_public_candidates','collect_input_params'):
                        if name=='collect_input_params':stack.enter_context(patch('simulator.round_adoption.'+name,AsyncMock()))
                        else:stack.enter_context(patch('simulator.engine.'+name,AsyncMock()))
                    logs=stack.enter_context(patch('simulator.engine.collect_logs',AsyncMock(side_effect=RuntimeError('unavailable'))))
                    stack.enter_context(patch('simulator.engine.generate',lambda *args,**kwargs:None))
                    await engine.run(once=True)
                self.assertEqual(1,logs.await_count)
                sources=logs.await_args.args[1]
                self.assertEqual({'target_window'},{source.kind for source in sources})
                self.assertEqual({'captaind','watchmand'},{source.component for source in sources})
                self.assertIsNone(store.get_meta('paused'))
                self.assertEqual(0,store.db.execute('SELECT count(*) FROM action').fetchone()[0])
                self.assertTrue(any(row['kind']=='log.capture.gap' for row in store.trace.records()))
            finally:store.close()


class ReleaseLogConfig(unittest.TestCase):
    def test_declared_sources_and_bounds_are_loaded_without_enabling_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'config.toml'
            text=f'''[target]
network="signet"
genesis="{SIGNET_GENESIS}"
container="abandon-signet-fallback-fb-captaind-1"
image_digest="sha256:{'a'*64}"
server_pubkey="02{'b'*64}"
[runtime]
state_dir="{directory}/state"
wallet_root="{directory}/wallets"
observer_command=["observer"]
fee_budget_sat=10000
'''
            path.write_text(text);self.assertFalse(Config.load(path).log_target_enabled)
            path.write_text(text+'[logs]\ntarget=true\nlocal_sources=["simulator"]\nsince_us=123\nmaximum_bytes=65536\n')
            cfg=Config.load(path)
            self.assertTrue(cfg.log_target_enabled);self.assertEqual(('simulator',),cfg.log_local_sources)
            self.assertEqual(65536,cfg.log_maximum_bytes)
            path.write_text(text+'[logs]\nlocal_sources=["arbitrary.service"]\n')
            with self.assertRaises(ValueError):Config.load(path)
            descriptor=Path(directory)/'rounds.json';descriptor.write_text('{}')
            operator=f'[operator]\nbridge=true\ndescriptors=["{descriptor}"]\n'
            path.write_text(text+operator)
            with self.assertRaises(ValueError):Config.load(path)
            path.write_text(text+'inventory_command=["readonly-bridge"]\n'+operator)
            self.assertTrue(Config.load(path).operator_bridge_enabled)
            path.write_text(text+'inventory_command=["readonly-bridge"]\n'+operator+'[trace]\nenabled=false\n')
            with self.assertRaises(ValueError):Config.load(path)

"""A healthy target alone cannot authorize a final-build financial pilot."""
import tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from simulator.engine import Engine,initialize
from simulator.store import Store

class OperatingDispatchRegressions(unittest.TestCase):
    def test_final_build_without_financial_envelope_is_held(self):
        with tempfile.TemporaryDirectory() as directory:
            store=Store(Path(directory),'synthetic',100000);initialize(store)
            store.db.execute("INSERT INTO meta VALUES ('final_financial_epoch','fixture-present')")
            engine=Engine.__new__(Engine);engine.store=store
            engine.config=SimpleNamespace(board_amount_sat=12000,action_fee_reserve_sat=2000)
            self.assertFalse(engine.ready_for_actions({'observed_at':time.time(),'stable_tip':True,
                'initial_block_download':False,'server_status':{'status':'running'}}),
                'server health does not establish affordable fees or confirmed financial readiness')
            store.close()

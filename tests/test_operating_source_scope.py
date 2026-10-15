"""Synthetic funding-only source controls; no funding or native calls."""
import unittest
import time
from simulator.engine import Engine
from simulator.operating_limits import preflight
from tests.test_operating_limits import OperatingLimitsTests


class OperatingSourceScopeTests(OperatingLimitsTests):
    def test_funding_only_source_does_not_admit_any_wallet_operation(self):
        snapshot=self.readiness(operation_scope=['funding'])
        self.assertTrue(preflight(self.store,self.config,snapshot,operation='funding')['allowed'])
        for operation in ('ordinary','create','address','snapshot','sync','board','send_arkoor',
                          'claim','progression','invoice','pay_invoice','refresh','exit'):
            with self.subTest(operation=operation),self.assertRaisesRegex(ValueError,'source operation scope'):
                preflight(self.store,self.config,snapshot,operation=operation)
        self.store.db.execute("INSERT INTO meta VALUES ('financial_qualification_required','true')")
        engine=Engine.__new__(Engine);engine.store,engine.config=self.store,self.config
        snapshot.update(observed_at=time.time(),stable_tip=True,
            initial_block_download=False,server_status={'status':'running'})
        self.assertFalse(engine.ready_for_actions(snapshot))

    def test_malformed_source_scopes_are_refused(self):
        for scope in ([],['funding','funding'],'funding',[None],[1],['']):
            with self.subTest(scope=scope),self.assertRaisesRegex(ValueError,'source operation scope'):
                preflight(self.store,self.config,self.readiness(operation_scope=scope),operation='funding')

    def test_source_scope_does_not_replace_fee_budget_or_exact_native_ceilings(self):
        with self.assertRaisesRegex(ValueError,'ceilings differ'):
            preflight(self.store,self.config,self.readiness(operation_scope=['funding'],
                effective_fee_ceilings_sat_kvb={}),operation='funding')
        with self.assertRaisesRegex(ValueError,'limit exhausted'):
            preflight(self.store,self.config,self.readiness(operation_scope=['funding']),
                operation='funding',maximum_fee_sat=201)

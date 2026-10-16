"""Software controls only; no live/native financial admission credit."""
import copy,time,unittest
from types import SimpleNamespace
from simulator.operating_limits import declare_envelope
from tests.test_final_campaign import PINS
from tests.test_treasury import TreasuryFixture
from simulator.operating_limits import preflight,validate

class NoOperatorPublicationTests(TreasuryFixture,unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.config = SimpleNamespace(board_amount_sat=800, action_fee_reserve_sat=200)
        self.limits = {
            'id': 'scoped-fixture', 'pins': PINS, 'boundary_id': 'fixture',
            'capital_exposure_msat': 3000000,
            'fee_budgets_msat': {'ordinary': 500000, 'urgent': 500000},
            'fee_ceilings_sat_kvb': {'round': None, 'pool': None, 'sweep': 2000,
                                   'payout': 2000, 'claim': None, 'progression': None},
            'per_action_fee_sat': 200, 'grant_sat': 1000, 'board_sat': 800,
            'board_fee_reserve_sat': 200, 'minimum_pool_sat': 100,
            'minimum_channel_msat': 100000, 'fee_assets': ['a' * 64 + ':0'],
            'operation_fee_paths': {operation: ['sweep', 'payout'] for operation in
                ('ordinary', 'create', 'address', 'snapshot', 'sync', 'board', 'send_arkoor')},
        }
        self.inventories = {'rounds': self.inventory(self.wallet), 'peer': self.inventory(self.peer)}
        self.store.add_snapshot({'observed_at': time.time(), 'financial_pins': PINS})
        self.limits['fee_ceilings_sat_kvb']={'round':5000,'pool':5000,'sweep':5000,'payout':5000,'claim':20000,'progression':20000}
        self.limits['operation_fee_paths']={'ordinary':['round','pool','sweep','payout'],'claim':['claim'],'progression':['progression'],'refresh':['round'],'board':[],'send_arkoor':[]}

    def declare(self):
        declare_envelope(self.store, self.limits, self.config, self.inventories, self.chain)

    def readiness(self, **changes):
        proof = {'financial_pins': PINS, 'boundary_id': 'fixture', 'tip_hash': 'tip',
                 'height': 100, 'complete': True, 'observed_at': time.time(),
                 'effective_fee_ceilings_sat_kvb': self.limits['fee_ceilings_sat_kvb'],
                 'capital_exposure_msat': 2000000, 'available_fee_funding_msat': 1000000,
                 'estimated_fee_rate_sat_kvb': 1000}
        proof.update(changes)
        self.event('financial_operating_readiness', proof)
        return {'financial_pins': PINS, 'tip_hash': 'tip', 'height': 100,
                'operating_readiness_sequence': self.sequence(), 'observed_at': time.time(),
                'stable_tip': True, 'initial_block_download': False,
                'server_status': {'status': 'running'}}

    def test_expensive_actual_quote_kept_without_unrelated_operator_cap(self):
        self.declare();snapshot=self.readiness(estimated_fee_rate_sat_kvb=11003)
        for operation in ('board','send_arkoor'):
            self.assertTrue(preflight(self.store,self.config,snapshot,operation=operation,maximum_fee_sat=200)['allowed'])
        self.assertFalse(preflight(self.store,self.config,snapshot,operation='ordinary')['allowed'])
        self.assertFalse(preflight(self.store,self.config,snapshot,operation='refresh')['allowed'])
        self.assertEqual(self.limits['fee_ceilings_sat_kvb']['round'],5000)
    def test_empty_other_operation_and_urgent_mislabel_refused(self):
        for operation in ('ordinary','claim','progression','refresh','offboard_all','unknown'):
            value=copy.deepcopy(self.limits);value['operation_fee_paths'][operation]=[]
            with self.subTest(operation=operation),self.assertRaises(ValueError):validate(value,self.config)
        for path in ('claim','progression'):
            value=copy.deepcopy(self.limits);value['operation_fee_paths']['board']=[path]
            with self.assertRaisesRegex(ValueError,'urgent'):validate(value,self.config)
    def test_empty_scope_retains_readiness_identity_funding_and_action_caps(self):
        self.declare()
        for changes in ({'complete':False},{'financial_pins':{}},{'available_fee_funding_msat':999999},{'observed_at':0}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):preflight(self.store,self.config,self.readiness(**changes),operation='board')
        with self.assertRaisesRegex(ValueError,'per-action'):preflight(self.store,self.config,self.readiness(),operation='board',maximum_fee_sat=201)
        with self.assertRaisesRegex(ValueError,'operation not admitted'):preflight(self.store,self.config,self.readiness(operation_scope=['board']),operation='send_arkoor')

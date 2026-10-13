"""Synthetic ledger regressions: fixtures never dispatch clients or earn live credit."""
import json
import tempfile
import unittest
from pathlib import Path
from simulator.campaign import CampaignClock, RampPlan, traffic_ready
from simulator.engine import initialize
from simulator.model import canonical
from simulator.report import generate
from simulator.store import Store

PINS = {'product_commit':'1'*40, 'sdk_commit':'2'*40, 'driver_sha256':'3'*64,
        'configuration_sha256':'4'*64, 'schema_sha256':'5'*64}

class FinalCampaignRegressions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name), 'synthetic', 1000000)
        initialize(self.store)
        self.store.db.execute("INSERT INTO meta VALUES ('real_campaign_started','100')")
        self.declaration = {'id':'final-fixture', 'pins':PINS, 'started_at':100,
            'windows_seconds':{'ark':600, 'internal_lightning':600, 'external_lightning':600},
            'minimum_observations':{'ark':1, 'internal_lightning':1, 'external_lightning':1}}
        self.store.db.execute("INSERT INTO meta VALUES ('final_financial_epoch',?)", (canonical(self.declaration),))

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def transfer(self, identity, operation, data, at, args=None):
        self.store.queue(identity, 'actor-01', 'H07', operation, args or {}, 0)
        self.store.db.execute('UPDATE action SET state=?,result=?,updated_at=? WHERE id=?',
            ('completed', canonical({'status':'ok', 'data':data}), at, identity))

    def old_dual_rail(self):
        self.transfer('ark', 'send_arkoor', {'submitted':'send_arkoor'}, 101)
        self.store.event('ark_transfer_verified', {'action_id':'ark', 'verified_at':101})
        self.transfer('internal', 'pay_invoice', {'paid':True, 'payment_status_verified':True,
            'payment_state':'succeeded'}, 102, {'recipient_actor':'actor-02'})

    def test_final_clock_cannot_use_old_dual_rail_as_complete_three_rail_evidence(self):
        self.old_dual_rail()
        self.assertFalse(traffic_ready(self.store, 103),
            'internal Lightning plus Ark does not qualify external Lightning or final financial pins')

    def test_final_clock_does_not_credit_a_foreign_financial_epoch(self):
        self.old_dual_rail()
        self.store.event('final_traffic_verified', {'epoch_id':'previous-financial-build',
            'pins':PINS, 'rail':'external_lightning', 'action_id':'internal', 'verified_at':102})
        self.assertFalse(traffic_ready(self.store, 103), 'an older financial build cannot earn new final time')

    def test_creating_ramp_actor_rows_does_not_qualify_the_actual_funded_ramp(self):
        # Existing expansion is useful preparation, but has no funding or boards.
        clock_now = [0]
        clock = CampaignClock(self.store, RampPlan(), clock=lambda:clock_now[0])
        clock.tick(healthy=True, real_campaign_started=True)
        for _ in range(90):
            clock_now[0] += 120
            clock.tick(healthy=True, real_campaign_started=True)
        report = generate(self.store)
        self.assertFalse(report['campaign']['ramp_applied'],
            'preparing actor rows cannot report a final-build qualified funded ramp')

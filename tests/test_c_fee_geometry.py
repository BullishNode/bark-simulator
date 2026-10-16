"""Prospective source/state controls only; no Core signing or live liquidity proof."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from simulator import c_fee_geometry as geometry, c_pilot
from simulator.architecture import DIRECT_PER_KEY
from simulator.model import canonical
from simulator.store import Store
from tests.test_c_pilot import pilot


class WatchGeometryControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name)/'state', 'synthetic', 60000,
                           architecture_profile=DIRECT_PER_KEY)
        self.store.db.execute("INSERT INTO meta VALUES('paused','true')")
        c_pilot.declare(self.store, pilot())
        self.amounts = {'actor-01': 25000, 'watchman': 100000}
        self.rows = [self.row('actor-01', 25000), self.row('watchman', 100000)]
        self.addresses = {('watchman', 0, i): ('watch'+str(i), '0014'+str(i+1)*40)
                          for i in range(2)}

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    @staticmethod
    def row(member, amount):
        return {'member_id': member, 'amount_sat': amount,
                'role': 'operator' if member=='watchman' else 'customer',
                'address': member, 'script': '0014'+'a'*40 if member=='watchman' else '0014'+'b'*40,
                'descriptor_index': 0, 'child_index': 0}

    def test_explicit_geometry_preserves_grants_budgets_and_no_readiness(self):
        original = self.store.get_meta(c_pilot.KEY)
        self.assertIsNone(geometry.declaration(self.store))
        self.assertEqual(self.rows, geometry.expand_recipients(self.store, self.rows, self.addresses))
        self.assertTrue(geometry.declare(self.store))
        self.assertFalse(geometry.declare(self.store))
        value = geometry.declaration(self.store)
        self.assertEqual([50000, 50000], value['amounts_sat'])
        self.assertFalse(value['financial_readiness'])
        self.assertFalse(value['new_spending_authority'])
        self.assertEqual((60000,40000), (value['ordinary_budget_sat'],value['urgent_budget_sat']))
        self.assertEqual(original, self.store.get_meta(c_pilot.KEY))
        rows = geometry.expand_recipients(self.store, self.rows, self.addresses)
        self.assertEqual(3, len(rows))
        self.assertEqual(125000, sum(row['amount_sat'] for row in rows))
        self.assertEqual({0,1}, {r['child_index'] for r in rows if r['member_id']=='watchman'})
        geometry.validate_recipients(self.store, rows, self.amounts)
        # This is a prospective physical layout fact, not native coin selection.
        self.assertGreaterEqual(sum(r['amount_sat'] for r in rows if r['member_id']=='watchman')-50000,40000)
        self.assertFalse(self.store.db.execute('SELECT 1 FROM action').fetchone())
        self.assertIsNone(self.store.get_meta('finite_initial_funding_plan'))

    def test_duplicate_scripts_wrong_sums_and_unapproved_children_refused(self):
        geometry.declare(self.store)
        rows = geometry.expand_recipients(self.store, self.rows, self.addresses)
        mutations = [lambda r:r[1].update(amount_sat=100000),
                     lambda r:r[2].update(child_index=2),
                     lambda r:r[2].update(script=r[1]['script']),
                     lambda r:r[2].update(address=r[1]['address']),
                     lambda r:r[1].update(role='customer'),
                     lambda r:r[0].update(member_id='foreign'),
                     lambda r:r[2].update(descriptor_index=1)]
        for mutate in mutations:
            bad = copy.deepcopy(rows); mutate(bad)
            with self.subTest(rows=bad), self.assertRaises(ValueError):
                geometry.validate_recipients(self.store,bad,self.amounts)
        with self.assertRaises(ValueError):
            geometry.validate_recipients(self.store,self.rows,self.amounts)

    def test_no_replan_after_original_financial_declaration(self):
        for key in ('finite_initial_funding_plan','fixture_funding_plan',
                    'conserved_treasury_boundary','financial_operating_envelope'):
            self.store.db.execute('INSERT INTO meta VALUES(?,?)',(key,'{}'))
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'preserve'):
                geometry.declare(self.store)
            self.store.db.execute('DELETE FROM meta WHERE key=?',(key,))

    def test_no_replan_after_prepare_unknown_or_cost_history(self):
        for kind in ('fixture_funding_intent','fixture_funding_prepare_intent',
                     'fixture_funding_prepared','fixture_funding_broadcast_intent','financial_cost_verified'):
            with self.store.transaction():
                self.store._event(kind, {'synthetic':True})
            with self.subTest(kind=kind),self.assertRaisesRegex(ValueError,'monetary'):
                geometry.declare(self.store)
            # Each refusal is read-only. The test retains the growing real chain.
        self.assertIsNone(self.store.get_meta(geometry.KEY))

    def test_original_event_and_metadata_cannot_be_changed_or_removed(self):
        geometry.declare(self.store)
        value = json.loads(self.store.get_meta(geometry.KEY)); value['amounts_sat']=[40000,60000]
        self.store.db.execute('UPDATE meta SET value=? WHERE key=?',(canonical(value),geometry.KEY))
        with self.assertRaises(ValueError):geometry.declaration(self.store)
        self.store.db.execute('DELETE FROM meta WHERE key=?',(geometry.KEY,))
        with self.assertRaisesRegex(ValueError,'missing'):geometry.declaration(self.store)

    def test_unpaused_or_other_architecture_cannot_declare(self):
        self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        with self.assertRaisesRegex(ValueError,'pause'):geometry.declare(self.store)
        other = Store(Path(self.tmp.name)/'other','synthetic',60000)
        try:
            self.assertIsNone(geometry.validate_recipients(other,self.rows,self.amounts))
            with self.assertRaisesRegex(ValueError,'C-only'):geometry.declare(other)
        finally:other.close()

    def test_undeclared_duplicate_member_outputs_do_not_enter_legacy_path(self):
        bad = copy.deepcopy(self.rows)
        bad[1]['amount_sat']=50000
        bad.append({**bad[1],'address':'different','script':'0014'+'c'*40,'child_index':1})
        with self.assertRaises(ValueError):geometry.validate_recipients(self.store,bad,self.amounts)


if __name__ == '__main__':
    unittest.main()

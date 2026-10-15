import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from simulator.architecture import PROFILES
from simulator.engine import catalog, initialize
from simulator.report import coverage
from simulator.store import Store


class ScenarioProfileContractsTests(unittest.TestCase):
    def test_unprofiled_catalogue_is_the_original_source(self):
        original = json.loads((Path(__file__).resolve().parents[1] /
                               'simulator/scenarios.json').read_text())
        self.assertEqual(catalog(), original)

    def test_profiles_preserve_all_case_ids_and_driver_routes(self):
        original = {case['id']: case for case in catalog()}
        self.assertEqual(len(original), 80)
        for profile in PROFILES:
            selected = {case['id']: case for case in catalog(profile)}
            self.assertEqual(selected.keys(), original.keys())
            for identifier, case in selected.items():
                self.assertEqual(case['driver'], original[identifier]['driver'])
                if identifier in {'H25', 'H27', 'H29', 'H32'}:
                    self.assertEqual(case['profile_contract']['profile'], profile)
                else:
                    self.assertEqual(case, original[identifier])

    def test_fresh_profile_state_uses_own_contract_without_qualification(self):
        for profile in PROFILES:
            with tempfile.TemporaryDirectory(dir='/dev/shm') as root:
                store = Store(Path(root), 'live', 10000, architecture_profile=profile)
                try:
                    initialize(store)
                    selected = {case['id']: case for case in catalog(profile)}
                    rows = coverage(store)
                    self.assertEqual(len(rows), 80)
                    for row in rows:
                        self.assertEqual(row['behavior'], selected[row['id']]['behavior'])
                        self.assertEqual(row['scenario_verdict'], 'not_exercised')
                        self.assertEqual(row['verified_actions'], 0)
                finally:
                    store.close()

    def test_existing_history_never_adopts_new_description(self):
        profile = 'two_step_per_key'
        with tempfile.TemporaryDirectory(dir='/dev/shm') as root:
            store = Store(Path(root), 'live', 10000, architecture_profile=profile)
            try:
                initialize(store)
                before = {row['id']: row['behavior'] for row in coverage(store)}
                changed = copy.deepcopy(catalog(profile))
                changed[0]['behavior'] = 'A later source change must not rewrite this history.'
                with patch('simulator.engine.catalog', return_value=changed):
                    initialize(store)
                self.assertEqual({row['id']: row['behavior'] for row in coverage(store)}, before)
                self.assertTrue(store.verify_event_chain())
            finally:
                store.close()


if __name__ == '__main__':
    unittest.main()

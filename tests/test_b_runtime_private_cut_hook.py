"""Private capture ordering over the runtime loop and its real verifier.

No Docker, database, wallet, native tool or protected live source is opened.
"""
import copy
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

from simulator import b_normal_runtime_source as original
import test_b_normal_runtime_source as fixtures


class ProtectedLoopHookControls(unittest.TestCase):
    def setUp(self):
        self.module = original
        self.expected, self.checkpoint, self.observation = fixtures.fixture()
        self.events = []
        self.schema = b'owned-synthetic-schema\n'
        self.inventory_raw = {
            'rounds_inventory': b'{\"rounds\":{\"wallet\":\"rounds\",\"original\":1}}\n',
            'watchman_inventory': b'{\"watchman\":{\"wallet\":\"watchman\",\"original\":2}} \n'}
        self.expected['canonical_schema_sha256'] = original.digest(self.schema)
        self.checkpoint['expected_sha256'] = original.identity(self.expected)
        self.before = copy.deepcopy(self.observation['before'])
        self.after = copy.deepcopy(self.before)
        self.before_budget = copy.deepcopy(self.observation['native_budget'])
        self.after_budget = copy.deepcopy(self.before_budget)
        self.route_before = copy.deepcopy(self.observation['owner_route'])
        self.route_after = copy.deepcopy(self.route_before)
        self.private_result = {'raw_sql': b'EXACT-SYNTHETIC-PUBLIC-SQL\n',
            'auxiliary_originals': {'exact-private-source': b'PRIVATE-SYNTHETIC-BUFFER\n'}}

    def invoke(self, *, private_mode=True, mutation=None):
        module = self.module
        daemon_calls = 0
        budget_calls = 0
        route_calls = 0

        def daemon(expected, name):
            nonlocal daemon_calls
            phase = 'before' if daemon_calls < len(original.SERVICES) else 'after'
            daemon_calls += 1
            self.events.append(phase + ':' + name)
            return copy.deepcopy((self.before if phase == 'before' else self.after)[name])

        def budget(expected, helper):
            nonlocal budget_calls
            self.events.append('budget:' + str(budget_calls))
            value = self.before_budget if budget_calls == 0 else self.after_budget
            budget_calls += 1
            return copy.deepcopy(value)

        def route(daemons):
            nonlocal route_calls
            self.events.append('route:' + str(route_calls))
            value = self.route_before if route_calls == 0 else self.route_after
            route_calls += 1
            return copy.deepcopy(value)

        def cut(expected, observed_budget):
            self.events.append('private-cut')
            self.assertEqual(expected, self.expected)
            self.assertEqual(observed_budget, self.before_budget)
            self.assertEqual(budget_calls, 1)
            self.assertEqual(daemon_calls, len(original.SERVICES))
            self.assertIsNotNone(module._CAPTURE_END.get())
            if mutation is not None:
                mutation()
            return copy.deepcopy(self.private_result)

        def run(command, maximum=2 * 1024 * 1024):
            if 'pg_dump' in command:
                self.events.append('schema')
                return self.schema
            self.events.append('inventory:' + command[2])
            self.assertEqual(maximum, 65536)
            return self.inventory_raw['rounds_inventory' if command[2] == self.expected['containers']['captaind'] else 'watchman_inventory']

        expected_raw = json.dumps(self.expected).encode()
        checkpoint_raw = json.dumps(self.checkpoint).encode()

        def checked_file(path):
            raw = expected_raw if str(path) == '/owned/expected' else checkpoint_raw if str(path) == '/owned/checkpoint' else Path(path).read_bytes()
            return raw, original.digest(raw)

        actual_verify = module.verify

        def verify(expected, checkpoint, observation):
            self.events.append('verify')
            return actual_verify(expected, checkpoint, observation,
                now_ns=observation['completed_at_ns'] + 1)

        private = types.ModuleType('simulator.b_private_native_fee_capture')
        private.capture_private_cut = unittest.mock.Mock(side_effect=cut)
        with patch.dict(sys.modules, {'simulator.b_private_native_fee_capture': private}), \
             patch.object(module, '_helper', return_value=object()), \
             patch.object(module, '_daemon', side_effect=daemon), \
             patch.object(module, '_budget', side_effect=budget), \
             patch.object(module, '_owner_route', side_effect=route), \
             patch.object(module, '_lock', return_value=copy.deepcopy(self.observation['budget_lock'])), \
             patch.object(module, '_run', side_effect=run), \
             patch.object(module, 'checked_file', side_effect=checked_file), \
             patch.object(module, 'verify', side_effect=verify), \
             patch.object(module.time, 'time_ns', side_effect=[self.observation['started_at_ns'], self.observation['completed_at_ns']]):
            if private_mode:
                value = module.capture_native_fee_originals_protected('/owned/expected', '/owned/checkpoint')
            else:
                value = module.capture(self.expected, self.checkpoint)
            return value, private.capture_private_cut.call_count

    def test_success_returns_exact_private_originals_only_after_same_window_verification(self):
        (runtime_originals, private_originals), calls = self.invoke()
        self.assertEqual(calls, 1)
        self.assertEqual(private_originals, {**self.private_result, 'wallet_inventory_originals': self.inventory_raw})
        self.assertEqual(set(runtime_originals), {'expected_raw', 'checkpoint_raw', 'observation_raw', 'protected_receipt_raw'})
        observation = json.loads(runtime_originals['observation_raw'])
        receipt = json.loads(runtime_originals['protected_receipt_raw'])
        self.assertNotIn('private-cut', json.dumps(observation))
        self.assertNotIn('PRIVATE-SYNTHETIC', json.dumps(runtime_originals))
        for role, daemon in [('rounds_inventory', 'captaind'), ('watchman_inventory', 'watchmand')]:
            self.assertEqual(original.digest(private_originals['wallet_inventory_originals'][role]),
                receipt['daemons'][daemon]['admin_response_sha256'])
        self.assertEqual(sum(e.startswith('inventory:') for e in self.events), 2)
        self.assertNotIn('wallet_inventory_originals', observation)
        self.assertFalse(receipt['complete'])
        self.assertFalse(receipt['qualified'])
        self.assertLess(self.events.index('budget:0'), self.events.index('private-cut'))
        self.assertLess(self.events.index('private-cut'), self.events.index('budget:1'))
        self.assertLess(self.events.index('private-cut'), self.events.index('after:watchmand'))
        self.assertLess(self.events.index('route:1'), self.events.index('verify'))

    def test_after_query_owner_mutation_refuses_before_any_private_return(self):
        def mutation():
            self.after_budget['files']['ordinary-fee-budget']['sha256'] = 'c' * 64
        with self.assertRaisesRegex(ValueError, 'changed during'):
            self.invoke(mutation=mutation)
        self.assertIn('private-cut', self.events)
        self.assertIn('verify', self.events)

    def test_after_query_process_mutation_refuses_before_any_private_return(self):
        def mutation():
            self.after['watchmand']['proc_start_ticks'] += 1
        with self.assertRaisesRegex(ValueError, 'same actual'):
            self.invoke(mutation=mutation)

    def test_after_query_route_mutation_refuses_before_any_private_return(self):
        def mutation():
            self.route_after['watch_listener']['inode'] += 1
        with self.assertRaisesRegex(ValueError, 'route'):
            self.invoke(mutation=mutation)

    def test_default_public_capture_never_calls_private_helper(self):
        (observation, receipt), calls = self.invoke(private_mode=False)
        self.assertEqual(calls, 0)
        self.assertNotIn('private-cut', self.events)
        self.assertNotIn('auxiliary_originals', observation)
        self.assertNotIn('wallet_inventory_originals', observation)
        self.assertFalse(receipt['complete'])
        self.assertFalse(receipt['qualified'])


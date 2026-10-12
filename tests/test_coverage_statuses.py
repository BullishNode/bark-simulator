"""Coverage counts meaningful operations without certifying whole scenarios."""
import tempfile
import unittest
from pathlib import Path

from simulator.engine import initialize
from simulator.report import generate
from simulator.store import Store


class CoverageStatusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.s = Store(Path(self.tmp.name), 'synthetic', 10000)
        initialize(self.s)

    def tearDown(self):
        self.s.close()
        self.tmp.cleanup()

    def action(self, name, operation, scenario='H01', state='completed', result=None, actual=None):
        self.s.queue(name, 'actor-01', scenario, operation, {}, 1)
        if state != 'queued':
            self.s.db.execute("UPDATE action SET state='dispatched' WHERE id=?", (name,))
            self.s.finish(name, state, result or {}, actual)

    def case(self, scenario='H01'):
        return next(c for c in generate(self.s, evaluate=False)['coverage'] if c['id'] == scenario)

    def test_maintenance_does_not_inflate_board_coverage_or_verify_it(self):
        with self.s.transaction():
            self.s.db.executemany("""INSERT INTO action VALUES (?, 'actor-01','H01','snapshot','{}',
                'completed',0,0,0,'{}',?,?)""", [(f'snapshot-{i}', i, i) for i in range(100)])
        self.action('board', 'board')
        case = self.case()
        self.assertEqual(1, case['actions'])
        self.assertEqual('executed-unverified', case['status'])
        self.assertEqual('not_qualified', case['scenario_verdict'])
        self.assertEqual(100, case['excluded_maintenance_actions'])
        self.assertTrue(case['driver_available'])


if __name__ == '__main__':
    unittest.main()

import asyncio
import json
import sys
import unittest
import test_continuous as helpers
from simulator.continuous import schedule
from simulator.model import public_payload
from simulator.process import text_command, MAX_RESPONSE_BYTES


class DecisionLogs(unittest.TestCase):
    setUp=helpers.ContinuousTests.setUp
    tearDown=helpers.ContinuousTests.tearDown
    detail=helpers.ContinuousTests.detail

    def test_dry_wallet_reason_and_inputs_are_logged_in_one_tick_event(self):
        self.detail('actor-01', registered_spendable_sat=1500)
        schedule(self.s, self.c, self.snapshot)
        rows=self.s.db.execute("SELECT payload FROM event WHERE kind='scheduler_tick'").fetchall()
        self.assertEqual(1,len(rows))
        actor=next(x for x in json.loads(rows[0][0])['actors'] if x['actor']=='actor-01')
        self.assertEqual('dry_wallet',actor['rule_id'])
        self.assertEqual(1500,actor['inputs']['spendable'])
        self.assertEqual('held',actor['outcome'])

    def test_unknown_outcome_is_logged_and_never_retried(self):
        self.s.queue('ambiguous','actor-01','H01','board',{},2000)
        self.s.db.execute("UPDATE action SET state='outcome_unknown' WHERE id='ambiguous'")
        schedule(self.s, self.c, self.snapshot)
        row=self.s.db.execute("SELECT payload FROM event WHERE kind='scheduler_tick'").fetchone()
        self.assertIsNotNone(row)
        actor=next(x for x in json.loads(row[0])['actors'] if x['actor']=='actor-01')
        self.assertEqual('unknown_outcome',actor['rule_id'])
        self.assertEqual(1,self.s.db.execute('SELECT COUNT(*) FROM action').fetchone()[0])


class DriverStderr(unittest.TestCase):
    def test_stderr_is_captured_separately_from_response(self):
        logs=[]
        result=asyncio.run(text_command([sys.executable,'-c',
            'import sys; print("trace line",file=sys.stderr); print("{}")'],
            on_stderr=logs.append))
        self.assertEqual('{}',result.strip())
        self.assertEqual('trace line\n',logs[0]['text'])
        self.assertFalse(logs[0]['truncated'])

    def test_large_stderr_is_drained_and_bounded_without_blocking_result(self):
        logs=[]
        result=asyncio.run(text_command([sys.executable,'-c',
            'import sys; sys.stderr.write("x"*400000); print("{}")'],
            on_stderr=logs.append))
        self.assertEqual('{}',result.strip())
        self.assertEqual(256*1024,len(logs[0]['text'].encode()))
        self.assertTrue(logs[0]['truncated'])
        self.assertEqual(400000,logs[0]['bytes'])

    def test_plaintext_mnemonic_log_cannot_enter_public_event(self):
        with self.assertRaises(ValueError):
            public_payload({'text':'mnemonic: [redacted fixture secret]'} )

"""Fixed private query/framing source controls; no PostgreSQL qualification."""
import re
import unittest
from simulator.b_private_native_fee_cut import sql,query_sha256,PRIVATE_TABLES
from simulator.two_step_normal import digest
from simulator.ownership import EvidenceGap
from test_b_native_owner_snapshot import PrivateInputControls


class PrivateCutControls(unittest.TestCase):
    def test_one_fixed_readonly_rr_transaction_and_two_json_results(self):
        query=sql()
        self.assertTrue(query.startswith('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;'))
        self.assertTrue(query.endswith('; COMMIT;'))
        self.assertEqual(query.count('COMMIT;'),1)
        self.assertEqual(query.count("SET LOCAL statement_timeout='8s'"),1)
        self.assertIn("current_setting('transaction_read_only')='on'",query)
        self.assertIn("current_setting('transaction_isolation')='repeatable read'",query)
        self.assertIn("'kind','closed_frontier'",query)
        self.assertEqual(query_sha256(),digest(query.encode()))
        self.assertFalse(re.search(r'\b(INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE)\b',query,re.I))
        with self.assertRaises(TypeError):sql('SELECT caller_selected')
    def test_private_set_is_whole_and_has_native_exact_field_names(self):
        self.assertEqual(set(PRIVATE_TABLES),{'native_funding_fee_intent','native_funding_fee_input',
            'native_funding_fee_resolution','nursery_tx'})
        for table,key,columns in PRIVATE_TABLES.values():
            self.assertNotIn(' WHERE ',columns);self.assertNotIn(' LIMIT ',columns)
        self.assertIn("encode(signed_tx,'hex') AS signed_tx_hex",sql())
        self.assertIn("encode(tx,'hex') AS tx_hex",sql())
        self.assertIn('urgent_fee_attempt,urgent_fee_bound',sql())
        self.assertIn('outpoint,attempt_key FROM native_funding_fee_input',sql())
        self.assertNotIn("coalesce(encode",sql())
    def test_whole_raw_package_and_json_metadata_bounds_precede_materialization(self):
        query=sql();bound=query.index('DO $b_native_fee_cut$')
        self.assertLess(bound,query.index("'kind','closed_frontier'"))
        for fragment in ('count(*)>4096 FROM native_funding_fee_intent',
                         'count(*)>10000 FROM native_funding_fee_input',
                         'count(*)>4096 FROM native_funding_fee_resolution',
                         'count(*)>10000 FROM nursery_tx','octet_length(tx)',
                         'octet_length(urgent_fee_attempt::text)','> 16777216'):
            self.assertIn(fragment,query)
        self.assertIn("RAISE EXCEPTION 'bounded complete native fee source unavailable'",query)
        self.assertNotIn('EXCEPTION WHEN',query)
    def test_unguarded_or_two_cut_stdout_does_not_become_native_request(self):
        f=PrivateInputControls();target,runtime,observation=f.inputs()
        f.mutate_originals(target,lambda value:value.update(sql_raw=value['sql_raw'].replace('DO\n','')))
        with self.assertRaisesRegex(EvidenceGap,'bounded single RR'):f.prepare(target,runtime,observation)

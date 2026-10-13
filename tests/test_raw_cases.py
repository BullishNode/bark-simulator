import tempfile, unittest
from pathlib import Path
from simulator.engine import initialize
from simulator.store import Store
from simulator.raw_cases import RAW_CASES,AUTOMATIC_RAW_CASES,next_case

class RawCasesTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.store=Store(Path(self.tmp.name),'synthetic',10000);initialize(self.store)
    def tearDown(self):
        self.store.close();self.tmp.cleanup()
    def test_victim_signature_case_requires_another_verified_public_key(self):
        self.store.db.execute("INSERT INTO owner_key VALUES ('own','actor-11','own-mailbox','{}')")
        self.assertNotEqual('D01',next_case(self.store,'actor-11',0)[0])
        self.store.db.execute("INSERT INTO owner_key VALUES ('victim','actor-01','victim-mailbox','{}')")
        self.assertEqual(('D01','raw_foreign_record',{'victim_mailbox_pk':'victim-mailbox'}),next_case(self.store,'actor-11',0))
        self.assertEqual(('D08','raw_invalid_link',{'victim_pubkey':'victim'}),next_case(self.store,'actor-11',7))
    def test_all_adapters_have_distinct_catalogue_cases(self):
        self.assertEqual(14,len(AUTOMATIC_RAW_CASES));self.assertEqual(27,len(RAW_CASES));self.assertEqual(27,len(set(RAW_CASES.values())))
        self.assertEqual('D09',RAW_CASES['raw_mailbox_tamper'])
    def test_malformed_variants_are_bounded_and_repeatable(self):
        for count in [13,27,41,55]:
            self.assertEqual(('D40','raw_malformed',{'variant':count//14%3}),next_case(self.store,'actor-11',count))

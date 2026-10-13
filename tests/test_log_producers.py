import unittest

class PublicLogProducerTests(unittest.TestCase):
    def request(self,cursor=None,**kwargs):
        return {'kind':'logs','component':'captaind','since_us':1000000,'cursor':cursor,'limit':2,'maximum_bytes':1024,**kwargs}
    def records(self):
        return [{'cursor':'a','utc_us':1000000,'stream':'stdout','text':'first'},
                {'cursor':'b','utc_us':1000000,'stream':'stderr','text':'second'},
                {'cursor':'c','utc_us':1000001,'stream':'stdout','text':'third'}]
    def test_repeated_timestamps_page_by_exact_ordinal_and_resume_without_skipping(self):
        from simulator.log_producer import page_records
        first=page_records(self.request(),self.records(),source_id='instance1')
        self.assertEqual(2,len(first['rows']));self.assertTrue(first['more']);self.assertEqual(2,first['next_cursor']['ordinal'])
        second=page_records(self.request(first['next_cursor']),self.records(),source_id='instance1')
        self.assertEqual(['third'],[r['text'] for r in second['rows']]);self.assertFalse(second['more'])
    def test_private_log_becomes_marker_with_no_secret_text_or_hash_and_cursor_advances(self):
        import json
        from simulator.log_producer import page_records
        records=[{'cursor':'a','utc_us':1000000,'stream':'stdout','text':'seed: '+'ab'*32},self.records()[1]]
        result=page_records(self.request(),records,source_id='instance1');encoded=json.dumps(result)
        self.assertNotIn('ab'*32,encoded);self.assertTrue(result['rows'][0]['redacted']);self.assertEqual(2,result['next_cursor']['ordinal'])
    def test_source_replacement_is_named_gap_and_never_silently_continues_old_ordinal(self):
        from simulator.log_producer import page_records
        first=page_records(self.request(),self.records(),source_id='instance1')
        second=page_records(self.request(first['next_cursor']),self.records(),source_id='instance2')
        self.assertEqual('source_replaced',second['gap']['kind']);self.assertEqual([],second['rows'])
    def test_requests_reject_arbitrary_units_paths_commands_and_resource_bypass(self):
        from simulator.log_producer import validate_request
        for extra in [{'component':'other-container'},{'limit':0},{'limit':10001},{'maximum_bytes':999999999},
          {'command':'docker exec'}, {'path':'/etc/shadow'}, {'cursor':{'source_id':'instance1','utc_us':1000000,'ordinal':-1}},
          {'since_us':True}]:
            with self.subTest(extra=extra),self.assertRaises(ValueError):validate_request(self.request(**extra),{'captaind','watchmand'})
    def test_local_journal_reader_uses_bounded_head_order_and_selected_service_only(self):
        from simulator.log_producer import journal_command
        argv=journal_command('bark-simulator.service','cursor123',2)
        self.assertIn('--lines=+3',argv);self.assertIn('--after-cursor=cursor123',argv)
        self.assertIn('--unit=bark-simulator.service',argv);self.assertIn('--output=json',argv)
        self.assertNotIn('--follow',argv)
    def test_structured_seed_and_surrounding_phrase_are_redacted_without_hashing(self):
        from simulator.log_producer import page_records
        secrets=['{"seed":"'+'cd'*32+'"}', 'context '+('abandon '*12).strip()+' suffix']
        for secret in secrets:
            result=page_records(self.request(),[{'utc_us':1000000,'stream':'stdout','text':secret}],source_id='instance1')
            self.assertTrue(result['rows'][0]['redacted']);self.assertNotIn('raw_line',result['rows'][0]);self.assertNotIn('text',result['rows'][0])
    def test_native_journal_cursor_resumes_equal_timestamp_without_replaying_old_rows(self):
        from simulator.log_producer import page_records
        cursor={'source_id':'journal:simulator.service','utc_us':1000000,'ordinal':2,'token':'old'}
        result=page_records(self.request(cursor),[{'utc_us':1000000,'cursor':'new','stream':'service','text':'next'}],source_id=cursor['source_id'],after_native_cursor=True)
        self.assertEqual(3,result['next_cursor']['ordinal']);self.assertEqual('new',result['next_cursor']['token'])
    def test_missing_retained_cursor_and_nonmonotonic_input_are_explicit_gaps(self):
        from simulator.log_producer import page_records
        cursor={'source_id':'instance1','utc_us':1000000,'ordinal':2}
        empty=page_records(self.request(cursor),[],source_id='instance1')
        self.assertEqual('cursor_missing',empty['gap']['kind']);self.assertEqual(0,empty['next_cursor']['ordinal'])
        records=[self.records()[2],self.records()[0]]
        invalid=page_records(self.request(),records,source_id='instance1')
        self.assertEqual('nonmonotonic_log_order',invalid['gap']['kind'])
    def test_real_bounded_child_preserves_complete_prefix_and_stops_only_own_process(self):
        import sys
        from simulator.log_producer import ProcessRecords,parse_docker,page_records
        code='import time;print("2026-01-01T00:00:00.000000000Z public tick",flush=True);time.sleep(20)'
        with ProcessRecords([sys.executable,'-c',code],parse_docker,timeout=.1) as records:
            result=page_records({**self.request(),'since_us':0},records,source_id='instance1')
            self.assertEqual(1,len(result['rows']));self.assertEqual('producer_timeout',records.gap['kind'])
            child=records.process
        self.assertIsNotNone(child.poll())

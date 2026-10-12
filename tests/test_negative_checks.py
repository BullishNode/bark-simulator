import asyncio,json,tempfile,unittest
from pathlib import Path
from unittest.mock import AsyncMock,patch
from simulator.engine import initialize
from simulator.model import InvariantError
from simulator.negative_checks import check,request_for,collect
from simulator.ownership import EvidenceGap
from simulator.store import Store
class NegativeChecks(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.s=Store(Path(self.tmp.name),'synthetic',10000);initialize(self.s)
        self.record={'mailbox_pk':'02'+'1'*64,'spk':'0014'+'2'*40,'seq':10,'sig':'3'*128}
        self.protected={'mailbox_pk':self.record['mailbox_pk'],'serialized':self.record['spk']+(10).to_bytes(8,'little').hex()+self.record['sig']}
        self.request={'kind':'binding_check','mailboxes':[self.record['mailbox_pk']],'keys':['03'+'4'*64]}
        self.observed={**self.request,'records':[self.record],'links':[],'inventory_consistent':True}
    def tearDown(self):self.s.close();self.tmp.cleanup()
    def test_absence_of_forged_new_key_and_exact_record_are_proved(self):
        self.assertTrue(check(self.request,{self.request['keys'][0]:None},self.protected,self.observed)['key_mappings_unchanged'])
    def test_partial_insert_is_an_incident_even_with_null_mapping(self):
        for mailbox in [None,self.record['mailbox_pk']]:
            self.observed['links']=[{'user_pubkey':self.request['keys'][0],'mailbox_pk':mailbox,'sig':'fake'}]
            with self.assertRaises(InvariantError):check(self.request,{self.request['keys'][0]:None},self.protected,self.observed)
    def test_mapping_redirect_and_record_update_are_incidents(self):
        self.observed['links']=[{'user_pubkey':self.request['keys'][0],'mailbox_pk':'thief','sig':'fake'}]
        with self.assertRaises(InvariantError):check(self.request,{self.request['keys'][0]:self.record['mailbox_pk']},self.protected,self.observed)
        self.observed['links']=[];self.observed['records']=[{**self.record,'seq':11}]
        with self.assertRaises(InvariantError):check(self.request,{self.request['keys'][0]:None},self.protected,self.observed)
    def test_cyclic_or_different_snapshot_is_not_a_pass(self):
        self.observed['inventory_consistent']=False
        with self.assertRaises(EvidenceGap):check(self.request,{self.request['keys'][0]:None},self.protected,self.observed)
        self.observed['inventory_consistent']=True;self.observed['keys']=[]
        with self.assertRaises(InvariantError):check(self.request,{},self.protected,self.observed)
    def test_relink_requires_original_mapping_and_a_valid_independent_signature(self):
        self.s.queue('relink','actor-01','D11','raw_relink',{},0)
        self.s.db.execute("UPDATE action SET state='dispatched' WHERE id='relink'")
        self.s.finish('relink','completed',{'data':{'protected_record':self.protected,'user_pubkey':self.request['keys'][0],'original_mailbox_pk':self.record['mailbox_pk']}})
        self.observed['links']=[{'user_pubkey':self.request['keys'][0],'mailbox_pk':self.record['mailbox_pk'],'sig':'fake'}]
        mocked=AsyncMock(side_effect=[self.observed,ValueError('signature invalid')])
        with patch('simulator.negative_checks.json_command',mocked):asyncio.run(collect(self.s,['bridge'],['proof']))
        self.assertEqual('pending',self.s.db.execute('SELECT state FROM negative_check').fetchone()[0])
        mocked=AsyncMock(side_effect=[self.observed,{'user_pubkey':self.request['keys'][0],'binding':{'mailbox_pk':self.record['mailbox_pk'],'spk':self.record['spk'],'seq':10,'record_signature_valid':True,'key_link_signature_valid':True}}])
        with patch('simulator.negative_checks.json_command',mocked):asyncio.run(collect(self.s,['bridge'],['proof']))
        self.assertEqual('checked',self.s.db.execute('SELECT state FROM negative_check').fetchone()[0])
        self.s.verify_event_chain();self.assertEqual(1,self.s.db.execute("SELECT COUNT(*) FROM event WHERE kind='negative_binding_checked'").fetchone()[0])
    def test_explicitly_invalidated_run_cannot_be_promoted_by_a_later_checker(self):
        self.s.queue('old','actor-01','D02','raw_record_tamper',{},0)
        self.s.db.execute("UPDATE action SET state='dispatched' WHERE id='old'")
        self.s.finish('old','expected_refusal',{'data':{}},0)
        self.s.db.execute("INSERT INTO negative_check VALUES ('old','invalidated','{}',0)")
        mocked=AsyncMock()
        with patch('simulator.negative_checks.json_command',mocked):asyncio.run(collect(self.s,['bridge'],['proof']))
        mocked.assert_not_called()
        self.assertEqual('invalidated',self.s.db.execute('SELECT state FROM negative_check').fetchone()[0])

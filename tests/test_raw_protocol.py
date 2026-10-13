import hashlib,json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from simulator.engine import initialize
from simulator.store import Store
from simulator.model import canonical,InvariantError
from simulator.ownership import EvidenceGap

class RawProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name),'synthetic',100000);initialize(self.store)
        self.server='02'+'33'*32;self.config=SimpleNamespace(expected_server_pubkey=self.server)
        self.actor='actor-11';self.key='02'+'11'*32;self.coin='aa'*32+':0'
        self.store.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',(self.key,self.actor,'mailbox','{}'))
        self.store.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',(self.coin,self.key,5000,hashlib.sha256(b'ab').hexdigest(),b'ab'.hex(),'{}'))
        self.store.queue('snapshot',self.actor,'H01','snapshot',{},0)
        self.store.db.execute("UPDATE action SET state='completed',updated_at=100,result='{}' WHERE id='snapshot'")
        self.store.db.execute('INSERT INTO coin_observation VALUES (?,?,?,?,?)',('snapshot',self.coin,'Spendable',100,None))
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def prepare(self,scenario='D14',**extra):
        from simulator.raw_protocol import queue_probe
        return queue_probe(self.store,self.config,self.actor,scenario,{'input_coin_ids':[self.coin],**extra})
    def test_every_required_scenario_has_one_honest_mechanism_row(self):
        from simulator.raw_protocol import scenario_rows
        rows=scenario_rows(self.store);self.assertEqual([f'D{i:02}' for i in range(13,37)],[r['scenario'] for r in rows])
        for row in rows:self.assertEqual('live-qualification-pending',row['result']);self.assertIn('mechanism',row);self.assertIn('fees',row);self.assertIn('liabilities',row)
    def test_frozen_owned_input_fee_and_server_pin_are_bound_once(self):
        result=self.prepare();action=self.store.db.execute('SELECT * FROM action WHERE id=?',(result['action_id'],)).fetchone()
        self.assertEqual(2000,action['fee_reservation_sat']);args=json.loads(action['args'])
        self.assertEqual(5000,args['probe_intent']['input_amount_sat']);self.assertEqual(self.server,args['probe_intent']['server_pubkey'])
        self.assertEqual([self.coin],args['input_coin_ids']);self.assertEqual(result,self.prepare())
        self.assertEqual(2,self.store.db.execute('SELECT count(*) FROM action').fetchone()[0]);self.store.verify_event_chain()
    def test_original_absent_actor_cannot_be_opened_even_if_marked_online(self):
        from simulator.raw_protocol import queue_probe
        for actor in ['actor-03','actor-09','actor-10']:
            with self.assertRaises(EvidenceGap):queue_probe(self.store,self.config,actor,'D13',{'input_coin_ids':[]})
    def test_foreign_or_public_import_input_cannot_be_spent_by_probe(self):
        self.store.db.execute("UPDATE owner_key SET actor='actor-05'")
        with self.assertRaises(InvariantError):self.prepare()
        self.store.db.execute('UPDATE owner_key SET actor=?',(self.actor,));self.store.db.execute("UPDATE coin_observation SET state='PublicProof'")
        with self.assertRaises(EvidenceGap):self.prepare()
    def test_unknown_action_and_permanent_absence_fences_survive_new_adapters(self):
        self.store.queue('lost',self.actor,'H01','sync',{},2000);self.store.db.execute("UPDATE action SET state='outcome_unknown' WHERE id='lost'")
        with self.assertRaises(EvidenceGap):self.prepare()
        self.store.db.execute("UPDATE action SET state='completed' WHERE id='lost'")
        self.store.db.execute('UPDATE actor SET details=? WHERE id=?',(canonical({'permanent_absence':{'original_wallet_must_stay_closed':True}}),self.actor))
        with self.assertRaises(EvidenceGap):self.prepare()
    def test_phase_race_is_not_an_alias_for_malformed_refusal(self):
        for scenario in ['D17','D18','D19','D20','D24','D26','D27','D28','D33','D34','D36']:
            with self.subTest(scenario=scenario),self.assertRaises(EvidenceGap):self.prepare(scenario)
        self.assertEqual(1,self.store.db.execute('SELECT count(*) FROM action').fetchone()[0])
    def test_refund_and_receive_probes_require_exact_existing_payment_hash(self):
        for scenario in ['D15','D16','D29','D30','D31','D32','D35']:
            with self.subTest(scenario=scenario),self.assertRaises(EvidenceGap):self.prepare(scenario)
    def test_generic_invalid_argument_or_transport_error_never_qualifies(self):
        from simulator.raw_protocol import validate_response
        action_id=self.prepare()['action_id'];action=self.store.db.execute('SELECT * FROM action WHERE id=?',(action_id,)).fetchone()
        for value in [{'rpc':'RequestArkoorCosign','code':'InvalidArgument','guard':'other'}, {'rpc':'RequestArkoorCosign','code':'Unavailable','guard':'missing_fallback'}]:
            with self.subTest(value=value),self.assertRaises(EvidenceGap):validate_response(action,{'probe':value})
    def test_probe_response_is_bound_to_scenario_actor_intent_and_request_hash(self):
        from simulator.raw_protocol import validate_response
        result=self.prepare();action=self.store.db.execute('SELECT * FROM action WHERE id=?',(result['action_id'],)).fetchone()
        base={'scenario':'D14','actor':self.actor,'intent_hash':result['intent_hash'],'request_hash':'dd'*32,'rpc':'RequestArkoorCosign','code':'InvalidArgument','guard':'missing_fallback','attempted_key_pubkeys':['03'+'22'*32],'input_coin_ids':[self.coin],'input_status_before':[1],'input_status_after':[1],'response_message_hash':'ee'*32,'rpc_attempted':True,'actual_fee_sat':0,'client_owner_verified':False}
        self.assertFalse(validate_response(action,{'probe':base})['live_qualified'])
        for changes in [{'actor':'actor-05'},{'scenario':'D16'},{'intent_hash':'ff'*32},{'input_status_after':[2]},{'request_hash':''}]:
            with self.subTest(changes=changes),self.assertRaises(InvariantError):validate_response(action,{'probe':{**base,**changes}})
    def test_secret_arguments_and_excess_fee_cap_are_rejected_before_queue(self):
        with self.assertRaises(ValueError):self.prepare(payment_preimage='secret')
        with self.assertRaises(ValueError):self.prepare(maximum_fee_sat=2001)

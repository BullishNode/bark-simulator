"""Explicit owned destination rotation, never an absent original wallet call."""
import tempfile,unittest,json
from pathlib import Path
from types import SimpleNamespace
from simulator.engine import initialize
from simulator.store import Store
from simulator.model import InvariantError
from simulator.ownership import EvidenceGap

class FallbackRotationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name),'synthetic',10000);initialize(self.store)
        self.actor='actor-11';self.old='0014'+'11'*20;self.new='0014'+'22'*20
        self.config=SimpleNamespace(network='signet',expected_server_pubkey='02'+'33'*32)
        self.store.db.execute('INSERT INTO owner_record VALUES (?,?,?,?,?)',(self.actor,'mailbox',7,self.old,'{}'))
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def paid(self):self.store.db.execute('INSERT INTO checked_settlement VALUES (?,?,?,?,?,?)',('coin','aa'*32,self.actor,self.old,4661,'{}'))
    def queue(self,actor=None):
        from simulator.fallback_rotation import queue_rotation
        return queue_rotation(self.store,self.config,actor or self.actor,self.new)
    def test_requires_checked_original_payout_before_rotation(self):
        with self.assertRaises(EvidenceGap):self.queue()
        self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM action').fetchone()[0])
    def test_rotation_preserves_old_record_and_once_only_intent(self):
        self.paid();first=self.queue();self.assertEqual(first,self.queue())
        row=self.store.db.execute('SELECT * FROM action WHERE id=?',(first['action_id'],)).fetchone();args=json.loads(row['args'])
        self.assertEqual('fallback_rotate',row['operation']);self.assertEqual(0,row['fee_reservation_sat'])
        self.assertEqual(self.old,args['rotation_intent']['old_script']);self.assertEqual(self.new,args['rotation_intent']['new_script'])
        self.assertEqual(7,self.store.db.execute('SELECT seq FROM owner_record').fetchone()[0]);self.store.verify_event_chain()
    def test_unknown_outcome_blocks_another_destination(self):
        self.paid();self.store.queue('lost',self.actor,'H01','sync',{},2000)
        self.store.db.execute("UPDATE action SET state='outcome_unknown' WHERE id='lost'")
        with self.assertRaises(EvidenceGap):self.queue()
    def test_absent_originals_are_rejected_before_dispatch(self):
        self.paid()
        for actor in ['actor-03','actor-09','actor-10']:
            with self.assertRaises(EvidenceGap):self.queue(actor)
    def test_same_or_nonstandard_script_cannot_be_rotated(self):
        self.paid()
        from simulator.fallback_rotation import queue_rotation
        for script in [self.old,'aa','zz','00'*100]:
            with self.subTest(script=script),self.assertRaises((EvidenceGap,ValueError)):
                queue_rotation(self.store,self.config,self.actor,script)

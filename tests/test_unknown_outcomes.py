"""Unknown money requests remain held until a complete positive proof exists."""
import hashlib,json,tempfile,time,unittest
from pathlib import Path
from simulator.store import Store
from simulator.engine import initialize
from simulator.model import canonical
from simulator import unknown_outcomes

class UnknownOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.s=Store(Path(self.tmp.name),'synthetic',1000000);initialize(self.s)
        self.actor='actor-08';self.key='02'+'11'*32;self.output_key='02'+'22'*32
        self.binding={'mailbox_pk':'mailbox','seq':1,'spk':'owner-script','record_signature_valid':True,'key_link_signature_valid':True}
        self.s.db.execute('INSERT INTO owner_record VALUES (?,?,?,?,?)',(self.actor,'mailbox',1,'owner-script',canonical(self.binding)))
        self.coin('original',self.key,10000,'aa')
        self.coin('replacement',self.output_key,9900,'bb')
        self.s.queue('lost',self.actor,'H17','refresh',{},2000)
        self.s.db.execute("UPDATE action SET state='outcome_unknown',result=? WHERE id='lost'",(canonical({'reason':'TimeoutError'}),))
        self.original_time=self.row()['updated_at']
        self.proposal={'committed_fee_sat':100,'participation':{'inputs':['aa'],'outputs':[{'amount':9900,'policy':'00'+self.output_key}]}}
        self.s.event('driver_evidence',{'action_id':'lost','event':'refresh_proposal','data':self.proposal})
    def coin(self,name,key,amount,signed,actor=None):
        actor=actor or self.actor
        self.s.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',(key,actor,'mailbox','{}'))
        proof={'id':name,'user_pubkey':key,'amount_sat':amount,'signed_path_valid':True,'anchor_confirmations':1,'chain_anchor':'a'*64+':0','binding':self.binding}
        self.s.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',(name,key,amount,hashlib.sha256(bytes.fromhex(signed)).hexdigest(),signed,canonical(proof)))
    def movement(self):
        self.s.db.execute('INSERT INTO movement_evidence VALUES (?,?,?)',(self.actor,'round',canonical({'id':'round','subsystem':'bark.round','status':'successful','payment_hash':None,
            'input_vtxos':['original'],'output_vtxos':['replacement'],'offchain_fee_sat':100,'effective_balance_sat':-100})))
    def row(self):return self.s.db.execute("SELECT * FROM action WHERE id='lost'").fetchone()
    def tearDown(self):self.s.close();self.tmp.cleanup()
    def test_complete_signed_success_resolves_unknown_once_without_replaying_request(self):
        self.movement();self.s.set_online(self.actor,False)
        self.assertTrue(unknown_outcomes.resolve(self.s,'lost'),'complete independent success leaves the actor indefinitely unknown')
        row=self.row();self.assertEqual('completed',row['state']);self.assertEqual(100,row['actual_fee_sat'])
        self.assertEqual(self.original_time,row['updated_at'],'archived reconciliation must not manufacture current traffic')
        self.assertFalse(self.s.online(self.actor));self.assertFalse(unknown_outcomes.resolve(self.s,'lost'))
        self.assertEqual(1,self.s.db.execute("SELECT count(*) FROM event WHERE kind='unknown_outcome_resolved'").fetchone()[0])
        self.assertEqual(1,self.s.db.execute('SELECT count(*) FROM action').fetchone()[0])
        self.assertEqual({'reason':'TimeoutError'},json.loads(row['result'])['resolution']['original_result'])

if __name__=='__main__':unittest.main()

"""Synthetic shared current-right origin controls; no native money credit."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from simulator.architecture import DIRECT,TWO_STEP,DIRECT_PER_KEY
from simulator.financial_transition import _current_claims
from simulator.model import canonical
from simulator.store import Store
from tests.account_fixtures import proof as account_proof
from tests.test_direct_per_key import public_objects


class CurrentClaimOriginTests(unittest.TestCase):
    def source(self,profile):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        store=Store(Path(tmp.name),'synthetic',10000,architecture_profile=profile)
        self.addCleanup(store.close);store.actor('actor-01','synthetic origin control')
        store.register_catalog([{'id':'synthetic','behavior':'synthetic source'}],{'synthetic'})
        store.queue('snapshot','actor-01','synthetic','snapshot',{},0)
        key='02'+'11'*32
        if profile==DIRECT:
            proof=account_proof({'user_pubkey':key,'binding':{'mailbox_pk':'mailbox'}})
        elif profile==DIRECT_PER_KEY:
            _,_,_,proof=public_objects();key=proof['user_pubkey']
        else:
            proof={'user_pubkey':key,'binding':{'record_signature_valid':True,
                'key_link_signature_valid':True,'seq':0,'mailbox_pk':'mailbox','spk':'script'}}
        proof.update(id='coin',amount_sat=1000,signed_path_valid=True)
        store.db.execute('INSERT INTO owner_key VALUES(?,?,?,?)',(key,'actor-01','mailbox',canonical(proof)))
        store.db.execute('INSERT INTO owned_coin VALUES(?,?,?,?,?,?)',('coin',key,1000,'digest','encoding',canonical(proof)))
        store.db.execute('INSERT INTO coin_observation VALUES(?,?,?,?)',('coin','snapshot','Spendable',1))
        return store,proof

    def replace(self,store,proof):
        store.db.execute('UPDATE owned_coin SET proof=?',(canonical(proof),))

    def test_b_authenticated_account_origin_reaches_current_right(self):
        store,_=self.source(DIRECT);before=store.db.total_changes
        self.assertEqual(1000,_current_claims(store)[0]['amount_sat'])
        self.assertEqual(before,store.db.total_changes)

    def test_a_existing_perkey_origin_remains_current_right(self):
        store,_=self.source(TWO_STEP)
        self.assertEqual('actor-01',_current_claims(store)[0]['actor'])

    def test_c_existing_exact_keylink_origin_remains_current_right(self):
        store,_=self.source(DIRECT_PER_KEY)
        self.assertEqual('coin',_current_claims(store)[0]['coin_id'])

    def test_b_failed_account_signature_child_type_or_full_key_refuses(self):
        store,proof=self.source(DIRECT)
        for field,value in [('record_signature_valid',False),('account_child_verified',False),
                            ('child_index',True),('child_index',-1),('child_index',2**31),
                            ('policy_pubkey_full','other')]:
            with self.subTest(field=field,value=value):
                altered=copy.deepcopy(proof);altered['binding'][field]=value;self.replace(store,altered)
                with self.assertRaisesRegex(ValueError,'signed ownership'):_current_claims(store)

    def test_a_invalid_link_signature_still_refuses(self):
        store,proof=self.source(TWO_STEP);proof['binding']['key_link_signature_valid']=False;self.replace(store,proof)
        with self.assertRaisesRegex(ValueError,'signed ownership'):_current_claims(store)

    def test_c_invalid_link_signature_or_profile_alias_still_refuses(self):
        store,proof=self.source(DIRECT_PER_KEY)
        for edit in ('signature','account-alias'):
            with self.subTest(edit=edit):
                altered=copy.deepcopy(proof)
                if edit=='signature':altered['binding']['key_link_signature_valid']=False
                else:altered['binding']['account_xpub']='forbidden'
                self.replace(store,altered)
                with self.assertRaisesRegex(ValueError,'signed ownership'):_current_claims(store)

    def test_wrong_profile_c_proof_is_not_a_or_b_right(self):
        for target in (DIRECT,TWO_STEP):
            with self.subTest(target=target):
                store,own=self.source(target);_,_,_,c=public_objects()
                c.update(id='coin',amount_sat=1000,signed_path_valid=True,user_pubkey=own['user_pubkey'])
                self.replace(store,c)
                with self.assertRaisesRegex(ValueError,'signed ownership'):_current_claims(store)

    def test_expired_sdk_spent_without_authenticated_supersession_keeps_right(self):
        store,_=self.source(DIRECT)
        store.db.execute("UPDATE coin_observation SET state='Spent'")
        self.assertEqual(1000,_current_claims(store)[0]['amount_sat'])

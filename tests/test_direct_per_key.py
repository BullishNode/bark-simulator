"""C consumer/isolation controls only; synthetic bytes are not signature or money proof."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from simulator.architecture import DIRECT_PER_KEY, profile
from simulator.model import InvariantError, canonical, SIGNET_GENESIS
from simulator.ownership import proof_matches_profile, record_verified, binding_matches
from simulator.per_key import link_bytes, record_bytes
from simulator.store import Store


def public_objects(index=50):
    record = {'mailbox_pk':'02'+'11'*32, 'spk':'0014'+'22'*20, 'mailbox_sig':'33'*64}
    link = {'user_pubkey':'03'+'44'*32, 'mailbox_pk':record['mailbox_pk'],
            'sig':'55'*64, 'recovery_index':index}
    binding = {'mailbox_pk':record['mailbox_pk'], 'spk':record['spk'],
               'fallback_record':record_bytes(record)}
    proof = {'user_pubkey':link['user_pubkey'], 'binding':{
        **binding, 'record_version':4, 'key_link_version':1,
        'key_link_attestation':link_bytes(link), 'recovery_index':index,
        'policy_pubkey_full':link['user_pubkey'],
        'record_signature_valid':True, 'key_link_signature_valid':True}}
    return record, link, binding, proof


class DirectPerKeyControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'c'
        self.store = Store(self.path, 'synthetic', 10000, architecture_profile=DIRECT_PER_KEY)
        self.store.actor('actor-01','consumer fixture')

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_c_profile_has_immutable_record_schema_and_reopens_only_as_c(self):
        self.assertEqual(DIRECT_PER_KEY, profile(self.store))
        names = {row['name'] for row in self.store.db.execute('PRAGMA table_info(owner_record)')}
        self.assertIn('record_version',names)
        self.assertTrue({'seq','account_xpub'}.isdisjoint(names))
        for other in (None,'direct_xpub','two_step_per_key'):
            with self.subTest(other=other), self.assertRaises(ValueError):
                Store(self.path,'synthetic',10000,architecture_profile=other)

    def test_c_does_not_adopt_a_or_b_database(self):
        for other in ('direct_xpub','two_step_per_key'):
            path = Path(self.tmp.name)/other
            old = Store(path,'synthetic',10000,architecture_profile=other)
            before = [tuple(r) for r in old.db.execute('SELECT * FROM event')]
            old.close()
            with self.assertRaises(ValueError):
                Store(path,'synthetic',10000,architecture_profile=DIRECT_PER_KEY)
            old = Store(path,'synthetic',10000,architecture_profile=other)
            self.assertEqual(before,[tuple(r) for r in old.db.execute('SELECT * FROM event')])
            old.close()

    def test_consumer_requires_exact_verified_link_and_immutable_binding(self):
        record,link,binding,proof = public_objects()
        source = {'user_pubkey':link['user_pubkey'],'key_link_attestation':link_bytes(link)}
        self.assertTrue(proof_matches_profile(self.store,proof,source))
        self.assertTrue(binding_matches(proof['binding'],binding,per_key=True))
        for edit in ('record-signature','link-signature','link-bytes','key','xpub','seq','index','version'):
            altered = copy.deepcopy(proof)
            if edit=='record-signature':altered['binding']['record_signature_valid']=False
            if edit=='link-signature':altered['binding']['key_link_signature_valid']=False
            if edit=='link-bytes':altered['binding']['key_link_attestation']=link_bytes({**link,'sig':'66'*64})
            if edit=='key':altered['binding']['policy_pubkey_full']='02'+'77'*32
            if edit=='xpub':altered['binding']['account_xpub']='forbidden'
            if edit=='seq':altered['binding']['seq']=0
            if edit=='index':altered['binding']['recovery_index']=25
            if edit=='version':altered['binding']['record_version']=3
            with self.subTest(edit=edit):self.assertFalse(proof_matches_profile(self.store,altered,source))

    def test_record_version_and_link_index_are_not_boolean_or_hardened(self):
        _,link,_,proof = public_objects()
        for index in (True,-1,2**31,'50'):
            with self.subTest(index=index),self.assertRaises(ValueError):link_bytes({**link,'recovery_index':index})
        proof['binding']['record_version']=True
        self.assertFalse(proof_matches_profile(self.store,proof,{'user_pubkey':link['user_pubkey']}))

    def test_optional_index_absence_is_distinct_from_zero_and_not_admission_authority(self):
        _,link,_,proof=public_objects(None)
        self.assertEqual(99,len(bytes.fromhex(link_bytes(link))))
        self.assertTrue(proof_matches_profile(self.store,proof,{'user_pubkey':link['user_pubkey']}))
        zero={**link,'recovery_index':0}
        self.assertEqual(103,len(bytes.fromhex(link_bytes(zero))))
        self.assertNotEqual(link_bytes(link),link_bytes(zero))
        proof['binding']['key_link_signature_valid']=False
        self.assertFalse(proof_matches_profile(self.store,proof,{'user_pubkey':link['user_pubkey']}))

    def test_conflicting_record_rolls_back_new_key_and_cannot_rotate_destination(self):
        record,link,binding,proof=public_objects()
        def verified(proof,link):
            return {'objects':[{'kind':'key','proof':proof,'request_origin':{
                'user_pubkey':link['user_pubkey'],'key_link_attestation':link_bytes(link)}}],
                'movements':[],'financial_pins':None}
        record_verified(self.store,'actor-01','first',verified(proof,link))
        before=[tuple(r) for r in self.store.db.execute('SELECT * FROM owner_key')]
        other_link={**link,'user_pubkey':'02'+'77'*32}
        other_record={**record,'spk':'0014'+'88'*20}
        other=copy.deepcopy(proof);other['user_pubkey']=other_link['user_pubkey']
        other['binding'].update(spk=other_record['spk'],fallback_record=record_bytes(other_record),
            policy_pubkey_full=other_link['user_pubkey'],key_link_attestation=link_bytes(other_link))
        with self.assertRaises(InvariantError):record_verified(self.store,'actor-01','second',verified(other,other_link))
        self.assertEqual(before,[tuple(r) for r in self.store.db.execute('SELECT * FROM owner_key')])
        self.assertEqual(record['spk'],self.store.db.execute('SELECT script FROM owner_record').fetchone()[0])
        self.store.verify_event_chain()

    def test_no_account_or_mutable_record_can_be_serialized_as_c(self):
        record,_,_,_=public_objects()
        for field in ('account_xpub','account_sig','seq'):
            with self.subTest(field=field),self.assertRaises(ValueError):record_bytes({**record,field:'foreign'})

    def test_public_import_accepts_retained_c_link_and_rejects_account_substitution(self):
        from simulator.proof_import import _bundle, _checked
        record,link,binding,proof=public_objects()
        self.store.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',
            (link['user_pubkey'],'actor-01',record['mailbox_pk'],canonical(proof)))
        coin={'id':'66'*32+':0','user_pubkey':link['user_pubkey'],'amount_sat':20000,
            'expiry_height':100,'signed_vtxo':'abcd','key_link_attestation':link_bytes(link),'binding':binding}
        config=SimpleNamespace(network='signet',expected_genesis=SIGNET_GENESIS,expected_server_pubkey='02'+'77'*32)
        value={'schema_version':1,'actor':'actor-01','identity':{'network':'signet','genesis':SIGNET_GENESIS,
            'server_pubkey':config.expected_server_pubkey},'coins':[coin]}
        self.assertEqual(('actor-01',[coin]),_bundle(self.store,config,value))
        proof.update(id=coin['id'],amount_sat=20000,expiry_height=100,genesis=SIGNET_GENESIS,
            server_pubkey=config.expected_server_pubkey,authorization_path_valid=True,anchor_confirmations=2)
        self.assertEqual('coin',_checked(config,coin,proof,architecture=DIRECT_PER_KEY)['kind'])
        bad=copy.deepcopy(value);bad['coins'][0]['binding']['account_xpub']='forbidden'
        with self.assertRaises(ValueError):_bundle(self.store,config,bad)
        proof['binding']['key_link_attestation']=link_bytes({**link,'sig':'99'*64})
        with self.assertRaises(ValueError):_checked(config,coin,proof,architecture=DIRECT_PER_KEY)

    def test_c_journal_reuses_direct_money_checks_but_rejects_foreign_profile_and_link(self):
        from simulator.direct_settlements import frame, check_group
        record,link,binding,proof=public_objects()
        identity='66'*32+':0'
        proof.update(proof_encoding='ark-public-authorization-v1',authorization_path_valid=True,
            conditional_steps=0,id=identity,amount_sat=20000,ancestor_ids=[identity],path=[])
        self.store.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',
            (link['user_pubkey'],'actor-01',record['mailbox_pk'],canonical(proof)))
        self.store.db.execute('INSERT INTO owner_record VALUES (?,?,?,?,?)',
            ('actor-01',record['mailbox_pk'],4,record['spk'],canonical(proof['binding'])))
        self.store.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',
            (identity,link['user_pubkey'],20000,'synthetic','synthetic',canonical(proof)))
        operator='5120'+'88'*32
        self.store.db.execute('INSERT INTO operator_script VALUES (?,?)',(operator,'synthetic descriptor control'))
        allocation={'id':identity,'freeze_set':'group','owner_pubkey':link['user_pubkey'],'spk':record['spk'],
            'disposition':'pay','gross_sat':20000,'fee_sat':1000,'payout_sat':19000,'forfeited_sat':0,
            'source':'registered','retirement_ids':[identity],'frozen_at':'synthetic'}
        carrier={'txid':'99'*32,'generation':1,'backing_ids':[identity],'fee_inputs':[],
            'miner_fee_sat':100,'funding_subsidy_sat':0,'created_at':'synthetic',
            'confirmed_height':101,'confirmed_block':'aa'*32}
        journal={'kind':'direct_journal','schema_version':1,'fallback_protocol':4,'architecture_profile':DIRECT_PER_KEY,
            'binding_scope':'owners_referenced_by_allocations','journal_complete':True,'inventory_consistent':True,
            'complete':False,'qualified':False,'rows':{'allocations':[allocation],'carriers':[carrier],
            'mappings':[{'txid':carrier['txid'],'allocation_id':identity,'vout':0}],'records':[record],'links':[link]}}
        tx={'confirmations':2,'blockhash':carrier['confirmed_block'],
            'inputs':[{'outpoint':identity,'amount_sat':20000,'script':'synthetic backing'}],
            'outputs':[{'vout':0,'amount_sat':19000,'script':record['spk']},
                       {'vout':1,'amount_sat':900,'script':operator}]}
        result=check_group(self.store,journal,'group',{carrier['txid']:tx})
        self.assertEqual(100,result['accounting']['mining_fee_sat'])
        self.assertEqual(1000,result['accounting']['flat_fee_sat'])
        with self.assertRaises(ValueError):frame(journal)
        changed=copy.deepcopy(journal);changed['fallback_protocol']=3
        with self.assertRaises(ValueError):frame(changed,architecture=DIRECT_PER_KEY)
        changed=copy.deepcopy(journal);changed['rows']['links'][0]['sig']='ab'*64
        with self.assertRaises(ValueError):check_group(self.store,changed,'group',{carrier['txid']:tx})
        self.assertEqual(0,self.store.db.execute('SELECT COUNT(*) FROM checked_settlement').fetchone()[0])

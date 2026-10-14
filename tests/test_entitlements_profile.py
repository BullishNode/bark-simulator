"""Delegated controller profile controls; no native signature/chain qualification.

Fixtures model the exact per-key verifier output schema in the A native source.
No native verifier, wallet, node or payment runs here. A checked-path flag is an
input to the Python controller test, never financial/live evidence.
"""
import copy
import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path

from simulator import entitlements
from simulator.architecture import DIRECT, TWO_STEP
from simulator.engine import initialize
from simulator.final_campaign import declare_epoch
from simulator.model import InvariantError, SIGNET_GENESIS, canonical
from simulator.ownership import EvidenceGap, proof_matches_profile, record_verified
from simulator.store import Store
from tests import account_fixtures

PINS = {'product_commit': '1'*40, 'sdk_commit': '2'*40, 'driver_sha256': '3'*64,
        'configuration_sha256': '4'*64, 'schema_sha256': '5'*64}
ACTOR = 'actor-08'
PUBKEY = '02' + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
MAILBOX = '03' + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
SCRIPT = '0014' + '11'*20


class DelegatedProfileCoinTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.opened = []

    def tearDown(self):
        for store in self.opened:
            store.close()
        self.tmp.cleanup()

    def setup_profile(self, profile, *, final=True):
        directory = Path(self.tmp.name) / ('case-' + str(len(self.opened)))
        store = Store(directory, 'synthetic', 100000, architecture_profile=profile)
        self.opened.append(store)
        initialize(store)
        if final:
            store.db.execute("INSERT INTO meta VALUES ('paused','fixture declaration')")
            declare_epoch(store, {'id': 'controller-profile-control', 'pins': PINS,
                'started_at': time.time(),
                'windows_seconds': {'ark':600, 'internal_lightning':600, 'external_lightning':600},
                'minimum_observations': {'ark':1, 'internal_lightning':1, 'external_lightning':1}})
            store.db.execute("DELETE FROM meta WHERE key='paused'")
            store.add_snapshot({'observed_at':time.time(), 'financial_pins':PINS})
        store.queue('observe', ACTOR, 'H01', 'snapshot', {}, 0)
        if profile == TWO_STEP:
            binding = {'mailbox_pk': MAILBOX, 'spk': SCRIPT, 'seq': 7,
                'record_signature_valid': True, 'key_link_signature_valid': True}
            coin = {'id': 'controller-input:0', 'user_pubkey': PUBKEY, 'amount_sat':10000,
                'signed_vtxo':'aa', 'key_link_attestation':'cc', 'expiry_height':150,
                'state':'Spendable'}
        else:
            binding = account_fixtures.proof({'user_pubkey':PUBKEY,
                'binding': {'mailbox_pk':MAILBOX, 'spk':SCRIPT}})['binding']
            coin = account_fixtures.coin({'id':'controller-input:0', 'user_pubkey':PUBKEY,
                'amount_sat':10000, 'signed_vtxo':'aa', 'expiry_height':150, 'state':'Spendable'})
        proof = {'id':coin['id'], 'user_pubkey':PUBKEY, 'amount_sat':10000,
            'authorization_path_valid':True, 'signed_path_valid':True,
            'anchor_confirmations':4, 'chain_anchor':'a'*64+':0',
            'genesis':SIGNET_GENESIS, 'expiry_height':150, 'binding':binding,
            'financial_pins':copy.deepcopy(PINS) if final else None}
        self.assertTrue(proof_matches_profile(store, proof, coin),
            'fixture must match the existing authentic selected verifier contract')
        verified = {'objects':[{'kind':'coin', 'coin':coin, 'proof':proof,
            'signed_hash':hashlib.sha256(bytes.fromhex(coin['signed_vtxo'])).hexdigest(),
            'request_binding':binding}], 'movements':[],
            'financial_pins':copy.deepcopy(PINS) if final else None}
        # Use the real shared ownership recorder. Do not bypass its profile/schema
        # selection or insert a fictitious account column into a per-key campaign.
        record_verified(store, ACTOR, 'observe', verified)
        return store, coin, proof

    def write_proof(self, store, proof):
        store.db.execute('UPDATE owned_coin SET proof=?', (canonical(proof),))

    def rejected(self, store, coin_id='controller-input:0', actor=ACTOR, *, pattern=None):
        # A missing SQL column or arbitrary exception is not an acceptable refusal.
        with self.assertRaises((EvidenceGap, InvariantError)) as failure:
            entitlements._coin(store, coin_id, actor)
        if pattern is not None:
            self.assertRegex(str(failure.exception), pattern)

    def test_truthful_per_key_contract_passes_delegated_coin_without_xpub_flags(self):
        store, coin, proof = self.setup_profile(TWO_STEP)
        self.assertNotIn('account_xpub', proof['binding'])
        self.assertNotIn('account_child_verified', proof['binding'])
        columns = {row['name'] for row in store.db.execute('PRAGMA table_info(owner_record)')}
        self.assertIn('seq', columns)
        self.assertNotIn('account_xpub', columns)
        result, actual = entitlements._coin(store, coin['id'], ACTOR)
        self.assertEqual((ACTOR,10000), (result['actor'],result['amount_sat']))
        self.assertEqual(proof, actual)

    def test_direct_xpub_contract_still_passes_delegated_coin(self):
        store, coin, proof = self.setup_profile(DIRECT)
        result, actual = entitlements._coin(store, coin['id'], ACTOR)
        self.assertEqual(coin['id'], result['id'])
        self.assertEqual(proof, actual)

    def test_unprofiled_direct_compatibility_remains_without_final_epoch(self):
        store, coin, proof = self.setup_profile(None, final=False)
        self.assertEqual(proof, entitlements._coin(store,coin['id'],ACTOR)[1])

    def test_per_key_frozen_inputs_conserve_without_account_flags(self):
        store, coin, _ = self.setup_profile(TWO_STEP)
        proposal = {'participation':{'inputs':[coin['signed_vtxo']]}}
        rows, gross = entitlements._inputs(store, ACTOR, proposal,
            [{'pubkey':PUBKEY, 'amount_sat':9900}], 100)
        self.assertEqual([coin['id']], [row['id'] for row in rows])
        self.assertEqual(10000, gross)

    def test_per_key_link_signature_missing_false_or_wrong_type_is_rejected(self):
        for value in (None, False, 'true'):
            with self.subTest(value=value):
                store, _, proof = self.setup_profile(TWO_STEP)
                if value is None: proof['binding'].pop('key_link_signature_valid')
                else: proof['binding']['key_link_signature_valid'] = value
                self.write_proof(store,proof)
                self.rejected(store,pattern='ownership origin differs from campaign profile')

    def test_record_signature_remains_required_for_both_profiles(self):
        for profile in (TWO_STEP,DIRECT):
            for value in (None,False):
                with self.subTest(profile=profile,value=value):
                    store,_,proof=self.setup_profile(profile)
                    if value is None:proof['binding'].pop('record_signature_valid')
                    else:proof['binding']['record_signature_valid']=value
                    self.write_proof(store,proof);self.rejected(store)

    def test_per_key_sequence_is_exact_signed_record_not_latest_or_invented_revision(self):
        for sequence in (None,8,-1,True,'7',2**63):
            with self.subTest(sequence=sequence):
                store,_,proof=self.setup_profile(TWO_STEP)
                if sequence is None:proof['binding'].pop('seq')
                else:proof['binding']['seq']=sequence
                self.write_proof(store,proof)
                if type(sequence) is int and sequence == 8:
                    self.assertTrue(proof_matches_profile(store,proof,{'user_pubkey':PUBKEY}))
                    self.rejected(store,pattern='lacks its verified owner record')
                else:
                    self.rejected(store,pattern='ownership origin differs from campaign profile')

    def test_per_key_later_record_does_not_retire_historical_owned_sequence(self):
        store,coin,original=self.setup_profile(TWO_STEP)
        changed=copy.deepcopy(original)
        changed['binding'].update(seq=8,spk='0014'+'22'*20)
        record_verified(store,ACTOR,'observe',{'objects':[{'kind':'coin','coin':coin,
            'proof':changed,'signed_hash':hashlib.sha256(bytes.fromhex(coin['signed_vtxo'])).hexdigest(),
            'request_binding':changed['binding']}],'movements':[],'financial_pins':PINS})
        self.assertEqual(8,entitlements._coin(store,coin['id'],ACTOR)[1]['binding']['seq'])
        self.write_proof(store,original)
        self.assertEqual(7,entitlements._coin(store,coin['id'],ACTOR)[1]['binding']['seq'])
        self.assertEqual([7,8],[row['seq'] for row in store.db.execute('SELECT seq FROM owner_record ORDER BY seq')])

    def test_cross_profile_account_flags_cannot_replace_a_per_key_link(self):
        store,_,proof=self.setup_profile(TWO_STEP)
        proof['binding'].update(account_xpub='invented',account_child_verified=True)
        self.write_proof(store,proof)
        self.rejected(store,pattern='ownership origin differs from campaign profile')

    def test_foreign_actor_or_owner_record_remains_rejected(self):
        for profile in (TWO_STEP,DIRECT):
            with self.subTest(profile=profile):
                store,_,_=self.setup_profile(profile)
                self.rejected(store,actor='actor-02')
                store.db.execute("UPDATE owner_record SET actor='actor-02'")
                self.rejected(store,pattern='lacks its verified owner record')

    def test_missing_record_or_mailbox_script_mismatch_remains_rejected(self):
        for profile in (TWO_STEP,DIRECT):
            for change in ('missing','mailbox','script'):
                with self.subTest(profile=profile,change=change):
                    store,_,proof=self.setup_profile(profile)
                    if change=='missing':store.db.execute('DELETE FROM owner_record')
                    else:
                        proof['binding']['mailbox_pk' if change=='mailbox' else 'spk']='foreign'
                        self.write_proof(store,proof)
                    self.rejected(store)

    def test_signed_coin_identity_value_and_actor_checks_remain(self):
        for profile in (TWO_STEP,DIRECT):
            for key,value in (('id','other:0'),('user_pubkey','different'),('amount_sat',9999)):
                with self.subTest(profile=profile,key=key):
                    store,_,proof=self.setup_profile(profile)
                    proof[key]=value;self.write_proof(store,proof);self.rejected(store)

    def test_signature_path_and_confirmed_anchor_checks_remain(self):
        for profile in (TWO_STEP,DIRECT):
            for change in ('path','anchor'):
                with self.subTest(profile=profile,change=change):
                    store,_,proof=self.setup_profile(profile)
                    if change=='path':proof.update(signed_path_valid=False,authorization_path_valid=False)
                    else:proof['anchor_confirmations']=0
                    self.write_proof(store,proof)
                    self.rejected(store,pattern='signature or backing proof is incomplete')

    def test_signed_byte_digest_is_still_checked_in_both_profiles(self):
        for profile in (TWO_STEP,DIRECT):
            with self.subTest(profile=profile):
                store,_,_=self.setup_profile(profile)
                store.db.execute("UPDATE owned_coin SET signed_vtxo='bb'")
                with self.assertRaisesRegex(InvariantError,'signed coin bytes differ from their proof digest'):
                    entitlements._coin(store,'controller-input:0',ACTOR)

    def test_final_epoch_missing_or_changed_original_proof_pins_are_rejected(self):
        for profile in (TWO_STEP,DIRECT):
            for change in ('missing','different_sdk'):
                with self.subTest(profile=profile,change=change):
                    store,_,proof=self.setup_profile(profile)
                    if change=='missing':proof.pop('financial_pins')
                    else:proof['financial_pins']={**PINS,'sdk_commit':'f'*40}
                    self.write_proof(store,proof)
                    self.rejected(store,pattern='differs from final financial epoch')

    def test_successful_predicate_preserves_all_original_rows_and_events(self):
        for profile in (TWO_STEP,DIRECT):
            with self.subTest(profile=profile):
                store,coin,_=self.setup_profile(profile)
                tables=('owner_key','owner_record','owned_coin','coin_observation','event','action')
                before={t:[tuple(r) for r in store.db.execute('SELECT * FROM '+t)] for t in tables}
                entitlements._coin(store,coin['id'],ACTOR)
                self.assertEqual(before,{t:[tuple(r) for r in store.db.execute('SELECT * FROM '+t)] for t in tables})
                store.verify_event_chain()


if __name__ == '__main__':
    unittest.main()

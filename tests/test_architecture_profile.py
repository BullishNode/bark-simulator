"""Campaign isolation controls; these synthetic proofs earn no live credit."""
import asyncio
import copy
import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from simulator.engine import initialize
from simulator.model import InvariantError, canonical
from simulator.ownership import record_verified, verify_client_evidence
from simulator.store import Store


class ArchitectureProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.opened = []

    def tearDown(self):
        for store in self.opened:
            store.close()
        self.tmp.cleanup()

    def open(self, profile, name='campaign'):
        store = Store(self.root / name, 'synthetic', 10000, architecture_profile=profile)
        self.opened.append(store)
        return store

    def test_profile_declaration_is_immutable_across_restart(self):
        store = self.open('two_step_per_key')
        before = [tuple(r) for r in store.db.execute('SELECT * FROM event')]
        store.close(); self.opened.remove(store)
        reopened = self.open('two_step_per_key')
        self.assertEqual(before, [tuple(r) for r in reopened.db.execute('SELECT * FROM event')])
        self.assertEqual('seq', reopened.db.execute('PRAGMA table_info(owner_record)').fetchall()[2]['name'])
        reopened.verify_event_chain()

    def test_explicit_campaign_cannot_reopen_without_profile_or_with_other_profile(self):
        for profile in ('two_step_per_key', 'direct_xpub'):
            with self.subTest(profile=profile):
                store = self.open(profile, profile)
                store.close(); self.opened.remove(store)
                for requested in (None, 'direct_xpub' if profile == 'two_step_per_key' else 'two_step_per_key'):
                    with self.assertRaises(ValueError):
                        self.open(requested, profile)

    def test_no_automatic_adoption_of_existing_unprofiled_database(self):
        old = Store(self.root / 'old', 'synthetic', 10000)
        initialize(old)
        before = list(old.db.execute('SELECT * FROM event'))
        old.close()
        with self.assertRaises(ValueError):
            self.open('two_step_per_key', 'old')
        with sqlite3.connect(self.root / 'old' / 'state.sqlite') as db:
            self.assertIsNone(db.execute("SELECT value FROM meta WHERE key='architecture_profile'").fetchone())
            self.assertEqual(len(before), db.execute('SELECT COUNT(*) FROM event').fetchone()[0])

    def test_mismatched_or_missing_persisted_declaration_fails_closed(self):
        for change in ('delete_meta', 'change_meta', 'delete_event'):
            with self.subTest(change=change):
                store = self.open('two_step_per_key', change)
                if change == 'delete_meta':
                    store.db.execute("DELETE FROM meta WHERE key='architecture_profile'")
                elif change == 'change_meta':
                    store.db.execute("UPDATE meta SET value=? WHERE key='architecture_profile'", (canonical({'version':1,'id':'direct_xpub'}),))
                else:
                    store.db.execute("DELETE FROM event WHERE kind='architecture_profile_declared'")
                with self.assertRaises(ValueError):
                    from simulator.architecture import profile
                    profile(store)

    def test_invalid_profile_does_not_create_a_database(self):
        with self.assertRaises(ValueError):
            self.open('typo')
        self.assertFalse((self.root / 'campaign' / 'state.sqlite').exists())

    def test_legacy_mutable_database_is_not_opened_as_default_direct(self):
        path = self.root / 'old'; path.mkdir()
        with sqlite3.connect(path / 'state.sqlite') as db:
            db.execute('CREATE TABLE owner_record(actor TEXT, mailbox TEXT, seq INTEGER, script TEXT, proof TEXT)')
        with self.assertRaises(ValueError):
            self.open(None, 'old')
        with sqlite3.connect(path / 'state.sqlite') as db:
            self.assertEqual(['owner_record'],[r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")])

    def test_unknown_serialized_profile_type_fails_closed(self):
        store=self.open('two_step_per_key')
        for profile_id in ([], {}, False, 1):
            payload=canonical({'version':1,'id':profile_id})
            store.db.execute("UPDATE meta SET value=? WHERE key='architecture_profile'",(payload,))
            with self.assertRaises(ValueError):
                from simulator.architecture import profile
                profile(store)


class PerKeyOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name), 'synthetic', 10000,
                           architecture_profile='two_step_per_key')
        initialize(self.store)
        self.store.queue('observe', 'actor-01', 'H01', 'snapshot', {}, 0)
        self.binding = {'mailbox_pk':'mailbox','spk':'script-1','seq':1,'record_attestation':'aa'}
        self.coin = {'id':'coin:0','user_pubkey':'pubkey','amount_sat':1000,
                     'signed_vtxo':'bb','key_link_attestation':'cc','expiry_height':100,'state':'Spendable'}
        self.proof = {'id':'coin:0','user_pubkey':'pubkey','amount_sat':1000,
                      'signed_path_valid':True,'anchor_confirmations':1,
                      'binding':{'mailbox_pk':'mailbox','spk':'script-1','seq':1,
                                 'record_signature_valid':True,'key_link_signature_valid':True}}

    def tearDown(self):
        self.store.close(); self.tmp.cleanup()

    def verify(self, proof=None, operation='snapshot', actor='actor-01'):
        async def verifier(*args, **kwargs):
            return copy.deepcopy(self.proof if proof is None else proof)
        data = {'evidence':{'binding':self.binding,'coins':[self.coin]}}
        if operation == 'address':
            data = {'binding':self.binding,'user_pubkey':'pubkey','key_link_attestation':'cc'}
        with patch('simulator.ownership.json_command', side_effect=verifier) as call:
            value = asyncio.run(verify_client_evidence(self.store, actor, operation, data, ['legacy-proof']))
        return value, call

    def test_per_key_native_contract_is_accepted_without_account_flags(self):
        verified, call = self.verify()
        record_verified(self.store, 'actor-01', 'observe', verified)
        self.assertEqual('cc', call.call_args.args[1]['key_link_attestation'])
        stored = json.loads(self.store.db.execute('SELECT proof FROM owned_coin').fetchone()[0])
        self.assertNotIn('account_child_verified', stored['binding'])
        self.assertNotIn('account_xpub', stored['binding'])
        self.assertEqual(1, self.store.db.execute('SELECT seq FROM owner_record').fetchone()[0])

    def test_address_verifier_receives_actual_per_key_signature(self):
        verified, call = self.verify(operation='address')
        record_verified(self.store, 'actor-01', 'observe', verified)
        self.assertEqual({'user_pubkey','key_link_attestation','binding'}, set(call.call_args.args[1]))
        self.assertEqual('pubkey', self.store.db.execute('SELECT pubkey FROM owner_key').fetchone()[0])

    def test_later_signed_sequence_preserves_earlier_destination(self):
        verified, _ = self.verify(); record_verified(self.store,'actor-01','observe',verified)
        self.binding.update(seq=2, spk='script-2')
        self.proof['binding'].update(seq=2, spk='script-2')
        verified, _ = self.verify(); record_verified(self.store,'actor-01','observe',verified)
        self.assertEqual([(1,'script-1'),(2,'script-2')],
                         [tuple(r) for r in self.store.db.execute('SELECT seq,script FROM owner_record ORDER BY seq')])

    def next_key_and_sequence(self):
        self.binding.update(seq=2, spk='script-2')
        self.proof['binding'].update(seq=2, spk='script-2')
        self.coin.update(id='second:0', user_pubkey='second-key', signed_vtxo='dd', key_link_attestation='ee')
        self.proof.update(id='second:0', user_pubkey='second-key')

    def test_mailbox_cannot_move_to_another_actor_at_later_sequence(self):
        verified,_=self.verify();record_verified(self.store,'actor-01','observe',verified)
        self.store.queue('second-observe','actor-02','H01','snapshot',{},0)
        tables=('owner_key','owner_record','owned_coin','coin_observation','event')
        before={table:[tuple(row) for row in self.store.db.execute('SELECT * FROM '+table)] for table in tables}
        self.next_key_and_sequence()
        verified,_=self.verify(actor='actor-02')
        with self.assertRaises(InvariantError):
            record_verified(self.store,'actor-02','second-observe',verified)
        self.assertEqual(before,{table:[tuple(row) for row in self.store.db.execute('SELECT * FROM '+table)] for table in tables})

    def test_same_actor_accepts_multiple_linked_keys_across_signed_sequences(self):
        verified,_=self.verify();record_verified(self.store,'actor-01','observe',verified)
        self.next_key_and_sequence()
        verified,_=self.verify();record_verified(self.store,'actor-01','observe',verified)
        self.assertEqual([('pubkey','actor-01'),('second-key','actor-01')],
                         [tuple(row) for row in self.store.db.execute('SELECT pubkey,actor FROM owner_key ORDER BY pubkey')])
        self.assertEqual([(1,'script-1'),(2,'script-2')],
                         [tuple(row) for row in self.store.db.execute('SELECT seq,script FROM owner_record ORDER BY seq')])
        self.store.verify_event_chain()

    def test_same_sequence_conflict_rolls_back_all_evidence(self):
        verified, _ = self.verify(); record_verified(self.store,'actor-01','observe',verified)
        self.binding['spk'] = self.proof['binding']['spk'] = 'redirect'
        verified, _ = self.verify()
        with self.assertRaises(InvariantError):
            record_verified(self.store,'actor-01','observe',verified)
        self.assertEqual('script-1',self.store.db.execute('SELECT script FROM owner_record').fetchone()[0])

    def test_missing_signature_mismatched_binding_and_xpub_contract_are_rejected(self):
        for edit in ('record','key','seq','script','xpub'):
            with self.subTest(edit=edit):
                proof = copy.deepcopy(self.proof)
                if edit == 'record': proof['binding']['record_signature_valid'] = False
                if edit == 'key': proof['binding']['key_link_signature_valid'] = False
                if edit == 'seq': proof['binding']['seq'] = 2
                if edit == 'script': proof['binding']['spk'] = 'wrong'
                if edit == 'xpub': proof['binding'].update(account_xpub='xpub',account_child_verified=True)
                with self.assertRaises(InvariantError): self.verify(proof)

    def test_invalid_sequence_is_not_a_signed_revision(self):
        for sequence in (-1, True, 2**63, '1'):
            with self.subTest(sequence=sequence):
                proof=copy.deepcopy(self.proof);proof['binding']['seq']=sequence
                with self.assertRaises(InvariantError):self.verify(proof)

    def test_changed_financial_context_reverifies_original_proof(self):
        verified,_=self.verify();record_verified(self.store,'actor-01','observe',verified)
        with patch.object(self.store,'financial_context',return_value={'sdk':'new'}):
            verified, call=self.verify()
        self.assertEqual(1,call.call_count)
        self.assertEqual({'sdk':'new'},verified['objects'][0]['proof']['financial_pins'])

    def test_profile_tampering_prevents_another_verifier_invocation(self):
        self.store.db.execute("DELETE FROM meta WHERE key='architecture_profile'")
        with patch('simulator.ownership.json_command') as call:
            with self.assertRaises(ValueError):
                asyncio.run(verify_client_evidence(self.store,'actor-01','snapshot',
                            {'evidence':{'binding':self.binding,'coins':[self.coin]}},['legacy-proof']))
            call.assert_not_called()

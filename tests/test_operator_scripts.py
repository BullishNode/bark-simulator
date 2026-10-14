import asyncio
import json
import unittest
from pathlib import Path
from types import SimpleNamespace

from tests.test_settlements import SettlementTests
from simulator.model import InvariantError
from simulator.ownership import EvidenceGap, record_server_page
from simulator.settlements import check_payment


class OperatorScriptTests(unittest.TestCase):
    tearDown = SettlementTests.tearDown
    proof = SettlementTests.proof
    record = SettlementTests.record
    server = SettlementTests.server
    evidence = SettlementTests.evidence
    def setUp(self):
        SettlementTests.setUp(self)
        self.row, self.tx = self.evidence()
        self.s.db.execute("DELETE FROM operator_script")
        self.s.db.execute("INSERT INTO operator_script VALUES (?,?)",
                          ('anchor-script', json.dumps({'outpoint': 'anchor:0', 'confirmations': 2})))
        record_server_page(self.s, {'kind': 'settlements', 'rows': [self.row], 'next': None,
                                   'inventory_consistent': False})
        self.identity = {'network': 'regtest', 'genesis': 'genesis', 'server_pubkey': 'server'}
        self.s.db.execute("INSERT INTO meta VALUES ('target_identity',?)", (json.dumps(self.identity),))
        self.path = Path(self.tmp.name) / 'public-descriptor.json'
        self.value = {'schema_version': 1, 'identity': self.identity, 'descriptor': 'wpkh(tpub-public/0/*)#checksum',
                      'first_index': 0, 'last_index': 2}
        self.path.write_text(json.dumps(self.value))
        self.config = SimpleNamespace(operator_descriptors=(self.path,), network='regtest',
                                      expected_genesis='genesis', expected_server_pubkey='server')
        test = self
        class Chain:
            private = False
            foreign = False
            confirmed = True
            calls = []
            def identity(self): return {'blocks': 100}
            def call(self, method, *args):
                self.calls.append((method, args))
                if method == 'getdescriptorinfo':
                    return {'descriptor': test.value['descriptor'], 'hasprivatekeys': self.private,
                            'isrange': True, 'issolvable': True}
                if method == 'deriveaddresses':
                    return [('foreign-' if self.foreign else '') + 'address-' + str(i)
                            for i in range(args[1][0], args[1][1] + 1)]
                if method == 'validateaddress':
                    return {'isvalid': True, 'scriptPubKey': {'address-0': 'anchor-script',
                            'address-1': 'change', 'address-2': 'future'}[args[0]]}
                raise AssertionError(method)
            def tx(self, txid):
                outputs = [('anchor-script', 'address-0')] if txid == 'anchor' else [('spk-actor-01', 'client'), ('change', 'address-1')]
                return {'txid': txid, 'confirmations': 2 if self.confirmed else 0, 'vout': [
                    {'n': i, 'scriptPubKey': {'hex': script, 'address': address}}
                    for i, (script, address) in enumerate(outputs)]}
        self.chain = Chain()

    def collect(self, **kwargs):
        from simulator.operator_scripts import collect
        asyncio.run(collect(self.s, self.config, self.chain, **kwargs))

    def test_spent_change_qualified_by_public_derivation_and_independent_anchor(self):
        with self.assertRaises(EvidenceGap): check_payment(self.s, [self.row], self.tx)
        self.collect()
        self.assertEqual(129, check_payment(self.s, [self.row], self.tx)['operator_fee_sat'])
        evidence = json.loads(self.s.db.execute("SELECT evidence FROM operator_script WHERE script='change'").fetchone()[0])
        self.assertEqual(1, evidence['derivation_index'])
        self.assertEqual('anchor:0', evidence['anchor_outpoint'])
        self.assertFalse(any(method == 'gettxout' for method, _ in self.chain.calls))
        self.s.verify_event_chain()

    def test_direct_winner_and_supplemental_funding_are_verified_without_legacy_rows(self):
        from simulator.direct_settlements import initialize
        initialize(self.s)
        self.s.db.execute("DELETE FROM server_item WHERE kind='settlements'")
        carrier={'txid':'direct','confirmed_height':2,'fee_inputs':[{'outpoint':'fee-funding:0'}]}
        self.s.db.execute('INSERT INTO direct_journal_object VALUES(?,?,?)',('carriers','direct',json.dumps(carrier)))
        original=self.chain.tx
        def transaction(txid):
            if txid=='fee-funding':return {'txid':txid,'confirmations':3,
                'vout':[{'n':0,'scriptPubKey':{'hex':'future','address':'address-2'}}]}
            return original(txid)
        self.chain.tx=transaction
        self.collect()
        for script in ['change','future']:
            evidence=json.loads(self.s.db.execute('SELECT evidence FROM operator_script WHERE script=?',(script,)).fetchone()[0])
            self.assertEqual('anchor:0',evidence['anchor_outpoint'])
            self.assertIn(evidence['txid'],{'direct','fee-funding'})
    def test_pending_direct_version_does_not_guess_change_ownership(self):
        from simulator.direct_settlements import initialize
        initialize(self.s)
        self.s.db.execute("DELETE FROM server_item WHERE kind='settlements'")
        self.s.db.execute('INSERT INTO direct_journal_object VALUES(?,?,?)',('carriers','pending',json.dumps(
            {'txid':'pending','confirmed_height':None,'fee_inputs':[]})))
        self.collect()
        self.assertIsNone(self.s.db.execute("SELECT 1 FROM operator_script WHERE script='change'").fetchone())
    def test_foreign_public_descriptor_cannot_adopt_payout_change(self):
        self.chain.foreign = True
        self.collect()
        self.assertIsNone(self.s.db.execute("SELECT 1 FROM operator_script WHERE script='change'").fetchone())
        with self.assertRaises(EvidenceGap): check_payment(self.s, [self.row], self.tx)

    def test_private_or_unranged_descriptor_is_rejected_without_derivation(self):
        self.chain.private = True
        self.collect()
        self.assertFalse(any(method == 'deriveaddresses' for method, _ in self.chain.calls))
        self.assertEqual(1, self.s.db.execute('SELECT COUNT(*) FROM operator_script').fetchone()[0])

    def test_declaration_is_immutable_after_first_validation(self):
        self.collect()
        self.value['last_index'] = 3
        self.path.write_text(json.dumps(self.value))
        with self.assertRaises(InvariantError): self.collect()

    def test_bounded_derivation_resumes_and_deduplicates_without_false_ownership(self):
        self.collect(batch_size=1)
        self.assertIsNone(self.s.db.execute("SELECT 1 FROM operator_script WHERE script='change'").fetchone())
        self.collect(batch_size=1)
        self.assertIsNotNone(self.s.db.execute("SELECT 1 FROM operator_script WHERE script='change'").fetchone())
        self.collect(batch_size=1)
        before = self.s.db.execute('SELECT COUNT(*) FROM event').fetchone()[0]
        self.collect(batch_size=1)
        self.assertEqual(before, self.s.db.execute('SELECT COUNT(*) FROM event').fetchone()[0])
        self.assertEqual(3, self.s.db.execute('SELECT COUNT(*) FROM operator_address').fetchone()[0])

    def test_identity_mismatch_holds_ownership(self):
        self.value['identity']['server_pubkey'] = 'foreign'
        self.path.write_text(json.dumps(self.value))
        self.collect()
        self.assertFalse(any(method == 'deriveaddresses' for method, _ in self.chain.calls))

    def test_unconfirmed_anchor_cannot_qualify_descriptor(self):
        self.chain.confirmed = False
        self.collect()
        self.assertIsNone(self.s.db.execute('SELECT anchor_outpoint FROM operator_descriptor').fetchone()[0])
        self.assertIsNone(self.s.db.execute("SELECT 1 FROM operator_script WHERE script='change'").fetchone())

    def test_mismatched_core_script_is_an_ownership_incident(self):
        original = self.chain.call
        self.chain.call = lambda method, *args: ({'isvalid': True, 'scriptPubKey': 'wrong'}
            if method == 'validateaddress' else original(method, *args))
        with self.assertRaises(InvariantError): self.collect()

    def test_duplicate_derived_addresses_hold_without_partial_range_commit(self):
        original = self.chain.call
        self.chain.call = lambda method, *args: (['same'] * 3
            if method == 'deriveaddresses' else original(method, *args))
        self.collect()
        self.assertEqual(0, self.s.db.execute('SELECT COUNT(*) FROM operator_address').fetchone()[0])
        self.assertEqual(0, self.s.db.execute('SELECT next_index FROM operator_descriptor').fetchone()[0])


if __name__ == '__main__': unittest.main()

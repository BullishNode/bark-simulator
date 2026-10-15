"""Full-node treasury gaps, using synthetic controller/Core fixtures only.

No CLN/Core RPC, native ownership verifier, wallet, channel, payment or live
producer runs. These inputs exercise the actual treasury consumer; a named
verified event is a test fixture and never evidence of native completeness.
"""
import unittest
import copy
from decimal import Decimal
from unittest.mock import patch

from simulator.model import InvariantError
from simulator.treasury import capture_assets
from tests.test_treasury import TreasuryFixture
from tests.test_final_campaign import PINS
from simulator.model import SIGNET_GENESIS


class LightningNodeInventoryTests(TreasuryFixture, unittest.TestCase):
    def wallet_output(self, *, funding=False):
        # The existing fixture has a 2,000sat physical channel at b...:0;
        # the independent synthetic Core additionally knows 700sat node cash.
        txid, amount, script = ('b'*64, 2000, 'channel-script') if funding else (
            'c'*64, 700, 'cln-wallet-script')
        self.chain.coins[(txid, 0)] = {'confirmations': 1,
            'value': Decimal(amount) / Decimal(100_000_000),
            'scriptPubKey': {'hex': script}}
        self.cash_source={'member_id':'peer','identity':self.peer['identity'],
            'member_verification_sequence':self.declaration['members'][1]['verification_sequence'],
            'financial_pins':PINS,'genesis':SIGNET_GENESIS,'tip_hash':'tip','height':100,
            'getinfo':{'id':self.peer['identity'],'network':'signet','blockheight':100},
            'listfunds':{'outputs':[{'txid':txid,'output':0,'amount_msat':amount*1000,
                'scriptpubkey':script,'status':'confirmed','blockheight':100}], 'channels':[]}}
        self.event('treasury_cln_wallet_source',self.cash_source)
        return {'outpoint': txid+':0', 'amount_sat': amount, 'script': script,
                'source_sequence':self.sequence()}

    def node_assets(self, **node_changes):
        return capture_assets(self.store, {
            'rounds': self.inventory(self.wallet),
            'peer': self.inventory(self.peer, **node_changes)}, self.chain)

    def test_confirmed_cln_cash_cannot_disappear_from_an_accepted_member_inventory(self):
        output = self.wallet_output()
        result = self.node_assets(utxos=[output])
        # Existing wallet 1,000sat + channel ownership1,500.999sat + CLN cash700sat.
        self.assertEqual(3_200_999, result['total_msat'])
        self.assertIn(output['outpoint'], result['assets'])
        self.assertEqual('peer', result['assets'][output['outpoint']]['member'])
        self.assertIn(('gettxout', ('c'*64, 0, False)), self.chain.calls)

    def test_channel_funding_cannot_also_be_accepted_as_cln_wallet_cash(self):
        # An ordinary full-value wallet claim and a channel position are two
        # incompatible classifications of the same physical point at this cut.
        # The existing cross-member funding rule must also apply inside one node.
        with self.assertRaisesRegex(InvariantError, 'channel|physical|twice'):
            self.node_assets(utxos=[self.wallet_output(funding=True)])

    def test_existing_channel_and_descriptor_wallet_accounting_is_unchanged(self):
        result = self.node_assets()
        self.assertEqual(2_500_999, result['total_msat'])
        self.assertEqual(1_000_000, result['operator_controlled_msat'])

    def test_missing_or_mismatched_member_coverage_cannot_become_zero_cash(self):
        output = self.wallet_output()
        for change in ({'complete': False}, {'height': 99}, {'identity': 'another-node'}):
            with self.subTest(change=change):
                with self.assertRaisesRegex(ValueError, 'coverage'):
                    self.node_assets(utxos=[output], **change)

    def test_channel_only_legacy_shape_cannot_earn_exhaustive_capture(self):
        sequence=self.inventory(self.peer)
        import json
        payload=json.loads(self.store.db.execute('SELECT payload FROM event WHERE sequence=?',(sequence,)).fetchone()[0])
        payload.pop('utxos')
        self.event('treasury_inventory',payload)
        legacy_sequence=self.sequence()
        with self.assertRaisesRegex(ValueError,'coverage'):
            capture_assets(self.store,{'rounds':self.inventory(self.wallet),'peer':legacy_sequence},self.chain)

    def test_native_source_scope_and_node_are_exact(self):
        output=self.wallet_output()
        changes=[{'member_id':'another'}, {'identity':'another-node'},
                 {'member_verification_sequence':999}, {'genesis':'00'*32},
                 {'financial_pins':{**PINS,'sdk_commit':'f'*40}}, {'height':99}, {'tip_hash':'old'},
                 {'getinfo':{'id':'another-node','network':'signet','blockheight':100}},
                 {'getinfo':{'id':self.peer['identity'],'network':'mainnet','blockheight':100}},
                 {'getinfo':{'id':self.peer['identity'],'network':'signet','blockheight':99}},
                 {'getinfo':None}, {'listfunds':{'outputs':[42],'channels':[]}}]
        for change in changes:
            with self.subTest(change=change):
                self.event('treasury_cln_wallet_source',{**self.cash_source,**change})
                row={**output,'source_sequence':self.sequence()}
                with self.assertRaisesRegex(ValueError,'source'):
                    self.node_assets(utxos=[row])

    def test_core_and_native_output_values_scripts_and_status_all_match(self):
        output=self.wallet_output()
        for change in ({'amount_msat':700001},{'amount_msat':True},
                       {'scriptpubkey':'foreign'}, {'status':'unconfirmed'},
                       {'blockheight':101}, {'blockheight':99}, {'blockheight':0}):
            with self.subTest(change=change):
                source=copy.deepcopy(self.cash_source)
                source['listfunds']['outputs'][0].update(change)
                self.event('treasury_cln_wallet_source',source)
                with self.assertRaises(ValueError):
                    self.node_assets(utxos=[{**output,'source_sequence':self.sequence()}])
        self.chain.coins[('c'*64,0)]['value']=Decimal('.00000701')
        with self.assertRaisesRegex(InvariantError,'actual chain'):
            self.node_assets(utxos=[output])

    def test_original_source_kind_presence_hash_and_duplicate_rows_are_checked(self):
        output=self.wallet_output()
        for kind,source in [('unverified_label',self.cash_source),
                            ('treasury_cln_wallet_source',{**self.cash_source,'listfunds':{'outputs':[],'channels':[]}}),
                            ('treasury_cln_wallet_source',{**self.cash_source,'listfunds':{'outputs':self.cash_source['listfunds']['outputs']*2,'channels':[]}})]:
            with self.subTest(kind=kind,source=source):
                self.event(kind,source)
                with self.assertRaises(ValueError):
                    self.node_assets(utxos=[{**output,'source_sequence':self.sequence()}])
        self.store.db.execute('UPDATE event SET hash=? WHERE sequence=?',('0'*64,output['source_sequence']))
        with self.assertRaisesRegex(ValueError,'event frame changed'):
            self.node_assets(utxos=[output])

    def test_cash_duplicates_inside_one_node_or_across_members_are_rejected(self):
        output=self.wallet_output()
        with self.assertRaisesRegex(InvariantError,'physical'):
            self.node_assets(utxos=[output,output])
        self.chain.coins[('c'*64,0)]['scriptPubKey']['hex']='wallet-script'
        source=copy.deepcopy(self.cash_source)
        source['listfunds']['outputs'][0]['scriptpubkey']='wallet-script'
        self.event('treasury_cln_wallet_source',source)
        row={**output,'script':'wallet-script','source_sequence':self.sequence()}
        wallet_coin={**row,'descriptor_index':0,'child_index':0}
        with self.assertRaisesRegex(InvariantError,'physical'):
            capture_assets(self.store,{'rounds':self.inventory(self.wallet,utxos=[wallet_coin]),
                'peer':self.inventory(self.peer,utxos=[row])},self.chain)

    def test_original_source_aggregate_rows_and_bytes_are_bounded(self):
        output=self.wallet_output()
        source=copy.deepcopy(self.cash_source)
        source['listfunds']['channels']=[{}]*2000
        self.event('treasury_cln_wallet_source',source)
        with self.assertRaisesRegex(ValueError,'bound'):
            self.node_assets(utxos=[{**output,'source_sequence':self.sequence()}])
        source=copy.deepcopy(self.cash_source)
        source['getinfo']['opaque']='0'*(2*1024*1024)
        self.event('treasury_cln_wallet_source',source)
        with self.assertRaisesRegex(ValueError,'bound'):
            self.node_assets(utxos=[{**output,'source_sequence':self.sequence()}])

    def refuse_source_load(self, forbidden, seen):
        from simulator.treasury import _source_event
        def observed(store,sequence):
            seen.append(sequence)
            if sequence in forbidden:
                self.fail('Over-budget original CLN source was loaded before its byte guard')
            return _source_event(store,sequence)
        return patch('simulator.treasury._source_event',side_effect=observed)

    def test_oversized_original_source_is_refused_before_load_or_parse(self):
        output=self.wallet_output()
        source=copy.deepcopy(self.cash_source)
        source['getinfo']['opaque']='0'*(2*1024*1024)
        self.event('treasury_cln_wallet_source',source)
        sequence=self.sequence();seen=[]
        size=self.store.db.execute('SELECT length(CAST(payload AS BLOB)) FROM event WHERE sequence=?',(sequence,)).fetchone()[0]
        self.assertGreater(size,2*1024*1024)
        with self.refuse_source_load({sequence},seen):
            with self.assertRaisesRegex(ValueError,'byte'):
                self.node_assets(utxos=[{**output,'source_sequence':sequence}])
        self.assertNotIn(sequence,seen)

    def test_second_unique_source_exceeding_aggregate_bytes_is_not_loaded(self):
        output=self.wallet_output()
        source=copy.deepcopy(self.cash_source)
        source['getinfo']['opaque']='0'*(1100*1024)
        self.event('treasury_cln_wallet_source',source)
        first=self.sequence()
        second_source=copy.deepcopy(source)
        second_source['listfunds']['outputs'][0]['txid']='d'*64
        self.chain.coins[('d'*64,0)]=copy.deepcopy(self.chain.coins[('c'*64,0)])
        self.event('treasury_cln_wallet_source',second_source)
        second=self.sequence();seen=[]
        sizes=[self.store.db.execute('SELECT length(CAST(payload AS BLOB)) FROM event WHERE sequence=?',(seq,)).fetchone()[0]
               for seq in (first,second)]
        self.assertTrue(all(size<2*1024*1024 for size in sizes))
        self.assertGreater(sum(sizes),2*1024*1024)
        rows=[{**output,'source_sequence':first},
              {**output,'outpoint':'d'*64+':0','source_sequence':second}]
        with self.refuse_source_load({second},seen):
            with self.assertRaisesRegex(ValueError,'byte'):
                self.node_assets(utxos=rows)
        self.assertEqual(1,seen.count(first))
        self.assertNotIn(second,seen)

    def test_same_original_source_is_loaded_and_charged_once(self):
        output=self.wallet_output()
        source=copy.deepcopy(self.cash_source)
        source['getinfo']['opaque']='0'*(1100*1024)
        other=copy.deepcopy(source['listfunds']['outputs'][0]);other['txid']='d'*64
        source['listfunds']['outputs'].append(other)
        self.chain.coins[('d'*64,0)]=copy.deepcopy(self.chain.coins[('c'*64,0)])
        self.event('treasury_cln_wallet_source',source)
        sequence=self.sequence();seen=[]
        with self.refuse_source_load(set(),seen):
            result=self.node_assets(utxos=[{**output,'source_sequence':sequence},
                {**output,'outpoint':'d'*64+':0','source_sequence':sequence}])
        self.assertEqual(3_900_999,result['total_msat'])
        self.assertEqual(1,seen.count(sequence))

    def test_missing_original_source_is_rejected_before_loading(self):
        output=self.wallet_output()
        sequence=999999;seen=[]
        with self.refuse_source_load({sequence},seen):
            with self.assertRaisesRegex(ValueError,'byte bound'):
                self.node_assets(utxos=[{**output,'source_sequence':sequence}])
        self.assertNotIn(sequence,seen)


if __name__ == '__main__':
    unittest.main()

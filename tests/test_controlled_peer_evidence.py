"""Reducer contracts only; synthetic rows never earn live scenario credit."""
import unittest

from tests import test_final_campaign as campaign_fixture


class ReferencedExternalProofRegressions(unittest.TestCase):
    def setUp(self):
        self.fixture = campaign_fixture.FinalEpochEvidenceTests()
        self.fixture.setUp()

    def tearDown(self):
        self.fixture.tearDown()

    def summary(self, operation, direction):
        f = self.fixture
        f.action('external', operation, data={'payment_hash': 'b' * 64})
        return f.event('controlled_peer_payment_verified', {
            'action_id': 'external', 'payment_hash': 'b' * 64,
            'state': 'succeeded', 'direction': direction,
            'peer_pubkey': '02' + '6' * 64,
            'peer_outcome_checked': True, 'verified_at': 101,
        })

    def test_non_payment_action_cannot_be_relabelled_external_send(self):
        sequence = self.summary('snapshot', 'send')
        with self.assertRaises(ValueError):
            self.fixture.credit('external_lightning', 'external', sequence)

    def test_paid_hold_without_signed_native_claim_is_not_receive_recovery(self):
        sequence = self.summary('invoice', 'receive')
        with self.assertRaises(ValueError):
            self.fixture.credit('external_lightning', 'external', sequence)

    def test_summary_without_original_payer_receiver_cost_sources_is_not_send(self):
        sequence = self.summary('pay_invoice', 'send')
        with self.assertRaises(ValueError):
            self.fixture.credit('external_lightning', 'external', sequence)

import asyncio
import copy
import hashlib
import json
from unittest.mock import patch
from simulator.controlled_peer_evidence import SelectedClnReader, _hold_invoice, _derive_external
from simulator.model import canonical, public_payload
from simulator.ownership import EvidenceGap
from tests.controlled_peer_fixture import NODES, external_send, external_receive


class ReferencedPositiveAndTamperTests(ReferencedExternalProofRegressions):
    def prepare(self,direction='send'):
        sequence=(external_send if direction=='send' else external_receive)(self.fixture)
        event=self.fixture.store.db.execute('SELECT payload FROM event WHERE sequence=?',(sequence,)).fetchone()
        return sequence,json.loads(event[0])

    def verify_changes(self,changes,direction='send'):
        _,proof=self.prepare(direction)
        proof.update(changes)
        f=self.fixture
        sequence=f.event('controlled_peer_payment_verified',proof)
        with self.assertRaises((ValueError,EvidenceGap)):
            f.credit('external_lightning','external',sequence)

    def test_original_signed_send_and_original_recipient_claim_are_separate(self):
        sequence,proof=self.prepare('send')
        self.assertTrue(self.fixture.credit('external_lightning','external',sequence))
        self.assertFalse(self.fixture.credit('external_lightning','external',sequence))
        self.assertEqual(3,proof['router_fee_msat'])
        self.assertEqual(0,proof['native_customer_fee_sat'])
        self.fixture.store.verify_event_chain()

    def test_invoice_receive_requires_its_unique_actual_native_claim_references(self):
        sequence,proof=self.prepare('receive')
        self.assertEqual('claim',proof['claim_action_id'])
        self.assertTrue(self.fixture.credit('external_lightning','external',sequence))
        self.fixture.store.verify_event_chain()

    def test_swapped_node_source_is_rejected(self):
        _,proof=self.prepare()
        proof['operator_source_sequence']=proof['peer_source_sequence']
        sequence=self.fixture.event('controlled_peer_payment_verified',proof)
        with self.assertRaisesRegex(ValueError,'selected controlled source'):
            self.fixture.credit('external_lightning','external',sequence)

    def test_forged_router_fee_or_updated_summary_time_is_rejected(self):
        self.verify_changes({'router_fee_msat':4,'verified_at':104})

    def test_old_claim_action_cannot_be_replaced_by_unrelated_sync(self):
        self.fixture.action('unrelated','sync',data={})
        self.verify_changes({'claim_action_id':'unrelated'},'receive')

    def test_other_owner_cannot_take_receive_credit(self):
        self.prepare('receive')
        self.fixture.store.db.execute("UPDATE owner_key SET actor='actor-02' WHERE pubkey='key-received'")
        action=self.fixture.store.db.execute("SELECT * FROM action WHERE id='external'").fetchone()
        proof=json.loads(self.fixture.store.db.execute("SELECT payload FROM event WHERE kind='controlled_peer_payment_verified'").fetchone()[0])
        with self.assertRaises(ValueError):_derive_external(self.fixture.store,action,proof)

    def test_missing_signed_send_source_cannot_keep_summary_credit(self):
        sequence,_=self.prepare()
        self.fixture.store.db.execute('DELETE FROM coin_observation')
        self.fixture.store.db.execute('DELETE FROM owned_coin')
        with self.assertRaises(ValueError):self.fixture.credit('external_lightning','external',sequence)


class SelectedNativeReaderContractTests(unittest.TestCase):
    """Fake RPC replies exercise private projection only; no native/live credit."""
    def setUp(self):
        self.secret=bytes(range(32)).hex();self.hash=hashlib.sha256(bytes.fromhex(self.secret)).hexdigest()
        self.calls=[];self.pay={'payment_hash':self.hash,'bolt11':'synthetic-pay','status':'complete','preimage':self.secret,
            'amount_msat':'1000000msat','amount_sent_msat':'1000003msat','completed_at':101,'destination':NODES['fixture_peer'],
            'number_of_parts':2,'label':'must not capture','payment_secret':'private decode field'}
        self.invoice={'payment_hash':self.hash,'bolt11':'synthetic-invoice','status':'paid','payment_preimage':self.secret,
            'amount_received_msat':'1000000msat','paid_at':101,'description':'private description'}
        self.decoder={'type':'bolt11 invoice','valid':True,'payment_hash':self.hash,'currency':'bcrt','payee':NODES['fixture_peer'],
                      'amount_msat':1000000,'payment_secret':'private decoder field'}
    async def rpc(self,alias,method,params):
        self.calls.append((alias,method,copy.deepcopy(params)))
        if method=='getinfo':return {'id':NODES[alias],'network':'regtest','version':'actual-shape-contract'}
        if method=='listpays':return {'pays':[copy.deepcopy(self.pay)] if self.pay else []}
        if method=='listinvoices':return {'invoices':[copy.deepcopy(self.invoice)] if self.invoice else []}
        if method=='decode':
            value=copy.deepcopy(self.decoder)
            if params['string']=='synthetic-invoice':value['payee']=NODES['operator']
            return value
        raise AssertionError(method)
    def read(self):
        return asyncio.run(SelectedClnReader(self.rpc,node_ids=NODES,network='regtest',clock=lambda:102).read('operator',self.hash))
    def test_raw_private_fields_checked_then_projected_before_capture(self):
        public=self.read();public_payload(public)
        self.assertEqual(2,public['pay']['number_of_parts'])
        text=canonical(public)
        for private in (self.secret,'private decode field','private decoder field','private description','must not capture'):
            self.assertNotIn(private,text)
        self.assertTrue(public['invoice']['preimage_hash_verified'])
        self.assertEqual({'payment_hash':self.hash},next(params for _,method,params in self.calls if method=='listpays'))
    def test_wrong_private_witness_never_reaches_public_projection(self):
        self.pay['preimage']='0'*64
        with self.assertRaises(ValueError):self.read()
    def test_pending_multipart_payment_is_not_terminal(self):
        self.pay['status']='pending';public=self.read()
        self.assertFalse(public['pay']['preimage_hash_verified'])
        self.assertNotIn('terminal_at',public['pay'])
    def test_original_decode_hash_network_or_payee_mismatch_refuses(self):
        self.decoder['payment_hash']='a'*64
        with self.assertRaises(ValueError):self.read()
    def test_unknown_hold_invoice_is_not_core_absence_proof(self):
        self.pay=self.invoice=None
        with self.assertRaises(EvidenceGap):self.read()
    def test_actual_node_identity_must_match_sealed_alias(self):
        async def wrong(alias,method,params):
            if method=='getinfo':return {'id':NODES['fixture_peer'],'network':'regtest','version':'wrong'}
            return await self.rpc(alias,method,params)
        with self.assertRaises(ValueError):
            asyncio.run(SelectedClnReader(wrong,node_ids=NODES,network='regtest').read('operator',self.hash))
    def test_unrelated_alias_or_non_exact_hash_refuses_before_any_rpc(self):
        reader=SelectedClnReader(self.rpc,node_ids=NODES,network='regtest')
        for alias,value in [('arbitrary_node',self.hash),('operator','bad')]:
            with self.assertRaises(ValueError):asyncio.run(reader.read(alias,value))
        self.assertEqual([],self.calls)
    def hold(self):
        return {'invoices':[{'payment_hash':self.hash,'invoice':'synthetic','state':2,'preimage':self.secret,'settled_at':101,
            'htlcs':[{'channel_id':'channel','id':1,'state':2,'msat':1000000},{'channel_id':'channel','id':2,'state':3,'msat':999}]}]}
    def test_hold_list_private_witness_and_all_parts_checked(self):
        row=_hold_invoice(self.hold(),self.hash)
        self.assertEqual(1000000,row['amount_received_msat'])
        # Internal row remains private until SelectedClnReader projects it.
        self.assertIn('payment_preimage',row)
    def test_hold_paid_label_cannot_hide_accepted_part(self):
        response=self.hold();response['invoices'][0]['htlcs'][1]['state']=1
        with self.assertRaises(EvidenceGap):_hold_invoice(response,self.hash)
    def test_hold_duplicate_parts_or_wrong_hash_refused(self):
        response=self.hold();response['invoices'][0]['htlcs'].append(response['invoices'][0]['htlcs'][0])
        with self.assertRaises(ValueError):_hold_invoice(response,self.hash)
        response=self.hold();response['invoices'][0]['preimage']='f'*64
        with self.assertRaises(ValueError):_hold_invoice(response,self.hash)


class PairedProfileConsumerControls(unittest.TestCase):
    def test_original_claim_reference_with_each_native_ownership_contract(self):
        import importlib.util
        if importlib.util.find_spec('simulator.architecture') is None:
            self.skipTest('canonical paired profile contribution is not on this isolated base')
        from simulator.store import Store
        from functools import partial
        for profile in ('direct_xpub','two_step_per_key'):
            with self.subTest(profile=profile):
                f=campaign_fixture.FinalEpochEvidenceTests()
                with patch('tests.test_final_campaign.Store',partial(Store,architecture_profile=profile)):
                    f.setUp()
                try:
                    original_coin=f.coin
                    if profile=='two_step_per_key':
                        def coin(actor,identity,action,at):
                            original_coin(actor,identity,action,at)
                            row=f.store.db.execute('SELECT proof FROM owned_coin WHERE id=?',(identity,)).fetchone()
                            proof=json.loads(row[0]);proof['binding']={'mailbox_pk':actor,'spk':'synthetic-owned-script','seq':1,
                                'record_signature_valid':True,'key_link_signature_valid':True}
                            f.store.db.execute('UPDATE owned_coin SET proof=? WHERE id=?',(canonical(proof),identity))
                        f.coin=coin
                    sequence=external_receive(f)
                    self.assertTrue(f.credit('external_lightning','external',sequence))
                    f.store.db.execute("UPDATE coin_observation SET action_id='external' WHERE coin_id='received'")
                    with self.assertRaises(ValueError):f.credit('external_lightning','external',sequence)
                finally:f.tearDown()


class ControlledCollectorContractTests(unittest.TestCase):
    def setUp(self):
        self.f=campaign_fixture.FinalEpochEvidenceTests();self.f.setUp()
        self.refs=external_send(self.f,emit=False)
        self.calls=[]
    def tearDown(self):self.f.tearDown()
    def reader(self):
        parent=self
        class Reader:
            async def read(self,alias,payment_hash):
                parent.calls.append((alias,payment_hash))
                key=('operator' if alias=='operator' else 'peer')+'_source_sequence'
                row=parent.f.store.db.execute('SELECT payload FROM event WHERE sequence=?',(parent.refs[key],)).fetchone()
                return json.loads(row[0])['fact']
        return Reader()
    def collect(self,reader=None):
        from simulator.controlled_peer_evidence import collect_controlled_peer_payments
        with patch('simulator.store.time.time',return_value=105.0):
            return asyncio.run(collect_controlled_peer_payments(self.f.store,None,reader or self.reader()))
    def test_original_sources_emit_once_and_do_not_refresh_terminal_time(self):
        self.assertEqual(1,self.collect())
        row=self.f.store.db.execute("SELECT payload FROM event WHERE kind='controlled_peer_payment_verified'").fetchone()
        proof=json.loads(row[0]);self.assertEqual(103,proof['verified_at'])
        self.assertEqual(0,self.collect());self.assertEqual(2,len(self.calls))
        self.f.store.verify_event_chain()
    def test_missing_native_reconciliation_never_queries_or_retries(self):
        self.f.store.db.execute("UPDATE action SET result='{}' WHERE id='external'")
        self.assertEqual(0,self.collect());self.assertEqual([],self.calls)
        self.assertEqual(0,self.f.store.db.execute("SELECT COUNT(*) FROM event WHERE kind='controlled_peer_payment_verified'").fetchone()[0])
    def test_timeout_records_unknown_evidence_without_money_dispatch(self):
        class Reader:
            async def read(self,*args):raise TimeoutError('private internal failure')
        self.assertEqual(0,self.collect(Reader()))
        payload=json.loads(self.f.store.db.execute("SELECT payload FROM event WHERE kind='controlled_peer_payment_pending'").fetchone()[0])
        self.assertFalse(payload['monetary_retry']);self.assertNotIn('private internal failure',canonical(payload))
        self.assertEqual(1,self.f.store.db.execute("SELECT COUNT(*) FROM event WHERE kind='action_dispatched'").fetchone()[0])

    def test_context_change_during_private_read_cannot_relabel_observation(self):
        base=self.reader();fixture=self.f
        class Reader:
            async def read(self,*args):
                value=await base.read(*args)
                fixture.store.add_snapshot({'observed_at':105.0,'financial_pins':{**campaign_fixture.PINS,'sdk_commit':'9'*40}})
                return value
        self.assertEqual(0,self.collect(Reader()))
        self.assertEqual(0,self.f.store.db.execute("SELECT COUNT(*) FROM event WHERE kind='controlled_peer_payment_verified'").fetchone()[0])

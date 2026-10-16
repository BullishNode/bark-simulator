"""Synthetic original rights/native tool only; real source/hash/current join."""
import copy
import json
import unittest
from decimal import Decimal
from unittest.mock import patch
from simulator import c_current_liability_source as c
from simulator.model import SIGNET_GENESIS
from simulator.ownership import EvidenceGap
from tests import test_c_native_body_proof as fixture
from tests import test_c_native_fee_sources as f

class CurrentJoin(unittest.TestCase):
    def setUp(self):
        self.x=fixture.NativeBodyProof();self.x.setUp();self.addCleanup(self.x.doCleanups)
        self.loaded=self.x.loaded;self.paths,_=self.x.collect();self.obs=self.x.f.observation;self.store=self.x.f.fixture.store
        self.original={'id':self.x.point,'pubkey':self.x.proof['user_pubkey'],'actor':'actor-01','proof':json.dumps({'chain_anchor':self.x.point})}
        self.mailbox='03'+'9'*64
        self.record={'mailbox_pk':self.mailbox,'spk':'5120'+'8'*64,'mailbox_sig':'7'*128}
        self.link={'user_pubkey':self.x.proof['user_pubkey'],'mailbox_pk':self.mailbox,'sig':'6'*128,'recovery_index':1}
        self.loaded['database']['rows']['records']=[self.record];self.loaded['database']['rows']['links']=[self.link]
        self.original['mailbox']=self.mailbox
        self.original['proof']=json.dumps({'chain_anchor':self.x.point,'binding':{'mailbox_pk':self.mailbox,'spk':self.record['spk'],'fallback_record':c.record_bytes(self.record),'key_link_attestation':c.link_bytes(self.link)}})
        self.claim={'coin_id':self.x.point,'actor':'actor-01','amount_sat':25000,'signed_hash':'a'*64,'state':'Spendable','observation_action_id':'snapshot'}
        # Store projection is mocked because the original crypto authority is a
        # distinct existing reducer. No fabricated source gets journaled.
        self.backings={self.x.point:{'confirmations':3,'bestblock':f.TIP,'coinbase':False,'value':Decimal('0.00025'),'scriptPubKey':{'hex':'5120'+'5'*64}}}
    def reduce(self,claims=None):
        outer=self
        class DB:
            def execute(self,*args):return [outer.original]
        class Store:
            db=DB()
        with patch('simulator.c_normal_source._context'),patch.object(c,'has_owner_record',return_value=True),patch.object(c,'_current_claims',return_value=[self.claim]if claims is None else claims):
            return c.reduce(Store(),self.loaded,self.paths,observation=self.obs,server_pubkey=f.KEY,backings=self.backings)
    def test_original_customer_right_and_actual_same_RR_still_not_global_readiness(self):
        audit=self.reduce();self.assertEqual([],audit['unresolved']);rights=c.require_resolved(audit)
        self.assertEqual(25000000,rights[0]['amount_msat']);self.assertFalse(audit['complete']);self.assertFalse(audit['financial_readiness'])
    def test_missing_or_wrong_unresolved_inventory_cannot_be_treated_as_empty(self):
        audit=self.reduce()
        for value in (None,False,0,{},''):
            with self.subTest(value=value),self.assertRaises(EvidenceGap):
                c.require_resolved({**audit,'unresolved':value})
        del audit['unresolved']
        with self.assertRaises(EvidenceGap):c.require_resolved(audit)
    def test_native_signedfalse_and_conditional_policy_stay_hold(self):
        original=copy.deepcopy(self.loaded)
        self.paths['paths'][0]['signed_path_valid']=False
        with self.assertRaises(EvidenceGap):c.require_resolved(self.reduce())
        self.paths['paths'][0]['signed_path_valid']=True
        self.loaded['private_pg']['coins'][0]['metadata']['policy_type']='htlc-send'
        with self.assertRaises(EvidenceGap):c.require_resolved(self.reduce())
    def test_spent_or_expired_status_never_removes_original_customer_right(self):
        self.loaded['private_pg']['coins'][0]['metadata']['spend_state']='spent'
        audit=self.reduce();self.assertTrue(audit['unresolved'])
        with self.assertRaises(EvidenceGap):c.require_resolved(audit)
    def test_absent_owner_is_not_operator_and_missing_original_row_is_not_zero(self):
        with self.assertRaises(EvidenceGap):c.require_resolved(self.reduce(claims=[]))
        self.loaded['private_pg']['coins']=[];self.paths['paths']=[]
        with self.assertRaises(EvidenceGap):c.require_resolved(self.reduce())
    def test_independent_spent_root_and_wrong_tip_or_amount_hold(self):
        self.backings[self.x.point]=None
        with self.assertRaises(EvidenceGap):c.require_resolved(self.reduce())
        self.backings[self.x.point]={'confirmations':3,'bestblock':'f'*64,'coinbase':False,'value':Decimal('0.00025'),'scriptPubKey':{'hex':'5120'+'5'*64}}
        with self.assertRaises(ValueError):self.reduce()
    def test_extra_missing_body_or_wrong_body_proof_refuses(self):
        self.paths['paths'].append(copy.deepcopy(self.paths['paths'][0]))
        with self.assertRaises(ValueError):self.reduce()
        self.paths['paths'].pop();self.paths['paths'][0]['body_sha256']='b'*64
        with self.assertRaises(ValueError):self.reduce()
    def test_retained_conditional_tables_cannot_hide_behind_supported_pubkey(self):
        for name in ('payments','receives','htlcs','rounds','participations','participation_inputs','participation_outputs'):
            self.loaded['database']['rows'][name]=[{'id':'synthetic'}]
            audit=self.reduce()
            with self.assertRaises(EvidenceGap):c.require_resolved(audit)
            self.loaded['database']['rows'][name]=[]

    def test_same_RR_immutable_payout_record_and_retained_V1_ack_are_mandatory(self):
        original=copy.deepcopy(self.loaded['database']['rows'])
        for name in ('links','records'):
            self.loaded['database']['rows'][name]=[]
            with self.assertRaises(EvidenceGap):self.reduce()
            self.loaded['database']['rows']=copy.deepcopy(original)
        self.loaded['database']['rows']['records'][0]['spk']='5120'+'1'*64
        with self.assertRaises(ValueError):self.reduce()
        self.loaded['database']['rows']=copy.deepcopy(original)
        self.loaded['database']['rows']['links'][0]['recovery_index']=2
        with self.assertRaises(ValueError):self.reduce()

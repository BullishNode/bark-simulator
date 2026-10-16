"""Preserved pre-money path: actual Store/Lease/SQLite, synthetic native proofs.

No native signature, actual Core or financial admission credit.
"""
import copy
import json
import sqlite3
import time
import unittest
from unittest import mock
from types import SimpleNamespace

from simulator import c_cohort as c, c_pilot, identity_bootstrap as bootstrap
from simulator.engine import Lease
from simulator.model import canonical
from simulator.ownership import record_verified
from tests import test_identity_bootstrap
from tests import test_c_cohort_admission
from tests.test_c_pilot import initial_data,pilot


class PremoneyControls(unittest.TestCase):
    def setUp(self):
        self.fixture=test_identity_bootstrap.IdentityBootstrapTests()
        self.fixture.architecture_profile='direct_per_key';self.fixture.setUp();self.addCleanup(self.fixture.tearDown)
        self.store=self.fixture.store;self.config=self.fixture.config;self.wallet=self.fixture.wallets
        self.pins=self.fixture.pins
        c_pilot.declare(self.store,{**pilot(),'pins':self.pins,'bank_opening_sat':900000})
        self.fixture.declare()
        self.lease=Lease(self.wallet);self.lease.__enter__();self.addCleanup(lambda:self.lease.__exit__(None,None,None))
        self.store.queue('c_create_01','actor-01','H01','create',{},0)
        self.action=self.store.claim({'create'})
        bootstrap.begin(self.store,self.config,self.fixture.snapshot,self.action)
        self.data,proofs=initial_data(100)
        proofs=[{**proof,'financial_pins':self.pins} for proof in proofs]
        self.data['onchain_inventory']={'schema_version':1,'network':'signet','read_only':True,'complete':True,
            'utxos':[],'pending_transactions':[],'pending_parents':[],'unavailable_parent_txids':[],
            'descriptors':[{'keychain':'external','last_revealed_index':1,'descriptor':'synthetic-public-actor-01'}]}
        response={'action_id':'c_create_01','status':'ok','actual_fee_sat':0,'data':self.data}
        self.store.db.execute("UPDATE action SET state='completed',actual_fee_sat=0,result=? WHERE id='c_create_01'",(canonical(response),))
        self.store.event('driver_response',{'action_id':'c_create_01','response':response})
        record_verified(self.store,'actor-01','c_create_01',{'objects':[{'kind':'key','proof':proof,'request_origin':row['origin']} for proof,row in zip(proofs,self.data['initial_key_links'])],'movements':[],'financial_pins':self.pins})
        directory=self.wallet/'actor-01';directory.mkdir(mode=0o700)
        path=directory/'db.sqlite';db=sqlite3.connect(path)
        db.execute('CREATE TABLE bark_vtxo_key(idx INTEGER,public_key TEXT,linked_proof BLOB,issued INTEGER)')
        for index,row in enumerate(self.data['initial_key_links']):
            origin=row['origin'];db.execute('INSERT INTO bark_vtxo_key VALUES (?,?,?,?)',(index,origin['user_pubkey'],bytes.fromhex(origin['key_link_attestation']),int(index==0)))
        db.commit();db.close();path.chmod(0o600)
        self.chain=test_c_cohort_admission.CohortCreateAdmission.core(SimpleNamespace(store=self.store,config=SimpleNamespace()))
        original_call=self.chain.call
        def exact_range(method,*args,**kwargs):
            if method=='deriveaddresses':return [args[0]+':'+str(i) for i in range(args[1][0],args[1][1]+1)]
            return original_call(method,*args,**kwargs)
        self.chain.call=exact_range
        self.store.db.execute("INSERT OR REPLACE INTO meta VALUES ('paused','premoney source test')")

    def verify(self):
        return bootstrap.verify_created(self.store,self.config,self.chain,'actor-01','c_create_01')

    def profile(self):
        return {'id':'direct-initial12','seal_sequence':c.seal(self.store)['seal_sequence'],'pins':self.pins,
            'initial_actors':list(c.INITIAL),'ramp_actors':list(c.RAMP),'grant_sat':25000,
            'maximum_client_principal_sat':600000,'fee_budgets_sat':{'ordinary':60000,'urgent':40000},'capital_exposure_sat':900000}

    def test_actual_no_zero_proof_state_holds_without_native_recreate(self):
        self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM event WHERE kind='identity_bootstrap_zero_assets_verified'").fetchone()[0])
        with self.assertRaisesRegex(ValueError,'zero-asset proof'):c.seal_unfunded(self.store,self.config,self.chain)
        self.assertIsNone(self.store.get_meta(c.SEAL_KEY))
        self.assertEqual(1,self.store.db.execute('SELECT count(*) FROM action').fetchone()[0])

    def test_direct_initial12_requires_no_board_or_ark_and_preserves_original01(self):
        self.verify();original_actions=[tuple(row) for row in self.store.db.execute('SELECT * FROM action')]
        self.assertTrue(c.seal_unfunded(self.store,self.config,self.chain));self.assertFalse(c.seal_unfunded(self.store,self.config,self.chain))
        self.assertTrue(c.declare_profile(self.store,self.profile()))
        request=c.cohort_request(self.store,'initial')
        self.assertEqual(300000,sum(request['funding_requirements_sat'].values()))
        self.assertEqual(25000,request['funding_requirements_sat']['actor-01'])
        self.assertEqual({'watchman':0},request['retained_operator_credits_sat'])
        policy=c.prospective_funding_policy(self.store)
        self.assertEqual(400000,sum(policy['amounts'].values()))
        self.assertEqual(300000,policy['client_principal_sat'])
        self.assertEqual(original_actions,[tuple(row) for row in self.store.db.execute('SELECT * FROM action')])
        self.assertEqual({'ordinary':0,'urgent':0},c.seal(self.store)['used_fees_msat'])
        self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM event WHERE kind='financial_operating_readiness'").fetchone()[0])
        c.validate_original_unfunded_create(self.store,{'id':'c_create_02','actor_id':'actor-02'})
        for value in ({'id':'retry01','actor_id':'actor-01'},{'id':'new02','actor_id':'actor-02'}):
            with self.assertRaisesRegex(ValueError,'pending c_create_02'):c.validate_original_unfunded_create(self.store,value)
        with self.assertRaisesRegex(ValueError,'original01/02 zero-asset'):
            c.declare_enrollment(self.store,self.config,'initial',identifier='extra10',
                actions={actor:'c_create_'+actor[-2:] for actor in c.INITIAL[2:]})
        self.assertIsNone(c.enrollment(self.store,'initial'))
        # Original02 remains on its original bootstrap admission, not new03 scope.
        self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        self.store.queue('c_create_02','actor-02','H01','create',{},0)
        action=self.store.claim({'create'})
        self.assertTrue(bootstrap.eligible(self.store,self.config,self.fixture.snapshot,action))

    def test_any_prior_money_or_missing_key_proof_refuses(self):
        self.verify()
        self.store.event('financial_cost_verified',{'budget':'ordinary','amount_msat':1})
        with self.assertRaisesRegex(ValueError,'financial history'):c.seal_unfunded(self.store,self.config,self.chain)
        self.assertIsNone(self.store.get_meta(c.SEAL_KEY))

    def test_stale_or_wrong_tip_zero_source_and_original_action_change_refuse(self):
        self.verify();self.chain.height=101
        with self.assertRaisesRegex(ValueError,'current independently'):c.seal_unfunded(self.store,self.config,self.chain)
        self.chain.height=100
        self.store.db.execute("UPDATE action SET actual_fee_sat=1 WHERE id='c_create_01'")
        with self.assertRaises(ValueError):c.seal_unfunded(self.store,self.config,self.chain)
        self.assertIsNone(self.store.get_meta(c.SEAL_KEY))

    def test_original_payout_must_independently_derive_at_external0(self):
        self.verify();original_call=self.chain.call
        def wrong(method,*args,**kwargs):
            result=original_call(method,*args,**kwargs)
            if method=='validateaddress':return {**result,'scriptPubKey':'0014'+'ff'*20}
            return result
        self.chain.call=wrong
        with self.assertRaisesRegex(ValueError,'immutable payout'):c.seal_unfunded(self.store,self.config,self.chain)
        self.assertIsNone(self.store.get_meta(c.SEAL_KEY))

    def test_original51st_verified_key_cannot_be_omitted(self):
        self.verify();pubkey=self.data['initial_key_links'][-1]['origin']['user_pubkey']
        self.store.db.execute('DELETE FROM owner_key WHERE pubkey=?',(pubkey,))
        with self.assertRaisesRegex(ValueError,'key identity'):c.seal_unfunded(self.store,self.config,self.chain)
        self.assertIsNone(self.store.get_meta(c.SEAL_KEY))

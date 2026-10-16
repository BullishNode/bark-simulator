"""Real paths/Lease/Store and admission; public native source stubs are explicit."""
import copy
import json
from pathlib import Path
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from simulator import c_cohort as c,identity_bootstrap as bootstrap
from simulator.engine import Lease
from tests import test_c_cohort


class CohortCreateAdmission(unittest.TestCase):
    def setUp(self):
        self.fixture=test_c_cohort.PreservedCohortControls();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.store=self.fixture.store;self.wallet=self.fixture.wallet;self.pins=self.fixture.pins
        self.fixture.record();c.declare_profile(self.store,self.fixture.profile())
        for actor in ('actor-01','actor-02'):(self.wallet/actor).mkdir(mode=0o700)
        self.lease=Lease(self.wallet);self.lease.__enter__();self.addCleanup(lambda:self.lease.__exit__(None,None,None))
        patch=mock.patch.object(bootstrap,'_context',return_value={'actual_config_boundary':'explicit test stub'})
        patch.start();self.addCleanup(patch.stop)
        self.config=SimpleNamespace(validate_identity=lambda _:None)
        self.snapshot={'financial_pins':self.pins,'observed_at':time.time(),'stable_tip':True,
            'initial_block_download':False,'server_status':{'status':'running'}}
        self.actions={actor:'cohort-create-'+actor for actor in c.INITIAL[2:]}
    def declare(self,actions=None):
        return c.declare_enrollment(self.store,self.config,'initial',identifier='initial-extra10',actions=self.actions if actions is None else actions)
    def action(self,actor='actor-03'):
        action={'id':self.actions[actor],'actor_id':actor,'operation':'create','args':{},'fee_reservation_sat':0}
        self.store.db.execute('INSERT INTO action VALUES (?,?,NULL,\'create\',\'{}\',\'queued\',0,0,NULL,NULL,0,0)',(action['id'],actor))
        return action

    def test_explicit_new_cohort_preserves_old_root_guard_and_ten_exact_ids(self):
        original=self.store.get_meta('zero_principal_identity_bootstrap')
        self.assertTrue(self.declare());self.assertFalse(self.declare())
        self.assertEqual(original,self.store.get_meta('zero_principal_identity_bootstrap'))
        self.assertTrue(bootstrap.pending(self.store));self.assertTrue(bootstrap.eligible(self.store,self.config,self.snapshot))
        action=self.action();self.assertTrue(bootstrap.eligible(self.store,self.config,self.snapshot,action))
        bootstrap.begin(self.store,self.config,self.snapshot,action)
        self.assertEqual(1,self.store.db.execute('SELECT count(*) FROM event WHERE kind=?',(c.CREATE_EVENT,)).fetchone()[0])
        with self.assertRaisesRegex(ValueError,'await original'):bootstrap.eligible(self.store,self.config,self.snapshot)
        self.assertFalse((self.wallet/'actor-03').exists())
        self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM event WHERE kind='identity_bootstrap_create_intent'").fetchone()[0])

    def test_preexisting_new_path_or_unenumerated_wallet_refuses_without_new_scope(self):
        for name in ('actor-03','foreign-wallet'):
            path=self.wallet/name;path.mkdir(mode=0o700)
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'retained private'):self.declare()
            path.rmdir()
        self.assertIsNone(c.enrollment(self.store,'initial'))

    def test_original_actor_id_reuse_arbitrary_action_or_money_is_never_admitted(self):
        bad={**self.actions,'actor-03':'actor-01-create'}
        with self.assertRaises(ValueError):self.declare(bad)
        self.declare();action=self.action()
        for changed in ({'actor_id':'actor-01'},{'id':'replacement-id'},{'operation':'board'},
                        {'args':{'amount_sat':1}},{'fee_reservation_sat':1}):
            with self.subTest(changed=changed),self.assertRaises(ValueError):bootstrap.eligible(self.store,self.config,self.snapshot,{**action,**changed})

    def test_unknown_create_is_parked_and_snapshot_foreign_stale_or_unhealthy_refuses(self):
        self.declare();action=self.action()
        for changed in ({'financial_pins':{**self.pins,'sdk_commit':'f'*40}}, {'observed_at':time.time()-91},
                        {'stable_tip':False},{'initial_block_download':True}):
            with self.subTest(changed=changed),self.assertRaises(ValueError):bootstrap.eligible(self.store,self.config,{**self.snapshot,**changed},action)
        self.store.db.execute("UPDATE action SET state='outcome_unknown' WHERE id=?",(action['id'],))
        with self.assertRaisesRegex(ValueError,'unknown outcome'):bootstrap.eligible(self.store,self.config,self.snapshot,action)

    def test_fake_zeroasset_summary_without_original_native_source_cannot_complete(self):
        self.declare();action=self.action();bootstrap.begin(self.store,self.config,self.snapshot,action)
        current=c.enrollment(self.store,'initial');actor='actor-03'
        self.fixture.event(c.ZERO_EVENT,{'actor':actor,'action_id':action['id'],'bootstrap_id':current['declaration']['id'],
            'bootstrap_declaration_sha256':c._digest(current['declaration']),'financial_pins':self.pins,
            'complete':True,'zero_assets':True,'driver_response_sequence':1,'source_event_hash':'0'*64,
            'native_response_sha256':'0'*64})
        self.assertFalse(c.enrollment_complete(self.store,'initial'))
        with self.assertRaises(ValueError):bootstrap.eligible(self.store,self.config,self.snapshot)

    def fill_created(self,actor):
        """Synthetic promoted native signatures; real public SQLite/trace/Core seam."""
        import sqlite3,hashlib
        from tests.test_c_pilot import initial_data
        from simulator.ownership import initialize,record_verified
        from simulator.model import canonical
        action=self.action(actor);bootstrap.begin(self.store,self.config,self.snapshot,action)
        data,proofs=initial_data(int(actor[-2:])*100)
        data['onchain_inventory']={'schema_version':1,'network':'signet','read_only':True,'complete':True,
            'utxos':[],'pending_transactions':[],'pending_parents':[],'unavailable_parent_txids':[],
            'descriptors':[{'keychain':'external','last_revealed_index':1,'descriptor':'synthetic-public-'+actor}]}
        reply={'action_id':action['id'],'status':'ok','actual_fee_sat':0,'data':data}
        self.store.db.execute("UPDATE action SET state='completed',actual_fee_sat=0,result=? WHERE id=?",(canonical(reply),action['id']))
        self.fixture.event('driver_response',{'action_id':action['id'],'response':reply})
        initialize(self.store)
        record_verified(self.store,actor,action['id'],{'objects':[{'kind':'key','proof':proof,'request_origin':row['origin']} for proof,row in zip(proofs,data['initial_key_links'])],'movements':[],'financial_pins':self.pins})
        path=self.wallet/actor;path.mkdir(mode=0o700)
        database=path/'db.sqlite';connection=sqlite3.connect(database)
        connection.execute('CREATE TABLE bark_vtxo_key(idx INTEGER,public_key TEXT,linked_proof BLOB,issued INTEGER)')
        for index,row in enumerate(data['initial_key_links']):
            origin=row['origin'];connection.execute('INSERT INTO bark_vtxo_key VALUES (?,?,?,?)',(index,origin['user_pubkey'],bytes.fromhex(origin['key_link_attestation']),int(index==0)))
        connection.commit();connection.close();database.chmod(0o600)
        return action,data

    def core(self):
        from simulator.model import SIGNET_GENESIS
        from tests.owned_activity_fixture import capture
        import hashlib
        outer=self
        class Core:
            height=100;tip='c'*64
            def identity(self):return {'chain':'signet','initialblockdownload':False,'blocks':self.height,'bestblockhash':self.tip}
            def call(self,method,*args,**kwargs):
                if method=='getdescriptorinfo':return {'hasprivatekeys':False,'isrange':True,'issolvable':True,'descriptor':args[0]}
                if method=='deriveaddresses':return [args[0]+':'+str(i) for i in range(20)]
                if method=='validateaddress':
                    actor,index=args[0].rsplit(':',1)
                    script=('0014'+format(int(actor[-2:])*100,'040x')) if index=='0' else hashlib.sha256(args[0].encode()).hexdigest()
                    return {'isvalid':True,'scriptPubKey':script}
                if method=='scantxoutset':return None if args[0]=='status' else {'success':True,'height':self.height,'bestblock':self.tip,'unspents':[],'total_amount':0}
                if method=='getdescriptoractivity':return capture(self,outer.store,args,{'activity':[]})
                raise AssertionError('unexpected non-readonly Core method')
        self.config.network='signet';self.config.expected_genesis=SIGNET_GENESIS
        self.store.attach_trace();return Core()

    def test_all_ten_native_shape_and_real_sqlite_sources_close_one_tip_without_actions(self):
        self.declare();core=self.core()
        original=[tuple(row) for row in self.store.db.execute('SELECT * FROM funding_batch')]
        for actor in c.INITIAL[2:]:
            action,_=self.fill_created(actor)
            receipt=bootstrap.verify_created(self.store,self.config,core,actor,action['id'])
            self.assertTrue(receipt['zero_assets'])
        self.assertTrue(c.enrollment_complete(self.store,'initial'))
        self.assertEqual(1,self.store.db.execute("SELECT count(*) FROM event WHERE kind='direct_per_key_cohort_identities_verified'").fetchone()[0])
        self.assertEqual(original,[tuple(row) for row in self.store.db.execute('SELECT * FROM funding_batch')])
        self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM event WHERE kind='financial_operating_readiness'").fetchone()[0])
        # Historical completed identity proofs remain valid after legitimate SDK
        # key issuance; original root-empty metadata is never rewritten.
        database=self.wallet/'actor-03'/'db.sqlite'
        import sqlite3
        connection=sqlite3.connect(database);connection.execute('UPDATE bark_vtxo_key SET issued=1 WHERE idx=1');connection.commit();connection.close()
        self.assertTrue(c.enrollment_complete(self.store,'initial'))

    def test_different_tip_receipts_hold_then_readonly_original_create_refresh_closes(self):
        self.declare();core=self.core()
        actions={}
        for index,actor in enumerate(c.INITIAL[2:]):
            action,_=self.fill_created(actor);actions[actor]=action
            if index:core.height=101;core.tip='d'*64
            bootstrap.verify_created(self.store,self.config,core,actor,action['id'])
        self.assertFalse(c.enrollment_complete(self.store,'initial'))
        self.assertEqual(10,self.store.db.execute('SELECT count(*) FROM event WHERE kind=?',(c.CREATE_EVENT,)).fetchone()[0])
        # Reobserve ONLY already-created actor03 with actual readonly Core/source
        # verification. No native driver call, action or create intent is repeated.
        bootstrap.verify_created(self.store,self.config,core,'actor-03',actions['actor-03']['id'])
        self.assertTrue(c.enrollment_complete(self.store,'initial'))
        self.assertEqual(10,self.store.db.execute('SELECT count(*) FROM event WHERE kind=?',(c.CREATE_EVENT,)).fetchone()[0])

    def test_wrong_core_external0_script_refuses_before_zero_receipt(self):
        self.declare();core=self.core();action,_=self.fill_created('actor-03');call=core.call
        def changed(method,*args,**kw):
            result=call(method,*args,**kw)
            if method=='validateaddress':return {'isvalid':True,'scriptPubKey':'0014'+'ff'*20}
            return result
        core.call=changed
        with self.assertRaisesRegex(ValueError,'external0'):bootstrap.verify_created(self.store,self.config,core,'actor-03',action['id'])
        self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM event WHERE kind=?',(c.ZERO_EVENT,)).fetchone()[0])

    def test_missing51st_signature_or_actual_sqlite_row_holds_before_Core_zero_credit(self):
        self.declare();core=self.core();action,data=self.fill_created('actor-03')
        with self.store.transaction():self.store.db.execute('DELETE FROM owner_key WHERE pubkey=?',(data['initial_key_links'][-1]['origin']['user_pubkey'],))
        with self.assertRaisesRegex(ValueError,'key identity'):bootstrap.verify_created(self.store,self.config,core,'actor-03',action['id'])
        self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM event WHERE kind=?',(c.ZERO_EVENT,)).fetchone()[0])

    def test_ramp_scope_refuses_before_final_epoch_or_without_checked_initial_cohort(self):
        with self.assertRaisesRegex(ValueError,'epoch'):
            c.declare_enrollment(self.store,self.config,'ramp',identifier='ramp-extra12',actions={a:'ramp-'+a for a in c.RAMP})
        self.assertIsNone(c.enrollment(self.store,'ramp'))


if __name__=='__main__':unittest.main()

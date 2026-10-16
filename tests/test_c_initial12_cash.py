"""Real Store/Lease/12 SQLite provenance; native signatures/Core are doubles."""
import copy
import json
import sqlite3
import unittest

from simulator import c_cohort as cohort, fresh_cash_readiness as cash
from tests import test_c_premoney


class Initial12CashControls(unittest.TestCase):
    def test_historical_twelve_survives_funding_but_not_missing_native_sources(self):
        case=test_c_premoney.PremoneyControls();case.setUp();self.addCleanup(case.doCleanups)
        case.verify();cohort.seal_unfunded(case.store,case.config,case.chain)
        cohort.declare_profile(case.store,case.profile());case.complete_new_identity('actor-02')
        cohort.declare_enrollment(case.store,case.config,'initial',identifier='extra10',
            actions={actor:'c_create_'+actor[-2:] for actor in cohort.INITIAL[2:]})
        for actor in cohort.INITIAL[2:]:case.complete_new_identity(actor)
        original=case.store.get_meta('zero_principal_identity_bootstrap')
        initial=cohort.initial_identity_sources(case.store)
        case.store.db.execute('CREATE TABLE funding_batch(state TEXT)')
        case.store.db.execute("INSERT INTO funding_batch VALUES ('confirmed')")
        with self.assertRaisesRegex(ValueError,'funded path'):cohort.initial_identity_sources(case.store)
        historical=cohort.historical_initial_identity_sources(case.store)
        self.assertEqual(initial,historical)
        # Current issued flags are not rewritten into an original create proof.
        path=case.wallet/'actor-12'/'db.sqlite'
        db=sqlite3.connect(path);db.execute('UPDATE bark_vtxo_key SET issued=1 WHERE idx=1');db.commit();db.close()
        self.assertEqual(initial,cohort.historical_initial_identity_sources(case.store))
        cash._phase_history(case.store,case.pins,list(cohort.INITIAL))
        proof={'financial_pins':case.pins,'operation_scope':cash.OPERATIONS,'client_action_scope':{
            'actors':list(cohort.INITIAL),'operations':cash.OPERATIONS,'maximum_fee_sat':0,'args':{}}}
        cash.validate_client_action_scope(case.store,proof,operation='sync',maximum_fee_sat=0,reserved_action_id=None)
        for actors in (list(cohort.INITIAL[:-1]),[*cohort.INITIAL[:-1],'foreign']):
            changed=copy.deepcopy(proof);changed['client_action_scope']['actors']=actors
            with self.assertRaisesRegex(ValueError,'action scope'):
                cash.validate_client_action_scope(case.store,changed,operation='sync',maximum_fee_sat=0,reserved_action_id=None)
        # Every actual private SQLite is read, including the twelfth wallet.
        for actor in cohort.INITIAL:
            db=sqlite3.connect(case.wallet/actor/'db.sqlite')
            db.execute('CREATE TABLE migrations(value INTEGER)');db.execute('INSERT INTO migrations VALUES (43)')
            for table in cash.ECONOMIC_TABLES|cash.METADATA_TABLES-{'bark_vtxo_key'}:
                db.execute('CREATE TABLE '+table+'(dummy INTEGER)')
            db.commit();db.close()
        sequence=cash.observe_empty_client_economics(case.store,case.config)
        value=json.loads(case.store.db.execute('SELECT payload FROM event WHERE sequence=?',(sequence,)).fetchone()[0])
        self.assertEqual(set(cohort.INITIAL),set(value['clients']))
        self.assertEqual(12,len(value['actors']))
        db=sqlite3.connect(path);db.execute('INSERT INTO bark_wallet_action_checkpoint VALUES(1)');db.commit();db.close()
        with self.assertRaisesRegex(ValueError,'existing monetary state'):
            cash.observe_empty_client_economics(case.store,case.config)
        db=sqlite3.connect(path);db.execute('DELETE FROM bark_wallet_action_checkpoint');db.commit();db.close()
        self.assertEqual(original,case.store.get_meta('zero_principal_identity_bootstrap'))
        case.store.db.execute("DELETE FROM owner_key WHERE actor='actor-12'")
        with self.assertRaisesRegex(ValueError,'key identity'):
            cash.validate_client_action_scope(case.store,proof,operation='sync',maximum_fee_sat=0,reserved_action_id=None)
        self.assertEqual(12,case.store.db.execute('SELECT count(*) FROM action').fetchone()[0])
        self.assertEqual(0,case.store.db.execute("SELECT count(*) FROM event WHERE kind='financial_operating_readiness'").fetchone()[0])

    def test_null_reserved_fee_is_unknown_even_when_actual_fee_is_zero(self):
        from types import SimpleNamespace
        connection=sqlite3.connect(':memory:');self.addCleanup(connection.close)
        connection.execute('CREATE TABLE action(state TEXT,actual_fee_sat INTEGER,fee_reservation_sat INTEGER,args TEXT)')
        connection.execute("INSERT INTO action VALUES('completed',0,NULL,'{}')")
        connection.execute('CREATE TABLE funding_batch(state TEXT)')
        with self.assertRaisesRegex(ValueError,'unfinished'):
            cash._phase_history(SimpleNamespace(db=connection),{},[])

"""Pure native producer controls: no SSH, database, wallet or chain execution."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]/'deploy'/'track-c'


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value)
    return value


public=load('public_observer',ROOT/'public_observer.py')
observer=load('track_c_server_observer',ROOT/'server-observer.py')


def manifest():
    from tests.test_c_pilot import PINS
    return {'schema_version':1,'track':'C','architecture_profile':'direct_per_key','active':True,
        'deployment_id':'synthetic-c-control','genesis':observer.GENESIS,'financial_pins':PINS,
        'observer_files':{'server-observer.py':'a'*64,'public_observer.py':'b'*64},
        'ops':{'path':'/opt/track-c/observer/ops','sha256':'c'*64},
        'services':{service:{'unit':'track-c-'+service+'.service','executable_path':'/opt/track-c/runtime/'+service,
            'executable_sha256':'d'*64,'config_path':'/etc/track-c/'+service+'.toml','config_sha256':'e'*64,
            'admin_address':'127.0.0.1:'+str(port)} for service,port in (('captaind',3536),('watchmand',3538))}}


class NativeObserverControls(unittest.TestCase):
    def test_c_timing_projection_uses_actual_direct_flag_without_legacy_payout_oracles(self):
        from simulator.remote_observer import timing_projection
        info={'data':{'vtxo_lifetime':48,'required_board_confirmations':3,'round_interval_secs':600}}
        remote={'direct_expiry_enabled':True,'timings':{'enabled':False}}
        result=timing_projection(remote,info,per_key=True)
        self.assertTrue(result['payout_enabled']);self.assertFalse(result['legacy_payout_enabled'])
        self.assertTrue({'min_payout_sat','grace_blocks','sweep_min_confs'}.isdisjoint(result))
        self.assertFalse(timing_projection({},info,per_key=True)['payout_enabled'])
        old={'enabled':True,'min_payout_sat':330,'grace_blocks':1008,'sweep_min_confs':3}
        self.assertEqual({'payout_enabled':True,'min_payout_sat':330,'grace_blocks':1008,'sweep_min_confs':3,
            **info['data']},timing_projection({'timings':old},info))
    def test_false_profile_inactive_or_missing_pins_and_sources_refuse(self):
        self.assertEqual(manifest(),observer.validate_manifest(manifest()))
        for key,value in [('architecture_profile','direct_xpub'),('active',False),('track','B'),
                          ('financial_pins',{}),('observer_files',{}),('schema_version',True)]:
            with self.subTest(key=key),self.assertRaises(ValueError):observer.validate_manifest({**manifest(),key:value})
        with patch.object(observer,'checked_file',side_effect=FileNotFoundError):
            with patch.object(public,'ops') as operation:
                with self.assertRaises(FileNotFoundError):observer.installed_manifest()
                operation.assert_not_called()
    def test_public_sql_preserves_atomic_exhaustive_source_and_never_exports_secrets_or_account_fields(self):
        for sql in (public.claimant_sql(closed=True),public.direct_journal_sql()):
            self.assertTrue(sql.startswith('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;'))
            self.assertIn('statement_timeout',sql);self.assertIn('LIMIT 2001',sql)
            for forbidden in ('account_xpub','account_sig','child_index','source_evidence','signed_tx','encoded_vtxo','unlock_preimage','signed_forfeit_tx'):
                self.assertNotIn(forbidden,sql)
            self.assertIn("encode(sig,'hex') AS sig,recovery_index",sql)
        sql=public.claimant_sql(closed=True)
        self.assertIn('public.track_c_observer_round_participation',sql)
        self.assertIn('public.track_c_observer_round_part_input',sql)
        for name in ('journal_allocations','journal_carriers','journal_mappings','journal_records','journal_links','nursery','rounds'):
            self.assertIn("'"+name+"'",sql)
        self.assertIn('WHERE EXISTS',public.direct_journal_sql())
    def test_whole_frontier_bound_and_unexpected_rows_hold_without_qualification(self):
        names=public.FINANCIAL_TABLES|{'journal_'+n for n in public.DIRECT_JOURNAL_FIELDS}|{'nursery','rounds'}
        frame={'snapshot':'1:2:','observed_at':'synthetic','rows':{n:[] for n in names}}
        with patch.object(public,'ops',return_value=json.dumps(frame)):
            result=public.closed_frontier();self.assertFalse(result['complete']);self.assertFalse(result['qualified'])
            self.assertTrue(result['database_tables_complete']);self.assertEqual('direct_per_key',result['architecture_profile'])
        bad=copy.deepcopy(frame);bad['rows']['records']=[{'mailbox_pk':'02'+'1'*64,'account_xpub':'old'}]
        with patch.object(public,'ops',return_value=json.dumps(bad)),self.assertRaisesRegex(ValueError,'fields'):public.closed_frontier()
        bad=copy.deepcopy(frame);bad['rows']['coins']=[{}]*1001;bad['rows']['pool']=[{}]*1000
        with patch.object(public,'ops',return_value=json.dumps(bad)),self.assertRaisesRegex(ValueError,'whole closed frontier'):public.closed_frontier()
    def test_transport_refuses_request_selected_methods_paths_and_mutating_sql(self):
        for args in [('sql','DELETE FROM vtxo'),('cli','sendrawtransaction','00'),('cli','getblockhash','9'),
                     ('runtime-identity','other'),('wallet-inventory','bank'),('shell','id')]:
            with self.subTest(args=args),patch.object(public,'run') as run,self.assertRaises(ValueError):
                observer.transport(manifest(),*args)
            run.assert_not_called()
    def test_fixed_request_contract_rejects_sql_and_extra_host(self):
        for value in ({'kind':'closed_frontier','sql':'SELECT secret'},
                      {'kind':'snapshot','host':'elsewhere'},{'kind':'logs','service':'other'},
                      {'kind':'binding_check','mailboxes':['not-hex'],'keys':[]}):
            with self.subTest(value=value),self.assertRaises(ValueError):public.request(json.dumps(value))


if __name__=='__main__':unittest.main()

"""Synthetic same-process source controls; no live loaded-config credit."""
import copy,datetime,json,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from simulator.runtime_startup import verify_owned_startup_sources,PRODUCT_COMMIT

class RuntimeStartupTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.events=[]
        self.store=SimpleNamespace(event=lambda kind,payload:self.events.append((kind,payload)))
        stamp=datetime.datetime.now(datetime.timezone.utc)
        observed=stamp.isoformat();started=(stamp-datetime.timedelta(seconds=60)).isoformat()
        config_time=int((stamp-datetime.timedelta(seconds=120)).timestamp()*10**9)
        self.expected={'product_commit':PRODUCT_COMMIT,'image_sha256':'sha256:'+'a'*64,'schema_sha256':'b'*64,
            'database':'finite','containers':{},'binary_sha256':{},'config_sha256':{},'config_paths':{}}
        self.current={'kind':'owned_startup_source','product_commit':PRODUCT_COMMIT,'schema_sha256':'b'*64,'observed_at':observed,'daemons':{}}
        for service in ('captaind','watchmand'):
            paths={'host':'/owned/'+service+'.toml','container':'/config/'+service+'.toml'}
            for key,value in {'containers':'owned-'+service,'binary_sha256':'c'*64,'config_sha256':'d'*64,'config_paths':paths}.items():self.expected[key][service]=value
            config={'network':'signet','postgres_database':'finite','fee_estimator':{'max_fee_rate':'20 sat/vb'}}
            if service=='captaind':config.update(lightning_configured=False,vtxopool={'vtxo_targets':[]},vtxo_lifetime=48,round_interval='10m',required_board_confirmations=2,direct_expiry={'enabled':True},expiry_payout={'enabled':False})
            else:config['watchman']={'direct_expiry':{'max_miner_fee':'10000 sat'}}
            self.current['daemons'][service]={'container':'owned-'+service,'image_sha256':'sha256:'+'a'*64,'binary_sha256':'c'*64,
                'config_sha256':'d'*64,'pid':123 if service=='captaind' else 456,'started_at':started,'restart_count':0,'running':True,
                'config_mtime_ns':config_time,'config_ctime_ns':config_time,'config_device':1,'config_inode':2,
                'config_path':paths['host'],'container_config_sha256':'d'*64,'mount_read_only':True,
                'config_mount':{'source':paths['host'],'destination':paths['container'],'read_only':True},
                'process_cmdline':[service,'--config',paths['container'],'start'],'process_exe_sha256':'c'*64,
                'version':service+' '+PRODUCT_COMMIT,'environment_names':['PATH',service.upper()+'_LOG'],
                'config_overrides':{service.upper()+'_LOG':'info'},'public_loaded_config_provenance':config}
        self.original=copy.deepcopy(self.current)
    def tearDown(self):self.tmp.cleanup()
    def verify(self):
        for name,value in [('original',self.original),('current',self.current)]: (self.root/name).write_text(json.dumps(value))
        return verify_owned_startup_sources(self.store,self.root/'original',self.root/'current',expected=self.expected)
    def test_same_live_process_and_immutable_config_yield_scoped_loaded_receipt(self):
        result=self.verify();self.assertTrue(result['loaded_configuration_identity_verified']);self.assertFalse(result['qualified']);self.assertFalse(result['complete'])
        self.assertIsNone(result['effective_fee_ceilings_sat_kvb']['claim']);self.assertEqual(10000,result['direct_carrier_max_miner_fee_sat'])
    def test_real_captaind_environment_prefix_and_lowercase_override_refuse(self):
        for name in ('BARK_SERVER__NETWORK','bark_server__network','WATCHMAND__WATCHMAN__DIRECT_EXPIRY__MAX_MINER_FEE'):
            with self.subTest(name=name):
                self.current=copy.deepcopy(self.original);self.current['daemons']['captaind']['environment_names'].append(name)
                with self.assertRaisesRegex(ValueError,'override'):self.verify()
    def test_changed_process_executable_config_and_mount_refuse(self):
        for key,value in [('pid',999),('process_exe_sha256','e'*64),('config_ctime_ns',time.time_ns()),('config_mount',{})]:
            with self.subTest(key=key):
                self.current=copy.deepcopy(self.original);self.current['daemons']['watchmand'][key]=value
                with self.assertRaises(ValueError):self.verify()
    def test_unsupported_paths_and_nonfinite_policy_refuse(self):
        self.current['daemons']['captaind']['public_loaded_config_provenance']['lightning_configured']=True
        with self.assertRaisesRegex(ValueError,'finite'):self.verify()
    def test_schema_artifacts_remain_distinct_and_unstable_canonical_refuses(self):
        self.current['schema_sha256']='e'*64
        self.current['canonical_schema']={'protocol':'pg-dump-restrict-lines-v1','sha256':'f'*64,
            'repeat_sha256':'f'*64,'removed_line_kinds':['restrict','unrestrict']}
        result=self.verify();self.assertEqual('b'*64,result['schema_sha256'])
        self.assertEqual('e'*64,result['current_schema_artifact_sha256'])
        self.current['canonical_schema']['repeat_sha256']='a'*64
        with self.assertRaisesRegex(ValueError,'unstable'):self.verify()

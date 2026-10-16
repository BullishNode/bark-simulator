"""Real C same-process verifier, synthetic public native config/cert sources."""
import copy
import hashlib
import unittest

from simulator import c_runtime_profile as p
from tests import test_c_pilot as fixture


class FullNormalProfile(unittest.TestCase):
    def setUp(self):
        self.f=fixture.NativeStartupControls();self.f.setUp();self.addCleanup(self.f.tearDown)
        self.expected,self.original,self.current=self.f.frames()
        self.config={'min_board_amount':'1000sat',**{key:'25000sat' for key in p.CAPS},
            'vtxopool':{'vtxo_targets':['20000sat:3'],'vtxo_pre_expiry':6},
            'cln_array':[{'uri':'https://owned.example:9736','priority':0,
                'server_cert_path':'/owned/public/server.pem','client_cert_path':'/owned/public/client.pem',
                'client_key_path':'/NEVER/READ/private.key','hold_invoice':{
                    'uri':'https://owned.example:9737','server_cert_path':'/owned/public/hold-server.pem',
                    'client_cert_path':'/owned/public/hold-client.pem','client_key_path':'/NEVER/READ/hold.key'}}]}
        self.watch={'watchman':{'direct_expiry':{'max_miner_fee':'20000sat',
            'ordinary_fee_policy':{'ordinary_budget_sat':58000,'urgent_reserve_sat':40000}}}}
        self.reads=[]
        self.prior=self.current['daemons']['captaind']['config_ctime_ns']
        def certificate(path,maximum):
            self.reads.append(path)
            if 'private' in path or path.endswith('.key'):raise AssertionError('private key must never be read')
            raw=b'-----BEGIN CERTIFICATE-----\nSYNTHETIC-PUBLIC\n-----END CERTIFICATE-----'
            return raw,{'sha256':hashlib.sha256(raw).hexdigest(),'device':1,'inode':4,'mtime_ns':self.prior,'ctime_ns':self.prior}
        self.certificate=certificate
        cap=p.project(self.config,'captaind',certificate);watch=p.project(self.watch,'watchmand',certificate)
        self.profile={'schema_version':1,'mode':'fullnormal_sources',
            'operating_source_sha256':{'captaind':p.digest(cap),'watchmand':p.digest(watch)},
            'lightning_context_sha256':'a'*64,'ordinary_fee_policy_sha256':'b'*64,
            'node_ids':{'operator':'02'+'a'*64,'fixture_peer':'03'+'b'*64}}
        self.expected['operating_profile']=self.profile
        for frame in (self.original,self.current):
            cfg=frame['daemons']['captaind']['public_loaded_config_provenance']
            cfg.update(lightning_configured=True,vtxopool={'vtxo_targets':['20000sat:3']},operating_source=copy.deepcopy(cap))
            frame['daemons']['watchmand']['public_loaded_config_provenance']['operating_source']=copy.deepcopy(watch)

    def verify(self):return self.f.verify(self.expected,self.original,self.current)

    def test_real_same_process_gate_accepts_declared_actual_sources_only_without_financial_credit(self):
        result=self.verify()
        self.assertTrue(result['loaded_configuration_identity_verified']);self.assertFalse(result['qualified']);self.assertFalse(result['complete'])
        self.assertEqual(self.profile,result['operating_profile'])
        self.assertIsNone(result['effective_fee_ceilings_sat_kvb']['pool'])
        self.assertIsNone(result['effective_fee_ceilings_sat_kvb']['claim'])
        self.assertEqual(4,len(self.reads));self.assertFalse(any('.key' in path for path in self.reads))

    def test_fullmode_is_not_a_boolean_bypass_for_old_empty_pool_or_missing_native_source(self):
        cfg=self.current['daemons']['captaind']['public_loaded_config_provenance']
        cfg['vtxopool']['vtxo_targets']=[]
        with self.assertRaises(ValueError):self.verify()
        cfg['vtxopool']['vtxo_targets']=['20000sat:3'];cfg.pop('operating_source')
        with self.assertRaises(ValueError):self.verify()

    def test_tls_file_changed_after_load_fails_even_if_caller_repins_source_hash(self):
        cfg=self.current['daemons']['captaind']['public_loaded_config_provenance'];source=cfg['operating_source']
        source['lightning_connections'][0]['certificates']['server']['ctime_ns']=self.prior+120*10**9
        self.profile['operating_source_sha256']['captaind']=p.digest(source)
        with self.assertRaisesRegex(ValueError,'after actual native'):self.verify()

    def test_original_direct_allowance_reserve_cannot_be_redeclared_for_fullmode(self):
        cfg=self.current['daemons']['watchmand']['public_loaded_config_provenance'];source=cfg['operating_source']
        source['ordinary_fee_policy']['ordinary_budget_sat']=60000
        self.profile['operating_source_sha256']['watchmand']=p.digest(source)
        with self.assertRaisesRegex(ValueError,'immutable allowance'):self.verify()

    def test_wrong_node_context_or_missing_required_amount_caps_hold(self):
        self.profile['node_ids']['fixture_peer']=self.profile['node_ids']['operator']
        with self.assertRaises(ValueError):self.verify()
        del self.config['max_ln_receive_amount']
        with self.assertRaises(KeyError):p.project(self.config,'captaind',self.certificate)

    def test_private_key_certificate_or_plaintext_endpoint_is_rejected_before_projection(self):
        self.config['cln_array'][0]['uri']='http://owned.example:9736'
        with self.assertRaisesRegex(ValueError,'HTTPS mutual TLS'):p.project(self.config,'captaind',self.certificate)
        self.config['cln_array'][0]['uri']='https://owned.example:9736'
        def private(path,maximum):
            raw=b'-----BEGIN PRIVATE KEY-----'
            return raw,{'sha256':hashlib.sha256(raw).hexdigest()}
        with self.assertRaisesRegex(ValueError,'public TLS certificate'):p.project(self.config,'captaind',private)

    def test_pilot_default_remains_ln_off_pool_empty_and_process_guards_apply_fullmode(self):
        self.expected.pop('operating_profile')
        with self.assertRaisesRegex(ValueError,'pilot keeps LN off'):self.verify()
        self.expected['operating_profile']=self.profile
        self.current['daemons']['watchmand']['start_ticks']+=1
        with self.assertRaisesRegex(ValueError,'same native daemon process'):self.verify()

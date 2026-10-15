"""Synthetic Core/trace controls only; no live scan, readiness or latency credit."""
import copy
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from simulator import confirmed_scan as scans
from simulator.engine import initialize
from simulator.model import SIGNET_GENESIS,canonical
from simulator.store import Store
from tests.test_final_campaign import PINS


class ConfirmedScanControls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name),'synthetic',100000);initialize(self.store);self.store.attach_trace()
        self.config=SimpleNamespace(network='signet',expected_genesis=SIGNET_GENESIS)
        self.members=[{'id':'bank','identity':'named-bank','kind':'wallet','role':'operator','descriptors':['public-bank']}]
        self.specs={'public-bank':[0,21]};self.context={'owners':copy.deepcopy(self.members),'actual_image':'image-1','sdk':'sdk-1','driver':'driver-1','epoch':None}
        self.tip=(100,'a'*64);self.rows=[{'txid':'b'*64,'vout':0,'amount':'0.00001000','scriptPubKey':'public-bank:0'}]
        self.calls=[];self.active_scan=None;outer=self
        class Core:
            def call(self,method,*args,**kwargs):
                outer.calls.append((method,args))
                if method=='getblockhash':return SIGNET_GENESIS
                if method=='getblockchaininfo':return {'chain':'signet','initialblockdownload':False,'blocks':outer.tip[0],'bestblockhash':outer.tip[1]}
                if method=='getdescriptorinfo':return {'descriptor':args[0],'hasprivatekeys':False,'isrange':True}
                if method=='deriveaddresses':return [args[0]+':'+str(index) for index in range(args[1][0],args[1][1]+1)]
                if method=='validateaddress':return {'isvalid':True,'scriptPubKey':args[0]}
                if method=='scantxoutset':
                    if args[0]=='status':return outer.active_scan
                    result={'success':True,'height':outer.tip[0],'bestblock':outer.tip[1],'unspents':copy.deepcopy(outer.rows),
                        'total_amount':str(sum(__import__('decimal').Decimal(coin['amount']) for coin in outer.rows))}
                    self.last_capture=outer.store.trace_sample({'kind':'chain.rpc','payload':{'method':method,'params':list(args),'result':result,'error':None},
                        'raw':canonical({'result':result,'error':None}).encode()})
                    return result
                raise AssertionError(method)
        self.chain=Core()
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def scan(self):
        with patch.object(scans,'_identity',return_value=copy.deepcopy(self.context)):
            return scans.confirmed_scan(self.store,self.config,self.chain,{},pins=PINS,boundary_id='finite',members=self.members,specs=self.specs,tip=self.tip)
    def scans(self):return sum(method=='scantxoutset' and args[0]=='start' for method,args in self.calls)
    def test_identical_tip_reuses_original_complete_rows_provenance_and_fresh_derivation(self):
        first=self.scan();original=json.loads(self.store.db.execute("SELECT payload FROM event WHERE kind=?",(scans.KIND,)).fetchone()[0])
        calls=len(self.calls);second=self.scan()
        self.assertEqual(1,self.scans());self.assertFalse(first[3]['reused']);self.assertTrue(second[3]['reused'])
        self.assertEqual(first[:3],second[:3]);self.assertEqual(first[3]['original_scan_sequence'],second[3]['original_scan_sequence'])
        self.assertEqual(first[3]['original_scan_observed_at'],second[3]['original_scan_observed_at'])
        self.assertTrue(any(method=='deriveaddresses' for method,args in self.calls[calls:]))
        self.assertEqual(original,json.loads(self.store.db.execute("SELECT payload FROM event WHERE kind=?",(scans.KIND,)).fetchone()[0]))
        self.assertEqual(1,self.store.db.execute('SELECT count(*) FROM event WHERE kind=?',(scans.KIND,)).fetchone()[0])
    def test_retained_superset_derives_all_scripts_and_never_filters_unknown_rows(self):
        self.rows.append({'txid':'c'*64,'vout':1,'amount':'0.00002000','scriptPubKey':'public-bank:21'})
        first=self.scan();self.specs={'public-bank':[0,19]};second=self.scan()
        self.assertTrue(second[3]['reused']);self.assertEqual(22,len(second[0]));self.assertEqual(first[2],second[2])
        self.assertEqual(2,len(second[2]['unspents']));self.assertIn('public-bank:21',second[0]);self.assertEqual(1,self.scans())
    def test_new_height_same_height_other_hash_or_new_script_outside_coverage_force_full_scan(self):
        self.scan();self.tip=(101,'c'*64);self.scan();self.assertEqual(2,self.scans())
        self.tip=(101,'d'*64);self.scan();self.assertEqual(3,self.scans())
        self.specs={'public-bank':[0,22]};self.rows.append({'txid':'e'*64,'vout':0,'amount':'0.00003000','scriptPubKey':'public-bank:22'})
        result=self.scan();self.assertEqual(4,self.scans());self.assertFalse(result[3]['reused']);self.assertEqual(2,len(result[2]['unspents']))
    def test_current_image_sdk_driver_boundary_and_active_epoch_invalidate(self):
        self.scan()
        for key,value in (('actual_image','image-2'),('sdk','sdk-2'),('driver','driver-2'),('epoch','qualified-epoch'),('boundary','other-boundary')):
            before=self.scans();self.context[key]=value;result=self.scan();self.assertFalse(result[3]['reused']);self.assertEqual(before+1,self.scans())
    def test_partial_or_damaged_immutable_receipt_refuses_no_blind_rescan(self):
        self.scan();row=self.store.db.execute('SELECT * FROM event WHERE kind=?',(scans.KIND,)).fetchone();value=json.loads(row['payload']);value['complete']=False
        self.store.event(scans.KIND,value);sequence=self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
        self.store.db.execute('UPDATE meta SET value=? WHERE key=?',(str(sequence),scans.KEY))
        with self.assertRaisesRegex(ValueError,'incomplete'):self.scan()
        self.assertEqual(1,self.scans())
    def test_missing_raw_trace_or_changed_result_refuses_even_at_new_tip(self):
        self.scan();self.store.trace.close()
        reference=json.loads(self.store.db.execute('SELECT payload FROM event WHERE kind=?',(scans.KIND,)).fetchone()[0])['raw_trace']
        (self.store.root/reference['partition']).rename(self.store.root/'preserved-missing-trace.sqlite')
        self.tip=(101,'f'*64)
        with self.assertRaisesRegex(ValueError,'trace unavailable'):self.scan()
        self.assertEqual(1,self.scans())
    def test_unknown_output_duplicate_point_partial_scan_and_oversize_ranges_refuse(self):
        self.rows.append({'txid':'e'*64,'vout':0,'amount':'0.00002000','scriptPubKey':'foreign-script'})
        with self.assertRaisesRegex(ValueError,'unowned output'):self.scan()
        self.rows=[self.rows[0],copy.deepcopy(self.rows[0])]
        with self.assertRaisesRegex(ValueError,'duplicate'):self.scan()
        self.specs={'public-bank':[0,2000]}
        with self.assertRaisesRegex(ValueError,'bounded descriptor'):self.scan()
        self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM event WHERE kind=?',(scans.KIND,)).fetchone()[0])
    def test_removed_pointer_cannot_silently_drop_retained_scan_history(self):
        self.scan();self.store.db.execute('DELETE FROM meta WHERE key=?',(scans.KEY,))
        with self.assertRaisesRegex(ValueError,'pointer missing'):self.scan()
        self.assertEqual(1,self.scans())
    def test_changed_event_hash_or_raw_trace_refuses_without_reconstruction(self):
        self.scan();sequence=int(self.store.get_meta(scans.KEY))
        self.store.db.execute("UPDATE event SET payload='{}' WHERE sequence=?",(sequence,))
        with self.assertRaisesRegex(ValueError,'event frame changed'):self.scan()
        self.assertEqual(1,self.scans())
    def test_changed_original_raw_bytes_refuse_without_new_scan(self):
        import sqlite3
        result=self.scan();reference=result[3]['raw_trace'];self.store.trace.close()
        conn=sqlite3.connect(self.store.root/reference['partition']);conn.execute('DROP TRIGGER trace_no_update')
        conn.execute('UPDATE trace SET raw=? WHERE seq=?',(b'{"result":null,"error":null}',reference['seq']));conn.commit();conn.close()
        with self.assertRaisesRegex(ValueError,'trace changed'):self.scan()
        self.assertEqual(1,self.scans())
    def test_busy_core_scan_holds_without_abort_or_start(self):
        self.active_scan={'progress':10}
        with self.assertRaisesRegex(ValueError,'scan running'):self.scan()
        self.assertEqual(0,self.scans());self.assertFalse(any(args and args[0]=='abort' for method,args in self.calls))


class ScanIdentityControls(unittest.TestCase):
    def setUp(self):
        from tests.test_identity_bootstrap import IdentityBootstrapTests
        self.fixture=IdentityBootstrapTests();self.fixture.setUp();self.fixture.declare()
        self.fixture.config=__import__('dataclasses').replace(self.fixture.config,proof_command=('proof','http://127.0.0.1:38332','credential'))
        self.chain=SimpleNamespace(url=self.fixture.config.proof_command[1],expected=SIGNET_GENESIS)
        self.current={'kind':'owned_startup_source','product_commit':self.fixture.pins['product_commit'],'daemons':{}}
        for service in ('captaind','watchmand'):
            self.current['daemons'][service]={'container':'actual-'+service,'image_sha256':self.fixture.config.expected_image,
                'running':True,'pid':123 if service=='captaind' else 124,'started_at':'2026-10-15T10:00:00Z',
                'process_exe_sha256':'6'*64,'binary_sha256':'6'*64,'config_sha256':'7'*64}
        self.members=[{'id':'bank','identity':'bank-owned','kind':'wallet','role':'operator','descriptors':['public-bank']}]
    def tearDown(self):self.fixture.tearDown()
    def context(self):
        return scans._identity(self.fixture.store,self.fixture.config,self.chain,self.current,pins=self.fixture.pins,boundary_id='finite',members=self.members)
    def test_actual_files_sdk_image_binary_and_current_product_are_bound(self):
        first=self.context();self.assertEqual(self.fixture.digest(self.fixture.driver),first['native']['driver_sha256'])
        self.assertEqual(self.fixture.config.expected_image,first['daemons']['captaind']['image_sha256'])
        self.current['product_commit']='8'*40;self.assertNotEqual(first,self.context())
        self.fixture.driver.write_bytes(b'changed-native-source')
        with self.assertRaisesRegex(ValueError,'driver differs'):self.context()
    def test_optional_qualified_epoch_is_bound_even_with_unchanged_origin_pins(self):
        manifest={'deployment_epoch_id':'qualified-epoch-1','execution_release':{'product_commit':self.current['product_commit']}}
        with patch('simulator.target_epochs.active_runtime_manifest',return_value=manifest,create=True):
            first=self.context();manifest['deployment_epoch_id']='qualified-epoch-2';second=self.context()
            self.assertNotEqual(first,second);self.assertEqual(first['financial_pins'],second['financial_pins'])
            manifest['execution_release']['product_commit']='f'*40
            with self.assertRaisesRegex(ValueError,'execution release'):self.context()
    def test_actual_image_mismatch_and_unverified_core_endpoint_refuse(self):
        self.current['daemons']['captaind']['image_sha256']='sha256:'+'f'*64
        with self.assertRaisesRegex(ValueError,'image identity differs'):self.context()
        self.current['daemons']['captaind']['image_sha256']=self.fixture.config.expected_image;self.chain.url='http://127.0.0.1:1'
        with self.assertRaisesRegex(ValueError,'endpoint/genesis'):self.context()


class CachedCashSourceControls(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        from tests.test_fresh_cash_readiness import CashSourceControls
        self.fixture=CashSourceControls();self.fixture.setUp();self.f=self.fixture;self.calls=[]
        original=self.f.chain.call
        def tracked(method,*args,**kwargs):
            self.calls.append((method,args));return original(method,*args,**kwargs)
        self.f.chain.call=tracked
    def tearDown(self):self.f.tearDown()
    def starts(self):return sum(method=='scantxoutset' and args[0]=='start' for method,args in self.calls)
    async def collect(self):
        from simulator.fresh_cash_readiness import collect_fresh_cash_sources
        return await collect_fresh_cash_sources(self.f.store,self.f.config,self.f.chain,None,current_startup_path='/synthetic-only')
    async def test_reuse_still_rechecks_all_known_utxos_mempool_bank_native_and_server(self):
        from simulator import funding_bank,process,fresh_cash_readiness
        with self.f.dependencies():
            first=await self.collect();second=await self.collect()
            import sys
            self.assertEqual(2,sys.modules['simulator.funding_bank'].collect_funding_bank_source.call_count)
            self.assertEqual(2,sys.modules['simulator.process'].json_command.call_count)
            self.assertEqual(2,sys.modules['simulator.fresh_cash_readiness'].observe_empty_client_economics.call_count)
        self.assertEqual(1,self.starts());self.assertTrue(second['source']['confirmed_scan']['reused'])
        self.assertEqual(12,sum(method=='gettxout' for method,args in self.calls));self.assertEqual(4,sum(method=='getrawmempool' for method,args in self.calls))
        self.assertGreaterEqual(second['source']['observed_at'],first['source']['observed_at'])
    async def test_cached_confirmed_coin_pending_spent_is_still_refused(self):
        with self.f.dependencies():await self.collect()
        original=self.f.chain.call
        def pending(method,*args,**kwargs):
            if method=='gettxout' and args[0]==self.f.txid and args[1]==2:
                self.assertIs(args[2],True);return None
            return original(method,*args,**kwargs)
        self.f.chain.call=pending
        with self.f.dependencies(),self.assertRaisesRegex(ValueError,'unavailable or pending-spent'):await self.collect()
        self.assertEqual(1,self.starts())
    async def test_new_owned_mempool_output_is_not_hidden_by_same_tip_reuse(self):
        with self.f.dependencies():await self.collect()
        original=self.f.chain.call
        def arrival(method,*args,**kwargs):
            if method=='getrawmempool':return ['9'*64]
            return original(method,*args,**kwargs)
        self.f.chain.call=arrival;self.f.chain.tx=lambda txid:{'vout':[{'scriptPubKey':{'hex':'actor-02:0'}}]}
        with self.f.dependencies(),self.assertRaisesRegex(ValueError,'unconfirmed output'):await self.collect()
        self.assertEqual(1,self.starts())
    async def test_changed_server_or_native_database_refuses_despite_scan_reuse(self):
        with self.f.dependencies():await self.collect()
        self.f.db['rows']['coins']=1
        with self.f.dependencies(),self.assertRaisesRegex(ValueError,'frontier'):await self.collect()
        self.f.db['rows']['coins']=0
        with self.f.dependencies(),patch('simulator.fresh_cash_readiness.observe_empty_client_economics',side_effect=ValueError('actual native checkpoint')),self.assertRaisesRegex(ValueError,'native checkpoint'):
            await self.collect()
        self.assertEqual(1,self.starts())
        self.assertEqual(1,self.f.store.db.execute("SELECT count(*) FROM event WHERE kind='finite_fresh_cash_sources_verified'").fetchone()[0])
    async def test_unknown_confirmed_owned_coin_is_retained_and_refused_on_every_attempt(self):
        original=self.f.chain.call
        def extra(method,*args,**kwargs):
            if method=='scantxoutset' and args[0]=='start':
                self.calls.append((method,args))
                rows=[{'txid':self.f.txid,'vout':row['vout'],'amount':str(__import__('decimal').Decimal(row['amount_sat'])/100000000),
                    'scriptPubKey':row['script']} for row in self.f.transaction['outputs']]
                rows.append({'txid':'9'*64,'vout':0,'amount':'0.00000001','scriptPubKey':'actor-02:10'})
                return self.f.capture_scan({'success':True,'height':100,'bestblock':self.f.tip,'unspents':rows,'total_amount':'0.00664455'},args[1])
            return original(method,*args,**kwargs)
        self.f.chain.call=extra
        for _ in range(2):
            with self.f.dependencies(),self.assertRaisesRegex(ValueError,'extra or changed capital'):await self.collect()
        self.assertEqual(1,self.starts())
        self.assertEqual(0,self.f.store.db.execute("SELECT count(*) FROM event WHERE kind='finite_fresh_cash_sources_verified'").fetchone()[0])
    async def test_new_own_script_outside_retained_coverage_forces_real_scan_and_detects_asset(self):
        with self.f.dependencies():await self.collect()
        original=self.f.chain.call
        def growth(method,*args,**kwargs):
            if method=='scantxoutset' and args[0]=='start':
                self.calls.append((method,args))
                rows=[{'txid':self.f.txid,'vout':row['vout'],'amount':str(__import__('decimal').Decimal(row['amount_sat'])/100000000),
                    'scriptPubKey':row['script']} for row in self.f.transaction['outputs']]
                rows.append({'txid':'8'*64,'vout':0,'amount':'0.00000001','scriptPubKey':'rounds:22'})
                return self.f.capture_scan({'success':True,'height':100,'bestblock':self.f.tip,'unspents':rows,'total_amount':'0.00664455'},args[1])
            return original(method,*args,**kwargs)
        self.f.chain.call=growth
        with self.f.dependencies(frontier=2),self.assertRaisesRegex(ValueError,'extra or changed capital'):await self.collect()
        self.assertEqual(2,self.starts())

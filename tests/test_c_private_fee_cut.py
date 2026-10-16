"""Real private filesystem/tar and frozen public protocol; synthetic PG only."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

from simulator import c_private_fee_cut as c
from simulator.model import SIGNET_GENESIS,canonical
from tests import test_c_native_fee_sources as fee_fixtures

PACKET=Path(__file__).with_name('fixtures')/'track_c_frontier_v2'


def adapter():
    manifest=json.loads((PACKET/'manifest.json').read_text())
    for name,sha in manifest['files'].items():
        if hashlib.sha256((PACKET/name).read_bytes()).hexdigest()!=sha:raise ValueError('frozen protocol fixture changed')
    spec=importlib.util.spec_from_file_location('C_fee_fixed_adapter',PACKET/'dbapi_adapter.py')
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


class RawPG:
    """Named-cursor API double, with one actual ordered transaction journal."""
    autocommit=True
    def __init__(self,f,rows,private,on_private=None):
        self.f,self.rows,self.private,self.on_private=f,rows,private,on_private
        self.executed=[];self.active=False;self.rollbacks=0;self.private_calls=0;self.preflight_override=None
        self.identity={'snapshot':private['snapshot'],'backend_pid':123,'database':'trackc','observed_at':'2026-10-16 06:45:00+00','read_only':'on','isolation':'repeatable read'}
    def cursor(self,name=None,**kwargs):
        outer=self
        class Cursor:
            def __init__(self):self.answer=[];self.offset=0;self.table=None
            def __enter__(self):return self
            def __exit__(self,*args):self.close()
            def execute(self,sql):
                outer.executed.append(sql)
                if sql.startswith('BEGIN '):
                    if outer.active:raise AssertionError('second transaction')
                    outer.active=True
                elif sql=='ROLLBACK':outer.active=False
                elif sql==c.PREFLIGHT_SQL:
                    assert outer.active
                    self.answer=[(outer.preflight_override or {'allocations':len(outer.private['allocations']),'carriers':len(outer.private['carriers']),'mappings':sum(len(json.loads(v['witness'])['mappings'])for v in outer.private['carriers']),'bytes':len(canonical(outer.private).encode())},)]
                elif sql==c.PRIVATE_SQL:
                    assert outer.active;outer.private_calls+=1
                    if outer.on_private:outer.on_private()
                    self.answer=[(copy.deepcopy(outer.private),)]
                elif sql==outer.f.IDENTITY_SQL:self.answer=[(dict(outer.identity),)]
                elif sql.startswith('SELECT jsonb_build_object('):self.answer=[({k:len(v)for k,v in outer.rows.items()},)]
                elif name:
                    for table,spec in outer.f.projections().items():
                        expected='SELECT row_to_json(q) FROM (SELECT %s FROM %s ORDER BY %s) q'%(spec['columns'],spec['table'],spec['order_by'])
                        if sql==expected:self.table=table;break
                    if self.table is None:raise AssertionError('unexpected named query')
                elif not sql.startswith('SET LOCAL '):raise AssertionError('unexpected SQL')
            def fetchone(self):return self.answer.pop(0)if self.answer else None
            def fetchmany(self,n):
                rows=outer.rows[self.table][self.offset:self.offset+n];self.offset+=len(rows);return [(copy.deepcopy(v),)for v in rows]
            def close(self):pass
        return Cursor()
    def rollback(self):self.active=False;self.rollbacks+=1


class PrivateFeeCapture(unittest.TestCase):
    def setUp(self):
        self.fixture=fee_fixtures.CNativeFeeSources();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.history=self.root/'history';self.history.mkdir(mode=0o700)
        self.expected=c._history_identity(self.history.stat());self.fixed=adapter();self.f=self.fixed.frontier()
        self.binding={'observer_sha256':'1'*64,'schema_sha256':'2'*64,'deployment_sha256':'3'*64,'genesis':SIGNET_GENESIS,'server_pubkey':'02'+'5'*64,'network':'signet','database':'trackc'}
        self.limits={'max_total_rows':6000,'max_total_bytes':8*1024*1024,'max_page_rows':127,'max_page_bytes':256*1024,'max_pages':100,'deadline_ms':20000,'statement_timeout_ms':4000}
        self.observation={'id':'a'*32,'architecture_profile':'direct_per_key','started_at':time.time(),'financial_pins':self.fixture.body['financial_pins']if hasattr(self.fixture,'body')else __import__('tests.test_final_campaign',fromlist=['PINS']).PINS,'height':100,'tip_hash':'b'*64}
        self.chain={'genesis':SIGNET_GENESIS,'height':100,'tip_hash':'b'*64,'ibd':False}
        self.write('identity.json',bytes.fromhex(self.fixture.cut['identity_hex']));self.write('ordinary-fee-policy.json',self.fixture.policy)
        self.write('ordinary-fee-budget',b'');self.write('history',b'')
    def write(self,name,raw):
        p=self.history/name;p.write_bytes(raw);p.chmod(0o600)
    def read(self):
        fd=os.open(self.history,os.O_RDONLY|os.O_DIRECTORY)
        try:return c._history(fd,self.expected)
        finally:os.close(fd)
    def pg(self,charged=False):
        rows={name:[]for name in self.f.projections()};pg={'snapshot':'synthetic-fixed-RR','database':'trackc','role':'trackcfeeobserver','read_only':'on','isolation':'repeatable read','allocations':[],'carriers':[]}
        if charged:
            x=self.fixture;self.write('ordinary-fee-budget',b'20000\n');self.write('history',(x.txid+'\n').encode());self.write(x.txid+'.json',bytes.fromhex(x.cut['records'][x.txid]))
            for name,items in x.database['rows'].items():rows[name]=copy.deepcopy(items)
            rows['journal_carriers'][0]['created_at']='synthetic'
            pg['allocations']=[{'freeze_set':'synthetic-freeze','id':x.pid+':0','witness':x.cut['allocation_witnesses']['synthetic-freeze'][0]}]
            pg['carriers']=[{'txid':x.txid,'signed_tx_hex':x.raw.hex(),'witness':x.cut['carrier_witnesses'][x.txid]}]
        return RawPG(self.f,rows,pg)
    def capture(self,raw):
        def opened(expected):
            self.assertEqual(expected,self.expected);return os.open(self.history,os.O_RDONLY|os.O_DIRECTORY)
        with patch.object(c,'_open_history',side_effect=opened):
            return c.capture(raw,self.fixed,limits=self.limits,binding=self.binding,expected_history_identity=self.expected,observation=self.observation,expected_financial_pins=__import__('tests.test_final_campaign',fromlist=['PINS']).PINS,chain_identity=lambda:dict(self.chain))
    def test_zero_actual_files_and_all19_frozen_protocol_tables_same_one_transaction(self):
        raw=self.pg();value=self.capture(raw);cut=json.loads(value['private_cut'])
        self.assertEqual('',cut['budget_hex']);self.assertEqual({},cut['records']);self.assertEqual(1,raw.private_calls)
        self.assertEqual(1,sum(sql.startswith('BEGIN ')for sql in raw.executed));self.assertGreater(raw.executed.index(c.PRIVATE_SQL),raw.executed.index(self.f.IDENTITY_SQL))
        database=self.f.consume(value['public_lines'],self.limits,self.binding,lambda:0)
        self.assertEqual(19,len(database['rows']));self.assertTrue(all(not v for v in database['rows'].values()));self.assertFalse(database['complete']);self.assertFalse(database['qualified'])
        self.assertEqual(database['snapshot'],cut['database_snapshot']);self.assertFalse(raw.active);self.assertGreaterEqual(raw.rollbacks,1)
    def test_real_charged_files_match_private_PG_signed_originals_and_public_protocol(self):
        raw=self.pg(True);value=self.capture(raw);cut=json.loads(value['private_cut'])
        self.assertEqual(b'20000\n',bytes.fromhex(cut['budget_hex']));self.assertEqual({self.fixture.txid},set(cut['records']))
        database=self.f.consume(value['public_lines'],self.limits,self.binding,lambda:0)
        self.assertEqual(self.fixture.txid,database['rows']['journal_carriers'][0]['txid'])
        self.assertNotIn(b'"evidence"',b''.join(value['public_lines']))
    def test_private_PG_signature_substitution_and_snapshot_mismatch_hold(self):
        raw=self.pg(True);raw.private['carriers'][0]['signed_tx_hex']='00'
        with self.assertRaisesRegex(ValueError,'signed bytes'):self.capture(raw)
        raw=self.pg(True);raw.private['snapshot']='different'
        with self.assertRaisesRegex(ValueError,'snapshots'):self.capture(raw)
    def test_wrong_actual_PG_role_never_becomes_private_package(self):
        raw=self.pg();raw.private['role']='trackcserver'
        with self.assertRaisesRegex(ValueError,'same-RR'):self.capture(raw)
        self.assertFalse(raw.active)
    def test_signing_budget_change_during_transaction_holds_all_public_output(self):
        raw=self.pg();raw.on_private=lambda:self.write('ordinary-fee-budget',b'20000\n')
        with self.assertRaisesRegex(ValueError,'history changed'):self.capture(raw)
        self.assertFalse(raw.active)
    def test_preflight_refuses_private_read_before_unbounded_or_unknown_rows(self):
        for value in ({'allocations':0,'carriers':0,'mappings':0,'bytes':c.MAX_ORIGINAL_BYTES+1},{'allocations':10001,'carriers':0,'mappings':0,'bytes':1}):
            raw=self.pg();raw.preflight_override=value
            with self.assertRaisesRegex(ValueError,'preflight'):self.capture(raw)
            self.assertEqual(0,raw.private_calls);self.assertFalse(raw.active)
    def test_missing_unrelated_temporary_symlink_and_loose_files_refuse_before_copy(self):
        original=self.history/'history';raw=original.read_bytes();original.unlink()
        with self.assertRaises(ValueError):self.read()
        self.write('history',raw)
        for name in ('hsm_secret','.pending.tmp','regtest-qualification-declaration.json'):
            p=self.history/name;p.write_bytes(b'not-read')
            with self.subTest(name=name),self.assertRaises(ValueError):self.read()
            p.unlink()
        target=self.root/'outside';target.write_bytes(b'not-read');link=self.history/('e'*64+'.json');link.symlink_to(target)
        with self.assertRaises(OSError):self.read()
        link.unlink();(self.history/'history').chmod(0o644)
        with self.assertRaises(ValueError):self.read()
    def test_observation_pins_and_independent_chain_tip_refuse_before_PG(self):
        raw=self.pg();self.observation['financial_pins']={**self.observation['financial_pins'],'product_commit':'f'*40}
        with self.assertRaises(ValueError):self.capture(raw)
        self.assertEqual([],raw.executed)
        self.observation['financial_pins']=__import__('tests.test_final_campaign',fromlist=['PINS']).PINS
        self.chain['tip_hash']='c'*64
        with self.assertRaises(ValueError):self.capture(raw)
        self.assertEqual([],raw.executed)
    def test_captured_original_reduces_actual_wire_cost_and_repeated_import_once(self):
        value=self.capture(self.pg(True));x=self.fixture
        x.cut=json.loads(value['private_cut']);x.root=self.expected
        database=self.f.consume(value['public_lines'],self.limits,self.binding,lambda:0)
        x.database={**database,'architecture_profile':'direct_per_key','fallback_protocol':4,'declared_financial_pins':self.observation['financial_pins']}
        reduced=x.collect();self.assertEqual(20000,reduced['native_fee']['ordinary_booked_sat'])
        self.assertEqual(100,reduced['native_fee']['ordinary_confirmed_cost_sat']);self.assertEqual(19900,reduced['native_fee']['ordinary_held_sat'])
        x.join(reduced);again=x.collect();self.assertEqual([],again['cost_records']);x.join(again)
        self.assertEqual(1,x.store.db.execute("SELECT count(*)FROM event WHERE kind='financial_cost_verified'").fetchone()[0])
    def test_charged_without_retained_record_is_unknown_held_not_zero_cost_liquidity(self):
        self.write('ordinary-fee-budget',b'20000\n');value=self.capture(self.pg());x=self.fixture
        x.cut=json.loads(value['private_cut']);x.root=self.expected
        database=self.f.consume(value['public_lines'],self.limits,self.binding,lambda:0)
        x.database={**database,'architecture_profile':'direct_per_key','fallback_protocol':4,'declared_financial_pins':self.observation['financial_pins']}
        reduced=x.collect();self.assertEqual([],reduced['cost_records'])
        self.assertEqual(20000,reduced['native_fee']['ordinary_held_sat']);self.assertEqual(38000,reduced['native_fee']['ordinary_remaining_sat'])
    def test_captured_signed_unconfirmed_keeps_whole_reservation_held(self):
        value=self.capture(self.pg(True));x=self.fixture;x.cut=json.loads(value['private_cut']);x.root=self.expected
        database=self.f.consume(value['public_lines'],self.limits,self.binding,lambda:0)
        x.database={**database,'architecture_profile':'direct_per_key','fallback_protocol':4,'declared_financial_pins':self.observation['financial_pins']}
        x.chain.values[x.txid]['confirmations']=0;reduced=x.collect()
        self.assertEqual([],reduced['cost_records']);self.assertEqual(20000,reduced['native_fee']['ordinary_held_sat'])
    def test_exclusive0600_tar_has_only_fixed_originals_and_hash_manifest(self):
        value=self.capture(self.pg());out=self.root/'cut.tar';safe=c.write_private_package(value,out)
        self.assertEqual(0o600,out.stat().st_mode&0o777);self.assertEqual(hashlib.sha256(out.read_bytes()).hexdigest(),safe['sha256'])
        with tarfile.open(out,'r:')as archive:
            files={item.name:archive.extractfile(item).read()for item in archive};self.assertEqual(set(files),{'cut.json','private-pg.json','public-frontier.ndjson','manifest.json',*{'history/'+n for n in c.POLICY_NAMES}})
            manifest=json.loads(files.pop('manifest.json'));self.assertEqual(set(files),set(manifest['files']))
            for name,raw in files.items():self.assertEqual(hashlib.sha256(raw).hexdigest(),manifest['files'][name]['sha256'])
        with self.assertRaises(FileExistsError):c.write_private_package(value,out)
        value['history']['../outside']=b'not-read'
        with self.assertRaises(ValueError):c.write_private_package(value,self.root/'wrong.tar')

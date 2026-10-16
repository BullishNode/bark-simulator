"""Actual frozen public19 stream/one-RR ordering, synthetic native PG replies.

Body bytes are explicitly synthetic; these controls grant no native path or
current-economic-owner credit. Full decoder qualification is separate.
"""
import copy
import unittest
from unittest.mock import patch
from simulator import c_private_native_body_cut as c
from tests import test_c_private_fee_cut as fixtures


class BodyPG(fixtures.RawPG):
    def __init__(self,f,rows,private):
        super().__init__(f,copy.deepcopy(rows),copy.deepcopy(private));self.body_calls=0
        self.size={'role':c.ROLE,'database':'trackc','read_only':'on','isolation':'repeatable read',
          'pool_retirements':len(private['pool_retirements']),'pool_retirements_bytes':0}
        for name in c.SOURCES:
            values=private[name]
            self.size.update({name:len(values),name+'_bytes':sum(len(v['body_hex'])+512 for v in values),
              name+'_max':max([len(v['body_hex'])//2 for v in values]or[0]),name+'_null':0})
    def cursor(self,name=None,**kwargs):
        base=super().cursor(name,**kwargs);outer=self
        class Cursor:
            def __init__(self):self.answer=None
            def __enter__(self):return self
            def __exit__(self,*args):base.close()
            def execute(self,sql):
                if sql in (c.PREFLIGHT_SQL,c.PRIVATE_SQL):
                    outer.executed.append(sql)
                    if not outer.active:raise AssertionError('private read outside public RR')
                    if sql==c.PRIVATE_SQL:outer.body_calls+=1
                    self.answer=[(copy.deepcopy(outer.size if sql==c.PREFLIGHT_SQL else outer.private),)]
                else:base.execute(sql);self.answer=None
            def fetchone(self):return self.answer.pop(0)if self.answer else base.fetchone()
            def fetchmany(self,n):return base.fetchmany(n)
            def close(self):base.close()
        return Cursor()


class PrivateNativeBodyCut(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.PrivateFeeCapture();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.f=self.fixture.f;self.rows={name:[]for name in self.f.projections()}
        self.pg={'snapshot':'synthetic-fixed-RR','backend_pid':123,'database':'trackc','role':c.ROLE,
          'read_only':'on','isolation':'repeatable read','coins':[],'pending_boards':[],'pool':[],'pool_retirements':[]}
    def populated(self):
        for n in (1,2):
            metadata={k:None for k in self.f.projections()['coins']['fields']}
            metadata.update(vtxo_id=str(n)*64+':0',amount=1000,expiry=200,spend_state='spent'if n==1 else'pool',policy_type='pubkey',policy='00'+'02'+'a'*64)
            self.rows['coins'].append(metadata)
            self.pg['coins'].append({'metadata':copy.deepcopy(metadata),'source_encoding':'ServerVtxoFull','body_hex':'00aa'})
        p={'vtxo_id':'3'*64+':0','expiry':200};self.rows['pending_boards']=[p]
        self.pg['pending_boards']=[{'metadata':copy.deepcopy(p),'anchor_point':'4'*64+':0','source_encoding':'VtxoFull','body_hex':'00bb'}]
        p={'id':1,'vtxo_id':'1'*64+':0','expiry_height':200,'amount':1000};self.rows['pool']=[p]
        self.pg['pool']=[{'metadata':copy.deepcopy(p),'spent_at':'synthetic-spent','source_encoding':'VtxoFull','body_hex':'00cc'}]
        self.pg['pool_retirements']=[{'vtxo_id':'2'*64+':0','pool_input_id':'1'*64+':0'}]
    def capture(self,raw=None,chain=None):
        x=self.fixture
        return c.capture(raw or BodyPG(self.f,self.rows,self.pg),x.fixed,limits=x.limits,binding=x.binding,
          observation=x.observation,expected_financial_pins=x.observation['financial_pins'],chain_identity=chain or(lambda:dict(x.chain)))
    def test_empty_and_nonempty_all_sources_one_real_protocol_transaction(self):
        for populated in (False,True):
            if populated:self.populated()
            raw=BodyPG(self.f,self.rows,self.pg);value=self.capture(raw)
            self.assertEqual(1,raw.body_calls);self.assertEqual(1,sum(s.startswith('BEGIN ')for s in raw.executed))
            self.assertLess(raw.executed.index(c.PREFLIGHT_SQL),raw.executed.index(c.PRIVATE_SQL));self.assertFalse(raw.active)
            self.assertEqual(1,raw.rollbacks)
            database=self.f.consume(value['public_lines'],self.fixture.limits,self.fixture.binding,lambda:0)
            self.assertEqual(self.rows,database['rows']);self.assertFalse(database['complete']);self.assertFalse(database['qualified'])
            self.assertNotIn(b'body_hex',b''.join(value['public_lines']))
    def test_exact_closed19_keeps_spent_and_unspent_pool_and_retirement(self):
        self.populated()
        # Authenticated closed=True model deliberately has NO active-only filter.
        self.assertEqual('vtxo_pool',self.f.projections()['pool']['table'])
        public={'id':2,'vtxo_id':'2'*64+':0','expiry_height':200,'amount':1000}
        self.rows['pool'].append(public)
        self.pg['pool'].append({'metadata':copy.deepcopy(public),'spent_at':None,'source_encoding':'VtxoFull','body_hex':'00dd'})
        value=self.capture();private=c.common._json(value['private_pg'])
        self.assertEqual(2,len(private['pool']));self.assertIsNotNone(private['pool'][0]['spent_at']);self.assertIsNone(private['pool'][1]['spent_at'])
        self.assertEqual(self.pg['pool_retirements'],private['pool_retirements'])
        for missing in (True,False):
            raw=BodyPG(self.f,self.rows,self.pg)
            if missing:raw.rows['pool'].pop(0) # even spent source is mandatory.
            else:raw.rows['pool'].append({**public,'id':3,'vtxo_id':'3'*64+':0'})
            with self.assertRaisesRegex(ValueError,'membership or metadata'):self.capture(raw)

    def test_wrong_role_or_resource_preflight_refuses_before_any_body_read(self):
        for key,value in [('role','trackcserver'),('database','foreign'),('coins',10001),('coins_bytes',c.MAX_BYTES+1),('pool_max',c.MAX_BODY_BYTES+1),('pending_boards_null',1),('pool',True)]:
            raw=BodyPG(self.f,self.rows,self.pg);raw.size[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.capture(raw)
            self.assertEqual(0,raw.body_calls);self.assertFalse(raw.active)
    def test_mixed_snapshot_backend_settings_or_membership_refuses(self):
        self.populated()
        for mutate in [lambda p:p.update(snapshot='foreign'),lambda p:p.update(backend_pid=9),lambda p:p.update(isolation='read committed'),lambda p:p['coins'].pop(),lambda p:p['coins'][0]['metadata'].update(amount=999),lambda p:p['pending_boards'][0].update(anchor_point='')]:
            raw=BodyPG(self.f,self.rows,self.pg);mutate(raw.private)
            with self.assertRaises(ValueError):self.capture(raw)
            self.assertFalse(raw.active)
    def test_wrong_native_type_or_noncanonical_empty_oversize_hex_refuses(self):
        self.populated()
        for value in ['','AA','0','zz','aa'*(c.MAX_BODY_BYTES+1)]:
            raw=BodyPG(self.f,self.rows,self.pg);raw.private['pool'][0]['body_hex']=value
            with self.assertRaises(ValueError):self.capture(raw)
        raw=BodyPG(self.f,self.rows,self.pg);raw.private['pending_boards'][0]['source_encoding']='ServerVtxoFull'
        with self.assertRaisesRegex(ValueError,'type/columns'):self.capture(raw)
    def test_missing_unspent_duplicate_or_unknown_retirement_relation_holds(self):
        self.populated()
        for mutate in [lambda p:p['pool'][0].update(spent_at=None),lambda p:p['pool_retirements'][0].update(pool_input_id='f'*64+':0'),lambda p:p['pool_retirements'][0].update(vtxo_id='e'*64+':0'),lambda p:p['pool_retirements'][0].update(unrelated_secret='refuse')]:
            raw=BodyPG(self.f,self.rows,self.pg);mutate(raw.private)
            with self.assertRaisesRegex(ValueError,'retirement'):self.capture(raw)
    def test_unknown_private_column_and_chain_change_refuse(self):
        raw=BodyPG(self.f,self.rows,self.pg);raw.private['unlock_preimage']='never-export'
        with self.assertRaises(ValueError):self.capture(raw)
        values=iter([dict(self.fixture.chain),{**self.fixture.chain,'height':101}])
        with self.assertRaisesRegex(ValueError,'chain/deadline'):self.capture(chain=lambda:next(values))
    def test_fixed_grants_and_queries_have_no_dedicated_secret_column_or_request_sql(self):
        self.assertEqual({'public.vtxo':['vtxo'],'public.pending_board':['id','vtxo'],'public.vtxo_pool':['vtxo','spent_at'],'public.vtxo_pool_retirement':['vtxo_id','pool_input_id']},c.ADDITIONAL_SELECT_COLUMNS)
        for sql in (c.PREFLIGHT_SQL,c.PRIVATE_SQL):
            self.assertNotIn('preimage',sql);self.assertNotIn('seed',sql);self.assertNotIn('SELECT *',sql)
        self.assertIn('ORDER BY b.vtxo_id',c.PRIVATE_SQL)
        self.assertIn('ORDER BY b.id',c.PRIVATE_SQL)


class PrivateNativeBodyPackage(unittest.TestCase):
    def setUp(self):
        self.cut=PrivateNativeBodyCut();self.cut.setUp();self.addCleanup(self.cut.doCleanups)
        self.cut.populated();self.value=self.cut.capture();self.path=self.cut.fixture.root/'body.tar'
        from simulator import c_private_native_body_package
        self.p=c_private_native_body_package;self.safe=self.p.write_private_package(self.value,self.path)
    def load(self,**changes):
        x=self.cut.fixture
        args={'expected_package_sha256':self.safe['sha256'],'expected_source_sha256':self.value['source_sha256'],
          'expected_financial_pins':x.observation['financial_pins'],'expected_observation':x.observation,
          'expected_chain':x.chain,'adapter':x.fixed,'limits':x.limits,'binding':x.binding,'producer_exit':lambda:0}
        args.update(changes);return self.p.load_target_tar(self.path,**args)
    def test_private_actual_tar_round_trip_retains_originals_not_readiness(self):
        result=self.load();self.assertEqual(0o600,self.path.stat().st_mode&0o777)
        self.assertEqual(self.cut.pg,result['private_pg']);self.assertFalse(result['qualified']);self.assertFalse(result['complete'])
        self.assertEqual({'cut.json','private-pg.json','public-frontier.ndjson'},set(result['originals']))
        with self.assertRaises(FileExistsError):self.p.write_private_package(self.value,self.path)
    def test_wrong_hash_source_pins_tip_and_actual_transport_failure_refuse(self):
        for change in [{'expected_package_sha256':'f'*64},{'expected_source_sha256':'e'*64},
            {'expected_financial_pins':{**self.value['financial_pins'],'sdk_commit':'d'*40}},
            {'expected_chain':{**self.value['chain'],'height':101}},
            {'producer_exit':lambda:1},{'producer_exit':lambda:False},{'producer_exit':lambda:None}]:
            with self.subTest(change=list(change)),self.assertRaises(ValueError):self.load(**change)
    def test_loose_mode_symlink_and_nonzero_trailing_tar_data_refuse(self):
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):self.load()
        self.path.chmod(0o600)
        other=self.path.with_name('linked.tar');other.symlink_to(self.path);original=self.path;self.path=other
        with self.assertRaises(ValueError):self.load()
        self.path=original
        with self.path.open('ab')as f:f.write(b'private-trailing-data')
        from simulator import c_private_fee_cut as common
        with self.assertRaises(ValueError):self.load(expected_package_sha256=common.digest(self.path.read_bytes()))

"""Shared actual protocol/USTAR/history boundaries; synthetic PG replies only."""
import copy
import os
import unittest
from unittest.mock import patch
from simulator import c_private_normal_cut as c
from tests import test_c_private_native_body_cut as body_fixtures


class CombinedPG(body_fixtures.BodyPG):
    def __init__(self,f,rows,body,fees):
        super().__init__(f,rows,body);self.fees=copy.deepcopy(fees);self.fee_calls=0
    def cursor(self,name=None,**kwargs):
        base=super().cursor(name,**kwargs);outer=self
        class Cursor:
            def __init__(self):self.answer=None
            def __enter__(self):return self
            def __exit__(self,*args):base.close()
            def execute(self,sql):
                if sql in (c.fee.PREFLIGHT_SQL,c.fee.PRIVATE_SQL):
                    outer.executed.append(sql)
                    if not outer.active:raise AssertionError('fee read outside shared RR')
                    if sql==c.fee.PRIVATE_SQL:
                        outer.fee_calls+=1;answer=outer.fees
                    else:answer={'allocations':len(outer.fees['allocations']),'carriers':len(outer.fees['carriers']),'mappings':0,'bytes':len(c.fee.canonical(outer.fees))}
                    self.answer=[(copy.deepcopy(answer),)]
                else:self.answer=None;base.execute(sql)
            def fetchone(self):return self.answer.pop(0)if self.answer else base.fetchone()
            def fetchmany(self,n):return base.fetchmany(n)
            def close(self):base.close()
        return Cursor()


class CombinedNativeCut(unittest.TestCase):
    def setUp(self):
        self.x=body_fixtures.PrivateNativeBodyCut();self.x.setUp();self.addCleanup(self.x.doCleanups)
        self.fixture=self.x.fixture
    def pg(self,charged=False):
        old=self.fixture.pg(charged);fees=old.private;fees['role']=c.body.ROLE
        if charged:
            self.x.rows=old.rows
            for index,row in enumerate(self.x.rows['coins'],1):
                self.x.pg['coins'].append({'metadata':copy.deepcopy(row),'source_encoding':'ServerVtxoFull','body_hex':'00aa','native_id':index,'lightning_htlc_subscription_id':None})
        return CombinedPG(self.x.f,self.x.rows,self.x.pg,fees)
    def capture(self,raw):
        x=self.fixture
        with patch.object(c.fee,'_open_history',side_effect=lambda expected:os.open(x.history,os.O_RDONLY|os.O_DIRECTORY)):
            return c.capture(raw,x.fixed,limits=x.limits,binding=x.binding,observation=x.observation,
              expected_financial_pins=x.observation['financial_pins'],chain_identity=lambda:dict(x.chain),
              expected_history_identity=x.expected,expected_policy_sha256=c.fee.digest(x.fixture.policy))
    def load(self,result,path,**changes):
        x=self.fixture;safe=c.write_private_package(result,path)
        args={'expected_package_sha256':safe['sha256'],'expected_source_sha256':result['source_sha256'],
          'expected_body_source_sha256':result['body_source_sha256'],'expected_financial_pins':x.observation['financial_pins'],
          'expected_observation':x.observation,'expected_chain':x.chain,'expected_history_identity':x.expected,
          'expected_policy_sha256':result['policy_sha256'],'adapter':x.fixed,'limits':x.limits,'binding':x.binding,'producer_exit':lambda:0}
        args.update(changes);return c.load_target_tar(path,**args)
    def test_zero_and_charged_fee_plus_fullbody_in_one_original_RR(self):
        for charged in (False,True):
            raw=self.pg(charged);result=self.capture(raw)
            self.assertEqual(1,raw.fee_calls);self.assertEqual(1,raw.body_calls)
            self.assertEqual(1,sum(s.startswith('BEGIN ')for s in raw.executed));self.assertFalse(raw.active)
            self.assertLess(raw.executed.index(c.fee.PRIVATE_SQL),raw.executed.index(c.body.PRIVATE_SQL))
            loaded=self.load(result,self.fixture.root/('charged.tar'if charged else'zero.tar'))
            self.assertEqual(loaded['private_pg']['snapshot'],loaded['fee_cut']['database_snapshot'])
            self.assertEqual(c.body.ROLE,loaded['fee_private_pg']['role']);self.assertFalse(loaded['qualified'])
            self.assertEqual(b'20000\n'if charged else b'',bytes.fromhex(loaded['fee_cut']['budget_hex']))
            self.assertEqual(bool(charged),bool(loaded['fee_cut']['records']))
    def test_same_block_different_database_snapshot_refuses(self):
        raw=self.pg();raw.fees['snapshot']='different-RR-same-block'
        with self.assertRaisesRegex(ValueError,'RR snapshot'):self.capture(raw)
    def test_wrong_dedicated_role_refuses_before_any_opaque_fee_or_body(self):
        raw=self.pg();raw.size['role']='trackcserver'
        with self.assertRaises(ValueError):self.capture(raw)
        self.assertEqual(0,raw.fee_calls);self.assertEqual(0,raw.body_calls)
    def test_signed_history_change_across_shared_cut_refuses(self):
        raw=self.pg();base=raw.cursor
        class Change:
            def __init__(self,inner):self.inner=inner
            def __getattr__(self,k):return getattr(self.inner,k)
            def __enter__(self):self.inner.__enter__();return self
            def __exit__(self,*args):return self.inner.__exit__(*args)
            def execute(inner,sql):
                inner.inner.execute(sql)
                if sql==c.body.PRIVATE_SQL:self.fixture.write('ordinary-fee-budget',b'20000\n')
        raw.cursor=lambda *a,**kw:Change(base(*a,**kw))
        with self.assertRaisesRegex(ValueError,'history changed'):self.capture(raw)
    def test_old_diagnostic_role_default_unchanged_no_relabel(self):
        raw=self.pg();result=self.capture(raw)
        files={n:{'raw':b}for n,b in result['history'].items()}
        with self.assertRaisesRegex(ValueError,'same-RR'):c.fee._assemble(files,raw.fees,self.fixture.expected)
        with self.assertRaisesRegex(ValueError,'unsupported'):c.fee._assemble(files,raw.fees,self.fixture.expected,expected_role='trackcserver')
    def test_wrong_source_policy_or_transport_cannot_promote_private_cut(self):
        result=self.capture(self.pg())
        for n,change in enumerate([{'expected_body_source_sha256':'f'*64},{'expected_policy_sha256':'e'*64},{'producer_exit':lambda:1}]):
            with self.assertRaises(ValueError):self.load(result,self.fixture.root/('bad%d.tar'%n),**change)


class StatelessTransportSplit(unittest.TestCase):
    def setUp(self):
        self.x=CombinedNativeCut();self.x.setUp();self.addCleanup(self.x.doCleanups)
        self.result=self.x.capture(self.x.pg());self.path=self.x.fixture.root/'transport.tar'
        self.safe=c.write_private_package(self.result,self.path)
    def test_stateless_loader_retains_actual_accessor_and_no_authority_from_manifest(self):
        import inspect
        exit_accessor=lambda:0
        transport=c.decode_transport(self.path,producer_exit=exit_accessor)
        self.assertIs(exit_accessor,transport['producer_exit']);self.assertFalse(transport['complete']);self.assertFalse(transport['qualified'])
        self.assertEqual(('path','producer_exit'),tuple(inspect.signature(c.decode_transport).parameters))
        self.assertIsNone(c.decode_transport.__closure__);self.assertIsNone(c.decode_transport.__defaults__)
        # No expected authority is accepted by the stateless transport API.
        with self.assertRaises(TypeError):c.decode_transport(self.path,producer_exit=exit_accessor,expected_financial_pins={})
        x=self.x.fixture
        args={'expected_package_sha256':transport['archive_sha256'],'expected_source_sha256':self.result['source_sha256'],
          'expected_body_source_sha256':self.result['body_source_sha256'],'expected_financial_pins':x.observation['financial_pins'],
          'expected_observation':x.observation,'expected_chain':x.chain,'expected_history_identity':x.expected,
          'expected_policy_sha256':self.result['policy_sha256'],'adapter':x.fixed,'limits':x.limits,'binding':x.binding,
          'producer_exit':transport['producer_exit']}
        self.assertFalse(c.load_target_tar(transport['path'],**args)['qualified'])
        for key,value in [('expected_source_sha256','f'*64),('expected_body_source_sha256','e'*64),
          ('expected_observation',{**x.observation,'id':'c'*32}),
          ('expected_financial_pins',{**x.observation['financial_pins'],'sdk_commit':'d'*40}),
          ('expected_history_identity',{**x.expected,'inode':x.expected['inode']+1}),
          ('expected_policy_sha256','b'*64)]:
            with self.subTest(key=key),self.assertRaises(ValueError):c.load_target_tar(transport['path'],**{**args,key:value})
    def test_failed_unknown_bool_or_changed_actual_process_status_refuses_transport(self):
        for accessor in [lambda:1,lambda:None,lambda:False]:
            with self.assertRaises(ValueError):c.decode_transport(self.path,producer_exit=accessor)
        statuses=iter([0,1])
        with self.assertRaises(ValueError):c.decode_transport(self.path,producer_exit=lambda:next(statuses))

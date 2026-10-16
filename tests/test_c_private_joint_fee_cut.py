"""Real shared RR/framing; synthetic SQL/witnesses, NO native validation credit."""
import copy
import inspect
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from simulator import c_private_joint_fee_cut as c
from tests import test_c_private_normal_cut as base


class JointPG(base.CombinedPG):
    def __init__(self,old,pg):
        super().__init__(old.f,old.rows,old.private,old.fees)
        self.joint=copy.deepcopy(pg);self.joint_calls=0;self.sizes={}
        for t in c.PROJECTIONS:
            rows=self.joint[t];sizes=[len(c.fee.canonical(v).encode())for v in rows]
            self.sizes.update({t:len(rows),t+'_bytes':sum(sizes),t+'_max':max(sizes or[0])})
    def cursor(self,*args,**kwargs):
        inner=super().cursor(*args,**kwargs);outer=self
        class Cursor:
            def __init__(self):self.answer=None
            def __enter__(self):return self
            def __exit__(self,*args):inner.close()
            def __getattr__(self,n):return getattr(inner,n)
            def execute(self,sql):
                if sql in (c.PREFLIGHT_SQL,c.PRIVATE_SQL):
                    outer.executed.append(sql)
                    if not outer.active:raise AssertionError('joint source outside original RR')
                    if sql==c.PRIVATE_SQL:outer.joint_calls+=1
                    self.answer=[(copy.deepcopy(outer.sizes if sql==c.PREFLIGHT_SQL else outer.joint),)]
                else:self.answer=None;inner.execute(sql)
            def fetchone(self):return self.answer.pop(0)if self.answer else inner.fetchone()
        return Cursor()


class JointPrivateCut(unittest.TestCase):
    def setUp(self):
        self.x=base.CombinedNativeCut();self.x.setUp();self.addCleanup(self.x.doCleanups)
        self.f=self.x.fixture
        self.addCleanup(patch.stopall)
        patch.object(c.fee,'HISTORY_ROOT',self.f.history).start()
        patch.object(c.fee,'_open_history',side_effect=lambda expected:os.open(self.f.history,os.O_RDONLY|os.O_DIRECTORY)).start()
        self.pg={'snapshot':'synthetic-fixed-RR','backend_pid':123,'database':'trackc','role':c.body.ROLE,
            'read_only':'on','isolation':'repeatable read',**{t:[]for t in c.PROJECTIONS}}
    def raw(self):return JointPG(self.x.pg(),self.pg)
    def capture(self,raw=None):
        x=self.f
        return c.capture(raw or self.raw(),x.fixed,limits=x.limits,binding=x.binding,observation=x.observation,
            expected_financial_pins=x.observation['financial_pins'],chain_identity=lambda:dict(x.chain),
            expected_history_identity=x.expected,expected_policy_sha256=c.fee.digest(x.fixture.policy))
    def witness(self):
        for suffix,files in [('.ordinary-native-publications',{'urgent-1.candidate.json':b'{"synthetic":true}'}),
                ('.ordinary-native-opening',{'certificate.json':b'{"synthetic":true}','validated.sha256':b'a'*64})]:
            root=self.f.history.with_name(self.f.history.name+suffix);root.mkdir(mode=0o700)
            for name,raw in files.items():
                p=root/name;p.write_bytes(raw);p.chmod(0o600)
    def args(self,result,safe):
        x=self.f
        return dict(expected_package_sha256=safe['sha256'],expected_source_sha256=result['source_sha256'],
            expected_body_source_sha256=result['body_source_sha256'],expected_joint_source_sha256=result['joint_source_sha256'],
            expected_financial_pins=x.observation['financial_pins'],expected_observation=x.observation,expected_chain=x.chain,
            expected_history_identity=x.expected,expected_policy_sha256=result['policy_sha256'],adapter=x.fixed,
            limits=x.limits,binding=x.binding,producer_exit=lambda:0)
    def packed(self):
        result=self.capture();path=self.f.root/'joint.tar';safe=c.write_private_package(result,path)
        return result,path,safe,self.args(result,safe)
    def test_one_RR_all_preflights_before_any_new_or_old_opaque_read_and_roundtrip(self):
        self.witness();self.pg['wallet_changeset']=[{'id':1,'kind':'synthetic','content_hex':None}]
        raw=self.raw();result=self.capture(raw)
        self.assertEqual((1,1,1),(raw.joint_calls,raw.fee_calls,raw.body_calls))
        self.assertEqual(1,sum(s.startswith('BEGIN ')for s in raw.executed))
        for pre in (c.PREFLIGHT_SQL,c.fee.PREFLIGHT_SQL,c.body.PREFLIGHT_SQL):
            for opaque in (c.PRIVATE_SQL,c.fee.PRIVATE_SQL,c.body.PRIVATE_SQL):self.assertLess(raw.executed.index(pre),raw.executed.index(opaque))
        path=self.f.root/'positive.tar';safe=c.write_private_package(result,path)
        transport=c.decode_transport(path,producer_exit=lambda:0)
        self.assertEqual(safe['sha256'],transport['archive_sha256'])
        value=c.load_target_tar(path,**self.args(result,safe))
        self.assertEqual(None,value['joint_pg']['wallet_changeset'][0]['content_hex'])
        self.assertTrue(value['native_validation_required']);self.assertFalse(value['qualified']);self.assertFalse(value['complete'])
        self.assertIn('joint-witness/opening/certificate.json',value['originals'])
    def test_missing_sibling_is_preserved_unknown_never_empty_or_ready(self):
        result,path,safe,args=self.packed();value=c.load_target_tar(path,**args)
        for v in value['joint_witnesses'].values():
            self.assertIs(v['exists'],False);self.assertIsNone(v['files'])
        self.assertTrue(value['native_validation_required']);self.assertFalse(value['complete'])
    def test_wrong_RR_role_and_missing_table_are_HOLD(self):
        for key,value in [('snapshot','same-block-other-RR'),('backend_pid',456),('role','trackcserver')]:
            raw=self.raw();raw.joint[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.capture(raw)
        raw=self.raw();del raw.joint['nursery_tx']
        with self.assertRaises(ValueError):self.capture(raw)
    def test_count_resource_and_wrong_columns_refuse(self):
        raw=self.raw();raw.sizes['native_fee_input']=True
        with self.assertRaises(ValueError):self.capture(raw)
        self.assertEqual(0,raw.joint_calls);self.assertEqual(0,raw.fee_calls);self.assertEqual(0,raw.body_calls)
        raw=self.raw();raw.sizes['nursery_tx_bytes']=c.MAX_BYTES
        with self.assertRaises(ValueError):self.capture(raw)
        self.assertEqual(0,raw.joint_calls)
        raw=self.raw();raw.joint['foreign_table']=[]
        with self.assertRaises(ValueError):self.capture(raw)
    def test_sibling_permissions_links_unknown_names_refuse(self):
        self.witness();p=self.f.history.with_name(self.f.history.name+'.ordinary-native-publications')/'urgent-1.candidate.json'
        p.chmod(0o644)
        with self.assertRaises(ValueError):self.capture()
        p.chmod(0o600);os.link(p,p.with_name('a'*64+'.json'))
        with self.assertRaises(ValueError):self.capture()
    def test_small_shared_witness_quota_is_checked_before_buffering_next_file(self):
        self.witness()
        with patch.object(c,'MAX_WITNESS_BYTES',80),patch.object(c.fee,'digest',wraps=c.fee.digest)as hashed:
            with self.assertRaisesRegex(ValueError,'whole witness bounds exceeded before read'):
                c._files(self.f.expected)
        self.assertNotIn(b'a'*64,[call.args[0]for call in hashed.call_args_list])
    def test_context_each_independent_expected_binding_and_exit_required(self):
        result,path,safe,args=self.packed()
        for key,value in [('expected_joint_source_sha256','e'*64),('expected_source_sha256','d'*64),
                ('expected_observation',{**self.f.observation,'id':'f'*32}),('expected_chain',{**self.f.chain,'height':9}),
                ('expected_policy_sha256','b'*64),('producer_exit',lambda:1)]:
            with self.subTest(key=key),self.assertRaises(ValueError):c.load_target_tar(path,**{**args,key:value})
        with self.assertRaises(ValueError):c.normal.load_target_tar(path,**{k:v for k,v in args.items()if k!='expected_joint_source_sha256'})
    def test_stateless_transport_no_expected_authority_and_unknown_bool_terminal_refused(self):
        result,path,safe,args=self.packed()
        self.assertEqual(('path','producer_exit'),tuple(inspect.signature(c.decode_transport).parameters))
        self.assertIsNone(c.decode_transport.__closure__);self.assertIsNone(c.decode_transport.__defaults__)
        for status in (False,None,1):
            with self.assertRaises(ValueError):c.decode_transport(path,producer_exit=lambda:status)
        statuses=iter([0,1])
        with self.assertRaises(ValueError):c.decode_transport(path,producer_exit=lambda:next(statuses))
    def test_required_nullable_signed_pair_and_actual_hex_shape(self):
        pg=copy.deepcopy(self.pg)
        row={name+'_hex'if name in c.HEX_FIELDS['native_urgent_attempt']else name:'a'*64 for name in c.PROJECTIONS['native_urgent_attempt'][2]}
        row.update(attempt_index=1,purpose='claim',created_at='synthetic',reservation_entry_hex='aa',candidate_hex='bb',signed_entry_hex=None,signed_record_hex=None)
        pg['native_urgent_attempt']=[row]
        def sizes(p):
            return {k:v for t in c.PROJECTIONS for k,v in ((t,len(p[t])),(t+'_bytes',sum(len(c.fee.canonical(r))for r in p[t])),(t+'_max',max([len(c.fee.canonical(r))for r in p[t]]or[0])))}
        c.assemble(pg,self.pg,sizes(pg))
        for key,value in [('candidate_hex',None),('candidate_hex','AA'),('signed_entry_hex','aa')]:
            bad=copy.deepcopy(pg);bad['native_urgent_attempt'][0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):c.assemble(bad,self.pg,sizes(bad))
    def test_actual_witness_change_across_RR_and_symlink_refuse(self):
        self.witness();path=self.f.history.with_name(self.f.history.name+'.ordinary-native-publications')/'urgent-1.candidate.json'
        raw=self.raw();original=raw.cursor
        class Change:
            def __init__(inner,cursor):inner.cursor=cursor
            def __getattr__(inner,name):return getattr(inner.cursor,name)
            def __enter__(inner):inner.cursor.__enter__();return inner
            def __exit__(inner,*args):return inner.cursor.__exit__(*args)
            def execute(inner,sql):
                inner.cursor.execute(sql)
                if sql==c.PRIVATE_SQL:path.write_bytes(b'{"changed":true}')
        raw.cursor=lambda *args,**kwargs:Change(original(*args,**kwargs))
        with self.assertRaisesRegex(ValueError,'witnesses/deadline'):self.capture(raw)
        path.unlink();path.symlink_to(self.f.history/'identity.json')
        with self.assertRaises(OSError):self.capture()
    def test_tampered_physical_archive_or_EOF_refuses_and_writer_is_exclusive(self):
        result,path,safe,args=self.packed()
        with self.assertRaises(FileExistsError):c.write_private_package(result,path)
        with path.open('r+b')as stream:stream.seek(1024);byte=stream.read(1);stream.seek(1024);stream.write(bytes([byte[0]^1]))
        with self.assertRaises(ValueError):c.load_target_tar(path,**args)
        other=self.f.root/'bad-eof.tar';c.write_private_package(result,other)
        with other.open('ab')as stream:stream.write(b'X'*512)
        with self.assertRaises(ValueError):c.decode_transport(other,producer_exit=lambda:0)
    def rights(self,history=None):
        root=self.f.history.with_name(self.f.history.name+'.ordinary-native-round-rights');root.mkdir(mode=0o700)
        self.rights_id='f'*64
        for name,raw in {'identity.json':b'{"synthetic":true}',
                'history':(self.rights_id+'\n').encode()if history is None else history,
                self.rights_id+'.json':b'{"synthetic_full_anchor":true}'}.items():
            p=root/name;p.write_bytes(raw);p.chmod(0o600)
        return root
    def test_round_full_and_associations_share_original_RR_and_rights_index_without_native_credit(self):
        self.rights()
        self.pg['rounds']=[{'id':99,'seq':1,'expiry':200,'funding_txid':'f'*64,'funding_tx_hex':'aabb','signed_tree_hex':'ccdd'}]
        self.pg['round_participation']=[{'id':1,'round_id':'f'*64,'unlock_hash':'a'*64}]
        self.pg['round_part_input']=[{'participation_id':1,'vtxo_id':'b'*64+':0'}]
        row={'participation_id':1,'policy_hex':'aabb','amount':1000,'unblinded_mailbox_id':None}
        self.pg['round_part_output']=[row,copy.deepcopy(row)] # full multiset, no dropping duplicate source rows
        self.pg['virtual_transaction']=[{'txid':'c'*64,'signed_tx_hex':None}]
        result,path,safe,args=self.packed();loaded=c.load_target_tar(path,**args)
        self.assertEqual(4,loaded['manifest']['schema_version'])
        self.assertEqual(c.ROUND_ABI_SHA256,loaded['manifest']['round_abi_sha256'])
        self.assertEqual((99,1),(loaded['joint_pg']['rounds'][0]['id'],loaded['joint_pg']['rounds'][0]['seq']))
        self.assertEqual(2,len(loaded['joint_pg']['round_part_output']))
        self.assertIsNone(loaded['joint_pg']['virtual_transaction'][0]['signed_tx_hex'])
        self.assertEqual((self.rights_id+'\n').encode(),loaded['originals']['joint-witness/round_rights/history'])
        self.assertTrue(loaded['native_validation_required']);self.assertFalse(loaded['complete'])
    def test_empty_initialized_round_namespace_preserved_but_never_qualified(self):
        root=self.rights(history=b'');(root/(self.rights_id+'.json')).unlink()
        result,path,safe,args=self.packed();loaded=c.load_target_tar(path,**args)
        self.assertEqual(b'',loaded['originals']['joint-witness/round_rights/history'])
        self.assertFalse(loaded['qualified']);self.assertTrue(loaded['native_validation_required'])
    def test_torn_duplicate_missing_extra_and_unknown_round_index_hold(self):
        root=self.rights()
        for raw in [(self.rights_id+'\n'+self.rights_id+'\n').encode(),self.rights_id.encode(),b'AA\n',('a'*64+'\n').encode()]:
            (root/'history').write_bytes(raw)
            with self.subTest(raw=raw),self.assertRaises(ValueError):self.capture()
        (root/'history').write_bytes((self.rights_id+'\n').encode())
        (root/'unexpected.tmp').write_bytes(b'unknown');(root/'unexpected.tmp').chmod(0o600)
        with self.assertRaises(ValueError):self.capture()
    def test_new_required_round_projection_missing_or_different_RR_never_old_empty(self):
        raw=self.raw();del raw.joint['rounds']
        with self.assertRaises(ValueError):self.capture(raw)
        raw=self.raw();raw.joint['round_participation']=[{'id':1,'round_id':None,'unlock_hash':None,'unlock_preimage':'FORBIDDEN'}]
        raw.sizes.update(round_participation=1,round_participation_bytes=256,round_participation_max=256)
        with self.assertRaises(ValueError):self.capture(raw)
    def test_pending_participations_preserve_NULL_without_booked_rights_claim(self):
        self.pg['round_participation']=[{'id':10,'round_id':None,'unlock_hash':None},
            {'id':11,'round_id':None,'unlock_hash':'a'*64}]
        result,path,safe,args=self.packed();value=c.load_target_tar(path,**args)
        self.assertEqual(self.pg['round_participation'],value['joint_pg']['round_participation'])
        self.assertTrue(value['native_validation_required']);self.assertFalse(value['complete'])
    def test_round_id_is_not_seq_and_duplicate_id_or_funding_txid_HOLD(self):
        row={'id':99,'seq':1,'expiry':200,'funding_txid':'f'*64,'funding_tx_hex':'aa','signed_tree_hex':'bb'}
        for rows in [[row,{**row,'id':100}],[row,{**row,'funding_txid':'e'*64}],[{k:v for k,v in row.items()if k!='id'}],
                [{**row,'id':True}],[{**row,'seq':None}]]:
            self.pg['rounds']=rows
            with self.subTest(rows=rows),self.assertRaises(ValueError):self.capture()
    def test_queries_literal_exact_schema_no_dedicated_secret_columns(self):
        for sql in (c.PREFLIGHT_SQL,c.PRIVATE_SQL):
            for forbidden in ('SELECT *','preimage','seed','signed_forfeit'):self.assertNotIn(forbidden,sql)
        self.assertEqual(13,len(c.PROJECTIONS))
        self.assertEqual('round',c.TABLES['rounds'])
        self.assertEqual(['id','seq','expiry','funding_txid','funding_tx','signed_tree'],c.ADDITIONAL_SELECT_COLUMNS['public.round'])
        self.assertIn("FROM public.round ORDER BY id",c.PRIVATE_SQL)
        self.assertNotIn('public.rounds',c.PRIVATE_SQL)
        self.assertEqual(c.ABI_SHA256,'fe08a60e263c3c411f1fbbc622dfad00184fcf3da8b45f0794174176859cb456')


class JointCheckedTarget(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        from simulator import c_normal_target_source as target
        from simulator.store import Store
        self.x=JointPrivateCut();self.x.setUp();self.addCleanup(self.x.doCleanups)
        self.result,self.path,self.safe,args=self.x.packed();self.f=self.x.f;self.t=target
        self.store=Store(self.f.root/'journal','synthetic-C',architecture_profile='direct_per_key');self.addCleanup(self.store.close)
        self.reader=target.TargetTarReader(['/synthetic/fixed-target'],self.f.root,timeout=25,request_stdin=True,loader=c.decode_transport)
        self.cfg={n:args['expected_'+n]for n in ('source_sha256','body_source_sha256','joint_source_sha256','history_identity','policy_sha256')}
        self.cfg.update(limits=self.f.limits,binding=self.f.binding)
        self.target=target.CheckedTargetReader(self.reader,self.f.fixed,self.cfg,1);self.calls=0;outer=self
        class Chain:
            def identity(self):return {'chain':'signet','blocks':outer.f.chain['height'],'bestblockhash':outer.f.chain['tip_hash'],'initialblockdownload':False}
            def call(self,name,*args):
                if name=='getblockhash'and args==(0,):return outer.f.chain['genesis']
                raise AssertionError('no financial methods')
        self.chain=Chain()
    async def collect(self,mutate=None):
        outer=self
        async def transport(reader,observation):
            outer.calls+=1
            return c.decode_transport(outer.path,producer_exit=lambda:0)
        with patch.object(self.t.TargetTarReader,'read',transport),patch.object(self.t,'_context'):
            requirement=self.target.admission_requirement(self.f.observation)
            self.store.event('c_normal_target_source_qualified',requirement)
            self.target.qualification_sequence=self.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
            if mutate:mutate()
            return await self.target.read(self.store,self.chain,self.f.observation)
    async def test_real_checked_target_dispatches_current_version_full_context_without_legacy_alias(self):
        value=await self.collect()
        self.assertEqual(4,value['loaded']['manifest']['schema_version'])
        self.assertTrue(value['loaded']['native_validation_required']);self.assertFalse(value['financial_readiness']);self.assertEqual(1,self.calls)
    async def test_changed_config_refuses_before_transport(self):
        with self.assertRaises(ValueError):await self.collect(lambda:self.target.configuration.update(joint_source_sha256='b'*64))
        self.assertEqual(0,self.calls)
    async def test_no_manifest_or_stock_loader_can_select_current_version_constructor(self):
        self.reader.loader=c.normal.decode_transport
        with self.assertRaises(ValueError):self.t.CheckedTargetReader(self.reader,self.f.fixed,self.cfg,1)
        self.reader.loader=c.decode_transport
        with self.assertRaises(ValueError):self.t.CheckedTargetReader(self.reader,self.f.fixed,{k:v for k,v in self.cfg.items()if k!='joint_source_sha256'},1)

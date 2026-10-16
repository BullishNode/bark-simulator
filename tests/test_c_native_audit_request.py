"""Original PRIVATE source/framing to DTO, no native process/crypto/admission."""
import copy
import json
import time
import unittest
from simulator import c_native_audit_request as c
from simulator import c_private_joint_fee_cut as source
from tests import test_c_private_joint_fee_cut as fixture


class CapturedRequest(unittest.TestCase):
    def setUp(self):
        self.f=fixture.JointPrivateCut();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.base=self.f.f
        self.policy=b' {"urgent_reserve_sat":40000, "ordinary_budget_sat":58000} \n'
        self.base.fixture.policy=self.policy;self.base.write('ordinary-fee-policy.json',self.policy)
        self.base.write('ordinary-fee-budget',b'20000\n')
        self.expected={'server_pubkey':self.base.binding['server_pubkey'],'genesis':self.base.chain['genesis'],
            'policy_sha256':'e'*64,'opening_sha256':'f'*64}
    def load(self,*,groups=True,empty_publications=False,bad_utf8=False):
        if groups:
            self.f.witness();self.f.rights()
            pub=self.base.history.with_name(self.base.history.name+'.ordinary-native-publications')/'urgent-1.candidate.json'
            if bad_utf8:pub.write_bytes(b'\xff')
            if empty_publications:pub.unlink()
        result,path,safe,args=self.f.packed();self.loaded=source.load_target_tar(path,**args)
        self.refs=copy.deepcopy(self.loaded['original_private_source_references'])
        self.observation=copy.deepcopy(self.base.observation)
    def prepare(self,**changes):
        args={'expected':self.expected,'source_observation':self.observation,'original_source_references':self.refs}
        args.update(changes);return c.prepare(self.loaded,**args)
    def test_actual_originals_to_exact_declared_DTO_no_normal_authority(self):
        self.f.pg['round_participation']=[{'id':3,'round_id':None,'unlock_hash':None}]
        self.f.pg['virtual_transaction']=[{'txid':'a'*64,'signed_tx_hex':None}]
        self.load();before=copy.deepcopy(self.loaded);result=self.prepare();request=json.loads(result['private_request'])
        self.assertEqual({'format','expected','policy_utf8','history_utf8','publication_files','round_rights_files','opening_files','joint_rows','body_rows'},set(request))
        self.assertEqual(c.FORMAT,request['format']);self.assertEqual(self.expected,request['expected'])
        self.assertEqual(self.policy,request['policy_utf8'].encode('utf-8'))
        self.assertEqual(b'20000\n',request['history_utf8'].encode('utf-8'))
        self.assertNotEqual(request['history_utf8'].encode(),self.loaded['originals']['history/history'])
        self.assertNotEqual(source.fee.digest(self.policy),request['expected']['policy_sha256']) # external canonical identity, not raw hash
        self.assertEqual(self.loaded['joint_pg'],request['joint_rows']);self.assertEqual(self.loaded['private_pg'],request['body_rows'])
        self.assertIsNone(request['joint_rows']['round_participation'][0]['round_id'])
        self.assertIsNone(request['joint_rows']['virtual_transaction'][0]['signed_tx_hex'])
        self.assertEqual(before,self.loaded)
        for flag in ('complete','qualified','financial_readiness'):self.assertIs(result['safe'][flag],False)
        self.assertEqual(source.fee.digest(result['private_request']),result['safe']['request_sha256'])
        self.assertNotIn('private_request',result['safe']);self.assertNotIn('policy_utf8',result['safe'])
    def test_all_file_bytes_and_opening_marker_preserved_without_reencoding(self):
        self.load();value=json.loads(self.prepare()['private_request'])
        for field,group in c.GROUPS.items():
            for name,entry in self.loaded['joint_witnesses'][group]['files'].items():
                self.assertEqual(entry['raw'],value[field][name].encode('utf-8'))
        self.assertEqual(b'a'*64,value['opening_files']['validated.sha256'].encode())
    def test_missing_namespaces_remain_None_not_empty_maps(self):
        self.load(groups=False);value=json.loads(self.prepare()['private_request'])
        for field in c.GROUPS:self.assertIsNone(value[field])
    def test_initialized_empty_publication_namespace_is_not_missing(self):
        self.load(empty_publications=True);value=json.loads(self.prepare()['private_request'])
        self.assertEqual({},value['publication_files']);self.assertEqual(0,self.prepare()['safe']['file_counts']['publication_files'])
    def test_invalid_UTF8_original_is_HOLD_without_lossy_replacement(self):
        self.load(bad_utf8=True)
        with self.assertRaises(UnicodeDecodeError):self.prepare()
    def test_each_omitted_or_mutated_original_is_rejected_against_independent_refs(self):
        self.load();original=self.loaded
        for name in ('history/ordinary-fee-policy.json','history/ordinary-fee-budget','joint-pg.json','private-pg.json','joint-witness/opening/certificate.json'):
            for mutate in (lambda files,name:files.pop(name),lambda files,name:files.update({name:files[name]+b' '})):
                self.loaded=copy.deepcopy(original);mutate(self.loaded['originals'],name)
                with self.subTest(name=name),self.assertRaises(ValueError):self.prepare()
        self.loaded=original
    def test_mutated_rows_witnesses_and_refs_cannot_replace_original_bytes(self):
        self.load();original=self.loaded
        for change in (lambda v:v['joint_pg']['round_participation'].append({'id':1,'round_id':None,'unlock_hash':None}),
                lambda v:v['private_pg'].update(backend_pid=999),
                lambda v:v['joint_witnesses']['opening']['files']['certificate.json'].update(raw=b'changed'),
                lambda v:v['original_private_source_references'].update(archive_sha256='0'*64)):
            self.loaded=copy.deepcopy(original);change(self.loaded)
            with self.assertRaises(ValueError):self.prepare()
    def test_wrong_source_observation_reference_or_native_owner_or_chain_HOLD(self):
        self.load()
        cases=[{'source_observation':{**self.observation,'id':'b'*32}},
            {'original_source_references':{**self.refs,'manifest_sha256':'a'*64}},
            {'expected':{**self.expected,'server_pubkey':'03'+'9'*64}},
            {'expected':{**self.expected,'genesis':c.fee.digest(b'foreign chain')}}]
        for change in cases:
            with self.subTest(change=list(change)),self.assertRaises(ValueError):self.prepare(**change)
    def test_closed_expected_fields_and_no_caller_path_command_or_cap_override(self):
        self.load()
        for expected in ({k:v for k,v in self.expected.items()if k!='opening_sha256'},
                {**self.expected,'complete':True},{**self.expected,'policy_sha256':None}):
            with self.assertRaises(ValueError):self.prepare(expected=expected)
        for name in ('command','path','maximum_bytes','run_tool'):
            with self.subTest(name=name),self.assertRaises(TypeError):self.prepare(**{name:'forbidden'})
    def test_existing_aggregate_deadline_and_source_age_never_reset(self):
        self.load();deadline=c.Deadline(self.observation['started_at']);deadline.monotonic_end=time.monotonic()-1
        token=c.ACTIVE.set(deadline)
        try:
            with self.assertRaises(TimeoutError):self.prepare()
        finally:c.ACTIVE.reset(token)
        with self.assertRaises(ValueError):self.prepare(source_observation={**self.observation,'started_at':time.time()-91})
    def test_actual32MiB_encoded_boundary_and_escape_expansion_HOLD(self):
        # Actual streaming serializer, no patched ceiling. Raw16MiB is below the
        # input ceiling but escaped wire expansion must still refuse >=32MiB.
        with self.assertRaisesRegex(ValueError,'32MiB'):
            c._encode({'x':'\\'*(c.MAX_BYTES//2)},c.Deadline(time.time()))
        overhead=len(b'{"x":""}')
        exact=c._encode({'x':'a'*(c.MAX_BYTES-overhead)},c.Deadline(time.time()))
        self.assertEqual(c.MAX_BYTES,len(exact))
        with self.assertRaisesRegex(ValueError,'32MiB'):
            c._encode({'x':'a'*(c.MAX_BYTES-overhead+1)},c.Deadline(time.time()))

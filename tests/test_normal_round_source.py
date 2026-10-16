"""Source/admission controls with public fake tools; no native or money credit."""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from simulator import normal_lineage as lineage
from simulator import normal_lineage_join as join
from simulator.model import canonical
from simulator.store import Store
from simulator.two_step_normal import module_hash, native_tables
from tests import test_normal_round_lineage as tree_controls


class RoundSourceControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir='/dev/shm')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = Store(self.root/'state', 'public-software-source', 10000)
        self.addCleanup(self.store.close)
        self.binary = self.root/'public-proof'
        self.binary.write_text('#!/usr/bin/python3\nimport sys,json\nr=json.load(sys.stdin)\n'
            'print(json.dumps({"schema_version":1,"sdk_commit":'+repr(lineage.NATIVE_COMPLETION_SDK)+',"public_echo":r}))\n')
        self.binary.chmod(0o500)
        self.evidence = self.root/'evidence'; self.evidence.mkdir(mode=0o700)
        self.tool = {'command':[str(self.binary)],
            'sha256':hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            'evidence_directory':str(self.evidence)}
        self.tools = {'policy':self.tool}
        self.sha = 'a'*64; self.nonce = 'b'*32
        components = {'ordinary_lineage':module_hash(join.authenticate_frontier),
            'typed_lineage':module_hash(lineage.bind_coin)}
        self.admission = {'ordinary_lineage':join.ROUND_CONFIGURATION,
            'financial_pins':{'sdk_commit':lineage.NATIVE_COMPLETION_SDK},
            'proof_tool_sha256':{'policy':self.tool['sha256']},
            'proof_commands_sha256':{'policy':hashlib.sha256(canonical(self.tool['command']).encode()).hexdigest()},
            'component_sha256':components, 'capture_dependencies_sha256':components}

    def admit(self, value=None):
        self.store.event('normal_financial_collector_qualified', value or self.admission)
        return self.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]

    def executor(self, sequence):
        return join.round_executor(self.store,self.tools,sequence,
            native_source_sha256=self.sha,observation_id=self.nonce)

    def test_real_local_process_retains_exact_private_buffers_without_journal_changes(self):
        self.assertEqual(Path(join.__file__).resolve(), Path(__file__).resolve().parents[1]/'simulator/normal_lineage_join.py')
        seq = self.admit(); before = self.store.db.execute('SELECT count(*)FROM event').fetchone()[0]
        execute,pins = self.executor(seq)
        sent,received,binding = execute({'public':'source-control'},expected=pins)
        self.assertEqual(json.loads(sent),{'public':'source-control'})
        self.assertEqual(json.loads(received)['public_echo'],{'public':'source-control'})
        self.assertEqual(binding,pins)
        self.assertEqual(before,self.store.db.execute('SELECT count(*)FROM event').fetchone()[0])
        dirs = list(self.evidence.iterdir()); self.assertEqual(len(dirs),1)
        self.assertEqual((dirs[0]/'request.json').read_bytes(),sent)
        self.assertEqual((dirs[0]/'stdout').read_bytes(),received)
        self.assertEqual((dirs[0]/'request.json').stat().st_mode&0o777,0o600)

    def test_wrong_sdk_argv_tool_module_or_scope_refuses_before_execution(self):
        for field in ('sdk','command','tool','module','scope'):
            value = copy.deepcopy(self.admission)
            if field=='sdk': value['financial_pins']['sdk_commit']='e'*40
            elif field=='command': value['proof_commands_sha256']['policy']='e'*64
            elif field=='tool': value['proof_tool_sha256']['policy']='e'*64
            elif field=='module': value['capture_dependencies_sha256']['ordinary_lineage']='e'*64
            else: value['ordinary_lineage']=join.CONFIGURATION
            with self.subTest(field=field),self.assertRaises(ValueError):self.executor(self.admit(value))
        self.assertEqual(list(self.evidence.iterdir()),[])

    def test_callback_cannot_replace_nonce_source_admission_or_stub_scope(self):
        execute,pins = self.executor(self.admit())
        for field in ('source_observation_id','source_sha256','admission_sha256','qualification_scope'):
            changed=dict(pins);changed[field]='software_stub_no_native_credit' if field=='qualification_scope' else 'f'*len(pins[field])
            with self.subTest(field=field),self.assertRaises(ValueError):execute({},expected=changed)
        self.assertEqual(list(self.evidence.iterdir()),[])

    def test_changed_executable_does_not_run_under_old_admission(self):
        execute,pins = self.executor(self.admit())
        self.binary.chmod(0o700);self.binary.write_text('#!/usr/bin/python3\nraise SystemExit(91)\n')
        with self.assertRaisesRegex(ValueError,'executable identity'):execute({},expected=pins)
        self.assertEqual(list(self.evidence.iterdir()),[])

    def context(self):
        control=tree_controls.TreeControls();f=control.fixture();edge=control.refresh(f)
        # Deliberately fabricated metadata for parser tests, never an admission.
        for proof in [edge['native_tree_originals'],*edge['native_forfeit_originals']]:
            proof['execution_binding']['qualification_scope']='admitted_native'
        return f,{'native_source_sha256':f[2]['source_sha256'],'source_observation_id':f[2]['source_observation_id'],
            'round_proof_evidence':[{'action_id':'r','native_tree_originals':edge['native_tree_originals'],
                'native_forfeit_originals':edge['native_forfeit_originals']}]}

    def test_handoff_binds_every_raw_tree_anchor_participation_and_input(self):
        f,value=self.context();self.assertEqual(len(join.require_round_evidence(value,f[1],f[2]['source_sha256'])),1)
        for field in ('source','tree','anchor','input','extra_part','nonce','stub'):
            frames=copy.deepcopy(f[1]);context=copy.deepcopy(value)
            proof=context['round_proof_evidence'][0]
            if field=='source':context['native_source_sha256']='f'*64
            elif field=='tree':frames['round'][0]['signed_tree_hex']='aabc'
            elif field=='anchor':frames['round'][0]['funding_tx_hex']='00'
            elif field=='input':proof['native_forfeit_originals']=[]
            elif field=='extra_part':frames['round_participation'].append({**frames['round_participation'][0],'id':11,'unlock_hash':'e'*64})
            elif field=='nonce':proof['native_tree_originals']['execution_binding']['source_observation_id']='f'*32
            else:proof['native_tree_originals']['execution_binding']['qualification_scope']='software_stub_no_native_credit'
            with self.subTest(field=field),self.assertRaises(ValueError):join.require_round_evidence(context,frames,f[2]['source_sha256'])

    def test_round_transport_only_opens_under_exact_new_source_configuration(self):
        from simulator.two_step_normal import TABLES
        frame={'read_only':'on','isolation':'repeatable read','tables':{n:{'count':0,'rows':[]}for n in TABLES}}
        frame['tables']['round']={'count':1,'rows':[{'public':'source framing only'}]}
        raw=('BEGIN\nSET\n'+canonical(frame)+'\nCOMMIT\n').encode();sha=hashlib.sha256(raw).hexdigest()
        with self.assertRaises(ValueError):native_tables(raw,sha)
        with self.assertRaises(ValueError):native_tables(raw,sha,ordinary_lineage_configuration=join.CONFIGURATION)
        self.assertEqual(len(native_tables(raw,sha,ordinary_lineage_configuration=join.ROUND_CONFIGURATION)['round']),1)
        with self.assertRaises(ValueError):native_tables(raw,sha,ordinary_lineage_configuration={**join.ROUND_CONFIGURATION,'source_sha256':'e'*64})


if __name__=='__main__':
    unittest.main()

"""Real journal admission/config binding; no source or financial calls."""
import copy
import tempfile
import unittest
from pathlib import Path
from simulator.store import Store
from simulator.model import canonical
from simulator.two_step_normal import digest,module_hash
from simulator.two_step_capture import SourceCapture
from simulator.private_source_package import TargetTarReader
from simulator.normal_member_source import MemberReader
from tests.test_final_campaign import PINS

def private_loader(path, *, producer_exit):
    return path,producer_exit()

def other_private_loader(path, *, producer_exit):
    return path,producer_exit()

class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name),'reader-admission',10000)
        self.target=TargetTarReader(['/usr/bin/ssh','actual-owned-target'],self.tmp.name)
        self.member=MemberReader({'helper_command':['/usr/bin/python3','/public/helper.py']},self.store)
        self.boundary={'id':'bounded-test'};self.config={'boundary_sha256':digest(canonical(self.boundary).encode())}
        self.value={'financial_pins':PINS,'capture_dependencies_sha256':{'target_reader':module_hash(self.target.read),'member_reader':module_hash(self.member.read)},
            'capture_configuration_sha256':digest(canonical(self.config).encode()),
            'reader_configuration_sha256':digest(canonical({'target':{'command':list(self.target.command),'evidence_directory':str(self.target.evidence_directory),'timeout':45},'member':self.member.configuration}).encode())}
        self.store.event('normal_financial_collector_qualified',self.value)
        self.sequence=self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
        self.capture=SourceCapture(self.target.read,self.member.read,self.sequence,self.boundary,self.config)
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def test_actual_modules_and_both_installed_reader_configurations_match_original_event(self):
        self.assertEqual(self.value,self.capture.admission(self.store,{'financial_pins':PINS}))
        self.store.verify_event_chain()
    def test_same_module_different_ssh_or_helper_configuration_is_not_admitted(self):
        self.target.command=('/usr/bin/ssh','foreign-target')
        with self.assertRaisesRegex(ValueError,'qualification'):self.capture.admission(self.store,{'financial_pins':PINS})
        self.target.command=('/usr/bin/ssh','actual-owned-target');self.member.configuration['helper_command'][-1]='/other/helper.py'
        with self.assertRaisesRegex(ValueError,'qualification'):self.capture.admission(self.store,{'financial_pins':PINS})
    def test_pending_transport_config_cannot_enable_unadmitted_or_other_tool(self):
        self.member.configuration['pending_board_proof_sha256']='a'*64
        self.value['reader_configuration_sha256']=digest(canonical({'target':{'command':list(self.target.command),'evidence_directory':str(self.target.evidence_directory),'timeout':45},'member':self.member.configuration}).encode())
        self.store.event('normal_financial_collector_qualified',self.value);self.capture.admission_sequence=self.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
        with self.assertRaisesRegex(ValueError,'qualification'):self.capture.admission(self.store,{'financial_pins':PINS})
        self.value['proof_tool_sha256']={'pending':'a'*64}
        self.store.event('normal_financial_collector_qualified',self.value);self.capture.admission_sequence=self.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
        self.assertEqual(self.value,self.capture.admission(self.store,{'financial_pins':PINS}))
    def test_dependency_override_and_boundary_substitution_refuse(self):
        with self.assertRaisesRegex(ValueError,'overridden'):
            SourceCapture(self.target.read,self.member.read,self.sequence,self.boundary,self.config,dependencies={'member_reader':module_hash})
        self.boundary['id']='substituted'
        with self.assertRaisesRegex(ValueError,'qualification'):self.capture.admission(self.store,{'financial_pins':PINS})
    def test_default_admission_cannot_enable_request_input_or_private_loader(self):
        self.target.request_stdin=True
        with self.assertRaisesRegex(ValueError,'qualification'):
            self.capture.admission(self.store,{'financial_pins':PINS})
        self.target.request_stdin=False;self.target.loader=private_loader
        with self.assertRaisesRegex(ValueError,'qualification'):
            self.capture.admission(self.store,{'financial_pins':PINS})
    def test_admitted_loader_and_request_input_are_bound_to_name_source_and_mode(self):
        self.target.request_stdin=True;self.target.loader=private_loader
        target={'command':list(self.target.command),'evidence_directory':str(self.target.evidence_directory),
            'timeout':45,'request_stdin':True,'loader':{'module':private_loader.__module__,
            'qualified_name':private_loader.__qualname__,'source_sha256':module_hash(private_loader)}}
        value={**self.value,'reader_configuration_sha256':digest(canonical(
            {'target':target,'member':self.member.configuration}).encode())}
        self.store.event('normal_financial_collector_qualified',value)
        self.capture.admission_sequence=self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
        self.assertEqual(value,self.capture.admission(self.store,{'financial_pins':PINS}))
        # These functions share one module/hash, but select different code.
        self.target.loader=other_private_loader
        with self.assertRaisesRegex(ValueError,'qualification'):
            self.capture.admission(self.store,{'financial_pins':PINS})
        self.target.loader=private_loader;self.target.request_stdin=False
        with self.assertRaisesRegex(ValueError,'qualification'):
            self.capture.admission(self.store,{'financial_pins':PINS})
        self.target.request_stdin=True;target['loader']['source_sha256']='0'*64
        value['reader_configuration_sha256']=digest(canonical(
            {'target':target,'member':self.member.configuration}).encode())
        self.store.event('normal_financial_collector_qualified',value)
        self.capture.admission_sequence=self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
        with self.assertRaisesRegex(ValueError,'qualification'):
            self.capture.admission(self.store,{'financial_pins':PINS})
    def test_factory_refuses_pending_hash_before_constructing_any_reader(self):
        from simulator.two_step_normal_factory import build_collector
        for member,tools in [({'pending_board_proof_sha256':'a'*64},{}),
                ({},{'pending':{'sha256':'a'*64}}),
                ({'pending_board_proof_sha256':'b'*64},{'pending':{'sha256':'a'*64}})]:
            with self.subTest(member=member,tools=tools),self.assertRaisesRegex(ValueError,'exact installed admitted'):
                build_collector(self.store,admission_sequence=self.sequence,boundary=self.boundary,
                    capture_configuration={},target_configuration={},member_configuration=member,tools=tools)
    def test_pool_config_requires_immutable_reader_and_collector_binding(self):
        self.member.configuration['ordinary_pool']={'classifier_sha256':'a'*64}
        self.value['reader_configuration_sha256']=digest(canonical({'target':{'command':list(self.target.command),
            'evidence_directory':str(self.target.evidence_directory),'timeout':45},'member':self.member.configuration}).encode())
        self.store.event('normal_financial_collector_qualified',self.value);self.capture.admission_sequence=self.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
        with self.assertRaisesRegex(ValueError,'qualification'):self.capture.admission(self.store,{'financial_pins':PINS})
        self.value['ordinary_pool']=copy.deepcopy(self.member.configuration['ordinary_pool'])
        self.store.event('normal_financial_collector_qualified',self.value);self.capture.admission_sequence=self.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
        self.capture.admission(self.store,{'financial_pins':PINS})
        self.member.configuration['ordinary_pool']['maximum_exit_depth']=999
        with self.assertRaisesRegex(ValueError,'qualification'):self.capture.admission(self.store,{'financial_pins':PINS})

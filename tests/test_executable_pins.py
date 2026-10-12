import hashlib,tempfile,unittest
from pathlib import Path
from simulator.config import verify_executables

class ExecutablePinTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.built=self.root/'built';self.installed=self.root/'installed'
        self.built.write_bytes(b'new-qualified-binary');self.installed.write_bytes(b'old-installed-binary')
        self.runtime={'active':True,'driver_command':[str(self.installed)],
            'observer_command':['observer','--driver',str(self.installed)]}
    def tearDown(self):self.tmp.cleanup()
    def digest(self,path):return hashlib.sha256(path.read_bytes()).hexdigest()
    def test_checking_build_output_does_not_qualify_installed_command(self):
        with self.assertRaises(ValueError):verify_executables(self.runtime,{str(self.built):self.digest(self.built)})
        with self.assertRaises(ValueError):verify_executables(self.runtime,{str(self.installed):self.digest(self.built)})
        self.installed.write_bytes(self.built.read_bytes())
        verify_executables(self.runtime,{str(self.installed):self.digest(self.built)})
    def test_observer_and_proof_must_use_the_pinned_executables_too(self):
        pins={str(self.installed):self.digest(self.installed)}
        self.runtime['proof_command']=[str(self.built),'rpc']
        with self.assertRaises(ValueError):verify_executables(self.runtime,pins)
        pins[str(self.built)]=self.digest(self.built);verify_executables(self.runtime,pins)
        self.runtime['observer_command']=['observer','--driver',str(self.root/'foreign')]
        with self.assertRaises(ValueError):verify_executables(self.runtime,pins)
    def test_observation_only_can_run_without_a_customer_driver(self):
        verify_executables({'active':False},{})
        with self.assertRaises(ValueError):verify_executables({'active':True},{})
    def test_symlink_cannot_redirect_an_installed_executable(self):
        link=self.root/'link';link.symlink_to(self.built)
        with self.assertRaises(ValueError):verify_executables({'active':True,'driver_command':[str(link)]},{str(link):self.digest(self.built)})

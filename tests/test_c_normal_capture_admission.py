"""Synthetic constructor admission only; no installed or collected source credit."""
import copy
import unittest
from pathlib import Path

from simulator.c_normal_profile_adapter import DirectPerKeyProfile
from simulator.c_normal_runtime_source import RuntimeSource
from simulator.c_normal_owning_join import OwningBinding
from simulator.c_normal_cln_join import ClnBinding
from simulator.c_normal_member_join import MemberBinding
from simulator.c_owning_wallet_source import FixedOwningReader
from simulator.c_cln_normal_source import FixedClnReads, ALIASES, native
from simulator.funding import WalletRpc
from simulator.two_step_capture import SourceCapture
from simulator.two_step_normal import digest,module_hash
from simulator.model import canonical
from simulator.ownership import EvidenceGap
from tests import test_c_normal_target_source as fixture


class Admission(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.f=fixture.CheckedTarget();self.f.setUp()
        for function,args,kwargs in self.f._cleanups:self.addCleanup(function,*args,**kwargs)
        self.f._cleanups.clear()
        runtime=RuntimeSource({'command':['/synthetic/inventory'],'command_files':{'/synthetic/inventory':'a'*64},
            'startup_path':'/synthetic/startup','startup_sha256':'b'*64,'expected_path':'/synthetic/expected',
            'expected_sha256':'c'*64,'schema_artifact_path':'/synthetic/schema','source_dir':'/synthetic/private'},1)
        owning=OwningBinding(FixedOwningReader({o:['/synthetic/ops','wallet-inventory',o]for o in ('rounds','watchman')},ops_sha256='d'*64),1)
        cln=ClnBinding(FixedClnReads({a:{m:['/synthetic/'+a,m]for m in native.METHODS}for a in ALIASES}),
            {'operator':'operator-cln','fixture_peer':'fixture-cln'},'e'*64,1)
        members=MemberBinding(str(self.f.f.root),{f'actor-{n:02}':f'actor-{n:02}'for n in range(1,13)},
            WalletRpc(Path('/synthetic/credential'),'Cbank'),1)
        self.profile=DirectPerKeyProfile(self.f.target,runtime=runtime,owning=owning,cln=cln,members=members)
        self.boundary={'synthetic_static_shape':'not an actual treasury declaration'}
        self.configuration={'boundary_sha256':digest(canonical(self.boundary).encode())}
        self.capture=SourceCapture(self.f.reader.read,None,1,self.boundary,self.configuration,native_profile=self.profile)
        self.admit()

    def admit(self,mutate=None):
        reader=self.f.reader
        actual={'target':{'command':list(reader.command),'evidence_directory':str(reader.evidence_directory),
            'timeout':reader.timeout,'request_stdin':True,'loader':{'module':reader.loader.__module__,
            'qualified_name':reader.loader.__qualname__,'source_sha256':module_hash(reader.loader)}},
            'member':self.profile.source_configuration()}
        value={'financial_pins':self.f.f.observation['financial_pins'],
            'reader_configuration_sha256':digest(canonical(actual).encode()),
            'capture_dependencies_sha256':{'target_reader':module_hash(self.f.reader.read),**self.profile.component_hashes()},
            'capture_configuration_sha256':digest(canonical(self.configuration).encode())}
        if mutate:mutate(value)
        self.f.store.event('normal_financial_collector_qualified',value)
        self.capture.admission_sequence=self.f.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
        return value

    async def test_C_static_admission_binds_actual_sources_without_A_B_helper(self):
        value=self.capture.admission(self.f.store,self.f.f.observation)
        self.assertNotIn('member_reader',value['capture_dependencies_sha256'])
        self.assertIn('c_member_join',value['capture_dependencies_sha256'])
        self.assertEqual('fixed_c_normal_sources',self.profile.source_configuration()['kind'])
        self.assertEqual([],self.f.calls)
        self.assertEqual(0,self.f.store.db.execute('SELECT count(*) FROM action').fetchone()[0])

    async def test_partial_C_bindings_refuse_instead_of_default_helper_or_empty_source(self):
        for name in ('runtime','owning','cln','members'):
            original=getattr(self.profile,name);setattr(self.profile,name,None)
            with self.subTest(name=name),self.assertRaisesRegex(EvidenceGap,'all fixed actual'):
                self.capture.admission(self.f.store,self.f.f.observation)
            setattr(self.profile,name,original)
        self.assertEqual([],self.f.calls)

    async def test_changed_private_constructor_never_matches_saved_admission(self):
        self.profile.cln.member_ids['operator']='other-owned-node'
        with self.assertRaisesRegex(ValueError,'qualification/configuration'):
            self.capture.admission(self.f.store,self.f.f.observation)
        self.assertEqual([],self.f.calls)

    async def test_opaque_instance_callback_never_executes_before_constructor_check(self):
        called=[]
        self.profile.source_configuration=lambda:called.append(True)
        with self.assertRaisesRegex(EvidenceGap,'all fixed actual'):
            self.capture.admission(self.f.store,self.f.f.observation)
        self.assertEqual([],called);self.assertEqual([],self.f.calls)

    async def test_unadmitted_target_constructor_metadata_is_rejected(self):
        self.profile.target.notes = 'synthetic-unadmitted-metadata'
        with self.assertRaisesRegex(EvidenceGap,'all fixed actual'):
            self.capture.admission(self.f.store,self.f.f.observation)
        self.assertEqual([],self.f.calls)

    async def test_A_B_member_helper_cannot_be_smuggled_into_C_capture(self):
        with self.assertRaisesRegex(ValueError,'do not use'):
            SourceCapture(self.f.reader.read,lambda *a:None,1,{}, {},native_profile=self.profile)

    async def test_manifest_or_saved_reader_configuration_cannot_pick_source_profile(self):
        self.admit(lambda v:v.update(reader_configuration_sha256='f'*64))
        with self.assertRaisesRegex(ValueError,'qualification/configuration'):
            self.capture.admission(self.f.store,self.f.f.observation)
        self.assertEqual([],self.f.calls)


if __name__=='__main__':unittest.main()

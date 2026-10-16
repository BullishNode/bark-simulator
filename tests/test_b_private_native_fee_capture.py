"""Owned synthetic filesystem/capture I/O only; no protected live proof."""
import copy
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from simulator import b_private_native_fee_capture as private
from simulator import b_normal_runtime_source as runtime
from simulator.b_final_native_profile import checked_owner_original,PRODUCT
from simulator.b_private_native_fee_inputs import AUXILIARY
from simulator.two_step_normal import digest
from simulator.ownership import EvidenceGap
import test_b_native_owner_snapshot as fixtures


def metadata(path):
    value=path.stat();return {**private._meta(value),'sha256':digest(path.read_bytes())}


class BoundFileControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.path=self.root/'ordinary-fee-budget'
        self.path.write_bytes(b'PRIVATE-SYNTHETIC-WITNESS\n');self.path.chmod(0o600)
    def test_actual_owned_regular_bytes_match_all_original_metadata(self):
        expected=metadata(self.path)
        self.assertEqual(private.bound_original(self.path,expected,100),self.path.read_bytes())
    def test_changed_digest_size_time_boolean_metadata_and_bound_refuse(self):
        for key,value in [('sha256','0'*64),('bytes',0),('mtime_ns',0),('inode',True)]:
            expected=metadata(self.path);expected[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):private.bound_original(self.path,expected,100)
        with self.assertRaises(ValueError):private.bound_original(self.path,metadata(self.path),2)
    def test_leaf_or_parent_symlink_and_nonregular_source_refuse(self):
        target=self.root/'alias';target.symlink_to(self.path)
        with self.assertRaises(OSError):private.bound_original(target,metadata(self.path),100)
        alias=self.root/'parent';alias.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(OSError):private.bound_original(alias/self.path.name,metadata(self.path),100)
        fifo=self.root/'fifo';os.mkfifo(fifo)
        value=fifo.stat();expected={**private._meta(value),'sha256':digest(b'')}
        with self.assertRaises(ValueError):private.bound_original(fifo,expected,100)
    def test_change_during_bounded_read_refuses_whole_file(self):
        expected=metadata(self.path);changed=[]
        def alter():
            if not changed:self.path.write_bytes(b'changed');changed.append(True)
        with patch.object(runtime,'_require_time',side_effect=alter),self.assertRaises(ValueError):
            private.bound_original(self.path,expected,100)


class PrivateCaptureControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.directory=self.root/'witness';self.directory.mkdir()
        for name in private.ROLES.values():(self.directory/name).write_bytes(('PRIVATE SYNTHETIC '+name).encode())
        self.binding={'source':'synthetic own temp mount'}
        self.budget={'files':{name:metadata(self.directory/name)for name in private.ROLES.values()},
            'source_mount_identity_sha256':runtime.identity(self.binding),'owner_snapshot_raw':'{"synthetic":true}\n'}
        self.expected={'data_mount':{'source':str(self.root)},'postgres_container':'own-synthetic-pg','database':'own_synthetic'}
        self.helper=SimpleNamespace(source_mount=lambda:(self.directory,self.binding),
            LIMITS={name:4096 for name in private.ROLES.values()})
        self.stdout=b'BEGIN\nSET\nDO\n{"kind":"closed_frontier","synthetic":true}\n{"native_funding_fee_intent":[]}\nCOMMIT\n'
    def capture(self,run=None):
        token=runtime._CAPTURE_END.set(time.monotonic()+20)
        try:
            with patch.object(runtime,'_expected'),patch.object(runtime,'_check_owner_budget'),\
                 patch.object(runtime,'_helper',return_value=self.helper),\
                 patch.object(runtime,'_run',side_effect=run or (lambda *a,**k:self.stdout))as command:
                value=private.capture_private_cut(self.expected,self.budget)
                return value,command.call_args
        finally:runtime._CAPTURE_END.reset(token)
    def test_exact_private_buffers_and_fixed_query_argv_do_not_create_public_receipt(self):
        value,call=self.capture();args,kwargs=call
        self.assertEqual(args[0],['/usr/bin/docker','exec','own-synthetic-pg','psql','-X','-A','-t',
            '-U','postgres','-d','own_synthetic','-v','ON_ERROR_STOP=1','-c',private.sql()])
        self.assertEqual(kwargs,{'maximum':2*1024*1024})
        self.assertEqual(value['raw_sql'],self.stdout.splitlines()[3]+b'\n')
        original=json.loads(value['auxiliary_originals']['b-native-fee-originals.json'])
        self.assertEqual(original['sql_raw'].encode(),self.stdout)
        for role,name in private.ROLES.items():self.assertEqual(original[role].encode(),(self.directory/name).read_bytes())
        self.assertEqual(value['auxiliary_originals']['b-native-fee-snapshot.json'],b'{"synthetic":true}\n')
        self.assertFalse({'complete','qualified','ready','loaded'}&set(value))
    def test_no_active_protected_loop_refuses_before_private_source_access(self):
        with patch.object(runtime,'_helper')as helper,self.assertRaisesRegex(ValueError,'bounded protected'):
            private.capture_private_cut(self.expected,self.budget)
        helper.assert_not_called()
    def test_sql_error_missing_bound_framing_and_oversize_refuse_whole_capture(self):
        def failed(*a,**k):raise ValueError('synthetic command refused')
        for run in (failed,lambda *a,**k:self.stdout.replace(b'DO\n',b''),lambda *a,**k:b'x'*(2*1024*1024+1)):
            with self.assertRaises(ValueError):self.capture(run)
    def test_journal_or_mount_change_around_query_refuses(self):
        def alter(*a,**k):
            (self.directory/'ordinary-fee-budget').write_bytes(b'changed');return self.stdout
        with self.assertRaises(ValueError):self.capture(alter)
        self.budget['files']['ordinary-fee-budget']=metadata(self.directory/'ordinary-fee-budget')
        self.helper.source_mount=lambda:(self.directory,{'source':'different'})
        with self.assertRaisesRegex(ValueError,'same owning mount'):self.capture()
    def test_protected_owner_stdout_cannot_be_replaced_by_equivalent_json(self):
        target,ctx,observation=fixtures.PrivateInputControls().inputs()
        ctx['product_commit']=ctx['execution_release']['product_commit']=PRODUCT
        raw=target['auxiliary_originals'][AUXILIARY['b_native_fee_snapshot']]
        ctx['native_budget'].update(owner_snapshot_raw=raw.decode(),owner_snapshot_raw_sha256=digest(raw),owner_snapshot=json.loads(raw))
        checked_owner_original(target,ctx)
        target['auxiliary_originals'][AUXILIARY['b_native_fee_snapshot']]=json.dumps(json.loads(raw),indent=2).encode()
        with self.assertRaisesRegex(EvidenceGap,'exact protected CLI original'):checked_owner_original(target,ctx)

import copy
import fcntl
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from simulator import b_normal_runtime_source as runtime


def fixture():
    h = 'a'*64
    pins = {name: ('b'*40 if name.endswith('commit') else h) for name in runtime.PINS}
    pins['image_sha256'] = 'sha256:'+h
    expected = {'execution_release': pins, 'containers': {n: 'owned-'+n for n in runtime.SERVICES},
        'binary_sha256': {n: h for n in runtime.SERVICES}, 'config_sha256': {n: h for n in runtime.SERVICES},
        'config_paths': {n: {'host': '/owned/'+n+'.toml', 'container': '/config/'+n+'.toml'} for n in runtime.SERVICES},
        'data_mount': {'source': '/owned/captaind', 'destination': '/data/captaind'},
        'budget_helper_path': '/opt/owned/reader.py', 'budget_helper_sha256': h,
        'accounting_receipt_path': '/opt/owned/accounting.json', 'load_gate_sources': dict(runtime.LOAD_GATES),
        'driver_artifact_sha256': h, 'postgres_container': 'owned-postgres', 'database': 'owned-db', 'canonical_schema_sha256': h}
    t = 1800000000*10**9
    meta = {'device': os.makedev(8, 1), 'inode': 44, 'bytes': 3, 'mtime_ns': t-3, 'ctime_ns': t-3, 'sha256': h}
    disk = {'policy_sha256': h, 'opening_sha256': h, 'budget_file_sha256': h, 'history_prefix_sha256': h,
            'accounting_receipt_sha256': h, **{k: False for k in ('runtime_loaded_identity_verified', 'retained_signed_fee_coverage_verified', 'urgent_selection_isolation_verified', 'complete', 'qualified')}}
    budget = {'disk_budget': disk, 'files': {n: dict(meta) for n in runtime.BUDGET_FILES},
              'history': {'prefix_sha256': h}, 'accounting_receipt_sha256': h, 'source_mount_identity_sha256': h}
    checkpoint = {'kind': 'b_runtime_before_start', 'observed_at_ns': t-2, 'expected_sha256': runtime.identity(expected),
                  'configs': {n: dict(meta) for n in runtime.SERVICES}, 'native_budget': copy.deepcopy(budget)}
    daemons = {n: {'container': expected['containers'][n], 'image_sha256': pins['image_sha256'],
                  'pid': 50+i, 'started_at': '2027-01-15T08:00:00Z', 'proc_start_ticks': 123,
                  'binary_sha256': h, 'process_exe_sha256': h, 'config_sha256': h, 'restart_count': 0,
                  **{'config_'+k: meta[k] for k in ('device', 'inode', 'ctime_ns', 'mtime_ns')}}
               for i, n in enumerate(runtime.SERVICES)}
    # Exact epoch above is intentionally computed from the actual UTC parser.
    started = runtime._time_ns(daemons['watchmand']['started_at'])
    for d in daemons.values():
        for k in ('ctime_ns', 'mtime_ns'): d['config_'+k] = started-3
    for d in checkpoint['configs'].values(): d.update(ctime_ns=started-3, mtime_ns=started-3)
    for d in budget['files'].values(): d.update(ctime_ns=started-3, mtime_ns=started-3)
    checkpoint['native_budget'] = copy.deepcopy(budget); checkpoint['observed_at_ns'] = started-2
    lock = {'pid': 51, 'fd': 5, 'device': meta['device'], 'inode': 44,
            'lock_line': 'lock:\t1: FLOCK  ADVISORY  WRITE 51 08:01:44 0 EOF', 'fdinfo_sha256': h}
    observation = {'started_at_ns': started+1, 'completed_at_ns': started+2,
        'before': daemons, 'after': copy.deepcopy(daemons), 'native_budget': budget, 'native_budget_after': copy.deepcopy(budget),
        'budget_lock': lock, 'budget_lock_after': dict(lock), 'admin_responses': {n: h for n in runtime.SERVICES},
        'canonical_schema_sha256': h, 'canonical_schema_repeat_sha256': h}
    return expected, checkpoint, observation


class RuntimeTests(unittest.TestCase):
    def check(self, args):
        return runtime.verify(*args, now_ns=args[2]['completed_at_ns']+1)

    def test_same_process_budget_lock_source_scope(self):
        result = self.check(fixture())
        self.assertTrue(result['loaded_configuration_identity_verified'])
        self.assertFalse(result['complete']); self.assertFalse(result['qualified'])
        self.assertFalse(result['retained_signed_fee_coverage_verified'])
        self.assertFalse(result['urgent_selection_isolation_verified'])

    def test_old_live_image_not_relabelled(self):
        args = fixture(); args[2]['before']['watchmand']['image_sha256'] = 'sha256:'+'c'*64
        args[2]['after'] = copy.deepcopy(args[2]['before'])
        with self.assertRaisesRegex(ValueError, 'artifact'): self.check(args)

    def test_missing_budget_is_not_loaded(self):
        args = fixture(); del args[2]['native_budget']
        with self.assertRaises((ValueError, KeyError)): self.check(args)

    def test_restarted_process_refused(self):
        args = fixture(); args[2]['after']['watchmand']['pid'] += 1
        with self.assertRaisesRegex(ValueError, 'same actual'): self.check(args)

    def test_changed_process_start_refused(self):
        args = fixture(); args[2]['after']['watchmand']['proc_start_ticks'] += 1
        with self.assertRaisesRegex(ValueError, 'same actual'): self.check(args)

    def test_checkpoint_after_start_refused(self):
        args = fixture(); args[1]['observed_at_ns'] = args[2]['started_at_ns']
        with self.assertRaisesRegex(ValueError, 'pre-start'): self.check(args)

    def test_post_start_config_change_refused(self):
        args = fixture(); args[2]['before']['captaind']['config_inode'] += 1
        args[2]['after'] = copy.deepcopy(args[2]['before'])
        with self.assertRaisesRegex(ValueError, 'configuration changed'): self.check(args)

    def test_schema_drift_refused(self):
        args = fixture(); args[2]['canonical_schema_repeat_sha256'] = 'd'*64
        with self.assertRaisesRegex(ValueError, 'schema'): self.check(args)

    def test_policy_replaced_after_checkpoint_refused(self):
        args = fixture(); args[2]['native_budget']['files']['ordinary-fee-policy.json']['inode'] += 1
        args[2]['native_budget_after'] = copy.deepcopy(args[2]['native_budget'])
        with self.assertRaisesRegex(ValueError, 'policy/opening'): self.check(args)

    def test_ledger_change_during_capture_refused(self):
        args = fixture(); args[2]['native_budget_after']['files']['ordinary-fee-budget']['sha256'] = 'c'*64
        with self.assertRaisesRegex(ValueError, 'changed during'): self.check(args)

    def test_foreign_lock_pid_refused(self):
        args = fixture(); args[2]['budget_lock']['lock_line'] = args[2]['budget_lock']['lock_line'].replace('WRITE 51', 'WRITE 52')
        with self.assertRaisesRegex(ValueError, 'FLOCK'): self.check(args)

    def test_wrong_lock_inode_refused(self):
        args = fixture(); args[2]['budget_lock']['lock_line'] = args[2]['budget_lock']['lock_line'].replace(':44 ', ':45 ')
        with self.assertRaisesRegex(ValueError, 'FLOCK'): self.check(args)

    def test_read_lock_and_partial_lock_refused(self):
        raw = fixture()[2]['budget_lock']['lock_line']
        for changed in (raw.replace('WRITE', 'READ'), raw.replace('0 EOF', '0 500'), raw.replace('FLOCK', 'POSIX')):
            with self.assertRaisesRegex(ValueError, 'FLOCK'): runtime.parse_flock(changed, pid=51, device=os.makedev(8,1), inode=44)

    def test_disk_loaded_flag_cannot_substitute_proof(self):
        args = fixture(); args[2]['native_budget']['disk_budget']['runtime_loaded_identity_verified'] = True
        args[2]['native_budget_after'] = copy.deepcopy(args[2]['native_budget'])
        with self.assertRaisesRegex(ValueError, 'disk labels'): self.check(args)

    def test_original_history_and_receipt_required(self):
        for key in ('history_prefix_sha256', 'accounting_receipt_sha256'):
            args = fixture(); args[2]['native_budget']['disk_budget'][key] = 'd'*64
            args[2]['native_budget_after'] = copy.deepcopy(args[2]['native_budget'])
            with self.assertRaisesRegex(ValueError, 'original history'): self.check(args)

    def test_missing_admin_result_refused(self):
        args = fixture(); args[2]['admin_responses']['watchmand'] = None
        with self.assertRaisesRegex(ValueError, 'SHA256'): self.check(args)

    def test_reviewed_load_gate_required(self):
        args = fixture(); args[0]['load_gate_sources']['server/src/watchman/daemon.rs'] = 'f'*64
        with self.assertRaisesRegex(ValueError, 'mandatory-load'): self.check(args)

    def test_source_file_no_follow_and_prefix_hash(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'history'; path.write_bytes(b'originalnew')
            actual = runtime._file(path, 100, 8)
            self.assertEqual(actual['prefix_sha256'], runtime.digest(b'original'))
            alias = Path(root)/'alias'; alias.symlink_to(path)
            with self.assertRaises(OSError): runtime._file(alias, 100)
            with self.assertRaises(ValueError): runtime._file(path, 3)

    def test_actual_isolated_fdinfo_flock_parser(self):
        # Isolated test fixture only; the production capture never acquires a lock.
        with tempfile.TemporaryFile() as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            info = os.fstat(stream.fileno())
            raw = Path(f'/proc/self/fdinfo/{stream.fileno()}').read_text()
            line = runtime.parse_flock(raw, pid=os.getpid(), device=info.st_dev, inode=info.st_ino)
            self.assertIn('FLOCK', line)
            with self.assertRaises(ValueError): runtime.parse_flock(raw, pid=os.getpid()+1, device=info.st_dev, inode=info.st_ino)

    def test_actual_capture_rejects_old_image_before_budget(self):
        args = fixture()
        old = {'State': {'Running': True, 'Pid': 99}, 'Image': 'sha256:'+'0'*64}
        with patch.object(runtime, '_inspect', return_value=old):
            with self.assertRaisesRegex(ValueError, 'current daemon image'): runtime._daemon(args[0], 'watchmand')

class BudgetCaptureTests(unittest.TestCase):
    def test_budget_capture_authenticates_history_receipt_and_mount(self):
        import types
        with tempfile.TemporaryDirectory() as root:
            parent = Path(root); directory = parent/'direct-expiry-witness'; directory.mkdir()
            files = {n: (str(i)+'\n').encode() for i,n in enumerate(runtime.BUDGET_FILES)}
            for n, raw in files.items(): (directory/n).write_bytes(raw)
            (directory/'history').write_bytes(b'oldnew'); receipt=parent/'receipt'; receipt.write_bytes(b'actual')
            projection = {'policy_sha256': runtime.digest(files[runtime.BUDGET_FILES[0]]),
                'opening_sha256': runtime.digest(files[runtime.BUDGET_FILES[1]]),
                'budget_file_sha256': runtime.digest(files[runtime.BUDGET_FILES[2]]),
                'history_prefix_bytes': 3, 'history_prefix_sha256': runtime.digest(b'old'),
                'accounting_receipt_sha256': runtime.digest(b'actual')}
            helper = types.SimpleNamespace(source_mount=lambda:(directory,{'source':str(parent)}),
                read_directory=lambda _:dict(projection), LIMITS={n:100 for n in files})
            expected={'data_mount':{'source':str(parent)},'accounting_receipt_path':str(receipt)}
            actual=runtime._budget(expected,helper)
            self.assertEqual(actual['history']['prefix_sha256'],runtime.digest(b'old'))
            receipt.write_bytes(b'other')
            with self.assertRaisesRegex(ValueError,'accounting receipt'): runtime._budget(expected,helper)

    def test_capture_held_budget_inode_uses_actual_fd(self):
        with tempfile.TemporaryFile() as stream:
            fcntl.flock(stream,fcntl.LOCK_EX)
            info=os.fstat(stream.fileno())
            actual=runtime._lock(os.getpid(),{'device':info.st_dev,'inode':info.st_ino})
            self.assertEqual(actual['fd'],stream.fileno())
            fcntl.flock(stream,fcntl.LOCK_UN)
            with self.assertRaisesRegex(ValueError,'FLOCK'): runtime._lock(os.getpid(),{'device':info.st_dev,'inode':info.st_ino})

    def test_protected_sources_required_before_capture(self):
        with patch.object(runtime,'checked_file',side_effect=ValueError('root-owned immutable installed file required')):
            with self.assertRaisesRegex(ValueError,'root-owned'): runtime.capture_protected('/tmp/expected','/tmp/checkpoint')

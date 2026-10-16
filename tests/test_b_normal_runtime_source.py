import copy
import fcntl
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from simulator import b_normal_runtime_source as runtime



def configuration_bytes(service):
    common = 'admin_address = "0.0.0.0:3538"\nnetwork = "regtest"\n[fee_estimator]\nmax_fee_rate = "5000sat/kwu"\n'
    policy = 'urgent_reserve_sat = 15000\nordinary_budget_sat = 60000\nexternal_future_reserved_sat = 17622\nopening_sha256 = "'+'a'*64+'"\n'
    if service == 'watchmand':
        return (common+'[watchman.direct_expiry]\nmax_miner_fee = "0.00010000 BTC"\n[watchman.direct_expiry.ordinary_fee_policy]\n'+policy).encode()
    return ('admin_address = "127.0.0.1:3536"\nnative_funding_owner_address = "192.0.2.20:3538"\nnetwork = "regtest"\nvtxo_lifetime = 48\nvtxo_exit_delta = 12\nhtlc_expiry_delta = 6\nhtlc_send_expiry_delta = 258\nln_max_fee_ppm = 900000\nprivate_credential = "DO-NOT-EXPORT"\n[fee_estimator]\nmax_fee_rate = "20sat/vb"\n[direct_expiry]\nenabled = true\ngrace_blocks = 6\n[expiry_payout]\nenabled = false\n[direct_expiry_fee_policy]\n'+policy+'[vtxopool]\nvtxo_targets = ["10000sat:24"]\nvtxo_target_issue_threshold = 80\nvtxo_lifetime = 48\nvtxo_pre_expiry = 12\nmax_vtxo_exit_depth = 50\n').encode()


def fixture():
    h = 'a'*64
    pins = {name: ('b'*40 if name.endswith('commit') else h) for name in runtime.PINS}
    pins['image_sha256'] = 'sha256:'+h
    pins['product_commit'] = pins['sdk_commit'] = runtime.POLICY_PRODUCT_COMMIT
    expected = {'execution_release': pins, 'containers': {n: 'owned-'+n for n in runtime.SERVICES},
        'binary_sha256': {n: h for n in runtime.SERVICES}, 'config_sha256': {n: h for n in runtime.SERVICES},
        'config_paths': {n: {'host': '/owned/'+n+'.toml', 'container': '/config/'+n+'.toml'} for n in runtime.SERVICES},
        'data_mount': {'source': '/owned/captaind', 'destination': '/data/captaind'},
        'budget_helper_path': '/opt/owned/reader.py', 'budget_helper_sha256': runtime.BUDGET_HELPER_SHA256,
        'accounting_receipt_path': '/opt/owned/accounting.json', 'load_gate_sources': dict(runtime.LOAD_GATES),
        'driver_artifact_sha256': h, 'postgres_container': 'owned-postgres', 'database': 'owned-db', 'canonical_schema_sha256': h}
    t = 1800000000*10**9
    meta = {'device': os.makedev(8, 1), 'inode': 44, 'bytes': 3, 'mtime_ns': t-3, 'ctime_ns': t-3, 'sha256': h}
    owner={'schema':1,'policy_sha256':h,'opening_sha256':h,'journal_sha256':h,
        'journal_device':meta['device'],'journal_inode':meta['inode'],'journal_bytes':meta['bytes'],
        'policy':{'urgent_reserve_sat':15000,'ordinary_budget_sat':60000,'external_future_reserved_sat':17622,'opening_sha256':h},
        'opening':{'version':1,'network':'regtest','genesis':h,'server_pubkey':'02'+'b'*64,'history_prefix_bytes':65,
            'history_prefix_sha256':h,'native_spent_sat':4985,'external_spent_sat':3257,'accounting_receipt_sha256':h},
        'charged_sat':25864,'remaining_total_sat':34136,'urgent_remaining_sat':15000,'discretionary_remaining_sat':19136,
        'direct_attempt_count':0,'direct_reserved_sat':0,'funding_reserved_sat':0,'round_reserved_sat':0,'pool_reserved_sat':0,
        'urgent_reserved_sat':0,'funding':[],'urgent':[],'resolutions':[]}
    raw=json.dumps(owner)+'\n'
    budget={'owner_snapshot':owner,'owner_snapshot_raw':raw,'owner_snapshot_raw_sha256':runtime.digest(raw.encode()),
        'files':{n:dict(meta)for n in runtime.BUDGET_FILES},'history':{'prefix_sha256':h,'prefix_bytes':65},
        'accounting_receipt_sha256':h,'source_mount_identity_sha256':h}
    checkpoint = {'kind': 'b_runtime_before_start', 'observed_at_ns': t-2, 'expected_sha256': runtime.identity(expected),
                  'configs': {n: dict(meta) for n in runtime.SERVICES}, 'native_budget': copy.deepcopy(budget)}
    daemons = {n: {'container': expected['containers'][n], 'image_sha256': pins['image_sha256'],
                  'pid': 50+i, 'started_at': '2027-01-15T08:00:00Z', 'proc_start_ticks': 123,
                  'binary_sha256': h, 'process_exe_sha256': h, 'config_sha256': h, 'restart_count': 0,
                  **{'config_'+k: meta[k] for k in ('device', 'inode', 'ctime_ns', 'mtime_ns')}}
               for i, n in enumerate(runtime.SERVICES)}
    for name in runtime.SERVICES:
        projection=runtime.public_configuration(configuration_bytes(name),name)
        checkpoint['configs'][name]['public_configuration']=projection
        daemons[name]['public_configuration']=copy.deepcopy(projection)
        daemons[name]['networks']=[{'network_id':h,'address':'192.0.2.10'if name=='captaind'else'192.0.2.20'}]
    # Exact epoch above is intentionally computed from the actual UTC parser.
    started = runtime._time_ns(daemons['watchmand']['started_at'])
    for d in daemons.values():
        for k in ('ctime_ns', 'mtime_ns'): d['config_'+k] = started-3
    for d in checkpoint['configs'].values(): d.update(ctime_ns=started-3, mtime_ns=started-3)
    for d in budget['files'].values(): d.update(ctime_ns=started-3, mtime_ns=started-3)
    checkpoint['native_budget'] = copy.deepcopy(budget); checkpoint['observed_at_ns'] = started-2
    lock = {'pid': 51, 'fd': 5, 'device': meta['device'], 'inode': 44,
            'lock_line': 'lock:\t1: FLOCK  ADVISORY  WRITE 51 08:01:44 0 EOF', 'fdinfo_sha256': h}
    observation = {'started_at_ns': started+1, 'completed_at_ns': started+2, 'elapsed_ns': 1,
        'before': daemons, 'after': copy.deepcopy(daemons), 'native_budget': budget, 'native_budget_after': copy.deepcopy(budget),
        'budget_lock': lock, 'budget_lock_after': dict(lock), 'admin_responses': {n: h for n in runtime.SERVICES},
        'canonical_schema_sha256': h, 'canonical_schema_repeat_sha256': h}
    route={'cap_pid':50,'watch_pid':51,'destination':daemons['captaind']['public_configuration']['native_funding_owner_address'],
        'listener':daemons['watchmand']['public_configuration']['admin_address'],'network_namespaces':{'captaind':'net:[100]','watchmand':'net:[101]'},
        'shared_network_id':h,'watch_listener':{'fd':7,'inode':55,'tcp_table_sha256':h}}
    observation.update(owner_route=route,owner_route_after=copy.deepcopy(route))
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

    def test_supplied_ready_field_cannot_substitute_native_reply(self):
        args=fixture();owner=args[2]['native_budget']['owner_snapshot'];owner['ready']=True
        raw=json.dumps(owner);args[2]['native_budget'].update(owner_snapshot_raw=raw,owner_snapshot_raw_sha256=runtime.digest(raw.encode()))
        args[2]['native_budget_after']=copy.deepcopy(args[2]['native_budget'])
        with self.assertRaisesRegex(ValueError,'complete native owner'):self.check(args)

    def test_original_history_and_receipt_required(self):
        for key in ('history_prefix_sha256','accounting_receipt_sha256'):
            args=fixture();owner=args[2]['native_budget']['owner_snapshot'];owner['opening'][key]='d'*64
            raw=json.dumps(owner);args[2]['native_budget'].update(owner_snapshot_raw=raw,owner_snapshot_raw_sha256=runtime.digest(raw.encode()))
            args[2]['native_budget_after']=copy.deepcopy(args[2]['native_budget'])
            with self.assertRaisesRegex(ValueError,'history/accounting'):self.check(args)

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
            parent=Path(root);directory=parent/'direct-expiry-witness';directory.mkdir()
            receipt=parent/'receipt';receipt.write_bytes(b'actual')
            owner=copy.deepcopy(fixture()[2]['native_budget']['owner_snapshot'])
            owner['opening'].update(accounting_receipt_sha256=runtime.digest(b'actual'),history_prefix_sha256=runtime.digest(b'a'*64+b'\n'))
            opening=json.dumps(owner['opening']).encode();owner['opening_sha256']=runtime.digest(opening)
            owner['policy']['opening_sha256']=owner['opening_sha256'];policy=json.dumps({'policy':owner['policy'],'opening_sha256':owner['opening_sha256']}).encode()
            files={'ordinary-fee-policy.json':policy,'ordinary-fee-opening.json':opening,'ordinary-fee-budget':b''}
            for name,raw in files.items():(directory/name).write_bytes(raw)
            (directory/'history').write_bytes(b'a'*64+b'\n'+b'b'*64+b'\n')
            meta=runtime._file(directory/'ordinary-fee-budget',2048)
            owner.update(policy_sha256=runtime.digest(policy),journal_sha256=runtime.digest(b''),journal_device=meta['device'],journal_inode=meta['inode'],journal_bytes=0)
            raw=json.dumps(owner)+'\n'
            helper=types.SimpleNamespace(source_mount=lambda:(directory,{'source':str(parent)}),LIMITS={name:2048 for name in files},read_directory=lambda _:self.fail('old fee grammar was invoked'))
            expected={'data_mount':{'source':str(parent)},'accounting_receipt_path':str(receipt)}
            with patch.object(runtime,'_owner_snapshot',return_value=(owner,raw))as rpc:
                actual=runtime._budget(expected,helper)
                self.assertEqual(actual['history']['prefix_sha256'],runtime.digest(b'a'*64+b'\n'))
                self.assertEqual(actual['owner_snapshot_raw'],raw);rpc.assert_called_once_with(expected)
            with patch.object(runtime,'_owner_snapshot')as rpc:
                checkpoint=runtime._budget(expected,helper,before_start=True)
                self.assertNotIn('owner_snapshot',checkpoint);rpc.assert_not_called()
            receipt.write_bytes(b'other')
            with self.assertRaisesRegex(ValueError,'accounting receipt'):runtime._budget(expected,helper)

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

class BoundedCaptureTests(unittest.TestCase):
    def test_stdout_stops_before_writer_finishes(self):
        import sys
        with tempfile.TemporaryDirectory() as root:
            marker=Path(root)/'progress'
            script="import os,pathlib; p=pathlib.Path("+repr(str(marker))+"); [(os.write(1,b'x'*4096),p.open('ab').write(b'x')) for i in range(768)]"
            with self.assertRaises(ValueError): runtime._run([sys.executable,'-c',script],maximum=1024)
            self.assertLess(marker.stat().st_size if marker.exists() else 0,32)

    def test_stderr_stops_before_writer_finishes(self):
        import sys
        with tempfile.TemporaryDirectory() as root:
            marker=Path(root)/'progress'
            script="import os,pathlib; p=pathlib.Path("+repr(str(marker))+"); [(os.write(2,b'x'*4096),p.open('ab').write(b'x')) for i in range(768)]"
            with self.assertRaises(ValueError): runtime._run([sys.executable,'-c',script])
            self.assertLess(marker.stat().st_size if marker.exists() else 0,64)

    def test_deadline_stops_verified_descendants_and_reaps_direct_command(self):
        import subprocess,sys,time
        original=subprocess.Popen; created=[]
        def track(*a,**kw):
            process=original(*a,**kw);created.append(process);return process
        with tempfile.TemporaryDirectory() as root:
            marker=Path(root)/'child'
            script="import subprocess,sys,time,pathlib; p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(20)']); pathlib.Path("+repr(str(marker))+").write_text(str(p.pid)); time.sleep(20)"
            with patch.object(runtime.subprocess,'Popen',side_effect=track):
                with self.assertRaisesRegex(ValueError,'deadline'): runtime._run([sys.executable,'-c',script],timeout=2)
            self.assertEqual(len(created),1);self.assertIsNotNone(created[0].returncode)
            with self.assertRaises(ChildProcessError): os.waitpid(created[0].pid,os.WNOHANG)
            child=int(marker.read_text())
            for _ in range(100):
                path=Path('/proc')/str(child)/'stat'
                if not path.exists() or path.read_text().rsplit(')',1)[1].split()[0]=='Z':break
                time.sleep(.01)
            else:self.fail('owned descendant remained running after deadline')

    def test_capture_duration_cannot_borrow_fresh_completion(self):
        args=fixture();args[2]['completed_at_ns']=args[2]['started_at_ns']+61*10**9;args[2]['elapsed_ns']=61*10**9
        with self.assertRaisesRegex(ValueError,'duration'): runtime.verify(*args,now_ns=args[2]['completed_at_ns'])

    def test_monotonic_capture_bound_independent_of_wall_clock(self):
        args=fixture();args[2]['elapsed_ns']=61*10**9
        with self.assertRaisesRegex(ValueError,'duration'): runtime.verify(*args,now_ns=args[2]['completed_at_ns'])

    def test_public_canonical_history_projection(self):
        raw=b'a'*64+b'\n'+b'b'*64+b'\n'
        self.assertEqual(runtime.history_txids(raw,65),['a'*64,'b'*64])
        self.assertEqual(runtime.history_txids(b'',0),[])

    def test_history_rejects_duplicate_torn_uppercase_and_outofbound(self):
        for raw,prefix in ((b'a'*64+b'\n'+b'a'*64+b'\n',65),(b'a'*64,0),(b'A'*64+b'\n',65),(b'a'*64+b'\n',64),(b'a'*64+b'\n',130),(b'a'*650001,0)):
            with self.assertRaises(ValueError): runtime.history_txids(raw,prefix)


class AggregateDeadlineTests(unittest.TestCase):
    def test_shared_deadline_interrupts_command_before_own_eight_seconds(self):
        import sys,time
        token=runtime._CAPTURE_END.set(time.monotonic()+.5)
        started=time.monotonic()
        try:
            with self.assertRaisesRegex(ValueError,'deadline'):
                runtime._run([sys.executable,'-c','import time;time.sleep(10)'])
        finally:runtime._CAPTURE_END.reset(token)
        self.assertLess(time.monotonic()-started,2)

    def test_expired_shared_deadline_refuses_before_new_command(self):
        import time
        token=runtime._CAPTURE_END.set(time.monotonic()-1)
        try:
            with patch.object(runtime.subprocess,'Popen')as spawn:
                with self.assertRaisesRegex(ValueError,'aggregate'):runtime._run(['/usr/bin/true'])
                spawn.assert_not_called()
        finally:runtime._CAPTURE_END.reset(token)


class OwnedPidTests(unittest.TestCase):
    def test_changed_pid_startticks_never_receives_signal(self):
        actual=runtime._process_identity(os.getpid()); changed=dict(actual);changed['start_ticks']-=1
        with patch.object(runtime.signal,'pidfd_send_signal')as send:
            with self.assertRaisesRegex(ValueError,'identity changed'):runtime._signal_owned(changed,runtime.signal.SIGSTOP)
            send.assert_not_called()

    def test_bounded_successful_command_keeps_exact_output(self):
        import sys
        self.assertEqual(runtime._run([sys.executable,'-c',"print('owned',end='')"]),b'owned')


class CaptureCleanupRegressionTests(unittest.TestCase):
    def run_tracked(self, body):
        import subprocess
        original = subprocess.Popen; created = []
        def track(*args, **kwargs):
            process = original(*args, **kwargs); created.append(process); return process
        with patch.object(runtime.subprocess, 'Popen', side_effect=track):
            body()
        self.assertEqual(len(created), 1)
        process = created[0]
        self.assertIsNotNone(process.returncode)
        self.assertTrue(process.stdout.closed); self.assertTrue(process.stderr.closed)
        with self.assertRaises(ChildProcessError): os.waitpid(process.pid, os.WNOHANG)

    def test_identity_setup_exception_reaps_direct_child(self):
        import sys
        def body():
            with patch.object(runtime, '_process_identity', side_effect=ValueError('identity setup failed')):
                with self.assertRaisesRegex(ValueError, 'identity setup'):
                    runtime._run([sys.executable, '-c', 'import time; time.sleep(10)'])
        self.run_tracked(body)

    def test_selector_setup_exception_still_cleans_command(self):
        import sys
        def body():
            with patch.object(runtime.selectors, 'DefaultSelector', side_effect=ValueError('selector setup failed')):
                with self.assertRaisesRegex(ValueError, 'selector setup'):
                    runtime._run([sys.executable, '-c', 'import time; time.sleep(10)'])
        self.run_tracked(body)

    def test_cleanup_exception_does_not_skip_pipe_closes(self):
        import sys
        original = runtime._stop_command
        def stop(*args):
            original(*args)
            raise ValueError('cleanup receipt failed')
        def body():
            with patch.object(runtime, '_stop_command', side_effect=stop):
                with self.assertRaisesRegex(ValueError, 'cleanup receipt'):
                    runtime._run([sys.executable, '-c', 'pass'])
        self.run_tracked(body)

    def test_initial_cleanup_signal_failure_still_reaps_direct_child(self):
        import sys
        def body():
            with patch.object(runtime, '_stop_command', side_effect=ValueError('initial stop failed')):
                with self.assertRaisesRegex(ValueError, 'initial stop'):
                    runtime._run([sys.executable, '-c', 'import time; time.sleep(10)'])
        self.run_tracked(body)

    def test_discovery_failure_still_reaps_direct_child(self):
        import sys
        def body():
            with patch.object(runtime, '_command_descendants', side_effect=ValueError('discovery bound')):
                with self.assertRaisesRegex(ValueError, 'discovery bound'):
                    runtime._run([sys.executable, '-c', 'pass'])
        self.run_tracked(body)

    def test_process_discovery_checks_deadline_and_entry_bound(self):
        import time
        root = runtime._process_identity(os.getpid())
        with self.assertRaisesRegex(ValueError, 'discovery bound'):
            runtime._command_descendants(root, end=time.monotonic()-1)
        with patch.object(runtime, 'MAX_PROCESS_ENTRIES', 0):
            with self.assertRaisesRegex(ValueError, 'discovery bound'):
                runtime._command_descendants(root, end=time.monotonic()+1)

    def test_process_metadata_reads_only_limit_plus_one(self):
        import io
        class Source(io.BytesIO):
            def read(self, size=-1):
                self.requested = size
                return super().read(size)
        stream = Source(b'x'*20)
        with patch('builtins.open', return_value=stream):
            with self.assertRaisesRegex(ValueError, 'bounded process metadata'):
                runtime._proc_bytes('/owned/test', 8)
        self.assertEqual(stream.requested, 9)

    def test_running_executable_digest_checks_size_before_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'owned-elf'; path.write_bytes(b'12345678')
            with patch.object(runtime, 'MAX_EXECUTABLE_BYTES', 8):
                self.assertEqual(runtime._executable_digest(path), runtime.digest(b'12345678'))
                path.write_bytes(b'123456789')
                with self.assertRaisesRegex(ValueError, 'executable size'):
                    runtime._executable_digest(path)


class NativeOwnerReplyTests(unittest.TestCase):
    def verify(self,args):return runtime.verify(*args,now_ns=args[2]['completed_at_ns'])

    def test_actual_raw_reply_hash_is_required(self):
        args=fixture();args[2]['native_budget']['owner_snapshot_raw']+=' '
        with self.assertRaisesRegex(ValueError,'original native owner reply'):self.verify(args)

    def test_foreign_same_length_journal_or_wrong_inode_refuses(self):
        for key,value in [('journal_sha256','d'*64),('journal_inode',45),('journal_bytes',4)]:
            args=fixture();budget=args[2]['native_budget'];budget['owner_snapshot'][key]=value
            raw=json.dumps(budget['owner_snapshot']);budget.update(owner_snapshot_raw=raw,owner_snapshot_raw_sha256=runtime.digest(raw.encode()))
            with self.assertRaisesRegex(ValueError,'native owner'):self.verify(args)

    def test_unknown_or_duplicate_top_level_reply_refuses(self):
        raw=fixture()[2]['native_budget']['owner_snapshot_raw']
        for bad in [raw[:-2]+',"extra":true}',raw[:-2]+',"schema":1}']:
            with self.assertRaises(ValueError):runtime._owner_document(bad)

    def test_missing_owner_reply_cannot_borrow_disk_projection(self):
        args=fixture();del args[2]['native_budget']['owner_snapshot']
        args[2]['native_budget']['disk_budget']={'complete':True}
        with self.assertRaises(KeyError):self.verify(args)

    def test_native_public_projection_not_python_reparsed_journal(self):
        args=fixture();result=self.verify(args)
        self.assertNotIn('disk_budget',result['native_budget']);self.assertNotIn('public_ledger',result['native_budget'])
        self.assertFalse(result['complete'])




class PublicConfigurationTests(unittest.TestCase):
    def test_same_actual_config_bytes_hash_and_whitelist_only(self):
        import json
        for service in runtime.SERVICES:
            raw=configuration_bytes(service)
            with tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'config';path.write_bytes(raw)
                actual=runtime._file(path,2*1024*1024,configuration_service=service)
                self.assertEqual(actual['sha256'],runtime.digest(raw))
                self.assertEqual(actual['public_configuration'],runtime.public_configuration(raw,service))
                self.assertNotIn('DO-NOT-EXPORT',json.dumps(actual))
        cap=runtime.public_configuration(configuration_bytes('captaind'),'captaind')
        self.assertEqual(cap['fee_estimator_max_sat_kwu'],5000)
        self.assertEqual(cap['vtxopool']['targets'],[{'amount_sat':10000,'count':24}])
        self.assertNotIn('fee_ceilings_sat_kvb',cap)

    def test_fee_encodings_match_supported_native_integer_rounding(self):
        self.assertEqual(runtime._public_rate('20sat/vb'),5000)
        self.assertEqual(runtime._public_rate('20001sat/kvb'),5001)
        self.assertEqual(runtime._public_amount('0.00010000 BTC'),10000)
        self.assertIsNone(runtime._public_rate(None))
        for bad in [True,'1.5sat/vb','-1sat/kwu','18446744073709551615sat/vb']:
            with self.assertRaises(ValueError):runtime._public_rate(bad)
        for bad in ['0.1sat','NaN BTC','1MSAT','21000001 BTC']:
            with self.assertRaises(ValueError):runtime._public_amount(bad)

    def test_missing_cap_rate_is_honest_absence_not_a_ceiling(self):
        raw=configuration_bytes('captaind').replace(b'max_fee_rate = "20sat/vb"\n',b'')
        self.assertIsNone(runtime.public_configuration(raw,'captaind')['fee_estimator_max_sat_kwu'])

    def test_missing_or_foreign_policy_cannot_borrow_defaults(self):
        raw=configuration_bytes('captaind')
        for changed in [raw.replace(b'opening_sha256',b'unsupported_opening'),raw.replace(b'urgent_reserve_sat = 15000',b'urgent_reserve_sat = true')]:
            with self.assertRaises(ValueError):runtime.public_configuration(changed,'captaind')

    def test_projection_tamper_and_disk_policy_mismatch_refuse(self):
        args=fixture();args[2]['before']['captaind']['public_configuration']['ln_max_fee_ppm']+=1
        args[2]['after']=copy.deepcopy(args[2]['before'])
        with self.assertRaisesRegex(ValueError,'same-byte'):runtime.verify(*args,now_ns=args[2]['completed_at_ns']+1)
        args=fixture();budget=args[2]['native_budget'];budget['owner_snapshot']['policy']['ordinary_budget_sat']+=1
        raw=json.dumps(budget['owner_snapshot']);budget.update(owner_snapshot_raw=raw,owner_snapshot_raw_sha256=runtime.digest(raw.encode()));args[2]['native_budget_after']=copy.deepcopy(budget)
        with self.assertRaisesRegex(ValueError,'same native owner'):runtime.verify(*args,now_ns=args[2]['completed_at_ns']+1)

    def test_policy_projection_stays_false_for_financial_scope(self):
        args=fixture();out=runtime.verify(*args,now_ns=args[2]['completed_at_ns']+1)
        self.assertEqual(out['public_configuration']['product_commit'],runtime.POLICY_PRODUCT_COMMIT)
        self.assertEqual(out['public_configuration']['config_sha256'],args[0]['config_sha256'])
        self.assertFalse(out['complete']);self.assertFalse(out['qualified'])
        self.assertFalse(out['urgent_selection_isolation_verified'])

    def test_exact_original_utf8_envelope_retains_original_whitespace(self):
        import json
        expected,checkpoint,observation=fixture();receipt=runtime.verify(expected,checkpoint,observation,now_ns=observation['completed_at_ns']+1)
        eraw=('  '+json.dumps(expected,indent=2)+'\n').encode();craw=(json.dumps(checkpoint,indent=1)+'\n\n').encode()
        originals={'/opt/expected':eraw,'/opt/checkpoint':craw}
        def protected(path):
            raw=originals.get(str(path),b'actual protected producer');return raw,runtime.digest(raw)
        with patch.object(runtime,'checked_file',side_effect=protected),patch.object(runtime,'capture',return_value=(observation,copy.deepcopy(receipt))):
            envelope=runtime.capture_originals_protected('/opt/expected','/opt/checkpoint')
        self.assertEqual(set(envelope),{'expected_raw','checkpoint_raw','observation_raw','protected_receipt_raw'})
        self.assertTrue(all(type(x)is str for x in envelope.values()))
        self.assertEqual(envelope['expected_raw'].encode(),eraw);self.assertEqual(envelope['checkpoint_raw'].encode(),craw)
        result=json.loads(envelope['protected_receipt_raw']);self.assertEqual(result['operator_expected_source_sha256'],runtime.digest(eraw))
        self.assertEqual(result['operator_checkpoint_source_sha256'],runtime.digest(craw))
        self.assertEqual(json.loads(envelope['observation_raw']),observation)

    def test_protected_original_change_during_capture_refuses(self):
        import json
        expected,checkpoint,observation=fixture();receipt={};count={}
        raw={'/opt/expected':json.dumps(expected).encode(),'/opt/checkpoint':json.dumps(checkpoint).encode()}
        def protected(path):
            name=str(path);count[name]=count.get(name,0)+1;value=raw.get(name,b'producer')
            if name=='/opt/expected'and count[name]>1:value+=b' '
            return value,runtime.digest(value)
        with patch.object(runtime,'checked_file',side_effect=protected),patch.object(runtime,'capture',return_value=(observation,receipt)):
            with self.assertRaisesRegex(ValueError,'declaration changed'):runtime.capture_originals_protected('/opt/expected','/opt/checkpoint')


class NativeOwnerRouteTests(unittest.TestCase):
    def check(self,args):return runtime.verify(*args,now_ns=args[2]['completed_at_ns'])

    def test_distinct_endpoint_texts_reach_same_owned_service(self):
        args=fixture();out=self.check(args)
        self.assertEqual(out['native_owner_route']['destination']['address'],'192.0.2.20')
        self.assertEqual(out['native_owner_route']['listener']['address'],'0.0.0.0')
        self.assertFalse(out['complete'])

    def test_foreign_service_ip_and_network_refuse(self):
        for change in ('ip','network'):
            args=fixture()
            if change=='ip':args[2]['owner_route']['destination']={'address':'192.0.2.30','port':3538}
            else:args[2]['owner_route']['shared_network_id']='d'*64
            with self.assertRaises(ValueError):self.check(args)

    def test_loopback_in_another_namespace_is_not_owning_watchman(self):
        args=fixture();cap=args[2]['before']['captaind'];cap['public_configuration']['native_funding_owner_address']['address']='127.0.0.1'
        args[1]['configs']['captaind']['public_configuration']=copy.deepcopy(cap['public_configuration'])
        args[2]['after']=copy.deepcopy(args[2]['before']);args[2]['owner_route']['destination']=copy.deepcopy(cap['public_configuration']['native_funding_owner_address'])
        with self.assertRaisesRegex(ValueError,'shared network'):self.check(args)

    def test_foreign_pid_route_change_or_missing_actual_socket_refuse(self):
        for field in ('pid','changed','socket'):
            args=fixture()
            if field=='pid':args[2]['owner_route']['watch_pid']=52
            elif field=='changed':args[2]['owner_route_after']['watch_listener']['inode']=56
            else:args[2]['owner_route']['watch_listener']['fd']=-1
            with self.assertRaises(ValueError):self.check(args)

    def test_missing_route_cannot_borrow_correct_flock(self):
        args=fixture();del args[2]['owner_route']
        with self.assertRaises(KeyError):self.check(args)

    def test_actual_local_owned_tcp_listener_requires_own_fd(self):
        import socket
        with socket.socket()as sock:
            sock.bind(('127.0.0.1',0));sock.listen(1)
            raw=Path('/proc/self/net/tcp').read_bytes();port=sock.getsockname()[1]
            links={sock.fileno():os.readlink('/proc/self/fd/'+str(sock.fileno()))}
            actual=runtime._listener(raw,links,address='127.0.0.1',port=port)
            self.assertEqual(actual['fd'],sock.fileno())
            with self.assertRaisesRegex(ValueError,'watch-owned'):runtime._listener(raw,{},address='127.0.0.1',port=port)

    def test_native_owner_tool_route_is_fixed(self):
        expected=fixture()[0];raw=fixture()[2]['native_budget']['owner_snapshot_raw'].encode()
        with patch.object(runtime,'_run',return_value=raw)as run:
            value,original=runtime._owner_snapshot(expected)
        run.assert_called_once_with(['/usr/bin/docker','exec','owned-watchmand','captaind','rpc','--addr','127.0.0.1:3538','native-fee-budget'])
        self.assertEqual(original.encode(),raw);self.assertEqual(value['schema'],1)

    def test_source_bound_final_policy_is_actual15e(self):
        self.assertEqual(runtime.POLICY_PRODUCT_COMMIT,'15e4fd7085802ba5f7b1d9a2c87aab7277d5a7e4')
        self.assertIn('server/src/watchman/funding_owner.rs',runtime.LOAD_GATES)


class NativeRouteBracketTests(unittest.TestCase):
    def test_unrelated_tcp_activity_does_not_invent_a_route_change(self):
        args=fixture();args[2]['owner_route_after']['watch_listener']['tcp_table_sha256']='d'*64
        result=runtime.verify(*args,now_ns=args[2]['completed_at_ns'])
        self.assertEqual(result['native_owner_route']['watch_listener']['inode'],55)
        self.assertFalse(result['complete'])

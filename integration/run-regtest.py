#!/usr/bin/env python3
"""Declare and run the absent-owner hArk regression in an isolated checkout."""
from pathlib import Path
import argparse, datetime, fcntl, hashlib, importlib.util, json, os, shutil, subprocess, time

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / 'runs/integration'
CLONE = Path('/home/francis/simulator-regtest-src')
TARGET = Path('/home/francis/abandon-ship-slots/target-3')
HEAD = 'd47c6a4d115b30bf56219d69251fa9238d13f32d'
PRODUCTION = Path('/home/francis/bark-integration-2026-10-01/candidate-d47c6a4d1/bins')
spec = importlib.util.spec_from_file_location('stage4runner', Path('/home/francis/bark-integration-2026-10-01/scale-stage4/run-stage4.py'))
s4 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s4)

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('name')
    parser.add_argument('--independent-target',action='store_true',help='use this simulator own target and lease; never share a suite slot')
    parser.add_argument('--test',choices=['simulator_owner_funded_renewal','simulator_confirmed_receipt_recycling','simulator_board_absence_restore','simulator_pending_board_absence_restore','simulator_ark_receive_then_disappear','simulator_lightning_receive_then_disappear','simulator_payments_refresh_exits','simulator_fallback_negative_requests'],default='simulator_board_absence_restore')
    args = parser.parse_args()
    assert args.name.replace('-', '').replace('_', '').isalnum()
    run = HERE / args.name
    HERE.mkdir(parents=True,exist_ok=True)
    run.mkdir(parents=True, exist_ok=False)
    target=ROOT/'fixture-target' if args.independent_target else TARGET
    lock=ROOT/'runs/integration/native-fixture.lock' if args.independent_target else Path('/home/francis/bark-integration-2026-10-01/expiry-fallback-evidence/runtime/fixture/slot-3.lock')
    with open(lock, 'a') as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=CLONE, text=True).strip() == HEAD
        changes = subprocess.check_output(['git', 'status', '--porcelain'], cwd=CLONE, text=True).splitlines()
        assert sorted(x[3:] for x in changes) == ['testing/tests/bark_sdk/mod.rs', 'testing/tests/bark_sdk/simulator_vertical.rs']
        harness = CLONE / 'testing/tests/bark_sdk/simulator_vertical.rs'
        assert harness.read_bytes() == (ROOT / 'integration/simulator_vertical.rs').read_bytes()
        env, _ = s4.build_env(run)
        env.update(CARGO_TARGET_DIR=str(target), GIT_HASH=HEAD + '-harkfixture',
                   CAPTAIND_EXEC=str(PRODUCTION / 'captaind'), WATCHMAND_EXEC=str(PRODUCTION / 'watchmand'),
                   BARK_EXEC=str(PRODUCTION / 'bark'), BARKD_EXEC=str(PRODUCTION / 'barkd'),
                   STAGE4_RECOVERY_DEADLINE='180', STAGE4_CONCURRENCY='1')
        env.update(SIMULATOR_WORKSPACE=str(ROOT), SIMULATOR_OUT=str(run / 'out'), SIMULATOR_SERVER_SHA256=digest(PRODUCTION / 'captaind'))
        name = 'simulator_vertical::'+args.test
        decl = {'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'head': HEAD,
                'test': name, 'harness_sha256': digest(harness), 'runner_sha256': digest(__file__),
                'binaries': {p.name: digest(p) for p in PRODUCTION.iterdir()},
                'wall_seconds': 1800 if args.independent_target else 1200, 'target_dir':str(target),'lease':str(lock),'source': 'actual simulator supervisor/native driver; '+args.test,
                'fixture_customer_fee_budget_sat':100_000 if args.test in ('simulator_owner_funded_renewal','simulator_confirmed_receipt_recycling','simulator_ark_receive_then_disappear','simulator_lightning_receive_then_disappear','simulator_payments_refresh_exits') else 10_000,
                'checks': {
                    'simulator_owner_funded_renewal':['actual separately funded Core owner deposit','source-only funding PSBT <=2k fees','8k confirmed owned client grant','native new source-only board and5k confirmed Ark balance','zero recycling or qualified traffic credit'],
                    'simulator_confirmed_receipt_recycling':['two actual confirmed cooperative exits, no extra funding','frozen own receipt is the only board input','fresh action IDs','principal+service+mining+ownchange conservation exact','no source reuse'],
                    'simulator_ark_receive_then_disappear':['native actual Ark receive','independent signed outputs before permanent silence','no original calls until payout','rightful grouped confirmed payout','seed-only recovery and confirmed spend'],
                    'simulator_lightning_receive_then_disappear':['native actual Lightning receive','external payer paid without refund','independent signed claim outputs before permanent silence','rightful grouped confirmed payout','seed-only recovery and confirmed spend'],
                    'simulator_fallback_negative_requests': ['actual Python journal and driver', 'typed refusals/unchanged protected records and links', 'bounded valid queries'],
                    'simulator_payments_refresh_exits': ['actual Python journal and driver', 'Ark recipient receives the intended amount', 'interactive and delegated refresh produce new spendable coins', 'empty wallet invoices and collects2000sat without initial grant or Ark balance', 'internal and external Lightning success verified against payment hashes', 'confirmed collaborative offboard to the intended script', 'board, successful round/send and offboard fees reconciled against frozen intents and signed values; newly completed internal receive claims conserved against frozen invoice and independently owned signed outputs; failed-send costs remain outside fixture accounting scope'],
                    'simulator_board_absence_restore': ['actual Python journal and driver', 'no original calls after absence', 'confirmed rightful payout', 'fresh BIP84 seed-only recovery with no txid/index/birthday hints', 'confirmed spend'],
                    'simulator_pending_board_absence_restore': ['actual Python journal and driver', 'confirmed real board funding with fewer than required registration confirmations', 'no registered coin or original calls after absence', 'pending-board payout to independently verified owner', 'fresh BIP84 seed-only recovery with no txid/index/birthday hints', 'confirmed spend'],
                }[args.test],
                'simulator_sources':{str(p.relative_to(ROOT)):digest(p) for p in [*ROOT.glob('simulator/*.py'), ROOT/'integration/regtest-client.py',ROOT/'driver/src/main.rs',ROOT/'driver/src/bin/seed-restore.rs']},
                'driver_sha256':digest(ROOT/'target/debug/bark-sim-driver'), 'restore_sha256':digest(ROOT/'target/debug/seed-restore'),
                'proof_sha256':digest(ROOT/'target/debug/vtxo-proof')}
        (run / 'predeclared.json').write_text(json.dumps(decl, indent=2) + '\n')
        shutil.copyfile(harness, run / 'simulator_vertical.rs')
        shutil.copyfile(__file__, run / 'run-regtest.py')
        shutil.copyfile(ROOT / 'integration/regtest-client.py', run / 'regtest-client.py')
        with open(run / 'build.log', 'w') as log:
            build = subprocess.run(['cargo', 'test', '--locked', '-p', 'ark-testing', '--test', 'bark-sdk', '--no-run'],
                                   cwd=CLONE, env=env, stdout=log, stderr=subprocess.STDOUT)
        if build.returncode:
            (run / 'summary.json').write_text(json.dumps({'overall': 'FAIL', 'phase': 'build', 'exit': build.returncode}) + '\n')
            raise SystemExit(build.returncode)
        started = time.monotonic()
        timed_out = False
        with open(run / 'test.log', 'w') as log:
            proc = subprocess.Popen(['cargo', 'test', '--locked', '-p', 'ark-testing', '--test', 'bark-sdk',
                                     '--', '--exact', name, '--nocapture'], cwd=CLONE, env=env,
                                    stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            sampler = s4.Sampler(run, {'run_rss_gib': 12, 'run_disk_gib': 20, 'min_free_disk_gib': 40}, proc)
            sampler.start()
            try:
                while proc.poll() is None:
                    if time.monotonic() - started > decl['wall_seconds'] or sampler.violation:
                        timed_out = True
                        break
                    time.sleep(1)
            finally:
                cleanup = s4.cleanup(proc, run / 'test-data')
                sampler.stop.set()
                sampler.join(timeout=10)
        result_path = run / 'out/result.json'
        result = json.loads(result_path.read_text()) if result_path.exists() else None
        changed_sources = [name for name, expected in decl['simulator_sources'].items()
                           if not (ROOT/name).is_file() or digest(ROOT/name) != expected]
        passed = (proc.returncode == 0 and not timed_out and not sampler.violation
                  and result and result['result'] == 'PASS' and not changed_sources)
        summary = {'overall': 'PASS' if passed else 'FAIL', 'exit': proc.returncode, 'timeout': timed_out,
                   'wall_seconds': time.monotonic() - started, 'result': result,
                   'resource_violation': sampler.violation, 'invalidated_sources':changed_sources, 'cleanup': cleanup}
        (run / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        print(json.dumps({k:v for k,v in summary.items() if k!="result"}, indent=2))
        raise SystemExit(0 if passed else 1)

if __name__ == '__main__':
    main()

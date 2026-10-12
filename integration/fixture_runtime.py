"""Resource limits and cleanup restricted to one isolated fixture."""
from pathlib import Path
import json,os,shutil,signal,subprocess,threading,time

def run_pids(test_dir):
    key = b'\0TEST_DIRECTORY=' + str(test_dir).encode() + b'\0'
    pids = []
    for d in Path('/proc').iterdir():
        if not d.name.isdigit() or int(d.name) == os.getpid():
            continue
        try:
            if key in b'\0' + (d / 'environ').read_bytes():
                pids.append(int(d.name))
        except OSError:
            pass
    return pids

def run_containers(test_dir):
    own = str(test_dir).rstrip('/') + '/'
    names = subprocess.run(['docker', 'ps', '-a', '--format', '{{.Names}}'], capture_output=True, text=True).stdout.split()
    mine = []
    for n in (n for n in names if n.startswith('cln')):
        srcs = subprocess.run(['docker', 'inspect', '--format', '{{range .Mounts}}{{.Source}}\n{{end}}', n],
            capture_output=True, text=True).stdout.split()
        if any(x.startswith(own) for x in srcs):
            mine.append(n)
    return mine

def cleanup(proc, test_dir):
    for sig, grace in ((signal.SIGTERM, 20), (signal.SIGKILL, 5)):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            pass
        for pid in run_pids(test_dir):
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                pass
        end = time.monotonic() + grace
        while time.monotonic() < end and (proc.poll() is None or run_pids(test_dir)):
            time.sleep(0.5)
    proc.wait()
    mine = run_containers(test_dir)
    if mine:
        subprocess.run(['docker', 'rm', '-f', *mine], capture_output=True)
    return {'containers_removed': mine, 'survivors': run_pids(test_dir)}

def proc_sample(pid):
    stat = Path(f'/proc/{pid}/stat').read_text()
    rest = stat[stat.rindex(')') + 2:].split()
    utime, stime = int(rest[11]), int(rest[12])
    rss = 0
    for line in Path(f'/proc/{pid}/status').read_text().splitlines():
        if line.startswith('VmRSS:'):
            rss = int(line.split()[1])
    exe = os.path.basename(os.readlink(f'/proc/{pid}/exe'))
    return {'pid': pid, 'exe': exe, 'cpu_ticks': utime + stime, 'rss_kib': rss}

class Sampler(threading.Thread):
    """CPU, RSS and disk of the run's processes; enforces the declared bounds."""

    def __init__(self, run, bounds, proc):
        super().__init__(daemon=True)
        self.run_dir, self.bounds, self.proc = run, bounds, proc
        self.stop = threading.Event()
        self.violation = None

    def run_dir_bytes(self):
        out = subprocess.run(['du', '-sb', str(self.run_dir)], capture_output=True, text=True).stdout.split()
        return int(out[0]) if out else 0

    def run(self):
        test_dir = self.run_dir / 'test-data'
        last_disk = 0
        while not self.stop.wait(5):
            rows = []
            for pid in run_pids(test_dir):
                try:
                    rows.append(proc_sample(pid))
                except OSError:
                    pass
            rss = sum(r['rss_kib'] for r in rows)
            load = os.getloadavg()
            mem = {l.split(':')[0]: int(l.split()[1]) for l in Path('/proc/meminfo').read_text().splitlines()
                if l.startswith(('MemAvailable', 'SwapFree'))}
            with (self.run_dir / 'resources.jsonl').open('a') as f:
                f.write(json.dumps({'utc': time.time(), 'procs': rows, 'rss_kib_total': rss, 'loadavg': load,
                    'mem_kib': mem}) + '\n')
            if rss > self.bounds['run_rss_gib'] * 1024 * 1024:
                self.violation = f'run RSS {rss} KiB above {self.bounds["run_rss_gib"]} GiB'
            if time.monotonic() - last_disk >= 60:
                last_disk = time.monotonic()
                used = self.run_dir_bytes()
                free = shutil.disk_usage(self.run_dir).free
                with (self.run_dir / 'disk.jsonl').open('a') as f:
                    f.write(json.dumps({'utc': time.time(), 'run_bytes': used, 'free_bytes': free}) + '\n')
                if used > self.bounds['run_disk_gib'] * 2**30:
                    self.violation = f'run disk {used} B above {self.bounds["run_disk_gib"]} GiB'
                if free < self.bounds['min_free_disk_gib'] * 2**30:
                    self.violation = f'free disk {free} B below {self.bounds["min_free_disk_gib"]} GiB'
            if self.violation:
                return

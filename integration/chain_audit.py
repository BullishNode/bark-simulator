"""Network-disabled raw-chain reconstruction for independent fixture audits."""
from pathlib import Path
from decimal import Decimal
import base64,hashlib,json,socket,subprocess,time,urllib.request

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def sats(value):
    amount = Decimal(str(value)) * 100_000_000
    assert amount >= 0 and amount == amount.to_integral_value(), 'invalid BTC amount'
    return int(amount)

class Core:
    def __init__(self, datadir, executable, evidence):
        self.datadir, self.executable, self.evidence = datadir, executable, evidence
        self.proc = None
        self.cache = {}

    def __enter__(self):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            self.port = sock.getsockname()[1]
        self.log = (self.evidence / 'core-audit.log').open('wb')
        self.proc = subprocess.Popen([
            str(self.executable), '-regtest', '-conf=/dev/null', '-nosettings',
            f'-datadir={self.datadir}', '-server=1', '-listen=0', '-networkactive=0',
            '-disablewallet=1', '-txindex=1', '-reindex=1', f'-rpcport={self.port}', '-rpcbind=127.0.0.1',
            '-rpcallowip=127.0.0.1', '-debug=0',
        ], stdout=self.log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 600
            while time.monotonic() < deadline:
                assert self.proc.poll() is None, 'audit Core exited; inspect core-audit.log'
                try:
                    info = self.call('getblockchaininfo')
                    assert info['chain'] == 'regtest', 'audit must use regtest'
                    if info['initialblockdownload'] or not self.call('getindexinfo').get('txindex', {}).get('synced'):
                        raise RuntimeError('audit chain/index reconstruction is still running')
                    self.start_tip = info['bestblockhash']
                    return self
                except (OSError, ValueError, RuntimeError):
                    time.sleep(.25)
            raise RuntimeError('audit Core readiness deadline')
        except BaseException:
            self.close()
            raise

    def call(self, method, *params):
        cookie = (self.datadir / 'regtest/.cookie').read_text().strip()
        request = urllib.request.Request(f'http://127.0.0.1:{self.port}',
            data=json.dumps({'jsonrpc': '2.0', 'id': 'audit', 'method': method,
                             'params': list(params)}).encode(),
            headers={'Authorization': 'Basic ' + base64.b64encode(cookie.encode()).decode(),
                     'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=30) as response:
            result = json.load(response, parse_float=Decimal)
        if result.get('error'):
            raise RuntimeError('audit Core RPC error: ' + str(result['error'].get('code')))
        return result['result']

    def tx(self, txid):
        if txid not in self.cache:
            self.cache[txid] = self.call('getrawtransaction', txid, True)
            with (self.evidence / 'core-transactions.jsonl').open('a') as stream:
                stream.write(json.dumps(self.cache[txid], default=str) + '\n')
        return self.cache[txid]

    def close(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()  # Only the process this audit started, by PID.
            try:
                self.proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)
        if hasattr(self, 'log'):
            self.log.close()

    def __exit__(self, *args):
        self.close()

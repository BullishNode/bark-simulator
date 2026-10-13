"""Private capture audit for one client invocation; no scenario traffic credit.

The native transport records gRPC body bytes before forwarding and streams
response frames/trailers. This index audits protected records independently;
it neither opens wallets nor treats a client gate refusal as a server refusal.
"""
from __future__ import annotations
import hashlib,json,os,re,sqlite3,stat,time
from .model import canonical,InvariantError

SCHEMA='''CREATE TABLE IF NOT EXISTS invocation(id TEXT PRIMARY KEY,actor TEXT NOT NULL,manifest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS capture(invocation TEXT NOT NULL,side TEXT NOT NULL,stream INTEGER NOT NULL,sequence INTEGER NOT NULL,digest TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(invocation,side,stream,sequence));
CREATE TABLE IF NOT EXISTS request(invocation TEXT NOT NULL,stream INTEGER NOT NULL,method TEXT NOT NULL,body_hash TEXT NOT NULL,state TEXT NOT NULL,PRIMARY KEY(invocation,stream));'''

class CaptureIndex:
    def __init__(self,vault,actor,invocation,manifest):
        if not re.fullmatch(r'actor-\d\d',actor) or actor in {'actor-03','actor-09','actor-10'} or not re.fullmatch(r'[A-Za-z0-9_-]{1,160}',invocation) or not re.fullmatch('[0-9a-f]{64}',manifest):raise ValueError('unsafe transport invocation scope')
        self.vault,self.actor,self.invocation,self.manifest=vault,actor,invocation,manifest
        path=vault.root/'transport.sqlite'
        try:
            fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,'O_NOFOLLOW',0),0o600);os.fsync(fd);os.close(fd)
        except FileExistsError:pass
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077:raise ValueError('unsafe transport index')
        self.db=sqlite3.connect(path);self.db.row_factory=sqlite3.Row
        self.db.execute('PRAGMA synchronous=FULL');self.db.executescript(SCHEMA)
        old=self.db.execute('SELECT * FROM invocation WHERE id=?',(invocation,)).fetchone();self.restarted=old is not None
        if old and (old['actor'],old['manifest'])!=(actor,manifest):raise InvariantError('immutable transport invocation scope changed')
        with self.db:self.db.execute('INSERT OR IGNORE INTO invocation VALUES (?,?,?)',(invocation,actor,manifest))
    def record(self,side,stream,sequence,kind,raw):
        if side not in {'request','response'} or kind not in {'headers','data','trailers','error'} or type(stream) is not int or stream<1 or type(sequence) is not int or sequence<0:raise ValueError('invalid capture frame')
        ref=self.vault.put('grpc_'+side+'_'+kind,raw,trial_id=self.invocation,leg_id='stream-'+str(stream))
        old=self.db.execute('SELECT payload FROM capture WHERE invocation=? AND side=? AND stream=? AND sequence=?',(self.invocation,side,stream,sequence)).fetchone()
        if old:
            value=json.loads(old[0])
            if value['kind']!=kind or value['object']!=ref:raise InvariantError('immutable transport frame changed')
            return value
        prior=self.db.execute('SELECT sequence,digest FROM capture WHERE invocation=? AND side=? AND stream=? ORDER BY sequence DESC LIMIT 1',(self.invocation,side,stream)).fetchone()
        if sequence!=(prior['sequence']+1 if prior else 0):raise InvariantError('transport capture has a sequence gap')
        payload={'invocation':self.invocation,'actor':self.actor,'manifest_sha256':self.manifest,'side':side,'stream':stream,'sequence':sequence,'kind':kind,'object':ref,'previous_sha256':prior['digest'] if prior else None,'captured_at_ns':time.time_ns(),'qualification':'capture-only; real upstream transport/scenario audit required'}
        checksum=hashlib.sha256(canonical(payload).encode()).hexdigest()
        with self.db:self.db.execute('INSERT INTO capture VALUES (?,?,?,?,?,?)',(self.invocation,side,stream,sequence,checksum,canonical(payload)))
        return payload
    def request_frozen(self,stream,method,body,headers):
        if not re.fullmatch('[A-Za-z][A-Za-z0-9]{1,100}',method):raise ValueError('invalid RPC method')
        # Scope here is an audit of one unary client request. Streaming response
        # data is captured separately without re-decoding or dropping trailers.
        if len(body)<5 or len(body)>4*1024*1024 or body[0] not in {0,1} or int.from_bytes(body[1:5],'big')!=len(body)-5:raise ValueError('incomplete or multiple unary gRPC messages')
        self.record('request',stream,0,'headers',headers);self.record('request',stream,1,'data',body)
        checksum=hashlib.sha256(body).hexdigest()
        old=self.db.execute('SELECT * FROM request WHERE invocation=? AND stream=?',(self.invocation,stream)).fetchone()
        if old and (old['method'],old['body_hash'])!=(method,checksum):raise InvariantError('frozen RPC changed')
        with self.db:self.db.execute('INSERT OR IGNORE INTO request VALUES (?,?,?,?,?)',(self.invocation,stream,method,checksum,'frozen'))
    def release(self,stream):
        if self.restarted:return False
        with self.db:
            row=self.db.execute('SELECT * FROM request WHERE invocation=? AND stream=?',(self.invocation,stream)).fetchone()
            if row is None or row['state']!='frozen':return False
            if row['method']=='SubmitPayment' and self.db.execute("SELECT 1 FROM request WHERE invocation=? AND method='SubmitPayment' AND state='forwarded'",(self.invocation,)).fetchone():
                self.db.execute("UPDATE request SET state='client_gate_refusal' WHERE invocation=? AND stream=?",(self.invocation,stream));return False
            self.db.execute("UPDATE request SET state='forwarded' WHERE invocation=? AND stream=?",(self.invocation,stream))
        return True

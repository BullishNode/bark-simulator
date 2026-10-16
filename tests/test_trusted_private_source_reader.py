"""Real owned subprocess controls for trusted private-source transport modes.

These test the actual shared implementation, without SSH, wallets or funds.
"""
import asyncio
import hashlib
import json
import os
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from simulator.private_source_package import TargetTarReader

class ReaderControls(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.root.chmod(0o700)
        self.observation={'id':uuid.uuid4().hex,'padding':'x'*60000}
    async def test_C_stdin_large_request_concurrent_output_and_actual_reaped_exit(self):
        child="import os,sys,hashlib;os.write(1,b'o'*131072);raw=sys.stdin.buffer.read();print(hashlib.sha256(raw).hexdigest());os.write(2,b'bounded diagnostic')"
        def load(path,producer_exit):return(path.read_bytes(),producer_exit())
        cls=TargetTarReader
        data,status=await cls(('/usr/bin/python3','-I','-c',child),self.root,timeout=3,loader=load,request_stdin=True).read(self.observation)
        encoded=(json.dumps(self.observation,sort_keys=True,separators=(',',':'))+'\n').encode()
        self.assertEqual(data,b'o'*131072+hashlib.sha256(encoded).hexdigest().encode()+b'\n');self.assertEqual(status,0)
        directories=list(self.root.iterdir());self.assertEqual(len(directories),1)
        self.assertEqual(0o600,(directories[0]/'source.tar').stat().st_mode&0o777)
    async def test_explicit_loader_alone_preserves_empty_stdin(self):
        cls=TargetTarReader;data=await cls(('/usr/bin/python3','-I','-c','import sys;print(len(sys.stdin.buffer.read()))'),self.root,timeout=2,loader=lambda path,producer_exit:path.read_bytes()).read(self.observation)
        self.assertEqual(b'0\n',data)
    async def test_stalled_nonreading_child_times_out_killed_and_reaped_no_loader(self):
        pid=self.root/'ownedpid'
        child="import os,time;f=os.open(%r,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(f,str(os.getpid()).encode());os.close(f);time.sleep(30)"%str(pid)
        cls=TargetTarReader;began=time.monotonic()
        with self.assertRaises(TimeoutError):await cls(('/usr/bin/python3','-I','-c',child),self.root,timeout=.25,loader=lambda *_args,**_kw:self.fail('loader after timeout'),request_stdin=True).read(self.observation)
        self.assertLess(time.monotonic()-began,2);actual=int(pid.read_text())
        with self.assertRaises(ProcessLookupError):os.kill(actual,0)
    async def test_nonzero_exit_never_calls_loader(self):
        cls=TargetTarReader
        with self.assertRaises(ValueError):await cls(('/usr/bin/python3','-I','-c','import sys;sys.stdin.buffer.read();raise SystemExit(7)'),self.root,timeout=2,loader=lambda *_a,**_kw:self.fail('injected loader after failure'),request_stdin=True).read(self.observation)
    async def test_oversized_request_refuses_before_process(self):
        cls=TargetTarReader
        with self.assertRaisesRegex(ValueError,'request exceeds'):await cls(('/usr/bin/python3','-I','-c','raise AssertionError("must not spawn")'),self.root,timeout=1,request_stdin=True).read({**self.observation,'padding':'x'*65536})

if __name__=='__main__':unittest.main()

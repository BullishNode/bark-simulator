"""Actual local timing/process controls; no chain, wallet or financial traffic."""
import asyncio
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
from unittest.mock import patch
import unittest

from simulator.normal_source_deadline import ACTIVE, Deadline, DeadlineChain
from simulator.two_step_normal import Collector, digest


class DeadlineTests(unittest.IsolatedAsyncioTestCase):
    async def test_combined_phases_exceed_remaining_budget_even_when_each_phase_is_short(self):
        collector=Collector(None,1,{})
        admitted=[]
        async def phases(*args,**kwargs):
            await asyncio.sleep(.04)
            await asyncio.sleep(.04)
            admitted.append('forbidden late readiness')
        with patch.object(collector,'_produce',side_effect=phases):
            with self.assertRaises(TimeoutError):
                await collector.produce(None,None,None,{}, {'started_at':time.time()-89.94},{},{})
        self.assertEqual([],admitted);self.assertIsNone(ACTIVE.get())
    async def test_expired_or_future_observation_never_enters_source(self):
        collector=Collector(None,1,{})
        for value in (time.time()-91,time.time()+20):
            with patch.object(collector,'_produce')as source,self.assertRaises(ValueError):
                await collector.produce(None,None,None,{}, {'started_at':value},{},{})
            source.assert_not_called()
    async def test_independent_rpc_is_capped_by_aggregate_and_late_result_refuses(self):
        class Chain:
            def call(inner,method,*args,timeout,**kwargs):
                inner.timeout=timeout;time.sleep(.03);return 'late'
        source=Chain();chain=DeadlineChain(source,Deadline(time.time()-89.98))
        with self.assertRaises(TimeoutError):chain.call('getblockhash',1)
        self.assertLessEqual(source.timeout,.021)


class RetainedPipeTests(unittest.IsolatedAsyncioTestCase):
    async def run_case(self,member):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);pidfile=root/'owned-child.pid'
            script=("import os,time\nchild=os.fork()\n"
                "if child==0:\n time.sleep(30)\n os._exit(0)\n"
                f"open({str(pidfile)!r},'w').write(str(child))\nos._exit(0)\n")
            helper=root/'helper.py';helper.write_text(script);helper.chmod(0o555)
            outputs=root/'captures';outputs.mkdir(mode=0o700)
            observation={'id':'12345678123456781234567812345678'}
            deadline=Deadline(time.time()-89.75);token=ACTIVE.set(deadline)
            try:
                if member:
                    from simulator.normal_member_source import MemberReader
                    reader=MemberReader({'helper_command':[sys.executable,str(helper)],
                        'helper_sha256':digest(helper.read_bytes()),'evidence_root':str(outputs)},None)
                    call=reader.read(observation,{}, {})
                else:
                    from simulator.private_source_package import TargetTarReader
                    reader=TargetTarReader([sys.executable,str(helper)],outputs,timeout=.2)
                    call=reader.read(observation)
                with self.assertRaises(TimeoutError):await call
                terminal=json.loads(next(outputs.iterdir()).joinpath('helper.terminal.json'if member else 'terminal.json').read_bytes())
                self.assertEqual(0,terminal['exit'])
                child=int(pidfile.read_text());status=Path('/proc')/str(child)/'stat'
                # An orphan can await init's reap as a zombie; it cannot retain
                # an executing process or open source-output descriptors.
                for _ in range(20):
                    if not status.exists()or status.read_text().split(') ',1)[1].split()[0]=='Z':break
                    await asyncio.sleep(.01)
                self.assertTrue(not status.exists()or status.read_text().split(') ',1)[1].split()[0]=='Z')
            finally:
                ACTIVE.reset(token)
                if pidfile.exists():
                    try:os.kill(int(pidfile.read_text()),signal.SIGKILL)
                    except ProcessLookupError:pass
    async def test_target_leader_exited_child_holds_pipe_kills_owned_group(self):await self.run_case(False)
    async def test_member_leader_exited_child_holds_pipe_kills_owned_group(self):await self.run_case(True)

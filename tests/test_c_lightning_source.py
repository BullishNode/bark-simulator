"""Synthetic public CLN replies; no daemon/chain/payment qualification."""
import asyncio
import copy
import hashlib
import json
import os
import socket
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock,patch

from simulator import c_lightning_source as c
from simulator.model import SIGNET_GENESIS
from simulator.topology import ready


class OwnedClnSourceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.ids={'operator':'02'+'1'*64,'fixture_peer':'03'+'2'*64};self.now=time.time()
        self.tip={'genesis':SIGNET_GENESIS,'height':100,'tip_hash':'a'*64,'initialblockdownload':False}
        self.frames={};self.calls=[]
        for alias,pk in self.ids.items():
            other=self.ids['fixture_peer' if alias=='operator' else 'operator']
            channel={'peer_id':other,'channel_id':'b'*64,'funding_txid':'c'*64,'funding_outnum':0,
                'state':'CHANNELD_NORMAL','total_msat':10000000,'to_us_msat':5000000,
                'spendable_msat':'4000000msat','receivable_msat':4000000}
            self.frames[alias]={'getinfo':{'id':pk,'network':'signet','blockheight':100},
                'listfunds':{'outputs':[],'channels':[{'peer_id':other,'amount_msat':10000000,'our_amount_msat':5000000}]},
                'listpeerchannels':{'channels':[channel]}}
    async def rpc(self,alias,method):
        self.calls.append((alias,method));return copy.deepcopy(self.frames[alias][method])
    async def chain(self):return copy.deepcopy(self.tip)
    async def collect(self):
        return await c.OwnedClnReader(self.rpc,self.chain,context_sha256='d'*64,node_ids=self.ids,clock=lambda:self.now).collect()
    def verify(self,source):
        return c.verify_source(source,context_sha256='d'*64,node_ids=self.ids,height=100,tip_hash='a'*64,now=self.now)
    async def test_actual_three_replies_are_replayed_and_existing_topology_checks_reciprocal_channel(self):
        source=await self.collect();self.assertEqual(set(self.calls),{(a,m) for a in c.ALIASES for m in c.METHODS})
        snapshot={'height':100,'capabilities':{'lightning_configured':True},'lightning':self.verify(source)}
        self.assertTrue(ready(snapshot))
        changed=copy.deepcopy(source);changed['nodes']['operator']['listpeerchannels']['channels'][0]['funding_txid']='e'*64
        snapshot['lightning']=self.verify(changed);self.assertFalse(ready(snapshot))
    async def test_wrong_owner_network_height_and_sync_warning_refuse(self):
        for field,value in [('id',self.ids['fixture_peer']),('network','bitcoin'),('blockheight',99),
                            ('blockheight',True),('warning_bitcoind_sync','sync')]:
            before=copy.deepcopy(self.frames)
            self.frames['operator']['getinfo'][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):await self.collect()
            self.frames=before
    async def test_missing_method_output_rows_and_foreign_counterparty_refuse(self):
        source=await self.collect()
        for method in c.METHODS:
            bad=copy.deepcopy(source);del bad['nodes']['operator'][method]
            with self.subTest(method=method),self.assertRaises(ValueError):self.verify(bad)
        for method in ('listfunds','listpeerchannels'):
            bad=copy.deepcopy(source);bad['nodes']['operator'][method]['channels'][0]['peer_id']='02'+'9'*64
            with self.subTest(method=method),self.assertRaises(ValueError):self.verify(bad)
        bad=copy.deepcopy(source);del bad['nodes']['operator']['listfunds']['outputs']
        with self.assertRaises(ValueError):self.verify(bad)
    async def test_native_amount_bool_negative_and_overcapacity_refuse(self):
        source=await self.collect()
        for amount in (True,-1,'1.0msat','garbage',11000000):
            bad=copy.deepcopy(source);bad['nodes']['operator']['listpeerchannels']['channels'][0]['spendable_msat']=amount
            with self.subTest(amount=amount),self.assertRaises(ValueError):self.verify(bad)
    async def test_chain_changed_same_height_refuses_and_source_tip_replay_refuses(self):
        count=0
        async def changing():
            nonlocal count
            count+=1;return {**self.tip,'tip_hash':('a' if count==1 else 'b')*64}
        with self.assertRaises(ValueError):
            await c.OwnedClnReader(self.rpc,changing,context_sha256='d'*64,node_ids=self.ids).collect()
        source=await self.collect();source['tip_hash']='b'*64
        with self.assertRaises(ValueError):self.verify(source)
    async def test_empty_or_oneway_channels_do_not_become_ready(self):
        for alias in self.frames:
            self.frames[alias]['listfunds']['channels']=[];self.frames[alias]['listpeerchannels']['channels']=[]
        snapshot={'height':100,'capabilities':{'lightning_configured':True},'lightning':self.verify(await self.collect())}
        self.assertFalse(ready(snapshot))
    async def test_stale_wrong_context_and_secret_field_refuse_before_export(self):
        source=await self.collect()
        for key,value in [('context_sha256','e'*64),('started_at',self.now-91),('completed_at',self.now+1)]:
            bad=copy.deepcopy(source);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.verify(bad)
        self.frames['operator']['listpeerchannels']['preimage']='e'*64
        with self.assertRaises(ValueError):await self.collect()
    async def test_transport_cannot_invoke_payment_or_foreign_alias(self):
        transport=c.LocalClnRpc({})
        for alias,method in [('operator','pay'),('foreign','getinfo'),('operator','invoice')]:
            with self.subTest(method=method),self.assertRaises(ValueError):await transport(alias,method)
    def test_declaration_requires_independent_hash_owner_and_explicit_owned_paths(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'context.json'
            nodes={alias:{'node_id':pk,'cli_path':'/owned/lightning-cli','cli_sha256':'f'*64,
                          'rpc_file':'/owned/'+alias+'/lightning-rpc','uid':os.getuid()} for alias,pk in self.ids.items()}
            value={'schema_version':1,'genesis':SIGNET_GENESIS,'network':'signet','nodes':nodes}
            def write():
                path.write_text(json.dumps(value));return hashlib.sha256(path.read_bytes()).hexdigest()
            digest=write();self.assertEqual(c.load_context(path,digest,node_ids=self.ids),value)
            with self.assertRaises(ValueError):c.load_context(path,'0'*64,node_ids=self.ids)
            value['nodes']['operator']['node_id']=self.ids['fixture_peer'];digest=write()
            with self.assertRaises(ValueError):c.load_context(path,digest,node_ids=self.ids)
            value['nodes']['operator']['node_id']=self.ids['operator'];value['nodes']['operator']['rpc_file']='relative'
            digest=write()
            with self.assertRaises(ValueError):c.load_context(path,digest,node_ids=self.ids)

    async def test_cancellation_finishes_owned_rpc_tasks_without_late_reads(self):
        started=asyncio.Event();finished=[];calls=[]
        async def blocked(alias,method):
            calls.append((alias,method));started.set()
            try:await asyncio.Event().wait()
            finally:finished.append(alias)
        reader=c.OwnedClnReader(blocked,self.chain,context_sha256='d'*64,node_ids=self.ids)
        task=asyncio.create_task(reader.collect());await started.wait();task.cancel()
        with self.assertRaises(asyncio.CancelledError):await task
        self.assertEqual(set(finished),c.ALIASES)
        self.assertEqual(set(calls),{(alias,'getinfo') for alias in c.ALIASES})
    async def test_original_frame_bound_and_duplicate_cash_output_refuse(self):
        source=await self.collect();bad=copy.deepcopy(source)
        bad['nodes']['operator']['getinfo']['alias']='x'*(c.MAX_BYTES+1)
        with self.assertRaises(ValueError):self.verify(bad)
        row={'txid':'e'*64,'output':0,'amount_msat':1000,'status':'confirmed','blockheight':99}
        bad=copy.deepcopy(source);bad['nodes']['operator']['listfunds']['outputs']=[row,row]
        with self.assertRaises(ValueError):self.verify(bad)

    async def test_local_transport_pins_executable_and_actual_socket_before_fixed_rpc(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);exe=root/'lightning-cli';exe.write_bytes(b'synthetic-not-executed');exe.chmod(0o500)
            rpc=root/'lightning-rpc';sock=socket.socket(socket.AF_UNIX);sock.bind(str(rpc));self.addCleanup(sock.close)
            node={'cli_path':str(exe),'cli_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),
                  'rpc_file':str(rpc),'uid':os.getuid()}
            reader=c.LocalClnRpc({'nodes':{'operator':node}})
            with patch.object(c,'json_command',new_callable=AsyncMock,return_value=self.frames['operator']['getinfo']) as run:
                await reader('operator','getinfo')
                run.assert_awaited_once_with([str(exe),'--network=signet','--rpc-file='+str(rpc),'getinfo'],timeout=8)
                run.reset_mock();exe.chmod(0o700);exe.write_bytes(b'changed')
                with self.assertRaises(ValueError):await reader('operator','getinfo')
                run.assert_not_called()
    async def test_wrong_socket_owner_and_oversized_cli_refuse_without_command(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);exe=root/'lightning-cli';exe.write_bytes(b'x');exe.chmod(0o500)
            rpc=root/'lightning-rpc';sock=socket.socket(socket.AF_UNIX);sock.bind(str(rpc));self.addCleanup(sock.close)
            node={'cli_path':str(exe),'cli_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),
                  'rpc_file':str(rpc),'uid':os.getuid()+1}
            reader=c.LocalClnRpc({'nodes':{'operator':node}})
            with patch.object(c,'json_command',new_callable=AsyncMock) as run:
                with self.assertRaises(ValueError):await reader('operator','getinfo')
                node['uid']=os.getuid();exe.chmod(0o700)
                with exe.open('wb') as f:f.truncate(64*1024*1024+1)
                with self.assertRaises(ValueError):await reader('operator','getinfo')
                run.assert_not_called()

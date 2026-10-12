"""Real process and worker-thread capture through the supervisor hooks."""
import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path

from simulator.config import Config
from simulator.engine import Engine, initialize
from simulator.model import SIGNET_GENESIS
from simulator.store import Store


class EngineTraceHooksTests(unittest.IsolatedAsyncioTestCase):
    async def test_full_native_boundaries_live_in_trace_with_compact_financial_references(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = Store(root, 'synthetic', 10000)
            initialize(store)
            code = '''import json,sys
r=json.load(sys.stdin)
for phase in ('before','after'):
 print(json.dumps({'kind':'driver_event','action_id':r['action_id'],'operation':r['operation'],
  'event':'client_evidence_'+phase,'data':{'fresh':True,'evidence':{'coins':[{'id':'public-test-coin'}]}}}),flush=True)
print('public SDK diagnostic',file=sys.stderr)
print(json.dumps({'action_id':r['action_id'],'status':'ok','actual_fee_sat':0,'data':{'balance':{'spendable_sat':0},'onchain':{'total_sat':0}}}),flush=True)
'''
            config = Config(root, (), (sys.executable, '-c', code), root/'wallets', SIGNET_GENESIS,
                            'container', 'image', 'server', 10000, 1, 10, True)
            store.queue('read', 'actor-01', 'H01', 'snapshot', {}, 0)
            try:
                engine = Engine(config, store)
                await engine.dispatch_one()
                self.assertEqual('completed', store.db.execute("SELECT state FROM action WHERE id='read'").fetchone()[0])
                records = list(store.trace.records(actor='actor-01'))
                events = [r for r in records if r['kind']=='driver.event']
                self.assertEqual(2, len(events))
                for event in events:
                    self.assertEqual('public-test-coin', event['payload']['data']['evidence']['coins'][0]['id'])
                for row in store.db.execute("SELECT payload FROM event WHERE kind='driver_evidence'"):
                    data = json.loads(row[0])['data']
                    self.assertTrue(data['fresh'])
                    self.assertNotIn('evidence', data)
                    self.assertEqual(64, len(data['trace_ref']['hash']))
                self.assertTrue(any(r['kind']=='driver.stdout' and r['raw'] for r in records))
                self.assertTrue(any(r['kind']=='driver.stderr' and r['raw'] for r in records))
                self.assertEqual(2, sum(r['kind']=='driver.call' for r in records))
                self.assertEqual(len(records), store.trace.verify()['records'])
                store.verify_event_chain()
            finally: store.close()

    async def test_worker_thread_chain_capture_preserves_exact_decimal_and_financial_chain(self):
        from decimal import Decimal
        from simulator.chain import ChainReader
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); store = Store(root, 'synthetic', 10000)
            store.attach_trace(); credential = root/'credential'; credential.write_text('user:test')
            reader = ChainReader('http://127.0.0.1:1',credential,SIGNET_GENESIS,capture=store.trace_sample,consumer='payout-test')
            class Response:
                def __enter__(self): return self
                def __exit__(self,*args): pass
                def read(self,*args): return b'{"result":{"value":0.00004661},"error":null}'
            try:
                with patch('simulator.chain.urllib.request.urlopen',return_value=Response()):
                    result=await asyncio.to_thread(reader.call,'getrawtransaction','a'*64,True)
                self.assertEqual(Decimal('0.00004661'),result['value'])
                record=next(store.trace.records())
                self.assertEqual('0.00004661',record['payload']['result']['value'])
                self.assertEqual('payout-test',record['payload']['consumer'])
                self.assertIsNotNone(record['raw'])
                self.assertEqual(0,store.db.execute('SELECT COUNT(*) FROM event').fetchone()[0])
                self.assertEqual(1,store.trace.verify()['records'])
            finally: store.close()

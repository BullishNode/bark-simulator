"""Synthetic private RPC bytes only; no live CLN/transport/cost admission credit."""
import asyncio
import copy
import hashlib
import unittest
from simulator import c_cln_payment_parts as c
from simulator.model import canonical,public_payload
from simulator.ownership import EvidenceGap
from simulator.process import CommandError
from tests.controlled_peer_fixture import NODES

class Parts(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.secret=bytes(range(32)).hex();self.h=hashlib.sha256(bytes.fromhex(self.secret)).hexdigest();self.calls=[]
        self.pay={'payment_hash':self.h,'bolt11':'synthetic-private-bolt11','status':'complete','preimage':self.secret,
          'amount_msat':1000000,'amount_sent_msat':1000003,'completed_at':101,'destination':NODES['fixture_peer'],'number_of_parts':2}
        self.parts=[{'id':i,'created_index':i,'groupid':1,'partid':i,'payment_hash':self.h,'status':'complete',
          'created_at':100,'amount_msat':500000,'amount_sent_msat':500000+fee,'destination':NODES['fixture_peer'],
          'payment_preimage':self.secret}for i,fee in [(1,1),(2,2)]]
    async def rpc(self,alias,method,params):
        self.calls.append((alias,method,copy.deepcopy(params)))
        if method=='getinfo':value={'id':NODES[alias],'network':'regtest','version':'synthetic'}
        elif method=='listpays':value={'pays':[self.pay]}
        elif method=='listinvoices':value={'invoices':[]}
        elif method=='decode':value={'type':'bolt11 invoice','valid':True,'payment_hash':self.h,'currency':'bcrt','payee':NODES['fixture_peer'],'amount_msat':1000000}
        elif method=='listsendpays':value={'payments':self.parts}
        else:raise AssertionError(method)
        return canonical(value).encode()
    async def read(self):return await c.CompletedPartsReader(self.rpc,node_ids=NODES,network='regtest',clock=lambda:102).read('operator',self.h)
    async def test_complete_parts_reuse_shared_verifier_and_replay_exact_originals(self):
        result=await self.read();safe=result['safe'];public_payload(safe)
        self.assertEqual(3,safe['router_fee_msat']);self.assertEqual(2,safe['row_count']);self.assertFalse(result['transport_admitted'])
        self.assertEqual({'payment_hash':self.h},next(p for _,m,p in self.calls if m=='listsendpays'))
        self.assertNotIn(self.secret,canonical(safe));self.assertNotIn('synthetic-private-bolt11',canonical(safe))
        replay=await c.replay(result['private_originals'],alias='operator',payment_hash=self.h,node_ids=NODES,network='regtest',query_times=result['query_times'])
        self.assertEqual(safe,replay)
    async def test_unknown_pending_or_missing_part_holds(self):
        original=copy.deepcopy(self.parts)
        for status in ('pending','unknown'):
            self.parts=copy.deepcopy(original);self.parts[1]['status']=status
            with self.assertRaises((EvidenceGap,ValueError)):await self.read()
        self.parts=original[:1]
        with self.assertRaises(EvidenceGap):await self.read()
    async def test_failed_retry_preserved_but_never_charged_as_miner_or_router_cost(self):
        failed={'id':3,'groupid':2,'partid':1,'payment_hash':self.h,'status':'failed','created_at':100,'amount_sent_msat':999999}
        self.parts.append(failed);result=await self.read()
        self.assertEqual(1,result['safe']['failed_parts']);self.assertEqual(3,result['safe']['router_fee_msat'])
    async def test_duplicate_identity_foreign_hash_wrong_witness_and_ambiguous_group_refuse(self):
        original=copy.deepcopy(self.parts)
        for change in ({'id':1,'created_index':1},{'payment_hash':'a'*64},{'payment_preimage':'0'*64},{'groupid':2},{'amount_sent_msat':500004}):
            self.parts=copy.deepcopy(original);self.parts[1].update(change)
            with self.assertRaises((EvidenceGap,ValueError)):await self.read()
    async def test_unknown_delivered_amount_or_destination_never_becomes_zero(self):
        for key in ('amount_msat','destination'):
            original=copy.deepcopy(self.parts);del self.parts[1][key]
            with self.assertRaises((KeyError,EvidenceGap)):await self.read()
            self.parts=original
    async def test_wrong_signed_network_refused_by_existing_reader(self):
        async def wrong(alias,method,params):
            raw=await self.rpc(alias,method,params)
            if method=='decode':return raw.replace(b'bcrt',b'tbs')
            return raw
        with self.assertRaises(ValueError):await c.CompletedPartsReader(wrong,node_ids=NODES,network='regtest').read('operator',self.h)
    async def test_replay_rejects_missing_extra_wrong_method_and_changed_original(self):
        result=await self.read();originals=result['private_originals']
        bad=copy.deepcopy(originals);bad[0]['method']='listsendpays'
        changed=copy.deepcopy(originals)
        position=next(i for i,row in enumerate(changed)if row['method']=='listsendpays')
        changed[position]['raw']=changed[position]['raw'].replace(b'500002',b'500003')
        for value in (originals[:-1],originals+[originals[-1]],bad,changed):
            with self.assertRaises((EvidenceGap,ValueError)):await c.replay(value,alias='operator',payment_hash=self.h,node_ids=NODES,network='regtest',query_times=result['query_times'])
    async def test_wire_bound_and_duplicate_json_keys_refuse_before_projection(self):
        for raw in (b'x'*(c.MAX_REPLY+1),b'{"id":1,"id":2}'):
            async def invalid(*args):return raw
            with self.assertRaises((EvidenceGap,ValueError,CommandError)):await c.CompletedPartsReader(invalid,node_ids=NODES,network='regtest').read('operator',self.h)

    async def test_actual_zero_fee_needs_complete_original_parts_not_empty_reply(self):
        self.pay['amount_sent_msat']=1000000
        for row in self.parts:row['amount_sent_msat']=row['amount_msat']
        result=await self.read();self.assertEqual(0,result['safe']['router_fee_msat'])
        self.parts=[]
        with self.assertRaises(EvidenceGap):await self.read()

    async def test_two_aggregate_cuts_cannot_change_identity_amount_or_clock(self):
        count=0
        async def changed(alias,method,params):
            nonlocal count
            if method=='listpays':
                count+=1
                if count==2:self.pay['amount_sent_msat']+=1
            return await self.rpc(alias,method,params)
        with self.assertRaises(EvidenceGap):await c.CompletedPartsReader(changed,node_ids=NODES,network='regtest',clock=lambda:102).read('operator',self.h)
        ticks=iter([102,103,102,104])
        with self.assertRaises(EvidenceGap):await c.CompletedPartsReader(self.rpc,node_ids=NODES,network='regtest',clock=lambda:next(ticks)).read('operator',self.h)

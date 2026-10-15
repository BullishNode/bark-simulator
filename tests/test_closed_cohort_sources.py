"""Synthetic source refusal controls; no live bootstrap/readiness credit."""
import copy
import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from simulator.closed_cohort_sources import verify_bootstrap_zero_assets, collect_closed_source_frames
from simulator.engine import initialize
from simulator.model import SIGNET_GENESIS, canonical
from simulator.store import Store
from tests.test_final_campaign import PINS


class Chain:
    def __init__(self):
        self.tip={'chain':'signet','blocks':100,'bestblockhash':'a'*64,'initialblockdownload':False}
        self.scan={'success':True,'height':100,'bestblock':'a'*64,'unspents':[],'total_amount':0}
        self.mempool=[]; self.tx_script='other'; self.changed=False
    def identity(self): return self.tip.copy()
    def tx(self,txid): return {'vout':[{'scriptPubKey':{'hex':self.tx_script}}]}
    def call(self,method,*args):
        if method=='getdescriptorinfo': return {'hasprivatekeys':False,'isrange':True,'issolvable':True,'descriptor':args[0]}
        if method=='deriveaddresses': return ['address'+str(i) for i in range(20)]
        if method=='validateaddress': return {'isvalid':True,'scriptPubKey':'script'+args[0]}
        if method=='scantxoutset': return self.scan
        if method=='getrawmempool':
            answer=self.mempool.copy()
            if self.changed:self.mempool.append('b'*64)
            return answer
        raise AssertionError(method)


class BootstrapSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name),'synthetic',10000)
        initialize(self.store);self.store.attach_trace();self.chain=Chain()
        self.config=SimpleNamespace(network='signet',expected_genesis=SIGNET_GENESIS)
        self.declaration={'id':'fresh','pins':PINS,'actors':['actor-01']}
        self.store.db.execute('INSERT INTO meta VALUES (?,?)',('zero_principal_identity_bootstrap',canonical(self.declaration)))
        self.store.event('identity_bootstrap_declared',{'declaration':self.declaration})
        self.native={'schema_version':1,'network':'signet','read_only':True,'complete':True,
            'descriptors':[{'keychain':'external','descriptor':'wpkh(public)#checksum','last_revealed_index':0}],
            'utxos':[],'pending_transactions':[],'pending_parents':[],'unavailable_parent_txids':[]}
        self.response={'action_id':'create-one','status':'ok','actual_fee_sat':0,'data':{'onchain_inventory':self.native}}
        self.store.db.execute("INSERT INTO action VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",('create-one','actor-01',None,'create','{}','completed',0,0,0,canonical(self.response),0,0))
        self.source()
    def source(self):
        self.store.db.execute("DELETE FROM event WHERE kind='driver_response'")
        self.store.event('driver_response',{'action_id':'create-one','response':self.response})
        self.store.db.execute('UPDATE action SET result=? WHERE id=?',(canonical(self.response),'create-one'))
    def tearDown(self): self.store.close();self.tmp.cleanup()
    def verify(self): return verify_bootstrap_zero_assets(self.store,self.config,self.chain,'actor-01','create-one',bootstrap_declaration=self.declaration)
    def test_original_create_and_independent_zero_assets_emit_scoped_receipt_only(self):
        result=self.verify();self.assertTrue(result['zero_assets']);self.assertEqual([0,19],result['descriptor_range'])
        self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM event WHERE kind IN ('financial_operating_readiness','treasury_inventory')").fetchone()[0])
    def test_confirmed_assets_and_wrong_tip_refuse(self):
        self.chain.scan['unspents']=[{'txid':'b'*64}]
        with self.assertRaisesRegex(ValueError,'not empty'):self.verify()
        self.chain.scan['unspents']=[];self.chain.scan['bestblock']='c'*64
        with self.assertRaisesRegex(ValueError,'exact tip'):self.verify()
    def test_unconfirmed_assets_complete_mempool_bound_and_churn_refuse(self):
        self.chain.mempool=['b'*64];self.chain.tx_script='scriptaddress0'
        with self.assertRaisesRegex(ValueError,'unconfirmed assets'):self.verify()
        self.chain.tx_script='other';self.chain.mempool=[str(i) for i in range(65)]
        with self.assertRaisesRegex(ValueError,'bound'):self.verify()
        self.chain.mempool=[];self.chain.changed=True
        with self.assertRaisesRegex(ValueError,'mempool changed'):self.verify()
    def test_missing_native_rows_and_fabricated_internal_keychain_refuse(self):
        del self.native['pending_transactions'];self.source()
        with self.assertRaisesRegex(ValueError,'native'):self.verify()
        self.native['pending_transactions']=[];self.native['descriptors'].append({'keychain':'internal'})
        self.source()
        with self.assertRaisesRegex(ValueError,'single external'):self.verify()
    def test_response_mismatch_or_nonzero_create_fee_refuse(self):
        self.store.db.execute("UPDATE action SET result='{}' WHERE id='create-one'")
        with self.assertRaisesRegex(ValueError,'differs'):self.verify()
        self.source();self.store.db.execute("UPDATE action SET actual_fee_sat=1 WHERE id='create-one'")
        with self.assertRaisesRegex(ValueError,'zero-fee'):self.verify()

    def test_actual_source_capture_preserves_four_wallet_provenance_without_readiness(self):
        actions={'actor-01':'create-one'}
        for number in (2,3,4):
            actor='actor-'+str(number).zfill(2);action_id='snapshot-'+str(number)
            response=copy.deepcopy(self.response);response['action_id']=action_id
            self.store.db.execute('INSERT INTO action VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                (action_id,actor,None,'snapshot','{}','completed',0,0,0,canonical(response),0,0))
            self.store.event('driver_response',{'action_id':action_id,'response':response});actions[actor]=action_id
        self.config.inventory_command=('fixed-bridge',)
        replies=[{'kind':'closed_frontier','complete':False,'qualified':False,'read_only':True,
                    'database_tables_complete':True,'inventory_consistent':True},
                 {'kind':'financial_readiness','complete':False,'qualified':False,'network':'signet',
                    'genesis':SIGNET_GENESIS,'height':100,'tip_hash':'a'*64,'stable_tip':True}]
        with patch('simulator.closed_cohort_sources.json_command',AsyncMock(side_effect=replies)) as command:
            result=asyncio.run(collect_closed_source_frames(self.store,self.config,self.chain,wallet_actions=actions))
        self.assertEqual(4,len(result['native_wallets']));self.assertTrue(result['independent_same_tip'])
        self.assertFalse(result['qualified']);self.assertFalse(result['complete']);self.assertEqual(2,command.await_count)
        self.assertEqual(2,self.store.db.execute("SELECT count(*) FROM event WHERE kind='closed_cohort_original_source'").fetchone()[0])
        self.assertEqual(0,self.store.db.execute("SELECT count(*) FROM event WHERE kind='financial_operating_readiness'").fetchone()[0])

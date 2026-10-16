"""Actual public SQLite/scan/bank/treasury reducers, synthetic authority/RPCs.

These fixtures do not authorize native creates, live membership or readiness.
"""
import copy
import hashlib
import sqlite3
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from simulator import c_normal_member_join as c
from simulator import funding_bank
from simulator.funding import WalletRpc
from simulator.model import SIGNET_GENESIS,canonical
from simulator.trace import normalized
from tests import test_c_normal_cln_join as fixture
from tests import test_wallet_projection as w


class Members(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.f = fixture.ClnJoin();self.f.setUp()
        for function,args,kwargs in self.f._cleanups:self.addCleanup(function,*args,**kwargs)
        self.f._cleanups.clear()
        self.store=self.f.store;self.observation=self.f.observation;self.root=self.f.f.f.root/'customers'
        self.root.mkdir(mode=0o700);self.core=self.f.f.f.chain;self.original_call=self.core.call
        self.mapping={a:a for a in c.c_cohort.INITIAL};self.descriptors={};self.addresses={};self.history_sources={}
        members=list(self.f.boundary['members'])
        for actor in self.mapping:
            directory=self.root/actor;directory.mkdir(mode=0o700);desc='wpkh(public-'+actor+'/*)#fixture'
            self.descriptors[desc]=actor;script=self.script(actor,0);index=hashlib.sha256(bytes.fromhex(script)).hexdigest()
            db=sqlite3.connect(directory/'db.sqlite')
            db.executescript('CREATE TABLE bdk_wallet(id,descriptor,change_descriptor,network);CREATE TABLE bdk_descriptor_last_revealed(descriptor_id,last_revealed);CREATE TABLE bdk_descriptor_derived_spks(descriptor_id,spk_index,spk);CREATE TABLE bdk_wallet_locked_outpoints(txid,vout);')
            db.execute('INSERT INTO bdk_wallet VALUES(1,?,NULL,?)',(desc,'signet'))
            db.execute('INSERT INTO bdk_descriptor_last_revealed VALUES(?,0)',(index,))
            db.execute('INSERT INTO bdk_descriptor_derived_spks VALUES(?,0,?)',(index,bytes.fromhex(script)))
            db.commit();db.close()
            self.store.event('driver_response',{'response':{'data':{'onchain_inventory':{
                'descriptors':[{'keychain':'external','descriptor':desc}]}}}})
            event,_=c._source_event(self.store,self.sequence())
            self.history_sources[actor]={'driver_response_sequence':event['sequence'],'driver_response_hash':event['hash']}
            members.append(self.member(actor,'customer','native-'+actor,[desc]))
        self.bank_descriptor='wpkh(public-bank/*)#fixture';self.descriptors[self.bank_descriptor]='bank'
        members.append(self.member('bank','operator','core-wallet:Cbank',[self.bank_descriptor]))
        self.boundary={**self.f.boundary,'members':members}
        outer=self
        def call(method,*args,**kwargs):
            if method=='deriveaddresses' and args[0] in outer.descriptors:
                name=outer.descriptors[args[0]]
                result=[]
                for i in range(args[1][0],args[1][1]+1):
                    address=name+':'+str(i);outer.addresses[address]=outer.script(name,i);result.append(address)
                return result
            if method=='validateaddress' and args[0] in outer.addresses:
                return {'isvalid':True,'scriptPubKey':outer.addresses[args[0]]}
            if method=='scantxoutset' and args[0]=='start':
                allowed=set()
                for r in args[1]:
                    for a in call('deriveaddresses',r['desc'],r['range']):allowed.add(call('validateaddress',a)['scriptPubKey'])
                coins=[{'txid':p[0],'vout':p[1],'amount':v['value'],'scriptPubKey':v['scriptPubKey']['hex']}
                    for p,v in outer.core.unspent.items() if v['scriptPubKey']['hex'] in allowed]
                result={'success':True,'height':outer.core.height,'bestblock':outer.core.tip,
                    'unspents':coins,'total_amount':str(sum(r['amount'] for r in coins))}
                outer.core.last_capture=outer.store.trace_sample({'kind':'chain.rpc','payload':{
                    'method':method,'params':list(args),'error':None,'result':normalized(result)},
                    'raw':canonical(normalized({'result':result,'error':None})).encode()})
                return result
            return outer.original_call(method,*args)
        self.core.call=call;self.core.expected=SIGNET_GENESIS;self.core.url='http://127.0.0.1:38332';self.core.credential='unused'
        self.bank_txid=self.core.add(w.transaction(['dd'*32+':1'],[(18000000,self.script('bank',0))],nonce=3),3)
        self.core.unspent[(self.bank_txid,0)]={'value':__import__('decimal').Decimal('0.18'),
            'confirmations':3,'bestblock':self.core.tip,'coinbase':False,'scriptPubKey':{'hex':self.script('bank',0)}}
        self.core.mempool_unspent[(self.bank_txid,0)]=self.core.unspent[(self.bank_txid,0)]
        class Bank:
            wallet='Cbank'
            def __init__(self):self.last_response_bytes=0
            def call(self,method,*args,**kwargs):
                if method=='getwalletinfo':value={'walletname':self.wallet,'walletversion':1,'format':'sqlite',
                    'txcount':1,'descriptors':True,'scanning':False,'lastprocessedblock':{'height':1000,'hash':outer.core.tip}}
                elif method=='listdescriptors':
                    if args!=(False,):raise AssertionError('only public descriptors')
                    value={'wallet_name':self.wallet,'descriptors':[{'desc':outer.bank_descriptor,'next_index':1,'range':[0,1000]}]}
                elif method=='listunspent':value=[{'txid':outer.bank_txid,'vout':0,'amount':'0.18','confirmations':3,
                    'scriptPubKey':outer.script('bank',0),'safe':True,'spendable':True,'solvable':True}]
                elif method=='listlockunspent':value=[]
                elif method=='listsinceblock':value={'lastblock':outer.core.tip,'transactions':[],'removed':[]}
                elif method=='getbalances':value={'mine':{'trusted':'0.18','untrusted_pending':'0','immature':'0'}}
                else:value=outer.core.call(method,*args)
                self.last_response_bytes=len(canonical(normalized(value)).encode());return copy.deepcopy(value)
        class Core:
            def __init__(self):self.last_response_bytes=0
            def call(self,method,*args,**kwargs):
                value=outer.core.call(method,*args)
                self.last_response_bytes=len(canonical(normalized(value)).encode());return value
        self.bank=Bank();self.bank_core=Core()
        token=self.root.parent/'credential';token.write_text('synthetic-test-only');token.chmod(0o600)
        self.binding=c.MemberBinding(str(self.root),self.mapping,WalletRpc(token,'Cbank'),1)
        self.binding=c.MemberBinding(str(self.root),self.mapping,self.binding.bank,self.admit())
        self.config=SimpleNamespace(wallet_root=self.root,network='signet',expected_genesis=SIGNET_GENESIS)
        from simulator.identity_bootstrap import _root
        self.history={'wallet_root':str(self.root),'filesystem':_root(str(self.root)),
            'financial_pins':self.observation['financial_pins'],'sources':self.history_sources}

    def script(self,name,index):return '0014'+hashlib.sha256((name+':'+str(index)).encode()).hexdigest()[:40]
    def sequence(self):return self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
    def member(self,name,role,identity,descriptors):
        value={'id':name,'kind':'wallet','role':role,'identity':identity,'descriptors':descriptors}
        self.store.event('treasury_member_verified',{'member':value,'genesis':SIGNET_GENESIS,'financial_pins':self.observation['financial_pins']})
        return {**value,'verification_sequence':self.sequence()}
    def admit(self):
        # Qualification identifies this exact prospective test construction;
        # it is synthetic authority, not an installed source receipt.
        self.store.event('c_normal_member_source_qualified',c.requirement(self.binding,self.observation['financial_pins']))
        return self.sequence()
    def count(self,kind):return self.store.db.execute('SELECT count(*) FROM event WHERE kind=?',(kind,)).fetchone()[0]
    async def prior(self):
        with patch('simulator.confirmed_scan._identity',side_effect=lambda *a,**k:{'owners':copy.deepcopy(k['members']),'synthetic_runtime':'explicit'}):
            return await self.f.collect()
    async def collect(self,prior=None):
        prior=await self.prior() if prior is None else prior
        with (patch.object(c,'_context'),patch.object(c,'history',return_value=self.history),
                patch.object(funding_bank,'WalletRpc',return_value=self.bank),patch.object(funding_bank,'ChainReader',return_value=self.bank_core),
                patch('simulator.confirmed_scan._identity',side_effect=lambda *a,**k:{'owners':copy.deepcopy(k['members']),'synthetic_runtime':'explicit'})):
            return await c.collect(self.store,self.config,self.core,self.observation,boundary=self.boundary,
                checked=self.f.f.checked,runtime=self.f.f.runtime,cln=prior,binding=self.binding)

    async def test_real_twelve_SQLite_and_bank_reducers_count_all_seventeen_members(self):
        result=await self.collect();safe=result['safe']
        self.assertEqual(17,len(safe['inventory_sequences']));self.assertEqual(12,len(safe['metadata']))
        self.assertEqual(18100000000,safe['actual_member_assets']['total_msat'])
        self.assertEqual(18100000000,safe['actual_member_assets']['operator_controlled_msat'])
        self.assertEqual([],safe['remaining_declared_members']);self.assertFalse(safe['complete']);self.assertFalse(safe['financial_readiness'])
        self.assertEqual(2,self.count(funding_bank.EVENT_KIND));self.assertEqual(0,self.count('financial_operating_readiness'))
        self.assertEqual('operator',next(r for r in self.boundary['members'] if r['id']=='bank')['role'])

    async def test_absent_real_history_stays_hold_before_bank_or_new_member_source(self):
        prior=await self.prior()
        with patch.object(c,'_context'):
            with self.assertRaises(ValueError):
                await c.collect(self.store,self.config,self.core,self.observation,boundary=self.boundary,
                    checked=self.f.f.checked,runtime=self.f.f.runtime,cln=prior,binding=self.binding)
        self.assertEqual(0,self.count(funding_bank.EVENT_KIND));self.assertEqual(0,self.count(c.KIND))

    async def test_missing_customer_never_counts_as_zero(self):
        self.boundary['members']=[v for v in self.boundary['members'] if v['id']!='actor-12']
        with self.assertRaisesRegex(c.EvidenceGap,'membership'):await self.collect()
        self.assertEqual(0,self.count(c.KIND))

    async def test_extra_actual_wallet_directory_is_not_omitted_from_initial_twelve(self):
        prior=await self.prior();(self.root/'actor-13').mkdir(mode=0o700)
        with self.assertRaisesRegex(c.EvidenceGap,'unenumerated'):
            await self.collect(prior)
        self.assertEqual(0,self.count(funding_bank.EVENT_KIND))

    async def test_original_descriptor_mismatch_refuses(self):
        prior=await self.prior();path=self.root/'actor-12'/'db.sqlite'
        db=sqlite3.connect(path);db.execute("UPDATE bdk_wallet SET descriptor='wpkh(other/*)#fixture'");db.commit();db.close()
        with self.assertRaisesRegex(c.EvidenceGap,'original native'):await self.collect(prior)
        self.assertEqual(0,self.count(c.KIND))

    async def test_nonempty_WAL_or_locked_customer_state_never_becomes_zero(self):
        prior=await self.prior();path=self.root/'actor-12'/'db.sqlite'
        Path(str(path)+'-wal').write_bytes(b'active-WAL-synthetic')
        with self.assertRaisesRegex(ValueError,'WAL'):await self.collect(prior)
        self.assertEqual(0,self.count(c.KIND))

    async def test_customer_cash_is_counted_without_operator_role_alias(self):
        prior=await self.prior();script=self.script('actor-12',0)
        txid=self.core.add(w.transaction(['ee'*32+':0'],[(2000,script)],nonce=4),3)
        self.core.unspent[(txid,0)]={'value':__import__('decimal').Decimal('0.00002'),
            'confirmations':3,'bestblock':self.core.tip,'coinbase':False,'scriptPubKey':{'hex':script}}
        result=await self.collect(prior);assets=result['safe']['actual_member_assets']
        self.assertEqual(18102000000,assets['total_msat'])
        self.assertEqual(18100000000,assets['operator_controlled_msat'])
        self.assertEqual('customer',assets['assets'][txid+':0']['role'])

    async def test_bad_original_descriptor_index_fails_actual_independent_derivation(self):
        prior=await self.prior();db=sqlite3.connect(self.root/'actor-12'/'db.sqlite')
        db.execute('UPDATE bdk_descriptor_last_revealed SET descriptor_id=?',('f'*64,))
        db.execute('UPDATE bdk_descriptor_derived_spks SET descriptor_id=?',('f'*64,));db.commit();db.close()
        with self.assertRaisesRegex(c.EvidenceGap,'descriptor index/cache'):
            await self.collect(prior)
        self.assertEqual(0,self.count(c.KIND))

    def test_twentyfour_constructor_never_substitutes_for_actual_ramp_history(self):
        with patch.object(c.c_cohort,'historical_initial_identity_sources',return_value={'sources':self.history_sources}):
            with self.assertRaisesRegex(ValueError,'profile missing'):
                c.history(self.store,set(c.c_cohort.INITIAL+c.c_cohort.RAMP))

    async def test_changed_metadata_during_scan_is_not_relabelled_fresh(self):
        prior=await self.prior();original=self.core.call
        def changed(method,*args,**kwargs):
            result=original(method,*args,**kwargs)
            if method=='scantxoutset' and args[0]=='start':
                db=sqlite3.connect(self.root/'actor-12'/'db.sqlite')
                db.execute('UPDATE bdk_descriptor_last_revealed SET last_revealed=1');db.commit();db.close()
            return result
        self.core.call=changed
        with self.assertRaisesRegex(c.EvidenceGap,'metadata changed'):await self.collect(prior)
        self.assertEqual(0,self.count(c.KIND))

    def test_A_B_public_role_gate_stays_closed_for_operator_bank(self):
        from simulator.two_step_capture import public_wallet_projection
        with self.assertRaises(ValueError):
            public_wallet_projection({'role':'operator'}, {},height=1000,tip_hash=self.core.tip)


if __name__=='__main__':unittest.main()

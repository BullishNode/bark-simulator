"""Synthetic source/SQLite/Core controls; no live escrow or financial authority."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock
from decimal import Decimal

from simulator import c_escrow as e,c_pilot
from simulator.architecture import DIRECT_PER_KEY
from simulator.model import SIGNET_GENESIS,canonical
from simulator.store import Store
from tests.test_c_pilot import pilot


class EscrowOpeningControls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'state'
        self.store=Store(self.root,'synthetic-escrow',60000,architecture_profile=DIRECT_PER_KEY)
        self.addCleanup(lambda:self.store.close())
        self.store.db.execute("INSERT INTO meta VALUES ('paused','same retained namespace')")
        value={**pilot(),'bank_opening_sat':900000};c_pilot.declare(self.store,value)
        self.original=value
        self.raw=(Path(__file__).parent/'data/c-escrow-allocation-authority.json').read_bytes()
        # Public synthetic bytes are deliberately NOT the live authority. Only
        # this test overrides its expected hash; production fixed hash is intact.
        self.assertNotEqual(e.AUTHORITY_SHA256,hashlib.sha256(self.raw).hexdigest())
        expected=hashlib.sha256(self.raw).hexdigest()
        authority=mock.patch.object(e,'AUTHORITY_SHA256',expected);authority.start();self.addCleanup(authority.stop)
        patch=mock.patch.object(e,'checked_file',return_value=(self.raw,expected));patch.start();self.addCleanup(patch.stop)
        allocation=json.loads(self.raw)['allocations'][0];self.script=allocation['script'];self.tip='a'*64
        expected={**e.ORIGINAL_POINTS,e.ESCROW_POINT:e.ESCROW_SAT}
        self.coins=[{'txid':point.split(':')[0],'vout':int(point.split(':')[1]),
            'amount':str(Decimal(amount)/100000000),'scriptPubKey':self.script,
            'confirmations':5,'safe':True,'spendable':True,'solvable':True} for point,amount in expected.items()]
        self.bank={'source_identity':{'wallet_name':e.BANK,'endpoint_path':'/wallet/'+e.BANK},
            'getwalletinfo':{'walletname':e.BANK},'network':'signet','genesis':SIGNET_GENESIS,
            'height':100,'tip_hash':self.tip,'completed_at':time.time(),
            'read_only':True,'stable_tip':True,'complete_source_projection':True,
            'pending_transactions':[],'pending_parents':[],'locked_coins':[],'listlockunspent':[],
            'listsinceblock':{'transactions':[],'removed':[]},'listunspent':self.coins,
            'getbalances':{'mine':{'trusted':'0.18000000','untrusted_pending':0,'immature':0}}}
        self.sequence=self.event('treasury_bank_original_source',self.bank)
        self.calls=[];outer=self
        class Core:
            def call(self,method,*args,**kwargs):
                outer.calls.append((method,args,kwargs))
                if method=='getblockhash':return SIGNET_GENESIS
                if method=='getblockchaininfo':return {'chain':'signet','initialblockdownload':False,'blocks':100,'bestblockhash':outer.tip}
                if method=='gettxout':
                    point=args[0]+':'+str(args[1]);row=next(c for c in outer.coins if c['txid']+':'+str(c['vout'])==point)
                    return {'bestblock':outer.tip,'confirmations':5,'value':row['amount'],'scriptPubKey':{'hex':row['scriptPubKey']}}
                raise AssertionError('non-readonly/unexpected RPC')
        self.chain=Core()

    def event(self,kind,value):
        self.store.event(kind,value);return self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
    def record(self,sequence=None):return e.record_transition(self.store,self.chain,bank_source_sequence=self.sequence if sequence is None else sequence)
    def assert_absent(self):
        self.assertIsNone(self.store.get_meta(e.KEY))
        self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM event WHERE kind=?',(e.EVENT,)).fetchone()[0])

    def test_all18M_included_once_original_limits_ids_actions_and_namespace_retained(self):
        self.store.actor('actor-01','same original actor')
        self.store.db.execute("INSERT INTO action VALUES ('c_create_01','actor-01',NULL,'create','{}','completed',0,0,0,'{}',0,0)")
        before_actions=[tuple(row) for row in self.store.db.execute('SELECT * FROM action')]
        before_meta=dict(self.store.db.execute('SELECT * FROM meta'))
        self.assertTrue(self.record());self.assertFalse(self.record())
        value=e.transition(self.store)
        self.assertEqual(18000000,sum(c['amount_sat'] for c in value['physical_outputs']))
        self.assertEqual(3,len({c['outpoint'] for c in value['physical_outputs']}))
        self.assertEqual(self.original,c_pilot.declaration(self.store))
        self.assertEqual(before_actions,[tuple(row) for row in self.store.db.execute('SELECT * FROM action')])
        self.assertEqual(before_meta,{k:v for k,v in self.store.db.execute('SELECT * FROM meta') if k!=e.KEY})
        funding=c_pilot.funding_policy(self.store);board=c_pilot.board_policy(self.store)
        self.assertEqual(18000000,funding['opening_sat']);self.assertEqual(18000000,board['opening_sat'])
        self.assertEqual({'actor-01':25000,'watchman':100000},funding['amounts'])
        self.assertEqual((125000,60000,40000,1000),(funding['principal_sat'],funding['ordinary_budget_sat'],funding['urgent_budget_sat'],funding['maximum_fee_sat']))
        self.assertEqual(self.original['board_action_id'],board['board_action_id'])
        self.assertFalse(value['financial_readiness']);self.assertFalse(value['new_dispatch_authority']);self.assertFalse(value['fee_budget_reset'])
        self.assertEqual({'getblockchaininfo','getblockhash','gettxout'},{call[0] for call in self.calls})
        self.assertEqual(3,sum(method=='gettxout' for method,_,_ in self.calls))
        self.store.verify_event_chain()

    def test_restart_and_later_spends_do_not_reset_or_redeclare_opening(self):
        self.record();self.store.close();self.store=Store(self.root,'synthetic-escrow',60000,architecture_profile=DIRECT_PER_KEY)
        self.chain.call=mock.Mock(side_effect=AssertionError('retained history must not query a now spent opening'))
        self.assertEqual(18000000,e.effective_opening_sat(self.store));self.assertFalse(self.record())
        other=self.event('treasury_bank_original_source',self.bank)
        with self.assertRaisesRegex(ValueError,'immutable'):self.record(other)
        self.assertEqual(1,self.store.db.execute('SELECT count(*) FROM event WHERE kind=?',(e.EVENT,)).fetchone()[0])

    def test_wrong_or_missing_fixed_authority_is_not_request_authority(self):
        with mock.patch.object(e,'checked_file',return_value=(b'{}','0'*64)),self.assertRaisesRegex(ValueError,'authority differs'):self.record()
        with mock.patch.object(e,'checked_file',side_effect=FileNotFoundError),self.assertRaises(FileNotFoundError):self.record()
        self.assert_absent();self.assertFalse(self.calls)

    def test_only_original900k_pilot_can_take_this_exact_once_transition(self):
        self.assertEqual(900000,e.effective_opening_sat(self.store))
        self.store.db.execute('UPDATE meta SET value=? WHERE key=?',(canonical({**self.original,'bank_opening_sat':150000}),c_pilot.KEY))
        with self.assertRaisesRegex(ValueError,'immutable|differs'):self.record()
        self.assert_absent()

    def test_foreign_incomplete_stale_pending_or_locked_bank_source_holds(self):
        changes=[{'source_identity':{'wallet_name':'foreign','endpoint_path':'/wallet/foreign'}},
                 {'complete_source_projection':False},{'completed_at':time.time()-91},
                 {'pending_transactions':[{'txid':'b'*64}]},{'locked_coins':[{'outpoint':e.ESCROW_POINT}]},
                 {'getbalances':{'mine':{'trusted':'0.18000001','untrusted_pending':0,'immature':0}}}]
        for change in changes:
            seq=self.event('treasury_bank_original_source',{**self.bank,**change})
            with self.subTest(change=change),self.assertRaises(ValueError):self.record(seq)
            self.assert_absent()

    def test_duplicate_extra_unconfirmed_changed_value_script_or_outpoint_holds(self):
        cases=[self.coins+[self.coins[0]],self.coins[:-1],
               [{**c,'confirmations':0} if i==0 else c for i,c in enumerate(self.coins)],
               [{**c,'amount':'0.17100001'} if i==2 else c for i,c in enumerate(self.coins)],
               [{**c,'scriptPubKey':'0014'+'00'*20} if i==2 else c for i,c in enumerate(self.coins)],
               [{**c,'txid':'f'*64} if i==2 else c for i,c in enumerate(self.coins)]]
        for coins in cases:
            seq=self.event('treasury_bank_original_source',{**self.bank,'listunspent':coins})
            with self.subTest(coins=coins),self.assertRaises(ValueError):self.record(seq)
            self.assert_absent()

    def test_independent_unspent_value_network_or_tip_mismatch_holds(self):
        original=self.chain.call
        for response in (None,{'bestblock':self.tip,'confirmations':0,'value':'0.17100000','scriptPubKey':{'hex':self.script}},
                         {'bestblock':'b'*64,'confirmations':5,'value':'0.17100000','scriptPubKey':{'hex':self.script}}):
            def call(method,*args,**kwargs):
                if method=='gettxout' and args[:2]==(e.ESCROW_POINT.split(':')[0],2):return response
                return original(method,*args,**kwargs)
            with self.subTest(response=response),mock.patch.object(self.chain,'call',side_effect=call),self.assertRaises(ValueError):self.record()
            self.assert_absent()
        with mock.patch.object(self.chain,'call',return_value={'chain':'regtest','initialblockdownload':False,'blocks':100,'bestblockhash':self.tip}),self.assertRaises(ValueError):self.record()
        self.assert_absent()

    def test_pending_unknown_or_monetary_action_prohibits_new_transition(self):
        self.store.actor('actor-01','original')
        for operation,state,fee in (('create','queued',0),('sync','outcome_unknown',0),('board','completed',0),('create','completed',1)):
            self.store.db.execute('DELETE FROM action')
            self.store.db.execute('INSERT INTO action VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',('same-id','actor-01',None,operation,'{}',state,0,fee,fee,'{}',0,0))
            with self.subTest(operation=operation,state=state),self.assertRaisesRegex(ValueError,'monetary, pending or unknown'):self.record()
            self.assert_absent()

    def test_empty_funding_table_allowed_but_any_retained_funding_or_fee_history_holds(self):
        self.store.db.execute('CREATE TABLE funding_batch(id TEXT)')
        self.store.db.execute("INSERT INTO funding_batch VALUES ('retained')")
        with self.assertRaisesRegex(ValueError,'retained funding'):self.record()
        self.assert_absent();self.store.db.execute('DELETE FROM funding_batch')
        self.assertTrue(self.record())

    def test_missing_metadata_over_retained_event_holds_instead_of_silent900k_reset(self):
        self.record();self.store.db.execute('DELETE FROM meta WHERE key=?',(e.KEY,))
        with self.assertRaisesRegex(ValueError,'metadata missing'):e.effective_opening_sat(self.store)
        with self.assertRaises(ValueError):self.record()

    def test_retained_bank_or_transition_event_tamper_holds(self):
        self.record()
        self.store.db.execute('UPDATE event SET payload=? WHERE sequence=?',(canonical({**self.bank,'height':101}),self.sequence))
        with self.assertRaisesRegex(ValueError,'event frame changed'):e.effective_opening_sat(self.store)

    def test_existing_treasury_epoch_or_fee_history_is_never_reset(self):
        for key in ('conserved_treasury_boundary','preserved_financial_opening','financial_operating_envelope','final_financial_epoch'):
            self.store.db.execute('INSERT INTO meta VALUES (?,?)',(key,'retained immutable declaration'))
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'cannot be reset'):self.record()
            self.assert_absent();self.assertEqual('retained immutable declaration',self.store.get_meta(key))
            self.store.db.execute('DELETE FROM meta WHERE key=?',(key,))
        self.event('financial_cost_verified',{'amount_msat':1,'budget':'ordinary'})
        with self.assertRaisesRegex(ValueError,'monetary, pending or unknown'):self.record()
        self.assert_absent()

    def test_original900k_plus_17_1M_classification_conserves_once_not_18M_plus_17_1M(self):
        from simulator.treasury import reconcile_edge
        from simulator.model import InvariantError
        self.record();value=e.transition(self.store)
        opening={'total_msat':value['original_pilot_bank_opening_sat']*1000}
        closing={'total_msat':18000000000,'operator_controlled_msat':18000000000}
        flow={'id':value['allocation_id'],'source':'neutral-outside','destination':'bank',
              'kind':'injection','amount_msat':value['escrow_bank_inflow_sat']*1000}
        result=reconcile_edge(opening,closing,[flow],[],{'bank':{'role':'operator'}})
        self.assertEqual(900000000,result['opening_msat'])
        self.assertEqual(17100000000,result['declared_injections_msat'])
        self.assertEqual(18000000000,result['closing_msat'])
        with self.assertRaises(InvariantError):reconcile_edge(opening,closing,[flow,flow],[],{'bank':{'role':'operator'}})
        with self.assertRaises(InvariantError):reconcile_edge(closing,closing,[flow],[],{'bank':{'role':'operator'}})


if __name__=='__main__':unittest.main()

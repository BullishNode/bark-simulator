"""Synthetic independent-oracle contracts; these do not earn native money credit."""
import copy,json,tempfile,unittest
from pathlib import Path
from simulator.store import Store
from simulator.direct_settlements import frame,record,check_group,commit_checked
from simulator.model import InvariantError,canonical
from simulator.ownership import EvidenceGap
from simulator.negative_checks import record_bytes

class DirectSettlementTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name),'synthetic',10000)
        self.store.actor('actor-01','ordinary fixture')
        self.customer='11'*32+':0';self.anchor='22'*32+':0';self.fee_anchor='11'*32+':1'
        self.script='0014'+'33'*20;self.operator='5120'+'44'*32;self.pub='02'+'55'*32;self.mb='02'+'66'*32
        self.rec={'mailbox_pk':self.mb,'spk':self.script,'account_xpub':'11'*78,'mailbox_sig':'22'*64,'account_sig':'33'*64}
        self.bound={'mailbox_pk':self.mb,'spk':self.script,'account_xpub':'synthetic-xpub',
            'fallback_record':record_bytes(self.rec),'child_index':0}
        self.proof={'proof_encoding':'ark-public-authorization-v1','authorization_path_valid':True,'conditional_steps':0,
            'user_pubkey':self.pub,'binding':self.bound,'ancestor_ids':[self.anchor,self.customer],'chain_anchor':self.anchor,
            'path':[{'txid':'11'*32,'inputs':[self.anchor],'outputs':[{'vout':0,'value_sat':20000,'script_pubkey':'source'},
                {'vout':1,'value_sat':1000,'script_pubkey':'51024e73'}]}]}
        self.store.db.execute('INSERT INTO owner_key VALUES(?,?,?,?)',(self.pub,'actor-01',self.mb,canonical(self.proof)))
        self.store.db.execute('INSERT INTO owner_record VALUES(?,?,?,?,?)',('actor-01',self.mb,'synthetic-xpub',self.script,canonical(self.bound)))
        self.store.db.execute('INSERT INTO owned_coin VALUES(?,?,?,?,?,?)',(self.customer,self.pub,20000,'synthetic-digest','synthetic-public-encoding',canonical(self.proof)))
        self.store.db.execute('INSERT INTO operator_script VALUES(?,?)',(self.operator,'synthetic independent descriptor result'))
        self.alloc={'id':self.customer,'freeze_set':'group','owner_pubkey':self.pub,'spk':self.script,'disposition':'pay',
            'gross_sat':20000,'fee_sat':1000,'payout_sat':19000,'forfeited_sat':0,'source':'registered',
            'retirement_ids':[self.customer],'frozen_at':'2026-10-14T00:00:00Z'}
        self.op={'id':self.fee_anchor,'freeze_set':'group','owner_pubkey':None,'spk':None,'disposition':'operator',
            'gross_sat':1000,'fee_sat':0,'payout_sat':0,'forfeited_sat':0,'source':'transition-fee-anchor',
            'retirement_ids':[self.customer],'frozen_at':'2026-10-14T00:00:00Z'}
        self.carrier={'txid':'77'*32,'generation':1,'backing_ids':[self.anchor],'fee_inputs':[],
            'miner_fee_sat':1124,'funding_subsidy_sat':0,'created_at':'2026-10-14T00:00:00Z','confirmed_height':201,'confirmed_block':'88'*32}
        self.value={'kind':'direct_journal','schema_version':1,'fallback_protocol':3,
            'binding_scope':'owners_referenced_by_allocations','journal_complete':True,
            'inventory_consistent':True,'complete':False,'qualified':False,'rows':{'allocations':[self.alloc,self.op],
            'carriers':[self.carrier],'mappings':[{'txid':self.carrier['txid'],'allocation_id':self.customer,'vout':0},
                {'txid':self.carrier['txid'],'allocation_id':self.fee_anchor,'vout':None}],
            'records':[self.rec],'links':[{'user_pubkey':self.pub,'mailbox_pk':self.mb,'child_index':0}]}}
        self.tx={'txid':self.carrier['txid'],'confirmations':6,'blockhash':'88'*32,
            'inputs':[{'outpoint':self.anchor,'amount_sat':21000,'script':'backing'}],
            'outputs':[{'vout':0,'script':self.script,'amount_sat':19000},{'vout':1,'script':self.operator,'amount_sat':876}]}
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def check(self):return check_group(self.store,self.value,'group',{self.tx['txid']:self.tx})
    def test_actual_example_and_operator_subsidy_are_exact(self):
        result=self.check();self.assertEqual(-124,result['accounting']['operator_capital_delta_sat'])
        self.assertEqual(1124,result['accounting']['mining_fee_sat'])
        commit_checked(self.store,result,self.tx)
        self.assertEqual(19000,self.store.db.execute('SELECT amount_sat FROM checked_settlement').fetchone()[0])
    def test_flat_fee_surplus_can_exceed_miner_fee(self):
        self.tx['outputs'][1]['amount_sat']=1900;self.carrier['miner_fee_sat']=100
        self.assertEqual(900,self.check()['accounting']['flat_fee_surplus_sat'])
    def test_frozen_mempool_and_unrecorded_confirmation_never_count_as_paid(self):
        self.tx['confirmations']=0
        with self.assertRaises(EvidenceGap):self.check()
        self.tx['confirmations']=6;self.carrier['confirmed_height']=None
        with self.assertRaises(EvidenceGap):self.check()
        self.assertEqual(0,self.store.db.execute('SELECT COUNT(*) FROM checked_settlement').fetchone()[0])
    def test_older_confirmed_winner_beats_newer_durable_version(self):
        replacement={**self.carrier,'txid':'99'*32,'generation':2,'confirmed_height':None,'confirmed_block':None}
        self.value['rows']['carriers'].append(replacement)
        self.value['rows']['mappings'] += [{**m,'txid':replacement['txid']} for m in list(self.value['rows']['mappings'])]
        result=check_group(self.store,self.value,'group',{self.tx['txid']:self.tx,replacement['txid']:{'confirmations':0}})
        self.assertEqual(self.tx['txid'],result['txid']);self.assertEqual(2,len(result['carrier_versions']))
    def test_unverified_operator_change_never_belongs_to_fee_wallet_by_inference(self):
        self.store.db.execute('DELETE FROM operator_script')
        with self.assertRaises(EvidenceGap):self.check()
    def test_wrong_payee_or_fee_or_record_or_mapping_is_refused(self):
        original=copy.deepcopy(self.value);tx=copy.deepcopy(self.tx)
        for mutation in ['payee','fee','record','mapping','root']:
            with self.subTest(mutation=mutation):
                self.value=copy.deepcopy(original);self.tx=copy.deepcopy(tx)
                if mutation=='payee':self.value['rows']['allocations'][0]['owner_pubkey']='foreign'
                if mutation=='fee':self.value['rows']['allocations'][0]['fee_sat']=999
                if mutation=='record':self.value['rows']['records'][0]['account_sig']='44'*64
                if mutation=='mapping':self.value['rows']['mappings'][0]['vout']=1
                if mutation=='root':self.value['rows']['carriers'][0]['backing_ids']=['foreign:0']
                with self.assertRaises((InvariantError,EvidenceGap)):self.check()
    def test_complete_joint_snapshot_and_immutable_observation_are_required(self):
        record(self.store,self.value)
        changed=copy.deepcopy(self.value);changed['rows']['allocations'][0]['spk']='changed'
        with self.assertRaises(InvariantError):record(self.store,changed)
        changed=copy.deepcopy(self.value);changed['rows']['mappings'].pop()
        with self.assertRaises(EvidenceGap):frame(changed)
        changed=copy.deepcopy(self.value);changed['journal_complete']=False
        with self.assertRaises(EvidenceGap):frame(changed)
        changed=copy.deepcopy(self.value);changed.pop('binding_scope')
        with self.assertRaises(EvidenceGap):frame(changed)
    def test_opaque_private_bytes_and_changed_historical_mapping_are_refused(self):
        secret=copy.deepcopy(self.value);secret['rows']['carriers'][0]['signed_tx']='opaque-witness'
        with self.assertRaises(EvidenceGap):record(self.store,secret)
        record(self.store,self.value)
        changed=copy.deepcopy(self.value);changed['rows']['mappings'][0]['vout']=1
        with self.assertRaises(InvariantError):record(self.store,changed)
    def test_conditional_and_lightning_sources_are_explicitly_unqualified(self):
        self.proof['conditional_steps']=1
        self.store.db.execute('UPDATE owned_coin SET proof=?',(canonical(self.proof),))
        with self.assertRaises(EvidenceGap):self.check()
        self.alloc['source']='lightning-send:hash'
        with self.assertRaises(EvidenceGap):self.check()
    def test_duplicate_terminal_payment_conflicts_across_groups(self):
        result=self.check();commit_checked(self.store,result,self.tx)
        second={**result,'freeze_set':'other','txid':'99'*32}
        with self.assertRaises(InvariantError):commit_checked(self.store,second,self.tx)
